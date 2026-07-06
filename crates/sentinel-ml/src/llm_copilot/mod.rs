//! LLM Copilot — asynchronous AI assistant for WAF operations.
//!
//! Communicates with OpenAI-compatible APIs (OpenAI, Ollama, LM Studio).
//!
//! **NOT on the request path** — the copilot runs out-of-band:
//! * `explain_alert(ctx)` — explains *why* a request was blocked in natural
//!   language.
//! * `suggest_rule(description)` — generates an SRL rule from a human
//!   description.
//! * `generate_virtual_patch(cve_id, description)` — creates a virtual
//!   patch for a CVE.
//!
//! Configuration is in `WafConfig.ml.copilot` (TBD field in JSON config).

use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use sentinel_core::context::RequestContext;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Copilot service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotConfig {
    /// OpenAI-compatible API endpoint (e.g. `https://api.openai.com/v1`,
    /// or `http://localhost:11434/v1` for Ollama).
    pub endpoint: String,
    /// API key (set to `"ollama"` for Ollama / `"local"` for LM Studio).
    pub api_key: String,
    /// Model name (e.g. `"gpt-4o-mini"`, `"llama3.2"`, `"qwen2.5:7b"`).
    pub model: String,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:11434/v1".to_string(),
            api_key: "ollama".to_string(),
            model: "llama3.2".to_string(),
            timeout_secs: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// LLM Copilot service.  Created once at startup; calls are async.
pub struct CopilotService {
    config: CopilotConfig,
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl CopilotService {
    /// Create a new copilot service.
    ///
    /// Panics if the TLS client cannot be initialised (programming error).
    pub fn new(config: CopilotConfig) -> Self {
        // hyper_rustls with webpki-roots feature bundles Mozilla CA certs.
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .build();

        let client: Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            Full<Bytes>,
        > = Client::builder(TokioExecutor::new()).build(https);

        Self { config, client }
    }

    // -----------------------------------------------------------------------
    // Public methods
    // -----------------------------------------------------------------------

    /// Ask a one-shot question with an optional system prompt.
    /// Returns the model's plain-text response.
    pub async fn ask(&self, system: &str, user: &str) -> Result<String, anyhow::Error> {
        self.chat(user, system).await
    }

    /// Explain why a request was blocked or flagged.
    ///
    /// Returns a one-to-two-sentence natural-language explanation,
    /// or a fallback error message if the LLM is unavailable.
    pub async fn explain_alert(&self, ctx: &RequestContext) -> String {
        let rules: Vec<String> = ctx
            .rule_matches
            .iter()
            .map(|m| format!("{} ({})", m.message, m.rule_id))
            .collect();
        let rules_text = if rules.is_empty() {
            "no specific rule matches".to_string()
        } else {
            rules.join(", ")
        };

        let prompt = format!(
            "You are a WAF security analyst. Explain in one sentence \
             why this HTTP request was blocked.\n\n\
             Method: {}\n\
             URI: {}\n\
             Client IP: {}\n\
             Anomaly score: {}\n\
             Matched rules: {}\n\
             Block reason: {}\n\n\
             Explanation (one sentence, plain English):",
            ctx.method,
            ctx.uri,
            ctx.client_ip,
            ctx.anomaly_score,
            rules_text,
            ctx.block_reason.as_deref().unwrap_or("unknown"),
        );

        self.chat(
            &prompt,
            "You are a concise WAF security expert. Always answer in one sentence.",
        )
        .await
        .unwrap_or_else(|e| {
            warn!("copilot explain failed: {e}");
            format!(
                "Request to {} was blocked due to anomaly score {} and rules: {}",
                ctx.uri, ctx.anomaly_score, rules_text
            )
        })
    }

    /// Generate an SRL rule from a human description.
    pub async fn suggest_rule(&self, description: &str) -> Result<String, anyhow::Error> {
        let prompt = format!(
            "You are a WAF rule engineer. Write a Sentinel Rule Language (SRL) \
             rule that detects: {description}\n\n\
             SRL syntax:\n\
             ```srl\n\
             rule \"Rule Name\" {{\n    match \"/pattern/\" in REQUEST_URI {{\n        block with severity Critical;\n        set_anomaly_score 5;\n    }}\n}}\n\
             ```\n\
             Available targets: REQUEST_URI, REQUEST_HEADERS:name, REQUEST_BODY, \
             ARGS:name, REQUEST_COOKIES:name, REMOTE_ADDR, RESPONSE_BODY.\n\
             Available operators: rx, contains, equals, exists, gt, ge.\n\
             Severities: Critical, High, Medium, Low.\n\
             Scoring: set_anomaly_score N (1-8).\n\n\
             Return ONLY the SRL rule, no other text:",
        );

        self.chat(
            &prompt,
            "You are a security rule engineer. Return ONLY the SRL rule with no commentary.",
        )
        .await
    }

    /// Generate a virtual patch for a CVE.
    pub async fn generate_virtual_patch(
        &self,
        cve_id: &str,
        description: &str,
    ) -> Result<String, anyhow::Error> {
        let prompt = format!(
            "You are a WAF security analyst. Write a virtual patch for {cve_id}.\n\n\
             CVE description: {description}\n\n\
             Write a Sentinel Rule Language (SRL) virtual patch:\n\
             ```srl\n\
             virtual_patch for CVE-{cve_id} {{\n    match \"PATTERN\" in REQUEST_URI {{\n        block with severity Critical;\n        set_anomaly_score 8;\n    }}\n}}\n\
             ```\n\n\
             Return ONLY the SRL virtual patch, no other text:",
        );

        self.chat(
            &prompt,
            "You are a security researcher. Return ONLY the virtual patch with no commentary.",
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Send a single-turn chat request.  Returns the model's response text.
    async fn chat(
        &self,
        user_message: &str,
        system_message: &str,
    ) -> Result<String, anyhow::Error> {
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0.2,
            "max_tokens": 500,
            "stream": false,
        });

        let req = Request::post(format!("{}/chat/completions", self.config.endpoint))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| anyhow::anyhow!("build chat request: {e}"))?;

        let resp = tokio::time::timeout(
            Duration::from_secs(self.config.timeout_secs),
            self.client.request(req),
        )
        .await
        .map_err(|_| anyhow::anyhow!("copilot request timed out"))?
        .map_err(|e| anyhow::anyhow!("copilot HTTP error: {e}"))?;

        // Save status before consuming body.
        let http_status = resp.status();

        let body_bytes = resp
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("read copilot response: {e}"))?
            .to_bytes();

        if http_status != StatusCode::OK {
            let err_str = String::from_utf8_lossy(&body_bytes)
                .chars()
                .take(300)
                .collect::<String>();
            anyhow::bail!("copilot returned HTTP {http_status} — {err_str}");
        }

        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| anyhow::anyhow!("parse copilot JSON: {e}"))?;

        let text = parsed["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("(no response)")
            .trim()
            .to_string();

        debug!(copilot_response = %text, "LLM copilot returned");
        Ok(text)
    }
}

// ---------------------------------------------------------------------------
// Tests (offline — no LLM endpoint needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_ollama() {
        let cfg = CopilotConfig::default();
        assert_eq!(cfg.endpoint, "http://localhost:11434/v1");
    }

    #[test]
    fn copilot_config_serializes() {
        let cfg = CopilotConfig {
            endpoint: "https://api.openai.com/v1".into(),
            api_key: "sk-test".into(),
            model: "gpt-4o-mini".into(),
            timeout_secs: 15,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: CopilotConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.model, "gpt-4o-mini");
    }
}
