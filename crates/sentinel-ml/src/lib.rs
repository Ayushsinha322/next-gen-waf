//! sentinel-ml — Machine Learning engine for Sentinel WAF.
//!
//! Provides three tiers of intelligence on the request path:
//!
//! **Tier 1 — Built-in models (always active, zero external deps):**
//! * [`MlEngine`] — orchestrates feature extraction, Isolation Forest
//!   anomaly scoring, and payload attack classification.
//! * Feature extraction: 24-dimensional normalised vector per request.
//! * Isolation Forest: online unsupervised anomaly detection, warm-started
//!   from a benign baseline and protected against attack-poisoning (only
//!   clean-looking traffic updates the "normal" model).
//! * Payload Classifier: a **trained logistic-regression** model whose weights
//!   are learned from a bundled labeled corpus (see `models::corpus`). Measured
//!   held-out accuracy lives in `tests/ml_validation.rs`.
//!
//! **Tier 2 — ONNX inference (optional, OFF by default — feature
//! `ort-inference`):**
//! * No models ship by default; this is an extension point for teams that
//!   train their own `.onnx` models and drop them in `ml-models/`.
//! * When enabled and a model is present, it is scored alongside the built-in
//!   models and contributes to `ml_scores`.
//!
//! **Tier 3 — LLM Copilot (async, out-of-band):**
//! * Not on the request path.  Used for alert explanations, rule
//!   generation, and virtual patches.
//!
//! # Usage
//! ```ignore
//! use sentinel_ml::MlEngine;
//!
//! let mut engine = MlEngine::new(1024, 64, None);
//! // On each request:
//! let scores = engine.evaluate(&ctx);
//! if scores.anomaly_score > 0.7 {
//!     // Flag request as suspicious.
//! }
//! ```

pub mod features;
pub mod inference;
pub mod llm_copilot;
pub mod models;

use std::path::Path;

use parking_lot::RwLock;
use tracing::{debug, info};

use self::features::FeatureVector;
use self::inference::ModelRegistry;
use self::models::isolation_forest::IncrementalForest;
use self::models::payload_classifier::PayloadClassifier;

// ---------------------------------------------------------------------------
// ML scores returned per request
// ---------------------------------------------------------------------------

/// Aggregated ML scores for a single request.
#[derive(Debug, Clone)]
pub struct MlScores {
    /// Isolation Forest anomaly score ∈ [0, 1].
    /// >0.6 = suspicious, >0.7 = likely anomalous.
    pub anomaly_score: f32,
    /// Payload Classifier attack probability ∈ [0, 1].
    pub payload_attack_score: f32,
    /// Per-ONNX-model scores, keyed by model name.
    pub onnx_scores: Vec<(String, f32)>,
    /// Combined score (max of all sources) ∈ [0, 1].
    pub combined_score: f32,
}

impl Default for MlScores {
    fn default() -> Self {
        Self {
            anomaly_score: 0.5,
            payload_attack_score: 0.0,
            onnx_scores: Vec::new(),
            combined_score: 0.5,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine configuration
// ---------------------------------------------------------------------------

/// Per-instance ML engine configuration.
#[derive(Debug, Clone)]
pub struct MlEngineConfig {
    /// Isolation Forest ring-buffer capacity (recent request vectors kept).
    pub buffer_capacity: usize,
    /// Retrain the forest after this many new observations.
    pub retrain_every: usize,
    /// Path to ONNX model directory (default: `ml-models/`).
    pub model_dir: Option<String>,
    /// Sensitivity threshold [0, 1] — combined score above this flags a
    /// request as suspicious (default: 0.85 from config).
    pub sensitivity: f32,
}

impl Default for MlEngineConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 4096,
            retrain_every: 256,
            model_dir: None,
            sensitivity: 0.85,
        }
    }
}

// ---------------------------------------------------------------------------
// ML Engine
// ---------------------------------------------------------------------------

/// Central ML orchestrator — created once, shared across all request
/// handlers.
///
/// # Thread safety
/// All fields are behind `RwLock` so the engine is `Send + Sync`.
/// Reads (scoring) are fast shared-lock; writes (retraining) are rare.
pub struct MlEngine {
    forest: IncrementalForest,
    payload_classifier: PayloadClassifier,
    model_registry: RwLock<ModelRegistry>,
    config: RwLock<MlEngineConfig>,
}

impl MlEngine {
    /// Create a new ML engine.
    ///
    /// * `buffer_capacity` — max recent vector count for Isolation Forest.
    /// * `retrain_every` — retrain forest after N new observations.
    /// * `model_dir` — path to load `.onnx` models from.
    pub fn new(buffer_capacity: usize, retrain_every: usize, model_dir: Option<&Path>) -> Self {
        let mut registry = ModelRegistry::new();
        let config = MlEngineConfig {
            buffer_capacity,
            retrain_every,
            model_dir: model_dir.map(|p| p.display().to_string()),
            sensitivity: 0.85,
        };

        if let Some(dir) = model_dir {
            match std::fs::read_dir(dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("onnx") {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                if let Err(e) = registry.load(stem, dir) {
                                    tracing::warn!("failed to load ONNX model {stem}: {e}");
                                }
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!("cannot read model dir {dir:?}: {e}"),
            }
        }

        if !registry.is_empty() {
            info!(count = registry.len(), "ONNX models loaded");
        }

        Self {
            forest: IncrementalForest::new(buffer_capacity, retrain_every),
            payload_classifier: PayloadClassifier::default(),
            model_registry: RwLock::new(registry),
            config: RwLock::new(config),
        }
    }

    /// Evaluate ML scores for a request and feed the result into online
    /// learning.
    ///
    /// This is the only method that should be called on the request path.
    pub fn evaluate(&self, ctx: &sentinel_core::context::RequestContext) -> MlScores {
        let fv = FeatureVector::extract(ctx);

        // 1. Isolation Forest anomaly score (against the current model, before
        //    feeding this request in).
        let anomaly_score = self.forest.score(fv.as_slice());

        // 2. Payload attack probability. Prefer the embedded char-n-gram model
        //    (learns injection structure, generalizes to evasive payloads); it
        //    scores each attackable value separately (matching its per-value
        //    training distribution) and takes the max, so an attack in one field
        //    is not diluted by benign content in others. Falls back to the
        //    legacy 25-feature classifier if the embedded model failed to load.
        let payload_attack_score = if models::ngram_classifier::is_loaded() {
            // Collect every attackable value as a candidate.
            let mut candidates: Vec<String> = Vec::new();
            // URL path segments (URLPath placement; path-borne injection).
            for seg in ctx.uri.path().split('/') {
                if !seg.is_empty() {
                    candidates.push(seg.to_string());
                }
            }
            // Query param values, percent-decoded (URLParam placement).
            if let Some(q) = ctx.uri.query() {
                let decoded = percent_encoding::percent_decode_str(q).decode_utf8_lossy();
                for kv in decoded.split('&') {
                    candidates.push(kv.split_once('=').map(|(_, v)| v).unwrap_or(kv).to_string());
                }
            }
            // Request body (Body/JSON/form/multipart placements).
            if let Some(body) = ctx.request_body.as_ref() {
                if let Ok(bs) = std::str::from_utf8(body.as_ref()) {
                    candidates.push(bs.to_string());
                    // Also score each PARSED, DECODED field value. Scoring only the
                    // whole raw body misses attacks carried in a form/multipart
                    // field: a URL- or Base64-encoded payload sits inside the
                    // envelope, so the wholly-encoded field never decodes (its
                    // marker is diluted by boundaries/`key=`) and slips past. Per-
                    // field candidates let score_all decode each value on its own.
                    let ct = ctx
                        .request_headers
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    body_field_values(bs, ct, &mut candidates);
                }
            }
            // Score each candidate over its raw form AND every decoded variant
            // (Base64, HTML-entity, recursive percent-decode) — recursive
            // normalization defeats encoder-axis evasion — taking the max so an
            // attack in any field or encoding is not diluted by benign content.
            let mut max_s = 0.0f32;
            for c in &candidates {
                if let Some(s) = models::ngram_classifier::score_all(c) {
                    max_s = max_s.max(s);
                }
            }
            max_s
        } else {
            self.payload_classifier.score(&fv)
        };

        // 3. Online learning — poisoning guard: only let *clean-looking*
        //    traffic update the "normal" model. A request that the rule engine
        //    already scored, or that the classifier flags, must not teach the
        //    Isolation Forest that attacks are normal.
        let looks_clean = ctx.anomaly_score == 0 && payload_attack_score < 0.5;
        if looks_clean {
            self.forest.observe(fv.as_slice());
        }

        // 4. ONNX model scores (optional; only if real .onnx models were
        //    loaded — disabled by default, see inference module).
        let registry = self.model_registry.read();
        let onnx_scores: Vec<(String, f32)> = registry
            .model_names()
            .map(|name| {
                let raw = registry.predict(name, &fv.values);
                let score = raw.first().copied().unwrap_or(0.5);
                (name.to_string(), score)
            })
            .collect();
        drop(registry);

        // When the supervised n-gram model is active it drives the block
        // decision; the unsupervised Isolation Forest stays informational
        // (its anomaly_score is reported but not fused into the block signal,
        // since an unsupervised model on varied benign traffic is FP-prone).
        let combined = if models::ngram_classifier::is_loaded() {
            payload_attack_score
        } else {
            anomaly_score.max(payload_attack_score)
        };

        let scores = MlScores {
            anomaly_score,
            payload_attack_score,
            onnx_scores,
            combined_score: combined,
        };

        debug!(
            anomaly = %anomaly_score,
            payload_attack = %payload_attack_score,
            combined = %combined,
            "ML scored request"
        );

        scores
    }

    /// Warm-start the anomaly model with a baseline of benign traffic so it
    /// scores meaningfully from the first live request instead of cold-starting
    /// at the neutral 0.5.  Seeds the Isolation Forest with the benign portion
    /// of the bundled corpus, then trains immediately.  Call once after
    /// construction (the proxy does this at startup).
    pub fn warm_start(&self) {
        let benign: Vec<Vec<f32>> = self::models::corpus::training_corpus()
            .into_iter()
            .filter(|s| s.label == 0.0)
            .map(|s| s.fv.values.to_vec())
            .collect();
        let n = benign.len();
        self.forest.seed(&benign);
        info!(
            seeded = n,
            "ML anomaly model warm-started from benign baseline"
        );
    }

    /// Update sensitivity threshold from config (hot-reload).
    pub fn set_sensitivity(&self, sensitivity: f32) {
        self.config.write().sensitivity = sensitivity.clamp(0.0, 1.0);
    }

    /// Current sensitivity threshold.
    pub fn sensitivity(&self) -> f32 {
        self.config.read().sensitivity
    }

    /// Whether the Isolation Forest has been trained at least once.
    pub fn is_trained(&self) -> bool {
        self.forest.is_trained()
    }

    /// Number of requests in the learning buffer.
    pub fn buffer_len(&self) -> usize {
        self.forest.buffer_len()
    }

    /// Training generation counter.
    pub fn generation(&self) -> u64 {
        self.forest.generation()
    }

    /// Number of ONNX models loaded.
    pub fn onnx_model_count(&self) -> usize {
        self.model_registry.read().len()
    }
}

/// Extract decoded field values from a form-urlencoded or multipart body and
/// push each as its own ML candidate. Each value is scored independently so a
/// URL/Base64-encoded payload in one field decodes cleanly (its whole-value
/// marker is intact) instead of being lost inside the raw body blob. Non-form
/// bodies (JSON, raw) are already covered by the whole-body candidate.
fn body_field_values(body: &str, content_type: &str, out: &mut Vec<String>) {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("application/x-www-form-urlencoded") {
        for kv in body.split('&') {
            let v = kv.split_once('=').map(|(_, v)| v).unwrap_or(kv);
            let dec = percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned();
            if !dec.is_empty() {
                out.push(dec);
            }
        }
    } else if let Some(pos) = ct.find("multipart/form-data") {
        // Boundary token from `; boundary=...`.
        let Some(b) = ct[pos..]
            .find("boundary=")
            .map(|i| pos + i + "boundary=".len())
            .map(|i| content_type[i..].trim().trim_matches('"'))
        else {
            return;
        };
        if b.is_empty() {
            return;
        }
        let delim = format!("--{b}");
        for part in body.split(&delim) {
            // Field value is everything after the part's header block (blank line).
            if let Some(idx) = part
                .find("\r\n\r\n")
                .map(|i| i + 4)
                .or_else(|| part.find("\n\n").map(|i| i + 2))
            {
                let val = part[idx..].trim_end_matches(['-', '\r', '\n']);
                if !val.is_empty() {
                    out.push(val.to_string());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn engine_creates_and_scores() {
        let engine = MlEngine::new(1024, 64, None);
        // Not trained yet — scores neutral.
        assert!(!engine.is_trained());
        assert_eq!(engine.buffer_len(), 0);
    }

    #[test]
    fn form_field_values_are_decoded() {
        let mut out = Vec::new();
        body_field_values(
            "a=%3Cscript%3E&b=hello",
            "application/x-www-form-urlencoded",
            &mut out,
        );
        assert!(out.contains(&"<script>".to_string()), "got {out:?}");
        assert!(out.contains(&"hello".to_string()));
    }

    #[test]
    fn multipart_field_values_extracted() {
        let b = "X99";
        let body = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n<svg onload=alert(1)>\r\n--{b}--\r\n"
        );
        let mut out = Vec::new();
        body_field_values(
            &body,
            &format!("multipart/form-data; boundary={b}"),
            &mut out,
        );
        assert!(
            out.iter().any(|v| v.contains("<svg onload=alert(1)>")),
            "multipart field value not extracted: {out:?}"
        );
    }

    #[test]
    fn engine_evaluates_clean_request() {
        let engine = MlEngine::new(1024, 64, None);
        let mut ctx =
            sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        ctx.uri = "http://example.com/".parse().unwrap();
        let scores = engine.evaluate(&ctx);
        assert!((0.0..=1.0).contains(&scores.anomaly_score));
        assert!((0.0..=1.0).contains(&scores.payload_attack_score));
        assert!((0.0..=1.0).contains(&scores.combined_score));
        assert_eq!(engine.buffer_len(), 1);
    }

    #[test]
    fn engine_trains_after_enough_data() {
        let engine = MlEngine::new(512, 64, None);
        let mut ctx =
            sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        ctx.uri = "http://example.com/".parse().unwrap();

        for i in 0..64 {
            ctx.uri = format!("http://example.com/page{i}").parse().unwrap();
            engine.evaluate(&ctx);
        }
        // After 64 evaluations, the forest should be trained.
        assert!(engine.is_trained(), "forest should be trained");
        assert!(engine.generation() >= 1, "at least one retrain");
    }

    #[test]
    fn sql_injection_scores_higher_than_clean() {
        let engine = MlEngine::new(512, 64, None);

        // Feed some "clean" traffic to give the forest a baseline.
        let mut ctx =
            sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        for i in 0..64 {
            ctx.uri = format!("http://example.com/products/{i}?page=1")
                .parse()
                .unwrap();
            engine.evaluate(&ctx);
        }
        assert!(engine.is_trained());

        let mut clean_ctx =
            sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        clean_ctx.uri = "http://example.com/products/42?page=1".parse().unwrap();
        let clean = engine.evaluate(&clean_ctx);

        // Use a percent-encoded SQLi so the URI is valid.
        let mut sqli_ctx =
            sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        sqli_ctx.uri =
            "http://example.com/products?id=1%27%20UNION%20SELECT%20*%20FROM%20users%20--"
                .parse()
                .unwrap();
        let sqli = engine.evaluate(&sqli_ctx);

        // The attack should score higher on the payload classifier.
        assert!(
            sqli.payload_attack_score > clean.payload_attack_score,
            "SQLi payload attack score ({}) should exceed clean ({})",
            sqli.payload_attack_score,
            clean.payload_attack_score
        );
    }

    #[test]
    fn sensitivity_clamped() {
        let engine = MlEngine::new(512, 64, None);
        engine.set_sensitivity(1.5);
        assert_eq!(engine.sensitivity(), 1.0);
        engine.set_sensitivity(-0.2);
        assert_eq!(engine.sensitivity(), 0.0);
        engine.set_sensitivity(0.73);
        assert_eq!(engine.sensitivity(), 0.73);
    }
}
