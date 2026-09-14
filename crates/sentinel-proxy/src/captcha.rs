//! Interactive third-party CAPTCHA challenge (reCAPTCHA / hCaptcha / Turnstile).
//!
//! Complements the native Proof-of-Work path in [`crate::challenge`]. When a
//! site configures `bot_detection.challenge = recaptcha|hcaptcha|turnstile`, a
//! suspicious client is served the provider's widget instead of the PoW page.
//! On solve the page stores the provider token in the `sentinel_captcha` cookie
//! and reloads; the server verifies that token against the provider's
//! `siteverify` endpoint (server-side, with the secret) and, on success, issues
//! the same stateless clearance cookie the PoW path grants.
//!
//! Verification fails closed: any network/parse error or a `success:false`
//! response re-serves the challenge rather than letting the client through.

use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use sentinel_core::config::{CaptchaProvider, ChallengeMode};
use tracing::warn;

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    http_body_util::combinators::BoxBody<Bytes, hyper::Error>,
>;

/// Which third-party provider a challenge uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaKind {
    Recaptcha,
    Hcaptcha,
    Turnstile,
}

impl CaptchaKind {
    /// Map a challenge mode to a provider (None for Off / native PoW).
    pub fn from_mode(mode: ChallengeMode) -> Option<Self> {
        match mode {
            ChallengeMode::Recaptcha => Some(Self::Recaptcha),
            ChallengeMode::Hcaptcha => Some(Self::Hcaptcha),
            ChallengeMode::Turnstile => Some(Self::Turnstile),
            _ => None,
        }
    }

    /// Pick the matching provider credentials from the bot config.
    pub fn provider(
        self,
        b: &sentinel_core::config::BotDetectionConfig,
    ) -> Option<&CaptchaProvider> {
        match self {
            Self::Recaptcha => b.recaptcha.as_ref(),
            Self::Hcaptcha => b.hcaptcha.as_ref(),
            Self::Turnstile => b.turnstile.as_ref(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Recaptcha => "reCAPTCHA",
            Self::Hcaptcha => "hCaptcha",
            Self::Turnstile => "Cloudflare Turnstile",
        }
    }

    /// Provider widget script URL.
    fn script(self) -> &'static str {
        match self {
            Self::Recaptcha => "https://www.google.com/recaptcha/api.js",
            Self::Hcaptcha => "https://js.hcaptcha.com/1/api.js",
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
        }
    }

    /// CSS class the provider's script looks for to render the widget.
    fn widget_class(self) -> &'static str {
        match self {
            Self::Recaptcha => "g-recaptcha",
            Self::Hcaptcha => "h-captcha",
            Self::Turnstile => "cf-turnstile",
        }
    }

    /// Server-side token verification endpoint.
    fn siteverify(self) -> &'static str {
        match self {
            Self::Recaptcha => "https://www.google.com/recaptcha/api/siteverify",
            Self::Hcaptcha => "https://api.hcaptcha.com/siteverify",
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        }
    }
}

fn client() -> &'static HttpsClient {
    static CLIENT: OnceLock<HttpsClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Client::builder(TokioExecutor::new()).build(https)
    })
}

/// URL-encode a value for an `application/x-www-form-urlencoded` body.
fn form_enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Verify a solved CAPTCHA token with the provider. Returns true only on an
/// explicit `success:true` (and, for a reCAPTCHA-v3 key that returns a score,
/// score ≥ `min_score`). Fails closed on any error.
pub async fn verify(
    kind: CaptchaKind,
    secret: &str,
    token: &str,
    remote_ip: &str,
    min_score: f32,
) -> bool {
    if secret.is_empty() || token.is_empty() {
        return false;
    }
    let body = format!(
        "secret={}&response={}&remoteip={}",
        form_enc(secret),
        form_enc(token),
        form_enc(remote_ip)
    );
    let req = match Request::builder()
        .method(hyper::Method::POST)
        .uri(kind.siteverify())
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(hyper::header::USER_AGENT, "sentinel-waf/1.0 captcha-verify")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed(),
        ) {
        Ok(r) => r,
        Err(e) => {
            warn!("captcha verify: build request failed: {e}");
            return false;
        }
    };

    let resp = match tokio::time::timeout(Duration::from_secs(10), client().request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!("captcha verify ({}) transport error: {e}", kind.label());
            return false;
        }
        Err(_) => {
            warn!("captcha verify ({}) timed out", kind.label());
            return false;
        }
    };
    if !resp.status().is_success() {
        warn!("captcha verify ({}) HTTP {}", kind.label(), resp.status());
        return false;
    }
    let bytes = match resp.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            warn!("captcha verify ({}) body error: {e}", kind.label());
            return false;
        }
    };
    let json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!("captcha verify ({}) bad JSON: {e}", kind.label());
            return false;
        }
    };
    if json.get("success").and_then(|v| v.as_bool()) != Some(true) {
        return false;
    }
    // reCAPTCHA v3 returns a score; v2 / hCaptcha / Turnstile omit it → pass.
    match json.get("score").and_then(|v| v.as_f64()) {
        Some(score) => score >= min_score as f64,
        None => true,
    }
}

/// Build the challenge interstitial embedding the provider widget. On solve the
/// widget's callback stores the token in the `sentinel_captcha` cookie and
/// reloads so the server can verify it on the next request.
pub fn interstitial(kind: CaptchaKind, sitekey: &str) -> String {
    let cookie_name = crate::challenge::CAPTCHA_COOKIE;
    // sitekey is operator-supplied; escape the quote/backslash/angle so it can't
    // break out of the HTML attribute or inject markup.
    let sitekey = html_attr_escape(sitekey);
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verify you are human…</title>
<script src="{script}" async defer></script>
<script>
function sentinelSolved(token){{document.cookie="{cookie}="+token+"; path=/; max-age=300; SameSite=Lax";setTimeout(function(){{location.reload();}},250);}}
</script>
<style>:root{{color-scheme:dark}}body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#070b12;color:#e6edf3;font-family:system-ui,Segoe UI,Roboto,sans-serif}}
.card{{max-width:460px;padding:40px 36px;text-align:center;background:#0d1420;border:1px solid rgba(0,212,255,.18);border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.5)}}
.logo{{font-weight:800;letter-spacing:1px;font-size:13px;color:#22d3ee;text-transform:uppercase}}
h1{{font-size:19px;margin:14px 0 6px}}p{{font-size:13px;color:#8b97a7;line-height:1.6;margin:0 0 20px}}
.widget{{display:flex;justify-content:center;min-height:70px}}
.foot{{margin-top:18px;font-size:10px;color:#52525b}}</style></head>
<body><div class="card"><div class="logo">{product}</div><h1>Verify you are human</h1><p>Complete the check below to continue to this site.</p>
<div class="widget"><div class="{widget_class}" data-sitekey="{sitekey}" data-callback="sentinelSolved"></div></div>
<div class="foot">Protected by {label}</div></div></body></html>"#,
        script = kind.script(),
        cookie = cookie_name,
        widget_class = kind.widget_class(),
        sitekey = sitekey,
        label = kind.label(),
        product = sentinel_core::PRODUCT_NAME,
    )
}

fn html_attr_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "&quot;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '&' => "&amp;".chars().collect(),
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_mode_maps_providers() {
        assert_eq!(
            CaptchaKind::from_mode(ChallengeMode::Recaptcha),
            Some(CaptchaKind::Recaptcha)
        );
        assert_eq!(
            CaptchaKind::from_mode(ChallengeMode::Hcaptcha),
            Some(CaptchaKind::Hcaptcha)
        );
        assert_eq!(
            CaptchaKind::from_mode(ChallengeMode::Turnstile),
            Some(CaptchaKind::Turnstile)
        );
        assert_eq!(CaptchaKind::from_mode(ChallengeMode::NativePow), None);
        assert_eq!(CaptchaKind::from_mode(ChallengeMode::Off), None);
    }

    #[test]
    fn form_enc_escapes_reserved() {
        assert_eq!(form_enc("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(form_enc("plain-Value_1.2~"), "plain-Value_1.2~");
    }

    #[test]
    fn interstitial_embeds_sitekey_and_widget() {
        let html = interstitial(CaptchaKind::Turnstile, "0xABC");
        assert!(html.contains("cf-turnstile"));
        assert!(html.contains(r#"data-sitekey="0xABC""#));
        assert!(html.contains("challenges.cloudflare.com/turnstile/v0/api.js"));
        assert!(html.contains("sentinel_captcha"));
    }

    #[test]
    fn interstitial_escapes_sitekey() {
        let html = interstitial(CaptchaKind::Recaptcha, r#""><script>x</script>"#);
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&quot;&gt;&lt;script&gt;"));
    }

    #[test]
    fn deserializes_the_exact_bot_detection_json_the_wizard_emits() {
        // Mirrors formToPayload() in dashboard/lib/siteConfig.ts.
        let json = r#"{
            "ja4": true,
            "challenge": "turnstile",
            "turnstile": { "sitekey": "0xSITE", "secret": "0xSECRET" }
        }"#;
        let cfg: sentinel_core::config::BotDetectionConfig =
            serde_json::from_str(json).expect("bot_detection JSON must deserialize");
        assert_eq!(cfg.challenge, ChallengeMode::Turnstile);
        let kind = CaptchaKind::from_mode(cfg.challenge).unwrap();
        let p = kind.provider(&cfg).expect("turnstile provider present");
        assert_eq!(p.sitekey, "0xSITE");
        assert_eq!(p.secret, "0xSECRET");
        assert_eq!(p.score, 0.5); // default applied (turnstile sends no score)
    }
}
