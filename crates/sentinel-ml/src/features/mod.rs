//! Feature extraction: `RequestContext` → `FeatureVector`.
//!
//! Produces a 25-dimensional row vector of normalised floats that is consumed
//! by both the Isolation Forest (anomaly detection) and the Payload Classifier.

use sentinel_core::context::RequestContext;

pub const FEATURE_DIM: usize = 25;

/// Named indices into `FeatureVector::values`.
pub mod idx {
    pub const URL_LEN: usize = 0;
    pub const QUERY_LEN: usize = 1;
    pub const BODY_LEN: usize = 2;
    pub const METHOD_GET: usize = 3;
    pub const METHOD_POST: usize = 4;
    pub const METHOD_PUT: usize = 5;
    pub const METHOD_DELETE: usize = 6;
    pub const METHOD_OTHER: usize = 7;
    pub const HEADER_COUNT: usize = 8;
    pub const PATH_DEPTH: usize = 9;
    pub const QUERY_PARAM_COUNT: usize = 10;
    pub const SPECIAL_CHAR_DENSITY_URI: usize = 11;
    pub const SPECIAL_CHAR_DENSITY_BODY: usize = 12;
    pub const ENTROPY_URI: usize = 13;
    pub const ENTROPY_BODY: usize = 14;
    pub const SQL_KEYWORD_SCORE: usize = 15;
    pub const XSS_KEYWORD_SCORE: usize = 16;
    pub const PCT_ENCODED_COUNT: usize = 17;
    pub const ANOMALY_SCORE: usize = 18;
    pub const HAS_UA: usize = 19;
    pub const UA_LEN: usize = 20;
    pub const CONTENT_TYPE_PRESENT: usize = 21;
    pub const COOKIE_COUNT: usize = 22;
    pub const IS_TLS: usize = 23;
    /// Set to 1.0 when the request matched the hot threat-intelligence feed.
    /// Carries a strong, fixed prior weight in the payload classifier (the
    /// corpus cannot teach a runtime signal), so a hit dominates the score.
    pub const MATCHES_THREAT_INTEL: usize = 24;
}

/// 25-dimensional, fully-normalised feature row extracted from a request.
/// Every element ∈ [0.0, 1.0].
#[derive(Debug, Clone)]
pub struct FeatureVector {
    pub values: [f32; FEATURE_DIM],
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self {
            values: [0.0; FEATURE_DIM],
        }
    }
}

impl FeatureVector {
    /// Extract features from a live request context.
    ///
    /// Called at Phase 2 (body available) so all fields are populated.
    pub fn extract(ctx: &RequestContext) -> Self {
        let uri_str = ctx.uri.to_string();
        let path = ctx.uri.path();
        let query_raw = ctx.uri.query().unwrap_or("");

        // Percent-decode the query string so encoded attacks (e.g. %27 for ')
        // are detected by the keyword scorers.
        let query_decoded = percent_encoding::percent_decode_str(query_raw)
            .decode_utf8_lossy()
            .to_string();

        let (body_str, body_bytes) = match ctx.request_body.as_ref() {
            Some(b) => {
                let bytes: &[u8] = b.as_ref();
                let s = std::str::from_utf8(bytes).unwrap_or("");
                (s, bytes)
            }
            None => ("", &[][..]),
        };
        let body_len = body_bytes.len();

        let mut v = [0.0f32; FEATURE_DIM];

        // --- Lengths (log-scaled to [0, 1]) ---
        v[idx::URL_LEN] = log_scale(uri_str.len(), 2048);
        v[idx::QUERY_LEN] = log_scale(query_raw.len(), 1024);
        v[idx::BODY_LEN] = log_scale(body_len, 65536);

        // --- HTTP method one-hot ---
        match ctx.method.as_str() {
            "GET" => v[idx::METHOD_GET] = 1.0,
            "POST" => v[idx::METHOD_POST] = 1.0,
            "PUT" => v[idx::METHOD_PUT] = 1.0,
            "DELETE" => v[idx::METHOD_DELETE] = 1.0,
            _ => v[idx::METHOD_OTHER] = 1.0,
        }

        // --- Headers ---
        v[idx::HEADER_COUNT] = log_scale(ctx.request_headers.len(), 50);
        v[idx::HAS_UA] = ctx.request_headers.contains_key(http::header::USER_AGENT) as u8 as f32;
        let ua_len = ctx
            .request_headers
            .get(http::header::USER_AGENT)
            .and_then(|val| val.to_str().ok())
            .map(|s| s.len())
            .unwrap_or(0);
        v[idx::UA_LEN] = log_scale(ua_len, 512);
        v[idx::CONTENT_TYPE_PRESENT] =
            ctx.request_headers.contains_key(http::header::CONTENT_TYPE) as u8 as f32;
        let cookie_count = ctx
            .request_headers
            .get_all(http::header::COOKIE)
            .iter()
            .count();
        v[idx::COOKIE_COUNT] = log_scale(cookie_count, 20);
        v[idx::IS_TLS] = ctx.tls_fingerprint.is_some() as u8 as f32;

        // --- Path depth ---
        v[idx::PATH_DEPTH] = log_scale(path.matches('/').count(), 10);

        // --- Query param count ---
        let qparam_count = if query_raw.is_empty() {
            0
        } else {
            query_raw.split('&').count()
        };
        v[idx::QUERY_PARAM_COUNT] = log_scale(qparam_count, 30);

        // --- Special-character density ---
        v[idx::SPECIAL_CHAR_DENSITY_URI] = special_char_density(uri_str.as_bytes());
        v[idx::SPECIAL_CHAR_DENSITY_BODY] = special_char_density(body_bytes);

        // --- Shannon entropy ---
        v[idx::ENTROPY_URI] = shannon_entropy(uri_str.as_bytes()) / 8.0;
        v[idx::ENTROPY_BODY] = shannon_entropy(body_bytes) / 8.0;

        // --- Attack-pattern keyword scores (use decoded query for accuracy) ---
        let combined = format!(
            "{} {}",
            query_decoded.to_ascii_lowercase(),
            body_str.to_ascii_lowercase()
        );
        v[idx::SQL_KEYWORD_SCORE] = sql_keyword_score(&combined);
        v[idx::XSS_KEYWORD_SCORE] = xss_keyword_score(&combined);

        // --- %-encoding density ---
        let pct_count = uri_str.matches('%').count() + body_str.matches('%').count();
        v[idx::PCT_ENCODED_COUNT] = log_scale(pct_count, 100);

        // --- Existing WAF anomaly score (rule engine output) ---
        v[idx::ANOMALY_SCORE] = (ctx.anomaly_score as f32 / 100.0).min(1.0);

        // --- Threat-intelligence feed match (dynamic CTI signal) ---
        v[idx::MATCHES_THREAT_INTEL] = ctx.threat_intel_hit as u8 as f32;

        Self { values: v }
    }

    /// Return the vector as a flat slice.
    pub fn as_slice(&self) -> &[f32] {
        &self.values
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Log-scale count to [0, 1]: `ln(1 + x) / ln(1 + max)`, clamped.
fn log_scale(x: usize, max: usize) -> f32 {
    let lmax = ((1 + max) as f32).ln();
    (((1 + x) as f32).ln() / lmax.max(1e-9)).clamp(0.0, 1.0)
}

/// Fraction of bytes that are web-attack special characters, in [0, 1].
fn special_char_density(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let count = bytes
        .iter()
        .filter(|&&b| {
            matches!(
                b,
                b'\''
                    | b'"'
                    | b'<'
                    | b'>'
                    | b';'
                    | b'('
                    | b')'
                    | b'\\'
                    | b'|'
                    | b'`'
                    | b'&'
                    | b'-'
                    | b'+'
                    | b'/'
            )
        })
        .count();
    (count as f32 / bytes.len() as f32).min(1.0)
}

/// Shannon entropy of a byte slice in bits (0 – 8).
pub(crate) fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let n = bytes.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

/// Maximum-weight SQL injection keyword score ∈ [0, 1].
fn sql_keyword_score(lower: &str) -> f32 {
    const PATTERNS: &[(&str, f32)] = &[
        ("union select", 0.90),
        ("union all select", 0.95),
        ("' or ", 0.80),
        ("\" or ", 0.80),
        ("or 1=1", 0.75),
        ("or '1'='1", 0.85),
        ("waitfor delay", 0.90),
        ("sleep(", 0.80),
        ("benchmark(", 0.80),
        ("xp_cmdshell", 1.00),
        ("information_schema", 0.60),
        ("select * from", 0.55),
        ("drop table", 0.80),
        ("load_file(", 0.85),
        ("into outfile", 0.85),
        ("into dumpfile", 0.85),
        ("cast(", 0.35),
        ("convert(", 0.35),
        ("declare @", 0.75),
        ("exec(", 0.65),
        ("exec sp_", 0.85),
    ];
    PATTERNS
        .iter()
        .filter(|(kw, _)| lower.contains(kw))
        .map(|(_, w)| *w)
        .fold(0.0f32, f32::max)
}

/// Maximum-weight XSS keyword score ∈ [0, 1].
fn xss_keyword_score(lower: &str) -> f32 {
    const PATTERNS: &[(&str, f32)] = &[
        ("<script", 0.90),
        ("javascript:", 0.85),
        ("vbscript:", 0.90),
        ("onerror=", 0.85),
        ("onload=", 0.80),
        ("onclick=", 0.70),
        ("onmouseover=", 0.70),
        ("onfocus=", 0.70),
        ("eval(", 0.75),
        ("alert(", 0.70),
        ("document.cookie", 0.90),
        ("document.write(", 0.80),
        ("innerhtml", 0.70),
        ("<iframe", 0.80),
        ("<svg", 0.60),
        ("expression(", 0.70),
        ("data:text/html", 0.85),
        ("data:application/x-www-form-urlencoded", 0.40),
        ("fromcharcode(", 0.80),
        ("String.fromCharCode", 0.75),
    ];
    PATTERNS
        .iter()
        .filter(|(kw, _)| lower.contains(kw))
        .map(|(_, w)| *w)
        .fold(0.0f32, f32::max)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[allow(clippy::unnecessary_to_owned)] // Uri::from_maybe_shared needs an owned 'static arg
    fn ctx_from_uri(uri: &str) -> RequestContext {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut ctx = RequestContext::new(ip, 1234);
        // For tests, use from_maybe_shared which is lenient on some chars,
        // otherwise default to root.
        ctx.uri = http::Uri::from_maybe_shared(uri.to_string()).unwrap_or_default();
        ctx
    }

    #[test]
    fn clean_request_scores_near_zero() {
        let ctx = ctx_from_uri("http://example.com/products?page=2&sort=price");
        let fv = FeatureVector::extract(&ctx);
        assert_eq!(fv.values[idx::METHOD_GET], 1.0);
        assert_eq!(fv.values[idx::SQL_KEYWORD_SCORE], 0.0);
        assert_eq!(fv.values[idx::XSS_KEYWORD_SCORE], 0.0);
        assert!(fv.values[idx::URL_LEN] > 0.0);
    }

    #[test]
    fn sqli_detected_in_query_string() {
        let ctx =
            ctx_from_uri("http://example.com/item?id=1%27%20UNION%20SELECT%20*%20FROM%20users");
        let fv = FeatureVector::extract(&ctx);
        assert!(
            fv.values[idx::SQL_KEYWORD_SCORE] > 0.5 || fv.values[idx::PCT_ENCODED_COUNT] > 0.0,
            "should flag UNION SELECT or percent-encoding"
        );
    }

    #[test]
    fn xss_detected_in_query_string() {
        let ctx = ctx_from_uri("http://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
        let fv = FeatureVector::extract(&ctx);
        assert!(
            fv.values[idx::XSS_KEYWORD_SCORE] > 0.5 || fv.values[idx::PCT_ENCODED_COUNT] > 0.0,
            "should flag <script> or percent-encoding"
        );
    }

    #[test]
    fn raw_xss_detected() {
        // Percent-encode the <script> tag so Uri parser accepts it.
        let ctx = ctx_from_uri("http://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
        let fv = FeatureVector::extract(&ctx);
        assert!(
            fv.values[idx::XSS_KEYWORD_SCORE] > 0.5,
            "encoded <script> must score high after percent-decode, got {}",
            fv.values[idx::XSS_KEYWORD_SCORE]
        );
    }

    #[test]
    fn raw_sqli_detected() {
        let ctx =
            ctx_from_uri("http://example.com/page?id=1%27%20UNION%20SELECT%20*%20FROM%20users");
        let fv = FeatureVector::extract(&ctx);
        assert!(
            fv.values[idx::SQL_KEYWORD_SCORE] > 0.5,
            "UNION SELECT must score high after decode, got {}",
            fv.values[idx::SQL_KEYWORD_SCORE]
        );
    }

    #[test]
    fn all_values_in_unit_interval() {
        let ctx = ctx_from_uri("http://example.com/api/v2/users?sort=name&order=asc");
        let fv = FeatureVector::extract(&ctx);
        for (i, v) in fv.values.iter().enumerate() {
            assert!(*v >= 0.0 && *v <= 1.0, "feature[{i}] = {v} out of [0,1]");
        }
    }

    #[test]
    fn log_scale_saturates() {
        assert!(
            log_scale(1_000_000, 2048) <= 1.2,
            "log-scale should not blow up"
        );
    }
}
