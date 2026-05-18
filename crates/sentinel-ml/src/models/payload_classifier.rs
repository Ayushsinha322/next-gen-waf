//! Payload Classifier — multi-category attack-pattern scoring.
//!
//! Scores a request against six attack families using word-list heuristics:
//! SQL injection, XSS, path traversal, command injection, encoding abuse,
//! and header injection.
//!
//! Each category returns a continuous score ∈ [0, 1].  The final combined
//! score is a sigmoid over the weighted sum, producing a probability that the
//! request contains an attack payload.
//!
//! Unlike the rule engine's binary match/no-match, this classifier produces
//! a *confidence* — useful for ranking alerts and auto-tuning the anomaly
//! threshold.

use super::super::features::FeatureVector;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fixed-weight payload classifier using keyword-based attack detection.
#[derive(Debug, Clone)]
pub struct PayloadClassifier {
    /// Sigmoid steepness — higher = sharper threshold.
    pub steepness: f32,
}

impl Default for PayloadClassifier {
    fn default() -> Self {
        Self { steepness: 4.0 }
    }
}

impl PayloadClassifier {
    /// Compute the combined attack probability ∈ [0, 1].
    ///
    /// Uses the max category score (dominant signal) plus the sum of all
    /// categories (breadth signal), passed through a sigmoid.
    pub fn score(&self, fv: &FeatureVector) -> f32 {
        // Each category ∈ [0, 1], extracted from the keyword scores already
        // computed during feature extraction, plus additional patterns.
        let sqli = fv.values[super::super::features::idx::SQL_KEYWORD_SCORE];
        let xss = fv.values[super::super::features::idx::XSS_KEYWORD_SCORE];
        let path_trav = path_traversal_score(fv);
        let cmd_inj = command_injection_score(fv);
        let enc_abuse = encoding_abuse_score(fv);
        let header_inj = 0.0; // header injection detected at Phase 1, not body

        let max_cat = sqli.max(xss).max(path_trav).max(cmd_inj).max(enc_abuse);
        let sum_cat = sqli + xss + path_trav + cmd_inj + enc_abuse + header_inj;

        // Score = sigmoid(steepness * (max + 0.3 * sum - 0.5))
        // The 0.5 offset is the decision boundary; max + sum push it over.
        sigmoid(self.steepness * (max_cat + 0.3 * sum_cat - 0.5))
    }

    /// Return per-category scores for diagnostic use.
    pub fn category_scores(&self, fv: &FeatureVector) -> CategoryScores {
        CategoryScores {
            sqli: fv.values[super::super::features::idx::SQL_KEYWORD_SCORE],
            xss: fv.values[super::super::features::idx::XSS_KEYWORD_SCORE],
            path_traversal: path_traversal_score(fv),
            command_injection: command_injection_score(fv),
            encoding_abuse: encoding_abuse_score(fv),
            header_injection: 0.0,
        }
    }
}

/// Per-category continuous scores ∈ [0, 1].
#[derive(Debug, Clone)]
pub struct CategoryScores {
    pub sqli: f32,
    pub xss: f32,
    pub path_traversal: f32,
    pub command_injection: f32,
    pub encoding_abuse: f32,
    pub header_injection: f32,
}

// ---------------------------------------------------------------------------
// Category detectors
// ---------------------------------------------------------------------------

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Path traversal score based on URI path patterns.
fn path_traversal_score(fv: &FeatureVector) -> f32 {
    // The URI features already capture path depth and special chars.
    // Extra boost when both path depth is high AND special-char density is high.
    let depth = fv.values[super::super::features::idx::PATH_DEPTH];
    let spec_uri = fv.values[super::super::features::idx::SPECIAL_CHAR_DENSITY_URI];
    let pct = fv.values[super::super::features::idx::PCT_ENCODED_COUNT];
    (depth * spec_uri * 2.0 + pct * spec_uri).min(1.0)
}

/// Command-injection score based on body special-char density + entropy.
fn command_injection_score(fv: &FeatureVector) -> f32 {
    let spec_body = fv.values[super::super::features::idx::SPECIAL_CHAR_DENSITY_BODY];
    let entropy = fv.values[super::super::features::idx::ENTROPY_BODY];
    let body_len = fv.values[super::super::features::idx::BODY_LEN];
    // High entropy + high special char + short body → suspicious (cmd is terse).
    (entropy * spec_body * (1.0 - body_len.min(0.5))).min(1.0)
}

/// Encoding-abuse score: heavy percent-encoding combined with high entropy.
fn encoding_abuse_score(fv: &FeatureVector) -> f32 {
    let pct = fv.values[super::super::features::idx::PCT_ENCODED_COUNT];
    let entropy_uri = fv.values[super::super::features::idx::ENTROPY_URI];
    (pct * 2.0 * entropy_uri).min(1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::context::RequestContext;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_from_str(uri: &str) -> RequestContext {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        ctx.uri = uri.parse().unwrap_or_else(|_| http::Uri::from_static("/"));
        ctx
    }

    #[test]
    fn clean_request_scores_low() {
        let cls = PayloadClassifier::default();
        let ctx = ctx_from_str("http://example.com/products?page=1&sort=price");
        let fv = FeatureVector::extract(&ctx);
        let s = cls.score(&fv);
        assert!(s < 0.5, "clean request scored {s}");
    }

    #[test]
    fn sqli_scores_high() {
        let cls = PayloadClassifier::default();
        // Percent-encode the SQLi payload so Uri parses it.
        let mut ctx = ctx_from_str("http://example.com/item");
        ctx.uri = "http://example.com/item?id=1%27%20UNION%20SELECT%20*%20FROM%20users%20--"
            .parse()
            .unwrap();
        let fv = FeatureVector::extract(&ctx);
        let s = cls.score(&fv);
        assert!(s > 0.5, "SQLi request scored {s}");
    }

    #[test]
    fn xss_scores_high() {
        let cls = PayloadClassifier::default();
        let mut ctx = ctx_from_str("http://example.com/search");
        ctx.uri = "http://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            .parse()
            .unwrap();
        let fv = FeatureVector::extract(&ctx);
        let s = cls.score(&fv);
        assert!(s > 0.5, "XSS request scored {s}");
    }

    #[test]
    fn category_scores_bounded() {
        let cls = PayloadClassifier::default();
        let mut ctx = ctx_from_str("http://example.com/search");
        ctx.uri = "http://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E%20%26%26%20..%2F..%2Fetc%2Fpasswd%20%26%26%20cmd%3Dls"
            .parse()
            .unwrap();
        let fv = FeatureVector::extract(&ctx);
        let cats = cls.category_scores(&fv);
        assert!((0.0..=1.0).contains(&cats.sqli));
        assert!((0.0..=1.0).contains(&cats.xss));
        assert!((0.0..=1.0).contains(&cats.path_traversal));
        assert!((0.0..=1.0).contains(&cats.command_injection));
        assert!((0.0..=1.0).contains(&cats.encoding_abuse));
    }
}
