//! Payload Classifier — a *trained* logistic-regression attack detector.
//!
//! The classifier is a [`LogisticRegression`] model whose weights are learned
//! by gradient descent from the bundled labeled [`corpus`], over the full
//! 25-dimensional [`FeatureVector`] (lengths, entropy, special-char density,
//! percent-encoding, method, keyword scores, …).  Because it learns over the
//! whole vector — not just keyword hits — it can flag attacks that evade the
//! keyword lists via high entropy / encoding-abuse / structural anomalies.
//!
//! Training is deterministic and runs once (cached in a `Lazy`), so every
//! engine instance shares the same reproducible model.  Inference is a single
//! dot product + sigmoid.
//!
//! Unlike the rule engine's binary match/no-match, this classifier produces a
//! *confidence* ∈ [0, 1] — useful for ranking alerts and auto-tuning the
//! anomaly threshold.  See `tests/ml_validation.rs` for measured FPR/FNR.

use once_cell::sync::Lazy;

use super::super::features::FeatureVector;
use super::corpus::corpus_xy;
use super::logistic::{LogisticRegression, TrainConfig};

/// The payload classifier model, trained once from the bundled corpus, then
/// augmented with the threat-intel prior (see [`apply_threat_intel_prior`]).
static TRAINED_MODEL: Lazy<LogisticRegression> = Lazy::new(|| {
    let (x, y) = corpus_xy();
    let mut model = LogisticRegression::fit(&x, &y, TrainConfig::default());
    apply_threat_intel_prior(&mut model);
    model
});

/// Fixed prior weight for the `MATCHES_THREAT_INTEL` feature. The bundled corpus
/// is payload-only, so it cannot teach a weight for this *runtime* signal (and
/// L2 would drive an untaught weight toward 0). We instead set a strong positive
/// weight post-training: with the feature at 1.0 the logit gains +4.0, pushing
/// σ(·) ≳ 0.98 so the classifier treats any feed-matched request as an attack.
/// For all corpus / normal traffic the feature is 0.0, so `0 · w = 0` changes no
/// existing score and leaves the validation metrics untouched.
const THREAT_INTEL_PRIOR_WEIGHT: f32 = 4.0;

/// Overwrite the learned weight of the threat-intel feature with the fixed prior.
fn apply_threat_intel_prior(model: &mut LogisticRegression) {
    use super::super::features::idx;
    if let Some(w) = model.weights.get_mut(idx::MATCHES_THREAT_INTEL) {
        *w = THREAT_INTEL_PRIOR_WEIGHT;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Trained logistic-regression payload classifier.
#[derive(Debug, Clone)]
pub struct PayloadClassifier {
    model: LogisticRegression,
}

impl Default for PayloadClassifier {
    fn default() -> Self {
        // Share the globally-trained model (cheap clone of the weight vector).
        Self {
            model: TRAINED_MODEL.clone(),
        }
    }
}

impl PayloadClassifier {
    /// Train a fresh classifier from an explicit dataset.  Used by the
    /// validation harness to train on a held-out split.
    pub fn from_dataset(x: &[Vec<f32>], y: &[f32]) -> Self {
        Self {
            model: LogisticRegression::fit(x, y, TrainConfig::default()),
        }
    }

    /// Compute the attack probability ∈ [0, 1] for a request.
    pub fn score(&self, fv: &FeatureVector) -> f32 {
        self.model.predict_proba(fv.as_slice())
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
// Category detectors (diagnostic breakdown for alerts/dashboard; the trained
// model above is what actually scores the request)
// ---------------------------------------------------------------------------

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
    fn threat_intel_hit_scores_as_attack() {
        use super::super::super::features::{idx, FeatureVector};
        let cls = PayloadClassifier::default();

        // An otherwise-benign feature vector (all zeros) that only carries the
        // threat-intel flag must score as a near-certain attack — the whole
        // point of the injected prior.
        let benign = cls.score(&FeatureVector::default());
        let mut fv = FeatureVector::default();
        fv.values[idx::MATCHES_THREAT_INTEL] = 1.0;
        let hit = cls.score(&fv);

        assert!(hit > 0.85, "threat-intel hit must score high, got {hit}");
        assert!(hit > benign + 0.3, "hit ({hit}) must far exceed benign ({benign})");
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
