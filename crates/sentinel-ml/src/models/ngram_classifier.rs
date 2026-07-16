//! Hashed char-n-gram payload classifier — the additive ML detector.
//!
//! A logistic-regression model over binary char-n-gram features, trained
//! offline on a labeled corpus (HttpParamsDataset + adversarial-benign
//! augmentation) and embedded here. The featurizer below (normalize → byte
//! n-grams → FNV-1a hash → presence) is BYTE-IDENTICAL to the Python trainer
//! (`train_ml2.py`), so train-time and inference-time features match exactly.
//!
//! Unlike the 25-feature logistic model (which relied on keyword scalars and so
//! could not tell "SELECT in prose" from real SQLi), this learns injection
//! STRUCTURE from character n-grams and generalizes to evasive payloads the
//! rules miss, while the adversarial-benign training keeps false positives low.

use once_cell::sync::Lazy;
use serde::Deserialize;

#[derive(Deserialize)]
struct NgramModel {
    k: usize,
    ngrams: Vec<usize>,
    bias: f32,
    weights: Vec<f32>,
}

/// The embedded model, parsed once. `None` if the embedded JSON is malformed.
static MODEL: Lazy<Option<NgramModel>> = Lazy::new(|| {
    const RAW: &str = include_str!("../../model/payload_ngram.json");
    match serde_json::from_str::<NgramModel>(RAW) {
        Ok(m) if m.weights.len() == m.k && !m.ngrams.is_empty() => Some(m),
        Ok(_) => {
            tracing::warn!("ngram model: k/weights length mismatch — classifier disabled");
            None
        }
        Err(e) => {
            tracing::warn!("ngram model parse failed: {e} — classifier disabled");
            None
        }
    }
});

/// FNV-1a 32-bit — identical to the Python trainer.
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Whether the embedded model loaded successfully.
pub fn is_loaded() -> bool {
    MODEL.is_some()
}

/// Attack probability ∈ [0, 1] for a single field/value string. Returns `None`
/// if the model failed to load (caller falls back to the legacy classifier).
///
/// Normalization MUST match the trainer: lowercase (UTF-8 bytes), char n-grams
/// over bytes, FNV-1a % k, binary presence (each bucket counted once).
pub fn score_text(text: &str) -> Option<f32> {
    let m = MODEL.as_ref()?;
    let lower = text.to_lowercase();
    let b = lower.as_bytes();
    let n = b.len();
    if n == 0 {
        return Some(sigmoid(m.bias));
    }
    let mut active = vec![false; m.k];
    let mut logit = m.bias;
    for &ng in &m.ngrams {
        if n < ng {
            continue;
        }
        for i in 0..=(n - ng) {
            let bucket = (fnv1a(&b[i..i + ng]) % m.k as u32) as usize;
            if !active[bucket] {
                active[bucket] = true;
                logit += m.weights[bucket];
            }
        }
    }
    Some(sigmoid(logit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_loads() {
        assert!(is_loaded(), "embedded ngram model must parse");
    }

    #[test]
    fn sqli_scores_higher_than_benign() {
        let attack = score_text("1' union select username,password from users--").unwrap();
        let benign = score_text("please select your preferred shipping option").unwrap();
        assert!(
            attack > 0.5,
            "structural SQLi should score high, got {attack}"
        );
        assert!(
            attack > benign,
            "attack ({attack}) must exceed benign prose ({benign})"
        );
    }

    #[test]
    fn xss_scores_high() {
        let s = score_text("<script>alert(document.cookie)</script>").unwrap();
        assert!(s > 0.5, "XSS should score high, got {s}");
    }
}
