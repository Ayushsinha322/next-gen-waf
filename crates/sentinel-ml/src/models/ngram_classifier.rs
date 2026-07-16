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

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// If `s` is a wholly-Base64 string (standard or URL-safe, padding/whitespace
/// tolerated) that decodes to mostly-printable text, return the decoded string.
/// Used to defeat the Base64 encoder axis: attackers Base64-encode a payload so
/// the raw value looks like gibberish to detectors — decoding it and re-scoring
/// exposes the attack. Requiring the ENTIRE value to be Base64 + a printable
/// result keeps false-positives on ordinary values near zero.
pub fn maybe_base64_decode(s: &str) -> Option<String> {
    let t: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    if t.len() < 12 {
        return None; // too short to be a meaningful encoded payload
    }
    let mut vals = Vec::with_capacity(t.len());
    for &b in &t {
        vals.push(b64_val(b)?); // any non-Base64 char → not Base64, bail
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let mut buf = [0u8; 4];
        for (i, &v) in chunk.iter().enumerate() {
            buf[i] = v;
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if chunk.len() >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    let decoded = String::from_utf8_lossy(&out).into_owned();
    let printable = decoded
        .bytes()
        .filter(|b| b.is_ascii_graphic() || *b == b' ')
        .count();
    if decoded.is_empty() || printable * 100 < decoded.len() * 80 {
        return None; // binary garbage, not a text payload
    }
    Some(decoded)
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
