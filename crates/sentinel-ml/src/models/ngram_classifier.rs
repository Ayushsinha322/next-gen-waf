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

/// Decode common HTML entities (`&lt;`, `&#60;`, `&#x3c;`) — attackers entity-
/// encode `<script>`/`'`/`"` to slip past detectors that match on the raw
/// character. Returns `None` when nothing decoded, so callers only re-score
/// when a transform actually changed the text.
fn html_entity_decode(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut changed = false;
    while i < cs.len() {
        if cs[i] == '&' {
            let limit = 12.min(cs.len() - i - 1);
            if let Some(semi) = (2..=limit).find(|&j| cs[i + j] == ';') {
                let ent: String = cs[i + 1..i + semi].iter().collect();
                if let Some(ch) = decode_entity(&ent) {
                    out.push(ch);
                    i += semi + 1;
                    changed = true;
                    continue;
                }
            }
        }
        out.push(cs[i]);
        i += 1;
    }
    if changed {
        Some(out)
    } else {
        None
    }
}

/// One HTML entity (numeric `#60`/`#x3c` or a common named entity) → char.
fn decode_entity(ent: &str) -> Option<char> {
    if let Some(num) = ent.strip_prefix('#') {
        let cp = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse::<u32>().ok()?,
        };
        return char::from_u32(cp);
    }
    Some(match ent {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        "colon" => ':',
        "lpar" => '(',
        "rpar" => ')',
        "sol" => '/',
        "equals" => '=',
        "grave" => '`',
        _ => return None,
    })
}

/// Percent-decode repeatedly (up to 3 passes) to unwrap double/triple URL-
/// encoding (`%253Cscript%253E` → `%3Cscript%3E` → `<script>`). Returns `None`
/// when the text was not percent-encoded.
fn recursive_percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }
    let mut cur = s.to_string();
    let mut changed = false;
    for _ in 0..3 {
        if !cur.contains('%') {
            break;
        }
        let dec = percent_encoding::percent_decode_str(&cur)
            .decode_utf8_lossy()
            .into_owned();
        if dec == cur {
            break;
        }
        cur = dec;
        changed = true;
    }
    if changed {
        Some(cur)
    } else {
        None
    }
}

/// Max attack score over the raw text and all of its decoded variants —
/// Base64, HTML-entity, recursive percent-decode, and percent-then-entity
/// (mixed encoding). Recursive normalization defeats the encoder-axis
/// evasions a single-pass detector misses; taking the max means an attack
/// hidden under any encoding is still caught. Each transform runs only when
/// its marker byte (`&`, `%`, Base64 shape) is present, so ordinary benign
/// values pay ~one extra branch.
pub fn score_all(text: &str) -> Option<f32> {
    let mut max = score_text(text)?;
    let mut variants: Vec<String> = Vec::new();
    if let Some(d) = maybe_base64_decode(text) {
        variants.push(d);
    }
    if let Some(d) = html_entity_decode(text) {
        variants.push(d);
    }
    if let Some(d) = recursive_percent_decode(text) {
        if let Some(e) = html_entity_decode(&d) {
            variants.push(e);
        }
        variants.push(d);
    }
    for v in &variants {
        if let Some(s) = score_text(v) {
            if s > max {
                max = s;
            }
        }
    }
    Some(max)
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

    #[test]
    fn html_entity_encoded_xss_caught_by_score_all() {
        // Entity-encoded `<script>alert(1)</script>` — raw form hides the tags.
        let raw = "&#60;script&#62;alert(1)&#60;/script&#62;";
        let all = score_all(raw).unwrap();
        assert!(
            all > 0.5,
            "entity-encoded XSS must be caught after normalization, got {all}"
        );
    }

    #[test]
    fn named_entity_decode_works() {
        assert_eq!(html_entity_decode("&lt;b&gt;").as_deref(), Some("<b>"));
        assert_eq!(html_entity_decode("no entities here"), None);
    }

    #[test]
    fn double_url_encoded_caught_by_score_all() {
        // `%253Cscript%253E...` → two percent passes → `<script>...`.
        let raw = "%253Cscript%253Ealert(1)%253C%252Fscript%253E";
        let all = score_all(raw).unwrap();
        assert!(
            all > score_text(raw).unwrap(),
            "recursive percent-decode must raise the score above the raw form"
        );
        assert!(all > 0.5, "double-encoded XSS must be caught, got {all}");
    }

    #[test]
    fn recursive_percent_decode_unwraps_double() {
        assert_eq!(
            recursive_percent_decode("%253Cscript%253E").as_deref(),
            Some("<script>")
        );
        assert_eq!(recursive_percent_decode("plain text"), None);
    }
}
