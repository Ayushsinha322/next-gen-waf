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
                if !seg.is_empty() && !is_plain_path_word(seg) {
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
            // Header values (Header/UserAgent placements) and each cookie value
            // separately (Cookie placement).
            //
            // The classifier must see every value the rules inspect. It is consulted
            // not only additively but as a precision VETO that can suppress a rule
            // block, and a veto based on data it never saw is blind: a header-borne
            // payload scores ~0 ("nothing here looks like an attack") and suppresses
            // a correct block from the all-placement libinjection rules, which are
            // the only coverage for arbitrary headers. Measured before this was
            // added: `X-Custom: <script>alert(1)</script>` bypassed entirely.
            //
            // This is only safe because the model was retrained on ordinary header
            // values. `payload_attack` is a MAX over candidates, so a routine header
            // scoring high would pin every request above the suppression cutoff and
            // silently disable FP suppression — the previous model scored a plain
            // `Accept: text/html,...` at 0.897, which would have done exactly that.
            //
            // Decoded lossily, as the rules read them: `to_str()` refused any byte
            // >= 0x80, so one such byte hid the whole header from the classifier
            // while the rules still matched it — exactly the blind veto above.
            for (name, value) in ctx.request_headers.iter() {
                let v = String::from_utf8_lossy(value.as_bytes());
                if is_plain_locator(&v) {
                    continue;
                }
                if name == http::header::COOKIE {
                    for c in v.split(';') {
                        let val = c.split_once('=').map(|(_, x)| x).unwrap_or(c).trim();
                        if !val.is_empty() {
                            candidates.push(val.to_string());
                        }
                    }
                } else if !v.is_empty() {
                    candidates.push(v.to_string());
                }
            }
            // Request body (Body/JSON/form/multipart placements).
            if let Some(body) = ctx.request_body.as_ref() {
                if let Ok(bs) = std::str::from_utf8(body.as_ref()) {
                    // Also score each PARSED, DECODED field value. Scoring only the
                    // whole raw body misses attacks carried in a form/multipart
                    // field: a URL- or Base64-encoded payload sits inside the
                    // envelope, so the wholly-encoded field never decodes (its
                    // marker is diluted by boundaries/`key=`) and slips past. Per-
                    // field candidates let score_all decode each value on its own.
                    let ct = ctx
                        .request_headers
                        .get(http::header::CONTENT_TYPE)
                        .map(|v| String::from_utf8_lossy(v.as_bytes()))
                        .unwrap_or_default();
                    let ct: &str = &ct;
                    // The whole raw body is a candidate only when it did NOT parse
                    // into fields. Scored whole, a well-formed JSON document is
                    // judged on its punctuation: `{"items":[{"id":1,…}],"note":
                    // "deliver after 6pm; ring twice"}` scored 0.905 — over the
                    // detection threshold, so the classifier ALONE blocked an
                    // ordinary basket update — while every field in it scored
                    // under 0.01. When the body parses, each field and key is
                    // already a candidate; a body that does not parse (malformed
                    // JSON, unknown type) is still scored whole.
                    if !body_field_values(bs, ct, &mut candidates) {
                        candidates.push(bs.to_string());
                    }
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
/// Push every scalar in a JSON document, so each field can be decoded and
/// scored on its own rather than being diluted inside the envelope.
///
/// Keys are pushed too: a payload can be carried in a field NAME, and the rule
/// engine inspects ARGS_NAMES for exactly that reason.
fn json_scalar_values(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if !k.is_empty() {
                    out.push(k.clone());
                }
                json_scalar_values(val, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                json_scalar_values(val, out);
            }
        }
        serde_json::Value::String(s) if !s.is_empty() => out.push(s.clone()),
        serde_json::Value::Number(n) => out.push(n.to_string()),
        // Bools and nulls carry no payload.
        _ => {}
    }
}

/// Longest segment treated as a plain word rather than scored.
const MAX_PLAIN_PATH_WORD: usize = 20;

/// A path segment that is one SHORT plain word — at most MAX_PLAIN_PATH_WORD
/// letters, digits and `-_.~`, with no `..` — and so cannot carry an injection
/// by itself.
///
/// Scoring such segments let the classifier block on vocabulary: `whoami` alone
/// scores 0.922, over the detection threshold, so `GET /rest/user/whoami` (an
/// ordinary Juice Shop endpoint) was blocked by the model with no rule behind
/// it. A segment with any metacharacter, encoding (`%`), traversal (`..`) or
/// markup is still scored.
fn is_plain_path_word(seg: &str) -> bool {
    // Short only. A long run of word characters is not a word: Base64 of an
    // attack is letters and digits too, and skipping it let 21 Base64Flat
    // GoTestWAF payloads through in the URL path (1.1.7 regression). Real path
    // words and ids — `whoami`, `products`, `v1`, a numeric id — are short.
    seg.len() <= MAX_PLAIN_PATH_WORD
        // …and not Base64 of readable text. `(alert)(1)` encodes to 14
        // characters, so length alone let two short payloads through; a real
        // word "decodes" to binary noise, which maybe_base64_decode rejects.
        && models::ngram_classifier::maybe_base64_decode(seg).is_none()
        && !seg.contains("..")
        && seg.chars().any(|c| c.is_ascii_alphanumeric())
        && seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

/// A header value that only names a place: a host (`shop.example.in`,
/// `test-site.local:8443`, an IPv4 address) or an http(s) URL with no query and
/// nothing but host and path characters (`https://shop.example.in/cart`).
///
/// Such a value cannot carry an injection payload, and Host, Origin and a
/// same-site Referer are the same on most requests to a site — so as a
/// classifier candidate it decided the veto for the whole site.
/// `test-site.local` scores 0.505 and `my-test-app.internal` 0.513, just over
/// the 0.5 cut-off, so no weak block on such a site could ever be vetoed; and
/// `http://localhost:3000/` scores 0.909, enough to block a request alone. A
/// value with anything else in it — a quote, a space, a query, `..` — is still
/// scored.
fn is_plain_locator(v: &str) -> bool {
    let v = v.trim();
    let (rest, url) = match v
        .strip_prefix("https://")
        .or_else(|| v.strip_prefix("http://"))
    {
        Some(r) => (r, true),
        None => (v, false),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) if url => (&rest[..i], &rest[i..]),
        Some(_) => return false,
        None => (rest, ""),
    };
    let host = match authority.rsplit_once(':') {
        Some((h, port))
            if !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            h
        }
        Some(_) => return false,
        None => authority,
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && (host.contains('.') || host.eq_ignore_ascii_case("localhost"))
        && !host.starts_with(['.', '-']);
    let path_ok = path.len() <= 512
        && !path.contains("..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_' | b'~'));
    host_ok && path_ok
}

/// Pushes each field value of a form, JSON or multipart body. Returns whether
/// the body was parsed into fields (so the caller need not score it whole).
fn body_field_values(body: &str, content_type: &str, out: &mut Vec<String>) -> bool {
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
        true
    } else if ct.starts_with("application/json") || ct.contains("+json") {
        // JSON was missing here, and that was a measured bypass on 2026-09-15.
        //
        // The comment on the caller explains why per-field candidates exist at
        // all: a wholly-encoded value sits inside an envelope, so decoding the
        // envelope as one string never reaches it. That reasoning applies to
        // JSON exactly as it does to form and multipart bodies, and JSON was
        // simply left out.
        //
        // The consequence was not a missed score, it was a WRONG VETO. A
        // base64'd MSSQL stacked query in `{"q":"MzsvKi…"}` fired the
        // libinjection rule for precisely the threshold score. The only
        // candidate the classifier received was the whole body string, which is
        // not itself base64, so `score_all` had nothing to decode and returned
        // ~0 — "no attack here". `apply_verdict` read that as benign evidence
        // and suppressed the block, and the payload reached the application.
        // The identical payload in a query parameter was blocked, because query
        // values ARE split out per field. Whether an attack was stopped depended
        // on which body format carried it.
        //
        // Malformed JSON falls through deliberately: the caller has already
        // pushed the raw body as a candidate, so nothing is lost by not
        // guessing at a broken document.
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(v) => {
                json_scalar_values(&v, out);
                true
            }
            Err(_) => false,
        }
    } else if let Some(pos) = ct.find("multipart/form-data") {
        // Boundary token from `; boundary=...`.
        let Some(b) = ct[pos..]
            .find("boundary=")
            .map(|i| pos + i + "boundary=".len())
            .map(|i| content_type[i..].trim().trim_matches('"'))
        else {
            return false;
        };
        if b.is_empty() {
            return false;
        }
        let before = out.len();
        let delim = format!("--{b}");
        // One fragment allowance for the whole body (see header_param_values).
        // One per part let every ~1 KB part of a body spend 64 KiB.
        let mut fragment_budget = body.len().saturating_mul(4).saturating_add(64 * 1024);
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
                // The part's own header parameters — `name=` and above all
                // `filename=` — are attacker-chosen too. They were only ever seen
                // inside the whole raw body; once a parsed body stopped being
                // scored whole, `filename="/static/img/../../etc/passwd"` got
                // through (GoTestWAF community-lfi-multipart, 2/2).
                for param in ["filename=", "name="] {
                    header_param_values(&part[..idx], param, &mut fragment_budget, out);
                }
            }
        }
        out.len() > before
    } else {
        false
    }
}

/// Pushes the values of `param` (`name=`, `filename=`) found in one multipart
/// part's header block.
///
/// The scan resumes just past each `param`, so it also finds one INSIDE a value
/// it has read: `name="…fname=|/bin/id"` yields the fragment `|/bin/id"` too,
/// and the classifier can score such a fragment far above the whole value —
/// 0.55 against 0.07 on a scanner-corpus line, either side of the veto line.
/// Each fragment, though, is a copy running to the end of the value, so
/// `name=name=name=…` copied the block once per repetition: 409 MB of
/// candidates from 64 KB, and the search for each value's end was quadratic
/// too. So the two kinds are told apart. A PARAMETER value — one starting
/// where the previous value ended — is always kept, and those add up to at
/// most the block. Whole fragments draw on `fragment_budget`, one allowance
/// for every header block of the body (four times the body plus 64 KiB); the
/// most any of 1.6 M corpus-built headers spends is 2.7 KB. Past it a
/// fragment is CUT at the next `param`, never dropped: those pieces do not
/// overlap, so they add up to at most the block, and the last one, the text
/// after the final `param`, is always whole. Dropping them let junk earlier
/// in the body decide which fragment the classifier never saw. Each value's
/// end is found once per stretch (`NextHit`).
fn header_param_values(
    block: &str,
    param: &str,
    fragment_budget: &mut usize,
    out: &mut Vec<String>,
) {
    let b = block.as_bytes();
    let mut quote = NextHit::new(b, |c| c == b'"');
    let mut delim = NextHit::new(b, |c| matches!(c, b';' | b'\r' | b'\n'));
    // Where the last parameter value (not fragment) ended.
    let mut value_end = 0;
    let mut next = block.find(param);
    while let Some(at) = next {
        let start = at + param.len();
        // Looked up before this value is read: a fragment cut short ends there.
        next = block[start..].find(param).map(|rel| start + rel);
        let quoted = b.get(start) == Some(&b'"');
        // The value's span before trimming, and where it ends (past a closing
        // quote).
        let (first, mut stop, end) = if quoted {
            let close = quote.at_or_after(start + 1);
            (start + 1, close, (close + 1).min(b.len()))
        } else {
            let stop = delim.at_or_after(start);
            (start, stop, stop)
        };
        if at >= value_end {
            value_end = end;
        } else if stop - first <= *fragment_budget {
            *fragment_budget -= stop - first;
        } else if let Some(cut) = next {
            stop = stop.min(cut.max(first));
        }
        let raw = &block[first..stop];
        let v = if quoted { raw } else { raw.trim() };
        if !v.is_empty() {
            out.push(v.to_string());
        }
    }
}

/// The next byte satisfying `hit` at or after a position, for positions that
/// never decrease: an answer is reused until the position passes it, so each
/// byte is examined once in all, however many values share an end.
struct NextHit<'a, F: Fn(u8) -> bool> {
    b: &'a [u8],
    hit: F,
    /// Where the last search started; no hit lies in `searched_from..found`.
    searched_from: usize,
    /// The hit it found, or `b.len()` for none.
    found: usize,
}

impl<'a, F: Fn(u8) -> bool> NextHit<'a, F> {
    fn new(b: &'a [u8], hit: F) -> Self {
        Self {
            b,
            hit,
            searched_from: usize::MAX,
            found: 0,
        }
    }

    fn at_or_after(&mut self, pos: usize) -> usize {
        if !(self.searched_from <= pos && pos <= self.found) {
            let hit = &self.hit;
            self.found = self.b[pos..]
                .iter()
                .position(|&c| hit(c))
                .map_or(self.b.len(), |i| pos + i);
            self.searched_from = pos;
        }
        self.found
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

#[cfg(test)]
mod json_candidate_tests {
    use super::body_field_values;
    use std::time::{Duration, Instant};

    /// JSON bodies were absent from `body_field_values`, and the cost was not a
    /// missed score but a WRONG VETO: the classifier only ever saw the whole
    /// body string, which is not itself base64, so an encoded payload inside a
    /// field decoded to nothing and scored ~0. `apply_verdict` read that as
    /// "no attack here" and suppressed a correct libinjection block.
    #[test]
    fn json_bodies_yield_per_field_candidates() {
        let mut out = Vec::new();
        body_field_values(
            r#"{"q":"MzsvKiBhICovIERFQ0xBUkU=","nested":{"deep":"payload"},"arr":["a","b"],"n":42}"#,
            "application/json",
            &mut out,
        );
        // Each scalar must arrive on its own so score_all can decode it.
        assert!(out.iter().any(|c| c == "MzsvKiBhICovIERFQ0xBUkU="));
        assert!(out.iter().any(|c| c == "payload"));
        assert!(out.iter().any(|c| c == "a") && out.iter().any(|c| c == "b"));
        assert!(out.iter().any(|c| c == "42"));
        // Keys count: a payload can be carried in a field name, which is why
        // the rule engine inspects ARGS_NAMES.
        assert!(out.iter().any(|c| c == "q"));
        assert!(out.iter().any(|c| c == "nested"));
    }

    #[test]
    fn json_variant_content_types_are_handled() {
        let mut out = Vec::new();
        body_field_values(r#"{"a":"x"}"#, "application/vnd.api+json", &mut out);
        assert!(out.iter().any(|c| c == "x"), "+json suffix must be parsed");
    }

    /// Malformed JSON must not panic or invent candidates. The caller has
    /// already pushed the raw body, so nothing is lost by declining to guess.
    #[test]
    fn malformed_json_yields_nothing_rather_than_guessing() {
        let mut out = Vec::new();
        body_field_values(r#"{"a":"unterminated"#, "application/json", &mut out);
        assert!(out.is_empty());
    }

    /// The other two body formats must keep working exactly as before.
    #[test]
    fn form_and_multipart_are_unchanged() {
        let mut out = Vec::new();
        body_field_values(
            "q=1%20OR%201%3D1--&z=ok",
            "application/x-www-form-urlencoded",
            &mut out,
        );
        assert!(out.iter().any(|c| c == "1 OR 1=1--"));

        let mut out2 = Vec::new();
        let body = "--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nvalue-here\r\n--B--";
        body_field_values(body, "multipart/form-data; boundary=B", &mut out2);
        assert!(out2.iter().any(|c| c.contains("value-here")));
    }

    /// A multipart header parameter's value was searched again for the next
    /// `name=`, so `name=name=name=…` copied a suffix of the header block per
    /// repetition — quadratic: 409 MB of candidates from a 64 KB block, about
    /// 100 GB from 1 MB, before the classifier scored any of it.
    #[test]
    fn multipart_header_parameters_are_read_in_linear_time() {
        let multipart = |headers: &str| {
            let body =
                format!("--B\r\nContent-Disposition: form-data; {headers}\r\n\r\nv\r\n--B--");
            let mut out = Vec::new();
            body_field_values(&body, "multipart/form-data; boundary=B", &mut out);
            (body.len(), out)
        };

        // Still every parameter, quoted or not, `filename=` included.
        let (_, out) = multipart("name=\"f\"; filename=\"../../etc/passwd\"; x=1");
        assert!(out.iter().any(|c| c == "f"), "{out:?}");
        assert!(out.iter().any(|c| c == "../../etc/passwd"), "{out:?}");
        let (_, out) = multipart("name=q ; filename=a.php");
        assert!(out.iter().any(|c| c == "q") && out.iter().any(|c| c == "a.php"));
        // A `name=` inside a value still yields its fragment, as it always
        // has: the classifier can score a fragment above the whole value.
        let (_, out) = multipart("name=\"x; name=y\"");
        assert!(out.iter().any(|c| c == "x; name=y"), "{out:?}");
        assert!(out.iter().any(|c| c == "y\""), "{out:?}");
        // A real parameter after a block built to multiply fragments is
        // still read.
        let (_, out) = multipart(&format!("{}; filename=\"evil.php\"", "name=".repeat(5000)));
        assert!(out.iter().any(|c| c == "evil.php"), "{out:?}");

        // Every parameter value (per kind, at most the body), cut-short
        // fragments (likewise) and whole fragments (at most four bodies plus
        // 64 KiB): bounded by the WHOLE body, however it is split into parts.
        let within_bound = |what: &str, len: usize, out: &[String], started: Instant| {
            let copied: usize = out.iter().map(String::len).sum();
            assert!(
                copied <= 10 * len + 128 * 1024,
                "{what}: {copied} bytes of candidates from {len}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{what} took {:?}",
                started.elapsed()
            );
        };

        // 16 KB first: the old scan copied ~26 MB there and failed before
        // reaching the megabyte, which would have needed about 100 GB.
        for size in [16 * 1024, 1 << 20] {
            for unit in ["name=", "name=\"\"", "filename=x;", "name= ", "name=\""] {
                let started = Instant::now();
                let (len, out) = multipart(&unit.repeat(size / unit.len()));
                within_bound(&format!("{unit:?} x {size} bytes"), len, &out, started);
            }
        }

        // The same spread over many parts. With a budget per header block,
        // each ~1 KB part could spend 64 KiB on fragments: 1 MB of them made
        // about 120 times the body in candidates (10 MiB, the default body
        // limit, 1.29 GB). The budget is per body.
        for (unit, reps) in [("filename=", 125), ("name=", 166), ("name=\"", 166)] {
            let started = Instant::now();
            let part = format!(
                "--B\r\nContent-Disposition: form-data; {}\r\n\r\nv\r\n",
                unit.repeat(reps)
            );
            let body = format!("{}--B--", part.repeat((1 << 20) / part.len()));
            let mut out = Vec::new();
            body_field_values(&body, "multipart/form-data; boundary=B", &mut out);
            let what = format!("{unit:?} x {reps} in each part of 1 MB");
            within_bound(&what, body.len(), &out, started);
        }
    }

    /// A fragment over the budget is cut short at the next parameter name,
    /// never dropped. Dropping it let the client choose what the classifier
    /// saw: 200 `name=` inside the name value spent the budget, the fragment
    /// `|/bin/id"` was skipped, and the request's score fell from 0.546 to
    /// 0.216 — under 0.5, where ml_vetoes_weak_block may suppress a rule block.
    #[test]
    fn a_fragment_over_the_budget_is_cut_short_not_dropped() {
        let attack = "filename=\"/cgi-bin/infosrch.cgi?cmd=getdoc&db=man&fname=|/bin/id\"";
        let part = |headers: &str| {
            format!("--B\r\nContent-Disposition: form-data; {headers}\r\n\r\nv\r\n")
        };
        let fragment_kept = |body: &str| {
            let mut out = Vec::new();
            body_field_values(body, "multipart/form-data; boundary=B", &mut out);
            out.iter().any(|c| c.starts_with("|/bin/id"))
        };

        // Junk in the same header block, at every count up to twice the one
        // that first lost the fragment (167).
        for junk in 0..400 {
            let headers = format!("name=\"{}\"; {attack}", "name=".repeat(junk));
            let body = format!("{}--B--", part(&headers));
            assert!(fragment_kept(&body), "lost after {junk} x name=");
        }
        // Junk in EARLIER parts: the budget belongs to the whole body, so they
        // can spend all of it before the part that matters.
        let junk = part(&"filename=".repeat(125)).repeat(900);
        let body = format!("{junk}{}--B--", part(&format!("name=\"f\"; {attack}")));
        assert!(fragment_kept(&body), "lost after 900 junk parts");
    }
}
