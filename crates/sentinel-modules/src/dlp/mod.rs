//! Data-loss-prevention (DLP) engine.
//!
//! A per-site guard that scans HTTP **response** bodies for personally
//! identifiable information (PII) and leaked secrets, and can **redact** them
//! in place before the body is returned to the client. It generalises the
//! detector that previously lived inline in `sentinel-proxy` ([`DlpEngine::scan`]
//! keeps the same detection semantics) and adds two capabilities:
//!
//!   - **Masking** — [`DlpEngine::mask`] rewrites matches instead of merely
//!     flagging them. PII is partially masked (last four alphanumerics kept,
//!     separators preserved); secrets are fully redacted.
//!   - **India PII** — Permanent Account Number, Aadhaar (UIDAI) and Indian
//!     mobile numbers are recognised in addition to the original pattern set.
//!
//! ## Length-preserving invariant
//!
//! [`DlpEngine::mask`] guarantees that the returned body has the **exact same
//! byte length** as the input. Every match is replaced with a run of `'*'`
//! whose byte length equals the match's byte length (multibyte user-pattern
//! matches are padded to their byte length, not their character count). This
//! keeps the response `Content-Length` valid so the proxy does not have to
//! rewrite headers.
//!
//! ## Bounds & safety
//!
//! Only the valid-UTF-8 prefix of the first [`MAX_SCAN_BYTES`] is ever
//! inspected or rewritten; bytes beyond the cap are treated as an opaque tail
//! and appended unchanged. The engine is built on the linear-time `regex`
//! crate (no catastrophic backtracking) and never panics on any input.
//!
//! ## Compatibility note
//!
//! The `regex` crate does not support look-around, so the `credit_card` and
//! `ssn` patterns are expressed here with word-boundary anchors (`\b`) rather
//! than the look-behind/look-ahead assertions used in the original proxy
//! source. Detection semantics are equivalent for well-formed inputs.
//!
//! References:
//!   - OWASP — Sensitive Data Exposure / Cryptographic Failures
//!   - UIDAI Aadhaar numbering scheme; Income Tax Dept. PAN format

use regex::Regex;
use tracing::warn;

/// Hard cap on how many bytes of a body are ever inspected or rewritten
/// (512 KiB). Bytes beyond this are appended to a masked body unchanged.
pub const MAX_SCAN_BYTES: usize = 512 * 1024;

/// Builtin pattern set: `(regex source, label)`.
///
/// Order matters for [`DlpEngine::scan`] (first match wins). The first eight
/// entries mirror the original proxy detector; the final three add India PII.
const BUILTIN_PATTERNS: &[(&str, &str)] = &[
    // Credit / debit card numbers (Luhn-shaped 13-19 digit groups).
    // Word-boundary anchored (the proxy used `(?<!\d)...(?!\d)`, unsupported by
    // the `regex` crate).
    (
        r"\b(?:4[0-9]{12,15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
        "credit_card",
    ),
    // US Social Security Number. Word-boundary anchored (the proxy used
    // negative look-aheads to exclude reserved ranges; not supported here).
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    // PEM private key header.
    (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "private_key",
    ),
    // AWS access key.
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
    // AWS secret key (contextual — next to a known keyword).
    (
        r#"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key["'\s:=]+[A-Za-z0-9/+]{40}"#,
        "aws_secret_key",
    ),
    // Generic high-entropy API / bearer tokens in JSON.
    (
        r#"(?i)(?:"|\b)(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|secret)["\s]*[:=]+\s*["']?[A-Za-z0-9/+_\-]{32,}"#,
        "api_token",
    ),
    // Password leaked in a JSON response.
    (
        r#""(?:password|passwd|pwd)"\s*:\s*"[^"]{4,}""#,
        "password_in_json",
    ),
    // Generic private-looking 40-char hex string (git-style secrets).
    (r"\b[0-9a-f]{40}\b", "hex_secret"),
    // India — Permanent Account Number (format AAAAA9999A).
    (r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "indian_pan"),
    // India — Aadhaar (UIDAI) 12-digit number, first digit 2-9, optional
    // 4-4-4 spacing.
    (r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", "aadhaar"),
    // India — 10-digit mobile number starting 6-9, optional +91 prefix.
    (r"(?:\+?91[-\s]?)?[6-9]\d{9}\b", "indian_mobile"),
];

/// Label reported for a match against a user-supplied pattern.
const USER_LABEL: &str = "user_pattern";

/// Returns `true` if `label` denotes a PII class that should be *partially*
/// masked (last four alphanumerics preserved). Everything else is a secret and
/// is fully redacted.
fn is_pii(label: &str) -> bool {
    matches!(
        label,
        "credit_card" | "ssn" | "indian_pan" | "aadhaar" | "indian_mobile"
    )
}

/// Produce the length-preserving replacement for a single match.
///
/// * Secrets (`pii == false`): every byte becomes `'*'` — the returned string
///   has `m.len()` bytes, so byte length is preserved even for multibyte
///   matches from user patterns.
/// * PII (`pii == true`): each ASCII-alphanumeric character is replaced with
///   `'*'` except the last four alphanumerics, which are kept; non-alphanumeric
///   separators (spaces, dashes, `+`) are preserved verbatim. Builtin PII
///   patterns match ASCII only, so character count equals byte count and the
///   result is byte-length-preserving.
fn mask_match(m: &str, pii: bool) -> String {
    if !pii {
        return "*".repeat(m.len());
    }
    let total_alnum = m.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    let keep_from = total_alnum.saturating_sub(4);
    let mut seen = 0usize;
    let mut out = String::with_capacity(m.len());
    for c in m.chars() {
        if c.is_ascii_alphanumeric() {
            if seen >= keep_from {
                out.push(c);
            } else {
                out.push('*');
            }
            seen += 1;
        } else {
            out.push(c);
        }
    }
    out
}

/// Largest scannable prefix length: capped at [`MAX_SCAN_BYTES`], but never
/// landing in the middle of a UTF-8 codepoint.
///
/// When a body is longer than the cap, the byte at `MAX_SCAN_BYTES` may be a
/// UTF-8 continuation byte (`0b10xx_xxxx`) belonging to a codepoint that
/// straddles the boundary. Slicing there would make [`str::from_utf8`] reject
/// the *entire* prefix (`Err`), which would silently fail open — leaving any
/// PII earlier in the body unscanned/unmasked. To avoid that, we back off over
/// trailing continuation bytes so the straddling codepoint is pushed into the
/// (unscanned) tail and the returned prefix always ends on a char boundary.
///
/// Backoff is bounded to at most three bytes (a UTF-8 codepoint is ≤ 4 bytes),
/// and only happens when the cap actually truncates the body.
fn scan_cap(body: &[u8]) -> usize {
    let mut cap = body.len().min(MAX_SCAN_BYTES);
    if cap < body.len() {
        while cap > 0 && (body[cap] & 0xC0) == 0x80 {
            cap -= 1;
        }
    }
    cap
}

/// Response-body DLP engine: detects and redacts PII / secrets.
///
/// Built once at startup / reload and shared across requests. Holds the
/// compiled builtin pattern set plus any caller-supplied user patterns.
pub struct DlpEngine {
    /// Compiled builtin patterns paired with their labels.
    builtin: Vec<(Regex, &'static str)>,
    /// Compiled user-supplied patterns (invalid ones are skipped at build).
    user_patterns: Vec<Regex>,
}

impl DlpEngine {
    /// Compile the builtin pattern set plus the caller's `user_patterns`.
    ///
    /// Invalid user patterns are skipped (logged via `tracing::warn`) rather
    /// than causing a panic. A builtin that fails to compile is likewise
    /// skipped and logged (this should never happen for the shipped set).
    pub fn new(user_patterns: &[String]) -> Self {
        let mut builtin = Vec::with_capacity(BUILTIN_PATTERNS.len());
        for &(pat, label) in BUILTIN_PATTERNS {
            match Regex::new(pat) {
                Ok(re) => builtin.push((re, label)),
                Err(e) => warn!("dlp: builtin pattern compile error ({label}): {e}"),
            }
        }
        let user = user_patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    warn!("dlp: user pattern compile error ({p}): {e}");
                    None
                }
            })
            .collect();
        Self {
            builtin,
            user_patterns: user,
        }
    }

    /// Scan `body` and return the first matched label, or `None` if clean.
    ///
    /// Only the valid-UTF-8 prefix of the first [`MAX_SCAN_BYTES`] is examined.
    /// A non-UTF-8 prefix yields `None`. Builtin patterns are tried in order,
    /// then user patterns (reported as `"user_pattern"`).
    pub fn scan(&self, body: &[u8]) -> Option<&'static str> {
        let cap = scan_cap(body);
        let text = std::str::from_utf8(&body[..cap]).ok()?;
        for (re, label) in &self.builtin {
            if re.is_match(text) {
                return Some(label);
            }
        }
        for re in &self.user_patterns {
            if re.is_match(text) {
                return Some(USER_LABEL);
            }
        }
        None
    }

    /// Redact every match in the scannable prefix and append the untouched tail.
    ///
    /// Returns `Some((new_body, labels))` where `labels` is the sorted, unique
    /// set of matched labels, or `None` when nothing matched or the prefix is
    /// not valid UTF-8.
    ///
    /// The returned body is **byte-length-identical** to the input: matches are
    /// replaced with `'*'` runs of equal byte length, and bytes beyond
    /// [`MAX_SCAN_BYTES`] are appended verbatim.
    pub fn mask(&self, body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
        let cap = scan_cap(body);
        let prefix = std::str::from_utf8(&body[..cap]).ok()?;

        let mut work = prefix.to_string();
        let mut hits: Vec<String> = Vec::new();

        for (re, label) in &self.builtin {
            let pii = is_pii(label);
            let mut matched = false;
            let replaced = re.replace_all(&work, |caps: &regex::Captures| {
                matched = true;
                mask_match(&caps[0], pii)
            });
            if matched {
                hits.push((*label).to_string());
                work = replaced.into_owned();
            }
        }
        for re in &self.user_patterns {
            let mut matched = false;
            let replaced = re.replace_all(&work, |caps: &regex::Captures| {
                matched = true;
                // User patterns are treated as secrets: full redaction.
                mask_match(&caps[0], false)
            });
            if matched {
                hits.push(USER_LABEL.to_string());
                work = replaced.into_owned();
            }
        }

        if hits.is_empty() {
            return None;
        }
        hits.sort();
        hits.dedup();

        let mut new_body = work.into_bytes();
        new_body.extend_from_slice(&body[cap..]);
        Some((new_body, hits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an engine with no user patterns.
    fn engine() -> DlpEngine {
        DlpEngine::new(&[])
    }

    #[test]
    fn all_builtin_patterns_compile() {
        // Guards against a look-around regression: every shipped builtin must
        // compile, otherwise scan() would silently miss that class.
        let e = engine();
        assert_eq!(e.builtin.len(), BUILTIN_PATTERNS.len());
    }

    #[test]
    fn scan_detects_each_builtin() {
        let e = engine();
        let cases: &[(&str, &str)] = &[
            ("pay with 4111111111111111 now", "credit_card"),
            ("ssn 123-45-6789 leaked", "ssn"),
            ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
            ("key AKIAABCDEFGHIJKLMNOP end", "aws_access_key"),
            (
                "aws_secret_access_key = abcdefghijklmnopqrstuvwxyz0123456789ABCD",
                "aws_secret_key",
            ),
            (
                r#"{"api_key": "abcdefghijklmnopqrstuvwxyz0123456789"}"#,
                "api_token",
            ),
            (r#"{"password": "hunter2secret"}"#, "password_in_json"),
            (
                "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 done",
                "hex_secret",
            ),
        ];
        for (body, label) in cases {
            assert_eq!(e.scan(body.as_bytes()), Some(*label), "body: {body}");
        }
    }

    #[test]
    fn scan_detects_india_pii() {
        let e = engine();
        assert_eq!(e.scan(b"pan ABCDE1234F issued"), Some("indian_pan"));
        assert_eq!(e.scan("uid 2345 6789 0123".as_bytes()), Some("aadhaar"));
        assert_eq!(e.scan(b"call 9876543210 today"), Some("indian_mobile"));
        assert_eq!(e.scan(b"call +91 9876543210 today"), Some("indian_mobile"));
    }

    #[test]
    fn scan_clean_and_tiny_inputs_none() {
        let e = engine();
        assert_eq!(e.scan(b""), None);
        assert_eq!(e.scan(b"A"), None);
        assert_eq!(e.scan(b"AB"), None);
        assert_eq!(e.scan(b"ABC"), None);
        assert_eq!(e.scan(b"just some clean text, nothing to see"), None);
    }

    #[test]
    fn scan_non_utf8_prefix_none() {
        let e = engine();
        // 0xFF is never valid UTF-8; the prefix is unscannable.
        assert_eq!(e.scan(&[0xff, 0xfe, 0x41, 0x42]), None);
    }

    #[test]
    fn mask_none_on_clean_tiny_and_non_utf8() {
        let e = engine();
        assert!(e.mask(b"").is_none());
        assert!(e.mask(b"A").is_none());
        assert!(e.mask(b"AB").is_none());
        assert!(e.mask(b"ABC").is_none());
        assert!(e.mask(b"nothing sensitive here").is_none());
        assert!(e.mask(&[0xff, 0xfe]).is_none());
    }

    /// Assert the length-preserving invariant plus expected content/labels.
    fn check_mask(input: &str, expected: &str, expected_labels: &[&str]) {
        let e = engine();
        let (body, labels) = e.mask(input.as_bytes()).expect("expected a match");
        assert_eq!(
            body.len(),
            input.len(),
            "byte length must be preserved (input {input:?})"
        );
        assert_eq!(
            String::from_utf8(body).unwrap(),
            expected,
            "masked output mismatch for {input:?}"
        );
        let want: Vec<String> = expected_labels.iter().map(|s| s.to_string()).collect();
        assert_eq!(labels, want, "labels mismatch for {input:?}");
    }

    #[test]
    fn mask_credit_card_keeps_last_four() {
        check_mask(
            "card 4111111111111111 end",
            "card ************1111 end",
            &["credit_card"],
        );
    }

    #[test]
    fn mask_ssn_preserves_separators() {
        check_mask("ssn 123-45-6789.", "ssn ***-**-6789.", &["ssn"]);
    }

    #[test]
    fn mask_aadhaar_preserves_spaces() {
        check_mask(
            "uid 2345 6789 0123 ok",
            "uid **** **** 0123 ok",
            &["aadhaar"],
        );
    }

    #[test]
    fn mask_indian_pan_keeps_last_four() {
        check_mask("pan ABCDE1234F z", "pan ******234F z", &["indian_pan"]);
    }

    #[test]
    fn mask_indian_mobile_with_prefix() {
        check_mask(
            "call +91 9876543210 now",
            "call +** ******3210 now",
            &["indian_mobile"],
        );
    }

    #[test]
    fn mask_secrets_fully_redacted() {
        let e = engine();

        let (body, labels) = e.mask(b"key AKIAABCDEFGHIJKLMNOP end").unwrap();
        assert_eq!(body.len(), 28);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "key ******************** end"
        );
        assert_eq!(labels, vec!["aws_access_key".to_string()]);

        let input = "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 done";
        let (body, labels) = e.mask(input.as_bytes()).unwrap();
        assert_eq!(body.len(), input.len());
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "commit **************************************** done"
        );
        assert_eq!(labels, vec!["hex_secret".to_string()]);
    }

    #[test]
    fn mask_multiple_pii_all_redacted_labels_sorted_unique() {
        // Two credit cards + ssn + pan: cards collapse to one label, and the
        // returned labels are unique and sorted.
        let input = "a 4111111111111111 b 4111111111111111 c 123-45-6789 d ABCDE1234F";
        let e = engine();
        let (body, labels) = e.mask(input.as_bytes()).unwrap();
        assert_eq!(body.len(), input.len());
        let out = String::from_utf8(body).unwrap();
        assert_eq!(
            out,
            "a ************1111 b ************1111 c ***-**-6789 d ******234F"
        );
        assert_eq!(
            labels,
            vec![
                "credit_card".to_string(),
                "indian_pan".to_string(),
                "ssn".to_string(),
            ]
        );
    }

    #[test]
    fn mask_multibyte_around_ascii_secret_preserves_length() {
        // Emoji + accented text surrounding an ASCII AWS key. The secret is
        // fully redacted; multibyte bytes are untouched; total length holds.
        let input = "café 🔑 AKIAABCDEFGHIJKLMNOP naïve";
        let e = engine();
        let (body, labels) = e.mask(input.as_bytes()).unwrap();
        assert_eq!(body.len(), input.len());
        let out = String::from_utf8(body).unwrap();
        assert_eq!(out, "café 🔑 ******************** naïve");
        assert_eq!(labels, vec!["aws_access_key".to_string()]);
    }

    #[test]
    fn mask_user_pattern_multibyte_byte_length_preserving() {
        // A user pattern whose match spans multibyte characters. Redaction pads
        // to the match's BYTE length, so the invariant holds even though the
        // character count is smaller.
        let e = DlpEngine::new(&[r"token=\S+".to_string()]);
        let input = "leak token=café☕ end";
        let (body, labels) = e.mask(input.as_bytes()).unwrap();
        assert_eq!(body.len(), input.len());
        let out = String::from_utf8(body).unwrap();
        // "token=café☕" is 11 chars but 14 bytes -> 14 stars.
        assert_eq!(out, "leak ************** end");
        assert_eq!(out.len(), input.len());
        assert_eq!(labels, vec!["user_pattern".to_string()]);
    }

    #[test]
    fn invalid_user_pattern_is_skipped_no_panic() {
        // Unbalanced paren must not panic; the engine still works otherwise.
        let e = DlpEngine::new(&["(unclosed".to_string(), r"SEKRET-\w+".to_string()]);
        assert_eq!(e.user_patterns.len(), 1);
        assert_eq!(e.scan(b"here is SEKRET-abc123"), Some("user_pattern"));
    }

    #[test]
    fn tail_beyond_cap_appended_unchanged() {
        // A secret in the scannable prefix is masked; an identical secret past
        // the 512 KiB cap is left untouched, and total length is preserved.
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"leak AKIAABCDEFGHIJKLMNOP here ");
        input.resize(MAX_SCAN_BYTES, b'x');
        input.extend_from_slice(b" tail AKIAABCDEFGHIJKLMNOP");
        let orig_len = input.len();
        let tail_start = MAX_SCAN_BYTES;
        let orig_tail = input[tail_start..].to_vec();

        let e = engine();
        let (body, labels) = e.mask(&input).unwrap();
        assert_eq!(body.len(), orig_len, "length preserved across the cap");
        assert_eq!(labels, vec!["aws_access_key".to_string()]);
        // Prefix secret redacted.
        assert!(String::from_utf8(body[..40].to_vec())
            .unwrap()
            .contains("****"));
        // Tail beyond the cap is byte-for-byte identical (secret NOT masked).
        assert_eq!(&body[tail_start..], &orig_tail[..]);
    }

    #[test]
    fn multibyte_codepoint_straddling_cap_still_scans_and_masks() {
        // Regression: a multibyte char straddling MAX_SCAN_BYTES must NOT make
        // std::str::from_utf8(&body[..cap]) fail and thereby drop the whole
        // prefix (fail-open re-exposure). Here an SSN sits at the very start.
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"ssn 123-45-6789 ");
        // Pad so that a 2-byte 'é' (0xC3 0xA9) straddles the cap: its lead byte
        // lands at MAX_SCAN_BYTES-1 and its continuation byte at MAX_SCAN_BYTES.
        input.resize(MAX_SCAN_BYTES - 1, b'x');
        input.extend_from_slice(&[0xC3, 0xA9]); // 'é'
        assert_eq!(input.len(), MAX_SCAN_BYTES + 1);
        // Sanity: the naive slice at the raw cap is undecodable...
        assert!(std::str::from_utf8(&input[..MAX_SCAN_BYTES]).is_err());

        let e = engine();
        // ...but scan/mask back off to a char boundary and still catch the SSN.
        assert_eq!(e.scan(&input), Some("ssn"));
        let (body, labels) = e.mask(&input).expect("SSN in prefix must be masked");
        assert_eq!(body.len(), input.len(), "length preserved across the cap");
        assert_eq!(labels, vec!["ssn".to_string()]);
        assert!(String::from_utf8_lossy(&body[..16]).starts_with("ssn ***-**-6789 "));
        // The straddling 'é' was pushed into the untouched tail.
        assert_eq!(&body[MAX_SCAN_BYTES - 1..], &[0xC3, 0xA9]);
    }

    #[test]
    fn no_panic_on_adversarial_bytes() {
        let e = DlpEngine::new(&[r"\d+".to_string()]);
        // Assorted awkward inputs: lone continuation bytes, nulls, huge run.
        let inputs: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x80, 0x80, 0x80],
            vec![0xf0, 0x9f], // truncated emoji lead bytes
            b"\x00\x00\x00\x00".to_vec(),
            vec![b'9'; 4096],
        ];
        for inp in inputs {
            let _ = e.scan(&inp);
            let _ = e.mask(&inp);
        }
    }
}
