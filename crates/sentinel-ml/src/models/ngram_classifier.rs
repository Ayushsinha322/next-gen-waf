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

/// Collapse shell command-obfuscation so an obfuscated command scores like the
/// plain one. Attackers break up a command with the shell's own no-op syntax:
/// `$IFS`/`${IFS}`/`${IFS%??}` (the internal field separator expands to
/// whitespace), empty positional/special params (`$9`, `$@`, `$*`), backslash
/// char-escapes (`c\a\t` → `cat`), and interior quotes (`c""at`, `w'h'o'ami`).
/// Runs only when a shell-obfuscation marker (`$`, `\`, `IFS`, or an adjacent
/// quote pair) is present, so ordinary benign values are left untouched.
fn collapse_shell_obfuscation(s: &str) -> Option<String> {
    let has_marker = s.contains('$')
        || s.contains('\\')
        || s.contains("IFS")
        || s.contains('\'')
        || s.contains('"');
    if !has_marker {
        return None;
    }
    // IFS references expand to whitespace in a shell — normalize them first.
    let pre = s
        .replace("${IFS%??}", " ")
        .replace("${IFS%?}", " ")
        .replace("${IFS}", " ")
        .replace("$IFS", " ");
    let cs: Vec<char> = pre.chars().collect();
    let mut out = String::with_capacity(cs.len());
    let mut i = 0;
    let mut changed = pre != s;
    while i < cs.len() {
        let c = cs[i];
        // Backslash char-escape: drop the backslash, keep the escaped char.
        if c == '\\' {
            changed = true;
            i += 1;
            continue;
        }
        // Empty positional/special parameter (`$9`, `$@`, `$*`, …): expands to
        // nothing, drop it.
        if c == '$' && matches!(cs.get(i + 1), Some('0'..='9' | '@' | '*' | '#' | '?' | '!')) {
            changed = true;
            i += 2;
            continue;
        }
        // Interior quote used to break up a token: an empty pair (`''`, `""`)
        // or a quote flanked by word characters.
        if c == '\'' || c == '"' {
            let next = cs.get(i + 1).copied();
            if next == Some(c) {
                changed = true;
                i += 2; // drop the empty pair
                continue;
            }
            let prev_word = out.chars().last().is_some_and(|p| p.is_alphanumeric());
            let next_word = next.is_some_and(|n| n.is_alphanumeric());
            if prev_word && next_word {
                changed = true;
                i += 1; // drop the interior quote
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    if changed {
        Some(out)
    } else {
        None
    }
}

/// Strip SQL/C-style comments so a comment-obfuscated query scores like the
/// plain one. `/*...*/` is a token separator in SQL, so attackers replace spaces
/// with it (`UNION/**/SELECT`) — we canonicalize each comment to a single space.
/// MySQL conditional comments (`/*!50000UNION*/`) execute, so their inner text
/// is kept (minus the leading version digits). Returns `None` when there is no
/// `/*`.
fn strip_sql_comments(s: &str) -> Option<String> {
    if !s.contains("/*") {
        return None;
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut changed = false;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            let bang = b.get(i + 2) == Some(&b'!');
            // Locate the closing `*/`.
            let mut j = i + 2;
            let mut end = None;
            while j + 1 < b.len() {
                if b[j] == b'*' && b[j + 1] == b'/' {
                    end = Some(j);
                    break;
                }
                j += 1;
            }
            match end {
                Some(close) => {
                    out.push(b' ');
                    if bang {
                        // Keep the executed inner text, skipping `!` + version digits.
                        let mut k = i + 3;
                        while k < close && b[k].is_ascii_digit() {
                            k += 1;
                        }
                        out.extend_from_slice(&b[k..close]);
                        out.push(b' ');
                    }
                    changed = true;
                    i = close + 2;
                    continue;
                }
                None => {
                    // Unterminated comment: drop the remainder.
                    out.push(b' ');
                    changed = true;
                    break;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    if changed {
        Some(String::from_utf8_lossy(&out).into_owned())
    } else {
        None
    }
}

/// Collapse any run of ASCII whitespace (space, tab, CR, LF, vtab, formfeed)
/// into a single space and trim the ends — defeats whitespace-variation evasion
/// (`SELECT\tFROM`, `cat\t/etc/passwd`). Returns `None` when nothing changed.
fn normalize_whitespace(s: &str) -> Option<String> {
    let is_ws = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c');
    if !s.chars().any(|c| is_ws(c) && c != ' ') && !s.contains("  ") {
        return None; // already single-space-separated ASCII
    }
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if is_ws(c) {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(' ');
            }
            in_ws = false;
            out.push(c);
        }
    }
    if out == s {
        None
    } else {
        Some(out)
    }
}

/// Normalize JavaScript method-call obfuscation so the model recognises
/// `confirm.call(null,1)` → `confirm(1)`, `alert.apply(null,[1])` → `alert(1)`,
/// `prompt.bind(window)(1)` → `prompt(1)`. Returns `None` when nothing changed.
fn normalize_js_method_call(s: &str) -> Option<String> {
    // Scan through the string looking for func.method(thisArg, pattern
    let js_funcs: &[&[u8]] = &[b"alert", b"confirm", b"prompt", b"eval"];
    let methods: &[&[u8]] = &[b".call(", b".apply(", b".bind("];
    let this_args: &[&[u8]] = &[b"null", b"this", b"window"];

    let lower = s.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();
    let b = s.as_bytes();
    let n = b.len();

    let mut i = 0;
    while i < n {
        for func in js_funcs {
            let fl = func.len();
            if i + fl > n || !lower_bytes[i..].starts_with(func) {
                continue;
            }
            for method in methods {
                let ml = method.len();
                let start = i + fl;
                if start + ml > n {
                    continue;
                }
                // Skip whitespace between func and .method
                let mut j = start;
                while j < n && lower_bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j + ml > n || !lower_bytes[j..].starts_with(method) {
                    continue;
                }
                let after_method = j + ml;
                // Skip whitespace after the opening paren
                let mut k = after_method;
                while k < n && lower_bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                for this_arg in this_args {
                    let tl = this_arg.len();
                    if k + tl > n || !lower_bytes[k..].starts_with(this_arg) {
                        continue;
                    }
                    let after_this = k + tl;
                    // Skip whitespace after this-arg
                    let mut m = after_this;
                    while m < n && lower_bytes[m].is_ascii_whitespace() {
                        m += 1;
                    }
                    // Expect a comma
                    if m < n && lower_bytes[m] == b',' {
                        // Build the replacement: func(
                        let mut out = Vec::with_capacity(n);
                        out.extend_from_slice(&b[..i]);
                        out.extend_from_slice(func);
                        out.push(b'(');
                        // Copy from after the comma to the end
                        let rest_start = m + 1;
                        out.extend_from_slice(&b[rest_start..]);
                        let out = String::from_utf8_lossy(&out).replace(['[', ']'], "");
                        return Some(out);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Max attack score over the raw text and all of its normalized variants.
///
/// Two axes of evasion are defeated here by scoring every de-obfuscated form and
/// taking the max: the ENCODER axis (Base64, HTML-entity, recursive percent-
/// decode, and mixed percent-then-entity) and the OBFUSCATION axis (shell
/// `$IFS`/backslash/quote insertion, SQL-comment token-splitting, whitespace
/// variation). The obfuscation canonicalizers run over both the raw text and its
/// percent-decoded form, since injection is usually URL-encoded on the wire.
/// Each transform runs only when its marker (`&`, `%`, `$`, `/*`, non-space
/// whitespace, Base64 shape) is present, so ordinary benign values pay only a
/// few cheap branches.
pub fn score_all(text: &str) -> Option<f32> {
    let mut max = score_text(text)?;
    let mut variants: Vec<String> = Vec::new();
    // Decode variants — these are the "encoder axis" transforms.
    let b64_decoded = maybe_base64_decode(text);
    if let Some(ref d) = b64_decoded {
        variants.push(d.clone());
    }
    if let Some(d) = html_entity_decode(text) {
        variants.push(d);
    }
    let percent = recursive_percent_decode(text);
    if let Some(d) = &percent {
        if let Some(e) = html_entity_decode(d) {
            variants.push(e);
        }
    }
    // Obfuscation canonicalizers over the raw text and its percent-decoded form.
    for base in std::iter::once(text).chain(percent.as_deref()) {
        if let Some(d) = collapse_shell_obfuscation(base) {
            variants.push(d);
        }
        if let Some(d) = strip_sql_comments(base) {
            variants.push(d);
        }
        if let Some(d) = normalize_whitespace(base) {
            variants.push(d);
        }
    }
    // Obfuscation canonicalizers also run over the Base64-decoded text — this is
    // critical: an attacker Base64-encodes an obfuscated payload (e.g. a shell
    // command with $IFS, a SQLi with /**/ comments), and the decoder exposes the
    // obfuscated form. Without running canonicalizers on the decoded text, the
    // obfuscation survives and the model can't recognize the payload.
    if let Some(ref d) = b64_decoded {
        if let Some(s) = collapse_shell_obfuscation(d) {
            variants.push(s);
        }
        if let Some(s) = strip_sql_comments(d) {
            variants.push(s);
        }
        if let Some(s) = normalize_whitespace(d) {
            variants.push(s);
        }
        // JS method-call normalizer: confirm.call(null,1) → confirm(1)
        if let Some(s) = normalize_js_method_call(d) {
            variants.push(s);
        }
    }
    // JS method-call normalizer on raw + percent-decoded too.
    if let Some(s) = normalize_js_method_call(text) {
        variants.push(s);
    }
    if let Some(ref d) = percent {
        variants.push(d.clone());
        if let Some(s) = normalize_js_method_call(d) {
            variants.push(s);
        }
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
        // (Assert catch + monotonicity, not strict `>`: this degenerate payload
        // carries the literal substring `script` in its raw form, so raw and
        // decoded can tie — what matters is that normalization still catches it.)
        let raw = "%253Cscript%253Ealert(1)%253C%252Fscript%253E";
        let all = score_all(raw).unwrap();
        assert!(
            all >= score_text(raw).unwrap(),
            "normalization must never lower the score below the raw form"
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

    #[test]
    fn shell_ifs_and_escape_collapse() {
        assert_eq!(
            collapse_shell_obfuscation("cat${IFS}/etc/passwd").as_deref(),
            Some("cat /etc/passwd")
        );
        assert_eq!(
            collapse_shell_obfuscation("cat$IFS$9/etc/passwd").as_deref(),
            Some("cat /etc/passwd")
        );
        assert_eq!(
            collapse_shell_obfuscation("c\\a\\t").as_deref(),
            Some("cat")
        );
        assert_eq!(
            collapse_shell_obfuscation("w'h'o'a'm'i").as_deref(),
            Some("whoami")
        );
        assert_eq!(
            collapse_shell_obfuscation("c\"\"at").as_deref(),
            Some("cat")
        );
        // No shell marker → no transform.
        assert_eq!(collapse_shell_obfuscation("please list files"), None);
    }

    #[test]
    fn shell_obfuscated_command_scored_by_score_all() {
        let raw = "cat${IFS}/etc/passwd;whoami";
        let all = score_all(raw).unwrap();
        assert!(
            all >= score_text(raw).unwrap(),
            "de-obfuscated form must not lower the score"
        );
    }

    #[test]
    fn sql_comment_stripping() {
        assert_eq!(
            strip_sql_comments("UNION/**/SELECT").as_deref(),
            Some("UNION SELECT")
        );
        assert_eq!(
            strip_sql_comments("/*!50000UNION*/ SELECT").as_deref(),
            Some(" UNION  SELECT")
        );
        assert_eq!(strip_sql_comments("no comment here"), None);
    }

    #[test]
    fn comment_obfuscated_sqli_caught_by_score_all() {
        let plain = score_text("union select username,password from users").unwrap();
        let obf = score_all("union/**/select/**/username,password/**/from/**/users").unwrap();
        assert!(
            obf >= plain - 0.05,
            "comment-obfuscated SQLi ({obf}) must score close to plain ({plain})"
        );
    }

    #[test]
    fn whitespace_normalization() {
        assert_eq!(
            normalize_whitespace("select\tid\nfrom\x0busers").as_deref(),
            Some("select id from users")
        );
        assert_eq!(normalize_whitespace("already single spaced"), None);
    }

    #[test]
    fn js_method_call_normalize() {
        assert_eq!(
            normalize_js_method_call("confirm.call(null,1)").as_deref(),
            Some("confirm(1)")
        );
        assert_eq!(
            normalize_js_method_call("alert.apply(null, [1])").as_deref(),
            Some("alert( 1)")
        );
        assert_eq!(
            normalize_js_method_call("prompt.call(window,1)").as_deref(),
            Some("prompt(1)")
        );
        assert_eq!(
            normalize_js_method_call("eval.call(this,'x')").as_deref(),
            Some("eval('x')")
        );
        // No method-call pattern → no transform.
        assert_eq!(normalize_js_method_call("alert(1)"), None);
        assert_eq!(normalize_js_method_call("normal text"), None);
    }

    #[test]
    fn base64_decoded_obfuscation_canonicalized() {
        // Base64 of "getent$IFS$9hosts somehost.burpcollaborator.net"
        let b64 = "Z2V0ZW50JElGUyQ5aG9zdHMgc29tZWhvc3QuYnVycGNvbGxhYm9yYXRvci5uZXQ";
        let all = score_all(b64).unwrap();
        let raw = score_text(b64).unwrap();
        assert!(
            all > raw,
            "Base64-decoded + $IFS-collapsed shell command must score higher than raw Base64, got all={all} raw={raw}"
        );
    }

    #[test]
    fn base64_decoded_sql_comment_canonicalized() {
        // Base64 of "UNION/**/SELECT username,password FROM users"
        let b64 = "VU5JT04vKiovU0VMRUNUIHVzZXJuYW1lLHBhc3N3b3JkIEZST00gdXNlcnM";
        let all = score_all(b64).unwrap();
        let raw = score_text(b64).unwrap();
        assert!(
            all > raw,
            "Base64-decoded + comment-stripped SQLi must score higher than raw, got all={all} raw={raw}"
        );
    }

    #[test]
    fn base64_decoded_js_call_normalized() {
        // Base64 of "confirm.call(null,1)"
        let b64 = "Y29uZmlybS5jYWxsKG51bGwsMSk";
        let all = score_all(b64).unwrap();
        assert!(
            all > 0.5,
            "Base64-decoded XSS js call must be caught, got {all}"
        );
    }
}
