//! GraphQL query firewall.
//!
//! A per-site guard for GraphQL endpoints that rejects abusive queries before
//! they reach the origin. It enforces three limits over the request body:
//!
//!   - **Depth** — maximum nesting of selection-set braces `{ ... }`. Deeply
//!     nested queries can trigger expensive recursive resolvers (a classic
//!     GraphQL DoS vector).
//!   - **Complexity** — a documented proxy for query cost: the number of
//!     field-name tokens (identifiers at selection positions, excluding
//!     GraphQL keywords and anything inside `( ... )` argument lists). Very
//!     wide queries selecting thousands of fields are rejected.
//!   - **Introspection** — `__schema` / `__type` meta-fields expose the full
//!     schema and are blocked by default so attackers cannot map the API.
//!
//! The scanner is a single linear pass over hand-written, panic-free code with
//! **no extra dependencies**. It never allocates unbounded memory and scans at
//! most the first [`MAX_SCAN_BYTES`] of the body.
//!
//! References:
//!   - OWASP API Security — API4:2023 Unrestricted Resource Consumption
//!   - GraphQL spec §2 (Language) — selection sets, string values, comments

/// Hard cap on how many bytes of the body are ever inspected (256 KiB).
///
/// Bounds work for pathological bodies so a single request can neither hang
/// the scanner nor force it to walk gigabytes of streamed data.
pub const MAX_SCAN_BYTES: usize = 256 * 1024;

/// Maximum JSON nesting the transport-envelope parser will descend before
/// bailing out (and falling back to treating the body as a raw query). Keeps
/// recursion bounded so a deeply nested JSON body cannot overflow the stack.
const MAX_JSON_DEPTH: u32 = 100;

/// Limits enforced by [`inspect`]. Mirrors `sentinel_core::config::GraphqlConfig`
/// (minus the `enable` flag, which the caller checks before invoking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphqlLimits {
    /// Maximum allowed selection-set nesting depth.
    pub max_depth: u32,
    /// Maximum allowed field-token count (complexity proxy).
    pub max_complexity: u32,
    /// When `true`, any `__schema` / `__type` introspection field is blocked.
    pub block_introspection: bool,
}

/// Inspect a request body against the configured GraphQL limits.
///
/// Returns `Some(reason)` when the request should be **blocked** and `None`
/// when it is allowed. The function never panics and scans at most the first
/// [`MAX_SCAN_BYTES`] of `body`.
///
/// The query text is extracted as follows:
///   - If the body parses as a JSON object with a string `"query"` field, that
///     field is inspected. A JSON **array** of such objects (a batched request)
///     is fully inspected — the request is blocked if *any* operation violates
///     a limit.
///   - Otherwise the whole body is treated as raw GraphQL query text.
///
/// Non-UTF-8 or otherwise unparseable input yields `None` (other layers handle
/// it), so this guard fails open rather than rejecting traffic it cannot read.
pub fn inspect(body: &[u8], limits: &GraphqlLimits) -> Option<String> {
    // Bound the work: only the first MAX_SCAN_BYTES are ever examined.
    let capped = &body[..body.len().min(MAX_SCAN_BYTES)];

    // Decode as UTF-8. If truncation split a multi-byte char at the cap
    // boundary, fall back to the valid prefix; if nothing is valid, allow.
    let text = match std::str::from_utf8(capped) {
        Ok(s) => s,
        Err(e) => {
            let valid = e.valid_up_to();
            if valid == 0 {
                return None;
            }
            // The prefix up to `valid` is guaranteed valid UTF-8.
            std::str::from_utf8(&capped[..valid]).ok()?
        }
    };

    for query in extract_queries(text) {
        if let Some(reason) = inspect_query(query.as_ref(), limits) {
            return Some(reason);
        }
    }
    None
}

/// Extract the GraphQL query string(s) from a request body.
///
/// Returns owned/borrowed query texts. Falls back to the whole body when the
/// input is not a JSON envelope carrying a string `"query"` field.
fn extract_queries(text: &str) -> Vec<std::borrow::Cow<'_, str>> {
    let trimmed = text.trim_start();
    // A raw GraphQL document also starts with `{`, but it is not valid JSON
    // (unquoted keys), so JSON parsing will fail and we fall through.
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Some(queries) = try_extract_json_queries(text) {
            if !queries.is_empty() {
                return queries.into_iter().map(std::borrow::Cow::Owned).collect();
            }
        }
    }
    vec![std::borrow::Cow::Borrowed(text)]
}

// ---------------------------------------------------------------------------
// Minimal, bounded, panic-free JSON parser (extracts string `"query"` fields)
// ---------------------------------------------------------------------------

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
    out: Vec<String>,
}

/// Parse `text` as JSON and collect the value of every string-typed `"query"`
/// field. Returns `None` if `text` is not well-formed JSON (so the caller can
/// treat the body as a raw query instead).
fn try_extract_json_queries(text: &str) -> Option<Vec<String>> {
    let mut p = JsonParser {
        b: text.as_bytes(),
        i: 0,
        out: Vec::new(),
    };
    p.skip_ws();
    p.parse_value(0)?;
    p.skip_ws();
    // Reject trailing garbage so a raw GraphQL doc isn't half-parsed as JSON.
    if p.i != p.b.len() {
        return None;
    }
    Some(p.out)
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: u32) -> Option<()> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => {
                self.parse_string()?;
                Some(())
            }
            b't' => self.parse_lit(b"true"),
            b'f' => self.parse_lit(b"false"),
            b'n' => self.parse_lit(b"null"),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: u32) -> Option<()> {
        self.i += 1; // consume '{'
        self.skip_ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Some(());
        }
        loop {
            self.skip_ws();
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek()? != b':' {
                return None;
            }
            self.i += 1;
            self.skip_ws();
            if key == "query" && self.peek()? == b'"' {
                let value = self.parse_string()?;
                self.out.push(value);
            } else {
                self.parse_value(depth + 1)?;
            }
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b'}' => {
                    self.i += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self, depth: u32) -> Option<()> {
        self.i += 1; // consume '['
        self.skip_ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Some(());
        }
        loop {
            self.parse_value(depth + 1)?;
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b']' => {
                    self.i += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    /// Parse a JSON string starting at the current `"`. Returns the unescaped
    /// contents. Multi-byte UTF-8 is preserved by copying raw bytes and
    /// re-validating at the end.
    fn parse_string(&mut self) -> Option<String> {
        if self.peek()? != b'"' {
            return None;
        }
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            // Surrogates / invalid scalars collapse to U+FFFD.
                            // Non-BMP fidelity is irrelevant to brace counting.
                            let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None, // invalid escape → not valid JSON
                    }
                }
                other => out.push(other),
            }
        }
    }

    fn parse_hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = *self.b.get(self.i)?;
            self.i += 1;
            let h = (d as char).to_digit(16)?;
            v = v * 16 + h;
        }
        Some(v)
    }

    fn parse_number(&mut self) -> Option<()> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'-' || c == b'+' || c == b'.' || c == b'e' || c == b'E' {
                self.i += 1;
            } else {
                break;
            }
        }
        if self.i == start {
            None
        } else {
            Some(())
        }
    }

    fn parse_lit(&mut self, lit: &[u8]) -> Option<()> {
        if self.b.len() >= self.i + lit.len() && &self.b[self.i..self.i + lit.len()] == lit {
            self.i += lit.len();
            Some(())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// GraphQL query tokenizer (depth / complexity / introspection)
// ---------------------------------------------------------------------------

/// GraphQL keywords that never count toward complexity.
fn is_keyword(name: &str) -> bool {
    matches!(
        name,
        "query" | "mutation" | "subscription" | "fragment" | "on"
    )
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Tokenize a single GraphQL query and check it against `limits`.
///
/// A single linear pass that safely skips string literals (`"..."` and
/// `"""..."""`) and `#` line comments so braces or words inside them never
/// affect the counts. All counters saturate, so no overflow is possible.
fn inspect_query(q: &str, limits: &GraphqlLimits) -> Option<String> {
    let bytes = q.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;

    let mut depth: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut complexity: u32 = 0;
    let mut paren_depth: u32 = 0;
    let mut introspection = false;

    while i < n {
        let c = bytes[i];
        match c {
            // `#` line comment — skip to end of line.
            b'#' => {
                i += 1;
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // String literal — regular `"..."` or block `"""..."""`.
            b'"' => {
                if i + 2 < n && bytes[i + 1] == b'"' && bytes[i + 2] == b'"' {
                    // Block string.
                    i += 3;
                    while i < n {
                        if bytes[i] == b'\\' {
                            i += 2; // skip escaped char (covers \""")
                            continue;
                        }
                        if bytes[i] == b'"'
                            && i + 2 < n
                            && bytes[i + 1] == b'"'
                            && bytes[i + 2] == b'"'
                        {
                            i += 3;
                            break;
                        }
                        i += 1;
                    }
                } else {
                    // Regular string.
                    i += 1;
                    while i < n {
                        match bytes[i] {
                            b'\\' => i += 2,
                            b'"' => {
                                i += 1;
                                break;
                            }
                            // A raw newline can only mean an unterminated
                            // string; stop so we don't swallow the document.
                            b'\n' => {
                                i += 1;
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
            }
            b'{' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    max_depth = depth;
                }
                i += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'(' => {
                paren_depth = paren_depth.saturating_add(1);
                i += 1;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                i += 1;
            }
            _ if is_name_start(c) => {
                let start = i;
                i += 1;
                while i < n && is_name_continue(bytes[i]) {
                    i += 1;
                }
                let name = &q[start..i];
                // Introspection meta-fields only appear at field positions.
                if paren_depth == 0 && (name == "__schema" || name == "__type") {
                    introspection = true;
                }
                // Complexity proxy: field-name tokens outside argument lists
                // that are not reserved keywords.
                if paren_depth == 0 && !is_keyword(name) {
                    complexity = complexity.saturating_add(1);
                }
            }
            _ => i += 1,
        }
    }

    if max_depth > limits.max_depth {
        return Some(format!(
            "graphql: query depth {} exceeds max {}",
            max_depth, limits.max_depth
        ));
    }
    if complexity > limits.max_complexity {
        return Some(format!(
            "graphql: query complexity {} exceeds max {}",
            complexity, limits.max_complexity
        ));
    }
    if limits.block_introspection && introspection {
        return Some("graphql: introspection blocked".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: GraphqlLimits = GraphqlLimits {
        max_depth: 10,
        max_complexity: 1000,
        block_introspection: true,
    };

    #[test]
    fn shallow_query_allowed() {
        let q = b"{ user { id name email } }";
        assert_eq!(inspect(q, &LIMITS), None);
    }

    #[test]
    fn deeply_nested_query_blocked_on_depth() {
        // Build `{ a { a { a ... } } }` nested well past max_depth.
        let mut q = String::new();
        let levels = 15;
        for _ in 0..levels {
            q.push_str("{ a ");
        }
        for _ in 0..levels {
            q.push_str("} ");
        }
        let reason = inspect(q.as_bytes(), &LIMITS).expect("should block");
        assert!(reason.contains("depth"), "reason: {reason}");
        assert!(reason.contains("exceeds max 10"), "reason: {reason}");
    }

    #[test]
    fn wide_query_blocked_on_complexity() {
        let limits = GraphqlLimits {
            max_depth: 10,
            max_complexity: 5,
            block_introspection: false,
        };
        // 20 fields, one selection set → depth 1, complexity 20 > 5.
        let mut q = String::from("{ ");
        for i in 0..20 {
            q.push_str(&format!("f{i} "));
        }
        q.push('}');
        let reason = inspect(q.as_bytes(), &limits).expect("should block");
        assert!(reason.contains("complexity"), "reason: {reason}");
    }

    #[test]
    fn introspection_blocked_when_enabled() {
        let q = b"{ __schema { types { name } } }";
        let reason = inspect(q, &LIMITS).expect("should block");
        assert_eq!(reason, "graphql: introspection blocked");
    }

    #[test]
    fn introspection_allowed_when_disabled() {
        let limits = GraphqlLimits {
            max_depth: 10,
            max_complexity: 1000,
            block_introspection: false,
        };
        let q = b"{ __schema { types { name } } }";
        assert_eq!(inspect(q, &limits), None);
    }

    #[test]
    fn type_meta_field_detected() {
        let q = br#"{ __type(name: "User") { name } }"#;
        let reason = inspect(q, &LIMITS).expect("should block");
        assert_eq!(reason, "graphql: introspection blocked");
    }

    #[test]
    fn braces_inside_string_do_not_inflate_depth() {
        let limits = GraphqlLimits {
            max_depth: 3,
            max_complexity: 1000,
            block_introspection: false,
        };
        // Many '{' live inside a string argument; real depth is only 1.
        let q = br#"{ a(note: "{{{{{{{{{{{{{{{{") }"#;
        assert_eq!(inspect(q, &limits), None);
    }

    #[test]
    fn braces_inside_block_string_and_comment_ignored() {
        let limits = GraphqlLimits {
            max_depth: 2,
            max_complexity: 1000,
            block_introspection: false,
        };
        let q = b"{ a(x: \"\"\"{{{{{\"\"\") # }}}}}}}}}}\n b }";
        // Real depth is 1; braces are inside a block string / comment.
        assert_eq!(inspect(q, &limits), None);
    }

    #[test]
    fn json_query_field_extracted() {
        let body = br#"{"operationName":null,"variables":{},"query":"{ a { b } }"}"#;
        // depth 2 with default limits → allowed.
        assert_eq!(inspect(body, &LIMITS), None);

        let shallow = GraphqlLimits {
            max_depth: 1,
            max_complexity: 1000,
            block_introspection: false,
        };
        let reason = inspect(body, &shallow).expect("depth 2 > 1 should block");
        assert!(reason.contains("depth"), "reason: {reason}");
    }

    #[test]
    fn json_query_with_escaped_quote_and_brace() {
        // The GraphQL string argument contains an escaped quote and a brace;
        // once JSON-unescaped the brace sits inside a GraphQL string and must
        // not count toward depth.
        let limits = GraphqlLimits {
            max_depth: 1,
            max_complexity: 1000,
            block_introspection: false,
        };
        let body = br#"{"query":"{ a(note: \"}{\") }"}"#;
        assert_eq!(inspect(body, &limits), None);
    }

    #[test]
    fn batched_json_blocks_if_any_violates() {
        let limits = GraphqlLimits {
            max_depth: 2,
            max_complexity: 1000,
            block_introspection: false,
        };
        // Second op nests to depth 3 > 2.
        let body = br#"[{"query":"{ a { b } }"},{"query":"{ a { b { c } } }"}]"#;
        let reason = inspect(body, &limits).expect("second op should block");
        assert!(reason.contains("depth"), "reason: {reason}");
    }

    #[test]
    fn batched_json_all_clean_allowed() {
        let body = br#"[{"query":"{ a }"},{"query":"{ b }"}]"#;
        assert_eq!(inspect(body, &LIMITS), None);
    }

    #[test]
    fn non_utf8_body_returns_none() {
        let body = &[0xff, 0xfe, 0xfd, 0x00, 0x80, 0x81][..];
        assert_eq!(inspect(body, &LIMITS), None);
    }

    #[test]
    fn empty_body_returns_none() {
        assert_eq!(inspect(b"", &LIMITS), None);
    }

    #[test]
    fn huge_benign_body_does_not_hang_or_block() {
        // 2 MiB single identifier token: one name → complexity 1, depth 0.
        let body = vec![b'a'; 2 * 1024 * 1024];
        assert_eq!(inspect(&body, &LIMITS), None);
    }

    #[test]
    fn garbage_json_falls_back_to_raw_scan() {
        // Not valid JSON (unquoted keys) → treated as raw GraphQL, depth 2.
        let limits = GraphqlLimits {
            max_depth: 1,
            max_complexity: 1000,
            block_introspection: false,
        };
        let body = b"{ outer { inner } }";
        let reason = inspect(body, &limits).expect("depth 2 > 1");
        assert!(reason.contains("depth"), "reason: {reason}");
    }

    #[test]
    fn unterminated_string_does_not_panic() {
        let limits = GraphqlLimits {
            max_depth: 10,
            max_complexity: 1000,
            block_introspection: true,
        };
        // No closing quote / brace — must not panic.
        let _ = inspect(b"{ a(x: \"unterminated", &limits);
        let _ = inspect(b"\"\"\"unterminated block", &limits);
        let _ = inspect(b"{{{{{{{{{{", &limits);
    }
}
