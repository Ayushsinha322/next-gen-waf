use sentinel_core::context::{Phase, RequestContext, RuleMatch, Severity, WafDecision};
use tracing::{debug, warn};

use super::emitter::{CompiledRuleSet, Instruction, RuleMeta, TargetSpec};
use crate::dsl::ast::{RuleAction, RulePhase, RuleSeverity, SetVar, SetVarOp, Transform};

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
    Strings(Vec<String>),
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
            let k = percent_decode(parts.next().unwrap_or(""));
            let v = percent_decode(parts.next().unwrap_or(""));
            (k, v)
        })
        .collect()
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
}

/// Locate the first occurrence of `needle` within `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
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

    // Position just past the first boundary marker.
    let mut search_from = match find_bytes(body, delim) {
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
        let next = match find_bytes(&body[part_start..], delim) {
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
fn body_args(ctx: &RequestContext) -> Vec<(String, String)> {
    let Some(body) = ctx.request_body.as_ref() else {
        return Vec::new();
    };
    let ct = content_type(ctx);
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
        multipart_parts(ctx).fields
    } else if is_xml_content_type(&ct) {
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

fn extract_target(spec: &TargetSpec, ctx: &RequestContext) -> Vec<String> {
    match spec {
        TargetSpec::Args => {
            let mut values: Vec<String> = parse_query_params(ctx.uri.query().unwrap_or(""))
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            // ARGS also includes urlencoded / JSON POST body parameters.
            values.extend(body_args(ctx).into_iter().map(|(_, v)| v));
            values
        }
        TargetSpec::ArgsNames => {
            let mut names: Vec<String> = parse_query_params(ctx.uri.query().unwrap_or(""))
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            names.extend(body_args(ctx).into_iter().map(|(k, _)| k));
            names
        }
        TargetSpec::RequestUri => vec![ctx.uri.to_string()],
        TargetSpec::RequestFilename => vec![ctx.uri.path().to_owned()],
        TargetSpec::RequestMethod => vec![ctx.method.as_str().to_owned()],
        TargetSpec::RequestLine => {
            vec![format!("{} {} {:?}", ctx.method, ctx.uri, ctx.http_version)]
        }
        TargetSpec::RequestBody => ctx
            .request_body
            .as_ref()
            .map(|b| vec![String::from_utf8_lossy(b).into_owned()])
            .unwrap_or_default(),
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
        TargetSpec::RequestCookiesAll => {
            if let Some(cookie_hdr) = ctx.request_headers.get("cookie") {
                if let Ok(s) = cookie_hdr.to_str() {
                    return parse_cookies(s).into_iter().map(|(_, v)| v).collect();
                }
            }
            vec![]
        }
        TargetSpec::RequestCookie(name) => {
            if let Some(cookie_hdr) = ctx.request_headers.get("cookie") {
                if let Ok(s) = cookie_hdr.to_str() {
                    return parse_cookies(s)
                        .into_iter()
                        .filter(|(k, _)| k == name)
                        .map(|(_, v)| v)
                        .collect();
                }
            }
            vec![]
        }
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
        TargetSpec::Files => multipart_parts(ctx).filenames,
        TargetSpec::FilesNames => multipart_parts(ctx).field_names,
        TargetSpec::FilesCombinedSize => vec![multipart_parts(ctx).combined_size.to_string()],
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
                other => extract_target(other, ctx).len(),
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
    let phase_idx = phase as usize;
    let program = &ruleset.phase_programs[phase_idx];

    let mut stack: Vec<StackVal> = Vec::with_capacity(16);
    let mut ip: usize = 0; // instruction pointer

    while ip < program.len() {
        // Early exit: if already decided (Block/Challenge), stop evaluating.
        if ctx.decision != WafDecision::Allow {
            return ctx.decision.clone();
        }

        let instr = &program[ip];
        match instr {
            Instruction::LoadTarget(spec) => {
                let values = extract_target(spec, ctx);
                stack.push(StackVal::Strings(values));
            }

            Instruction::MatchRx { pattern_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let regex = &ruleset.patterns[*pattern_id];
                    let matched = values.iter().any(|s| regex.is_match(s));
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
                    let matched = values.iter().any(|s| ac.is_match(s));
                    debug!(set_id, matched, "MatchMulti");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::MatchEq { literal_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let literal = &ruleset.literals[*literal_id];
                    let matched = values.iter().any(|s| s == literal);
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::Exists => {
                let values = pop_strings(&mut stack);
                let exists = !values.is_empty() && values.iter().any(|s| !s.is_empty());
                stack.push(StackVal::Bool(exists));
            }

            Instruction::DetectSqli => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let matched = values
                        .iter()
                        .any(|s| libinjectionrs::detect_sqli(s.as_bytes()).is_injection());
                    debug!(matched, "DetectSqli");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::DetectXss => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let matched = values
                        .iter()
                        .any(|s| libinjectionrs::detect_xss(s.as_bytes()).is_injection());
                    debug!(matched, "DetectXss");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::DetectOffDomainUrl => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let host = request_host(ctx);
                    let matched = values.iter().any(|v| contains_off_domain_url(v, &host));
                    debug!(matched, "DetectOffDomainUrl");
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
                if *multi_match && !transforms.is_empty() {
                    // multiMatch: collect the original values plus the result
                    // after each cumulative transform prefix so the subsequent
                    // operator can match at any intermediate step.
                    let mut all: Vec<String> =
                        Vec::with_capacity(values.len() * (transforms.len() + 1));
                    for v in &values {
                        let mut s = v.clone();
                        all.push(s.clone()); // original
                        for t in transforms.iter() {
                            s = apply_single_transform(s, t);
                            all.push(s.clone()); // after this transform
                        }
                    }
                    stack.push(StackVal::Strings(all));
                } else {
                    let transformed: Vec<String> = values
                        .into_iter()
                        .map(|s| apply_transforms(s, transforms))
                        .collect();
                    stack.push(StackVal::Strings(transformed));
                }
            }

            Instruction::LoadAnomalyScore => {
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
                if fired {
                    if let Some(meta) = ruleset.rule_meta.get(rule_id) {
                        fire_rule(ctx, meta);
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
                        if anomaly_threshold > 0
                            && ctx.anomaly_score >= anomaly_threshold
                            && ctx.decision == WafDecision::Allow
                        {
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason = Some(format!(
                                "anomaly score {} >= threshold {}",
                                ctx.anomaly_score, anomaly_threshold
                            ));
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

fn fire_rule(ctx: &mut RequestContext, meta: &RuleMeta) {
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

    // Add anomaly score
    if meta.score_delta > 0 {
        ctx.anomaly_score = ctx.anomaly_score.saturating_add(meta.score_delta as u32);
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
            target: String::new(),
            phase,
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

/// Apply a single transform step.  Used both by `apply_transforms` and by
/// the multiMatch loop in the VM.
fn apply_single_transform(s: String, t: &Transform) -> String {
    match t {
        Transform::Lowercase => s.to_ascii_lowercase(),
        Transform::UrlDecodeUni => url_decode_uni(&s),
        Transform::RemoveNulls => s.replace('\0', ""),
        Transform::ReplaceNulls => s.replace('\0', " "),
        Transform::HtmlEntityDecode => decode_html_entities(s),
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
    }
}

fn decode_html_entities(s: String) -> String {
    if !s.contains('&') {
        return s;
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&#x2F;", "/")
        .replace("&#47;", "/")
        .replace("&#x3C;", "<")
        .replace("&#60;", "<")
        .replace("&#x3E;", ">")
        .replace("&#62;", ">")
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
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let decode = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    };
    let bytes = cleaned.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return s.to_owned();
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let b0 = match decode(bytes[i]) {
            Some(v) => v,
            None => return s.to_owned(),
        };
        let b1 = match decode(bytes[i + 1]) {
            Some(v) => v,
            None => return s.to_owned(),
        };
        let b2 = match decode(bytes[i + 2]) {
            Some(v) => v,
            None => return s.to_owned(),
        };
        let b3 = match decode(bytes[i + 3]) {
            Some(v) => v,
            None => return s.to_owned(),
        };
        out.push((b0 << 2) | (b1 >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b1 << 4) | (b2 >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((b2 << 6) | b3);
        }
        i += 4;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
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

fn pop_strings(stack: &mut Vec<StackVal>) -> Vec<String> {
    match stack.pop() {
        Some(StackVal::Strings(v)) => v,
        Some(other) => {
            warn!("VM: expected Strings on stack, got {:?}", other);
            vec![]
        }
        None => {
            warn!("VM: stack underflow on pop_strings");
            vec![]
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
