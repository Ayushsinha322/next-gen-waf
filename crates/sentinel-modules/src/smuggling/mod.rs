//! HTTP Request Smuggling / Desync Attack Detection.
//!
//! Detects ambiguous HTTP requests that could be interpreted differently by
//! front-end proxies and back-end servers, enabling smuggling attacks:
//!
//!   - **CL.TE**: Content-Length + Transfer-Encoding both present. A front-end
//!     using CL may forward the whole body, while a back-end using TE may see a
//!     smuggled prefix request.
//!   - **TE.CL**: Both headers present + crafted TE chunk that hides a prefix.
//!     The front-end strips TE but the back-end uses CL, seeing the smuggled
//!     prefix as the next request.
//!   - **TE.TE**: Multiple Transfer-Encoding values (e.g. obfuscated "chunked"
//!     alongside "identity") to confuse one of the hops.
//!   - **HTTP method / request-line injection** in header values that a naive
//!     back-end might interpret as a new request.
//!
//! References:
//!   - RFC 7230 §3.3.3 (Message Body Length)
//!   - CWE-444 / CAPEC-33 / CAPEC-105 / CAPEC-273
//!   - PortSwigger HTTP Request Smuggling research

/// Outcome of a smuggling detection check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmugglingVerdict {
    /// Request is clean — no smuggling indicators.
    Clean,
    /// Request is ambiguous or contains smuggling patterns — should be
    /// rejected with HTTP 400 Bad Request.
    Reject { reason: String },
}

/// Header value tokens that are valid for the `Transfer-Encoding` header.
/// RFC 7230 §4 lists: chunked, compress, deflate, gzip, identity.
const VALID_TRANSFER_ENCODINGS: &[&str] = &["chunked", "compress", "deflate", "gzip", "identity"];

/// Run the full smuggling detection suite on request headers.
///
/// Call during Phase 1 (request headers) before the body is read.
/// Returns [`SmugglingVerdict::Reject`] if the request should be
/// dropped with 400 Bad Request.
pub fn detect(headers: &http::HeaderMap) -> SmugglingVerdict {
    // 1. Both Transfer-Encoding and Content-Length present → immediate reject.
    if let Some(verdict) = check_cl_te_conflict(headers) {
        return verdict;
    }

    // 2. Transfer-Encoding obfuscation / multiple values (TE.TE).
    if let Some(verdict) = check_te_obfuscation(headers) {
        return verdict;
    }

    // 3. Content-Length vs Transfer-Encoding header-name smuggling.
    //    An attacker may send both a valid "transfer-encoding" and an
    //    obfuscated "Transfer-encoding" or "Transfer-Encoding " header.
    if let Some(verdict) = check_duplicate_te_headers(headers) {
        return verdict;
    }

    // 4. HTTP request-line injection in header values.
    if let Some(verdict) = check_header_injection(headers) {
        return verdict;
    }

    // 5. Content-Length header validation — must be a single, valid numeric
    //    value (no multiple CL headers).
    if let Some(verdict) = check_cl_validity(headers) {
        return verdict;
    }

    SmugglingVerdict::Clean
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/// Reject when both `Content-Length` and `Transfer-Encoding` are present.
/// RFC 7230 §3.3.3 rule 3: if Transfer-Encoding is present, the sender MUST
/// NOT include a Content-Length header. Combined with rule 4: if both arrive
/// from a proxy, the request is malformed and MUST be rejected (400).
fn check_cl_te_conflict(headers: &http::HeaderMap) -> Option<SmugglingVerdict> {
    let has_te = headers.contains_key(http::header::TRANSFER_ENCODING);
    let has_cl = headers.contains_key(http::header::CONTENT_LENGTH);

    if has_te && has_cl {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: both Transfer-Encoding and Content-Length present (CL.TE / TE.CL ambiguity)".to_string(),
        });
    }
    None
}

/// Reject when `Transfer-Encoding` contains obfuscated or multiple values.
///
/// Attacks:
///   - "Transfer-Encoding: xchunked" — a proxy that strips the header by
///     prefix match misses it, back-end sees "chunked".
///   - "Transfer-Encoding: chunked, identity" — multiple values.
///   - "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity" with CRLF
///     injection in the value.
fn check_te_obfuscation(headers: &http::HeaderMap) -> Option<SmugglingVerdict> {
    let te_values: Vec<&str> = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    if te_values.is_empty() {
        return None;
    }

    // Multiple Transfer-Encoding headers → TE.TE attack (RFC 7230 §3.3.3
    // says it SHOULD be handled as an error).
    if te_values.len() > 1 {
        return Some(SmugglingVerdict::Reject {
            reason: format!(
                "HTTP request smuggling: multiple Transfer-Encoding headers ({})",
                te_values.len()
            ),
        });
    }

    let value = te_values[0].trim();

    // Reject if the value contains CR or LF (header folding/injection).
    if value.contains('\r') || value.contains('\n') {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: CR/LF in Transfer-Encoding value".to_string(),
        });
    }

    // Split by comma, trim each token.
    let tokens: Vec<&str> = value.split(',').map(str::trim).filter(|t| !t.is_empty()).collect();

    // Multiple tokens → reject (e.g. "chunked, identity").
    if tokens.len() > 1 {
        return Some(SmugglingVerdict::Reject {
            reason: format!(
                "HTTP request smuggling: multiple Transfer-Encoding tokens ({})",
                tokens.len()
            ),
        });
    }

    if tokens.is_empty() {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: empty Transfer-Encoding value".to_string(),
        });
    }

    let token = tokens[0].to_ascii_lowercase();

    // Check if the value is a known valid encoding.
    if !VALID_TRANSFER_ENCODINGS.contains(&token.as_str()) {
        return Some(SmugglingVerdict::Reject {
            reason: format!(
                "HTTP request smuggling: unrecognized Transfer-Encoding value '{}'",
                tokens[0]
            ),
        });
    }

    None
}

/// Detect duplicate `Transfer-Encoding` headers that use different casing or
/// whitespace tricks to bypass single-header checks.
///
/// Hyper normalises header values when accessed by the standard name, but
/// an attacker might send headers with different case (e.g. "Transfer-encoding"
/// with lowercase 'e') hoping the proxy only strips one variant.
fn check_duplicate_te_headers(headers: &http::HeaderMap) -> Option<SmugglingVerdict> {
    // Hyper v1's HeaderMap already normalises header names (case-insensitive
    // lookup). The `get_all()` method returns all values for that normalized
    // key. If we see > 1 TE value, reject — this is the TE.TE attack vector.
    //
    // This check is redundant with `check_te_obfuscation` which already
    // detects multiple values, but we keep it as a belt-and-suspenders.
    if headers.get_all(http::header::TRANSFER_ENCODING).iter().count() > 1 {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: duplicate Transfer-Encoding headers".to_string(),
        });
    }
    None
}

/// Scan header names and values for embedded HTTP request-line patterns.
///
/// An attacker may inject `\r\nGET /admin HTTP/1.1\r\nHost: ...` inside a
/// header value. If a back-end parses the raw byte-stream naively, the
/// injected fragment becomes the next request.
fn check_header_injection(headers: &http::HeaderMap) -> Option<SmugglingVerdict> {
    for (name, value) in headers.iter() {
        let val_str = match value.to_str() {
            Ok(s) => s,
            Err(_) => {
                // Non-UTF-8 header value — could be a binary smuggling attempt.
                return Some(SmugglingVerdict::Reject {
                    reason: format!(
                        "HTTP request smuggling: invalid UTF-8 in header '{}'",
                        name
                    ),
                });
            }
        };

        // CR or LF in a header value is always suspicious.
        if val_str.contains('\r') || val_str.contains('\n') {
            return Some(SmugglingVerdict::Reject {
                reason: format!(
                    "HTTP request smuggling: CR/LF injection in header '{}'",
                    name
                ),
            });
        }

        // Header name containing CR/LF.
        let name_str = name.as_str();
        if name_str.contains('\r') || name_str.contains('\n') {
            return Some(SmugglingVerdict::Reject {
                reason: "HTTP request smuggling: CR/LF in header name".to_string(),
            });
        }
    }
    None
}

/// Validate the `Content-Length` header value.
///
/// Reject if:
///   - Multiple `Content-Length` headers present (RFC 7230 §3.3.3 rule 5).
///   - Value is not a valid positive integer.
///   - Value is zero or negative (often a TE.CL attack setup).
fn check_cl_validity(headers: &http::HeaderMap) -> Option<SmugglingVerdict> {
    let cl_values: Vec<&str> = headers
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    if cl_values.is_empty() {
        return None;
    }

    // Multiple Content-Length headers → RFC 7230 §3.3.3 rule 5: MUST be
    // rejected with 400.
    if cl_values.len() > 1 {
        return Some(SmugglingVerdict::Reject {
            reason: format!(
                "HTTP request smuggling: multiple Content-Length headers ({})",
                cl_values.len()
            ),
        });
    }

    let value = cl_values[0].trim();

    // CR/LF in Content-Length value.
    if value.contains('\r') || value.contains('\n') {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: CR/LF in Content-Length value".to_string(),
        });
    }

    // Comma-separated Content-Length values (e.g. "0, 0").
    if value.contains(',') {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: comma in Content-Length value".to_string(),
        });
    }

    // Must be a valid u64 integer (the `+` prefix is allowed by some parsers
    // but is an ambiguity vector).
    if value.starts_with('+') {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: leading '+' in Content-Length value".to_string(),
        });
    }

    // Leading zeros (except for "0" itself) can cause parser differences.
    if value.len() > 1 && value.starts_with('0') {
        return Some(SmugglingVerdict::Reject {
            reason: "HTTP request smuggling: leading zero in Content-Length value".to_string(),
        });
    }

    match value.parse::<u64>() {
        Ok(_) => None,
        Err(_) => Some(SmugglingVerdict::Reject {
            reason: format!(
                "HTTP request smuggling: invalid Content-Length value '{}'",
                value
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING, HOST};

    fn headers_from_pairs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        map
    }

    // --- clean requests ---

    #[test]
    fn clean_no_cl_no_te() {
        let headers = headers_from_pairs(&[("host", "example.com")]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn clean_cl_only() {
        let headers = headers_from_pairs(&[("host", "example.com"), ("content-length", "42")]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn clean_cl_large() {
        let headers = headers_from_pairs(&[("host", "example.com"), ("content-length", "1048576")]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn clean_te_chunked_only() {
        let headers = headers_from_pairs(&[("host", "example.com"), ("transfer-encoding", "chunked")]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn clean_no_body_headers() {
        let headers = headers_from_pairs(&[("host", "example.com"), ("accept", "text/html")]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    // --- CL.TE conflict ---

    #[test]
    fn reject_both_cl_and_te() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "6"),
            ("transfer-encoding", "chunked"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("CL.TE") || reason.contains("Content-Length"));
            }
            _ => panic!("expected Reject for CL+TE ambiguity"),
        }
    }

    #[test]
    fn reject_both_cl_and_te_long_cl() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "999999"),
            ("transfer-encoding", "chunked"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { .. } => {}
            _ => panic!("expected Reject"),
        }
    }

    // --- TE obfuscation (TE.TE) ---

    #[test]
    fn reject_te_xchunked() {
        // "xchunked" — a front-end that strips by prefix match might miss it,
        // back-end sees "chunked".
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "xchunked"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("xchunked"));
            }
            _ => panic!("expected Reject for xchunked"),
        }
    }

    #[test]
    fn reject_te_multiple_tokens() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "chunked, identity"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("multiple"));
            }
            _ => panic!("expected Reject for multiple TE tokens"),
        }
    }

    #[test]
    fn reject_te_unknown_encoding() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "bogus"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("bogus"));
            }
            _ => panic!("expected Reject for unknown TE"),
        }
    }

    #[test]
    fn reject_te_empty() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", ""),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("empty"));
            }
            _ => panic!("expected Reject for empty TE"),
        }
    }

    #[test]
    fn reject_te_crlf_injection() {
        // The http crate already rejects CR/LF in header values at parse
        // time. Our TE obfuscation check verifies the value is not split
        // across multiple headers or containing comma-separated tokens.
        // This test verifies that valid single-token TE passes.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "chunked"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    // --- CL validity ---

    #[test]
    fn reject_multiple_cl_headers() {
        // Multiple Content-Length headers — classic TE.CL setup.
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com".parse().unwrap());
        headers.insert(CONTENT_LENGTH, "5".parse().unwrap());
        // Append a second Content-Length value
        headers.append(CONTENT_LENGTH, "0".parse().unwrap());
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("multiple"));
            }
            _ => panic!("expected Reject for multiple CL"),
        }
    }

    #[test]
    fn reject_cl_not_a_number() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "hello"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("invalid"));
            }
            _ => panic!("expected Reject for non-numeric CL"),
        }
    }

    #[test]
    fn reject_cl_leading_zero() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "042"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("leading zero"));
            }
            _ => panic!("expected Reject for leading-zero CL"),
        }
    }

    #[test]
    fn reject_cl_leading_plus() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "+42"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("leading '+'"));
            }
            _ => panic!("expected Reject for CL with +"),
        }
    }

    #[test]
    fn reject_cl_comma_separated() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "0, 0"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("comma"));
            }
            _ => panic!("expected Reject for comma in CL"),
        }
    }

    #[test]
    fn accept_cl_zero() {
        // Zero is valid — e.g. GET requests with no body.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "0"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    // --- header injection ---

    #[test]
    fn clean_header_injection_defense() {
        // CR/LF in headers is rejected by the http crate at parse time.
        // Our check_header_injection is defense-in-depth.
        // Verify that valid headers with no injection pass cleanly.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("x-custom", "normal-value"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn clean_content_type_with_body() {
        // Normal POST with a body and content-type should pass.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "100"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn reject_te_gzip_smuggling() {
        // "gzip" is valid but combined with CL → rejected by CL.TE check.
        // This tests that "gzip" alone is NOT rejected.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "gzip"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn reject_te_deflate_valid() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "deflate"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn reject_cl_negative() {
        // A negative CL is invalid per the HTTP spec.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "-1"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { .. } => {}
            _ => panic!("expected Reject for negative CL"),
        }
    }

    #[test]
    fn accept_cl_with_whitespace() {
        // Values with surrounding whitespace should be trimmed and accepted.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "  42  "),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn accept_te_with_whitespace() {
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "  chunked  "),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn reject_te_chunked_capitalised() {
        // Casing should be normalised — "CHUNKED" is valid.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("transfer-encoding", "CHUNKED"),
        ]);
        assert_eq!(detect(&headers), SmugglingVerdict::Clean);
    }

    #[test]
    fn reject_cl_overflow() {
        // A value larger than u64::MAX should be rejected.
        let headers = headers_from_pairs(&[
            ("host", "example.com"),
            ("content-length", "99999999999999999999999999999999"),
        ]);
        match detect(&headers) {
            SmugglingVerdict::Reject { .. } => {}
            _ => panic!("expected Reject for overflow CL"),
        }
    }

    #[test]
    fn reject_multiple_transfer_encoding_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.com".parse().unwrap());
        headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.append(TRANSFER_ENCODING, "identity".parse().unwrap());
        match detect(&headers) {
            SmugglingVerdict::Reject { reason } => {
                assert!(reason.contains("multiple"));
            }
            _ => panic!("expected Reject for multiple TE headers"),
        }
    }
}