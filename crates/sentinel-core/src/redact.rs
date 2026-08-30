//! One definition of "this value must never be written down".
//!
//! # Why this lives in core rather than beside either caller
//!
//! Two components independently decide whether a value is a secret: the rule VM,
//! when it captures the text a rule matched, and the proxy, when it writes an
//! access-log line. They were written at different times with different lists,
//! and the gap between them was a real leak: the VM's list never covered cookies
//! or headers, and the proxy's query-string logging had no list at all, so a
//! session JWT that tripped a libinjection rule was written verbatim into
//! `waf.log`, into ClickHouse under a 90-day retention, and out to the SIEM.
//!
//! Two lists that must agree are a list that will drift. This is the one list.
//!
//! # What this is and is not
//!
//! It is a NAME-based heuristic: it judges the parameter, cookie or header a
//! value arrived under, never the value itself. That is deliberate. Content
//! sniffing for "this looks like a JWT" both misses secrets that do not match a
//! known shape and redacts attack payloads that happen to look like one — and an
//! attack payload is precisely what the log exists to preserve. Redacting by
//! name keeps `?q=1' UNION SELECT` fully visible while removing `?token=…`.
//!
//! It is therefore not a guarantee. An application that puts a session id in a
//! parameter called `s` defeats it. It removes the overwhelmingly common cases —
//! the ones that appear in every framework's login, reset and OAuth flows.

/// Substrings that mark a field name as carrying a credential.
///
/// Substring matching is intentional: it covers `current_password`,
/// `x-auth-token`, `csrf_token` and `card_cvv` without anyone having to
/// enumerate every spelling an application might invent.
const SENSITIVE_NAME_PARTS: [&str; 22] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "auth",
    "session",
    "cookie",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "otp",
    "cvv",
    "cardnumber",
    "card_number",
    "signature",
    // OAuth / OIDC: `code` is the authorization code, `state` and `nonce` bind a
    // session to a redirect. All three are single-use credentials in flight.
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "assertion",
];

/// Exact field names that are credentials but whose names are too short or too
/// generic to match safely as substrings. `code` would otherwise redact
/// `country_code`, `postcode` and `zipcode`.
const SENSITIVE_NAME_EXACT: [&str; 5] = ["code", "state", "nonce", "sig", "jwt"];

/// The text substituted for a redacted value. Deliberately not empty: a reader
/// must be able to tell "this field was present and withheld" from "this field
/// was absent", because the difference matters when reconstructing a request.
pub const REDACTED: &str = "[redacted]";

/// Whether a value arriving under `name` must be kept out of logs and events.
///
/// Case-insensitive. Leading/trailing whitespace is ignored so a header name
/// with padding is not treated as a different field.
pub fn is_sensitive_field_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return false;
    }
    if SENSITIVE_NAME_EXACT.contains(&n.as_str()) {
        return true;
    }
    SENSITIVE_NAME_PARTS.iter().any(|s| n.contains(s))
}

/// Rewrite a URL-encoded query string, replacing the VALUES of
/// sensitively-named parameters while leaving everything else byte-identical.
///
/// Names are preserved on purpose. Knowing that a request carried a `token`
/// parameter is useful forensics; knowing its value is a liability. Attack
/// payloads live in ordinary parameters and pass through untouched, which is
/// what keeps the log worth reading.
///
/// Operates on the RAW (still percent-encoded) query, because the log records
/// the raw query. The name is compared after percent-decoding so that
/// `%74oken=` cannot smuggle a secret past the check.
pub fn redact_query(query: &str) -> String {
    // Fast path: most requests carry no sensitive parameter at all, and this
    // runs on the logging path of every request.
    if query.is_empty() {
        return String::new();
    }
    if !query.split(['&', ';']).any(|pair| {
        let name = pair.split('=').next().unwrap_or("");
        is_sensitive_field_name(&percent_decode_lossy(name))
    }) {
        return query.to_string();
    }

    let mut out = String::with_capacity(query.len());
    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((name, _value)) if is_sensitive_field_name(&percent_decode_lossy(name)) => {
                out.push_str(name);
                out.push('=');
                out.push_str(REDACTED);
            }
            _ => out.push_str(pair),
        }
    }
    out
}

/// Redact the query string of a URL while keeping scheme, host and path.
///
/// Used for `Referer`, which routinely carries the previous page's URL — and a
/// password-reset or OAuth-callback page has its single-use credential right
/// there in the query. The path is kept because "which screen was this request
/// made from" is the reason the field is logged at all.
pub fn redact_url_query(url: &str) -> String {
    match url.split_once('?') {
        None => url.to_string(),
        Some((head, tail)) => {
            // Keep any fragment intact and out of the redaction pass: it never
            // reaches a server and is not ours to rewrite.
            let (q, frag) = match tail.split_once('#') {
                Some((q, f)) => (q, Some(f)),
                None => (tail, None),
            };
            let mut out = format!("{head}?{}", redact_query(q));
            if let Some(f) = frag {
                out.push('#');
                out.push_str(f);
            }
            out
        }
    }
}

/// Minimal percent-decode for comparing a parameter NAME against the list.
///
/// Deliberately lossy and allocation-light: it exists so `%74oken` is recognised
/// as `token`, not to reconstruct the value. Invalid escapes are left as-is
/// rather than dropped, because a name that fails to decode should still be
/// compared against the list in the form it arrived.
fn percent_decode_lossy(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_names_are_recognised_including_compounds() {
        for n in [
            "password",
            "current_password",
            "Passwd",
            "PWD",
            "api_key",
            "apiKey",
            "X-Api-Key",
            "authorization",
            "auth",
            "session",
            "sessionid",
            "csrf_token",
            "access_token",
            "refresh_token",
            "client_secret",
            "card_cvv",
            "otp",
            "signature",
            "  Token  ",
        ] {
            assert!(
                is_sensitive_field_name(n),
                "{n} should be treated as a secret"
            );
        }
    }

    #[test]
    fn ordinary_names_are_not_redacted() {
        // Over-redaction destroys the forensic value the log exists for, so the
        // false-positive direction matters as much as the false-negative one.
        for n in [
            "q",
            "search",
            "id",
            "page",
            "country_code",
            "postcode",
            "zipcode",
            "name",
            "email",
            "product",
            "sort",
            "filter",
            "redirect_uri",
            "",
        ] {
            assert!(!is_sensitive_field_name(n), "{n} must NOT be redacted");
        }
    }

    #[test]
    fn short_generic_names_match_only_exactly() {
        // `code` is an OAuth credential; `country_code` is not.
        assert!(is_sensitive_field_name("code"));
        assert!(is_sensitive_field_name("state"));
        assert!(!is_sensitive_field_name("country_code"));
        assert!(!is_sensitive_field_name("statement"));
    }

    #[test]
    fn query_redaction_keeps_the_attack_and_removes_the_secret() {
        let q = "q=1%27+UNION+SELECT+pw&token=eyJhbGciOiJIUzI1NiJ9.abc&page=2";
        let out = redact_query(q);
        // The payload is why the log exists.
        assert!(out.contains("q=1%27+UNION+SELECT+pw"), "{out}");
        assert!(out.contains("page=2"), "{out}");
        // The credential is not.
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "{out}");
        assert!(out.contains("token=[redacted]"), "{out}");
    }

    #[test]
    fn a_query_with_no_secrets_is_returned_unchanged() {
        let q = "q=shoes&page=2&sort=asc";
        assert_eq!(redact_query(q), q);
        assert_eq!(redact_query(""), "");
    }

    #[test]
    fn percent_encoded_names_cannot_smuggle_a_secret_through() {
        // %74 is 't', so this is really `token=`.
        let out = redact_query("%74oken=supersecret&q=1");
        assert!(!out.contains("supersecret"), "{out}");
        assert!(out.contains("q=1"), "{out}");
    }

    #[test]
    fn valueless_and_malformed_pairs_survive() {
        assert_eq!(redact_query("flag&q=1"), "flag&q=1");
        // A bare sensitive name with no value has nothing to redact.
        assert_eq!(redact_query("token"), "token");
        // An empty value still gets the marker, so the field's presence shows.
        assert_eq!(redact_query("token="), "token=[redacted]");
    }

    #[test]
    fn referer_query_is_redacted_but_the_page_is_kept() {
        // The classic leak: a password-reset page's single-use token arriving in
        // the Referer of every asset the page loads.
        let r = redact_url_query("https://app.example/reset?token=abc123&lang=en");
        assert!(r.starts_with("https://app.example/reset?"), "{r}");
        assert!(!r.contains("abc123"), "{r}");
        assert!(r.contains("lang=en"), "{r}");

        // No query: untouched.
        assert_eq!(
            redact_url_query("https://app.example/home"),
            "https://app.example/home"
        );
        // Fragment preserved and not rewritten — it never reaches a server.
        let f = redact_url_query("https://app/#/search?token=x");
        assert!(f.contains('#'), "{f}");
    }
}
