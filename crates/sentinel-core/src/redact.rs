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
//!
//! Three names are deliberately ambiguous and resolved toward redaction:
//! `state` is an OAuth CSRF token but also a postal address field, `code` is an
//! authorization code but also a discount code, and `pin` is an authentication
//! PIN but also, in India, a postal code. All are redacted. Each benign reading
//! is personal data of near-zero forensic value while each sensitive reading is
//! a live credential, so the cost of being wrong is lopsided.
//!
//! # Keeping the list honest
//!
//! The list is checked against real framework defaults by
//! `tests/name_survey.rs`, which is where `PHPSESSID` and `connect.sid` were
//! caught: `session` as a substring looks like it covers session cookies and
//! does not, because neither name contains "session". Add to that survey before
//! adding here — it asserts in BOTH directions, since a list that redacts
//! everything is as useless as one that redacts nothing.

/// Substrings that mark a field name as carrying a credential.
///
/// Substring matching is intentional: it covers `current_password`,
/// `x-auth-token`, `csrf_token` and `card_cvv` without anyone having to
/// enumerate every spelling an application might invent.
const SENSITIVE_NAME_PARTS: [&str; 38] = [
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
    "oauth",
    // Framework session cookies. `session` as a substring looks like it covers
    // these and does not: PHP's `PHPSESSID` and Express's `connect.sid` contain
    // no "session" at all, and between them they are most of the web. Found by
    // surveying the list against real framework defaults after real traffic on
    // .71 showed a live socket.io `sid` passing through unredacted.
    "phpsessid",
    "sessid",
    "connect.sid",
    "wordpress_logged_in",
    // CSRF tokens. Stealing one is not session theft, but it is the second half
    // of an attack, and they appear in query strings constantly.
    "csrf",
    "xsrf",
    // SAML / federated SSO. The assertion IS the authentication.
    "saml",
    "relaystate",
    "bearer",
    // Long-lived secrets that are not session material but are just as bad in a
    // log that keeps 90 days.
    "private_key",
    "privatekey",
    "license_key",
    "licensekey",
    "recovery_code",
    "recoverycode",
];

/// Exact field names that are credentials but whose names are too short or too
/// generic to match safely as substrings. `code` would otherwise redact
/// `country_code`, `postcode` and `zipcode`; `ticket` would redact every
/// helpdesk `ticket_id`; `pass` would redact `passenger_name`.
const SENSITIVE_NAME_EXACT: [&str; 11] = [
    "code", "state", "nonce", "sig", "jwt",  // OAuth / OIDC / signing
    "sid",  // socket.io and generic session id — seen live on .71
    "pass", // a field called exactly "pass" is a password
    "pin",  // see the module note: PIN vs Indian postal PIN code
    "mfa", "sso", "ticket", // CAS service ticket
];

/// Names whose PREFIX marks them sensitive.
///
/// Exists for Drupal, whose session cookies are `SESS<hash>` and `SSESS<hash>`.
/// Matching "ssess" as a substring would redact `assessment`, `assessor` and
/// `reassessment` — ordinary enterprise field names — so the position matters.
const SENSITIVE_NAME_PREFIX: [&str; 2] = ["ssess", "sess"];

/// Names that match a sensitive substring but are NOT credentials, checked
/// first and winning over everything else.
///
/// `auth` is matched as a substring so `x-auth-token` and `auth_key` are
/// covered without enumerating spellings — and that also swallows `author`,
/// which blog and CMS software uses constantly. Worse, `?author=1` is
/// WordPress user enumeration: an attack an operator specifically needs to
/// SEE. Redacting it would hide the payload while the alert still fired.
///
/// Note `authorization` also begins "author", so this cannot be a prefix rule;
/// the names are listed exactly.
const NOT_SENSITIVE_EXACT: [&str; 6] = [
    "author",
    "authors",
    "author_id",
    "authorid",
    "author_name",
    "authorship",
];

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
    // Exceptions win: a name here is never a credential, however it matches.
    if NOT_SENSITIVE_EXACT.contains(&n.as_str()) {
        return false;
    }
    if SENSITIVE_NAME_EXACT.contains(&n.as_str()) {
        return true;
    }
    if SENSITIVE_NAME_PREFIX.iter().any(|p| n.starts_with(p)) {
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

    // Walk the pairs honouring BOTH separators, and put back the one that
    // actually arrived. The check above splits on `&` and `;`; if this loop
    // split on `&` alone, then `a=1;token=x` would be recognised as sensitive
    // and then walked as a SINGLE pair named "a" — passed through with the
    // credential still in it. Splitting on both is not optional once the
    // detection does.
    let mut out = String::with_capacity(query.len() + REDACTED.len());
    let mut rest = query;
    loop {
        let (pair, sep, tail) = match rest.find(['&', ';']) {
            Some(i) => (&rest[..i], Some(&rest[i..i + 1]), &rest[i + 1..]),
            None => (rest, None, ""),
        };
        match pair.split_once('=') {
            Some((name, _value)) if is_sensitive_field_name(&percent_decode_lossy(name)) => {
                out.push_str(name);
                out.push('=');
                out.push_str(REDACTED);
            }
            _ => out.push_str(pair),
        }
        match sep {
            Some(s) => {
                out.push_str(s);
                rest = tail;
            }
            None => break,
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
    // Split the FRAGMENT off first. Splitting on `?` first looks equivalent and
    // is not: in `…/page?a=1#/reset?token=x` the first `?` belongs to the real
    // query, so the fragment — and the token in it — never reached the
    // redaction pass at all.
    let (before_frag, frag) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };

    let mut out = match before_frag.split_once('?') {
        Some((head, q)) => format!("{head}?{}", redact_query(q)),
        None => before_frag.to_string(),
    };

    if let Some(f) = frag {
        out.push('#');
        // The fragment IS redacted, contrary to the usual reasoning that it
        // never reaches a server. A single-page app keeps its route there, and
        // a reset link in an SPA looks exactly like `#/reset?token=…`. Browsers
        // strip the fragment from `Referer`, but we are not entitled to assume
        // the client is a browser — and whatever did arrive here is about to be
        // written to disk, to a 90-day store, and to the SIEM.
        match f.split_once('?') {
            Some((route, q)) => {
                out.push_str(route);
                out.push('?');
                out.push_str(&redact_query(q));
            }
            None => out.push_str(f),
        }
    }
    out
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
    fn author_is_not_a_credential_but_authorization_is() {
        // "auth" is matched as a SUBSTRING so that `x-auth-token` and
        // `auth_key` are covered — which also catches `author`. Blog and CMS
        // software uses `?author=` constantly, and WordPress author enumeration
        // (`?author=1`) is itself an attack an operator needs to SEE.
        for n in [
            "author",
            "Authors",
            "author_id",
            "author_name",
            "authorship",
        ] {
            assert!(!is_sensitive_field_name(n), "{n} must NOT be redacted");
        }
        // The real ones still are — note `authorization` also starts "author".
        for n in [
            "authorization",
            "Authorisation",
            "auth",
            "x-auth-token",
            "auth_key",
        ] {
            assert!(is_sensitive_field_name(n), "{n} SHOULD be redacted");
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
    fn a_semicolon_separated_query_is_redacted_too() {
        // Legacy but real: PHP's arg_separator and older HTML guidance both
        // allow `;`. The presence CHECK split on `;`, but the rewrite loop split
        // only on `&`, so `a=1;token=x` was detected as sensitive, then walked
        // as a single pair named "a" and passed through untouched — the exact
        // shape the function exists to stop.
        let out = redact_query("a=1;token=supersecret");
        assert!(!out.contains("supersecret"), "{out}");
        assert!(out.contains("a=1"), "{out}");
        let out = redact_query("token=supersecret;a=1");
        assert!(!out.contains("supersecret"), "{out}");
        // Separators are preserved as they arrived.
        assert!(out.contains(';'), "{out}");
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
        // An SPA keeps its route — and its single-use token — in the FRAGMENT:
        // `#/reset?token=...`. A browser strips the fragment from Referer, but
        // we are not entitled to assume the client is a browser, and whatever
        // arrived here is about to be written down.
        let f = redact_url_query("https://app/#/reset?token=fragsecret&lang=en");
        assert!(f.contains('#'), "{f}");
        assert!(!f.contains("fragsecret"), "{f}");
        assert!(f.contains("lang=en"), "{f}");

        // Both at once: a real query AND a fragment route with its own query.
        // Splitting on `?` before `#` made the fragment invisible to redaction.
        let b = redact_url_query("https://app/page?api_key=qsecret#/reset?token=fsecret");
        assert!(!b.contains("qsecret"), "{b}");
        assert!(!b.contains("fsecret"), "{b}");
        assert!(b.contains("/page?") && b.contains("#/reset?"), "{b}");
    }
}
