//! Does the sensitive-name list actually cover what real software sends?
//!
//! The list is a heuristic, and a heuristic that is never checked against
//! reality drifts into looking right. This survey is the check, and it earned
//! its place immediately: it found that `session` as a substring covers neither
//! `PHPSESSID` nor `connect.sid` — PHP's and Express's default session cookies,
//! which between them account for a large fraction of the web. Real traffic on
//! .71 had already been carrying a live socket.io `sid` through the logs
//! unredacted.
//!
//! It asserts in BOTH directions on purpose. Over-redaction is not the safe
//! side of this trade: a log that replaces every payload with `[redacted]` is
//! as useless as one that leaks, and two of the six defects in the original
//! redaction work were exactly that. Add names here before adding them to the
//! module.

use sentinel_core::redact::is_sensitive_field_name;

/// Credentials that real software really sends, by the name it really uses.
#[test]
fn real_world_credential_names_are_all_covered() {
    let names = [
        // --- framework session cookies, as shipped by default ---
        ("PHPSESSID", "PHP"),
        ("connect.sid", "Express.js"),
        ("sid", "socket.io / generic — seen live on .71"),
        ("JSESSIONID", "Java servlet"),
        ("ASP.NET_SessionId", "ASP.NET"),
        ("_session_id", "Rails"),
        ("laravel_session", "Laravel"),
        ("sessionid", "Django"),
        ("SSESS7f3a9c", "Drupal (HTTPS)"),
        ("SESS7f3a9c", "Drupal (HTTP)"),
        ("wordpress_logged_in_9a8b", "WordPress"),
        // --- CSRF ---
        ("_csrf", "generic"),
        ("csrftoken", "Django"),
        ("XSRF-TOKEN", "Angular / Laravel"),
        // --- OAuth / OIDC ---
        ("access_token", "OAuth2"),
        ("refresh_token", "OAuth2"),
        ("id_token", "OIDC"),
        ("client_secret", "OAuth2"),
        ("oauth_token", "OAuth1"),
        ("oauth_verifier", "OAuth1"),
        ("client_assertion", "OIDC private_key_jwt"),
        ("code", "authorization code"),
        ("state", "CSRF binding"),
        ("nonce", "replay binding"),
        // --- SAML / federated SSO ---
        ("SAMLResponse", "SAML"),
        ("saml_response", "SAML"),
        ("RelayState", "SAML"),
        ("ticket", "CAS service ticket"),
        ("sso", "generic"),
        // --- bearer / API credentials ---
        ("Authorization", "HTTP"),
        ("bearer", "generic"),
        ("X-Api-Key", "generic"),
        ("api_key", "generic"),
        ("apikey", "generic"),
        ("private_key", "generic"),
        ("license_key", "generic"),
        ("webhook_secret", "generic"),
        // --- passwords and second factors ---
        ("password", "generic"),
        ("current_password", "change-password form"),
        ("passwd", "unix-ish"),
        ("pwd", "generic"),
        ("pass", "generic"),
        ("pin", "auth PIN"),
        ("otp", "2FA"),
        ("totp", "2FA"),
        ("mfa", "2FA"),
        ("recovery_code", "2FA backup"),
        // --- payment ---
        ("cvv", "card"),
        ("card_number", "card"),
        ("cardnumber", "card"),
    ];

    let missed: Vec<String> = names
        .iter()
        .filter(|(n, _)| !is_sensitive_field_name(n))
        .map(|(n, who)| format!("{n}  ({who})"))
        .collect();
    assert!(
        missed.is_empty(),
        "these credentials would be written to the log verbatim:\n  {}",
        missed.join("\n  ")
    );
}

/// The other half. Every one of these is a name a real application uses for
/// something an operator needs to READ in a log.
#[test]
fn ordinary_field_names_are_left_alone() {
    let names = [
        // the socket.io/SPA traffic actually seen on .71
        ("EIO", "socket.io protocol version"),
        ("transport", "socket.io transport"),
        ("t", "cache buster"),
        ("q", "search"),
        ("fields", "sparse fieldset"),
        ("name", "generic"),
        // attacks an operator must be able to see in full
        ("author", "WordPress user enumeration"),
        ("author_id", "CMS"),
        ("file", "traversal payloads live here"),
        ("cmd", "command injection payloads live here"),
        ("url", "SSRF payloads live here"),
        ("redirect_uri", "open-redirect payloads live here"),
        ("id", "IDOR / SQLi payloads live here"),
        // ordinary business fields, several of which nearly matched
        ("assessment", "vs Drupal's SSESS prefix"),
        ("assessor", "vs Drupal's SSESS prefix"),
        ("reassessment", "vs Drupal's SSESS prefix"),
        ("ticket_id", "helpdesk — vs the CAS `ticket`"),
        ("support_ticket", "helpdesk"),
        ("passenger_name", "vs `pass`"),
        ("passport_number", "vs `pass`"),
        ("pincode", "Indian postal code — vs `pin`"),
        ("country_code", "vs `code`"),
        ("postcode", "vs `code`"),
        ("zipcode", "vs `code`"),
        ("statement", "vs `state`"),
        ("estate", "vs `state`"),
        ("email", "generic"),
        ("page", "generic"),
        ("sort", "generic"),
        ("filter", "generic"),
        ("product", "generic"),
        ("quantity", "generic"),
        ("", "empty"),
    ];

    let over: Vec<String> = names
        .iter()
        .filter(|(n, _)| is_sensitive_field_name(n))
        .map(|(n, why)| format!("{n}  ({why})"))
        .collect();
    assert!(
        over.is_empty(),
        "these would be redacted, destroying evidence an operator needs:\n  {}",
        over.join("\n  ")
    );
}
