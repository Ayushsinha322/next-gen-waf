//! What the classifier is asked to judge, pinned by the requests it got wrong.
//!
//! On 2026-09-23 the model ALONE (no rule matching) blocked two ordinary Juice
//! Shop requests on the demo cluster: a basket update whose raw JSON body scored
//! 0.905 while every field in it scored < 0.01, and `GET /rest/user/whoami`,
//! whose path segment `whoami` scores 0.922 on vocabulary alone. Measured over
//! the corpora (zz_ml_placement_compare), scoring the raw body of parsed JSON
//! flagged 54.95% of hard-benign text in a nested document; field-only scoring
//! flags 2.46%, the same as the query string.
use std::net::{IpAddr, Ipv4Addr};

fn ctx(uri: &str, ct: Option<&str>, body: Option<&str>) -> sentinel_core::context::RequestContext {
    let mut c =
        sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 0);
    c.uri = uri.parse().unwrap();
    if let Some(ct) = ct {
        c.request_headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(ct).unwrap(),
        );
    }
    c.request_body = body.map(|b| bytes::Bytes::from(b.to_owned()));
    c
}

fn score(c: &sentinel_core::context::RequestContext) -> f32 {
    sentinel_ml::MlEngine::new(64, 1_000_000, None)
        .evaluate(c)
        .payload_attack_score
}

const DETECTION_MIN: f32 = 0.9;

#[test]
fn an_ordinary_nested_json_body_is_not_an_attack() {
    let s = score(&ctx(
        "/api/BasketItems",
        Some("application/json"),
        Some(
            r#"{"items":[{"id":1,"qty":2},{"id":5,"qty":1}],"note":"deliver after 6pm; ring twice"}"#,
        ),
    ));
    assert!(s < DETECTION_MIN, "basket update scored {s}");
}

#[test]
fn a_plain_word_in_the_path_is_not_an_attack() {
    let s = score(&ctx("/rest/user/whoami", None, None));
    assert!(s < DETECTION_MIN, "GET /rest/user/whoami scored {s}");
}

#[test]
fn attacks_in_json_fields_are_still_seen() {
    for body in [
        r#"{"q":"1' UNION SELECT password FROM users--"}"#,
        r#"{"items":[{"note":"<script>alert(document.cookie)</script>"}]}"#,
        r#"{"cmd":"; cat /etc/passwd"}"#,
    ] {
        let s = score(&ctx("/api/x", Some("application/json"), Some(body)));
        assert!(s >= DETECTION_MIN, "{body} scored only {s}");
    }
}

#[test]
fn a_body_that_does_not_parse_is_still_scored_whole() {
    let s = score(&ctx(
        "/api/x",
        Some("application/json"),
        Some(r#"{"q": "1' OR 1=1-- "#),
    ));
    assert!(
        s >= DETECTION_MIN,
        "malformed JSON carrying SQLi scored only {s}"
    );
}

#[test]
fn a_path_segment_with_structure_is_still_scored() {
    for uri in [
        "/p/..%2f..%2fetc%2fpasswd",
        "/p/%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/p/;cat%20%2Fetc%2Fpasswd",
    ] {
        let s = score(&ctx(uri, None, None));
        assert!(s >= DETECTION_MIN, "{uri} scored only {s}");
    }
}

/// The 1.1.7 regression GoTestWAF found: a Base64 attack is letters and digits,
/// so the plain-word rule skipped it in the URL path. Long segments are scored.
#[test]
fn a_base64_attack_in_the_path_is_still_scored() {
    // base64('"onClick="(prompt)(1)'), no padding characters
    let s = score(&ctx("/p/Im9uQ2xpY2s9Iihwcm9tcHQpKDEp", None, None));
    assert!(
        s >= DETECTION_MIN,
        "base64 XSS path segment scored only {s}"
    );
}

/// The other one: a traversal in a multipart part's filename lived only in the
/// raw body, which a parsed body no longer contributes whole.
#[test]
fn a_multipart_filename_is_scored() {
    let b = "--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"/static/img/../../etc/passwd\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XyZ--\r\n";
    let s = score(&ctx(
        "/upload",
        Some("multipart/form-data; boundary=XyZ"),
        Some(b),
    ));
    assert!(
        s >= DETECTION_MIN,
        "multipart filename traversal scored only {s}"
    );
}

/// Short Base64 is still Base64: `(alert)(1)` → 14 characters.
#[test]
fn a_short_base64_attack_in_the_path_is_still_scored() {
    for seg in ["KGFsZXJ0KSgxKQ", "Jy1hbGVydCgxKS8v"] {
        let s = score(&ctx(&format!("/p/{seg}"), None, None));
        assert!(s >= DETECTION_MIN, "{seg} scored only {s}");
    }
}

/// The classifier's veto may only judge what it saw. A header holding a byte
/// 0x80 or above was skipped whole (`to_str()` refuses it) while the rules matched
/// it, so its payload scored as nothing — and could veto a correct block.
#[test]
fn a_header_with_a_non_ascii_byte_is_still_scored() {
    let mut c = ctx("/", None, None);
    c.request_headers.insert(
        http::header::HeaderName::from_static("x-note"),
        http::HeaderValue::from_bytes(b"caf\xe9 <script>alert(document.cookie)</script>").unwrap(),
    );
    let s = score(&c);
    assert!(
        s >= DETECTION_MIN,
        "a header payload behind a non-ASCII byte scored only {s}"
    );
}

#[test]
fn a_cookie_in_a_field_with_a_non_ascii_byte_is_still_scored() {
    let mut c = ctx("/", None, None);
    c.request_headers.append(
        http::header::COOKIE,
        http::HeaderValue::from_bytes(b"lang=caf\xe9; pref=1' UNION SELECT password FROM users--")
            .unwrap(),
    );
    let s = score(&c);
    assert!(
        s >= DETECTION_MIN,
        "a cookie payload behind a non-ASCII byte scored only {s}"
    );
}

/// A Host, Origin or same-site Referer that only names a place decided the
/// veto for a whole site: `test-site.local` scored 0.505, over the 0.5 cut-off,
/// so no weak block there could be vetoed — and `http://localhost:3000/` scored
/// 0.909, enough to block a request on its own.
#[test]
fn a_plain_host_or_url_header_does_not_decide_the_score() {
    let mut c = ctx(
        "/search?q=We%20moved%3B%20update%20my%20address",
        None,
        None,
    );
    for (h, v) in [
        (http::header::HOST, "test-site.local"),
        (http::header::REFERER, "http://localhost:3000/"),
        (http::header::ORIGIN, "https://my-test-app.internal"),
    ] {
        c.request_headers
            .insert(h, http::HeaderValue::from_static(v));
    }
    let s = score(&c);
    assert!(s < 0.5, "an ordinary request on such a site scored {s}");
}

#[test]
fn a_host_or_referer_carrying_a_payload_is_still_scored() {
    for (h, v) in [
        (
            http::header::HOST,
            "x'><script>alert(document.cookie)</script>",
        ),
        (
            http::header::REFERER,
            "https://shop.example.in/?q=1' UNION SELECT password FROM users--",
        ),
    ] {
        let mut c = ctx("/", None, None);
        c.request_headers
            .insert(h.clone(), http::HeaderValue::from_str(v).unwrap());
        let s = score(&c);
        assert!(s >= DETECTION_MIN, "{h}: {v} scored only {s}");
    }
}

fn with_cookie(
    mut c: sentinel_core::context::RequestContext,
    cookie: &str,
) -> sentinel_core::context::RequestContext {
    c.request_headers.insert(
        http::header::COOKIE,
        http::HeaderValue::from_str(cookie).unwrap(),
    );
    c
}

/// On open-appsec's 1.04 million real browsing requests, 75% of the legitimate
/// requests the classifier blocked were blocked for one cookie value: consent and
/// analytics cookies the model never saw as benign. A cookie value may no longer
/// add to the anomaly score, but the veto still sees it.
#[test]
fn a_cookie_value_cannot_make_the_classifier_block_but_the_veto_still_sees_it() {
    let engine = sentinel_ml::MlEngine::new(64, 1_000_000, None);
    let attack = "1' UNION SELECT password FROM users--";

    let in_cookie = engine.evaluate(&with_cookie(
        ctx("/products", None, None),
        &format!("pref={attack}"),
    ));
    assert!(
        in_cookie.payload_attack_score >= DETECTION_MIN,
        "the veto must see a cookie-borne attack (scored {})",
        in_cookie.payload_attack_score
    );
    assert!(
        in_cookie.combined_score < DETECTION_MIN,
        "a cookie value alone added to the score ({})",
        in_cookie.combined_score
    );

    let in_query = engine.evaluate(&ctx(
        &format!(
            "/products?q={}",
            attack.replace(' ', "%20").replace('\'', "%27")
        ),
        None,
        None,
    ));
    assert!(
        in_query.combined_score >= DETECTION_MIN,
        "a query attack must still add ({})",
        in_query.combined_score
    );

    // A real consent cookie (OneTrust's documented format) next to a clean query.
    let consent = "OptanonConsent=isGpcEnabled=0&datestamp=Mon+Oct+14+2024+10%3A00%3A00+GMT%2B0200&version=202409.1.0&isIABGlobal=false&hosts=&interactionCount=1&landingPath=NotLandingPage&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A0";
    let page = engine.evaluate(&with_cookie(ctx("/products?page=2", None, None), consent));
    assert!(
        page.combined_score < DETECTION_MIN,
        "consent cookie page view scored {}",
        page.combined_score
    );
}
