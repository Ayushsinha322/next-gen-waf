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
