//! Every `Cookie` field, and every header holding a byte >= 0x80, reaches the
//! rules.
//!
//! HTTP/2 and HTTP/3 send one `Cookie` field per cookie, and the engine read
//! the first field only — live on .71 on 2026-10-06 a request whose CRS
//! matches were spread over several cookies matched 9 rules over HTTP/1.1 and
//! 1 over HTTP/2. And `to_str()` refused any byte >= 0x80, so a single such
//! byte hid a whole header, or every cookie in it, from every rule.

mod common;

use common::{eval, make_get_ctx};
use http::header::{HeaderName, HeaderValue, COOKIE};
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

fn engine_from(src: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf(src).expect("test rule must import");
    let ruleset = sentinel_rules::compile(file).expect("test rule must compile");
    RuleEngine::new(ruleset)
}

fn fired(engine: &RuleEngine, ctx: &mut RequestContext, id: &str) -> bool {
    eval(engine, ctx, Phase::RequestBody);
    ctx.rule_matches.iter().any(|m| m.rule_id == id)
}

/// A request as HTTP/2 delivers it: one `Cookie` field per cookie.
fn h2_cookies(fields: &[&[u8]]) -> RequestContext {
    let mut ctx = make_get_ctx("/");
    for f in fields {
        ctx.request_headers
            .append(COOKIE, HeaderValue::from_bytes(f).expect("valid field"));
    }
    ctx
}

const SQLI_COOKIE: &[u8] = b"pref=1' UNION SELECT password FROM users--";

#[test]
fn a_cookie_in_a_later_field_reaches_cookie_rules() {
    let engine = engine_from(
        r#"SecRule REQUEST_COOKIES "@rx union\s+select" "id:900301,phase:1,deny,t:lowercase,msg:'sqli'""#,
    );
    let mut ctx = h2_cookies(&[b"session=abc", SQLI_COOKIE]);
    assert!(
        fired(&engine, &mut ctx, "900301"),
        "the second Cookie field was not inspected"
    );
}

#[test]
fn cookie_names_in_a_later_field_are_seen() {
    let engine = engine_from(
        r#"SecRule REQUEST_COOKIES_NAMES "@rx ^__proto__" "id:900302,phase:1,deny,msg:'name'""#,
    );
    let mut ctx = h2_cookies(&[b"session=abc", b"__proto__=1"]);
    assert!(fired(&engine, &mut ctx, "900302"));
}

/// `REQUEST_HEADERS:Cookie` sees the header as HTTP/1.1 carries it: every
/// field, joined with `; `.
#[test]
fn the_whole_cookie_header_is_every_field_joined() {
    let engine = engine_from(
        r#"SecRule REQUEST_HEADERS:Cookie "@rx session=abc; pref=1' union" "id:900303,phase:1,deny,t:lowercase,msg:'whole'""#,
    );
    let mut ctx = h2_cookies(&[b"session=abc", SQLI_COOKIE]);
    assert!(fired(&engine, &mut ctx, "900303"));
}

#[test]
fn a_byte_above_0x7f_does_not_hide_the_cookies() {
    let engine = engine_from(
        r#"SecRule REQUEST_COOKIES "@rx union\s+select" "id:900304,phase:1,deny,t:lowercase,msg:'sqli'""#,
    );
    let mut ctx = h2_cookies(&[b"lang=caf\xe9; pref=1' UNION SELECT password FROM users--"]);
    assert!(
        fired(&engine, &mut ctx, "900304"),
        "one non-ASCII byte hid every cookie in its field"
    );
}

#[test]
fn a_byte_above_0x7f_does_not_hide_a_header() {
    let engine = engine_from(
        r#"SecRule REQUEST_HEADERS:X-Note|REQUEST_HEADERS "@rx <script" "id:900305,phase:1,deny,t:lowercase,msg:'xss'""#,
    );
    let mut ctx = make_get_ctx("/");
    ctx.request_headers.insert(
        HeaderName::from_static("x-note"),
        HeaderValue::from_bytes(b"caf\xe9 <script>alert(1)</script>").unwrap(),
    );
    assert!(
        fired(&engine, &mut ctx, "900305"),
        "a header holding a byte >= 0x80 was invisible to the rules"
    );
}

/// A repeated header is inspected in every field, not the first one only.
#[test]
fn every_field_of_a_repeated_header_is_inspected() {
    let engine = engine_from(
        r#"SecRule REQUEST_HEADERS:X-Note "@rx <script" "id:900306,phase:1,deny,t:lowercase,msg:'xss'""#,
    );
    let mut ctx = make_get_ctx("/");
    let name = HeaderName::from_static("x-note");
    ctx.request_headers
        .append(name.clone(), HeaderValue::from_static("hello"));
    ctx.request_headers
        .append(name, HeaderValue::from_static("<script>alert(1)</script>"));
    assert!(fired(&engine, &mut ctx, "900306"));
}

/// A clean request with several cookie fields still matches nothing.
#[test]
fn clean_cookie_fields_stay_clean() {
    let engine = engine_from(
        r#"SecRule REQUEST_COOKIES|REQUEST_HEADERS:Cookie "@rx union\s+select" "id:900307,phase:1,deny,t:lowercase,msg:'sqli'""#,
    );
    let mut ctx = h2_cookies(&[b"session=abc", b"lang=caf\xe9", b"theme=dark"]);
    assert!(!fired(&engine, &mut ctx, "900307"));
}
