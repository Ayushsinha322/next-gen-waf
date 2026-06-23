//! Tests for two detection capabilities added to close production gaps:
//!   1. JSON request-body parsing into the ARGS collection (API protection).
//!   2. Response-body rule evaluation (CRS RESPONSE-* / data-leakage rules).

mod common;

use bytes::Bytes;
use common::*;
use sentinel_core::context::{Phase, WafDecision};
use sentinel_rules::RuleEngine;

// ---------------------------------------------------------------------------
// 1. JSON body → ARGS
// ---------------------------------------------------------------------------

/// Build a POST context whose body is `application/json`.
fn json_post_ctx(uri: &str, body: &str) -> sentinel_core::context::RequestContext {
    let mut ctx = make_post_ctx(uri, body);
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    ctx
}

#[test]
fn sqli_in_json_body_is_detected() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut ctx = json_post_ctx(
        "/api/login",
        r#"{"username":"admin","password":"x' OR 1=1-- -"}"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(&ctx, 5, "SQLi inside a JSON body field should trigger SQLi rules");
}

#[test]
fn sqli_in_nested_json_body_is_detected() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut ctx = json_post_ctx(
        "/api/search",
        r#"{"filter":{"query":"1 UNION SELECT password FROM users"}}"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(&ctx, 5, "SQLi in a nested JSON object should trigger");
}

#[test]
fn xss_in_json_array_is_detected() {
    let eng = load_crs_engine("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
    let mut ctx = json_post_ctx(
        "/api/comments",
        r#"{"tags":["ok","<script>alert(1)</script>"]}"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(&ctx, 5, "XSS in a JSON array element should trigger");
}

#[test]
fn clean_json_body_passes() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut ctx = json_post_ctx(
        "/api/login",
        r#"{"username":"alice","password":"correct horse battery staple"}"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_clean(&ctx, "legitimate JSON login should not trigger SQLi rules");
}

// ---------------------------------------------------------------------------
// 2. Response-body rule evaluation
// ---------------------------------------------------------------------------

/// A minimal rule set with a single response-body (phase 4 = RESPONSE_BODY)
/// rule that blocks when the response leaks the marker `TOP_SECRET_TOKEN`.
fn response_body_engine() -> RuleEngine {
    let conf = r#"
SecRule RESPONSE_BODY "@rx TOP_SECRET_TOKEN" \
    "id:9001,phase:4,block,msg:'data leakage detected in response body'"
"#;
    let file = sentinel_rules::import_secrule_conf_dir(conf, None)
        .expect("import response-body rule");
    let ruleset = sentinel_rules::compile(file).expect("compile response-body rule");
    RuleEngine::new(ruleset)
}

#[test]
fn engine_reports_response_body_rules() {
    let eng = response_body_engine();
    assert!(
        eng.has_response_body_rules(),
        "engine with a phase-4 rule must report response-body rules"
    );

    // A request-only ruleset must NOT report response-body rules (so the proxy
    // never needlessly buffers the response).
    let req_only = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    assert!(
        !req_only.has_response_body_rules(),
        "REQUEST-only CRS file must not report response-body rules"
    );
}

#[test]
fn response_body_leak_is_blocked() {
    let eng = response_body_engine();
    let mut ctx = make_get_ctx("/account");
    ctx.response_body = Some(Bytes::from_static(
        b"{\"balance\":100,\"debug\":\"TOP_SECRET_TOKEN=abc123\"}",
    ));
    let decision = eng.evaluate(&mut ctx, Phase::ResponseBody, 5);
    assert_eq!(
        decision,
        WafDecision::Block,
        "response body leaking the secret marker must be blocked"
    );
}

#[test]
fn clean_response_body_passes() {
    let eng = response_body_engine();
    let mut ctx = make_get_ctx("/account");
    ctx.response_body = Some(Bytes::from_static(b"{\"balance\":100,\"status\":\"ok\"}"));
    let decision = eng.evaluate(&mut ctx, Phase::ResponseBody, 5);
    assert_eq!(
        decision,
        WafDecision::Allow,
        "clean response body must pass"
    );
}
