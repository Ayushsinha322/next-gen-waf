//! CRS's own target exclusions are honoured.
//!
//! 151 shipped CRS rules leave members out of a collection —
//! `REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/`, `!REQUEST_HEADERS:Referer` —
//! and the importer dropped every `!` token, so each of those rules inspected
//! exactly the values CRS had excluded: Google Analytics and Matomo cookies,
//! whose contents look like SQL often enough that CRS carves them out.

mod common;

use common::{eval, load_crs_engine, make_get_ctx, set_paranoia};
use http::header::{HeaderName, HeaderValue, COOKIE};
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

fn engine_from(src: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf(src).expect("test rule must import");
    let ruleset = sentinel_rules::compile(file).expect("test rule must compile");
    RuleEngine::new(ruleset)
}

fn with_cookie(cookie: &str) -> RequestContext {
    let mut ctx = make_get_ctx("/");
    ctx.request_headers
        .insert(COOKIE, HeaderValue::from_str(cookie).unwrap());
    ctx
}

fn fired(engine: &RuleEngine, ctx: &mut RequestContext, id: &str) -> bool {
    eval(engine, ctx, Phase::RequestBody);
    ctx.rule_matches.iter().any(|m| m.rule_id == id)
}

#[test]
fn a_negated_cookie_pattern_is_left_out() {
    let engine = engine_from(
        r#"SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS "@rx union\s+select" "id:900401,phase:1,deny,t:lowercase,msg:'sqli'""#,
    );
    assert!(
        !fired(
            &engine,
            &mut with_cookie("__utmz=1' UNION SELECT 1--"),
            "900401"
        ),
        "CRS excludes __utm* cookies from this rule"
    );
    assert!(
        fired(
            &engine,
            &mut with_cookie("pref=1' UNION SELECT 1--"),
            "900401"
        ),
        "every other cookie stays inspected"
    );
    assert!(
        fired(
            &engine,
            &mut with_cookie("__utmz=ok; pref=1' UNION SELECT 1--"),
            "900401"
        ),
        "an excluded cookie does not shield the others"
    );
}

#[test]
fn a_negated_header_is_left_out() {
    let engine = engine_from(
        r#"SecRule REQUEST_HEADERS|!REQUEST_HEADERS:Referer "@rx <script" "id:900402,phase:1,deny,t:lowercase,msg:'xss'""#,
    );
    let mut referer = make_get_ctx("/");
    referer.request_headers.insert(
        HeaderName::from_static("referer"),
        HeaderValue::from_static("https://example.com/?q=<script>"),
    );
    assert!(!fired(&engine, &mut referer, "900402"));

    let mut other = make_get_ctx("/");
    other.request_headers.insert(
        HeaderName::from_static("x-note"),
        HeaderValue::from_static("<script>alert(1)</script>"),
    );
    assert!(fired(&engine, &mut other, "900402"));
}

/// The shipped SQLi rules, as an operator runs them: an analytics cookie
/// gets the exclusions CRS wrote for it.
#[test]
fn the_shipped_sqli_rules_leave_analytics_cookies_to_crs() {
    let engine = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let hits = |cookie: &str| {
        let mut ctx = with_cookie(cookie);
        set_paranoia(&mut ctx, 2);
        eval(&engine, &mut ctx, Phase::RequestBody);
        ctx.rule_matches.len()
    };
    let payload = "1' UNION SELECT password FROM users WHERE '1'='1";
    let ordinary = hits(&format!("pref={payload}"));
    let analytics = hits(&format!("__utmz={payload}"));
    assert!(
        ordinary > 0,
        "test premise: the payload must fire as an ordinary cookie"
    );
    assert!(
        analytics < ordinary,
        "the __utm exclusions CRS ships were ignored: {analytics} matches vs {ordinary}"
    );
}
