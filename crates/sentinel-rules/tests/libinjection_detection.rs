//! Tests for libinjection-backed `@detectSQLi` / `@detectXSS` operators.
//!
//! These replace the previous coarse keyword/tag regex stubs. The key wins are
//! the keyword-less cases (SQL tautologies, attribute-based XSS) that a regex
//! keyed on `select|union|...` or `<script` would miss but libinjection's
//! tokeniser flags.

mod common;

use common::*;
use sentinel_core::context::{Phase, WafDecision};
use sentinel_rules::RuleEngine;

/// A two-rule set: `@detectSQLi` and `@detectXSS` over ARGS, both blocking.
fn detect_engine() -> RuleEngine {
    let conf = r#"
SecRule ARGS "@detectSQLi" "id:8001,phase:2,block,msg:'libinjection sqli'"
SecRule ARGS "@detectXSS" "id:8002,phase:2,block,msg:'libinjection xss'"
"#;
    let file = sentinel_rules::import_secrule_conf_dir(conf, None).expect("import detect rules");
    let ruleset = sentinel_rules::compile(file).expect("compile detect rules");
    RuleEngine::new(ruleset)
}

fn run(engine: &RuleEngine, ctx: &mut sentinel_core::context::RequestContext) -> WafDecision {
    engine.evaluate(ctx, Phase::RequestHeaders, 0);
    engine.evaluate(ctx, Phase::RequestBody, 0)
}

// --- SQLi ------------------------------------------------------------------

#[test]
fn keywordless_sql_tautology_is_detected() {
    // No SELECT/UNION/DROP keyword — the old regex stub would have missed this;
    // libinjection flags the `' OR '1'='1` tautology.
    let eng = detect_engine();
    let mut ctx = make_post_ctx("/login", "user=admin&pass=1' OR '1'='1");
    assert_eq!(
        run(&eng, &mut ctx),
        WafDecision::Block,
        "tautology SQLi must block"
    );
}

#[test]
fn union_select_sqli_is_detected() {
    let eng = detect_engine();
    let mut ctx = make_post_ctx("/q", "id=1 UNION SELECT username,password FROM users");
    assert_eq!(
        run(&eng, &mut ctx),
        WafDecision::Block,
        "UNION SELECT must block"
    );
}

#[test]
fn clean_sql_like_text_passes() {
    let eng = detect_engine();
    // Natural-language value that merely contains the word "or" must not block.
    let mut ctx = make_post_ctx("/comment", "text=tea or coffee, your choice");
    assert_eq!(
        run(&eng, &mut ctx),
        WafDecision::Allow,
        "benign prose must pass"
    );
}

// --- XSS -------------------------------------------------------------------

#[test]
fn attribute_event_handler_xss_is_detected() {
    // No literal `<script>` tag — attribute/event-handler XSS.
    let eng = detect_engine();
    let mut ctx = make_post_ctx("/c", "html=<img src=x onerror=alert(1)>");
    assert_eq!(
        run(&eng, &mut ctx),
        WafDecision::Block,
        "onerror XSS must block"
    );
}

#[test]
fn script_tag_xss_is_detected() {
    let eng = detect_engine();
    let mut ctx = make_post_ctx("/c", "html=<script>alert(document.cookie)</script>");
    assert_eq!(
        run(&eng, &mut ctx),
        WafDecision::Block,
        "script-tag XSS must block"
    );
}

#[test]
fn clean_html_mention_passes() {
    let eng = detect_engine();
    let mut ctx = make_post_ctx("/c", "text=I like the script of that movie");
    assert_eq!(
        run(&eng, &mut ctx),
        WafDecision::Allow,
        "benign mention must pass"
    );
}
