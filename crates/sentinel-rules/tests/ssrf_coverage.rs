//! End-to-end coverage for the SSRF and @ipMatch operators.
//!
//! These go through the real path — SecRule text → importer → compiler → VM — rather
//! than calling the detection helpers directly, because the defect being fixed lived in
//! the IMPORTER: `@ipMatch` and `@rbl` were mapped to `Operator::Never`, so rules using
//! them compiled and loaded successfully and then could never fire. A unit test on the
//! matching logic would have passed the whole time the feature was dead.

mod common;

use common::{eval, make_get_ctx, make_post_ctx};
use sentinel_core::context::{Phase, WafDecision};
use sentinel_rules::RuleEngine;

fn engine_from(conf: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf_dir(conf, None)
        .unwrap_or_else(|e| panic!("import failed: {e}"));
    let ruleset = sentinel_rules::compile(file).unwrap_or_else(|e| panic!("compile failed: {e}"));
    RuleEngine::new(ruleset)
}

fn blocks_arg(engine: &RuleEngine, uri: &str) -> bool {
    let mut ctx = make_get_ctx(uri);
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx.decision == WafDecision::Block
}

fn blocks_body(engine: &RuleEngine, body: &str) -> bool {
    let mut ctx = make_post_ctx("http://example.com/fetch", body);
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx.decision == WafDecision::Block
}

const SSRF_RULE: &str = r#"
SecRule ARGS "@rbl dummy.blocklist.example" \
    "id:9900300,phase:2,deny,status:403,msg:'SSRF: internal or metadata target',t:none"
"#;

/// The acceptance criterion from the audit: every encoding of the metadata endpoint
/// must fire through a real rule.
#[test]
fn ssrf_rule_fires_on_every_metadata_encoding() {
    let engine = engine_from(SSRF_RULE);
    for enc in [
        "169.254.169.254",
        "2852039166",
        "0xA9FEA9FE",
        "0xa9.0xfe.0xa9.0xfe",
        "0251.0376.0251.0376",
        "169.254.43518",
    ] {
        let uri = format!("/fetch?url=http://{enc}/latest/meta-data/");
        assert!(
            blocks_arg(&engine, &uri),
            "SSRF rule did not fire for encoding {enc} — this is the coverage gap the fix targets"
        );
    }
}

#[test]
fn ssrf_rule_fires_on_loopback_and_private_targets() {
    let engine = engine_from(SSRF_RULE);
    for host in [
        "127.0.0.1",
        "127.1",
        "0x7f000001",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "[::1]",
        "0.0.0.0",
    ] {
        assert!(
            blocks_arg(&engine, &format!("/fetch?url=http://{host}/admin")),
            "SSRF rule did not fire for internal host {host}"
        );
    }
}

#[test]
fn ssrf_rule_fires_on_userinfo_confusion() {
    let engine = engine_from(SSRF_RULE);
    assert!(blocks_body(
        &engine,
        "url=http://trusted.example.com@169.254.169.254/latest/meta-data/"
    ));
}

/// The other half of usable detection: legitimate outbound URLs must pass. A rule that
/// blocks ordinary webhooks is worse than no rule, because it gets switched off.
#[test]
fn ssrf_rule_does_not_fire_on_public_urls() {
    let engine = engine_from(SSRF_RULE);
    for url in [
        "https://api.stripe.com/v1/charges",
        "https://example.com/callback",
        "http://93.184.216.34/",
        "https://8.8.8.8/",
        "http://172.32.0.1/",
        "http://11.0.0.1/",
    ] {
        assert!(
            !blocks_arg(&engine, &format!("/fetch?url={url}")),
            "SSRF rule WRONGLY fired on the public URL {url}"
        );
    }
}

/// A bare number is a number. Restricting host parsing to URL authorities is what keeps
/// this from flagging order IDs and timestamps.
#[test]
fn ssrf_rule_does_not_fire_on_bare_numbers() {
    let engine = engine_from(SSRF_RULE);
    assert!(!blocks_arg(&engine, "/fetch?order_id=2852039166"));
    assert!(!blocks_arg(&engine, "/fetch?ts=2130706433"));
}

const IPMATCH_RULE: &str = r#"
SecRule ARGS:client_ip "@ipMatch 10.0.0.0/8,192.168.0.0/16,203.0.113.7" \
    "id:9900301,phase:2,deny,status:403,msg:'ipMatch hit',t:none"
"#;

/// @ipMatch previously compiled to Never, so this rule loaded and did nothing.
#[test]
fn ipmatch_rule_actually_fires() {
    let engine = engine_from(IPMATCH_RULE);
    for ip in ["10.1.2.3", "10.0.0.1", "192.168.50.50", "203.0.113.7"] {
        assert!(
            blocks_arg(&engine, &format!("/x?client_ip={ip}")),
            "@ipMatch did not fire for {ip} — the operator is still inert"
        );
    }
}

#[test]
fn ipmatch_rule_ignores_addresses_outside_the_ranges() {
    let engine = engine_from(IPMATCH_RULE);
    for ip in [
        "11.0.0.1",
        "192.169.0.1",
        "203.0.113.8",
        "8.8.8.8",
        "not-an-ip",
    ] {
        assert!(
            !blocks_arg(&engine, &format!("/x?client_ip={ip}")),
            "@ipMatch WRONGLY fired for {ip}"
        );
    }
}

/// An allow/deny list keyed on IPs must not be evadable by rewriting the same address
/// in another base — which is exactly why @ipMatch shares the SSRF host parser.
#[test]
fn ipmatch_cannot_be_evaded_by_alternate_encodings() {
    let engine = engine_from(IPMATCH_RULE);
    for alt in ["0xa000001", "167772161", "10.1"] {
        assert!(
            blocks_arg(&engine, &format!("/x?client_ip={alt}")),
            "@ipMatch was evaded by encoding {alt} of an in-range address"
        );
    }
}

/// The importer must no longer silently disable these operators. Compiling a rule that
/// uses them and observing it fire is the only way to know.
#[test]
fn importer_no_longer_disables_ipmatch_or_rbl() {
    // If either were still mapped to Operator::Never these would not block.
    assert!(blocks_arg(
        &engine_from(IPMATCH_RULE),
        "/x?client_ip=10.0.0.1"
    ));
    assert!(blocks_arg(
        &engine_from(SSRF_RULE),
        "/fetch?url=http://169.254.169.254/"
    ));
}
