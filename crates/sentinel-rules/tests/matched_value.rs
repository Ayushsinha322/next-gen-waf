//! The matched payload must survive onto the `RuleMatch`.
//!
//! Before this existed, an event said `target=ARGS:id` and nothing else — the
//! operator triaging a false positive had to reproduce the request to learn
//! what the rule saw. The VM captures the matched text for regex (with and
//! without capture groups) and `@pm` operators; this asserts it arrives,
//! capped and control-char-free, on the recorded match.

mod common;

use common::{eval, make_get_ctx};
use sentinel_core::context::Phase;
use sentinel_rules::RuleEngine;

fn engine_from(src: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf(src).expect("test rule must import");
    let ruleset = sentinel_rules::compile(file).expect("test rule must compile");
    RuleEngine::new(ruleset)
}

#[test]
fn plain_regex_records_matched_text() {
    let engine = engine_from(
        r#"SecRule ARGS "@rx union\s+select" "id:900101,phase:2,deny,t:lowercase,msg:'sqli'""#,
    );
    let mut ctx = make_get_ctx("/search?q=1%27+UNION+SELECT+password+FROM+users");
    eval(&engine, &mut ctx, Phase::RequestBody);

    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900101")
        .expect("rule must fire");
    assert!(
        m.matched_value.to_ascii_lowercase().contains("union"),
        "matched_value should carry the payload text, got: {:?}",
        m.matched_value
    );
}

#[test]
fn capture_regex_records_whole_match() {
    let engine = engine_from(
        r#"SecRule ARGS "@rx (etc/(passwd|shadow))" "id:900102,phase:2,deny,capture,msg:'lfi'""#,
    );
    let mut ctx = make_get_ctx("/download?file=../../etc/passwd");
    eval(&engine, &mut ctx, Phase::RequestBody);

    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900102")
        .expect("rule must fire");
    assert!(
        m.matched_value.contains("etc/passwd"),
        "capture-group rules must record TX.0 (whole match), got: {:?}",
        m.matched_value
    );
}

#[test]
fn pm_records_containing_value() {
    let engine = engine_from(
        r#"SecRule ARGS "@pm Invoke-Expression Net.WebClient" "id:900103,phase:2,deny,msg:'rce'""#,
    );
    let mut ctx = make_get_ctx("/run?cmd=IEX(New-Object%20Net.WebClient)");
    eval(&engine, &mut ctx, Phase::RequestBody);

    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900103")
        .expect("rule must fire");
    assert!(
        m.matched_value.contains("Net.WebClient"),
        "@pm should record the value that contained the pattern, got: {:?}",
        m.matched_value
    );
}

/// The libinjection operators back rules 942100 (SQLi) and 941100 (XSS) — the
/// two most-fired rules in the product. They were the last uninstrumented
/// match operators, so payload capture was blind exactly where it mattered
/// most: a real SQLi event named the rule and nothing about the payload.
#[test]
fn libinjection_operators_record_the_offending_value() {
    let engine = engine_from(
        r#"SecRule ARGS "@detectSQLi" "id:900105,phase:2,deny,msg:'sqli libinjection'"
SecRule ARGS "@detectXSS" "id:900106,phase:2,deny,msg:'xss libinjection'""#,
    );

    let mut ctx = make_get_ctx("/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--");
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900105")
        .expect("detectSQLi rule must fire");
    assert!(
        m.matched_value.to_ascii_uppercase().contains("UNION"),
        "@detectSQLi must name the offending value, got: {:?}",
        m.matched_value
    );

    let mut ctx = make_get_ctx("/page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900106")
        .expect("detectXSS rule must fire");
    assert!(
        m.matched_value.contains("script"),
        "@detectXSS must name the offending value, got: {:?}",
        m.matched_value
    );
}

/// A rule firing on a password field is usually a false positive — real
/// passwords contain quotes and SQL keywords. Capturing the payload there would
/// write a live credential into the log, so the value is dropped at capture
/// time. The target label cannot gate this: CRS rules are multi-target and
/// `ARGS` never carries the parameter name.
#[test]
fn credential_field_values_are_redacted_at_capture_time() {
    use bytes::Bytes;

    let engine = engine_from(r#"SecRule ARGS "@detectSQLi" "id:900107,phase:2,deny,msg:'sqli'""#);

    // Form-encoded login: the password itself trips the SQLi operator.
    let mut ctx = common::make_post_ctx("/login", "user=alice&password=1' OR 1=1-- UNION SELECT");
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900107")
        .expect("rule must fire");
    assert!(
        m.matched_value.starts_with("[redacted"),
        "a password value must never be captured, got: {:?}",
        m.matched_value
    );
    assert!(
        !m.matched_value.contains("OR 1=1"),
        "the credential leaked into the match"
    );

    // Same attack in a JSON login body — body_args flattens JSON, so this is
    // covered by the same check.
    let mut ctx = common::make_post_ctx("/api/login", "");
    ctx.request_body = Some(Bytes::from(
        r#"{"user":"alice","password":"1' OR 1=1-- UNION SELECT"}"#,
    ));
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900107")
        .expect("rule must fire on the JSON body");
    assert!(
        m.matched_value.starts_with("[redacted"),
        "a JSON password value must never be captured, got: {:?}",
        m.matched_value
    );

    // Control: the SAME payload in an ordinary parameter IS kept — redaction
    // must not be so broad that it destroys the forensic value of the field.
    let mut ctx = common::make_post_ctx("/search", "q=1' OR 1=1-- UNION SELECT");
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900107")
        .expect("rule must fire");
    assert!(
        m.matched_value.contains("OR 1=1"),
        "a non-credential parameter must keep its payload, got: {:?}",
        m.matched_value
    );
}

#[test]
fn matched_value_is_capped_and_sanitized() {
    let engine = engine_from(r#"SecRule ARGS "@rx aaa+" "id:900104,phase:2,deny,msg:'flood'""#);
    // A 10 KB payload of 'a' — the whole thing matches the regex.
    let huge = "a".repeat(10_000);
    let mut ctx = make_get_ctx(&format!("/x?p={huge}"));
    eval(&engine, &mut ctx, Phase::RequestBody);

    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900104")
        .expect("rule must fire");
    assert!(
        m.matched_value.chars().count() <= 260,
        "matched_value must be capped, got {} chars",
        m.matched_value.chars().count()
    );
    assert!(
        !m.matched_value.chars().any(|c| c.is_control()),
        "matched_value must not carry control characters"
    );
}
