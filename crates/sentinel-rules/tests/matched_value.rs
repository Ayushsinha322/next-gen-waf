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

/// The hole a 12-agent audit found on 2026-08-30, and the reason this file
/// exists a second time.
///
/// `collect_sensitive_values` read ONLY query parameters and body args — never
/// cookies, never headers. And the proxy's second, target-based redaction pass
/// keys off `RuleMatch.target`, which the VM sets to `None` for every
/// MULTI-TARGET rule. CRS 942100 (SQLi via libinjection) is multi-target and
/// covers REQUEST_COOKIES. So a session JWT that tripped libinjection was
/// captured verbatim and written to waf.log, to ClickHouse under a 90-day
/// retention, and out to the SIEM feed. Neither layer caught it.
#[test]
fn credentials_in_cookies_and_headers_are_redacted_too() {
    let engine = engine_from(
        r#"SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@detectSQLi" "id:900108,phase:2,deny,msg:'sqli'""#,
    );

    // A JWT whose payload happens to trip libinjection — the realistic shape,
    // since base64 segments contain quotes, dashes and mixed case.
    let jwt = "eyJhbGciOiJIUzI1NiJ9.dXNlcj0nIG9yIDE9MS0t.c2ln";

    let mut ctx = common::make_get_ctx("/account");
    ctx.request_headers.insert(
        http::header::COOKIE,
        format!("theme=dark; session={jwt}; lang=en")
            .parse()
            .unwrap(),
    );
    eval(&engine, &mut ctx, Phase::RequestBody);
    if let Some(m) = ctx.rule_matches.iter().find(|m| m.rule_id == "900108") {
        assert!(
            !m.matched_value.contains("dXNlcj0nIG9yIDE9MS0t"),
            "a session cookie leaked into the match: {:?}",
            m.matched_value
        );
    }

    // Same for an Authorization header.
    let mut ctx = common::make_get_ctx("/account");
    ctx.request_headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {jwt}").parse().unwrap(),
    );
    eval(&engine, &mut ctx, Phase::RequestBody);
    if let Some(m) = ctx.rule_matches.iter().find(|m| m.rule_id == "900108") {
        assert!(
            !m.matched_value.contains("dXNlcj0nIG9yIDE9MS0t"),
            "an Authorization header leaked into the match: {:?}",
            m.matched_value
        );
    }

    // Control: the same payload in an ordinary parameter is still KEPT. Redaction
    // must not be so broad that it destroys the reason the field is logged.
    let mut ctx = common::make_get_ctx("/search?q=1%27%20OR%201%3D1--%20UNION%20SELECT");
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900108")
        .expect("an attack in an ordinary parameter must still fire");
    assert!(
        m.matched_value.to_uppercase().contains("UNION") || m.matched_value.contains("OR 1=1"),
        "an ordinary parameter must keep its payload: {:?}",
        m.matched_value
    );
}

/// The other direction of the same fix: redaction must not eat the log.
///
/// Sensitive values are now collected from every cookie and header, and short
/// ones are ordinary — `X-Auth-Version: 1`, `authed=1`. Because the sensitivity
/// check compares by substring in both directions, a one-character sensitive
/// value would match nearly every attack payload and rewrite every logged
/// detection to `[redacted]`. Over-redaction is not the safe side of this
/// trade; it destroys the reason the field is captured.
#[test]
fn a_short_sensitive_value_does_not_redact_every_payload() {
    let engine = engine_from(
        r#"SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@detectSQLi" "id:900109,phase:2,deny,msg:'sqli'""#,
    );

    let mut ctx = common::make_get_ctx("/search?q=1%27%20OR%201%3D1--%20UNION%20SELECT");
    // Short, unremarkable, sensitively-NAMED fields, of the kind real apps send.
    ctx.request_headers
        .insert("x-auth-version", "1".parse().unwrap());
    ctx.request_headers
        .insert(http::header::COOKIE, "authed=1; sess_n=2".parse().unwrap());
    eval(&engine, &mut ctx, Phase::RequestBody);

    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900109")
        .expect("the attack must still fire");
    assert!(
        !m.matched_value.contains("redacted"),
        "a 1-char sensitive value wiped a real payload: {:?}",
        m.matched_value
    );
    assert!(
        m.matched_value.to_uppercase().contains("UNION") || m.matched_value.contains("OR 1=1"),
        "the payload must survive: {:?}",
        m.matched_value
    );

    // But a long credential in the SAME request is still redacted, so the floor
    // has not simply disabled the check.
    let mut ctx = common::make_get_ctx("/login");
    ctx.request_headers.insert(
        http::header::COOKIE,
        "session=eyJhbGciOiJIUzI1NiJ9.dXNlcj0nIG9yIDE9MS0t.c2ln"
            .parse()
            .unwrap(),
    );
    ctx.request_headers
        .insert("x-auth-version", "1".parse().unwrap());
    eval(&engine, &mut ctx, Phase::RequestBody);
    if let Some(m) = ctx.rule_matches.iter().find(|m| m.rule_id == "900109") {
        assert!(
            !m.matched_value.contains("dXNlcj0nIG9yIDE9MS0t"),
            "the long credential must still be redacted: {:?}",
            m.matched_value
        );
    }
}

/// Cookies are judged individually, not as one blob.
///
/// A live test on .71 caught this: because the `Cookie` HEADER name reads as
/// sensitive, the entire cookie jar became a single sensitive value, so ANY
/// payload injected into ANY cookie was a substring of it and got redacted —
/// including an attack in an ordinary `theme=` cookie. Cookie injection is a
/// real attack class and an operator cannot act on `[redacted]`.
#[test]
fn an_ordinary_cookie_keeps_its_payload_while_a_session_cookie_does_not() {
    let engine = engine_from(
        r#"SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@detectSQLi" "id:900110,phase:2,deny,msg:'sqli'""#,
    );
    let payload = "x' UNION SELECT password FROM users--";

    // Ordinary cookie name -> the payload is evidence, and must survive.
    let mut ctx = common::make_get_ctx("/rest/products/search?q=apple");
    ctx.request_headers.insert(
        http::header::COOKIE,
        format!("theme={payload}").parse().unwrap(),
    );
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900110")
        .expect("cookie injection must still be detected");
    assert!(
        !m.matched_value.contains("redacted"),
        "an attack in an ordinary cookie lost its payload: {:?}",
        m.matched_value
    );
    assert!(m.matched_value.contains("UNION"), "{:?}", m.matched_value);

    // Sensitive cookie name -> the value is a credential, and must not be kept.
    let mut ctx = common::make_get_ctx("/rest/products/search?q=apple");
    ctx.request_headers.insert(
        http::header::COOKIE,
        format!("session={payload}").parse().unwrap(),
    );
    eval(&engine, &mut ctx, Phase::RequestBody);
    let m = ctx
        .rule_matches
        .iter()
        .find(|m| m.rule_id == "900110")
        .expect("the rule must still fire on a session cookie");
    assert!(
        m.matched_value.contains("redacted"),
        "a session cookie's value was written down: {:?}",
        m.matched_value
    );

    // A rule matching the WHOLE cookie header still redacts, because each
    // cookie was registered individually and the check is bidirectional.
    let mut ctx = common::make_get_ctx("/x");
    ctx.request_headers.insert(
        http::header::COOKIE,
        format!("theme=dark; session={payload}").parse().unwrap(),
    );
    eval(&engine, &mut ctx, Phase::RequestBody);
    if let Some(m) = ctx.rule_matches.iter().find(|m| m.rule_id == "900110") {
        assert!(
            !m.matched_value.contains("UNION SELECT password"),
            "the session value leaked via a whole-header match: {:?}",
            m.matched_value
        );
    }
}
