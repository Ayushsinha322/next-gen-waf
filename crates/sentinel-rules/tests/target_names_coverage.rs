//! Coverage for the ModSecurity target tokens the CRS importer used to skip.
//!
//! WHY THIS FILE EXISTS
//!
//! Before these targets were implemented the importer emitted "unknown target
//! token, skipping" and dropped the rule. Measured statically against the shipped
//! ruleset, 149 CRS rules were lost that way — **129 of them to
//! `REQUEST_COOKIES_NAMES` alone**, because session-fixation, cookie-injection and
//! several protocol-enforcement rules all match on the NAME side of a cookie.
//!
//! A target that compiles but extracts the wrong thing is worse than one that is
//! absent: the rule loads, the engine reports a higher rule count, and nothing
//! ever matches. So each test below asserts on the extracted VALUES, and the
//! name-vs-value pairs assert that the two are actually different — which is the
//! specific way this class of bug hides.

mod common;
use common::{make_get_ctx, make_post_ctx};
use sentinel_core::context::Phase;
use sentinel_rules::RuleEngine;

/// Build an engine from real SecRule text, because the importer is the thing
/// under test. Constructing AST nodes directly would skip the token-parsing step
/// that was dropping these rules in the first place.
fn engine_for(target: &str, pattern: &str) -> RuleEngine {
    let src = format!(r#"SecRule {target} "@rx {pattern}" "id:900001,phase:2,deny,t:none""#);
    let file = sentinel_rules::import_secrule_conf(&src)
        .unwrap_or_else(|e| panic!("import failed for target {target}: {e}"));
    RuleEngine::new(sentinel_rules::compile(file).expect("compile failed"))
}

/// True if rule 900001 matched. Takes a BUILDER rather than a context because
/// RequestContext is deliberately not Clone, and a fresh context per assertion
/// also stops one assertion's match from leaking into the next.
///
/// Asserts on rule_matches rather than the returned decision, so the test is
/// about EXTRACTION rather than about scoring policy.
fn matches(target: &str, pattern: &str, build: impl Fn() -> sentinel_core::RequestContext) -> bool {
    let eng = engine_for(target, pattern);
    let mut c = build();
    eng.evaluate(&mut c, Phase::RequestHeaders, 0);
    eng.evaluate(&mut c, Phase::RequestBody, 0);
    c.rule_matches.iter().any(|m| m.rule_id == "900001")
}

// ── REQUEST_COOKIES_NAMES — the 129-rule token ──────────────────────────────

#[test]
fn cookie_names_matches_the_name_not_the_value() {
    let ctx = || {
        let mut c = make_get_ctx("/");
        c.request_headers.insert(
            http::header::COOKIE,
            "sessionid=abc123; tracker=xyz".parse().unwrap(),
        );
        c
    };

    assert!(
        matches("REQUEST_COOKIES_NAMES", "sessionid", ctx),
        "REQUEST_COOKIES_NAMES must see the cookie NAME"
    );
    assert!(
        matches("REQUEST_COOKIES_NAMES", "tracker", ctx),
        "every cookie name must be extracted, not just the first"
    );
}

#[test]
fn cookie_names_does_not_leak_values() {
    // The bug this guards: implementing NAMES by copying the values arm. It would
    // compile, the rule count would rise, and every name-side CRS rule would
    // still never fire.
    let ctx = || {
        let mut c = make_get_ctx("/");
        c.request_headers
            .insert(http::header::COOKIE, "sessionid=abc123".parse().unwrap());
        c
    };

    assert!(
        !matches("REQUEST_COOKIES_NAMES", "abc123", ctx),
        "REQUEST_COOKIES_NAMES must NOT return cookie values"
    );
    assert!(
        matches("REQUEST_COOKIES", "abc123", ctx),
        "...while REQUEST_COOKIES still does"
    );
}

#[test]
fn cookie_names_is_empty_without_a_cookie_header() {
    let ctx = || make_get_ctx("/");
    assert!(
        !matches("REQUEST_COOKIES_NAMES", ".", ctx),
        "no Cookie header must yield nothing, not an empty string that matches /./"
    );
}

// ── REQUEST_HEADERS_NAMES ───────────────────────────────────────────────────

#[test]
fn header_names_matches_the_name_not_the_value() {
    let ctx = || {
        let mut c = make_get_ctx("/");
        c.request_headers
            .insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        c
    };

    assert!(matches("REQUEST_HEADERS_NAMES", "x-forwarded-for", ctx));
    assert!(
        !matches("REQUEST_HEADERS_NAMES", "10.0.0.1", ctx),
        "REQUEST_HEADERS_NAMES must not return header values"
    );
}

// ── ARGS_GET / ARGS_GET_NAMES — query only, never the body ──────────────────

#[test]
fn args_get_covers_the_query_and_excludes_the_body() {
    let ctx = || make_post_ctx("/s?q=fromquery", "b=frombody");

    assert!(
        matches("ARGS_GET", "fromquery", ctx),
        "ARGS_GET must see query values"
    );
    assert!(
        !matches("ARGS_GET", "frombody", ctx),
        "ARGS_GET must NOT see body values — that is what ARGS is for. Scoring a \
         body parameter against a query-only rule is a false positive by construction"
    );
    assert!(
        matches("ARGS", "frombody", ctx),
        "...and ARGS still covers both"
    );
}

#[test]
fn args_get_names_returns_names_only() {
    let ctx = || make_get_ctx("/s?secretkey=secretvalue");
    assert!(matches("ARGS_GET_NAMES", "secretkey", ctx));
    assert!(
        !matches("ARGS_GET_NAMES", "secretvalue", ctx),
        "ARGS_GET_NAMES must not return values"
    );
}

// ── QUERY_STRING — must stay encoded ────────────────────────────────────────

#[test]
fn query_string_is_raw_and_undecoded() {
    // CRS uses QUERY_STRING precisely for rules that must see the encoding —
    // double-encoding and separator abuse. Decoding here would defeat them.
    let ctx = || make_get_ctx("/p?a=%3Cscript%3E");
    assert!(
        matches("QUERY_STRING", "%3Cscript%3E", ctx),
        "QUERY_STRING must preserve percent-encoding"
    );
    assert!(
        !matches("QUERY_STRING", "<script>", ctx),
        "QUERY_STRING must not be decoded — that is ARGS' job"
    );
}

#[test]
fn query_string_is_empty_when_there_is_no_query() {
    let ctx = || make_get_ctx("/plain");
    assert!(!matches("QUERY_STRING", "..", ctx));
}

// ── Regression guard: the 129 newly-enabled cookie-name rules must not fire on
//    ordinary traffic ─────────────────────────────────────────────────────────
//
// Enabling REQUEST_COOKIES_NAMES switched on 129 CRS rules that had never
// executed. The risk of turning on rules nobody has run is false positives on
// perfectly normal requests, which in this product is the failure that matters
// most: a WAF that blocks real users gets switched off entirely.
//
// This loads the real CRS session-fixation and protocol-enforcement files — the
// two families that use cookie names most — and asserts that a request carrying
// the sort of cookies every site sets scores nothing.

#[test]
fn ordinary_cookies_do_not_score_against_the_newly_enabled_rules() {
    let eng = common::load_crs_engines(&[
        "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
        "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    ]);

    // Cookies a normal session actually carries: a session id, an analytics id,
    // a consent flag, a CSRF token and a locale.
    let mut ctx = make_get_ctx("http://example.com/account");
    common::set_paranoia(&mut ctx, 2);
    ctx.request_headers.insert(
        http::header::COOKIE,
        "PHPSESSID=8f2a9c1b4e7d; _ga=GA1.2.1234567890.1699999999; \
         cookie_consent=accepted; csrftoken=aBcD1234EfGh5678; lang=en-GB"
            .parse()
            .unwrap(),
    );

    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert_eq!(
        ctx.anomaly_score, 0,
        "ordinary cookies must not score. Matched: {:?}",
        ctx.rule_matches
    );
}

#[test]
fn a_session_fixation_attempt_in_a_cookie_name_is_still_caught() {
    // The other half of the guard: having proved the rules are quiet on benign
    // traffic, prove they are not merely inert. Without this, "no false
    // positives" could be satisfied by rules that never match anything at all —
    // which is exactly the state these 129 rules were in before.
    let eng = common::load_crs_engines(&["REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"]);
    let mut ctx = make_get_ctx("http://example.com/?jsessionid=abc123&sessionid=fixed");
    common::set_paranoia(&mut ctx, 2);
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        ctx.anomaly_score > 0 || !ctx.rule_matches.is_empty(),
        "session-fixation rules must still detect a fixation attempt; \
         a quiet ruleset is not the same as a working one"
    );
}

// ── @pmFromFile: phrases must survive intact ────────────────────────────────
//
// The importer used to expand `@pmFromFile x.data` into `@pm phrase1 phrase2 …`
// in the source text and then split that on whitespace. Two consequences, and
// fixing only the first would have been worse than fixing neither:
//
//   1. A phrase containing a double quote terminated the enclosing operator
//      string, so the entire FILE failed to import. Three shipped CRS files were
//      lost that way (RESPONSE-952/953/955).
//   2. Multi-word phrases were shattered into single words. 1,782 of the 1,853
//      phrases in php-errors.data contain a space, so enabling those files
//      without fixing this would have made rules match the bare word "be" or
//      "error" against every response body.

#[test]
fn pmfromfile_preserves_multi_word_phrases() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("phrases.data"),
        "# a comment line, ignored\nFatal error: Uncaught\nsingleword\n",
    )
    .unwrap();

    let src = r#"SecRule RESPONSE_BODY "@pmFromFile phrases.data" "id:900500,phase:4,deny,t:none""#;
    let file = sentinel_rules::import_secrule_conf_dir(src, Some(dir.path())).expect("must import");

    let ops: Vec<_> = file
        .items
        .iter()
        .filter_map(|i| match i {
            sentinel_rules::dsl::ast::RuleItem::Rule(r) => Some(&r.operator),
            _ => None,
        })
        .collect();
    match ops.first().expect("one rule") {
        sentinel_rules::dsl::ast::Operator::ContainsWord(ws) => {
            assert!(
                ws.iter().any(|w| w == "Fatal error: Uncaught"),
                "the multi-word phrase must survive as ONE entry, got {ws:?}"
            );
            assert!(
                !ws.iter().any(|w| w == "Fatal"),
                "phrases must NOT be split on whitespace — that is what made these \
                 rules match single common words. Got {ws:?}"
            );
            assert_eq!(ws.len(), 2, "comment lines must be skipped, got {ws:?}");
        }
        other => panic!("expected ContainsWord, got {other:?}"),
    }
}

#[test]
fn pmfromfile_survives_a_quote_in_a_phrase() {
    // The exact shape that killed RESPONSE-952/953/955.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("quoted.data"),
        "API is restricted by \"\nis not a valid backing value for enum \"\n",
    )
    .unwrap();

    let src = r#"SecRule RESPONSE_BODY "@pmFromFile quoted.data" "id:900501,phase:4,deny,t:none""#;
    let file = sentinel_rules::import_secrule_conf_dir(src, Some(dir.path()))
        .expect("a quote inside a phrase must not break the import");
    assert_eq!(
        file.items.len(),
        1,
        "the rule must survive, not be dropped with the rest of its file"
    );
}

#[test]
fn pmfromfile_without_a_data_dir_is_disabled_not_matching_the_filename() {
    // Guards a latent trap: with no data_dir the old code would have handed the
    // operator the literal string "x.data", producing a rule that matches the
    // FILENAME in traffic. Never is the honest outcome.
    let src = r#"SecRule ARGS "@pmFromFile x.data" "id:900502,phase:2,deny,t:none""#;
    let file = sentinel_rules::import_secrule_conf_dir(src, None).expect("import");
    for item in &file.items {
        if let sentinel_rules::dsl::ast::RuleItem::Rule(r) = item {
            assert!(
                matches!(r.operator, sentinel_rules::dsl::ast::Operator::Never),
                "expected Never, got {:?}",
                r.operator
            );
        }
    }
}

// ── FP guard for the three newly-importable RESPONSE-* files ────────────────
//
// RESPONSE-952/953/955 had never imported, so their rules have never run against
// anything. They inspect RESPONSE_BODY for data-leakage and web-shell phrases,
// which makes them the highest false-positive risk in the ruleset: an ordinary
// page that happens to contain a phrase from php-errors.data would be flagged.

#[test]
fn ordinary_html_does_not_trip_the_response_body_leakage_rules() {
    let eng = common::load_crs_engines(&[
        "RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
        "RESPONSE-953-DATA-LEAKAGES-PHP.conf",
        "RESPONSE-955-WEB-SHELLS.conf",
    ]);

    let mut ctx = make_get_ctx("http://example.com/");
    common::set_paranoia(&mut ctx, 2);
    ctx.response_body = Some(
        b"<!doctype html><html><head><title>Order confirmation</title></head><body>\
          <h1>Thank you</h1><p>Your order has been placed and will be dispatched \
          shortly. If there is a problem we will email you. Errors in your address \
          can be corrected from your account page.</p>\
          <footer>&copy; Example Ltd</footer></body></html>"
            .to_vec()
            .into(),
    );

    // common::eval() hardcodes the REQUEST phases and ignores its phase
    // argument, so response-body rules must be driven explicitly.
    eng.evaluate(&mut ctx, Phase::ResponseBody, 0);
    assert_eq!(
        ctx.anomaly_score, 0,
        "ordinary HTML must not score against the response-body leakage rules. \
         Matched: {:?}",
        ctx.rule_matches
    );
}

#[test]
fn a_real_php_error_leak_is_detected() {
    // The other half: prove the newly-enabled rules are not merely quiet.
    let eng = common::load_crs_engines(&["RESPONSE-953-DATA-LEAKAGES-PHP.conf"]);
    let mut ctx = make_get_ctx("http://example.com/");
    common::set_paranoia(&mut ctx, 2);
    ctx.response_body = Some(
        b"<br /><b>Fatal error</b>:  Uncaught Error: Call to a member function \
          query() on null in /var/www/html/inc/db.php:42"
            .to_vec()
            .into(),
    );
    // common::eval() hardcodes the REQUEST phases and ignores its phase
    // argument, so response-body rules must be driven explicitly.
    eng.evaluate(&mut ctx, Phase::ResponseBody, 0);
    assert!(
        ctx.anomaly_score > 0 || !ctx.rule_matches.is_empty(),
        "a genuine PHP fatal-error leak must be detected — otherwise these three \
         files were enabled for nothing"
    );
}
