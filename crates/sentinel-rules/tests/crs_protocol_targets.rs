//! The last five CRS rules that were absent, and proof they now work.
//!
//! After `pcre_compat` fixed the six compile failures, five rules were still
//! not enforced — by two OTHER mechanisms, which is the part worth remembering.
//! A rule can go missing three different ways and each logs differently:
//!
//!   compile error      -> dropped, never loaded          (fixed earlier)
//!   unsupported TARGET -> importer drops the whole rule   920180, 920430, 920540
//!   unsupported OPERATOR -> loads as `Never`, can never match   920270, 920271
//!
//! The last one is the nastiest: the rule is present, counted, and reported as
//! loaded, and it cannot fire. That is the same shape as every bug in
//! `silently_inert_bug_class`.
//!
//! Each test names its rule id, and there is a matching quiet-on-benign check,
//! because a protocol rule that fires on ordinary traffic is worse than one that
//! is missing.

mod common;

use sentinel_core::context::Phase;
use std::path::Path;

fn crs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules")
}

fn engine(conf: &str) -> sentinel_rules::RuleEngine {
    let dir = crs_dir();
    let src = std::fs::read_to_string(dir.join(conf)).expect(conf);
    let parsed = sentinel_rules::import_secrule_conf_dir(&src, Some(&dir)).expect("import");
    let set = sentinel_rules::compile(parsed).expect("compile");
    sentinel_rules::RuleEngine::new(set)
}

/// The five rules must be PRESENT — not dropped by the importer, and not
/// loaded-but-inert.
#[test]
fn the_five_remaining_rules_are_loaded_and_enforceable() {
    let dir = crs_dir();
    let conf = "REQUEST-920-PROTOCOL-ENFORCEMENT.conf";
    let src = std::fs::read_to_string(dir.join(conf)).expect(conf);
    let parsed = sentinel_rules::import_secrule_conf_dir(&src, Some(&dir)).expect("import");
    let set = sentinel_rules::compile(parsed).expect("compile");

    for id in [920180u32, 920430, 920540, 920270, 920271] {
        assert!(
            set.rule_meta.contains_key(&id),
            "rule {id} is not in the ruleset at all — the importer dropped it, \
             so that protection is absent"
        );
        assert!(
            !set.coverage.disabled.contains(&id),
            "rule {id} loaded but is INERT (unsupported operator -> Never). It is \
             counted as present and can never match, which is worse than absent."
        );
    }
    assert!(
        set.coverage.dropped.is_empty(),
        "rules dropped on compile: {:?}",
        set.coverage.dropped
    );
}

/// `@validateByteRange 1-255` — a NUL byte anywhere in the request.
///
/// A NUL in a URI is a classic parser-confusion primitive: the WAF and the
/// origin disagree about where the string ends.
#[test]
fn a_null_byte_is_detected_920270() {
    let eng = engine("REQUEST-920-PROTOCOL-ENFORCEMENT.conf");
    // %00 in the query. The rule carries t:urlDecodeUni, so this decodes to a
    // real NUL before the operator sees it — and a header cannot carry one at
    // all, since http::HeaderValue rejects control bytes outright.
    let mut ctx = common::make_get_ctx("http://example.com/search?q=before%00after");
    common::set_paranoia(&mut ctx, 2);
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        ctx.rule_matches.iter().any(|m| m.rule_id == "920270"),
        "a NUL byte went undetected; matches: {:?}",
        ctx.rule_matches
            .iter()
            .map(|m| &m.rule_id)
            .collect::<Vec<_>>()
    );
}

/// `@validateByteRange 9,10,13,32-126,128-255` — control characters.
#[test]
fn a_control_character_is_detected_920271() {
    let eng = engine("REQUEST-920-PROTOCOL-ENFORCEMENT.conf");
    // 0x07 (BEL) is outside 920271's allowed set; tab/LF/CR deliberately are in it.
    let mut ctx = common::make_get_ctx("http://example.com/search?q=bell%07here");
    common::set_paranoia(&mut ctx, 2);
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        ctx.rule_matches.iter().any(|m| m.rule_id == "920271"),
        "a control character went undetected; matches: {:?}",
        ctx.rule_matches
            .iter()
            .map(|m| &m.rule_id)
            .collect::<Vec<_>>()
    );
}

/// Ordinary traffic must not trip either byte-range rule. Tab, LF and CR are
/// explicitly permitted by 920271's spec, and high bytes (UTF-8 text) by both.
#[test]
fn ordinary_and_utf8_traffic_does_not_trip_the_byte_range_rules() {
    let eng = engine("REQUEST-920-PROTOCOL-ENFORCEMENT.conf");
    for (name, value) in [
        ("x-probe", "plain ascii value"),
        ("x-probe", "tab\there"),
        ("accept-language", "en-GB,en;q=0.9"),
        // High bytes: a UTF-8 name. 128-255 is allowed by both specs, so this
        // must pass — if it did not, every non-English request would be flagged.
        ("x-probe", "Ayush Sinha — ESDS"),
    ] {
        let mut ctx = common::make_get_ctx("http://example.com/rest/products/search?q=apple");
        common::set_paranoia(&mut ctx, 2);
        ctx.request_headers.insert(name, value.parse().unwrap());
        common::eval(&eng, &mut ctx, Phase::RequestBody);
        let hits: Vec<_> = ctx
            .rule_matches
            .iter()
            .filter(|m| m.rule_id == "920270" || m.rule_id == "920271")
            .map(|m| m.rule_id.clone())
            .collect();
        assert!(
            hits.is_empty(),
            "byte-range rule(s) {hits:?} fired on benign header {name}: {value:?}"
        );
    }
}

/// `REQUEST_PROTOCOL` must report the version in ModSecurity's spelling, since
/// CRS 920430 compares it against `%{tx.allowed_http_versions}` as text.
#[test]
fn request_protocol_reports_the_modsecurity_spelling() {
    let eng = sentinel_rules::RuleEngine::from_crs_conf(
        r#"SecRule REQUEST_PROTOCOL "@rx ^HTTP/1\.1$" "id:900200,phase:1,pass,msg:'proto'"
"#,
    )
    .expect("crs conf");
    let mut ctx = common::make_get_ctx("http://example.com/");
    ctx.http_version = http::Version::HTTP_11;
    common::eval(&eng, &mut ctx, Phase::RequestHeaders);
    assert!(
        ctx.rule_matches.iter().any(|m| m.rule_id == "900200"),
        "REQUEST_PROTOCOL did not read as \"HTTP/1.1\"; matches: {:?}",
        ctx.rule_matches
            .iter()
            .map(|m| &m.rule_id)
            .collect::<Vec<_>>()
    );

    // HTTP/2 must NOT match the 1.1 pattern — i.e. the target really varies.
    let mut ctx = common::make_get_ctx("http://example.com/");
    ctx.http_version = http::Version::HTTP_2;
    common::eval(&eng, &mut ctx, Phase::RequestHeaders);
    assert!(
        !ctx.rule_matches.iter().any(|m| m.rule_id == "900200"),
        "REQUEST_PROTOCOL returned HTTP/1.1 for an HTTP/2 request"
    );
}

/// `REQBODY_PROCESSOR` gates CRS 920540, whose chain hunts `\uXXXX` escapes
/// everywhere EXCEPT a JSON body — where they are legal syntax.
#[test]
fn reqbody_processor_names_the_parser_that_handled_the_body() {
    let eng = sentinel_rules::RuleEngine::from_crs_conf(
        r#"SecRule REQBODY_PROCESSOR "@streq JSON" "id:900201,phase:2,pass,msg:'json body'"
"#,
    )
    .expect("crs conf");

    let mut ctx = common::make_post_ctx("http://example.com/api", r#"{"a":1}"#);
    ctx.request_headers
        .insert("content-type", "application/json".parse().unwrap());
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        ctx.rule_matches.iter().any(|m| m.rule_id == "900201"),
        "a JSON body did not report REQBODY_PROCESSOR=JSON"
    );

    // A form body is not JSON, so the same rule must stay quiet — that
    // difference is the entire point of the gate.
    let mut ctx = common::make_post_ctx("http://example.com/api", "a=1&b=2");
    ctx.request_headers.insert(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        !ctx.rule_matches.iter().any(|m| m.rule_id == "900201"),
        "a urlencoded body reported itself as JSON"
    );
}

/// CRS 920180's intent, pinned in both directions.
///
/// It flags an HTTP/1.1 POST carrying a body with neither Content-Length nor
/// Transfer-Encoding — a request smuggling primitive, since the WAF and the
/// origin can disagree about where the body ends. It must NOT flag an ordinary
/// POST, and must not flag HTTP/2, where framing carries the length and neither
/// header is required.
///
/// This rule immediately found a malformed fixture in the existing test helper
/// the moment it started working, which is the sort of thing that makes it worth
/// having.
#[test]
fn post_without_a_length_is_flagged_but_ordinary_posts_are_not_920180() {
    let eng = engine("REQUEST-920-PROTOCOL-ENFORCEMENT.conf");
    let body = "name=John&message=Hello";

    // (a) ordinary HTTP/1.1 POST with Content-Length -> quiet
    let mut ctx = common::make_post_ctx("http://example.com/contact", body);
    common::set_paranoia(&mut ctx, 2);
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        !ctx.rule_matches.iter().any(|m| m.rule_id == "920180"),
        "an ordinary POST was flagged as having no length: {:?}",
        ctx.rule_matches
            .iter()
            .map(|m| &m.rule_id)
            .collect::<Vec<_>>()
    );

    // (b) chunked, no Content-Length -> also quiet
    let mut ctx = common::make_post_ctx("http://example.com/contact", body);
    common::set_paranoia(&mut ctx, 2);
    ctx.request_headers.remove(http::header::CONTENT_LENGTH);
    ctx.request_headers
        .insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        !ctx.rule_matches.iter().any(|m| m.rule_id == "920180"),
        "a chunked POST was flagged as having no length"
    );

    // (c) neither header on HTTP/1.1 -> FLAGGED, which is the point
    let mut ctx = common::make_post_ctx("http://example.com/contact", body);
    common::set_paranoia(&mut ctx, 2);
    ctx.request_headers.remove(http::header::CONTENT_LENGTH);
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        ctx.rule_matches.iter().any(|m| m.rule_id == "920180"),
        "a POST with no length and no transfer-encoding was NOT flagged"
    );

    // (d) same request over HTTP/2 -> quiet, because framing carries the length
    let mut ctx = common::make_post_ctx("http://example.com/contact", body);
    common::set_paranoia(&mut ctx, 2);
    ctx.request_headers.remove(http::header::CONTENT_LENGTH);
    ctx.http_version = http::Version::HTTP_2;
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        !ctx.rule_matches.iter().any(|m| m.rule_id == "920180"),
        "HTTP/2 does not require Content-Length and must not be flagged"
    );
}
