//! A chained rule must behave the way ModSecurity runs it, link by link.
//!
//! The importer used to keep only a chain child's targets and operator. Its own
//! transformations were dropped and the PARENT's applied in their place, its own
//! `setvar`s were dropped, and the parent's `setvar`s ran only after the whole
//! chain had been evaluated. CRS is written for ModSecurity's semantics, where
//! the actions of each link run when that link matches (reference manual,
//! "chain"): a parent that stores a value for its child to check, as the CRS
//! protocol-policy rules all do, left the child reading a variable that did not
//! exist yet. Those rules compiled, were counted as enforced, and could never
//! fire — `/backup.sql`, a `Proxy:` header (httpoxy) and an unlisted
//! Content-Type all scored 0 on a live node.
//!
//! The contract pinned here, per link:
//!
//!   * a link's own transformations apply to it, and only to it;
//!   * a link's `setvar`s run as soon as that link matches — before the next
//!     link is evaluated — even when a later link then fails;
//!   * a link that does not match ends the chain: later links are not
//!     evaluated and their `setvar`s do not run;
//!   * the rule fires, and scores, only when every link matched;
//!   * `capture` makes the whole match available as `TX.0`, with or without
//!     groups in the pattern;
//!   * a `setvar` whose NAME is built from the match (`tx.name_%{tx.0}`) runs
//!     once per matched value, as ModSecurity runs actions per match — that is
//!     how CRS collects every header name for the restricted-header check.
//!
//! Assertions are on rule IDs, never on the decision alone: another rule or the
//! anomaly total could block the request while the rule under test stays broken.

mod common;

use common::*;
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn engine(conf: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf_dir(conf, None).expect("import rule");
    let ruleset = sentinel_rules::compile(file).expect("compile rule");
    RuleEngine::new(ruleset)
}

fn ids(ctx: &RequestContext) -> Vec<String> {
    ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect()
}

fn fired(ctx: &RequestContext, id: &str) -> bool {
    ids(ctx).iter().any(|r| r == id)
}

fn header(ctx: &mut RequestContext, name: &str, value: &str) {
    ctx.request_headers.append(
        http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
        value.parse().expect("header value"),
    );
}

/// The policy lists REQUEST-901-INITIALIZATION would set, copied from the
/// shipped CRS 4.7.0 file. The product does not load REQUEST-901 (it would
/// override the site's threshold and paranoia level); a site supplies these
/// through `crs_policy`, which the proxy seeds into the TX store the same way.
fn seed_crs_policy_lists(ctx: &mut RequestContext) {
    for (k, v) in [
        (
            "ALLOWED_REQUEST_CONTENT_TYPE",
            "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| \
             |text/xml| |application/xml| |application/soap+xml| |application/json| \
             |application/cloudevents+json| |application/cloudevents-batch+json|",
        ),
        (
            "ALLOWED_REQUEST_CONTENT_TYPE_CHARSET",
            "|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|",
        ),
        (
            "RESTRICTED_EXTENSIONS",
            ".asa/ .asax/ .ascx/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ \
             .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ \
             .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pem/ .pol/ \
             .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ \
             .vsdisco/ .webinfo/ .xsd/ .xsx/",
        ),
        (
            "RESTRICTED_HEADERS_BASIC",
            "/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/ \
             /x-http-method-override/ /x-http-method/ /x-method-override/",
        ),
        ("RESTRICTED_HEADERS_EXTENDED", "/accept-charset/"),
    ] {
        ctx.tx_vars.insert(k.to_string(), v.to_string());
    }
}

fn protocol_engine() -> RuleEngine {
    load_crs_engines(&[
        "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        "REQUEST-922-MULTIPART-ATTACK.conf",
    ])
}

/// A GET at paranoia level 1 with the CRS policy lists seeded.
fn policy_get(uri: &str) -> RequestContext {
    let mut ctx = make_get_ctx(uri);
    set_paranoia(&mut ctx, 1);
    seed_crs_policy_lists(&mut ctx);
    ctx
}

/// A JSON POST at paranoia level 1 with the given Content-Type.
fn policy_post(content_type: &str) -> RequestContext {
    let mut ctx = make_post_ctx("/api/feedback", r#"{"comment":"great","rating":5}"#);
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        content_type.parse().expect("content type"),
    );
    set_paranoia(&mut ctx, 1);
    seed_crs_policy_lists(&mut ctx);
    ctx
}

const BOUNDARY: &str = "----SentinelChainBoundary7MA4YWxkTrZu0gW";

fn multipart_charset_post(charset: &str) -> RequestContext {
    let body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"_charset_\"\r\n\r\n{charset}\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\r\n\
         --{BOUNDARY}--\r\n"
    );
    let mut ctx = make_post_ctx("/upload", &body);
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={BOUNDARY}")
            .parse()
            .unwrap(),
    );
    set_paranoia(&mut ctx, 1);
    seed_crs_policy_lists(&mut ctx);
    ctx
}

// ---------------------------------------------------------------------------
// 1. The shipped CRS policy rules (920420, 920480, 920440, 920450, 920451, 922100)
// ---------------------------------------------------------------------------

#[test]
fn rule_920420_flags_a_content_type_outside_the_policy() {
    let eng = protocol_engine();
    let mut ctx = policy_post("application/x-evil");
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        fired(&ctx, "920420"),
        "920420 must fire; fired: {:?}",
        ids(&ctx)
    );
}

#[test]
fn rule_920420_lowercases_in_the_child_so_case_is_not_a_violation() {
    let eng = protocol_engine();
    for ct in [
        "application/json",
        "Application/JSON",
        "APPLICATION/JSON; charset=utf-8",
    ] {
        let mut ctx = policy_post(ct);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            !fired(&ctx, "920420"),
            "{ct}: an allowed type in any case must not fire 920420; fired: {:?}",
            ids(&ctx)
        );
    }
}

#[test]
fn rule_920480_flags_a_charset_outside_the_policy_and_ignores_case() {
    let eng = protocol_engine();
    let mut bad = policy_post("application/json; charset=ebcdic-cp-us");
    eval(&eng, &mut bad, Phase::RequestBody);
    assert!(
        fired(&bad, "920480"),
        "920480 must fire; fired: {:?}",
        ids(&bad)
    );

    let mut ok = policy_post("application/json; charset=UTF-8");
    eval(&eng, &mut ok, Phase::RequestBody);
    assert!(
        !fired(&ok, "920480"),
        "UTF-8 is allowed; fired: {:?}",
        ids(&ok)
    );
}

#[test]
fn rule_920440_flags_restricted_extensions_in_any_case() {
    let eng = protocol_engine();
    for uri in ["/backup.bak", "/dump.sql", "/BACKUP.BAK", "/web.config"] {
        let mut ctx = policy_get(uri);
        eval(&eng, &mut ctx, Phase::RequestHeaders);
        assert!(
            fired(&ctx, "920440"),
            "{uri}: 920440 must fire; fired: {:?}",
            ids(&ctx)
        );
    }
    for uri in [
        "/",
        "/index.html",
        "/app.js",
        "/img/logo.png",
        "/api/products",
    ] {
        let mut ctx = policy_get(uri);
        eval(&eng, &mut ctx, Phase::RequestHeaders);
        assert!(
            !fired(&ctx, "920440"),
            "{uri}: benign; fired: {:?}",
            ids(&ctx)
        );
    }
}

#[test]
fn rule_920450_flags_a_restricted_header_wherever_it_appears() {
    let eng = protocol_engine();
    // Host and User-Agent are already present, so the restricted header is
    // never the first name the parent matches.
    for (name, value) in [
        ("Proxy", "http://attacker.example"),
        ("X-HTTP-Method-Override", "DELETE"),
        ("Content-Encoding", "gzip"),
    ] {
        let mut ctx = policy_get("/");
        header(&mut ctx, "Accept", "text/html");
        header(&mut ctx, name, value);
        eval(&eng, &mut ctx, Phase::RequestHeaders);
        assert!(
            fired(&ctx, "920450"),
            "{name}: 920450 must fire; fired: {:?}",
            ids(&ctx)
        );
    }

    let mut benign = policy_get("/");
    header(&mut benign, "Accept", "text/html");
    header(&mut benign, "Accept-Language", "en-IN");
    eval(&eng, &mut benign, Phase::RequestHeaders);
    assert!(
        !fired(&benign, "920450"),
        "benign headers; fired: {:?}",
        ids(&benign)
    );
}

#[test]
fn rule_920451_is_paranoia_level_two() {
    let eng = protocol_engine();
    let mut pl2 = policy_get("/");
    set_paranoia(&mut pl2, 2);
    header(&mut pl2, "Accept-Charset", "utf-8");
    eval(&eng, &mut pl2, Phase::RequestHeaders);
    assert!(
        fired(&pl2, "920451"),
        "920451 must fire at PL2; fired: {:?}",
        ids(&pl2)
    );

    let mut pl1 = policy_get("/");
    header(&mut pl1, "Accept-Charset", "utf-8");
    eval(&eng, &mut pl1, Phase::RequestHeaders);
    assert!(
        !fired(&pl1, "920451"),
        "920451 is PL2 only; fired: {:?}",
        ids(&pl1)
    );
}

#[test]
fn rule_922100_checks_the_multipart_charset_field() {
    let eng = protocol_engine();
    let mut bad = multipart_charset_post("ebcdic-cp-us");
    eval(&eng, &mut bad, Phase::RequestBody);
    assert!(
        fired(&bad, "922100"),
        "922100 must fire; fired: {:?}",
        ids(&bad)
    );

    for ok in ["utf-8", "UTF-8"] {
        let mut ctx = multipart_charset_post(ok);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            !fired(&ctx, "922100"),
            "{ok} is allowed; fired: {:?}",
            ids(&ctx)
        );
    }
}

/// Without the policy lists the operator macros cannot resolve, and the rules
/// must stay silent rather than treat every request as a violation (an empty
/// allow-list makes everything "not within" it). This is the default today,
/// because REQUEST-901 is not loaded.
#[test]
fn without_the_policy_lists_the_policy_rules_stay_silent() {
    let eng = protocol_engine();
    let mut post = make_post_ctx("/api", r#"{"a":1}"#);
    post.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/x-evil".parse().unwrap(),
    );
    set_paranoia(&mut post, 1);
    eval(&eng, &mut post, Phase::RequestBody);
    let mut get = make_get_ctx("/backup.bak");
    set_paranoia(&mut get, 1);
    header(&mut get, "Proxy", "http://attacker.example");
    eval(&eng, &mut get, Phase::RequestHeaders);
    for (ctx, id) in [(&post, "920420"), (&get, "920440"), (&get, "920450")] {
        assert!(
            !fired(ctx, id),
            "{id} has no policy list to check; fired: {:?}",
            ids(ctx)
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Chain semantics on minimal rules
// ---------------------------------------------------------------------------

const CAPTURE_CHAIN: &str = r#"
SecRule REQUEST_HEADERS:X-Probe "@rx ^[a-z]+" \
    "id:1001,phase:1,block,capture,t:none,msg:'probe',\
    setvar:'tx.probe=|%{tx.0}|',\
    chain"
    SecRule TX:probe "@streq |evil|" \
        "t:none,\
        setvar:'tx.probe_category_score=+5',\
        setvar:'tx.inbound_anomaly_score_pl1=+5'"
"#;

#[test]
fn a_parent_setvar_is_visible_to_its_child_and_tx0_needs_no_group() {
    let eng = engine(CAPTURE_CHAIN);
    let mut ctx = make_get_ctx("/");
    header(&mut ctx, "X-Probe", "evil");
    eval(&eng, &mut ctx, Phase::RequestHeaders);
    assert!(fired(&ctx, "1001"), "fired: {:?}", ids(&ctx));
    assert_eq!(ctx.anomaly_score, 5, "scored once, on the whole chain");
    assert_eq!(ctx.tx_vars.get("PROBE").map(String::as_str), Some("|evil|"));
    assert_eq!(
        ctx.tx_vars.get("PROBE_CATEGORY_SCORE").map(String::as_str),
        Some("5"),
        "the child's own setvar runs when the child matches"
    );
}

#[test]
fn a_failed_child_keeps_the_parent_setvar_and_runs_nothing_of_its_own() {
    let eng = engine(CAPTURE_CHAIN);
    let mut ctx = make_get_ctx("/");
    header(&mut ctx, "X-Probe", "harmless");
    eval(&eng, &mut ctx, Phase::RequestHeaders);
    assert!(!fired(&ctx, "1001"), "fired: {:?}", ids(&ctx));
    assert_eq!(ctx.anomaly_score, 0);
    assert_eq!(
        ctx.tx_vars.get("PROBE").map(String::as_str),
        Some("|harmless|"),
        "the parent matched, so its setvar ran (ModSecurity semantics)"
    );
    assert!(!ctx.tx_vars.contains_key("PROBE_CATEGORY_SCORE"));
}

#[test]
fn a_failed_parent_ends_the_chain() {
    let eng = engine(CAPTURE_CHAIN);
    let mut ctx = make_get_ctx("/");
    header(&mut ctx, "X-Probe", "123");
    eval(&eng, &mut ctx, Phase::RequestHeaders);
    assert!(!fired(&ctx, "1001"));
    assert!(
        !ctx.tx_vars.contains_key("PROBE"),
        "the parent did not match"
    );
    assert!(!ctx.tx_vars.contains_key("PROBE_CATEGORY_SCORE"));
}

#[test]
fn each_link_uses_its_own_transformations() {
    // The parent lowercases; the child must not inherit that.
    let eng = engine(
        r#"
SecRule ARGS:a "@rx ." "id:1002,phase:2,block,t:none,t:lowercase,msg:'own',chain"
    SecRule ARGS:b "@streq ABC" "t:none,setvar:'tx.inbound_anomaly_score_pl1=+5'"

SecRule ARGS:a "@rx ." "id:1003,phase:2,block,t:none,msg:'child lowercases',chain"
    SecRule ARGS:b "@streq abc" "t:none,t:lowercase,setvar:'tx.inbound_anomaly_score_pl1=+5'"
"#,
    );
    let mut ctx = make_get_ctx("/?a=x&b=ABC");
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        fired(&ctx, "1002"),
        "the parent's t:lowercase leaked into the child; fired: {:?}",
        ids(&ctx)
    );
    assert!(
        fired(&ctx, "1003"),
        "the child's own t:lowercase was dropped; fired: {:?}",
        ids(&ctx)
    );
}

#[test]
fn a_setvar_named_from_the_match_runs_once_per_matched_value() {
    let eng = engine(
        r#"
SecRule REQUEST_HEADERS_NAMES "@rx ^.*$" \
    "id:1004,phase:1,block,capture,t:none,t:lowercase,msg:'per value',\
    setvar:'tx.hn_%{tx.0}=/%{tx.0}/',\
    chain"
    SecRule TX:/^hn_/ "@within /x-evil/ /y-evil/" \
        "setvar:'tx.inbound_anomaly_score_pl1=+5'"
"#,
    );
    let mut ctx = make_get_ctx("/");
    header(&mut ctx, "Accept", "*/*");
    header(&mut ctx, "X-Evil", "1");
    eval(&eng, &mut ctx, Phase::RequestHeaders);
    assert!(fired(&ctx, "1004"), "fired: {:?}", ids(&ctx));
    assert_eq!(ctx.anomaly_score, 5, "one rule, scored once");
    assert_eq!(
        ctx.tx_vars.get("HN_HOST").map(String::as_str),
        Some("/host/")
    );
    assert_eq!(
        ctx.tx_vars.get("HN_X-EVIL").map(String::as_str),
        Some("/x-evil/")
    );

    let mut clean = make_get_ctx("/");
    header(&mut clean, "Accept", "*/*");
    eval(&eng, &mut clean, Phase::RequestHeaders);
    assert!(!fired(&clean, "1004"), "fired: {:?}", ids(&clean));
}

// ---------------------------------------------------------------------------
// 3. MATCHED_VAR(S) is the whole value the previous link matched
// ---------------------------------------------------------------------------

/// 944120's parent finds a gadget-chain class name (`clonetransformer`); its
/// child then looks for `processbuilder` in the same VALUE. Given only the
/// text the parent's pattern found, the child could never match: 120 of CRS's
/// own regression cases for this rule failed.
#[test]
fn rule_944120_checks_the_whole_matched_value() {
    let eng = load_crs_engines(&["REQUEST-944-APPLICATION-ATTACK-JAVA.conf"]);
    let mut attack = make_post_ctx("/post", "test=ProcessBuilder.evil.clonetransformer");
    set_paranoia(&mut attack, 1);
    eval(&eng, &mut attack, Phase::RequestBody);
    assert!(fired(&attack, "944120"), "fired: {:?}", ids(&attack));

    let mut benign = make_post_ctx("/post", "test=clonetransformer");
    set_paranoia(&mut benign, 1);
    eval(&eng, &mut benign, Phase::RequestBody);
    assert!(!fired(&benign, "944120"), "fired: {:?}", ids(&benign));
}

/// 932200: the parent finds `/ca?`; the children need a `/` and whitespace in
/// the value it came from (`www.google.com;/bin/ca? /et*/passwd`).
#[test]
fn rule_932200_reads_matched_var_through_two_children() {
    let eng = load_crs_engines(&["REQUEST-932-APPLICATION-ATTACK-RCE.conf"]);
    let mut ctx = make_get_ctx("/get?host=www.google.com;/bin/ca?+/et*/passwd");
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(fired(&ctx, "932200"), "fired: {:?}", ids(&ctx));
}

#[test]
fn matched_var_is_the_last_value_and_matched_vars_is_every_one() {
    let eng = engine(
        r#"
SecRule ARGS "@rx ^x" "id:1005,phase:2,block,t:none,msg:'last',chain"
    SecRule MATCHED_VAR "@rx yes" "setvar:'tx.inbound_anomaly_score_pl1=+5'"

SecRule ARGS "@rx ^x" "id:1006,phase:2,block,t:none,msg:'any',chain"
    SecRule MATCHED_VARS "@rx yes" "setvar:'tx.inbound_anomaly_score_pl1=+5'"
"#,
    );
    // Only the FIRST matching value holds `yes`.
    let mut first = make_get_ctx("/?a=x-yes&b=x-no");
    eval(&eng, &mut first, Phase::RequestBody);
    assert!(!fired(&first, "1005"), "fired: {:?}", ids(&first));
    assert!(fired(&first, "1006"), "fired: {:?}", ids(&first));

    // The LAST matching value holds it.
    let mut last = make_get_ctx("/?a=x-no&b=x-yes");
    eval(&eng, &mut last, Phase::RequestBody);
    assert!(fired(&last, "1005"), "fired: {:?}", ids(&last));
    assert!(fired(&last, "1006"), "fired: {:?}", ids(&last));
}
