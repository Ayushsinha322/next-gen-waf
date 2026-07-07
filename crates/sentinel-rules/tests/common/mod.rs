//! Shared test utilities for integration tests.
#![allow(dead_code)] // shared helpers; not every integration-test binary uses all of them

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use sentinel_core::context::{Phase, RequestContext, WafDecision};
use sentinel_rules::RuleEngine;

/// Resolve the OWASP CRS rules directory relative to the workspace root.
fn crs_rules_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/sentinel-rules
    // Workspace root = 2 levels up
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../rules/owasp-crs/rules")
}

/// Load a single CRS rule file and compile into a RuleEngine.
pub fn load_crs_engine(filename: &str) -> RuleEngine {
    let path = crs_rules_dir().join(filename);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let data_dir = path.parent().unwrap();
    let file = sentinel_rules::import_secrule_conf_dir(&source, Some(data_dir))
        .unwrap_or_else(|e| panic!("failed to import {}: {}", path.display(), e));
    let ruleset = sentinel_rules::compile(file)
        .unwrap_or_else(|e| panic!("failed to compile {}: {}", path.display(), e));
    RuleEngine::new(ruleset)
}

/// Load multiple CRS rule files and compile into a merged RuleEngine.
pub fn load_crs_engines(filenames: &[&str]) -> RuleEngine {
    use sentinel_rules::dsl::ast::RuleFile;

    let mut merged = RuleFile::default();
    for filename in filenames {
        let path = crs_rules_dir().join(filename);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let data_dir = path.parent().unwrap();
        let file = sentinel_rules::import_secrule_conf_dir(&source, Some(data_dir))
            .unwrap_or_else(|e| panic!("failed to import {}: {}", path.display(), e));
        merged.items.extend(file.items);
    }
    let ruleset = sentinel_rules::compile(merged).expect("failed to compile merged CRS rules");
    RuleEngine::new(ruleset)
}

/// Create a fresh RequestContext with default values for testing.
pub fn make_ctx() -> RequestContext {
    RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
}

/// Add the baseline headers every real HTTP request carries (Host and
/// User-Agent). Without these, CRS protocol-enforcement rules 920280
/// (missing Host) and 920320 (missing User-Agent) fire on otherwise clean
/// traffic. Tests that specifically set their own User-Agent overwrite it.
fn apply_baseline_headers(ctx: &mut RequestContext) {
    ctx.request_headers
        .insert(http::header::HOST, "example.com".parse().unwrap());
    ctx.request_headers.insert(
        http::header::USER_AGENT,
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0"
            .parse()
            .unwrap(),
    );
}

/// Create a context simulating a GET request with query parameters.
pub fn make_get_ctx(uri: &str) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.uri = uri.parse().expect("invalid test URI");
    ctx.http_version = http::Version::HTTP_11;
    let m = http::Method::GET;
    ctx.method = m;
    apply_baseline_headers(&mut ctx);
    apply_crs_setup(&mut ctx);
    ctx
}

/// Apply the CRS setup transaction variables that crs-setup.conf normally
/// provides. The CRS importer uppercases all TX variable names, so these
/// must be stored uppercase to be found at runtime (e.g. by rule 901001's
/// `&TX:crs_setup_version` configuration check).
pub fn apply_crs_setup(ctx: &mut RequestContext) {
    ctx.tx_vars
        .insert("CRS_SETUP_VERSION".to_string(), "400".to_string());
    ctx.tx_vars
        .insert("CRITICAL_ANOMALY_SCORE".to_string(), "5".to_string());
    ctx.tx_vars
        .insert("ERROR_ANOMALY_SCORE".to_string(), "4".to_string());
    ctx.tx_vars
        .insert("WARNING_ANOMALY_SCORE".to_string(), "3".to_string());
    ctx.tx_vars
        .insert("NOTICE_ANOMALY_SCORE".to_string(), "2".to_string());
}

/// Create a context simulating a POST request with a body.
pub fn make_post_ctx(uri: &str, body: &str) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.uri = uri.parse().expect("invalid test URI");
    ctx.http_version = http::Version::HTTP_11;
    let m = http::Method::POST;
    ctx.method = m;
    ctx.request_body = Some(Bytes::from(body.to_string()));
    // Set Content-Type for proper body inspection
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    apply_baseline_headers(&mut ctx);
    apply_crs_setup(&mut ctx);
    ctx
}

/// Evaluate rules against a context and assert the expected decision.
pub fn assert_decision(ctx: &RequestContext, expected: WafDecision, msg: &str) {
    assert_eq!(
        ctx.decision, expected,
        "{}: decision mismatch (expected {:?}, got {:?})",
        msg, expected, ctx.decision
    );
}

/// Evaluate rules against a context and assert the anomaly score matches.
pub fn assert_score(ctx: &RequestContext, min_score: u32, msg: &str) {
    assert!(
        ctx.anomaly_score >= min_score,
        "{}: anomaly_score {} < expected minimum {}. Rule matches: {:?}",
        msg,
        ctx.anomaly_score,
        min_score,
        ctx.rule_matches,
    );
}

/// Evaluate rules against a context and assert no anomaly score was added.
pub fn assert_clean(ctx: &RequestContext, msg: &str) {
    assert_eq!(
        ctx.anomaly_score, 0,
        "{}: expected clean (score 0), got {}. Rule matches: {:?}",
        msg, ctx.anomaly_score, ctx.rule_matches
    );
}

/// Evaluate a rule engine the way the real proxy does: run phase 1
/// (request headers) followed by phase 2 (request body), accumulating
/// anomaly score across both. The `phase` argument is accepted for call-site
/// readability but both CRS phases always run, matching the proxy pipeline
/// where `phase1_headers` and `phase2_body` execute sequentially.
///
/// A threshold of 0 disables early-exit so the full anomaly score is
/// accumulated, letting tests assert on the total.
pub fn eval(engine: &RuleEngine, ctx: &mut RequestContext, _phase: Phase) {
    engine.evaluate(ctx, Phase::RequestHeaders, 0);
    engine.evaluate(ctx, Phase::RequestBody, 0);
}

/// Set the DETECTION_PARANOIA_LEVEL in tx_vars (required by CRS skip-gates).
pub fn set_paranoia(ctx: &mut RequestContext, level: u8) {
    ctx.tx_vars
        .insert("DETECTION_PARANOIA_LEVEL".to_string(), level.to_string());
}
