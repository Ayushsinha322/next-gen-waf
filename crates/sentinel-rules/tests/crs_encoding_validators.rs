//! The four CRS rules that could not fire because their operator lived in a
//! chain CHILD — and the coverage report that could not see them.
//!
//! `@validateUrlEncoding` (920220, 920221, 920240) and `@validateUtf8Encoding`
//! (920250) were compiled to `Operator::Never`. Chain links are ANDed, so one
//! `Never` anywhere in the chain makes the whole rule unable to fire.
//!
//! Two things hid it for months:
//!
//!   1. `RuleCoverage::disabled` tested only `rule.operator` — the TOP-LEVEL
//!      operator. Every one of these four carries its unsupported operator in a
//!      chain child, so the coverage report honestly reported "zero gap".
//!   2. The one remaining trace was a `sentinel_rules::crs_compat::importer`
//!      WARN, and `RUST_LOG` did not name that crate, so it was never printed.
//!
//! That combination is the `silently_inert_bug_class` shape at its purest: the
//! product measured the wrong thing, and the log that knew better was muted.

mod common;

use sentinel_core::context::Phase;
use sentinel_rules::compiler::emitter::CompiledRuleSet;
use std::path::Path;

fn crs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules")
}

fn compile_conf(conf: &str) -> CompiledRuleSet {
    let dir = crs_dir();
    let src = std::fs::read_to_string(dir.join(conf)).expect(conf);
    let parsed = sentinel_rules::import_secrule_conf_dir(&src, Some(&dir)).expect("import");
    sentinel_rules::compile(parsed).expect("compile")
}

fn compile_src(src: &str) -> CompiledRuleSet {
    let parsed = sentinel_rules::import_secrule_conf(src).expect("import");
    sentinel_rules::compile(parsed).expect("compile")
}

const PROTO: &str = "REQUEST-920-PROTOCOL-ENFORCEMENT.conf";

/// THE census. Every shipped CRS file, every rule: nothing dropped on a compile
/// error, nothing loaded-but-inert — counting chain children.
///
/// This is the guard that would have caught the original defect. It must stay a
/// whole-corpus sweep: the four rules at issue sat in one file, and a per-rule
/// allowlist would have been updated to match reality instead of exposing it.
#[test]
fn no_shipped_crs_rule_is_unable_to_fire() {
    let dir = crs_dir();
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .expect("crs dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".conf"))
        .collect();
    files.sort();
    assert!(
        files.len() > 10,
        "expected the full CRS rule set, found {} files — is the corpus present?",
        files.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    for f in &files {
        let set = compile_conf(f);
        if !set.coverage.disabled.is_empty() {
            offenders.push(format!(
                "{f}: rules {:?} loaded but can NEVER match (unsupported operator at the \
                 top level or in a chain condition)",
                set.coverage.disabled
            ));
        }
        if !set.coverage.dropped.is_empty() {
            let ids: Vec<u32> = set.coverage.dropped.iter().map(|(i, _)| *i).collect();
            offenders.push(format!("{f}: rules {ids:?} dropped on compile error"));
        }
    }
    assert!(
        offenders.is_empty(),
        "CRS coverage gap — these rules are counted as loaded protection and are not:\n{}",
        offenders.join("\n")
    );
}

/// The coverage detector must SEE a `Never` in a chain child. Without this the
/// census above passes vacuously, which is exactly what happened before.
#[test]
fn coverage_detects_an_unsupported_operator_in_a_chain_child() {
    // @verifyCC is genuinely unsupported and sits in the CHILD here.
    let set = compile_src(
        r#"
SecRule ARGS "@rx foo" \
    "id:600001,phase:2,block,msg:'probe',chain"
    SecRule ARGS "@verifyCC /\d{13,16}/" "t:none"
"#,
    );
    assert!(
        set.coverage.disabled.contains(&600001),
        "a rule whose CHAIN CHILD compiled to Never must be reported as unable to \
         fire; coverage.disabled was {:?}",
        set.coverage.disabled
    );
}

/// All four are present AND enforceable.
#[test]
fn the_four_encoding_rules_are_loaded_and_enforceable() {
    let set = compile_conf(PROTO);
    for id in [920220u32, 920221, 920240, 920250] {
        assert!(
            set.rule_meta.contains_key(&id),
            "rule {id} is not in the ruleset at all — the importer dropped it"
        );
        assert!(
            !set.coverage.disabled.contains(&id),
            "rule {id} loaded but is INERT — counted as present, can never match"
        );
    }
}

// ---------------------------------------------------------------------------
// 920220 — URL Encoding Abuse, end to end
// ---------------------------------------------------------------------------

/// The full chain: `REQUEST_URI_RAW` contains `%`, the URI splits into capture
/// groups, and `TX:1|TX:2 @validateUrlEncoding` judges them.
///
/// This exercises capture-group population too — the chain reads `TX:1`/`TX:2`,
/// which exist only because the regex instruction stores its groups.
#[test]
fn malformed_percent_encoding_is_detected_920220() {
    let eng = sentinel_rules::RuleEngine::new(compile_conf(PROTO));
    for uri in [
        "http://example.com/index.php?p=%zz",
        "http://example.com/index.php?p=%2",
        "http://example.com/search?q=ok%41%",
        "http://example.com/search?q=%2z",
    ] {
        let mut ctx = common::make_get_ctx(uri);
        common::set_paranoia(&mut ctx, 2);
        common::apply_crs_setup(&mut ctx);
        common::eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            ctx.rule_matches.iter().any(|m| m.rule_id == "920220"),
            "920220 did not fire on {uri:?}, which contains malformed \
             percent-encoding; matches: {:?}",
            ctx.rule_matches
                .iter()
                .map(|m| &m.rule_id)
                .collect::<Vec<_>>()
        );
    }
}

/// The other direction, and the one that decides whether this is deployable:
/// ordinary URLs — including correctly-encoded ones — must stay quiet.
#[test]
fn well_formed_urls_do_not_trip_the_url_encoding_rules() {
    let eng = sentinel_rules::RuleEngine::new(compile_conf(PROTO));
    for uri in [
        "http://example.com/",
        "http://example.com/index.php",
        "http://example.com/search?q=hello",
        "http://example.com/search?q=a%20b",
        "http://example.com/path/to/file.html?x=1&y=2",
        "http://example.com/rest/products/search?q=%41%42%43",
        "http://example.com/caf%C3%A9",
        // A Google/Facebook click id — base64url, full of '-' and '_'.
        "http://example.com/?fbclid=IwAR2--xyz-abcDEF_ghi",
    ] {
        let mut ctx = common::make_get_ctx(uri);
        common::set_paranoia(&mut ctx, 2);
        common::apply_crs_setup(&mut ctx);
        common::eval(&eng, &mut ctx, Phase::RequestBody);
        let fired: Vec<&String> = ctx
            .rule_matches
            .iter()
            .filter(|m| m.rule_id == "920220" || m.rule_id == "920221")
            .map(|m| &m.rule_id)
            .collect();
        assert!(
            fired.is_empty(),
            "{uri:?} is a legitimate URL but tripped {fired:?} — a protocol rule that \
             fires on ordinary traffic is worse than a missing one"
        );
    }
}

// ---------------------------------------------------------------------------
// 920250 — UTF-8 Encoding Abuse
// ---------------------------------------------------------------------------

/// The fact promised in `Operator::ValidateUtf8Encoding`'s doc comment, pinned so
/// it is never rediscovered as a bug: implementing the operator does NOT make
/// 920250 fire, because CRS's own REQUEST-901-INITIALIZATION sets
/// `tx.crs_validate_utf8_encoding` to 0 unless the operator opts in.
///
/// Upstream's decision, not a gap in ours — the check is false-positive-prone for
/// applications that are not UTF-8. The test exists so that "920250 never fires"
/// reads as expected rather than broken.
#[test]
fn utf8_rule_920250_is_gated_off_by_crs_default() {
    let eng = sentinel_rules::RuleEngine::new(compile_conf(PROTO));
    let mut ctx = common::make_get_ctx("http://example.com/etc%c0%afpasswd?p=%e0%80%80");
    common::set_paranoia(&mut ctx, 2);
    common::apply_crs_setup(&mut ctx);
    common::eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(
        !ctx.rule_matches.iter().any(|m| m.rule_id == "920250"),
        "920250 fired without tx.crs_validate_utf8_encoding being set. That is not \
         necessarily wrong, but it contradicts the CRS default and the operator's \
         documentation — reconcile the two before changing this test."
    );
}

/// With the gate open, the operator does its job. Proves the implementation is
/// real, rather than the rule being quiet for two different reasons at once.
#[test]
fn utf8_abuse_is_detected_when_the_gate_is_open() {
    let set = compile_src(
        r#"
SecRule ARGS|REQUEST_FILENAME "@validateUtf8Encoding" \
    "id:600002,phase:2,block,msg:'UTF8 Encoding Abuse Attack Attempt',t:none"
"#,
    );
    assert!(
        set.coverage.disabled.is_empty(),
        "the operator is still compiling to Never: {:?}",
        set.coverage.disabled
    );
    let eng = sentinel_rules::RuleEngine::new(set);

    let mut bad = common::make_get_ctx("http://example.com/x?p=%e0%80%80");
    common::eval(&eng, &mut bad, Phase::RequestBody);
    assert!(
        bad.rule_matches.iter().any(|m| m.rule_id == "600002"),
        "overlong UTF-8 in an argument was not detected"
    );

    let mut good = common::make_get_ctx("http://example.com/x?p=caf%C3%A9");
    common::eval(&eng, &mut good, Phase::RequestBody);
    assert!(
        !good.rule_matches.iter().any(|m| m.rule_id == "600002"),
        "correctly-encoded UTF-8 (é) was flagged as abuse"
    );
}

// ---------------------------------------------------------------------------
// ARGS_COMBINED_SIZE
// ---------------------------------------------------------------------------

/// The target 920390 needs. It was reported as "unknown target token, skipping",
/// and since it is that chain link's ONLY target the link had no targets at all.
#[test]
fn args_combined_size_counts_names_and_values() {
    // a=1 (2) + bb=22 (4) + ccc=333 (6) = 12
    let set = compile_src(
        r#"
SecRule ARGS_COMBINED_SIZE "@gt 11" \
    "id:600003,phase:2,block,msg:'Total arguments size exceeded',t:none"
"#,
    );
    let eng = sentinel_rules::RuleEngine::new(set);

    let mut over = common::make_get_ctx("http://example.com/x?a=1&bb=22&ccc=333");
    common::eval(&eng, &mut over, Phase::RequestBody);
    assert!(
        over.rule_matches.iter().any(|m| m.rule_id == "600003"),
        "combined size 12 should exceed a threshold of 11 — names must be counted \
         alongside values, or a payload hidden in parameter NAMES goes unbounded"
    );

    let mut under = common::make_get_ctx("http://example.com/x?a=1&bb=22");
    common::eval(&eng, &mut under, Phase::RequestBody);
    assert!(
        !under.rule_matches.iter().any(|m| m.rule_id == "600003"),
        "combined size 6 must not exceed a threshold of 11"
    );
}

/// `@unconditionalMatch` was spelled in camelCase in a match on an
/// already-lowercased name, so the arm was dead and CRS 901320 compiled to
/// `Never`. One character of casing, one rule silently off.
#[test]
fn unconditional_match_is_reachable_901320() {
    let set = compile_conf("REQUEST-901-INITIALIZATION.conf");
    assert!(
        !set.coverage.disabled.contains(&901320),
        "901320 is inert again — check that the operator arm is spelled lowercase, \
         since parse_crs_operator lowercases before matching"
    );
}
