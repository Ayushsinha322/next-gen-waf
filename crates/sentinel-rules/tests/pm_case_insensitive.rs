//! Regression guard: `@pm` / `@pmFromFile` must be CASE-INSENSITIVE.
//!
//! ModSecurity's `@pm` and `@pmFromFile` are case-insensitive. Ours was not, and
//! the failure mode was invisible: rules compiled, loaded, reported healthy, and
//! silently never matched.
//!
//! CRS word lists are written in natural casing (`Invoke-Expression`,
//! `Add-Computer`, `Net.WebClient`) and are matched against input the rules do not
//! lowercase first. Case-sensitive matching therefore killed rule 932120's
//! 421-entry Windows PowerShell RCE list almost entirely — 420 of its 421 entries
//! contain an uppercase character, so a real `IEX(New-Object Net.WebClient)`
//! payload scored zero.
//!
//! What makes this worth a dedicated test rather than a comment: a fix WAS
//! written, tested and committed for this exact bug (7d17fe7, "@pm / @pmFromFile
//! made case-INSENSITIVE") — and it changed `patterns::PatternRegistry::ac_set`,
//! a function with no callers anywhere in the workspace. The live builder,
//! `compiler::optimizer::build_ac`, was untouched and kept matching
//! case-sensitively. Reading the diff showed the bug fixed. Only executing the
//! engine showed the truth, so this test executes it.

mod common;

use common::{eval, make_get_ctx};
use sentinel_core::context::{Phase, WafDecision};
use sentinel_rules::RuleEngine;

/// Build an engine from inline SecRule source.
fn engine_from(src: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf(src).expect("test rule must import");
    let ruleset = sentinel_rules::compile(file).expect("test rule must compile");
    RuleEngine::new(ruleset)
}

fn blocks(engine: &RuleEngine, uri: &str) -> bool {
    let mut ctx = make_get_ctx(uri);
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx.decision == WafDecision::Block
}

/// The word list is in CRS's natural casing; the payloads are not. This is the
/// exact shape of rule 932120 against a real PowerShell download-cradle.
#[test]
fn pm_matches_regardless_of_case() {
    let engine = engine_from(
        r#"SecRule ARGS "@pm Invoke-Expression Add-Computer Net.WebClient" "id:900001,phase:2,deny,t:none""#,
    );

    // Uppercase list vs lowercase input — this is precisely what was broken.
    assert!(
        blocks(&engine, "/?q=invoke-expression%20whoami"),
        "@pm must match lowercase input against an uppercase word list; this is \
         the 932120 PowerShell failure where 420 of 421 entries were dead"
    );

    // All-caps form of a mixed-case entry.
    assert!(
        blocks(&engine, "/?q=NET.WEBCLIENT"),
        "@pm must match an all-uppercase form of a mixed-case entry"
    );

    // Exact casing must still match — guards against "fixing" this into something
    // that only matches when the cases DIFFER.
    assert!(
        blocks(&engine, "/?q=Invoke-Expression%20Get-Process"),
        "@pm must still match exact casing"
    );

    // Case-insensitive must not degrade into "matches anything".
    assert!(
        !blocks(&engine, "/?q=perfectly%20ordinary%20user%20text"),
        "@pm must not match unrelated input"
    );
}

/// Asserts on the exported live builder directly. The previous fix modified a
/// parallel, uncalled builder; pinning the behaviour of the function the compiler
/// actually calls is what stops that mistake repeating silently.
#[test]
fn pm_case_insensitivity_is_wired_into_the_live_builder() {
    let words = vec!["Invoke-Expression".to_string(), "Net.WebClient".to_string()];
    let ac = sentinel_rules::compiler::optimizer::build_ac(&words)
        .expect("build_ac must succeed on a normal word list");

    assert!(
        ac.is_match("iex; invoke-expression"),
        "build_ac must produce a case-INSENSITIVE automaton (ModSecurity @pm semantics)"
    );
    assert!(
        ac.is_match("NET.WEBCLIENT"),
        "build_ac must match an all-uppercase form of a mixed-case entry"
    );
    assert!(
        !ac.is_match("nothing relevant here"),
        "build_ac must not match unrelated input"
    );
}
