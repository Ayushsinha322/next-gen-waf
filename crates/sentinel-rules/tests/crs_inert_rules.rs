//! No shipped rule may compile into something that can never match.
//!
//! The coverage census counts rules that COMPILED. It never asks whether a
//! compiled rule is capable of matching anything, so a rule can be present in
//! the inventory, reported in the total, shown in the console's rule list, and
//! still be incapable of firing. That is worse than a missing rule: a missing
//! rule is visible, an inert one reports itself as protection.
//!
//! There are two ways a rule ends up inert, and only one of them was detected:
//!
//!   * an unsupported OPERATOR imports as `Never` — already recorded in
//!     `coverage.disabled`, including in chain children.
//!
//!   * an unsupported TARGET is dropped from the target list. When every target
//!     of a condition is dropped the list is empty, and the compiler emits a
//!     constant-false (`MatchEq "__never__"`). Nothing recorded it anywhere, so
//!     the census read "zero gap" while the rules below could not fire.
//!
//! The second case cost eight rules, all of them chain children reading
//! `MATCHED_VARS` — the value the parent condition matched. Chain links are
//! ANDed, so a constant-false child disables the whole parent. Several are
//! NEGATED children, which are false-positive refinements ("…and the matched
//! text is not a JWT"), so the effect was to disable the detection outright
//! rather than to make it stricter.

mod common;

use sentinel_rules::compiler::emitter::Instruction;

/// Compile the shipped CRS exactly as the data plane does.
fn compile_shipped_crs() -> sentinel_rules::compiler::emitter::CompiledRuleSet {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("CRS rules directory must exist")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
        .collect();
    files.sort();

    let mut merged = sentinel_rules::dsl::ast::RuleFile::default();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("readable");
        if let Ok(f) = sentinel_rules::import_secrule_conf_dir(&src, path.parent()) {
            merged.items.extend(f.items);
        }
    }
    sentinel_rules::compile(merged).expect("merged CRS must compile")
}

/// Rule ids whose instruction span contains the never-match sentinel.
///
/// `RuleEnd` delimits each rule's instructions, so the span between one end and
/// the next belongs to the rule the end names.
fn never_matching_rules(cs: &sentinel_rules::compiler::emitter::CompiledRuleSet) -> Vec<u32> {
    let never_id = cs.literals.iter().position(|l| l == "__never__");
    let Some(never_id) = never_id else {
        return Vec::new(); // sentinel not in the literal table: nothing is inert
    };

    let mut inert = Vec::new();
    for program in &cs.phase_programs {
        let mut span_has_never = false;
        for instr in program {
            match instr {
                Instruction::MatchEq { literal_id } if *literal_id == never_id => {
                    span_has_never = true;
                }
                Instruction::RuleEnd { rule_id } => {
                    if span_has_never {
                        inert.push(*rule_id);
                    }
                    span_has_never = false;
                }
                _ => {}
            }
        }
    }
    inert.sort_unstable();
    inert.dedup();
    inert
}

#[test]
fn no_shipped_rule_compiles_to_a_constant_false() {
    let cs = compile_shipped_crs();
    let inert = never_matching_rules(&cs);

    assert!(
        inert.is_empty(),
        "these rules compiled and are counted in the inventory, but contain a \
         constant-false and can NEVER fire: {inert:?}\n\
         An empty target list compiles to `MatchEq \"__never__\"`. Either the \
         target is genuinely unsupported — in which case the rule belongs in \
         coverage.disabled so it is VISIBLE — or it should be supported."
    );
}

/// A rule that cannot fire must be reported as a coverage gap, whatever made it
/// inert. This is the structural half: fixing the nine rules without this would
/// leave the next unsupported target just as silent.
#[test]
fn every_inert_rule_is_reported_as_a_coverage_gap() {
    let cs = compile_shipped_crs();
    let inert = never_matching_rules(&cs);

    let unreported: Vec<u32> = inert
        .iter()
        .copied()
        .filter(|id| !cs.coverage.disabled.contains(id))
        .collect();

    assert!(
        unreported.is_empty(),
        "these rules can never fire and are NOT in coverage.disabled, so the \
         census reports no gap while they sit inert: {unreported:?}"
    );
}

/// The eight rules the target gap disabled, named so a regression says which
/// protection went away rather than only that a count moved.
#[test]
fn the_rules_that_read_what_their_parent_matched_can_fire() {
    let cs = compile_shipped_crs();
    let inert = never_matching_rules(&cs);

    // Chain children targeting MATCHED_VAR / MATCHED_VARS.
    //
    // 944110 is deliberately NOT here: its child targets
    // `MATCHED_VARS|XML:/*|XML://@*`, so the XML targets survived and the list
    // was never empty. It was still reading a target the engine dropped, which
    // is why it is fixed by the same change, but it was not constant-false and
    // claiming it was would overstate the damage.
    const WAS_INERT: &[(u32, &str)] = &[
        (932200, "RCE bypass via wildcards"),
        (932206, "RCE bypass, second form"),
        (932240, "RCE bypass, negated refinement"),
        (933120, "PHP config directive injection"),
        (933151, "PHP script injection"),
        (941310, "US-ASCII XSS encoding"),
        (942440, "SQL comment sequence"),
        (944120, "Java deserialization (CVE-2015-4852)"),
    ];

    let still_inert: Vec<String> = WAS_INERT
        .iter()
        .filter(|(id, _)| inert.contains(id))
        .map(|(id, what)| format!("{id} ({what})"))
        .collect();

    assert!(
        still_inert.is_empty(),
        "these rules are inert again: {}",
        still_inert.join(", ")
    );

    // And they must actually be present, not merely non-inert by absence.
    let missing: Vec<u32> = WAS_INERT
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !cs.rule_meta.contains_key(id))
        .collect();
    assert!(
        missing.is_empty(),
        "these rules are not in the compiled set at all: {missing:?}"
    );
}

/// Compile-level proof is necessary but not sufficient: a rule can stop being
/// constant-false and still not fire. This drives the whole engine at the
/// paranoia level the rule is tagged for.
#[test]
fn the_sql_comment_rule_actually_fires_again() {
    use common::{eval, make_get_ctx, set_paranoia};
    use sentinel_core::context::Phase;

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules");
    let path = dir.join("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let src = std::fs::read_to_string(&path).expect("readable");
    let file = sentinel_rules::import_secrule_conf_dir(&src, path.parent()).expect("imports");
    let engine = sentinel_rules::RuleEngine::new(sentinel_rules::compile(file).expect("compiles"));

    // `'--` is a SQL comment sequence and is not a JWT, so the parent matches
    // and the negated child lets it through.
    let mut ctx = make_get_ctx("/search?q=1%27--%20");
    set_paranoia(&mut ctx, 2); // 942440 is tagged paranoia-level/2
    eval(&engine, &mut ctx, Phase::RequestBody);

    let fired: Vec<&str> = ctx
        .rule_matches
        .iter()
        .map(|m| m.rule_id.as_str())
        .collect();
    assert!(
        fired.contains(&"942440"),
        "942440 should fire on a SQL comment sequence; rules that fired: {fired:?}"
    );
}

/// The same rule must still NOT fire on the thing its negated child exists to
/// exclude. Restoring the child is only correct if the exclusion works too —
/// otherwise this trades a silent gap for a false positive on every JWT.
#[test]
fn the_sql_comment_rule_still_excludes_a_jwt() {
    use common::{eval, make_get_ctx, set_paranoia};
    use sentinel_core::context::Phase;

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules");
    let path = dir.join("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let src = std::fs::read_to_string(&path).expect("readable");
    let file = sentinel_rules::import_secrule_conf_dir(&src, path.parent()).expect("imports");
    let engine = sentinel_rules::RuleEngine::new(sentinel_rules::compile(file).expect("compiles"));

    // A JWT whose payload segment contains "--": the parent regex matches it,
    // and the child is the only thing standing between a signed token and a
    // critical SQL-injection score.
    let mut ctx =
        make_get_ctx("/api?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhLS1iIn0.c2ln--bmF0dXJl");
    set_paranoia(&mut ctx, 2);
    eval(&engine, &mut ctx, Phase::RequestBody);

    let fired: Vec<&str> = ctx
        .rule_matches
        .iter()
        .map(|m| m.rule_id.as_str())
        .collect();
    assert!(
        !fired.contains(&"942440"),
        "942440 fired on a JWT — the negated MATCHED_VARS child is not excluding. \
         Rules that fired: {fired:?}"
    );
}
