//! A census of what the shipped CRS actually compiles to.
//!
//! This exists because measuring coverage by grepping the .conf files and the
//! importer's match arms produced two wrong answers in a row: a regex for
//! `"op" =>` missed multi-pattern arms like `"pm" | "pmfromfile" =>`, so @pm and
//! @streq were reported as unimplemented when both have been supported all along.
//!
//! Importing the real directory and inspecting the compiled output cannot be wrong
//! in that way. It is slower, and it is the number to quote.

mod common;

#[test]
fn census_of_the_shipped_ruleset() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("CRS rules directory must exist")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
        .collect();
    files.sort();

    let mut merged = sentinel_rules::dsl::ast::RuleFile::default();
    let mut imported = 0usize;
    let mut failed: Vec<(std::path::PathBuf, String)> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("readable");
        match sentinel_rules::import_secrule_conf_dir(&src, path.parent()) {
            Ok(f) => {
                imported += f
                    .items
                    .iter()
                    .filter(|i| matches!(i, sentinel_rules::dsl::ast::RuleItem::Rule(_)))
                    .count();
                merged.items.extend(f.items);
            }
            // Collect rather than panic: a file that fails to import is itself a
            // finding, and panicking on the first one hides how many there are.
            Err(e) => failed.push((path.clone(), e.to_string())),
        }
    }

    let compiled = sentinel_rules::compile(merged).expect("merged CRS must compile");
    let total = compiled.rule_meta.len();

    // "Compiled" is not "enforced". A rule can compile, be counted here, appear
    // in the console's inventory, and still be incapable of matching anything —
    // which is worse than a missing rule, because it reports itself as
    // protection. So the census states the ENFORCED number, and names the gap.
    let disabled = compiled.coverage.disabled.len();
    let dropped = compiled.coverage.dropped.len();
    let enforced = total - disabled;

    println!("\n  ── shipped CRS census ──");
    println!("  .conf files              : {}", files.len());
    println!("  rules surviving import   : {imported}");
    println!("  rules after compile      : {total}");
    println!("  rules ENFORCED           : {enforced}");
    println!("  inert (cannot ever fire) : {disabled}");
    println!("  dropped (compile error)  : {dropped}");
    println!("  files that FAILED import : {}", failed.len());
    for (p, e) in &failed {
        println!("      {} — {}", p.file_name().unwrap().to_string_lossy(), e);
    }
    if disabled > 0 {
        let mut ids = compiled.coverage.disabled.clone();
        ids.sort_unstable();
        println!("  inert rule ids           : {ids:?}");
    }
    for (id, why) in &compiled.coverage.dropped {
        println!("      dropped {id} — {why}");
    }

    // The number worth quoting is the enforced one. Asserting on it rather than
    // on `total` is the whole point: the previous floor was satisfied by rules
    // that could not fire, which is how this read "zero gap" while eight
    // MATCHED_VARS chain children sat constant-false.
    assert_eq!(
        disabled, 0,
        "{disabled} shipped rule(s) compiled but can never fire: {:?}. \
         Either support what they need, or accept the gap deliberately — but it \
         must not be counted as coverage.",
        compiled.coverage.disabled
    );

    // A floor, not an equality: the point is to catch a REGRESSION in coverage.
    // Before the target-token work this compiled to roughly 330; asserting a floor
    // above that makes a future importer change that silently drops rules fail here
    // rather than in production.
    assert!(
        enforced >= 450,
        "CRS coverage regressed: only {enforced} rules are enforced (of {total} \
         compiled). The target-token work took this above 450; a drop means the \
         importer started skipping rules again."
    );
}
