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

    println!("\n  ── shipped CRS census ──");
    println!("  .conf files              : {}", files.len());
    println!("  rules surviving import   : {imported}");
    println!("  rules after compile      : {total}");
    println!("  files that FAILED import : {}", failed.len());
    for (p, e) in &failed {
        println!("      {} — {}", p.file_name().unwrap().to_string_lossy(), e);
    }

    // A floor, not an equality: the point is to catch a REGRESSION in coverage.
    // Before the target-token work this compiled to roughly 330; asserting a floor
    // above that makes a future importer change that silently drops rules fail here
    // rather than in production.
    assert!(
        total >= 450,
        "CRS coverage regressed: only {total} rules compiled. \
         The target-token work took this above 450; a drop means the importer \
         started skipping rules again."
    );
}
