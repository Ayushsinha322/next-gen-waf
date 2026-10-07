//! Offline precision measurement for the in-house coverage signatures: hits on
//! the hard-benign corpus (false positives) and on the attack corpora
//! (detection), per file, plus the false positives the 2026-10-07 review
//! reported. Run manually, before and after a change to coverage.conf:
//!   cargo test -p sentinel-rules --test coverage_precision -- --ignored --nocapture
mod common;
use common::make_get_ctx;
use sentinel_core::context::Phase;
use std::path::Path;

/// Ordinary text the 2026-10-07 review found blocked by a coverage signature.
const REPORTED_FPS: &[&str] = &[
    "I was charged twice; for some reason the refund never came",
    "We moved; update my address please",
    "Sleep (8 hours) is recommended",
    "query($type: String, $where: Filter) { items(type: $type) { id } }",
    "Ticket #1234\nmore: the printer is offline again\nset: floor 3",
    "Hello,\necho, echo — is anyone there?",
];

fn engine() -> sentinel_rules::RuleEngine {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/custom/coverage.conf");
    let src = std::fs::read_to_string(&path).unwrap();
    let file = sentinel_rules::import_secrule_conf_dir(&src, path.parent()).unwrap();
    sentinel_rules::RuleEngine::new(sentinel_rules::compile(file).unwrap())
}

fn fires(engine: &sentinel_rules::RuleEngine, value: &str) -> Vec<String> {
    let q = percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
    let mut ctx = make_get_ctx(&format!("/search?q={q}"));
    engine.evaluate(&mut ctx, Phase::RequestHeaders, 0);
    engine.evaluate(&mut ctx, Phase::RequestBody, 0);
    ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect()
}

fn corpus(dir: &str) -> Vec<(String, Vec<String>)> {
    let root = format!("{}/waf-ml-corpora/{dir}", std::env::var("HOME").unwrap());
    let mut files: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    files
        .into_iter()
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("txt"))
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            let lines = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect();
            (p.file_name().unwrap().to_string_lossy().into_owned(), lines)
        })
        .collect()
}

#[test]
#[ignore]
fn coverage_precision_report() {
    let e = engine();
    let (mut bn, mut bh) = (0, 0);
    println!("--- hard-benign (any coverage hit = false positive)");
    for (name, lines) in corpus("hard-benign") {
        let hits: Vec<_> = lines.iter().filter(|l| !fires(&e, l).is_empty()).collect();
        println!("{:>5}/{:<5} {name}", hits.len(), lines.len());
        bn += lines.len();
        bh += hits.len();
    }
    let (mut an, mut ah) = (0, 0);
    println!("--- attack corpora (any coverage hit = detected)");
    for (name, lines) in corpus("evasion-corpus") {
        let hits = lines.iter().filter(|l| !fires(&e, l).is_empty()).count();
        println!("{:>5}/{:<5} {name}", hits, lines.len());
        an += lines.len();
        ah += hits;
    }
    println!("--- the review's reported false positives");
    for text in REPORTED_FPS {
        println!("{:?} -> {:?}", text, fires(&e, text));
    }
    println!("TOTAL benign FP {bh}/{bn}  attack detected {ah}/{an}");
}

/// Full ruleset (CRS 901-944 at PL2 + coverage) with the coverage file at
/// `$COVERAGE_OLD` against the one in the tree: every corpus line whose
/// block decision (anomaly score >= 10) differs. Run manually:
///   COVERAGE_OLD=/path/old.conf cargo test -p sentinel-rules \
///     --test coverage_precision full_ruleset_decision_diff -- --ignored --nocapture
#[test]
#[ignore]
fn full_ruleset_decision_diff() {
    use sentinel_rules::dsl::ast::RuleFile;
    let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules");
    let build = |coverage_src: &str| {
        let mut merged = RuleFile::default();
        let mut names: Vec<_> = std::fs::read_dir(&rules_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("REQUEST-9") && n.ends_with(".conf") && !n.contains("949"))
            .collect();
        names.sort();
        for n in names {
            let src = std::fs::read_to_string(rules_dir.join(&n)).unwrap();
            merged.items.extend(
                sentinel_rules::import_secrule_conf_dir(&src, Some(&rules_dir))
                    .unwrap()
                    .items,
            );
        }
        let cov_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/custom");
        merged.items.extend(
            sentinel_rules::import_secrule_conf_dir(coverage_src, Some(&cov_dir))
                .unwrap()
                .items,
        );
        sentinel_rules::RuleEngine::new(sentinel_rules::compile(merged).unwrap())
    };
    let new_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/custom/coverage.conf"),
    )
    .unwrap();
    let old_src =
        std::fs::read_to_string(std::env::var("COVERAGE_OLD").expect("COVERAGE_OLD")).unwrap();
    let (old, new) = (build(&old_src), build(&new_src));
    let blocked = |e: &sentinel_rules::RuleEngine, v: &str| {
        let q = percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC);
        let mut ctx = make_get_ctx(&format!("/search?q={q}"));
        common::set_paranoia(&mut ctx, 2);
        e.evaluate(&mut ctx, Phase::RequestHeaders, 0);
        e.evaluate(&mut ctx, Phase::RequestBody, 0);
        ctx.anomaly_score >= 10
    };
    for (dir, attack) in [("hard-benign", false), ("evasion-corpus", true)] {
        let (mut total, mut ob, mut nb) = (0, 0, 0);
        for (name, lines) in corpus(dir) {
            for l in &lines {
                let (o, n) = (blocked(&old, l), blocked(&new, l));
                total += 1;
                ob += o as usize;
                nb += n as usize;
                if o != n {
                    println!(
                        "{} {name}: {:?}",
                        if o { "UNBLOCKED" } else { "NEWLY-BLOCKED" },
                        l.chars().take(140).collect::<String>()
                    );
                }
            }
        }
        println!(
            "== {dir}: blocked old {ob} / new {nb} of {total} ({})",
            if attack {
                "detection"
            } else {
                "false positives"
            }
        );
    }
    for text in REPORTED_FPS {
        println!(
            "reported FP {:?}: old blocked {}, new blocked {}",
            text,
            blocked(&old, text),
            blocked(&new, text)
        );
    }
}
