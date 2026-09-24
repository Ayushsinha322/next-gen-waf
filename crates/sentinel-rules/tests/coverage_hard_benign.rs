//! Offline FP measurement for the coverage signatures over the local hard-benign
//! corpora (~/waf-ml-corpora/hard-benign). Run manually:
//!   cargo test -p sentinel-rules --test coverage_hard_benign -- --ignored --nocapture
mod common;
use common::make_get_ctx;
use sentinel_core::context::Phase;
use std::path::Path;

#[test]
#[ignore]
fn coverage_signatures_over_hard_benign() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/custom/coverage.conf");
    let src = std::fs::read_to_string(&path).unwrap();
    let file = sentinel_rules::import_secrule_conf_dir(&src, path.parent()).unwrap();
    let engine = sentinel_rules::RuleEngine::new(sentinel_rules::compile(file).unwrap());
    let dir = format!(
        "{}/waf-ml-corpora/hard-benign",
        std::env::var("HOME").unwrap()
    );
    let (mut n, mut hit) = (0usize, 0usize);
    let mut by_file = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("txt") {
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let (mut fn_, mut fh) = (0, 0);
        let mut examples = Vec::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .take(400)
        {
            let q: String =
                percent_encoding::utf8_percent_encode(line, percent_encoding::NON_ALPHANUMERIC)
                    .to_string();
            let mut ctx = make_get_ctx(&format!("/search?q={q}"));
            engine.evaluate(&mut ctx, Phase::RequestHeaders, 0);
            engine.evaluate(&mut ctx, Phase::RequestBody, 0);
            fn_ += 1;
            if !ctx.rule_matches.is_empty() {
                fh += 1;
                if examples.len() < 2 {
                    examples.push(format!(
                        "{} <- {:?}",
                        ctx.rule_matches[0].rule_id,
                        &line.chars().take(70).collect::<String>()
                    ));
                }
            }
        }
        n += fn_;
        hit += fh;
        by_file.push(format!(
            "{:<34} {:>4}/{:<4} {}",
            p.file_name().unwrap().to_string_lossy(),
            fh,
            fn_,
            examples.join(" | ")
        ));
    }
    by_file.sort();
    for l in &by_file {
        println!("{l}");
    }
    println!(
        "TOTAL coverage matches on hard-benign: {hit}/{n} = {:.2}%",
        100.0 * hit as f64 / n.max(1) as f64
    );
}
