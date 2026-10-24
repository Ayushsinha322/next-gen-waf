//! Per-line decisions of the full request ruleset over the local corpora, for
//! an A/B of two ENGINE versions on the same rules (`coverage_precision`
//! compares two coverage.conf files on the same engine instead).
//!
//! Run in each tree, then diff the two files:
//!   ENGINE_DUMP=/tmp/new.tsv cargo test --release -p sentinel-rules \
//!     --test engine_decision_dump -- --ignored --nocapture
//!
//! One line per (paranoia level, corpus line): `pl corpus file idx score ids`,
//! with the fired rule IDs sorted. `ENGINE_DUMP_BENIGN_MAX` caps how many lines
//! of the 1.3M-line benign corpus are read (default 200000).
//!
//! `ENGINE_DUMP_PLACEMENT` puts each line where it is sent from: `query` (the
//! default, `GET /search?q=`), `xml` (the text of a `<q>` element in a
//! pretty-printed SOAP envelope, POSTed as text/xml) or `json` (`{"q": …}`).

mod common;

use std::io::Write;
use std::path::Path;

use common::*;
use sentinel_core::context::Phase;

fn full_engine() -> sentinel_rules::RuleEngine {
    use sentinel_rules::dsl::ast::RuleFile;
    let crs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules");
    let custom = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/custom");
    let mut names: Vec<_> = std::fs::read_dir(&crs)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        // The request families the control plane loads: not 901 (the product
        // seeds policy itself) and not 949 (blocking is the engine's own).
        .filter(|n| {
            n.starts_with("REQUEST-9")
                && n.ends_with(".conf")
                && !n.contains("-901-")
                && !n.contains("-949-")
        })
        .collect();
    names.sort();
    let mut merged = RuleFile::default();
    for n in names {
        let src = std::fs::read_to_string(crs.join(&n)).unwrap();
        merged.items.extend(
            sentinel_rules::import_secrule_conf_dir(&src, Some(&crs))
                .unwrap()
                .items,
        );
    }
    for n in ["placement.conf", "coverage.conf"] {
        let src = std::fs::read_to_string(custom.join(n)).unwrap();
        merged.items.extend(
            sentinel_rules::import_secrule_conf_dir(&src, Some(&custom))
                .unwrap()
                .items,
        );
    }
    sentinel_rules::RuleEngine::new(sentinel_rules::compile(merged).unwrap())
}

fn corpus(dir: &str, max: usize) -> Vec<(String, Vec<String>)> {
    let root = format!("{}/waf-ml-corpora/{dir}", std::env::var("HOME").unwrap());
    let mut files: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("txt"))
        .collect();
    files.sort();
    let mut left = max;
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            let lines: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(left)
                .map(str::to_owned)
                .collect();
            left -= lines.len();
            (p.file_name().unwrap().to_string_lossy().into_owned(), lines)
        })
        .collect()
}

#[test]
#[ignore]
fn engine_decision_dump() {
    let out = std::env::var("ENGINE_DUMP").expect("ENGINE_DUMP=<output file>");
    let benign_max = std::env::var("ENGINE_DUMP_BENIGN_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let placement = std::env::var("ENGINE_DUMP_PLACEMENT").unwrap_or_else(|_| "query".into());
    let engine = full_engine();
    let mut w = std::io::BufWriter::new(std::fs::File::create(&out).unwrap());
    for (dir, max) in [
        ("evasion-corpus", usize::MAX),
        ("hard-benign", usize::MAX),
        ("benign-corpus", benign_max),
    ] {
        let files = corpus(dir, max);
        for pl in [1u8, 2] {
            for (file, lines) in &files {
                for (i, l) in lines.iter().enumerate() {
                    let mut ctx = request(&placement, l);
                    set_paranoia(&mut ctx, pl);
                    engine.evaluate(&mut ctx, Phase::RequestHeaders, 0);
                    engine.evaluate(&mut ctx, Phase::RequestBody, 0);
                    let mut ids: Vec<_> = ctx
                        .rule_matches
                        .iter()
                        .map(|m| m.rule_id.as_str())
                        .collect();
                    ids.sort_unstable();
                    ids.dedup();
                    writeln!(
                        w,
                        "{pl}\t{dir}\t{file}\t{i}\t{}\t{}",
                        ctx.anomaly_score,
                        ids.join(",")
                    )
                    .unwrap();
                }
            }
        }
    }
    w.flush().unwrap();
    println!("wrote {out}");
}

/// A request carrying `line` the way `placement` names.
fn request(placement: &str, line: &str) -> sentinel_core::context::RequestContext {
    let post = |content_type: &str, body: String| {
        let mut ctx = make_post_ctx("/service", &body);
        ctx.request_headers
            .insert("content-type", content_type.parse().unwrap());
        ctx
    };
    match placement {
        "query" => {
            let q = percent_encoding::utf8_percent_encode(line, percent_encoding::NON_ALPHANUMERIC);
            make_get_ctx(&format!("/search?q={q}"))
        }
        "xml" => {
            let text = line
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            post(
                "text/xml; charset=utf-8",
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                     <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  \
                     <soap:Body>\n    <Search xmlns=\"http://example.com/api\">\n      \
                     <q>{text}</q>\n    </Search>\n  </soap:Body>\n</soap:Envelope>\n"
                ),
            )
        }
        "json" => post(
            "application/json",
            serde_json::json!({ "q": line }).to_string(),
        ),
        other => panic!("ENGINE_DUMP_PLACEMENT={other}: query, xml or json"),
    }
}
