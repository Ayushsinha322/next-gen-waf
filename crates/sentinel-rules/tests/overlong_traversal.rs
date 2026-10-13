//! 9900219: path traversal written in overlong or malformed UTF-8
//! (`rules/custom/coverage.conf`).
//!
//! On open-appsec's dataset 5,209 of 28,314 traversal attacks passed the tuned
//! defaults, nearly all of them dotdotpwn's overlong forms (`%c0%ae` for `.`,
//! `%c1%af` for `/`, up to six-byte `%fc%80%80%80%80%ae`). In a form body
//! nothing in CRS scored them at paranoia level 1. The attacks below are taken
//! from that dataset; the benign values are what a too-broad pattern would hit:
//! Latin-1 form encoding, where `%C0` is `À` and `%E0` is `à`, and valid
//! multi-byte UTF-8 whose lead byte is the same as an overlong form's.

mod common;

use std::path::Path;

use common::{eval, make_get_ctx, make_post_ctx};
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

fn load_coverage_engine() -> RuleEngine {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join("../../rules/custom/coverage.conf");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let file = sentinel_rules::import_secrule_conf_dir(&source, path.parent())
        .unwrap_or_else(|e| panic!("import {}: {}", path.display(), e));
    let ruleset = sentinel_rules::compile(file)
        .unwrap_or_else(|e| panic!("compile {}: {}", path.display(), e));
    RuleEngine::new(ruleset)
}

fn fired(ctx: &RequestContext) -> bool {
    ctx.rule_matches.iter().any(|m| m.rule_id == "9900219")
}

fn in_query(engine: &RuleEngine, value: &str) -> RequestContext {
    let mut ctx = make_get_ctx(&format!("http://example.com/?p={value}"));
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx
}

fn in_body(engine: &RuleEngine, value: &str) -> RequestContext {
    let mut ctx = make_post_ctx("http://example.com/", &format!("p={value}"));
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx
}

#[test]
fn overlong_utf8_traversal_is_blocked_in_the_query_and_the_body() {
    let engine = load_coverage_engine();
    for attack in [
        "%c0%ae%c0%ae%c0/%c0%ae%c0%ae%c0/etc%c0/issue",
        "..%01%c0%af..%01%c0%af..%01%c0%afetc%c0%afissue",
        "%e0%80%ae%e0%80%ae%c1%af%e0%80%ae%e0%80%ae%c1%afetc%c1%afpasswd",
        "%f8%80%80%80%ae%f8%80%80%80%ae0x5cetc0x5cissue",
        "%fc%80%80%80%80%ae%fc%80%80%80%80%ae%c0%5Cboot.ini",
        "%c0%5e%c0%5e%c0%9vetc%c0%9vpasswd",
        "%3F%3F%c1%af%3F%3F%c1%afetc%c1%afpasswd",
        "..%c1%8s..%c1%8s..%c1%8setc%c1%8sissue",
        "%c0%ee%c0%ee%f0%80%80%afwindows%f0%80%80%afsystem32",
        // One unit directly before a well-known target.
        "%3F.%c0/boot.ini",
        "%3F.%e0%80%afboot.ini",
        // Double-encoded.
        "%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd",
    ] {
        for (place, ctx) in [
            ("query", in_query(&engine, attack)),
            ("body", in_body(&engine, attack)),
        ] {
            assert!(fired(&ctx), "{place}: 9900219 missed {attack}");
            assert!(
                ctx.anomaly_score >= 10,
                "{place}: {attack} scored {}, under the block threshold",
                ctx.anomaly_score
            );
        }
    }
}

#[test]
fn latin1_text_and_valid_multibyte_utf8_do_not_fire() {
    let engine = load_coverage_engine();
    for benign in [
        // Latin-1 form encoding: À, à, é, ®.
        "%C0+la+carte%2C+%E0+volont%E9",
        "%C0%E9t%E9+%C0+Paris",
        "Marque%AE+%C0+%E0",
        // Valid UTF-8 whose lead byte matches an overlong form's: ह (E0 A4 B9),
        // 中 (E4 B8 AD), 😀 (F0 9F 98 80), and ü/à (C3).
        "%E0%A4%B9%E0%A4%BF%E0%A4%A8%E0%A5%8D%E0%A4%A6%E0%A5%80",
        "%E4%B8%AD%E6%96%87",
        "%F0%9F%98%80%F0%9F%98%80",
        "M%C3%BCller+%C3%A0+la+gare",
        // A relative path and a hex-looking word.
        "../assets/logo.png",
        "c0ffee-c1af-e080",
    ] {
        for (place, ctx) in [
            ("query", in_query(&engine, benign)),
            ("body", in_body(&engine, benign)),
        ] {
            assert!(!fired(&ctx), "{place}: 9900219 fired on {benign}");
        }
    }
}
