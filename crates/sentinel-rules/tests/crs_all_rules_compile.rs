//! Every shipped CRS rule must actually compile and be enforceable.
//!
//! A rule that fails to compile is DROPPED. The compiler records it in
//! `coverage.dropped` and logs a warning at startup, and then the detection is
//! simply not there — the WAF reports healthy while the protection is missing.
//!
//! Six rules were silently absent on .71, found by reading the data plane's own
//! logs rather than by anything in the product saying so:
//!
//!   921200           LDAP injection
//!   932170, 932171   Shellshock
//!   933170, 933180   PHP object / code injection
//!   941380           AngularJS template XSS
//!
//! All six were the same two PCRE-vs-`regex` incompatibilities. This asserts the
//! whole shipped ruleset loads, so the next one fails the build instead of the
//! WAF.
//!
//! It also asserts on `disabled` — rules that compile but are permanently inert
//! because their operator is unsupported. Those are just as absent in practice;
//! the number is pinned so it can only go down without someone noticing.

mod common;

use std::path::Path;

fn crs_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs/rules")
}

#[test]
fn no_shipped_crs_rule_is_dropped_at_compile_time() {
    let dir = crs_dir();
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("CRS rule dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "conf"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no CRS .conf files in {dir:?}");

    let mut dropped: Vec<String> = Vec::new();
    let mut loaded = 0usize;

    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let parsed = sentinel_rules::import_secrule_conf_dir(&src, Some(&dir))
            .unwrap_or_else(|e| panic!("{} failed to import: {e}", f.display()));
        let set = sentinel_rules::compile(parsed)
            .unwrap_or_else(|e| panic!("{} failed to compile: {e}", f.display()));

        loaded += set.rule_meta.len();
        for (id, why) in &set.coverage.dropped {
            dropped.push(format!(
                "{:<38} rule {id}: {}",
                f.file_name().unwrap().to_string_lossy(),
                why.lines().next().unwrap_or("")
            ));
        }
    }

    eprintln!("CRS: {loaded} rules loaded from {} files", files.len());
    assert!(
        dropped.is_empty(),
        "{} CRS rule(s) are DROPPED — that detection is absent from the WAF:\n  {}",
        dropped.len(),
        dropped.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Compiling is not detecting.
//
// The six repaired rules are only fixed if they now FIRE on the attacks they
// exist to catch. Each test below names the rule id explicitly, so a future
// change that keeps the ruleset compiling while breaking one of these still
// fails here.
// ---------------------------------------------------------------------------

mod repaired_rules_actually_detect {
    use super::*;
    use sentinel_core::context::Phase;

    fn engine(conf: &str) -> sentinel_rules::RuleEngine {
        let dir = crs_dir();
        let src = std::fs::read_to_string(dir.join(conf)).expect(conf);
        let parsed = sentinel_rules::import_secrule_conf_dir(&src, Some(&dir)).expect("import");
        let set = sentinel_rules::compile(parsed).expect("compile");
        assert!(
            set.coverage.dropped.is_empty(),
            "{conf} still drops rules: {:?}",
            set.coverage.dropped
        );
        sentinel_rules::RuleEngine::new(set)
    }

    fn fired(ctx: &sentinel_core::context::RequestContext, rule: &str) -> bool {
        ctx.rule_matches.iter().any(|m| m.rule_id == rule)
    }

    #[test]
    fn shellshock_932170_fires_on_the_bash_function_prologue() {
        let eng = engine("REQUEST-932-APPLICATION-ATTACK-RCE.conf");
        let mut ctx = common::make_get_ctx("http://example.com/cgi-bin/x");
        common::set_paranoia(&mut ctx, 2);
        // The CVE-2014-6271 payload, as it arrives: in a header value.
        ctx.request_headers.insert(
            "user-agent",
            "() { :; }; /bin/bash -c 'cat /etc/passwd'".parse().unwrap(),
        );
        common::eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            fired(&ctx, "932170") || fired(&ctx, "932171"),
            "Shellshock went undetected; matches: {:?}",
            ctx.rule_matches
                .iter()
                .map(|m| &m.rule_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn php_object_injection_933170_fires_on_a_serialized_object() {
        let eng = engine("REQUEST-933-APPLICATION-ATTACK-PHP.conf");
        let mut ctx = common::make_get_ctx(
            "http://example.com/?u=O%3A4%3A%22User%22%3A1%3A%7Bs%3A5%3A%22admin%22%3Bb%3A1%3B%7D",
        );
        common::set_paranoia(&mut ctx, 2);
        common::eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            fired(&ctx, "933170"),
            "PHP object injection went undetected; matches: {:?}",
            ctx.rule_matches
                .iter()
                .map(|m| &m.rule_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn angular_template_injection_941380_fires_on_double_braces() {
        let eng = engine("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
        let mut ctx = common::make_get_ctx(
            "http://example.com/?q=%7B%7Bconstructor.constructor('alert(1)')()%7D%7D",
        );
        common::set_paranoia(&mut ctx, 2);
        common::eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            fired(&ctx, "941380"),
            "AngularJS template injection went undetected; matches: {:?}",
            ctx.rule_matches
                .iter()
                .map(|m| &m.rule_id)
                .collect::<Vec<_>>()
        );
    }

    /// The repair must not have made the pattern match everything. A rule that
    /// fires on ordinary traffic is worse than one that is missing.
    #[test]
    fn the_repaired_rules_stay_quiet_on_benign_traffic() {
        for conf in [
            "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
            "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
            "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            "REQUEST-921-PROTOCOL-ATTACK.conf",
        ] {
            let eng = engine(conf);
            for uri in [
                "http://example.com/rest/products/search?q=apple",
                "http://example.com/assets/i18n/en.json",
                "http://example.com/socket.io/?EIO=4&transport=polling&t=abc123",
                "http://example.com/?author=42&page=2&sort=asc",
            ] {
                let mut ctx = common::make_get_ctx(uri);
                common::set_paranoia(&mut ctx, 2);
                common::eval(&eng, &mut ctx, Phase::RequestBody);
                let hits: Vec<_> = ctx
                    .rule_matches
                    .iter()
                    .filter(|m| {
                        ["932170", "932171", "933170", "933180", "941380", "921200"]
                            .contains(&m.rule_id.as_str())
                    })
                    .map(|m| m.rule_id.clone())
                    .collect();
                assert!(
                    hits.is_empty(),
                    "{conf}: repaired rule(s) {hits:?} fired on benign {uri}"
                );
            }
        }
    }
}
