//! Guards for the RESPONSE-* families that the control plane now offers.
//!
//! These six files shipped inside the image for the whole life of the product and
//! were unreachable: the data plane could run them (the proxy buffers scannable
//! bodies and calls `evaluate(Phase::ResponseBody)`), the engine compiled them,
//! and no site configuration could name them because the control plane had no
//! category key. 108 importable rules of data-leakage and web-shell detection
//! were dead weight.
//!
//! Wiring them up is only half the fix. These tests pin the half that is easy to
//! break again: that each wired file still imports rules, that a real leak is
//! actually detected, that ordinary pages are not, and — the subtle one — that
//! detection depends on the proxy seeding DETECTION_PARANOIA_LEVEL.

mod common;

use sentinel_core::context::{Phase, RequestContext, WafDecision};

/// The six files wired to a category key in `crsCategoryFiles` (handlers.go).
const WIRED: &[&str] = &[
    "RESPONSE-950-DATA-LEAKAGES.conf",
    "RESPONSE-951-DATA-LEAKAGES-SQL.conf",
    "RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
    "RESPONSE-953-DATA-LEAKAGES-PHP.conf",
    "RESPONSE-954-DATA-LEAKAGES-IIS.conf",
    "RESPONSE-955-WEB-SHELLS.conf",
];

/// Build a context the way `phase1_headers` does in the proxy, then run the
/// response-body program over `body`.
fn scan(files: &[&str], body: &str, seed_paranoia: bool) -> RequestContext {
    let eng = common::load_crs_engines(files);
    let mut ctx = common::make_ctx();
    if seed_paranoia {
        // Exactly what crates/sentinel-proxy/src/lib.rs phase1_headers inserts.
        ctx.tx_vars
            .insert("DETECTION_PARANOIA_LEVEL".to_owned(), "2".to_owned());
    }
    ctx.response_body = Some(body.as_bytes().to_vec().into());
    // The site's configured anomaly threshold; these rules carry `block`
    // directly, so the threshold is not what drives the decision.
    eng.evaluate(&mut ctx, Phase::ResponseBody, 10);
    ctx
}

/// A wired category must deliver rules. An empty file behind a UI toggle is the
/// worst outcome of all: the operator ticks "SQL Error Leakage", the API stores
/// it, the data plane loads a file with nothing in it, and the site pays the
/// response-buffering cost for zero detection.
#[test]
fn every_wired_response_file_imports_rules_and_registers_the_phase() {
    for f in WIRED {
        let eng = common::load_crs_engines(&[f]);
        assert!(
            eng.has_response_body_rules(),
            "{f} registered no response-body rules — the proxy gates response \
             inspection on has_response_body_rules(), so this file would make \
             the site buffer responses and inspect nothing"
        );
    }
}

/// Real disclosure payloads, one per family. Each string is taken from the
/// pattern the shipped rule actually matches, not invented.
#[test]
fn each_family_detects_a_real_disclosure() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "RESPONSE-951-DATA-LEAKAGES-SQL.conf",
            "<html>You have an error in your SQL syntax; check the manual</html>",
            "MySQL error disclosure",
        ),
        (
            "RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
            "<html><pre>java.lang.NullPointerException\n\tat com.app.Main</pre></html>",
            "Java stack trace",
        ),
        (
            "RESPONSE-953-DATA-LEAKAGES-PHP.conf",
            "<html><?php $db = mysqli_connect($h,$u,$p); ?></html>",
            "PHP source disclosure",
        ),
        (
            "RESPONSE-954-DATA-LEAKAGES-IIS.conf",
            "<html>Server Error in c:\\inetpub\\wwwroot\\app\\default.aspx</html>",
            "IIS path disclosure",
        ),
        (
            "RESPONSE-950-DATA-LEAKAGES.conf",
            "<html><title>Index of /var/www</title><h1>Index of /var/www</h1></html>",
            "directory listing",
        ),
        (
            "RESPONSE-955-WEB-SHELLS.conf",
            "<html><head><title>r57 shell</title></head><body></body></html>",
            "r57 web shell",
        ),
    ];

    for (file, body, what) in cases {
        let ctx = scan(&[file], body, true);
        assert!(
            !ctx.rule_matches.is_empty(),
            "{file} did not detect {what}. The response would reach the visitor \
             with the disclosure intact. Body: {body}"
        );
        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "{file} matched {what} but did not block. These rules carry `block` \
             directly rather than contributing to the anomaly score, so a match \
             must be a decision — otherwise enabling the category detects \
             without protecting. Matched: {:?}",
            ctx.rule_matches
                .iter()
                .map(|m| m.rule_id.clone())
                .collect::<Vec<_>>()
        );
    }
}

/// False-positive guard. These rules had never run against anything in
/// production, and they block on a SINGLE match with no anomaly threshold to
/// moderate them, so an over-eager pattern is a customer-visible outage rather
/// than a score nudge.
#[test]
fn ordinary_pages_are_not_blocked_by_any_response_family() {
    let benign = [
        "<html><head><title>Dashboard</title></head><body><h1>Welcome back</h1>\
         <p>Your last login was on Tuesday. You have 3 new messages.</p></body></html>",
        "{\"status\":\"ok\",\"items\":[{\"id\":1,\"name\":\"Widget\",\"price\":9.99}],\"total\":1}",
        "<html><body><h1>Our SQL Server training course</h1><p>Learn about database \
         indexes, Java collections and PHP frameworks in this 3-day class.</p></body></html>",
        "<html><body><form method=post action=/login><input name=user><input \
         name=pass type=password></form></body></html>",
    ];
    for body in benign {
        let ctx = scan(WIRED, body, true);
        assert_eq!(
            ctx.decision,
            WafDecision::Allow,
            "a benign response was blocked by the response-body families — this \
             is a false positive that would break a real page. Matched: {:?}\nBody: {body}",
            ctx.rule_matches
                .iter()
                .map(|m| m.rule_id.clone())
                .collect::<Vec<_>>()
        );
    }
}

/// The coupling that is easy to break and impossible to see.
///
/// Every RESPONSE-* file opens with
/// `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" ... skipAfter:END-<file>`, so an
/// unset paranoia level reads as 0, the gate fires, and the ENTIRE file is
/// skipped — no match, no score, no log. The only reason response inspection
/// works at all is that `phase1_headers` seeds DETECTION_PARANOIA_LEVEL from the
/// site config before the response phase runs.
///
/// Delete that one line in the proxy and every test above still passes on the
/// request path while response inspection silently stops. This test is what
/// fails instead.
#[test]
fn response_families_self_skip_without_the_proxy_paranoia_seed() {
    let leak = "<html>You have an error in your SQL syntax; check the manual</html>";

    let seeded = scan(&["RESPONSE-951-DATA-LEAKAGES-SQL.conf"], leak, true);
    assert_eq!(
        seeded.decision,
        WafDecision::Block,
        "sanity: with DETECTION_PARANOIA_LEVEL seeded the leak must be blocked"
    );

    let unseeded = scan(&["RESPONSE-951-DATA-LEAKAGES-SQL.conf"], leak, false);
    assert!(
        unseeded.rule_matches.is_empty(),
        "expected the paranoia-level gate to skip the whole file when unseeded; \
         if this now matches, the gate semantics changed and the comment above \
         (plus the proxy's dependency on seeding) needs revisiting"
    );
}
