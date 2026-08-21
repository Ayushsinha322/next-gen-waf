//! Guards for `%{...}` interpolation in OPERATOR patterns.
//!
//! Before this existed, any operator whose pattern held a macro compiled to
//! `Operator::Never` — 20 reachable CRS rules silently disabled, including the
//! session-fixation off-domain-referer check and the SQL tautology check.
//!
//! The reason it stayed unimplemented for so long is that the naive version is
//! dangerous. CRS has rules of the form
//!
//!     SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}"
//!
//! and the policy list is normally seeded by `REQUEST-901-INITIALIZATION`, which
//! this product deliberately does not load (it would clobber the site's tuned
//! anomaly threshold and paranoia level). Expand an unset list to `""` and every
//! method is "not within" it — the rule becomes deny-all. The same shape appears
//! for allowed content types, allowed HTTP versions, and every `@gt %{tx.max_*}`
//! limit, where a non-numeric bound read as 0 would fire on any request at all.
//!
//! So the contract these tests pin is: **an unresolvable macro yields `Absent`,
//! never `false`**, because `Not(Absent)` is `false` while `Not(false)` is `true`.
//! Absent is the only value that cannot be flipped into a block.

mod common;

use common::*;
use sentinel_core::context::{Phase, RequestContext, WafDecision};

/// (rule file, uri, request headers, human label) for the table-driven cases.
type Case<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], &'a str);

fn eval(files: &[&str], ctx: &mut RequestContext) {
    let eng = load_crs_engines(files);
    eng.evaluate(ctx, Phase::RequestHeaders, 10);
    eng.evaluate(ctx, Phase::RequestBody, 10);
}

fn ctx_for(
    uri: &str,
    method: &str,
    hdrs: &[(&str, &str)],
    seed: &[(&str, &str)],
) -> RequestContext {
    let mut ctx = make_get_ctx(uri);
    ctx.method = method.parse().expect("method");
    ctx.tx_vars
        .insert("DETECTION_PARANOIA_LEVEL".to_string(), "2".to_string());
    for (k, v) in hdrs {
        ctx.request_headers.insert(
            http::header::HeaderName::from_bytes(k.as_bytes()).expect("header name"),
            v.parse().expect("header value"),
        );
    }
    for (k, v) in seed {
        ctx.tx_vars.insert(k.to_string(), v.to_string());
    }
    ctx
}

fn ids(ctx: &RequestContext) -> Vec<String> {
    ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect()
}

// ---------------------------------------------------------------------------
// The safety property: unresolved macros can never deny
// ---------------------------------------------------------------------------

/// `!@within %{tx.allowed_methods}` with the list unset must NOT reject traffic.
///
/// This is the deny-all case. 901 seeds `tx.allowed_methods` and we do not load
/// 901, so the unset state is the NORMAL state for this product — not an edge
/// case. If this test fails, every request of every method is being blocked.
#[test]
fn unset_method_allowlist_does_not_block_anything() {
    for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
        let mut ctx = ctx_for("/", method, &[("host", "app.example.com")], &[]);
        eval(&["REQUEST-911-METHOD-ENFORCEMENT.conf"], &mut ctx);
        assert_eq!(
            ctx.decision,
            WafDecision::Allow,
            "{method} was blocked with tx.allowed_methods UNSET. An unresolved \
             macro must yield Absent, not an empty allow-list — otherwise \
             `!@within` denies every method. Fired {:?}",
            ids(&ctx)
        );
        assert_eq!(ctx.anomaly_score, 0, "{method} should not even score");
    }
}

/// `@gt %{tx.max_num_args}` with the bound unset must not fire. An undecidable
/// numeric bound read as 0 would make "more than zero arguments" true for almost
/// every real request.
#[test]
fn unset_numeric_bound_does_not_fire() {
    let mut ctx = ctx_for(
        "/search?q=shoes&page=2&sort=price",
        "GET",
        &[("host", "app.example.com")],
        &[],
    );
    eval(&["REQUEST-920-PROTOCOL-ENFORCEMENT.conf"], &mut ctx);
    assert_eq!(
        ctx.decision,
        WafDecision::Allow,
        "a 3-argument request was blocked with tx.max_num_args UNSET; a \
         non-numeric bound must be undecidable, not zero. Fired {:?}",
        ids(&ctx)
    );
}

/// And the other half — once the operator DOES supply a policy, it is enforced.
/// Without this, the test above could pass simply because interpolation never
/// works at all.
#[test]
fn seeded_policy_lists_are_actually_enforced() {
    let allow = &[("ALLOWED_METHODS", "GET HEAD POST OPTIONS")];

    let mut ok = ctx_for("/", "GET", &[("host", "app.example.com")], allow);
    eval(&["REQUEST-911-METHOD-ENFORCEMENT.conf"], &mut ok);
    assert!(
        ids(&ok).is_empty(),
        "GET is on the allow-list and must not fire; got {:?}",
        ids(&ok)
    );

    let mut bad = ctx_for("/", "DELETE", &[("host", "app.example.com")], allow);
    eval(&["REQUEST-911-METHOD-ENFORCEMENT.conf"], &mut bad);
    assert!(
        ids(&bad).contains(&"911100".to_string()),
        "DELETE is not on the allow-list and must fire 911100; got {:?}",
        ids(&bad)
    );
}

// ---------------------------------------------------------------------------
// The value: rules that resolve from request data, needing no policy seeding
// ---------------------------------------------------------------------------

/// 943110 — a session-ID parameter combined with an OFF-domain `Referer`. Needs
/// regex capture *and* `%{request_headers.host}`, so it was disabled twice over.
#[test]
fn session_fixation_off_domain_referer_is_detected() {
    let mut ctx = ctx_for(
        "/?jsessionid=abc123",
        "GET",
        &[
            ("host", "shop.example.com"),
            ("referer", "http://evil.example.net/landing"),
        ],
        &[],
    );
    eval(
        &["REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"],
        &mut ctx,
    );
    assert!(
        ids(&ctx).contains(&"943110".to_string()),
        "an off-domain referer carrying a session id must be detected; got {:?}",
        ids(&ctx)
    );
}

/// The same rule must stay quiet for the site's own host — the check compares
/// against `%{request_headers.host}`, so getting this wrong flags normal
/// navigation.
#[test]
fn session_fixation_same_domain_referer_is_clean() {
    for (host, referer, what) in [
        (
            "shop.example.com",
            "https://shop.example.com/cart",
            "same host",
        ),
        (
            "shop.example.com",
            "https://cdn.shop.example.com/",
            "own subdomain",
        ),
    ] {
        let mut ctx = ctx_for(
            "/?jsessionid=abc123",
            "GET",
            &[("host", host), ("referer", referer)],
            &[],
        );
        eval(
            &["REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"],
            &mut ctx,
        );
        assert!(
            !ids(&ctx).contains(&"943110".to_string()),
            "{what}: own-domain referer must not trip 943110; got {:?}",
            ids(&ctx)
        );
    }
}

/// 942130 — a SQL tautology where two captured sides are equal (`1=1`,
/// `'a'='a'`). Needs capture plus `@streq %{TX.2}`.
#[test]
fn sql_tautology_is_detected_and_blocks_with_corroboration() {
    for uri in ["/?id=1%20or%201%3D1", "/?id=x%27%20or%20%27a%27%3D%27a"] {
        let mut ctx = ctx_for(uri, "GET", &[("host", "app.example.com")], &[]);
        eval(&["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"], &mut ctx);
        assert!(
            ids(&ctx).contains(&"942130".to_string()),
            "{uri}: tautology must be detected; got {:?}",
            ids(&ctx)
        );
        // 942100 (libinjection) corroborates, so the pair crosses the threshold.
        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "{uri}: a real tautology with a corroborating signal must block; \
             score {} from {:?}",
            ctx.anomaly_score,
            ids(&ctx)
        );
    }
}

// ---------------------------------------------------------------------------
// Chained rules must SCORE, not hard-block
// ---------------------------------------------------------------------------

/// CRS puts `block` on a chain starter and the score `setvar` on an inner link.
/// Reading only the starter made these compile to a hard block that no site
/// threshold could moderate, and interpolation made two of them reachable.
///
/// Measured before the fix: 943110 blocked any visitor arriving from a Google
/// search, and 942130 blocked query strings as ordinary as `filter=status=status`.
/// These are anomaly-scoring rules in CRS; neither should block alone.
#[test]
fn benign_traffic_that_trips_a_chained_rule_scores_but_passes() {
    let cases: &[Case] = &[
        (
            "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
            "/?session_id=u123",
            &[
                ("host", "www.example.com"),
                ("referer", "https://www.google.com/"),
            ],
            "visitor arriving from a Google search",
        ),
        (
            "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
            "/?session_id=u123",
            &[
                ("host", "www.example.com"),
                ("referer", "https://example.com/"),
            ],
            "apex domain linking to www",
        ),
        (
            "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "/?filter=status%3Dstatus",
            &[("host", "app.example.com")],
            "filter=status=status",
        ),
        (
            "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "/?redirect=%2Fhome%3Ftab%3Dtab",
            &[("host", "app.example.com")],
            "redirect containing tab=tab",
        ),
    ];
    for (file, uri, hdrs, what) in cases {
        let mut ctx = ctx_for(uri, "GET", hdrs, &[]);
        eval(&[file], &mut ctx);
        assert_eq!(
            ctx.decision,
            WafDecision::Allow,
            "{what} must NOT be blocked by a single chained rule — it should \
             score and let the threshold decide. Fired {:?} at score {}",
            ids(&ctx),
            ctx.anomaly_score
        );
    }
}
