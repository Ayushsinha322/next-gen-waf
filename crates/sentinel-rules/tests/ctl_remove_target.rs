//! `ctl:ruleRemoveTargetById` takes effect for the rest of the request, and
//! only when the rule carrying it fires.
//!
//! CRS 942440 (SQL comment sequences, PL2) matches the `--` that Facebook and
//! Google click identifiers routinely contain, so every visitor arriving from
//! an ad carried a SQL-injection score. CRS answers that with 942441/942442:
//! when `fbclid`/`gclid` is shaped like a click identifier, 942440 stops
//! inspecting that one argument. Two things kept it from working here, and
//! each is pinned below:
//!
//!   * the action was ignored, so the false positive stayed;
//!   * the selector `ARGS_GET:fbclid` was widened to every query argument, so
//!     any long identifier-shaped value ANYWHERE would have lifted 942440 off
//!     `fbclid` — a bypass for a SQL comment placed in `fbclid` itself.
//!
//! Lifting the rule off the argument unconditionally would be the same bypass,
//! which is why the click-shaped cases are paired with attacks.

mod common;

use common::*;
use sentinel_core::context::{Phase, RequestContext};

/// The click identifiers CRS's own 942440 regression tests use.
const FBCLID: &str = "IwAR1dug0BYxe0ukhZ2vKrdQwLAxVFRJ--Q2Y7OBJE_0uId9-Eh-sJWLdVk2E";
const GCLID: &str =
    "j0KCQiA1NebBhDDARIsAANiDD3_RJeMv8zScF--mC1jf8fO8PDYJCxD9xdwT7iQ59QIIwL-86ncQtMaAh0lEALw_wcB";

fn fired_942440(query: &str) -> (bool, Vec<String>) {
    let eng = load_crs_engines(&["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]);
    let mut ctx: RequestContext = make_get_ctx(&format!("/landing?{query}"));
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    let ids: Vec<String> = ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect();
    (ids.iter().any(|r| r == "942440"), ids)
}

#[test]
fn a_click_identifier_is_not_a_sql_comment() {
    for query in [format!("fbclid={FBCLID}"), format!("gclid={GCLID}")] {
        let (hit, ids) = fired_942440(&query);
        assert!(
            !hit,
            "{query}: 942440 must be lifted off the click id; fired: {ids:?}"
        );
    }
}

#[test]
fn an_attack_beside_a_click_identifier_is_still_seen() {
    let (hit, ids) = fired_942440(&format!("fbclid={FBCLID}&q=1%27--"));
    assert!(hit, "the removal is for fbclid only; fired: {ids:?}");
    let (hit, ids) = fired_942440(&format!("q=1%27--&gclid={GCLID}"));
    assert!(hit, "the removal is for gclid only; fired: {ids:?}");
}

#[test]
fn a_sql_comment_in_fbclid_that_is_not_a_click_identifier_is_seen() {
    let (hit, ids) = fired_942440("fbclid=1%27--");
    assert!(
        hit,
        "not click-shaped, so 942441 does not fire; fired: {ids:?}"
    );
}

#[test]
fn an_identifier_shaped_value_elsewhere_does_not_lift_the_rule_off_fbclid() {
    // With ARGS_GET:fbclid widened to every query argument, the long value in
    // `ref` matched 942441's pattern and lifted 942440 off `fbclid` — where the
    // SQL comment is.
    let (hit, ids) = fired_942440(&format!("ref={FBCLID}&fbclid=1%27--"));
    assert!(hit, "942441 must look at fbclid alone; fired: {ids:?}");
}
