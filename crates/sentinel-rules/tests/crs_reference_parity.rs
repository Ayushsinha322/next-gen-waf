//! Cases CRS 4.7.0's regression suite expects a rule to match, which the
//! reference engine (ModSecurity v2, the owasp/modsecurity-crs image — see
//! deploy/load-test/crs-regression-reference.sh) matched and this engine did
//! not, each through the shipped rule file. Every miss was a difference in how
//! the engine read the request or the pattern, not in the rule:
//! - `@rx` without PCRE_DOTALL: `.` stopped at a line break;
//! - REQUEST_FILENAME read still URL-encoded;
//! - UTF-8 sequences CRS spells in `\xHH` escapes read as Latin-1 characters.

mod common;

use common::*;
use sentinel_core::context::Phase;

fn fired(
    engine: &sentinel_rules::RuleEngine,
    mut ctx: sentinel_core::context::RequestContext,
    pl: u8,
) -> Vec<String> {
    set_paranoia(&mut ctx, pl);
    eval(engine, &mut ctx, Phase::RequestBody);
    ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect()
}

fn php() -> sentinel_rules::RuleEngine {
    load_crs_engine("REQUEST-933-APPLICATION-ATTACK-PHP.conf")
}

/// 933160 tests 16 and 34: a PHP call whose comment or argument list spans
/// lines. `\(.*\)` and `/\*.*\*/` need `.` to match the line break.
#[test]
fn a_dot_matches_a_line_break_as_in_modsecurity() {
    let engine = php();
    for uri in [
        "/get?foo=exec%09%2f%2afoo%0d%0abar%2a%2f%09%20%28%29",
        "/get?foo=assert_OptionS%20%28%0A%0A%29",
    ] {
        let ids = fired(&engine, make_get_ctx(uri), 1);
        assert!(ids.iter().any(|id| id == "933160"), "{uri}: {ids:?}");
    }
}

/// 933160 tests 18, 21 and 37: the call is in the path, which CRS reads
/// decoded (t:none) — Apache unescapes it before ModSecurity's rules run.
#[test]
fn request_filename_is_read_url_decoded() {
    let engine = php();
    for (method, uri) in [
        ("POST", "/post/subSTR%28%24x%29"),
        (
            "GET",
            "/get/eval%28base64_decode%28%27cGFwYWRhcHVwaSwK%27%29",
        ),
        ("POST", "/post/unPACK%28%24x%29"),
    ] {
        let ctx = if method == "POST" {
            make_post_ctx(uri, "")
        } else {
            make_get_ctx(uri)
        };
        let ids = fired(&engine, ctx, 1);
        assert!(ids.iter().any(|id| id == "933160"), "{uri}: {ids:?}");
    }
}

/// 934120 tests 23–26 and 39: SSRF to an address or host spelled in enclosed
/// alphanumerics or with ideographic full stops — characters CRS's pattern
/// spells as their UTF-8 bytes.
#[test]
fn utf8_sequences_in_a_pattern_match_the_characters_they_encode() {
    let engine = load_crs_engine("REQUEST-934-APPLICATION-ATTACK-GENERIC.conf");
    for q in [
        "acap://①②⑦.⓪.⓪.①",
        "imap://①⑥⑨.②⑤④.①⑥⑨.②⑤④",
        "irc://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
        "pop3://ⓁⓄⒸⒶⓁⒽⓄⓈⓉ",
        "http://169。254。169。254/",
    ] {
        let enc = percent_encoding::utf8_percent_encode(q, percent_encoding::NON_ALPHANUMERIC);
        let ids = fired(&engine, make_get_ctx(&format!("/get?ssrf={enc}")), 2);
        assert!(ids.iter().any(|id| id == "934120"), "{q}: {ids:?}");
    }
    // The ordinary hostname is still not an SSRF target to it.
    let ids = fired(
        &engine,
        make_get_ctx("/get?ssrf=https%3A%2F%2Fexample.com%2F"),
        2,
    );
    assert!(!ids.iter().any(|id| id == "934120"), "{ids:?}");
}

/// 941180 test 7: a path of filename characters only is not read by the XSS
/// rules tagged `xss-perf-disable` — CRS 941010 takes REQUEST_FILENAME off them
/// with `ctl:ruleRemoveTargetByTag`, which the importer dropped, so
/// `/get/javascript-manual/document.cookie` was an XSS attempt to 941180.
#[test]
fn a_ctl_removal_by_tag_takes_the_target_off_every_tagged_rule() {
    let engine = load_crs_engine("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
    let ids = fired(
        &engine,
        make_get_ctx("/get/javascript-manual/document.cookie"),
        1,
    );
    assert!(!ids.iter().any(|id| id == "941180"), "{ids:?}");
    // Only REQUEST_FILENAME, and only while the path holds filename characters.
    let ids = fired(&engine, make_get_ctx("/get?q=document.cookie"), 1);
    assert!(ids.iter().any(|id| id == "941180"), "{ids:?}");
    let ids = fired(&engine, make_get_ctx("/get/x;document.cookie"), 1);
    assert!(ids.iter().any(|id| id == "941180"), "{ids:?}");
}

/// 921180 tests 4 and 6: a parameter sent more than once is parameter
/// pollution at PL3. 921170 counts each name under MATCHED_VAR_NAME, which
/// named a value by its place, so no name was ever counted twice.
#[test]
fn a_repeated_parameter_name_is_counted_as_one_name() {
    let engine = load_crs_engine("REQUEST-921-PROTOCOL-ATTACK.conf");
    for uri in [
        "/?pineapple=pizza&pineapple=aint-pizza",
        "/?pineapple=pizza&pineapple=aint-pizza&pineapple=is-pizza&pineapple=aint-pizza2",
    ] {
        let ids = fired(&engine, make_get_ctx(uri), 3);
        assert!(ids.iter().any(|id| id == "921180"), "{uri}: {ids:?}");
    }
    let ids = fired(&engine, make_get_ctx("/?pineapple=pizza&mango=pizza"), 3);
    assert!(!ids.iter().any(|id| id == "921180"), "{ids:?}");
}

/// 942190 test 42: `t:removeCommentsChar` deletes MySQL's `#` and `--` marks,
/// which leaves `union` and `select` apart only by whitespace.
#[test]
fn remove_comments_char_deletes_what_modsecurity_deletes() {
    let engine = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    for body in [
        "id=@.:=right(right((select+user_login+from+wordpress.wp_users+limit+1,1),1111),1111)+union%23%0adistinctrow%0bselect@.",
        "id=1+union--%0adistinctrow%0bselect+1",
    ] {
        let ids = fired(&engine, make_post_ctx("/get", body), 1);
        assert!(ids.iter().any(|id| id == "942190"), "{body}: {ids:?}");
    }
}
