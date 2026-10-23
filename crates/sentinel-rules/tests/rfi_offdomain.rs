//! Off-domain RFI detection (CRS 931130/931131, run from CRS's own text).
//!
//! Verifies that a URL in a request argument pointing to an *off-domain* host
//! is flagged, while a URL to the request's own domain (or a subdomain) is not
//! — i.e. detection without a false positive on legitimate same-site links.
//!
//! These two rules used to be replaced by a native operator, because the
//! engine could not run their chain (a setvar per matched value, named with
//! MATCHED_VAR_NAME, read back through `TX:/rfi_parameter_.*/`). That operator
//! ended the host at the first `/` and dropped the port, so CRS's own
//! regression cases `http://example.com%2f@evil.com/` and
//! `https://example.com:1234/` passed through. CRS treats everything up to the
//! last `@` as userinfo — the stricter reading, against URL-parser confusion.

mod common;

use common::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use sentinel_core::context::Phase;

/// GET request whose `url` arg carries a percent-encoded raw value, evaluated
/// at PL2 (931130 activates at paranoia level 2). The request Host is
/// `example.com` (set by `make_get_ctx`'s baseline headers).
fn url_arg_ctx(raw: &str) -> sentinel_core::context::RequestContext {
    let enc = utf8_percent_encode(raw, NON_ALPHANUMERIC).to_string();
    let mut ctx = make_get_ctx(&format!("/page?url={enc}"));
    set_paranoia(&mut ctx, 2);
    ctx
}

#[test]
fn off_domain_http_url_is_flagged() {
    let eng = load_crs_engine("REQUEST-931-APPLICATION-ATTACK-RFI.conf");
    let mut ctx = url_arg_ctx("http://evil.example/shell.txt");
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "off-domain http URL in an arg should be flagged as RFI",
    );
}

#[test]
fn off_domain_ftp_and_php_wrappers_flagged() {
    let eng = load_crs_engine("REQUEST-931-APPLICATION-ATTACK-RFI.conf");
    for payload in [
        "ftp://attacker.test/backdoor.php",
        "https://203.0.113.9/c99.php",
        "php://filter/convert.base64-encode/resource=index.php",
    ] {
        let mut ctx = url_arg_ctx(payload);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "off-domain/scheme RFI payload should be flagged");
    }
}

#[test]
fn same_domain_url_is_not_flagged() {
    let eng = load_crs_engine("REQUEST-931-APPLICATION-ATTACK-RFI.conf");
    // Request Host is example.com; a link back to the same site is legitimate.
    let mut ctx = url_arg_ctx("http://example.com/account/profile");
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_clean(&ctx, "a same-domain URL must not be flagged as RFI");
}

#[test]
fn subdomain_url_is_not_flagged() {
    let eng = load_crs_engine("REQUEST-931-APPLICATION-ATTACK-RFI.conf");
    // A subdomain of our own host is on-domain.
    let mut ctx = url_arg_ctx("https://cdn.example.com/assets/app.js");
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_clean(
        &ctx,
        "a subdomain of the request host must not be flagged as RFI",
    );
}

fn fired_931130(ctx: &sentinel_core::context::RequestContext) -> bool {
    ctx.rule_matches.iter().any(|m| m.rule_id == "931130")
}

#[test]
fn cases_the_native_operator_let_through_are_flagged() {
    let eng = load_crs_engine("REQUEST-931-APPLICATION-ATTACK-RFI.conf");
    for payload in [
        // `%2f` decodes to `/` before the rules see it: CRS reads userinfo up
        // to the last `@`, so the host is evil.com.
        "http://example.com/@evil.com/",
        "http://example.com/:foo@bar@evil.com/",
        // Our own host on another port is a different origin to CRS.
        "https://example.com:1234/",
        // No host at all, behind the `url:` prefix.
        "url:file:///etc/passwd",
    ] {
        let mut ctx = url_arg_ctx(payload);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert!(
            fired_931130(&ctx),
            "{payload}: 931130 must fire; fired: {:?}",
            ctx.rule_matches
                .iter()
                .map(|m| &m.rule_id)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_off_domain_parameter_is_checked_not_only_the_first() {
    // One TX variable per matched parameter: the off-domain URL is the SECOND.
    let eng = load_crs_engine("REQUEST-931-APPLICATION-ATTACK-RFI.conf");
    let a = utf8_percent_encode("https://example.com/home", NON_ALPHANUMERIC).to_string();
    let b = utf8_percent_encode("https://evil.example/x", NON_ALPHANUMERIC).to_string();
    let mut ctx = make_get_ctx(&format!("/page?back={a}&next={b}"));
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert!(fired_931130(&ctx), "the second parameter is off-domain");
}
