//! XML / SOAP request-body parsing into ARGS.
//!
//! SOAP and XML APIs are a common injection vector, but the body was previously
//! only parsed for `urlencoded`/`json`/`multipart` content types — an XML body
//! sailed past the ARGS operators untouched. These tests drive the *real* OWASP
//! CRS rulesets against XML bodies to prove payloads inside XML elements,
//! attributes, and CDATA now reach detection.

mod common;

use bytes::Bytes;
use common::*;
use sentinel_core::context::{Phase, RequestContext};

/// Build a POST context whose body is an XML/SOAP document.
fn xml_post_ctx(uri: &str, content_type: &str, body: &str) -> RequestContext {
    let mut ctx = make_post_ctx(uri, body);
    ctx.request_body = Some(Bytes::from(body.to_string()));
    ctx.request_headers
        .insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
    ctx
}

#[test]
fn sqli_in_xml_element_text_is_detected() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut ctx = xml_post_ctx(
        "/api/orders",
        "application/xml",
        r#"<order><query>1 UNION SELECT password FROM users-- -</query></order>"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "SQLi inside an XML element's text should trigger SQLi rules via ARGS",
    );
}

#[test]
fn sqli_in_soap_body_is_detected() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut ctx = xml_post_ctx(
        "/soap/endpoint",
        "application/soap+xml; charset=utf-8",
        r#"<?xml version="1.0"?>
           <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
             <soap:Body>
               <getUser><id>1' OR '1'='1</id></getUser>
             </soap:Body>
           </soap:Envelope>"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "SQLi inside a SOAP body element should trigger SQLi rules",
    );
}

#[test]
fn xss_in_xml_attribute_is_detected() {
    let eng = load_crs_engine("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
    let mut ctx = xml_post_ctx(
        "/api/widgets",
        "text/xml",
        r#"<widget title="&lt;script&gt;alert(document.cookie)&lt;/script&gt;"/>"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "XSS inside an (entity-encoded) XML attribute should trigger XSS rules",
    );
}

#[test]
fn clean_xml_body_passes() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut ctx = xml_post_ctx(
        "/api/orders",
        "application/xml",
        r#"<order><customer>Jane Doe</customer><item qty="2">notebook</item></order>"#,
    );
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_clean(&ctx, "a benign XML order must not raise any anomaly score");
}
