//! Tests for `multipart/form-data` parsing and the FILES* target collections.
//!
//! Two capabilities are exercised:
//!   1. Non-file form fields in a multipart body feed ARGS, so injection
//!      delivered via a multipart form is detected exactly like a urlencoded
//!      form (previously multipart bodies were not parsed at all → bypass).
//!   2. The FILES / FILES_NAMES / FILES_COMBINED_SIZE collections expose
//!      uploaded-file metadata to rules (malicious-filename detection, etc.).

mod common;

use common::*;
use sentinel_core::context::{Phase, RequestContext, WafDecision};
use sentinel_rules::RuleEngine;

const BOUNDARY: &str = "----SentinelTestBoundary7MA4YWxkTrZu0gW";

/// Build a POST context whose body is `multipart/form-data` with the given
/// raw body and boundary.  `quote_boundary` controls whether the Content-Type
/// boundary parameter is quoted (both forms are RFC-legal).
fn multipart_ctx(uri: &str, body: &str, quote_boundary: bool) -> RequestContext {
    // Reuse make_post_ctx for baseline headers + CRS setup, then override the
    // body and Content-Type for multipart.
    let mut ctx = make_post_ctx(uri, body);
    let ct = if quote_boundary {
        format!("multipart/form-data; boundary=\"{BOUNDARY}\"")
    } else {
        format!("multipart/form-data; boundary={BOUNDARY}")
    };
    ctx.request_headers
        .insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
    ctx.request_body = Some(bytes::Bytes::from(body.to_string()));
    ctx
}

/// Assemble a multipart body from `(headers, content)` part tuples.  Each
/// `headers` string is the part's header block (without the trailing blank
/// line); `content` is the part body.  Uses CRLF line endings as required by
/// RFC 7578.
fn build_body(parts: &[(&str, &str)]) -> String {
    let mut s = String::new();
    for (headers, content) in parts {
        s.push_str(&format!("--{BOUNDARY}\r\n"));
        s.push_str(headers);
        s.push_str("\r\n\r\n");
        s.push_str(content);
        s.push_str("\r\n");
    }
    s.push_str(&format!("--{BOUNDARY}--\r\n"));
    s
}

// ---------------------------------------------------------------------------
// 1. Multipart form fields → ARGS (injection detection parity with urlencoded)
// ---------------------------------------------------------------------------

#[test]
fn sqli_in_multipart_field_is_detected() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let body = build_body(&[
        ("Content-Disposition: form-data; name=\"username\"", "admin"),
        (
            "Content-Disposition: form-data; name=\"password\"",
            "x' OR 1=1-- -",
        ),
    ]);
    let mut ctx = multipart_ctx("/login", &body, false);
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "SQLi in a multipart form field should trigger SQLi rules",
    );
}

#[test]
fn xss_in_multipart_field_is_detected() {
    let eng = load_crs_engine("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"comment\"",
        "<script>alert(1)</script>",
    )]);
    let mut ctx = multipart_ctx("/comments", &body, false);
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "XSS in a multipart form field should trigger XSS rules",
    );
}

#[test]
fn clean_multipart_form_passes() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let body = build_body(&[
        ("Content-Disposition: form-data; name=\"username\"", "alice"),
        (
            "Content-Disposition: form-data; name=\"bio\"",
            "I enjoy long walks and good coffee.",
        ),
    ]);
    let mut ctx = multipart_ctx("/profile", &body, false);
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_clean(
        &ctx,
        "a legitimate multipart form must not trigger SQLi rules",
    );
}

#[test]
fn quoted_boundary_is_parsed() {
    let eng = load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"q\"",
        "1 UNION SELECT password FROM users-- -",
    )]);
    // Quoted boundary form: boundary="...."
    let mut ctx = multipart_ctx("/search", &body, true);
    set_paranoia(&mut ctx, 2);
    eval(&eng, &mut ctx, Phase::RequestBody);
    assert_score(
        &ctx,
        5,
        "a quoted boundary parameter must still be parsed and inspected",
    );
}

// ---------------------------------------------------------------------------
// 2. FILES* collections (custom rules for precise extraction assertions)
// ---------------------------------------------------------------------------

/// Compile a single SecRule against a phase-2 (request body) target.
fn rule_engine(conf: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf_dir(conf, None).expect("import rule");
    let ruleset = sentinel_rules::compile(file).expect("compile rule");
    RuleEngine::new(ruleset)
}

#[test]
fn malicious_filename_matches_files_target() {
    // Rule fires when an uploaded file's name ends in .php (FILES = filenames).
    let eng = rule_engine(
        r#"SecRule FILES "@rx \.php$" "id:9200,phase:2,block,msg:'php upload blocked'""#,
    );
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"upload\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream",
        "<?php system($_GET[0]); ?>",
    )]);
    let mut ctx = multipart_ctx("/upload", &body, false);
    let decision = eng.evaluate(&mut ctx, Phase::RequestBody, 0);
    assert_eq!(
        decision,
        WafDecision::Block,
        "an uploaded file named shell.php must match a FILES rule"
    );
}

#[test]
fn field_name_matches_files_names_target() {
    // FILES_NAMES = the form field name of the file-upload part.
    let eng = rule_engine(
        r#"SecRule FILES_NAMES "@rx ^evilfield$" "id:9201,phase:2,block,msg:'bad file field'""#,
    );
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"evilfield\"; filename=\"ok.txt\"",
        "hello",
    )]);
    let mut ctx = multipart_ctx("/upload", &body, false);
    let decision = eng.evaluate(&mut ctx, Phase::RequestBody, 0);
    assert_eq!(
        decision,
        WafDecision::Block,
        "FILES_NAMES must expose the file part's form-field name"
    );
}

#[test]
fn combined_size_reflects_file_content_bytes() {
    // FILES_COMBINED_SIZE is the total byte count of all file contents.
    // Two files of 5 and 7 bytes → 12 bytes total → @ge 10 fires.
    let eng = rule_engine(
        r#"SecRule FILES_COMBINED_SIZE "@ge 10" "id:9202,phase:2,block,msg:'upload too large'""#,
    );
    let body = build_body(&[
        (
            "Content-Disposition: form-data; name=\"a\"; filename=\"a.bin\"",
            "12345",
        ),
        (
            "Content-Disposition: form-data; name=\"b\"; filename=\"b.bin\"",
            "1234567",
        ),
    ]);
    let mut ctx = multipart_ctx("/upload", &body, false);
    let decision = eng.evaluate(&mut ctx, Phase::RequestBody, 0);
    assert_eq!(
        decision,
        WafDecision::Block,
        "FILES_COMBINED_SIZE must sum the byte sizes of all uploaded files"
    );
}

#[test]
fn small_upload_under_size_limit_passes() {
    let eng = rule_engine(
        r#"SecRule FILES_COMBINED_SIZE "@ge 1000" "id:9203,phase:2,block,msg:'upload too large'""#,
    );
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"a\"; filename=\"a.bin\"",
        "tiny",
    )]);
    let mut ctx = multipart_ctx("/upload", &body, false);
    let decision = eng.evaluate(&mut ctx, Phase::RequestBody, 0);
    assert_eq!(
        decision,
        WafDecision::Allow,
        "an upload below the size threshold must pass"
    );
}

#[test]
fn file_content_does_not_leak_into_args() {
    // A custom rule that ONLY inspects ARGS. The SQLi-looking bytes live inside
    // the *file content*, not a form field, so they must NOT reach ARGS (file
    // bodies are surfaced via FILES*/REQUEST_BODY, never ARGS).
    let eng = rule_engine(
        r#"SecRule ARGS "@rx (?i)union\s+select" "id:9204,phase:2,block,msg:'sqli in args'""#,
    );
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"doc\"; filename=\"notes.txt\"\r\nContent-Type: text/plain",
        "UNION SELECT secret FROM users",
    )]);
    let mut ctx = multipart_ctx("/upload", &body, false);
    let decision = eng.evaluate(&mut ctx, Phase::RequestBody, 0);
    assert_eq!(
        decision,
        WafDecision::Allow,
        "file content must not be exposed through the ARGS collection"
    );
}

#[test]
fn form_field_alongside_file_still_feeds_args() {
    // Mixed body: a malicious regular field plus a benign file. The field must
    // still reach ARGS even though a file part is present.
    let eng = rule_engine(
        r#"SecRule ARGS "@rx (?i)union\s+select" "id:9205,phase:2,block,msg:'sqli in args'""#,
    );
    let body = build_body(&[
        (
            "Content-Disposition: form-data; name=\"q\"",
            "1 UNION SELECT password FROM users",
        ),
        (
            "Content-Disposition: form-data; name=\"doc\"; filename=\"notes.txt\"",
            "harmless attachment body",
        ),
    ]);
    let mut ctx = multipart_ctx("/upload", &body, false);
    let decision = eng.evaluate(&mut ctx, Phase::RequestBody, 0);
    assert_eq!(
        decision,
        WafDecision::Block,
        "a malicious form field must feed ARGS even when a file part is present"
    );
}
