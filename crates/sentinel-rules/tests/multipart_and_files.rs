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

// ---------------------------------------------------------------------------
// 3. MULTIPART_PART_HEADERS → REQUEST-922-MULTIPART-ATTACK
// ---------------------------------------------------------------------------
//
// The whole of REQUEST-922 targets `MULTIPART_PART_HEADERS` and nothing else, so
// until that target existed the file imported ZERO of its rules. It shipped in
// the image, compiled, and could not be selected by any site configuration —
// wiring it to a category would have advertised multipart protection that
// detected nothing.
//
// These headers arrive in the BODY, not the request headers, which is why CRS
// runs them in phase 2.

/// Load the real shipped 922 file, plus the paranoia seed the proxy provides.
fn crs_922_ctx(body: &str) -> (RuleEngine, RequestContext) {
    let eng = load_crs_engines(&["REQUEST-922-MULTIPART-ATTACK.conf"]);
    let mut ctx = multipart_ctx("/upload", body, false);
    // phase1_headers seeds this in the proxy; CRS files self-skip without it.
    ctx.tx_vars
        .insert("DETECTION_PARANOIA_LEVEL".to_string(), "2".to_string());
    (eng, ctx)
}

fn eval_922(body: &str) -> RequestContext {
    let (eng, mut ctx) = crs_922_ctx(body);
    eng.evaluate(&mut ctx, Phase::RequestBody, 10);
    ctx
}

fn fired(ctx: &RequestContext) -> Vec<String> {
    ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect()
}

/// The file must actually contribute rules. A category toggle backed by an empty
/// rule file is worse than no toggle: the operator pays the cost and gets nothing.
#[test]
fn crs_922_imports_all_four_rules() {
    let eng = load_crs_engines(&["REQUEST-922-MULTIPART-ATTACK.conf"]);
    assert_eq!(
        eng.rule_count(),
        4,
        "REQUEST-922 declares four rules and all four must import. This file \
         imported ZERO until MULTIPART_PART_HEADERS existed, because every one \
         of its SecRules targets that collection and nothing else."
    );
}

/// Content-Transfer-Encoding was deprecated by RFC 7578 and is a known
/// multipart-parser-confusion vector (922120).
#[test]
fn content_transfer_encoding_in_a_part_is_detected() {
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\
         Content-Type: text/plain\r\n\
         Content-Transfer-Encoding: base64",
        "aGVsbG8=",
    )]);
    let ctx = eval_922(&body);
    assert!(
        fired(&ctx).contains(&"922120".to_string()),
        "Content-Transfer-Encoding must be flagged; fired {:?}",
        fired(&ctx)
    );
}

/// A byte outside \x21-\x7E in a part header name (922130). The payload below
/// uses a BARE LF to smuggle a second header past a parser that only splits on
/// CRLF — which is precisely the confusion this rule detects, so the raw \n must
/// survive parsing rather than being normalised away.
#[test]
fn out_of_range_byte_in_a_part_header_name_is_detected() {
    let body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"f\"\r\nX-A:\nEvil:1\r\n\r\nv\r\n--{BOUNDARY}--\r\n"
    );
    let ctx = eval_922(&body);
    assert!(
        fired(&ctx).contains(&"922130".to_string()),
        "a bare LF smuggling a second part header must be flagged; fired {:?}",
        fired(&ctx)
    );
}

/// 922110 rejects a part Content-Type whose charset is not on the allowed list.
/// This rule is `capture` + a chained condition on `TX:1`, so it is also the
/// regression test for capture groups reaching a chained rule at all.
#[test]
fn disallowed_charset_in_a_part_content_type_is_detected() {
    let body = build_body(&[(
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\
         Content-Type: text/plain; charset=utf-7",
        "x",
    )]);
    let ctx = eval_922(&body);
    assert!(
        fired(&ctx).contains(&"922110".to_string()),
        "charset=utf-7 must be flagged. If this regressed, check that regex \
         capture groups still populate TX:1 — the chained condition reads it, \
         and an empty TX:1 makes the rule silently inert rather than noisy. \
         Fired {:?}",
        fired(&ctx)
    );
}

/// The other half of 922110: a normal charset must not trip it. Without capture
/// working, TX:1 is empty and this test passes for the WRONG reason, which is
/// why the positive case above is asserted alongside it.
#[test]
fn allowed_charset_in_a_part_content_type_is_clean() {
    for charset in ["utf-8", "iso-8859-1", "windows-1252"] {
        let body = build_body(&[(
            &format!(
                "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\
                 Content-Type: text/plain; charset={charset}"
            ),
            "x",
        )]);
        let ctx = eval_922(&body);
        assert_eq!(
            ctx.decision,
            WafDecision::Allow,
            "charset={charset} is on the CRS allowed list and must not be \
             blocked; fired {:?}",
            fired(&ctx)
        );
    }
}

/// False-positive guard. These rules had never executed against anything, and
/// they run on EVERY multipart request — every file upload in the product —
/// so an over-eager match here breaks ordinary uploads.
#[test]
fn ordinary_uploads_and_forms_are_not_flagged_by_922() {
    let cases: Vec<(&str, String)> = vec![
        (
            "plain text upload",
            build_body(&[(
                "Content-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\
                 Content-Type: text/plain",
                "quarterly numbers\r\nline two",
            )]),
        ),
        (
            "image upload beside two form fields",
            build_body(&[
                ("Content-Disposition: form-data; name=\"title\"", "Holiday photo"),
                ("Content-Disposition: form-data; name=\"tags\"", "beach,sunset"),
                (
                    "Content-Disposition: form-data; name=\"img\"; filename=\"p.jpg\"\r\n\
                     Content-Type: image/jpeg",
                    "\u{FFFD}\u{FFFD}\u{FFFD}JFIF binary-ish",
                ),
            ]),
        ),
        (
            "field with no content-type at all",
            build_body(&[("Content-Disposition: form-data; name=\"comment\"", "looks good")]),
        ),
        (
            "filename containing spaces and dots",
            build_body(&[(
                "Content-Disposition: form-data; name=\"f\"; filename=\"my report v2.final.pdf\"\r\n\
                 Content-Type: application/pdf",
                "%PDF-1.7",
            )]),
        ),
    ];
    for (label, body) in cases {
        let ctx = eval_922(&body);
        assert_eq!(
            ctx.decision,
            WafDecision::Allow,
            "{label}: an ordinary multipart request was blocked by the 922 \
             family — this would break real uploads. Fired {:?}",
            fired(&ctx)
        );
        assert_eq!(
            ctx.anomaly_score,
            0,
            "{label}: scored {} against 922 with no attack present; fired {:?}",
            ctx.anomaly_score,
            fired(&ctx)
        );
    }
}
