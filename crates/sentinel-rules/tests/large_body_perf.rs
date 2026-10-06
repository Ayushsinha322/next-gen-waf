//! Rule-engine cost on large, benign request bodies.
//!
//! Times `evaluate()` (phase 1 + phase 2, as the proxy runs them) over the full
//! CRS request-side ruleset on benign bodies of 64 KiB, 1 MiB and 8 MiB:
//!   * a JSON object with many fields,
//!   * an `application/x-www-form-urlencoded` form,
//!   * a `multipart/form-data` form.
//!
//! The VM used to re-derive a request view (query parameters, body arguments,
//! multipart parts) and re-run its transform chain for every rule that loaded
//! one, so a body was parsed once per ARGS-family rule rather than once per
//! request. This harness is how that cost is measured. It asserts nothing about
//! time — wall-clock assertions are flaky on shared runners — and only checks
//! that the bodies stay benign.
//!
//! Run manually, in an optimized build:
//!   cargo test -p sentinel-rules --release --test large_body_perf -- --ignored --nocapture

mod common;

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::*;
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

/// Same paranoia level as the accuracy harness (`crs_accuracy.rs`).
const PARANOIA: u8 = 2;

/// Full CRS request-side ruleset, in CRS load order.
const CRS_FILES: &[&str] = &[
    "REQUEST-901-INITIALIZATION.conf",
    "REQUEST-911-METHOD-ENFORCEMENT.conf",
    "REQUEST-913-SCANNER-DETECTION.conf",
    "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    "REQUEST-921-PROTOCOL-ATTACK.conf",
    "REQUEST-922-MULTIPART-ATTACK.conf",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
    "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
];

const SIZES: &[(&str, usize)] = &[("64 KiB", 64 << 10), ("1 MiB", 1 << 20), ("8 MiB", 8 << 20)];

const BOUNDARY: &str = "----PerfBoundary7MA4YWxkTrZu0gW";

/// Plain words only: nothing a CRS rule should score, so the timing measures
/// the inspection of a body rather than the handling of a detection.
fn benign_value(i: usize) -> String {
    format!("the quick brown fox jumps over the lazy dog {i}")
}

fn json_body(target: usize) -> String {
    let mut s = String::with_capacity(target + 128);
    s.push('{');
    let mut i = 0usize;
    while s.len() < target {
        if i > 0 {
            s.push(',');
        }
        write!(s, "\"field_{i:06}\":\"{}\"", benign_value(i)).unwrap();
        i += 1;
    }
    s.push('}');
    s
}

fn form_body(target: usize) -> String {
    let mut s = String::with_capacity(target + 128);
    let mut i = 0usize;
    while s.len() < target {
        if i > 0 {
            s.push('&');
        }
        write!(s, "field_{i:06}={}", benign_value(i).replace(' ', "+")).unwrap();
        i += 1;
    }
    s
}

fn multipart_body(target: usize) -> String {
    let mut s = String::with_capacity(target + 256);
    let mut i = 0usize;
    while s.len() < target {
        write!(
            s,
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"field_{i:06}\"\r\n\r\n{}\r\n",
            benign_value(i)
        )
        .unwrap();
        i += 1;
    }
    write!(s, "--{BOUNDARY}--\r\n").unwrap();
    s
}

/// A POST carrying `body`. The body is shared, not copied, so building a fresh
/// context per timed run stays cheap at 8 MiB.
fn post_ctx(body: &Bytes, content_type: &str) -> RequestContext {
    let mut ctx = make_post_ctx("/api/orders", "");
    ctx.request_body = Some(body.clone());
    ctx.request_headers.insert(
        http::header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    ctx.request_headers
        .insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
    set_paranoia(&mut ctx, PARANOIA);
    ctx
}

/// Builds a benign body of at least the given size.
type BodyBuilder = fn(usize) -> String;

struct Timing {
    median: Duration,
    min: Duration,
    runs: usize,
    score: u32,
    /// Ids of the rules that fired on the last run, to show the body is benign.
    fired: Vec<String>,
}

/// Evaluate a fresh context from `make` repeatedly: at least three timed runs,
/// then more until roughly two seconds have been spent (capped at 50). Only the
/// two `evaluate` calls are timed — building the context is not the engine's cost.
fn time_eval(engine: &RuleEngine, make: impl Fn() -> RequestContext) -> Timing {
    // One untimed run warms caches and lazily-built regex DFAs.
    let mut warm = make();
    eval(engine, &mut warm, Phase::RequestBody);

    let mut samples = Vec::new();
    let budget = Duration::from_secs(2);
    let started = Instant::now();
    let (mut score, mut fired) = (0, Vec::new());
    while samples.len() < 3 || (started.elapsed() < budget && samples.len() < 50) {
        let mut ctx = make();
        let t = Instant::now();
        engine.evaluate(&mut ctx, Phase::RequestHeaders, 0);
        engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        samples.push(t.elapsed());
        score = ctx.anomaly_score;
        fired = ctx.rule_matches.iter().map(|m| m.rule_id.clone()).collect();
    }
    samples.sort();
    Timing {
        median: samples[samples.len() / 2],
        min: samples[0],
        runs: samples.len(),
        score,
        fired,
    }
}

#[test]
#[ignore = "performance measurement; run manually with --release --ignored --nocapture"]
fn evaluate_cost_on_large_benign_bodies() {
    let engine = load_crs_engines(CRS_FILES);
    let multipart_ct = format!("multipart/form-data; boundary={BOUNDARY}");
    let kinds: [(&str, BodyBuilder, &str); 3] = [
        ("JSON object", json_body, "application/json"),
        (
            "urlencoded form",
            form_body,
            "application/x-www-form-urlencoded",
        ),
        ("multipart form", multipart_body, multipart_ct.as_str()),
    ];

    println!(
        "\nCRS request side, PL{PARANOIA}, {} rules; evaluate() phase 1 + phase 2 per request",
        engine.rule_count()
    );
    println!(
        "{:<16} {:>7} {:>8} {:>12} {:>12} {:>10} {:>5} {:>6} {:>5}",
        "body", "size", "fields", "median ms", "min ms", "MiB/s", "runs", "score", "hits"
    );
    for (kind, build, ct) in kinds {
        for (label, size) in SIZES {
            let text = build(*size);
            let fields = text.matches("field_").count();
            let body = Bytes::from(text);
            let t = time_eval(&engine, || post_ctx(&body, ct));
            let ms = t.median.as_secs_f64() * 1e3;
            let mib_s = (body.len() as f64 / (1 << 20) as f64) / t.median.as_secs_f64();
            println!(
                "{:<16} {:>7} {:>8} {:>12.2} {:>12.2} {:>10.2} {:>5} {:>6} {:>5}",
                kind,
                label,
                fields,
                ms,
                t.min.as_secs_f64() * 1e3,
                mib_s,
                t.runs,
                t.score,
                t.fired.len()
            );
            // Benign by construction: a detection here would mean the timing
            // includes rule-firing work the row does not describe.
            assert!(
                t.score < 5,
                "{kind} {label} scored {} — not benign: {:?}",
                t.score,
                t.fired
            );
        }
    }
}
