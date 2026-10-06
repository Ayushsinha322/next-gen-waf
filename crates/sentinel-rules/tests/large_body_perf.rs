//! Rule-engine cost on large, benign request bodies.
//!
//! Times `evaluate()` (phase 1 + phase 2, as the proxy runs them) over the full
//! CRS request-side ruleset on benign bodies of 64 KiB, 1 MiB and 8 MiB:
//!   * a JSON object with many fields, and the same with mixed text,
//!   * an `application/x-www-form-urlencoded` form, and the same with mixed text,
//!   * a `multipart/form-data` form.
//!
//! "Mixed" rows carry what real forms do: mixed-case names and values,
//! Devanagari and accented Latin text, and values holding `+` and `%`. The
//! plain rows are lower-case ASCII that no transform changes; on mixed text
//! `t:lowercase`, `t:utf8toUnicode` and `t:urlDecodeUni` rewrite values, which
//! is where the VM's per-call memo budget decides how many chains it keeps.
//! Mixed rows stop below 8 MiB: `t:urlDecodeUni` over a raw body re-decodes
//! the rest of the body at every `%` — quadratic, in every VM version — so an
//! 8 MiB body holding `%` runs for hours, and a urlencoded one (all `%XX`)
//! already takes minutes at 1 MiB.
//!
//! The VM used to re-derive a request view (query parameters, body arguments,
//! multipart parts) and re-run its transform chain for every rule that loaded
//! one, so a body was parsed once per ARGS-family rule rather than once per
//! request. This harness is how that cost is measured. It asserts nothing about
//! time — wall-clock assertions are flaky on shared runners — and only checks
//! that the bodies stay benign.
//!
//! Each row also reports the process's peak RSS while it ran (`VmHWM`, reset
//! per row through `/proc/self/clear_refs`) and how far that rose above the RSS
//! the row started from. A process keeps freed heap for reuse, so a row's rise
//! is exact only when it runs in a process of its own: `PERF_ROWS` selects rows
//! by label substring, e.g. `PERF_ROWS="form mixed/8 MiB"`.
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

const KIB_64: (&str, usize) = ("64 KiB", 64 << 10);
const KIB_256: (&str, usize) = ("256 KiB", 256 << 10);
const MIB_1: (&str, usize) = ("1 MiB", 1 << 20);
const MIB_8: (&str, usize) = ("8 MiB", 8 << 20);

const BOUNDARY: &str = "----PerfBoundary7MA4YWxkTrZu0gW";

/// Plain words only: nothing a CRS rule should score, so the timing measures
/// the inspection of a body rather than the handling of a detection.
fn benign_value(i: usize) -> String {
    format!("the quick brown fox jumps over the lazy dog {i}")
}

fn plain_field(i: usize) -> (String, String) {
    (format!("field_{i:06}"), benign_value(i))
}

/// Text real forms carry: mixed case, Devanagari, accented Latin, `+` and `%`.
/// Still nothing a CRS rule should score.
fn mixed_field(i: usize) -> (String, String) {
    let value = match i % 4 {
        0 => format!("Order {i} for Ravi Kumar, ships to Pune MH 411001"),
        1 => format!("नमस्ते, आपका ऑर्डर {i} भेज दिया गया है"),
        2 => format!("Save 20% + free shipping on order {i}"),
        _ => format!("Café Crème, Größe {i}, naïve façade"),
    };
    (format!("customerNote_{i:06}"), value)
}

/// A `(name, value)` per field index.
type Fields = fn(usize) -> (String, String);

/// `x-www-form-urlencoded` encoding: unreserved bytes as they are, space as
/// `+`, everything else `%XX` — so a `+` or `%` in the text reaches the parser
/// encoded, as a browser sends it.
fn form_encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => write!(out, "%{b:02X}").unwrap(),
        }
    }
}

fn json_body(fields: Fields, target: usize) -> (String, usize) {
    let mut s = String::with_capacity(target + 128);
    s.push('{');
    let mut i = 0usize;
    while s.len() < target {
        if i > 0 {
            s.push(',');
        }
        let (name, value) = fields(i);
        write!(s, "\"{name}\":\"{value}\"").unwrap();
        i += 1;
    }
    s.push('}');
    (s, i)
}

fn form_body(fields: Fields, target: usize) -> (String, usize) {
    let mut s = String::with_capacity(target + 128);
    let mut i = 0usize;
    while s.len() < target {
        if i > 0 {
            s.push('&');
        }
        let (name, value) = fields(i);
        form_encode(&name, &mut s);
        s.push('=');
        form_encode(&value, &mut s);
        i += 1;
    }
    (s, i)
}

fn multipart_body(fields: Fields, target: usize) -> (String, usize) {
    let mut s = String::with_capacity(target + 256);
    let mut i = 0usize;
    while s.len() < target {
        let (name, value) = fields(i);
        write!(
            s,
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n",
        )
        .unwrap();
        i += 1;
    }
    write!(s, "--{BOUNDARY}--\r\n").unwrap();
    (s, i)
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

/// Builds a benign body of at least the given size; returns it and its field
/// count.
type BodyBuilder = fn(Fields, usize) -> (String, usize);

/// One kind of body: how it is built, what it holds, and the sizes measured.
struct Kind<'a> {
    name: &'a str,
    build: BodyBuilder,
    fields: Fields,
    content_type: &'a str,
    sizes: &'a [(&'a str, usize)],
}

struct Timing {
    median: Duration,
    min: Duration,
    runs: usize,
    score: u32,
    /// Ids of the rules that fired on the last run, to show the body is benign.
    fired: Vec<String>,
}

/// Evaluate a fresh context from `make` repeatedly: at least three timed runs,
/// then more until roughly two seconds have been spent (capped at 50) — or a
/// single run when that one took 20 s or more, where run-to-run spread is a
/// few percent and three runs of every version would take hours. Only the
/// two `evaluate` calls are timed — building the context is not the engine's
/// cost. `warm` is evaluated once, untimed, first: a small body of the same
/// shape, which reaches the same lazily-built regex DFA states as the large one
/// without costing a large run.
fn time_eval(
    engine: &RuleEngine,
    warm: RequestContext,
    make: impl Fn() -> RequestContext,
) -> Timing {
    let mut warm = warm;
    eval(engine, &mut warm, Phase::RequestBody);

    let mut samples = Vec::new();
    let budget = Duration::from_secs(2);
    let started = Instant::now();
    let (mut score, mut fired) = (0, Vec::new());
    let slow = Duration::from_secs(20);
    while samples.len() < 3 || (started.elapsed() < budget && samples.len() < 50) {
        if samples.first().is_some_and(|first| *first >= slow) {
            break;
        }
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

/// A `/proc/self/status` field, in MiB; `None` off Linux.
fn status_mib(field: &str) -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with(field))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024.0)
}

/// Reset the process's peak RSS (`VmHWM`) to its current RSS, so the next
/// reading is the peak of what runs in between. Linux 4.0+.
fn reset_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

fn mib(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_string(), |v| format!("{v:.0}"))
}

#[test]
#[ignore = "performance measurement; run manually with --release --ignored --nocapture"]
fn evaluate_cost_on_large_benign_bodies() {
    let only = std::env::var("PERF_ROWS").unwrap_or_default();
    let selected = |label: &str| only.is_empty() || only.split(',').any(|o| label.contains(o));

    let engine = load_crs_engines(CRS_FILES);
    let multipart_ct = format!("multipart/form-data; boundary={BOUNDARY}");
    let plain_sizes: &[(&str, usize)] = &[KIB_64, MIB_1, MIB_8];
    let kinds = [
        Kind {
            name: "JSON object",
            build: json_body,
            fields: plain_field,
            content_type: "application/json",
            sizes: plain_sizes,
        },
        Kind {
            name: "JSON mixed",
            build: json_body,
            fields: mixed_field,
            content_type: "application/json",
            sizes: &[KIB_64, MIB_1],
        },
        Kind {
            name: "urlencoded form",
            build: form_body,
            fields: plain_field,
            content_type: "application/x-www-form-urlencoded",
            sizes: plain_sizes,
        },
        Kind {
            name: "form mixed",
            build: form_body,
            fields: mixed_field,
            content_type: "application/x-www-form-urlencoded",
            sizes: &[KIB_64, KIB_256],
        },
        Kind {
            name: "multipart form",
            build: multipart_body,
            fields: plain_field,
            content_type: multipart_ct.as_str(),
            sizes: plain_sizes,
        },
    ];

    println!(
        "\nCRS request side, PL{PARANOIA}, {} rules; evaluate() phase 1 + phase 2 per request; \
         engine built, RSS {} MiB",
        engine.rule_count(),
        mib(status_mib("VmRSS:"))
    );
    println!(
        "{:<16} {:>7} {:>8} {:>12} {:>12} {:>10} {:>5} {:>6} {:>5} {:>9} {:>7}",
        "body",
        "size",
        "fields",
        "median ms",
        "min ms",
        "MiB/s",
        "runs",
        "score",
        "hits",
        "peak MiB",
        "rise"
    );
    for Kind {
        name: kind,
        build,
        fields,
        content_type: ct,
        sizes,
    } in kinds
    {
        for (label, size) in sizes {
            if !selected(&format!("{kind}/{label}")) {
                continue;
            }
            let (text, field_count) = build(fields, *size);
            let body = Bytes::from(text);
            let warm = Bytes::from(build(fields, 16 << 10).0);
            let start_rss = status_mib("VmRSS:");
            reset_peak_rss();
            let t = time_eval(&engine, post_ctx(&warm, ct), || post_ctx(&body, ct));
            let peak = status_mib("VmHWM:");
            let ms = t.median.as_secs_f64() * 1e3;
            let mib_s = (body.len() as f64 / (1 << 20) as f64) / t.median.as_secs_f64();
            println!(
                "{:<16} {:>7} {:>8} {:>12.2} {:>12.2} {:>10.2} {:>5} {:>6} {:>5} {:>9} {:>7}",
                kind,
                label,
                field_count,
                ms,
                t.min.as_secs_f64() * 1e3,
                mib_s,
                t.runs,
                t.score,
                t.fired.len(),
                mib(peak),
                mib(peak.zip(start_rss).map(|(p, s)| p - s)),
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
