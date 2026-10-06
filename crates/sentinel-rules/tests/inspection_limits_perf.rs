//! What inspecting a request's arguments costs, by argument count and by
//! argument bytes: the measurements the default inspection limits
//! (`max_inspected_args`, `max_inspected_arg_bytes`) are chosen from.
//!
//! Times `evaluate()` (phase 1 + phase 2, as the proxy runs them) with the
//! ruleset a site created through the control plane loads by default — every
//! request-side CRS family plus our placement and coverage rules — at the
//! default paranoia level, on benign bodies:
//!   * a count sweep: urlencoded, JSON and multipart forms of N fields, each a
//!     ~48-byte value, plain and with mixed text (mixed case, Devanagari,
//!     accented Latin, `+` and `%`, which the transforms rewrite);
//!   * a size sweep: 1000 fields whose values grow until the body reaches
//!     64 KiB .. 1 MiB;
//!   * a few large values: 8 fields carrying up to 4 MiB between them;
//!   * and, under the limits a site gets by default (`WafConfig` parsed from
//!     an empty policy, as the control plane's is), an ordinary large form —
//!     1000 fields and 256 KiB of argument text — and requests exactly AT the
//!     argument limits: as many fields as allowed sharing all the bytes
//!     allowed (`at-limits`), and 8 fields sharing them (`at-bytes`), the
//!     costliest shape per byte. The `refused` column says whether the default
//!     limits — the time budget included — let them through.
//!
//! The limits are judged on the arguments the parser produces (decoded names
//! and values), so each row also prints those bytes. Like `large_body_perf`,
//! this asserts nothing about time and only checks the bodies stay benign.
//!
//! `PERF_PARANOIA=4` runs the rows at another paranoia level, and
//! `PERF_TIME_BUDGET=<ms>` runs every row under that time budget (0 = none;
//! by default only the rows under the default limits have one), which also
//! times the budget's clock checks.
//!
//! Run manually, in an optimized build:
//!   cargo test -p sentinel-rules --release --test inspection_limits_perf -- --ignored --nocapture
//! `PERF_ROWS` selects rows by label substring, e.g. `PERF_ROWS="count/json"`.

mod common;

use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::*;
use sentinel_core::config::WafConfig;
use sentinel_core::context::{InspectionLimit, InspectionLimits, Phase, RequestContext};
use sentinel_rules::RuleEngine;

/// The control plane's default (`buildRustWaf`); `PERF_PARANOIA` overrides it.
fn paranoia() -> u8 {
    std::env::var("PERF_PARANOIA")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2)
}

/// What `crsFilesForCategories` loads with no category chosen (every request
/// family), with 901 for the `tx.*` defaults the proxy otherwise seeds, then
/// `sentinelRuleFiles`.
const RULE_FILES: &[&str] = &[
    "owasp-crs/rules/REQUEST-901-INITIALIZATION.conf",
    "owasp-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf",
    "owasp-crs/rules/REQUEST-913-SCANNER-DETECTION.conf",
    "owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    "owasp-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf",
    "owasp-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf",
    "owasp-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "owasp-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "owasp-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "owasp-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf",
    "owasp-crs/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
    "owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "owasp-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
    "owasp-crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
    "custom/placement.conf",
    "custom/coverage.conf",
];

const BOUNDARY: &str = "----PerfBoundary7MA4YWxkTrZu0gW";

fn engine() -> RuleEngine {
    use sentinel_rules::dsl::ast::RuleFile;
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let mut merged = RuleFile::default();
    for f in RULE_FILES {
        let path = rules.join(f);
        let source = std::fs::read_to_string(&path).expect("rule file");
        let file = sentinel_rules::import_secrule_conf_dir(&source, path.parent()).expect("import");
        merged.items.extend(file.items);
    }
    RuleEngine::new(sentinel_rules::compile(merged).expect("compile"))
}

/// `(name, value)` of field `i`, its value padded to at least `len` bytes.
type Fields = fn(usize, usize) -> (String, String);

/// Plain words that no transform changes and no rule scores.
fn plain(i: usize, len: usize) -> (String, String) {
    let mut v = format!("the quick brown fox jumps over the lazy dog {i}");
    while v.len() < len {
        v.push_str(" and the quick brown fox jumps again");
    }
    (format!("field_{i:06}"), v)
}

/// What real forms carry: mixed case, Devanagari, accented Latin, `+` and `%`.
fn mixed(i: usize, len: usize) -> (String, String) {
    let mut v = match i % 4 {
        0 => format!("Order {i} for Ravi Kumar, ships to Pune MH 411001"),
        1 => format!("नमस्ते, आपका ऑर्डर {i} भेज दिया गया है"),
        2 => format!("Save 20% + free shipping on order {i}"),
        _ => format!("Café Crème, Größe {i}, naïve façade"),
    };
    while v.len() < len {
        v.push_str(" Café Crème, Größe, naïve");
    }
    (format!("customerNote_{i:06}"), v)
}

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

#[derive(Clone, Copy)]
enum Shape {
    Form,
    Json,
    Multipart,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Shape::Form => "form",
            Shape::Json => "json",
            Shape::Multipart => "multipart",
        }
    }

    fn content_type(self) -> String {
        match self {
            Shape::Form => "application/x-www-form-urlencoded".into(),
            Shape::Json => "application/json".into(),
            Shape::Multipart => format!("multipart/form-data; boundary={BOUNDARY}"),
        }
    }

    /// `n` fields of at least `len`-byte values — with `exact`, of exactly
    /// `len` bytes of name and value together: the body, and the bytes of
    /// argument names and values the parser yields from it.
    fn body(self, fields: Fields, n: usize, len: usize, exact: bool) -> (String, usize) {
        let mut s = String::new();
        let mut arg_bytes = 0;
        if let Shape::Json = self {
            s.push('{');
        }
        for i in 0..n {
            let (name, mut value) = fields(i, len);
            if exact {
                let want = len - name.len();
                let mut cut = want;
                while !value.is_char_boundary(cut) {
                    cut -= 1;
                }
                value.truncate(cut);
                while value.len() < want {
                    value.push('x');
                }
            }
            arg_bytes += name.len() + value.len();
            match self {
                Shape::Form => {
                    if i > 0 {
                        s.push('&');
                    }
                    form_encode(&name, &mut s);
                    s.push('=');
                    form_encode(&value, &mut s);
                }
                Shape::Json => {
                    if i > 0 {
                        s.push(',');
                    }
                    write!(s, "\"{name}\":\"{value}\"").unwrap();
                }
                Shape::Multipart => write!(
                    s,
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .unwrap(),
            }
        }
        match self {
            Shape::Json => s.push('}'),
            Shape::Multipart => write!(s, "--{BOUNDARY}--\r\n").unwrap(),
            Shape::Form => {}
        }
        (s, arg_bytes)
    }
}

/// The limits a site gets when its policy names none.
fn default_limits() -> InspectionLimits {
    serde_json::from_str::<WafConfig>("{}")
        .expect("empty policy")
        .inspection_limits()
}

fn post_ctx(body: &Bytes, content_type: &str, limits: InspectionLimits) -> RequestContext {
    let mut ctx = make_post_ctx("/api/orders", "");
    ctx.request_body = Some(body.clone());
    ctx.request_headers.insert(
        http::header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    ctx.request_headers
        .insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
    set_paranoia(&mut ctx, paranoia());
    ctx.inspection_limits = limits;
    if let Some(ms) = std::env::var("PERF_TIME_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        ctx.inspection_limits.time_budget_ms = ms;
    }
    ctx
}

/// The inspection limit the engine refused the request for, if any.
fn refusal(ctx: &RequestContext) -> Option<InspectionLimit> {
    ctx.rule_matches
        .iter()
        .find_map(|m| InspectionLimit::of_rule(&m.rule_id))
}

/// Median and minimum of at least five timed runs (more until ~1.5 s spent,
/// at most 40), after one untimed run of the same request; the score and
/// refusal of the last.
fn time_eval(
    engine: &RuleEngine,
    make: impl Fn() -> RequestContext,
) -> (Duration, Duration, u32, Option<InspectionLimit>) {
    let mut warm = make();
    eval(engine, &mut warm, Phase::RequestBody);
    let mut samples = Vec::new();
    let started = Instant::now();
    let mut score = 0;
    let mut refused = None;
    while samples.len() < 5
        || (started.elapsed() < Duration::from_millis(1500) && samples.len() < 40)
    {
        let mut ctx = make();
        let t = Instant::now();
        engine.evaluate(&mut ctx, Phase::RequestHeaders, 0);
        engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        samples.push(t.elapsed());
        score = ctx.anomaly_score;
        refused = refusal(&ctx);
    }
    samples.sort();
    (samples[samples.len() / 2], samples[0], score, refused)
}

#[test]
#[ignore = "performance measurement; run manually with --release --ignored --nocapture"]
fn evaluate_cost_by_argument_count_and_size() {
    let only = std::env::var("PERF_ROWS").unwrap_or_default();
    let selected = |label: &str| only.is_empty() || only.split(',').any(|o| label.contains(o));
    let engine = engine();
    println!(
        "\n{} rules at PL{}; evaluate() phase 1 + phase 2 per request",
        engine.rule_count(),
        paranoia()
    );
    let defaults = default_limits();
    println!("default limits: {defaults:?}");
    println!(
        "{:<26} {:>7} {:>10} {:>10} {:>10} {:>9} {:>8} {:>6} {:>9}",
        "row", "fields", "body B", "arg B", "median ms", "min ms", "us/field", "score", "refused"
    );

    // (label, shape, fields, n, len, under the default limits). Rows under the
    // defaults have `len` bytes of name and value per field, exactly.
    let mut rows: Vec<(String, Shape, Fields, usize, usize, bool)> = Vec::new();
    let max_args = defaults.max_args as usize;
    let max_bytes = defaults.max_arg_bytes as usize;
    for (text, fields) in [("plain", plain as Fields), ("mixed", mixed as Fields)] {
        for shape in [Shape::Form, Shape::Json, Shape::Multipart] {
            let s = shape.name();
            rows.push((
                format!("ordinary/{s}/{text}"),
                shape,
                fields,
                1000,
                262,
                true,
            ));
            rows.push((
                format!("at-limits/{s}/{text}"),
                shape,
                fields,
                max_args,
                max_bytes / max_args,
                true,
            ));
            rows.push((
                format!("at-bytes/{s}/{text}"),
                shape,
                fields,
                8,
                max_bytes / 8,
                true,
            ));
        }
    }
    for (text, fields) in [("plain", plain as Fields), ("mixed", mixed as Fields)] {
        for shape in [Shape::Form, Shape::Json, Shape::Multipart] {
            for n in [100, 500, 1000, 2000, 4000, 8000] {
                rows.push((
                    format!("count/{}/{text}", shape.name()),
                    shape,
                    fields,
                    n,
                    48,
                    false,
                ));
            }
            // 1000 fields, values grown to 64 KiB .. 1 MiB of body.
            for kib in [64, 256, 512, 1024] {
                let len = kib * 1024 / 1000;
                rows.push((
                    format!("size/{}/{text}", shape.name()),
                    shape,
                    fields,
                    1000,
                    len,
                    false,
                ));
            }
            // A few large values.
            for kib in [256, 1024, 4096] {
                let len = kib * 1024 / 8;
                rows.push((
                    format!("large/{}/{text}", shape.name()),
                    shape,
                    fields,
                    8,
                    len,
                    false,
                ));
            }
        }
    }
    for (label, shape, fields, n, len, under_defaults) in rows {
        if !selected(&label) {
            continue;
        }
        let (text, arg_bytes) = shape.body(fields, n, len, under_defaults);
        let body = Bytes::from(text);
        let ct = shape.content_type();
        let limits = if under_defaults {
            defaults
        } else {
            InspectionLimits::default()
        };
        let (median, min, score, refused) = time_eval(&engine, || post_ctx(&body, &ct, limits));
        println!(
            "{:<26} {:>7} {:>10} {:>10} {:>10.2} {:>9.2} {:>8.1} {:>6} {:>9}",
            label,
            n,
            body.len(),
            arg_bytes,
            median.as_secs_f64() * 1e3,
            min.as_secs_f64() * 1e3,
            median.as_secs_f64() * 1e6 / n as f64,
            score,
            refused.map_or("-", |l| l.reason())
        );
        // A row built to sit within the argument limits must: a refusal here
        // is the harness's arithmetic disagreeing with the engine's. A time
        // refusal is a measurement, and is only printed.
        assert!(
            !matches!(
                refused,
                Some(InspectionLimit::Args | InspectionLimit::ArgBytes)
            ),
            "{label} was built within the default argument limits, yet refused for {refused:?}"
        );
        // Benign at the default level; higher levels score ordinary text by
        // design, and their rows are timed all the same.
        assert!(
            paranoia() > 2 || score < 5,
            "{label} with {n} fields is not benign: score {score}"
        );
    }
}
