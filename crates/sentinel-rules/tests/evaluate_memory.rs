//! Peak heap of one `evaluate()` call on a body of many tiny fields.
//!
//! The VM parses a request once per call and keeps what it derives for the
//! rest of that call. What it keeps on top of the parse must stay bounded: an
//! unauthenticated client chooses the body, and `evaluate` runs inline on the
//! proxy's worker threads. The first version of that memo kept full copies of
//! ARGS, ARGS_NAMES and REQUEST_BODY next to the parsed pairs, uncounted, so a
//! body of tiny fields — mostly `String` headers once parsed — held several
//! times its parse for the whole call.
//!
//! Measured with a counting global allocator, so the numbers are exact and do
//! not depend on the machine: the peak live heap during `evaluate`, above what
//! was live when it started.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

use bytes::Bytes;
use sentinel_core::context::{Phase, RequestContext};
use sentinel_rules::RuleEngine;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: every call is forwarded to `System` unchanged; the counters only
// observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The counters are process-wide and tests run on parallel threads: each test
/// holds this for its whole body, so no other test allocates while it measures.
static SERIAL: Mutex<()> = Mutex::new(());

fn engine(rules: &str) -> RuleEngine {
    let file = sentinel_rules::import_secrule_conf(rules).expect("import");
    RuleEngine::new(sentinel_rules::compile(file).expect("compile"))
}

fn post(body: &Bytes) -> RequestContext {
    let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    ctx.method = http::Method::POST;
    ctx.uri = "/form".parse().unwrap();
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    ctx.request_body = Some(body.clone());
    ctx
}

/// Peak live heap during one phase-2 `evaluate`, above what was live before it.
fn peak_extra(engine: &RuleEngine, body: &Bytes) -> usize {
    // Regex caches grow on first use; warm them on the same shape first, so
    // the measurement is the request's cost and not the engine's.
    let warm = Bytes::from("a=1&b=2");
    engine.evaluate(&mut post(&warm), Phase::RequestBody, 0);

    let mut ctx = post(body);
    let start = LIVE.load(Relaxed);
    PEAK.store(start, Relaxed);
    engine.evaluate(&mut ctx, Phase::RequestBody, 0);
    PEAK.load(Relaxed).saturating_sub(start)
}

/// One rule reading ARGS: what parsing the body costs, and nothing more.
const ONE_READ: &str = r#"
SecRule ARGS "@rx never-1" "id:1,phase:2,pass,t:none"
"#;

/// The shape of CRS phase 2: ARGS, ARGS_NAMES and REQUEST_BODY read by several
/// rules each, through repeated chains and a single-use one over all three (as
/// CRS 921110 reads them).
///
/// The chains change nothing on this body and cost at most their input and
/// output while they run. `t:htmlEntityDecode` is left out: it expands its
/// input to a `Vec<char>` — eight times a raw body — which is the transform's
/// own working set, the same with or without a memo, and not what this
/// measures.
const CRS_SHAPED: &str = r#"
SecRule ARGS "@rx never-1" "id:1,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx never-2" "id:2,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx never-3" "id:3,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS_NAMES "@rx never-4" "id:4,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS_NAMES "@rx never-5" "id:5,phase:2,pass,t:none,t:urlDecodeUni"
SecRule ARGS "@rx never-6" "id:6,phase:2,pass,t:none,t:lowercase"
SecRule ARGS "@rx never-7" "id:7,phase:2,pass,t:none,t:lowercase"
SecRule REQUEST_BODY "@rx never-8" "id:8,phase:2,pass,t:none,t:lowercase"
SecRule REQUEST_BODY "@rx never-9" "id:9,phase:2,pass,t:none,t:lowercase"
SecRule REQUEST_BODY "@rx never-10" "id:10,phase:2,pass,t:none"
SecRule REQUEST_BODY "@rx never-11" "id:11,phase:2,pass,t:none"
SecRule ARGS_NAMES|ARGS|REQUEST_BODY "@rx never-12" "id:12,phase:2,pass,t:none,t:lowercase,t:removeNulls"
SecRule ARGS "@rx never-13" "id:13,phase:2,pass,t:none"
SecRule ARGS_NAMES "@rx never-14" "id:14,phase:2,pass,t:none"
SecRule &ARGS "@gt 100000000" "id:15,phase:2,pass"
SecRule ARGS_COMBINED_SIZE "@gt 100000000" "id:16,phase:2,pass"
"#;

/// One rule reading a body holds the parsed parameters and nothing more: a
/// name list and a value list — a `String` header per entry, at the lists'
/// final capacity — plus the text. The parse used to collect `(name, value)`
/// pairs first and split them after, holding the pairs and both lists at once:
/// 25 MB at peak here, nearly twice this bound.
#[test]
fn one_read_holds_the_two_parameter_lists_and_no_more() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fields = 250_000;
    let body = Bytes::from("a=1&".repeat(fields));
    let one = peak_extra(&engine(ONE_READ), &body);
    let lists = 2 * fields.next_power_of_two() * std::mem::size_of::<String>();
    let text = 2 * fields; // one byte per name and per value
    let allowed = lists + text + body.len() / 16;
    println!(
        "body {} B: one rule {one} B, allowed {allowed} B",
        body.len()
    );
    assert!(
        one <= allowed,
        "one read of {fields} one-byte fields held {one} B at peak, past the \
         {allowed} B its two parameter lists need"
    );
}

/// Sixteen rules reading a body hold at most the per-call memo budget (twice
/// the body) and one chain's working set (its input and output: twice the
/// body) more than one rule reading it. The first memo version kept a full
/// ARGS_NAMES copy — 25 bytes per one-byte field — and the raw body next to
/// the parsed pairs, uncounted: 14 times the body more.
#[test]
fn many_rules_reading_a_body_hold_at_most_the_memo_budget_more() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // 1 MB of `a=1&`: 250 000 fields, each a one-byte name and value.
    let body = Bytes::from("a=1&".repeat(250_000));
    let one = peak_extra(&engine(ONE_READ), &body);
    let many = peak_extra(&engine(CRS_SHAPED), &body);
    let allowed = one + 4 * body.len();
    println!(
        "body {} B: one rule {} B, CRS-shaped {} B ({:.2}x the body above one rule; at most 4x)",
        body.len(),
        one,
        many,
        many.saturating_sub(one) as f64 / body.len() as f64,
    );
    assert!(
        many <= allowed,
        "reading the body in many rules held {many} B at peak, a single read {one} B: \
         {} B more, past the {} B allowed (memo budget plus one chain's working set)",
        many - one,
        allowed - one,
    );
}
