//! Panic containment for the data plane.
//!
//! Release builds used `panic = "abort"` until 2026-10, so a single panic
//! anywhere — a slicing bug reached by one hostile request, an `unreachable!`
//! inside a dependency when Valkey closed a connection mid-setup — killed the
//! whole node: every site, every in-flight request, every connection. Builds now
//! unwind, and this module is what turns that into isolation:
//!
//!  * [`install_panic_hook`] counts every panic in `sentinel_panics_total` and
//!    logs it as one structured line (location and message, never request
//!    data). A panic inside a request is logged by the request's guard instead,
//!    rate-limited per location, so a client replaying the input that breaks a
//!    parser cannot flood the log.
//!  * The pipeline guard in `proxy` (via [`pipeline_panicked`]) and
//!    [`contain_request`] answer a panicking request with a 500 carrying its
//!    Support ID, and the connection keeps serving. Whether the request had
//!    already reached the origin is recorded, because after Phase 3 it had.
//!  * [`supervise`] / [`supervised!`] / [`supervise_blocking`] restart a
//!    background loop after a panic, with backoff, and record which loop it was
//!    (`/healthz` `panics.tasks`, the heartbeat), so a crash-looping loop shows
//!    up as a degraded node rather than a silent one.
//!
//! Unwinding is a backstop, not a licence: every panic is still a bug, and each
//! one is made loud on purpose.

use std::any::Any;
use std::backtrace::{Backtrace, BacktraceStatus};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::FutureExt as _;
use http::{header, Response, StatusCode};
use sentinel_core::context::{Phase, RequestContext};
use tracing::{debug, error};

use crate::BoxBody;

/// Lock a mutex of this module, recovering it if a panic poisoned it: every
/// critical section here is a plain read or update, so the data is still whole.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The panic hook
// ---------------------------------------------------------------------------

thread_local! {
    /// Set while this thread polls a request under [`catch_request`]. That
    /// request's guard writes the panic's one line, so the hook only counts it.
    static IN_REQUEST: Cell<bool> = const { Cell::new(false) };
    /// What the hook saw of the latest panic on this thread. A panic is caught
    /// on the thread that raised it, so the guards pick it up here.
    static LAST_PANIC: RefCell<Option<Caught>> = const { RefCell::new(None) };
}

/// What the hook recorded about one panic, for the guard that catches it.
struct Caught {
    location: String,
    /// Only for a request panic whose line is due, and only when
    /// `RUST_BACKTRACE` asks for one.
    backtrace: Option<Backtrace>,
    /// For a request panic: whether its line is due (see [`throttle`]),
    /// decided once, in the hook, so a suppressed one costs no backtrace.
    line: LogLine,
}

/// Marks this thread as polling a request until dropped; restores the previous
/// state, because the request guards nest (`contain_request` around `proxy`).
struct InRequest(bool);

impl InRequest {
    fn enter() -> Self {
        Self(IN_REQUEST.try_with(|f| f.replace(true)).unwrap_or(false))
    }
}

impl Drop for InRequest {
    fn drop(&mut self) {
        let _ = IN_REQUEST.try_with(|f| f.set(self.0));
    }
}

/// Install the process-wide panic hook. Idempotent; called by the binary once
/// tracing is up.
///
/// Every panic is counted (`sentinel_panics_total`). Outside a request it is
/// logged here as one ERROR line with its source location, a redacted message
/// (see [`panic_message`]) and, when `RUST_BACKTRACE` is set, the backtrace —
/// the default hook printed that, and once a panic no longer ends the process
/// the stack is the main clue left. Inside a request the guard logs it instead
/// (see [`pipeline_panicked`]). The default hook is replaced rather than chained
/// because it prints the raw message, which can hold request data, as a second,
/// unstructured line. With no tracing subscriber installed (a test binary, a
/// tool linking this crate) the default hook still runs, because otherwise the
/// panic would not be seen at all.
pub fn install_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let fallback = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            sentinel_telemetry::note_panic();
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown".to_string());
            let in_request = IN_REQUEST.try_with(Cell::get).unwrap_or(false);
            if !subscriber_present() {
                record(location, None, LogLine::Due { suppressed: 0 });
                fallback(info);
                return;
            }
            if in_request {
                let line = throttle(&location);
                let backtrace = match line {
                    LogLine::Due { .. } => captured_backtrace(),
                    LogLine::Suppressed => None,
                };
                record(location, backtrace, line);
                return;
            }
            let thread = std::thread::current();
            let thread = thread.name().unwrap_or("unnamed");
            let backtrace = captured_backtrace();
            error!(
                thread,
                location = %location,
                panic = %panic_message(info.payload()),
                backtrace = backtrace.as_ref().map(tracing::field::display),
                "{}",
                hook_line(thread, &location)
            );
            record(location, None, LogLine::Due { suppressed: 0 });
        }));
    });
}

/// Whether a tracing subscriber will record this thread's events. Asked of the
/// thread's effective dispatcher rather than `dispatcher::has_been_set()`,
/// which stays true for the whole process once any scoped subscriber existed.
fn subscriber_present() -> bool {
    tracing::dispatcher::get_default(|d| !d.is::<tracing::subscriber::NoSubscriber>())
}

/// The backtrace, when `RUST_BACKTRACE` (or `RUST_LIB_BACKTRACE`) enables one.
/// Stack frames are code addresses and symbols, never request data.
fn captured_backtrace() -> Option<Backtrace> {
    #[cfg(test)]
    if let Some(force) = FORCE_BACKTRACE.with(Cell::get) {
        return force.then(Backtrace::force_capture);
    }
    let bt = Backtrace::capture();
    (bt.status() == BacktraceStatus::Captured).then_some(bt)
}

#[cfg(test)]
thread_local! {
    /// Overrides `RUST_BACKTRACE` for this thread: std reads it once per
    /// process, so a test cannot set it.
    static FORCE_BACKTRACE: Cell<Option<bool>> = const { Cell::new(None) };
}

fn record(location: String, backtrace: Option<Backtrace>, line: LogLine) {
    let _ = LAST_PANIC.try_with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            *slot = Some(Caught {
                location,
                backtrace,
                line,
            });
        }
    });
}

/// The hook's message. Keeps the default hook's `thread '…' panicked at` wording
/// because deploy/docker/verify-deploy.sh finds panics in container logs by
/// exactly that text; the request guards' lines start with it too.
fn hook_line(thread: &str, location: &str) -> String {
    format!("thread '{thread}' panicked at {location}")
}

/// Take what the hook recorded for the panic just caught on this thread.
fn take_caught() -> Option<Caught> {
    LAST_PANIC
        .try_with(|slot| slot.try_borrow_mut().ok().and_then(|mut s| s.take()))
        .ok()
        .flatten()
}

/// The location of the panic just caught on this thread; "unknown" when the
/// hook is not installed.
fn take_panic_location() -> String {
    take_caught()
        .map(|c| c.location)
        .unwrap_or_else(|| "unknown".to_string())
}

/// [`take_caught`] for a request guard. Without the hook nothing decided
/// whether this line is due, so decide it here.
fn take_request_caught() -> Caught {
    take_caught().unwrap_or_else(|| Caught {
        location: "unknown".to_string(),
        backtrace: None,
        line: throttle("unknown"),
    })
}

/// Longest panic message carried onto a log line.
const PANIC_MESSAGE_MAX: usize = 200;

/// std's own panic messages that open with backtick spans of their own (method
/// and variant names, never data). Kept verbatim only as the START of a message,
/// the one place std puts them — see [`panic_message`].
const STD_MESSAGE_PREFIXES: &[&str] = &[
    "called `Option::unwrap()` on a `None` value",
    "called `Result::unwrap()` on an `Err` value: ",
    "called `Result::unwrap_err()` on an `Ok` value: ",
];

/// The panic's message, reduced to what is safe to log.
///
/// std quotes the operand of a failed str slice between backticks — "byte index
/// 7 is not a char boundary; it is inside 'é' (bytes 6..8) of `<the string>`" —
/// and on the request path that operand is request data: a header, a query
/// value, a cookie, a body. So everything from the first backtick on is
/// redacted, after one of std's own prefixes if the message starts with one.
/// Redacting only the span is not enough: the operand can contain backticks of
/// its own (`it`s`, a JavaScript template literal), and pairing them up put the
/// text after the operand's own backtick — a password, a session id — back on
/// the log line. Nor may a std term be recognised anywhere but in its prefix: an
/// operand starting "None`" or "Ok`" looked like std's own span, and the text
/// after it was logged in clear. std puts the operand last in every such
/// message, so nothing useful follows it. The whole message is also capped. An
/// `unwrap()` on an error whose Debug output embeds input can still carry a
/// fragment, never a whole value.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    let raw = if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        return "non-string panic payload".to_string();
    };
    let mut out = String::with_capacity(raw.len().min(PANIC_MESSAGE_MAX) + 16);
    let std_prefix = STD_MESSAGE_PREFIXES
        .iter()
        .find(|p| raw.starts_with(*p))
        .map_or(0, |p| p.len());
    let (head, rest) = raw.split_at(std_prefix);
    out.push_str(head);
    match rest.split_once('`') {
        Some((before, _)) => {
            out.push_str(before);
            out.push_str("`<redacted>");
        }
        None => out.push_str(rest),
    }
    if out.len() > PANIC_MESSAGE_MAX {
        let mut cut = PANIC_MESSAGE_MAX;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------------------
// Rate-limiting the request-path lines
// ---------------------------------------------------------------------------

/// Whether a request panic's ERROR line is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogLine {
    /// Write it, saying how many for this location were skipped since the last.
    Due { suppressed: u64 },
    /// Skip it; it is still counted and still has its access/waf.log records.
    Suppressed,
}

/// Shortest gap between two request-panic lines for the same location.
const REQUEST_LINE_EVERY: Duration = Duration::from_secs(1);

/// Distinct locations remembered. They are code sites, so this never fills in
/// practice; the cap only bounds the map.
const REQUEST_LINE_LOCATIONS: usize = 1024;

struct LineState {
    last: Instant,
    suppressed: u64,
}

static REQUEST_LINES: Mutex<BTreeMap<String, LineState>> = Mutex::new(BTreeMap::new());

/// Decide whether this request panic gets a line. A client that finds an input
/// which panics can send it as fast as it likes, and each one was two ERROR
/// lines on stdout: with the compose log rotation that pushed every other line
/// out — the first panic's evidence included — within minutes. The first is
/// written in full, then at most one a second per location, each saying how
/// many were skipped. The counters and the per-request log records still see
/// every one.
fn throttle(location: &str) -> LogLine {
    throttle_in(&mut lock(&REQUEST_LINES), location, Instant::now())
}

fn throttle_in(lines: &mut BTreeMap<String, LineState>, location: &str, now: Instant) -> LogLine {
    if let Some(st) = lines.get_mut(location) {
        if now.saturating_duration_since(st.last) < REQUEST_LINE_EVERY {
            st.suppressed += 1;
            return LogLine::Suppressed;
        }
        st.last = now;
        return LogLine::Due {
            suppressed: std::mem::take(&mut st.suppressed),
        };
    }
    if lines.len() >= REQUEST_LINE_LOCATIONS {
        lines.clear();
    }
    lines.insert(
        location.to_string(),
        LineState {
            last: now,
            suppressed: 0,
        },
    );
    LogLine::Due { suppressed: 0 }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Run `fut`, handing back the panic payload instead of unwinding if it panics.
pub(crate) async fn catch<F: Future>(fut: F) -> Result<F::Output, Box<dyn Any + Send>> {
    AssertUnwindSafe(fut).catch_unwind().await
}

/// [`catch`] for a request. While the future is being polled the hook leaves
/// the panic's line to the request guard, which writes one, rate-limited.
pub(crate) async fn catch_request<F: Future>(fut: F) -> Result<F::Output, Box<dyn Any + Send>> {
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        // Set per poll, not once: the task can move between worker threads.
        let _in_request = InRequest::enter();
        match std::panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(Poll::Ready(out)) => Poll::Ready(Ok(out)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(payload)),
        }
    })
    .await
}

/// Whether a request whose processing panicked had already been sent upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forwarded {
    /// Panicked before Phase 3: nothing left this node.
    No,
    /// Panicked in Phase 3 before the origin answered: the panic may have come
    /// before the send or during it, and nothing records which.
    Possibly,
    /// The origin answered (Phase 4 onward: response headers, response-body
    /// rules, DLP, logging). The request was executed there.
    Yes,
}

impl Forwarded {
    fn of(ctx: &RequestContext) -> Self {
        // Set the moment the origin answers, so it outranks the phase: a
        // panic while logging a forwarded request is in Phase::Logging too.
        if ctx.upstream_latency_us.is_some() {
            Forwarded::Yes
        } else if ctx.phase == Phase::Upstream {
            Forwarded::Possibly
        } else {
            Forwarded::No
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Forwarded::No => "no",
            Forwarded::Possibly => "possibly",
            Forwarded::Yes => "yes",
        }
    }

    /// The reason recorded on the request's log records. Reaches waf.log and
    /// the console, so it names the outcome, not the code. Each starts with
    /// [`REQUEST_PANIC_PREFIX`], which is how [`is_contained_panic`] knows it.
    fn reason(self) -> &'static str {
        match self {
            Forwarded::No => {
                "internal error: request processing failed before it reached the origin; \
                 answered 500, not forwarded"
            }
            Forwarded::Possibly => {
                "internal error: request processing failed while it was being sent to the \
                 origin, which may have received it; answered 500"
            }
            Forwarded::Yes => {
                "internal error: processing failed after the request reached the origin; \
                 the origin's response was discarded and 500 returned"
            }
        }
    }
}

/// Every [`Forwarded::reason`] starts with this; none of the pipeline's own
/// gateway errors (upstream, routing, body) does.
const REQUEST_PANIC_PREFIX: &str = "internal error: ";

/// Whether this request was answered by [`pipeline_panicked`], so waf.log can
/// label it an internal failure rather than an upstream or routing one.
pub(crate) fn is_contained_panic(ctx: &RequestContext) -> bool {
    ctx.gateway_error
        .as_deref()
        .is_some_and(|e| e.starts_with(REQUEST_PANIC_PREFIX))
}

/// The 500 for a request whose processing panicked: the Support ID and nothing
/// else. The location and message belong in the log; a client probing for the
/// input that breaks a parser learns only that something did.
pub(crate) fn panic_response(support_id: &str) -> Response<BoxBody> {
    let body = serde_json::json!({
        "error": "Internal Server Error",
        "support_id": support_id,
        // Same pair as the block response, for clients that read request_id.
        "request_id": support_id,
    });
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(crate::full_body(Bytes::from(body.to_string())))
        .expect("static 500 response always builds")
}

/// Turn a panic caught inside the WAF pipeline into the request's answer.
///
/// Called by `proxy`, where the request context outlives the panic, so the
/// request keeps its Support ID and still gets its access-log and waf.log lines,
/// marked ERROR. Whether it had reached the origin depends on where it
/// panicked — a response-body rule or DLP scan runs after the origin executed
/// the request — and the reason, the ERROR line's `forwarded` field and the
/// waf.log record all say which.
pub(crate) fn pipeline_panicked(
    ctx: &mut RequestContext,
    payload: Box<dyn Any + Send>,
) -> Response<BoxBody> {
    sentinel_telemetry::note_request_panic();
    let forwarded = Forwarded::of(ctx);
    let caught = take_request_caught();
    if let LogLine::Due { suppressed } = caught.line {
        let thread = std::thread::current();
        error!(
            request_id = %ctx.request_id,
            client_ip = %ctx.client_ip,
            site = ctx.site_id.as_deref().unwrap_or("-"),
            phase = %ctx.phase,
            forwarded = forwarded.as_str(),
            location = %caught.location,
            panic = %panic_message(&*payload),
            suppressed,
            backtrace = caught.backtrace.as_ref().map(tracing::field::display),
            "{}; request processing panicked, answered 500 (forwarded to the origin: {})",
            hook_line(thread.name().unwrap_or("unnamed"), &caught.location),
            forwarded.as_str(),
        );
    }
    #[cfg(test)]
    note_test_reason(ctx, forwarded.reason());
    let resp = panic_response(&ctx.request_id.to_string());
    crate::stamp_response(ctx, &resp);
    ctx.gateway_error = Some(forwarded.reason().to_string());
    ctx.advance_phase(Phase::Logging);
    // The panic may have come from logging itself; a second one must not cost
    // the client its 500.
    if std::panic::catch_unwind(AssertUnwindSafe(|| crate::log_request(ctx))).is_err() {
        error!(
            request_id = %ctx.request_id,
            location = %take_panic_location(),
            "request log record could not be written after a panic"
        );
    }
    resp
}

/// Last-resort guard for a TCP request, around everything `handle_request`
/// serves itself: health, metrics, the management console, the internal API,
/// ACME. The WAF pipeline has its own guard in `proxy`, which keeps the request
/// context, so a panic only reaches this one from those routes. It answers 500
/// with a fresh Support ID that is on the log line, so the response can still
/// be traced; without it the connection simply dropped.
pub(crate) async fn contain_request<F>(
    peer: SocketAddr,
    fut: F,
) -> Result<Response<BoxBody>, Infallible>
where
    F: Future<Output = Result<Response<BoxBody>, Infallible>>,
{
    match catch_request(fut).await {
        Ok(resp) => resp,
        Err(payload) => {
            sentinel_telemetry::note_request_panic();
            let support_id = uuid::Uuid::new_v4().to_string();
            let caught = take_request_caught();
            if let LogLine::Due { suppressed } = caught.line {
                let thread = std::thread::current();
                error!(
                    request_id = %support_id,
                    client_ip = %peer.ip(),
                    location = %caught.location,
                    panic = %panic_message(&*payload),
                    suppressed,
                    backtrace = caught.backtrace.as_ref().map(tracing::field::display),
                    "{}; request panicked outside the WAF pipeline, answered 500",
                    hook_line(thread.name().unwrap_or("unnamed"), &caught.location),
                );
            }
            Ok(panic_response(&support_id))
        }
    }
}

// ---------------------------------------------------------------------------
// Test-only injection points
// ---------------------------------------------------------------------------

/// Request path that makes the pipeline panic before Phase 1, in test builds
/// only: the request tests need a real panic inside the real pipeline.
#[cfg(test)]
pub(crate) const INJECT_PANIC_PATH: &str = "/__panic_guard_test__";

#[cfg(test)]
pub(crate) fn inject_test_panic<B>(req: &http::Request<B>) {
    if req.uri().path() == INJECT_PANIC_PATH {
        panic!("injected test panic");
    }
}

/// Request path that panics in Phase 5, after the origin answered.
#[cfg(test)]
pub(crate) const INJECT_RESPONSE_PANIC_PATH: &str = "/__panic_guard_response__";

#[cfg(test)]
pub(crate) fn inject_response_panic(ctx: &RequestContext) {
    if ctx.uri.path() == INJECT_RESPONSE_PANIC_PATH {
        panic!("injected response-phase panic");
    }
}

/// The reason each contained request was given, by Support ID, so a test can
/// read what its own request's log records said.
#[cfg(test)]
static TEST_REASONS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

#[cfg(test)]
fn note_test_reason(ctx: &RequestContext, reason: &str) {
    lock(&TEST_REASONS).push((ctx.request_id.to_string(), reason.to_string()));
}

#[cfg(test)]
pub(crate) fn test_reason(support_id: &str) -> Option<String> {
    lock(&TEST_REASONS)
        .iter()
        .find(|(id, _)| id == support_id)
        .map(|(_, r)| r.clone())
}

/// Site whose first engine rebuild panics, in test builds only, so the
/// hot-reload watcher's restart is exercised against the real watcher.
#[cfg(test)]
pub(crate) const INJECT_REBUILD_PANIC_SITE: &str = "panic-guard-rebuild";

#[cfg(test)]
static REBUILD_PANICKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn inject_rebuild_panic(cfg: &sentinel_core::config::SentinelConfig) {
    let armed = cfg
        .sites
        .iter()
        .any(|s| s.id == INJECT_REBUILD_PANIC_SITE && !s.waf.rules.is_empty());
    if armed && !REBUILD_PANICKED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        panic!("injected engine-rebuild panic");
    }
}

/// An inline rule of this name makes compiling its SITE panic, every time, in
/// `compile`: after every inline rule was parsed and its diagnostic recorded,
/// as a compiler bug reached by the merged ruleset would.
#[cfg(test)]
pub(crate) const INJECT_COMPILE_PANIC_RULE: &str = "panic-guard-compile";

#[cfg(test)]
pub(crate) fn inject_compile_panic(site: &sentinel_core::config::SiteConfig) {
    if site
        .waf
        .inline_rules
        .iter()
        .any(|r| r.name == INJECT_COMPILE_PANIC_RULE)
    {
        panic!("injected rule-compile panic");
    }
}

/// An inline rule whose DSL contains this makes the SRL parser panic on it.
#[cfg(test)]
pub(crate) const INJECT_PARSE_PANIC_MARKER: &str = "__panic_guard_parse__";

#[cfg(test)]
pub(crate) fn inject_parse_panic(dsl: &str) {
    if dsl.contains(INJECT_PARSE_PANIC_MARKER) {
        panic!("injected rule-parse panic");
    }
}

/// A config-sync payload carrying a site with this id panics the sync loop
/// while it applies it, on every poll.
#[cfg(test)]
pub(crate) const INJECT_SYNC_PANIC_SITE: &str = "panic-guard-sync";

#[cfg(test)]
pub(crate) fn inject_sync_panic(sites: &[sentinel_core::config::SiteConfig]) {
    if sites.iter().any(|s| s.id == INJECT_SYNC_PANIC_SITE) {
        panic!("injected config-sync panic");
    }
}

// ---------------------------------------------------------------------------
// Background loops
// ---------------------------------------------------------------------------

/// How a supervised loop is restarted after a panic.
#[derive(Clone, Copy)]
pub(crate) struct RestartPolicy {
    /// First delay; doubles with each consecutive panic.
    pub(crate) min: Duration,
    /// Ceiling: a loop that panics deterministically retries about this often,
    /// instead of spinning a core and flooding the log.
    pub(crate) max: Duration,
    /// A run that lasted this long was healthy, so its panic restarts at `min`.
    pub(crate) reset_after: Duration,
}

pub(crate) const RESTART_POLICY: RestartPolicy = RestartPolicy {
    min: Duration::from_secs(1),
    max: Duration::from_secs(60),
    reset_after: Duration::from_secs(300),
};

/// The restart delay of one supervised loop, shared by the async and thread
/// supervisors so both follow the same 1 s → 60 s policy.
pub(crate) struct Backoff {
    policy: RestartPolicy,
    next: Duration,
}

impl Backoff {
    pub(crate) fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            next: policy.min,
        }
    }

    /// How long to wait before restarting a run that lasted `ran` and panicked.
    pub(crate) fn after_panic(&mut self, ran: Duration) -> Duration {
        if ran >= self.policy.reset_after {
            self.next = self.policy.min;
        }
        let delay = self.next;
        self.next = (self.next * 2).min(self.policy.max);
        delay
    }
}

/// Per-loop restart history, for `/healthz` and the heartbeat. Without it a
/// climbing `sentinel_task_restarts_total` did not say which loop was failing.
#[derive(Clone, Default)]
struct TaskRecord {
    restarts: u64,
    /// Unix seconds of the latest panic.
    last_at: u64,
    last_location: String,
    last_panic: String,
}

static TASKS: Mutex<BTreeMap<&'static str, TaskRecord>> = Mutex::new(BTreeMap::new());

/// A loop that restarted this recently keeps the node "degraded" in the
/// heartbeat. A crash-looping loop restarts at least every `RESTART_POLICY.max`,
/// so it stays degraded for as long as it keeps failing.
const RECENT_RESTART: Duration = Duration::from_secs(600);

/// Record that the background loop `name` panicked and is being restarted.
/// Returns how many times it has been.
pub(crate) fn note_task_panic(name: &'static str, location: &str, message: &str) -> u64 {
    sentinel_telemetry::note_task_restart();
    let mut tasks = lock(&TASKS);
    let t = tasks.entry(name).or_default();
    t.restarts += 1;
    t.last_at = unix_now();
    t.last_location = location.to_string();
    t.last_panic = message.to_string();
    t.restarts
}

/// Record and log a panic that a background loop caught itself, for a loop
/// whose state must outlive the run and so cannot use [`supervise`] (the SIEM
/// forwarder's queue). Returns how many times it has restarted.
pub(crate) fn task_panicked(name: &'static str, payload: &(dyn Any + Send)) -> u64 {
    let message = panic_message(payload);
    let location = take_panic_location();
    let restarts = note_task_panic(name, &location, &message);
    error!(
        task = name,
        location = %location,
        panic = %message,
        restarts,
        "background task panicked; restarting it"
    );
    restarts
}

/// The loop that restarted most recently within [`RECENT_RESTART`], if any.
pub(crate) fn recently_restarted() -> Option<&'static str> {
    let cutoff = unix_now().saturating_sub(RECENT_RESTART.as_secs());
    lock(&TASKS)
        .iter()
        .filter(|(_, t)| t.last_at >= cutoff)
        .max_by_key(|(_, t)| t.last_at)
        .map(|(name, _)| *name)
}

/// Spawn `make()`'s future as a background task and restart it, with backoff,
/// whenever it panics. A normal return ends the task. `on_panic`, if given, is
/// called with the redacted message on each panic, for a loop whose failure
/// has to be reported somewhere specific (config sync → its sync status).
///
/// The future runs inside the supervising task, not a child of it, so aborting
/// the returned handle stops the loop too (the listener shutdown relies on it).
/// [`supervised!`] is the usual way to call this.
pub(crate) fn supervise<F, Fut>(
    name: &'static str,
    on_panic: Option<fn(&str)>,
    make: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(run_supervised(name, make, RESTART_POLICY, on_panic))
}

async fn run_supervised<F, Fut>(
    name: &'static str,
    mut make: F,
    policy: RestartPolicy,
    on_panic: Option<fn(&str)>,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut backoff = Backoff::new(policy);
    loop {
        let started = Instant::now();
        match AssertUnwindSafe(make()).catch_unwind().await {
            Ok(()) => {
                debug!(task = name, "background task finished");
                return;
            }
            Err(payload) => {
                let delay = backoff.after_panic(started.elapsed());
                let message = panic_message(&*payload);
                let location = take_panic_location();
                let restarts = note_task_panic(name, &location, &message);
                error!(
                    task = name,
                    location = %location,
                    panic = %message,
                    restart_in_ms = delay.as_millis() as u64,
                    restarts,
                    "background task panicked; restarting it"
                );
                if let Some(report) = on_panic {
                    report(&message);
                }
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// [`supervise`] for a loop on a dedicated OS thread: run `run` on the current
/// thread, restarting it with the same backoff whenever it panics, until it
/// returns normally.
pub(crate) fn supervise_blocking(name: &'static str, run: impl FnMut()) {
    supervise_blocking_with(name, run, RESTART_POLICY)
}

fn supervise_blocking_with(name: &'static str, mut run: impl FnMut(), policy: RestartPolicy) {
    let mut backoff = Backoff::new(policy);
    loop {
        let started = Instant::now();
        let Err(payload) = std::panic::catch_unwind(AssertUnwindSafe(&mut run)) else {
            return;
        };
        let delay = backoff.after_panic(started.elapsed());
        let message = panic_message(&*payload);
        let location = take_panic_location();
        let restarts = note_task_panic(name, &location, &message);
        error!(
            task = name,
            location = %location,
            panic = %message,
            restart_in_ms = delay.as_millis() as u64,
            restarts,
            "background thread panicked; restarting it"
        );
        std::thread::sleep(delay);
    }
}

/// Spawn a background loop under [`supervise`]: a panic restarts it, with
/// backoff, instead of ending it for the life of the process.
///
/// ```ignore
/// panic_guard::supervised!("config sync", on_panic = |msg| report(msg), {
///     per_run!(sync_url, poll_cfg);
///     let mut ticker = tokio::time::interval(Duration::from_secs(5));
///     loop { /* ... */ }
/// });
/// ```
///
/// The body is written exactly as inside `tokio::spawn(async move { .. })`.
/// `on_panic = <fn(&str)>,` is optional (see [`supervise`]). `per_run!`, when
/// present, must be the body's first statement: it names the captured values
/// the loop moves in, and every run gets its own clone of them, because a
/// restarted loop cannot reuse what the run that panicked consumed. Forgetting
/// one is a compile error ("cannot move out of ... an `FnMut` closure"), never a
/// silent bug. A macro rather than a closure so each loop keeps its shape; the
/// closure form re-indents all of them.
macro_rules! supervised {
    ($name:expr, $(on_panic = $report:expr,)? { per_run!($($cap:ident),* $(,)?); $($body:tt)* }) => {
        $crate::panic_guard::supervise(
            $name,
            ::std::option::Option::<fn(&str)>::None $(.or(::std::option::Option::Some($report)))?,
            move || {
                $(
                    #[allow(unused_mut)]
                    let mut $cap = ::std::clone::Clone::clone(&$cap);
                )*
                async move { $($body)* }
            },
        )
    };
    ($name:expr, $(on_panic = $report:expr,)? { $($body:tt)* }) => {
        $crate::panic_guard::supervise(
            $name,
            ::std::option::Option::<fn(&str)>::None $(.or(::std::option::Option::Some($report)))?,
            move || async move { $($body)* },
        )
    };
}
pub(crate) use supervised;

/// Where a supervised run leaves the rows it held when it ended, for the next
/// run to resume (see [`Carried`]). Bounded, and each row is retried once.
pub(crate) struct Carry<T> {
    rows: Mutex<Vec<T>>,
    /// Most rows held between runs; the rest are shed.
    cap: usize,
    /// Told how many rows were shed: over `cap`, or back from a second panic.
    shed: fn(usize),
}

impl<T> Carry<T> {
    pub(crate) fn new(cap: usize, shed: fn(usize)) -> Arc<Self> {
        Arc::new(Self {
            rows: Mutex::new(Vec::new()),
            cap,
            shed,
        })
    }
}

/// Rows a background run holds in memory, handed back to its [`Carry`] when
/// the run ends — by a panic too — so the restarted run resumes with them.
///
/// The ClickHouse writer drains the shared buffers into its own vectors before
/// inserting or spooling them; a panic in between dropped those rows without
/// even counting them in `history_shed`, and the audit trail was silently
/// incomplete. If the panic came after ClickHouse had accepted a batch, the
/// batch is sent again: a duplicated row is visible, a missing one is not.
///
/// What is handed back is bounded twice. Rows this run resumed and still holds
/// when it panics as well are shed, not handed on again: a panic that repeats on
/// the same rows (one row whose content breaks the insert) retried them for
/// ever, and history stopped for the life of the process. And the carry holds at
/// most its `cap`: a writer panicking on every run added up to a full drain to
/// it each time, past the event buffer's bound and past the spool, until the
/// node was OOM-killed. Both are counted through `shed`.
pub(crate) struct Carried<T> {
    rows: Vec<T>,
    /// How many rows at the front of `rows` came from the carry. No `DerefMut`,
    /// so nothing but [`Carried::clear`] can move them.
    resumed: usize,
    carry: Arc<Carry<T>>,
}

impl<T> Carried<T> {
    /// Take over whatever the previous run left in `carry`.
    pub(crate) fn resume(carry: &Arc<Carry<T>>) -> Self {
        let rows = std::mem::take(&mut *lock(&carry.rows));
        Self {
            resumed: rows.len(),
            rows,
            carry: Arc::clone(carry),
        }
    }

    pub(crate) fn extend(&mut self, rows: impl IntoIterator<Item = T>) {
        self.rows.extend(rows);
    }

    /// Empty the buffer once its rows are stored or spooled. The resumed rows go
    /// with it, so a later panic in this run hands its new rows on in full.
    pub(crate) fn clear(&mut self) {
        self.rows.clear();
        self.resumed = 0;
    }
}

impl<T> std::ops::Deref for Carried<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.rows
    }
}

impl<T> Drop for Carried<T> {
    fn drop(&mut self) {
        // Rows that already came back once stay in `self.rows` and are dropped.
        let retried = self.resumed.min(self.rows.len());
        let mut fresh = self.rows.split_off(retried);
        let mut shed = retried;
        let mut held = lock(&self.carry.rows);
        let room = self.carry.cap.saturating_sub(held.len());
        if fresh.len() > room {
            shed += fresh.len() - room;
            fresh.truncate(room);
        }
        held.append(&mut fresh);
        drop(held);
        if shed > 0 {
            (self.carry.shed)(shed);
        }
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// What `/healthz` reports under `panics`. Node-local, so it carries each
/// loop's last location and message: the first things to chase.
pub(crate) fn status() -> serde_json::Value {
    let tasks: serde_json::Map<String, serde_json::Value> = lock(&TASKS)
        .iter()
        .map(|(name, t)| {
            (
                (*name).to_string(),
                serde_json::json!({
                    "restarts": t.restarts,
                    "last_at": t.last_at,
                    "last_location": t.last_location,
                    "last_panic": t.last_panic,
                }),
            )
        })
        .collect();
    serde_json::json!({
        "total": sentinel_telemetry::panics_total(),
        "requests_contained": sentinel_telemetry::request_panics_total(),
        "task_restarts": sentinel_telemetry::task_restarts_total(),
        "restarting": recently_restarted(),
        "tasks": tasks,
    })
}

/// What the heartbeat reports under `panics`: the counts and which loops
/// restarted, without locations or messages. Those are source paths that carry
/// the crate codename, and the heartbeat feeds the console; they are on
/// `/healthz` and in the node's log.
pub(crate) fn heartbeat_status() -> serde_json::Value {
    let tasks: serde_json::Map<String, serde_json::Value> = lock(&TASKS)
        .iter()
        .map(|(name, t)| {
            (
                (*name).to_string(),
                serde_json::json!({ "restarts": t.restarts, "last_at": t.last_at }),
            )
        })
        .collect();
    serde_json::json!({
        "total": sentinel_telemetry::panics_total(),
        "requests_contained": sentinel_telemetry::request_panics_total(),
        "task_restarts": sentinel_telemetry::task_restarts_total(),
        "restarting": recently_restarted(),
        "tasks": tasks,
    })
}

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

/// A real `ProxyServer` against a counting mock origin, for the tests here and
/// in `http3`.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use sentinel_core::config::{
        InlineRule, ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig,
        UpstreamConfig, UpstreamServer, WafConfig, WafMode,
    };

    /// Serialises tests that run a `ProxyServer` or read the process-global
    /// proxy state it writes (inline-rule diagnostics, compile failures, sync
    /// status, `ENGINES_WARMING`). Every server start rebuilds the engines,
    /// which resets those globals under any test reading them concurrently.
    pub(crate) fn proxy_state_lock() -> MutexGuard<'static, ()> {
        lock(&crate::inline_rule_diag_tests::DIAG_TEST_LOCK)
    }

    /// Mock origin that counts what reaches it.
    pub(crate) async fn counting_origin() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |_req| {
                        counter.fetch_add(1, Ordering::SeqCst);
                        async {
                            Ok::<_, Infallible>(Response::new(http_body_util::Full::new(
                                Bytes::from_static(b"origin ok"),
                            )))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (addr, hits)
    }

    pub(crate) fn site(
        id: &str,
        domain: &str,
        origin: SocketAddr,
        rules: Vec<String>,
        inline_rules: Vec<InlineRule>,
    ) -> SiteConfig {
        SiteConfig {
            id: id.into(),
            tenant_id: String::new(),
            domains: vec![domain.into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: origin.port(),
                    weight: 1,
                    tls: false,
                }],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: WafConfig {
                mode: WafMode::Blocking,
                rules,
                inline_rules,
                anomaly_threshold: 5,
                paranoia_level: 2,
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    pub(crate) fn listener(listen: SocketAddr, default_site: Option<&str>) -> ListenerConfig {
        ListenerConfig {
            name: "panic-test".into(),
            bind: listen.to_string(),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: default_site.map(str::to_string),
            role: Default::default(),
            proxy_protocol: false,
        }
    }

    /// One plain-HTTP listener serving one site at `panic-site.local`.
    pub(crate) fn site_config(
        listen: SocketAddr,
        origin: SocketAddr,
        site_id: &str,
        rules: Vec<String>,
    ) -> SentinelConfig {
        SentinelConfig {
            listeners: vec![listener(listen, Some(site_id))],
            sites: vec![site(site_id, "panic-site.local", origin, rules, vec![])],
            ..Default::default()
        }
    }

    /// The CRS SQL-injection rule file, for a site that must block something.
    pub(crate) fn crs_sqli() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
            .to_string_lossy()
            .into_owned()
    }

    pub(crate) type Sender = hyper::client::conn::http1::SendRequest<http_body_util::Empty<Bytes>>;

    pub(crate) async fn get_host(
        sender: &mut Sender,
        host: &str,
        path: &str,
    ) -> (StatusCode, Bytes) {
        let req = http::Request::get(path)
            .header(header::HOST, host)
            .body(http_body_util::Empty::new())
            .unwrap();
        let resp = sender.send_request(req).await.expect("response");
        let status = resp.status();
        (status, resp.into_body().collect().await.unwrap().to_bytes())
    }

    pub(crate) async fn get(sender: &mut Sender, path: &str) -> (StatusCode, Bytes) {
        get_host(sender, "panic-site.local", path).await
    }

    pub(crate) async fn connect(addr: SocketAddr) -> Sender {
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        sender
    }

    pub(crate) fn free_port() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    }

    pub(crate) fn config_handle(cfg: SentinelConfig) -> sentinel_core::ConfigHandle {
        Arc::new(arc_swap::ArcSwap::new(Arc::new(cfg)))
    }

    pub(crate) struct RunningProxy {
        shutdown: tokio::sync::watch::Sender<bool>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl RunningProxy {
        pub(crate) async fn stop(self) {
            let _ = self.shutdown.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(30), self.task).await;
        }
    }

    pub(crate) async fn start_proxy(
        listen: SocketAddr,
        handle: sentinel_core::ConfigHandle,
    ) -> RunningProxy {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(crate::ProxyServer::new(handle).run(shutdown_rx));
        let deadline = Instant::now() + Duration::from_secs(30);
        while tokio::net::TcpStream::connect(listen).await.is_err() {
            assert!(!task.is_finished(), "proxy exited before binding");
            assert!(Instant::now() < deadline, "proxy never bound {listen}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        RunningProxy { shutdown, task }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::BodyExt as _;
    use sentinel_core::config::{InlineRule, SentinelConfig};

    // -- messages -----------------------------------------------------------

    #[test]
    fn a_sliced_request_value_never_reaches_the_log() {
        // The exact shape std produces for a bad str slice: the operand — here a
        // session cookie — sits between backticks.
        let msg = String::from(
            "byte index 7 is not a char boundary; it is inside 'é' (bytes 6..8) of \
             `session=s3cr3t-t0ken-value`",
        );
        let logged = panic_message(&msg);
        assert!(!logged.contains("s3cr3t"), "{logged}");
        assert!(logged.contains("not a char boundary"), "{logged}");
        assert!(logged.ends_with("of `<redacted>"), "{logged}");
    }

    /// The operand is request data and can hold backticks of its own. Pairing
    /// backticks put everything after the operand's first one back on the log:
    /// `{"q":"it`s é","password":"hunter2"}` came out with the password intact.
    #[test]
    fn backticks_inside_the_operand_cannot_unredact_the_rest() {
        for operand in [
            r#"{"q":"it`s é","password":"hunter2"}"#,
            "ab`sessionid=hunter2",
            "x`y`sessionid=hunter2",
            "``hunter2``",
        ] {
            let msg = format!(
                "byte index 9 is not a char boundary; it is inside 'é' (bytes 8..10) of `{operand}`"
            );
            let logged = panic_message(&msg);
            assert!(!logged.contains("hunter2"), "{operand:?} → {logged}");
            assert!(logged.ends_with("of `<redacted>"), "{operand:?} → {logged}");
        }
        let slicing = "begin <= end (4 <= 2) when slicing `a`b password=hunter2`";
        assert_eq!(
            panic_message(&slicing),
            "begin <= end (4 <= 2) when slicing `<redacted>"
        );
    }

    #[test]
    fn std_terms_survive_and_unpaired_backticks_redact_the_rest() {
        let unwrap = "called `Option::unwrap()` on a `None` value";
        assert_eq!(panic_message(&unwrap), unwrap);
        let result = "called `Result::unwrap()` on an `Err` value: Timeout";
        assert_eq!(panic_message(&result), result);
        assert_eq!(panic_message(&"ok `then dangling"), "ok `<redacted>");
        // An error's Debug output is not std's text: its spans are redacted.
        let quoted = "called `Result::unwrap()` on an `Err` value: Bad(\"`tok`=hunter2\")";
        assert_eq!(
            panic_message(&quoted),
            "called `Result::unwrap()` on an `Err` value: Bad(\"`<redacted>"
        );
    }

    /// std's terms were recognised in ANY backtick span, the operand's own
    /// first one included, so an operand starting with one ("None`", "Ok`")
    /// flipped the span pairing and the rest of it was logged in clear:
    /// "… of `None`session=s3cr3t é`<redacted>". Real std slice panics here,
    /// not hand-written messages.
    #[test]
    fn an_operand_starting_with_a_std_term_stays_redacted() {
        for operand in [
            "None`session=s3cr3t é",
            "Ok`password=s3cr3t é",
            "Err`token=s3cr3t é",
            "Option::unwrap()`sid=s3cr3t é",
            "called `Option::unwrap()` on a `None` value`k=s3cr3t é",
        ] {
            let s = operand.to_string();
            // Inside the trailing 'é', as a parser slicing request data would.
            let cut = s.len() - 1;
            let payload = std::panic::catch_unwind(|| s[..cut].len()).unwrap_err();
            let logged = panic_message(&*payload);
            assert!(!logged.contains("s3cr3t"), "{operand:?} → {logged}");
            assert!(logged.ends_with("of `<redacted>"), "{operand:?} → {logged}");
        }
    }

    #[test]
    fn messages_are_capped_and_odd_payloads_named() {
        let long = "x".repeat(10_000);
        let logged = panic_message(&long);
        assert!(
            logged.chars().count() <= PANIC_MESSAGE_MAX + 1,
            "{}",
            logged.len()
        );
        assert_eq!(panic_message(&42_u32), "non-string panic payload");
    }

    /// Records the fields of every event, for asserting what the hook logged.
    struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields<'a>(&'a mut BTreeMap<String, String>);
            impl tracing::field::Visit for Fields<'_> {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    self.0.insert(f.name().to_string(), format!("{v:?}"));
                }
            }
            let mut fields = BTreeMap::new();
            event.record(&mut Fields(&mut fields));
            lock(&self.0).push(fields);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Run `f` (which panics) under a capturing subscriber; return the hook's line.
    fn hook_event(force_backtrace: bool, f: fn()) -> BTreeMap<String, String> {
        install_panic_hook();
        let events = Arc::new(Mutex::new(Vec::new()));
        let dispatch = tracing::Dispatch::new(Capture(Arc::clone(&events)));
        FORCE_BACKTRACE.with(|c| c.set(Some(force_backtrace)));
        tracing::dispatcher::with_default(&dispatch, || {
            assert!(std::panic::catch_unwind(f).is_err());
        });
        FORCE_BACKTRACE.with(|c| c.set(None));
        let events = lock(&events);
        events
            .iter()
            .find(|e| e.get("message").is_some_and(|m| m.contains("panicked at")))
            .cloned()
            .expect("the hook logged the panic")
    }

    /// With panics contained the node keeps running, so the stack is the main
    /// clue left — and the replaced hook had dropped it: RUST_BACKTRACE=1, set
    /// in the systemd unit and the dev scripts, produced nothing.
    #[test]
    fn the_hook_logs_the_backtrace_when_one_is_enabled() {
        fn background_bug() {
            panic!("hook backtrace test");
        }
        let line = hook_event(true, background_bug);
        let bt = line.get("backtrace").expect("a backtrace field");
        assert!(bt.contains("background_bug"), "{bt}");
        assert_eq!(
            line.get("panic").map(String::as_str),
            Some("hook backtrace test")
        );
        assert!(line
            .get("location")
            .is_some_and(|l| l.contains("panic_guard.rs")));

        let line = hook_event(false, background_bug);
        assert!(
            !line.contains_key("backtrace"),
            "none unless enabled: {line:?}"
        );
    }

    /// deploy/docker/verify-deploy.sh counts panics with this pattern; the
    /// structured line must still match it, or a panicking roll reads clean.
    #[test]
    fn the_hook_line_still_matches_the_deploy_check() {
        let line = hook_line("sentinel-worker", "crates/x/src/lib.rs:1:2");
        let rest = line.strip_prefix("thread '").expect(&line);
        let (thread, tail) = rest.split_once('\'').expect(&line);
        assert!(
            !thread.is_empty() && tail.starts_with(" panicked"),
            "{line}"
        );
    }

    /// A client replaying a panicking input got two ERROR lines per request;
    /// now it gets one per location per second, and the next says how many
    /// were skipped.
    #[test]
    fn request_panic_lines_are_rate_limited_per_location() {
        let mut lines = BTreeMap::new();
        let t0 = Instant::now();
        assert_eq!(
            throttle_in(&mut lines, "a.rs:1:1", t0),
            LogLine::Due { suppressed: 0 }
        );
        for ms in [1, 10, 500, 999] {
            assert_eq!(
                throttle_in(&mut lines, "a.rs:1:1", t0 + Duration::from_millis(ms)),
                LogLine::Suppressed
            );
        }
        // Another location is not held back by the first.
        assert_eq!(
            throttle_in(&mut lines, "b.rs:2:2", t0 + Duration::from_millis(5)),
            LogLine::Due { suppressed: 0 }
        );
        assert_eq!(
            throttle_in(&mut lines, "a.rs:1:1", t0 + Duration::from_millis(1000)),
            LogLine::Due { suppressed: 4 }
        );
        assert_eq!(
            throttle_in(&mut lines, "a.rs:1:1", t0 + Duration::from_millis(2500)),
            LogLine::Due { suppressed: 0 }
        );
    }

    /// The guard marks the thread so the hook only counts; the mark is per
    /// poll and nests.
    #[test]
    fn the_request_mark_nests_and_clears() {
        assert!(!IN_REQUEST.with(Cell::get));
        {
            let _outer = InRequest::enter();
            {
                let _inner = InRequest::enter();
                assert!(IN_REQUEST.with(Cell::get));
            }
            assert!(IN_REQUEST.with(Cell::get), "the outer guard still holds");
        }
        assert!(!IN_REQUEST.with(Cell::get));
    }

    // -- requests -----------------------------------------------------------

    /// Every request panic was recorded as "not forwarded", including one in
    /// the response-body rules or DLP scan, after the origin had executed it.
    #[test]
    fn the_reason_says_whether_the_origin_saw_the_request() {
        let mut ctx = RequestContext::new("192.0.2.1".parse().unwrap(), 1);
        ctx.advance_phase(Phase::RequestBody);
        assert_eq!(Forwarded::of(&ctx), Forwarded::No);
        ctx.advance_phase(Phase::Upstream);
        assert_eq!(Forwarded::of(&ctx), Forwarded::Possibly);
        ctx.upstream_latency_us = Some(1200);
        for phase in [Phase::ResponseHeaders, Phase::ResponseBody, Phase::Logging] {
            ctx.advance_phase(phase.clone());
            assert_eq!(Forwarded::of(&ctx), Forwarded::Yes, "{phase}");
        }
        // A blocked request whose logging panicked never left the node.
        let mut blocked = RequestContext::new("192.0.2.1".parse().unwrap(), 1);
        blocked.advance_phase(Phase::Logging);
        assert_eq!(Forwarded::of(&blocked), Forwarded::No);

        for f in [Forwarded::No, Forwarded::Possibly, Forwarded::Yes] {
            assert!(f.reason().starts_with(REQUEST_PANIC_PREFIX), "{f:?}");
            ctx.gateway_error = Some(f.reason().to_string());
            assert!(is_contained_panic(&ctx));
        }
        assert!(Forwarded::No.reason().contains("not forwarded"));
        assert!(Forwarded::Yes.reason().contains("reached the origin"));
        assert!(!Forwarded::Yes.reason().contains("not forwarded"));
        ctx.gateway_error = Some("upstream request failed: connection refused".into());
        assert!(
            !is_contained_panic(&ctx),
            "a real gateway error stays GATEWAY"
        );
    }

    /// Contained panics were filed in waf.log as GATEWAY / "Upstream or
    /// routing failure", sending whoever read it to look at a healthy origin.
    #[test]
    fn a_contained_panic_has_its_own_waf_log_label() {
        let mut ctx = RequestContext::new("192.0.2.1".parse().unwrap(), 1);
        for f in [Forwarded::No, Forwarded::Possibly, Forwarded::Yes] {
            ctx.gateway_error = Some(f.reason().to_string());
            assert_eq!(
                crate::nonrule_label(&ctx),
                ("INTERNAL", "Internal processing failure")
            );
        }
        ctx.gateway_error = Some("upstream request failed: connection refused".into());
        assert_eq!(
            crate::nonrule_label(&ctx),
            ("GATEWAY", "Upstream or routing failure")
        );
    }

    #[tokio::test]
    async fn a_panic_outside_the_pipeline_is_a_500_with_a_support_id() {
        let before = sentinel_telemetry::request_panics_total();
        let peer: SocketAddr = "198.51.100.4:5000".parse().unwrap();
        let resp = contain_request(peer, async {
            if peer.port() == 5000 {
                panic!("management route bug");
            }
            Ok(panic_response("unreachable"))
        })
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = json["support_id"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(id).is_ok(), "{json}");
        assert!(!String::from_utf8_lossy(&body).contains("management route bug"));
        assert!(sentinel_telemetry::request_panics_total() > before);
    }

    /// The whole point of unwinding: a request that panics the pipeline costs
    /// that request a 500 with its Support ID — not the connection, not the
    /// listener, not the node — and it never reaches the origin.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_panicking_request_gets_a_500_and_the_listener_keeps_serving() {
        let _serial = proxy_state_lock();
        install_panic_hook();
        let panics_before = sentinel_telemetry::panics_total();
        let contained_before = sentinel_telemetry::request_panics_total();

        let (origin, hits) = counting_origin().await;
        let listen = free_port();
        let handle = config_handle(site_config(listen, origin, "panic-site", vec![]));
        let proxy = start_proxy(listen, handle).await;

        let mut conn = connect(listen).await;
        let (status, body) = get(&mut conn, INJECT_PANIC_PATH).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let support_id = json["support_id"].as_str().expect("support id in the 500");
        assert!(uuid::Uuid::parse_str(support_id).is_ok(), "{json}");
        assert!(
            !String::from_utf8_lossy(&body).contains("injected"),
            "the panic message must not reach the client"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a request that panicked before Phase 3 is never forwarded"
        );
        let reason = test_reason(support_id).expect("the request was logged");
        assert!(reason.contains("not forwarded"), "{reason}");

        // Same keep-alive connection: still alive, still proxying.
        let (status, body) = get(&mut conn, "/after-the-panic").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"origin ok");
        // And the listener still accepts new connections.
        let mut fresh = connect(listen).await;
        let (status, _) = get(&mut fresh, "/new-connection").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        assert!(sentinel_telemetry::request_panics_total() > contained_before);
        assert!(
            sentinel_telemetry::panics_total() > panics_before,
            "the hook counts it"
        );

        drop(conn);
        drop(fresh);
        proxy.stop().await;
    }

    /// A panic in the response-body phase comes AFTER the origin executed the
    /// request. It used to be recorded as "answered 500 and not forwarded" —
    /// for a SQL injection that passed the request rules, an audit trail
    /// saying the attack never reached the application.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_panic_after_the_origin_answered_is_recorded_as_forwarded() {
        let _serial = proxy_state_lock();
        install_panic_hook();
        let (origin, hits) = counting_origin().await;
        let listen = free_port();
        let handle = config_handle(site_config(listen, origin, "panic-site", vec![]));
        let proxy = start_proxy(listen, handle).await;

        let mut conn = connect(listen).await;
        let (status, body) = get(&mut conn, INJECT_RESPONSE_PANIC_PATH).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !String::from_utf8_lossy(&body).contains("origin ok"),
            "the origin's response is discarded"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the origin did see it");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let support_id = json["support_id"].as_str().expect("support id in the 500");
        let reason = test_reason(support_id).expect("the request was logged");
        assert!(reason.contains("reached the origin"), "{reason}");
        assert!(!reason.contains("not forwarded"), "{reason}");

        let (status, _) = get(&mut conn, "/after").await;
        assert_eq!(status, StatusCode::OK, "and the connection keeps serving");

        drop(conn);
        proxy.stop().await;
    }

    /// The hot-reload watcher was the one loop that already had a restart, and
    /// it never ran: under panic=abort the process died first. Run for real, it
    /// restarted from "the current config is built", so the rebuild that
    /// panicked was never retried — the site that triggered it stayed without an
    /// engine, refused with 503, until some unrelated config change came along.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_panicked_engine_rebuild_is_retried_after_the_restart() {
        let _serial = proxy_state_lock();
        let restarts_before = sentinel_telemetry::task_restarts_total();
        let (origin, _hits) = counting_origin().await;
        let listen = free_port();
        let unruled = site_config(listen, origin, INJECT_REBUILD_PANIC_SITE, vec![]);
        let handle = config_handle(unruled.clone());
        let proxy = start_proxy(listen, handle.clone()).await;
        let mut conn = connect(listen).await;
        assert_eq!(get(&mut conn, "/before").await.0, StatusCode::OK);

        // Give the site rules, as a reload would. Its first rebuild panics.
        let mut ruled = unruled;
        ruled.sites[0].waf.rules = vec![crs_sqli()];
        handle.store(Arc::new(ruled));

        // Refused (no engine yet) until a rebuild succeeds: 5s watcher tick,
        // the panic, a 1s restart delay, another tick, then the compile.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (status, _) = get(&mut conn, "/clean").await;
            if status == StatusCode::OK {
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "refused until built"
            );
            assert!(
                Instant::now() < deadline,
                "the restarted watcher never rebuilt the engines it panicked on"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(REBUILD_PANICKED.load(std::sync::atomic::Ordering::SeqCst));
        assert!(sentinel_telemetry::task_restarts_total() > restarts_before);
        let (status, _) = get(&mut conn, "/search?q=1%27%20OR%201%3D1--").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the rebuilt engine is enforcing"
        );

        drop(conn);
        proxy.stop().await;
    }

    /// One site whose rules panic the compiler — every time — used to unwind out
    /// of the whole rebuild. The watcher then replayed the same config forever:
    /// no later change applied to ANY site, `ENGINES_WARMING` never cleared (so
    /// every new site was refused 503), and the heartbeat called the node
    /// healthy on the current version. Now the panic costs that site only, as a
    /// parse error does: it keeps its last-good rules, and the console is told.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_site_whose_rules_panic_the_compiler_costs_only_that_site() {
        let _serial = proxy_state_lock();
        let (origin, _hits) = counting_origin().await;
        let listen = free_port();
        let v1 = SentinelConfig {
            listeners: vec![listener(listen, None)],
            sites: vec![
                site("compile-a", "a.local", origin, vec![crs_sqli()], vec![]),
                site("compile-b", "b.local", origin, vec![], vec![]),
            ],
            ..Default::default()
        };
        let handle = config_handle(v1.clone());
        let proxy = start_proxy(listen, handle.clone()).await;
        let mut conn = connect(listen).await;
        let sqli = "/search?q=1%27%20OR%201%3D1--";
        assert_eq!(
            get_host(&mut conn, "a.local", sqli).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_host(&mut conn, "b.local", "/?x=GOODMARKER").await.0,
            StatusCode::OK
        );

        // v2: A's rules now panic the compiler; B gains a rule of its own.
        let mut v2 = v1;
        // The rule itself parses, so the inline loop records it as enforced
        // before the compile panics.
        v2.sites[0].waf.inline_rules = vec![InlineRule {
            name: INJECT_COMPILE_PANIC_RULE.into(),
            dsl: r#"
rule 9990103 {
    phase    : request_headers
    targets  : ARGS
    operator : rx /AMARKER/
    action   : block
    severity : critical
    message  : "a marker"
}
"#
            .into(),
        }];
        v2.sites[1].waf.inline_rules = vec![InlineRule {
            name: "b-marker".into(),
            dsl: r#"
rule 9990101 {
    phase    : request_headers
    targets  : ARGS
    operator : rx /GOODMARKER/
    action   : block
    severity : critical
    message  : "b marker"
}
"#
            .into(),
        }];
        // As config sync does: warming first, then publish.
        crate::ENGINES_WARMING.store(true, std::sync::atomic::Ordering::Release);
        handle.store(Arc::new(v2));

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (status, _) = get_host(&mut conn, "b.local", "/?x=GOODMARKER").await;
            if status == StatusCode::FORBIDDEN {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "site B's new rule never applied (last status {status}): the panic in site A's \
                 compile stalled the rebuild for every site"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            !crate::ENGINES_WARMING.load(std::sync::atomic::Ordering::Acquire),
            "the rebuild completed, so warming must clear"
        );
        assert_eq!(
            get_host(&mut conn, "a.local", sqli).await.0,
            StatusCode::FORBIDDEN,
            "site A keeps its last-good rules"
        );
        let rejected = crate::config_sync_status().rejected_sites;
        let a = rejected
            .iter()
            .find(|r| r.id == "compile-a")
            .expect("the heartbeat's sync status names the site");
        assert!(a.kept_previous, "{a:?}");
        assert!(a.error.contains("crashed the rule compiler"), "{a:?}");
        assert!(!a.error.contains("sentinel"), "console text: {a:?}");
        // The rule row agrees: the rule parsed, but its site kept the old rules.
        let diag = crate::inline_rule_diag_snapshot()
            .into_iter()
            .find(|d| d.name == INJECT_COMPILE_PANIC_RULE)
            .expect("the rule is reported");
        assert!(
            !diag.enforced,
            "the console was told the rule is enforced: {diag:?}"
        );
        assert_eq!(
            get_host(&mut conn, "a.local", "/?x=AMARKER").await.0,
            StatusCode::OK,
            "and indeed it is not"
        );

        drop(conn);
        proxy.stop().await;
        crate::ENGINES_WARMING.store(false, std::sync::atomic::Ordering::Release);
    }

    /// A site whose engine did not build enforces none of its inline rules,
    /// however each one parsed. The inline loop had already recorded them as
    /// enforced when `compile` panicked (and when a rule file failed before the
    /// loop, they were not reported at all), so the console's rule row said
    /// "enforced" while the site ran its previous rules, or none.
    #[test]
    fn inline_rules_of_a_site_that_did_not_compile_are_not_enforced() {
        let _serial = proxy_state_lock();
        let good = |name: &str, id: u32| InlineRule {
            name: name.into(),
            dsl: format!(
                r#"
rule {id} {{
    phase    : request_headers
    targets  : ARGS
    operator : rx /DIAGMARKER/
    action   : block
    severity : critical
    message  : "diag"
}}
"#
            ),
        };
        let bad = InlineRule {
            name: "kept-bad".into(),
            dsl: "rule nope { totally invalid (((".into(),
        };
        let origin: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // v1 compiles, so v2's panicking site has a previous engine to keep.
        let v1 = SentinelConfig {
            sites: vec![site(
                "diag-kept",
                "kept.local",
                origin,
                vec![],
                vec![good("kept-ok", 9990104)],
            )],
            ..Default::default()
        };
        let previous = crate::build_rule_engines(&v1, &crate::RuleEngineMap::new());
        assert!(previous.contains_key("diag-kept"), "precondition");
        let v2 = SentinelConfig {
            sites: vec![
                site(
                    "diag-kept",
                    "kept.local",
                    origin,
                    vec![],
                    vec![
                        good("kept-ok", 9990104),
                        bad,
                        good(INJECT_COMPILE_PANIC_RULE, 9990105),
                    ],
                ),
                site(
                    "diag-none",
                    "none.local",
                    origin,
                    vec!["/nonexistent/panic-guard/rules.conf".into()],
                    vec![good("none-ok", 9990106)],
                ),
                site(
                    "diag-fine",
                    "fine.local",
                    origin,
                    vec![],
                    vec![good("fine-ok", 9990107)],
                ),
            ],
            ..Default::default()
        };
        let built = crate::build_rule_engines(&v2, &previous);
        assert!(built.contains_key("diag-kept"), "kept its previous engine");
        assert!(!built.contains_key("diag-none"), "no engine at all");

        let diags = crate::inline_rule_diag_snapshot();
        let get = |name: &str| {
            diags
                .iter()
                .find(|d| d.name == name)
                .cloned()
                .unwrap_or_else(|| panic!("{name} not reported: {diags:?}"))
        };
        for (name, consequence) in [
            ("kept-ok", "previous rules"),
            (INJECT_COMPILE_PANIC_RULE, "previous rules"),
            ("none-ok", "no rules on this node"),
        ] {
            let d = get(name);
            assert!(!d.enforced, "the console is told {name} is enforced: {d:?}");
            let err = d.error.unwrap_or_default();
            assert!(err.contains("did not compile"), "{name}: {err}");
            assert!(err.contains(consequence), "{name}: {err}");
            assert!(!err.contains("sentinel"), "console text: {err}");
        }
        let kept_bad = get("kept-bad").error.unwrap_or_default();
        assert!(
            kept_bad.contains("does not parse"),
            "a rule's own failure keeps its own reason: {kept_bad}"
        );
        assert!(get("fine-ok").enforced, "another site's rule is unaffected");
        crate::reset_inline_rule_diags();
    }

    /// An operator's rule is text typed into a web form, which is exactly what
    /// finds a parser bug. A panic parsing one rule now costs that rule only,
    /// reported to the console like a parse error.
    #[test]
    fn an_inline_rule_that_panics_the_parser_costs_only_itself() {
        let _serial = proxy_state_lock();
        crate::reset_inline_rule_diags();
        let good = r#"
rule 9990102 {
    phase    : request_body
    targets  : ARGS
    operator : rx /GOODMARKER/
    action   : block
    severity : critical
    message  : "ok"
}
"#;
        let s = site(
            "parse-panic",
            "parse-panic.local",
            "127.0.0.1:1".parse().unwrap(),
            vec![],
            vec![
                InlineRule {
                    name: "crashes-the-parser".into(),
                    dsl: format!("# {INJECT_PARSE_PANIC_MARKER}\n"),
                },
                InlineRule {
                    name: "parses-fine".into(),
                    dsl: good.into(),
                },
            ],
        );
        let engine = crate::load_site_engine(&s).expect("the site still compiles");
        assert_eq!(engine.rule_count(), 1, "the good rule is enforced");
        let diags = crate::inline_rule_diag_snapshot();
        let crashed = diags
            .iter()
            .find(|d| d.name == "crashes-the-parser")
            .expect("reported");
        assert!(!crashed.enforced);
        assert!(
            crashed
                .error
                .as_deref()
                .unwrap_or("")
                .contains("crashed the rule parser"),
            "{:?}",
            crashed.error
        );
        assert!(diags.iter().any(|d| d.name == "parses-fine" && d.enforced));
        crate::reset_inline_rule_diags();
    }

    /// A fake control plane: serves `config` and records every heartbeat.
    async fn fake_control_plane(
        config: serde_json::Value,
    ) -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let beats: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
        let seen = Arc::clone(&beats);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let seen = Arc::clone(&seen);
                let config = config.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(
                        move |req: http::Request<hyper::body::Incoming>| {
                            let seen = Arc::clone(&seen);
                            let config = config.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let (status, out) = match path.as_str() {
                                    "/api/v1/internal/config" => {
                                        (StatusCode::OK, config.to_string())
                                    }
                                    "/api/v1/internal/nodes/heartbeat" => {
                                        if let Ok(v) = serde_json::from_slice(&body) {
                                            lock(&seen).push(v);
                                        }
                                        (StatusCode::OK, "{}".to_string())
                                    }
                                    _ => (StatusCode::NOT_FOUND, "{}".to_string()),
                                };
                                let mut resp =
                                    Response::new(http_body_util::Full::new(Bytes::from(out)));
                                *resp.status_mut() = status;
                                Ok::<_, Infallible>(resp)
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (url, beats)
    }

    /// A crash-looping config sync was visible only on node-local /healthz:
    /// it never recorded a sync failure (so the console's REJECTING badge
    /// could not fire), the heartbeat carried no panic data, and the node kept
    /// reporting "healthy" while it took no config at all.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_crash_looping_config_sync_reaches_the_heartbeat() {
        let _serial = proxy_state_lock();
        crate::note_config_sync_ok();
        let (origin, _hits) = counting_origin().await;
        let (cp, beats) = fake_control_plane(serde_json::json!({
            "version": 7,
            "sites": [{
                "id": INJECT_SYNC_PANIC_SITE,
                "domains": ["sync.local"],
                "upstream": { "servers": [{ "host": "127.0.0.1", "port": 1 }] },
            }],
        }))
        .await;
        let listen = free_port();
        let mut cfg = site_config(listen, origin, "panic-site", vec![]);
        cfg.cluster.sync_url = Some(cp);
        cfg.cluster.sync_interval_secs = 1;
        cfg.cluster.node_id = "panic-guard-node".into();
        let proxy = start_proxy(listen, config_handle(cfg)).await;

        // The first poll panics while applying; the sync status says so.
        let deadline = Instant::now() + Duration::from_secs(20);
        let first_failure = loop {
            let st = crate::config_sync_status();
            if let (Some(err), Some(since)) = (st.last_error, st.failing_since) {
                assert!(err.contains("config sync crashed"), "{err}");
                assert!(!err.contains("sentinel"), "console text: {err}");
                break since;
            }
            assert!(
                Instant::now() < deadline,
                "the crash never reached the sync status"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // A restarted run fetches successfully before it crashes again; that
        // fetch must not report the sync healthy, or the failure never lasts
        // long enough for the console to call it.
        let restarts = || {
            lock(&TASKS)
                .get("config sync")
                .map(|t| t.restarts)
                .unwrap_or(0)
        };
        let before = restarts();
        while restarts() < before + 2 {
            assert!(Instant::now() < deadline, "the sync loop was not restarted");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let st = crate::config_sync_status();
        assert!(
            st.last_error.is_some(),
            "cleared by the restarted run's fetch"
        );
        assert_eq!(
            st.failing_since,
            Some(first_failure),
            "still failing since the first crash"
        );

        // And the heartbeat (every 10 s) reports a degraded node, naming the loop.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let beat = lock(&beats).last().cloned();
            if let Some(b) = beat.filter(|b| {
                b["metadata"]["panics"]["tasks"]["config sync"]["restarts"]
                    .as_u64()
                    .is_some_and(|n| n >= 1)
            }) {
                assert_eq!(b["status"], "degraded", "{b}");
                assert!(
                    b["metadata"]["config_sync"]["last_error"].is_string(),
                    "{b}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no heartbeat reported the crashing loop: {:?}",
                lock(&beats).last()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        proxy.stop().await;
        crate::note_config_sync_ok();
    }

    // -- poisoned locks -------------------------------------------------------

    /// A poisoned sync-status lock used to be skipped: failures stopped being
    /// recorded and the heartbeat kept reporting a healthy sync while this node
    /// stopped taking config.
    #[test]
    fn config_sync_status_survives_a_poisoned_lock() {
        let _serial = proxy_state_lock();
        let _ = std::thread::spawn(|| {
            let _held = crate::CONFIG_SYNC_STATUS.lock().unwrap();
            panic!("poisoning the sync status on purpose");
        })
        .join();
        assert!(
            crate::CONFIG_SYNC_STATUS.is_poisoned(),
            "fixture must poison the lock"
        );

        crate::note_config_sync_failure("fetch: connection refused".to_string());
        let st = crate::config_sync_status();
        assert_eq!(st.last_error.as_deref(), Some("fetch: connection refused"));
        assert!(st.failing_since.is_some());
        crate::note_config_sync_ok();
        assert!(crate::config_sync_status().last_error.is_none());
        crate::CONFIG_SYNC_STATUS.clear_poison();
    }

    // -- background loops -----------------------------------------------------

    const FAST: RestartPolicy = RestartPolicy {
        min: Duration::from_millis(20),
        max: Duration::from_millis(40),
        reset_after: Duration::from_secs(60),
    };

    #[test]
    fn backoff_doubles_to_the_ceiling_and_resets_after_a_healthy_run() {
        let mut b = Backoff::new(RESTART_POLICY);
        let quick = Duration::from_millis(5);
        let delays: Vec<u64> = (0..8).map(|_| b.after_panic(quick).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(
            b.after_panic(Duration::from_secs(301)),
            Duration::from_secs(1)
        );
        assert_eq!(b.after_panic(quick), Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_panicking_loop_is_restarted_with_backoff_until_it_succeeds() {
        let restarts_before = sentinel_telemetry::task_restarts_total();
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let started = Instant::now();
        let supervisor = tokio::spawn(run_supervised(
            "test loop",
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    let run = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if run < 4 {
                        panic!("loop panic #{run}");
                    }
                }
            },
            FAST,
            None,
        ));
        tokio::time::timeout(Duration::from_secs(10), supervisor)
            .await
            .expect("the loop must be restarted until it returns")
            .expect("the supervisor itself must not panic");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            4,
            "three panics, three restarts"
        );
        // 20 + 40 + 40 (capped): the delay grows and stops at the ceiling.
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(sentinel_telemetry::task_restarts_total() >= restarts_before + 3);
    }

    static REPORTED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// The per-loop record behind `/healthz` `panics.tasks` and the heartbeat,
    /// and the hook a loop uses to report its own failure.
    #[tokio::test]
    async fn a_restart_is_recorded_per_task_and_reported() {
        fn report(msg: &str) {
            lock(&REPORTED).push(msg.to_string());
        }
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        tokio::time::timeout(
            Duration::from_secs(10),
            run_supervised(
                "per-task record test",
                move || {
                    let counter = Arc::clone(&counter);
                    async move {
                        if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                            panic!("record me at `secret-operand`");
                        }
                    }
                },
                FAST,
                Some(report),
            ),
        )
        .await
        .expect("restarted until it returns");

        let tasks = lock(&TASKS).clone();
        let t = tasks.get("per-task record test").expect("recorded by name");
        assert_eq!(t.restarts, 2);
        assert!(t.last_at > 0);
        assert_eq!(t.last_panic, "record me at `<redacted>");
        assert_eq!(
            lock(&REPORTED)
                .iter()
                .filter(|m| m.starts_with("record me"))
                .count(),
            2,
            "the report hook ran once per panic"
        );
        assert!(recently_restarted().is_some());
        let health = status();
        assert_eq!(health["tasks"]["per-task record test"]["restarts"], 2);
        let beat = heartbeat_status();
        assert_eq!(beat["tasks"]["per-task record test"]["restarts"], 2);
        assert!(
            beat["tasks"]["per-task record test"]
                .get("last_location")
                .is_none(),
            "no source paths in what reaches the console"
        );
    }

    /// The macro form: each run gets fresh clones of what it moves in, and state
    /// kept OUTSIDE the loop (as the hot-reload watcher keeps `built_from`)
    /// survives the restart.
    #[tokio::test]
    async fn supervised_macro_restarts_with_fresh_captures() {
        let shared = Arc::new(AtomicUsize::new(0));
        let runs = Arc::clone(&shared);
        let label = String::from("captured");
        let handle = supervised!("macro test loop", {
            per_run!(runs, label);
            assert_eq!(label, "captured");
            if runs.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("first run panics");
            }
        });
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("restarted after the policy's first delay")
            .expect("supervisor must not panic");
        assert_eq!(shared.load(Ordering::SeqCst), 2);
    }

    /// The NDJSON writer thread restarted after a fixed 1 s with no backoff, so
    /// a deterministic panic in its setup looped at 1 Hz forever.
    #[test]
    fn a_panicking_thread_loop_backs_off_and_is_recorded() {
        let mut runs = 0;
        let started = Instant::now();
        supervise_blocking_with(
            "thread loop test",
            || {
                runs += 1;
                if runs < 4 {
                    panic!("thread loop panic #{runs}");
                }
            },
            FAST,
        );
        assert_eq!(runs, 4);
        // 20 + 40 + 40: the same doubling, capped, as the async supervisor.
        assert!(started.elapsed() >= Duration::from_millis(100));
        let tasks = lock(&TASKS).clone();
        assert_eq!(tasks.get("thread loop test").map(|t| t.restarts), Some(3));
    }

    /// Rows a run drained but had not stored when it panicked come back to the
    /// next run instead of vanishing uncounted.
    #[test]
    fn rows_held_by_a_run_that_panics_are_resumed_by_the_next() {
        fn no_shed(n: usize) {
            panic!("{n} rows shed by a single panic");
        }
        let carry = Carry::<u32>::new(100, no_shed);
        let run = |carry: &Arc<Carry<u32>>, panic_after: bool| {
            let mut rows = Carried::resume(carry);
            rows.extend([1, 2, 3]);
            if panic_after {
                panic!("writer panic with rows in hand");
            }
            let flushed = rows.to_vec();
            rows.clear();
            flushed
        };
        assert!(std::panic::catch_unwind(AssertUnwindSafe(|| run(&carry, true))).is_err());
        assert_eq!(*lock(&carry.rows), [1, 2, 3], "handed back on the panic");
        let flushed = run(&carry, false);
        assert_eq!(
            flushed,
            [1, 2, 3, 1, 2, 3],
            "the restarted run resumes them"
        );
        assert!(lock(&carry.rows).is_empty());
    }

    /// A writer that panics on every run handed its whole drain back each time,
    /// and the resumed rows with it: the carry grew by a full drain per restart
    /// (1000 rows after ten runs against a 100-row cap), outside every memory
    /// bound, until the node was OOM-killed. Now it never exceeds its cap, rows
    /// back from a second panic are shed, and every shed row is counted.
    #[test]
    fn a_writer_that_panics_every_run_keeps_its_carry_bounded() {
        static SHED: AtomicUsize = AtomicUsize::new(0);
        fn count_shed(n: usize) {
            SHED.fetch_add(n, Ordering::SeqCst);
        }
        const CAP: usize = 100;
        let carry = Carry::<u32>::new(CAP, count_shed);
        let mut resumed = Vec::new();
        for run in 0..10u32 {
            let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut rows = Carried::resume(&carry);
                resumed.push(rows.to_vec());
                // A full drain per run, more than the carry may hold.
                rows.extend(std::iter::repeat_n(run, CAP + 20));
                panic!("every run panics after the drain");
            }));
            assert!(caught.is_err());
            let held = lock(&carry.rows).len();
            assert!(held <= CAP, "run {run}: carry holds {held}, cap {CAP}");
        }
        // Run 0 handed on 100 of its 120 rows (20 shed); every later run shed
        // the 100 it resumed plus 20 of its own.
        assert_eq!(SHED.load(Ordering::SeqCst), 20 + 9 * 120);
        for (run, rows) in resumed.iter().enumerate().skip(1) {
            assert!(
                rows.iter().all(|&r| r as usize == run - 1),
                "run {run} resumed only the previous run's rows, never older ones"
            );
        }
    }

    /// A row whose content panics the insert (a poison row) is retried once,
    /// then shed, and the writer makes progress again with what came after it.
    #[test]
    fn a_poison_row_is_retried_once_then_shed() {
        static SHED: AtomicUsize = AtomicUsize::new(0);
        fn count_shed(n: usize) {
            SHED.fetch_add(n, Ordering::SeqCst);
        }
        let carry = Carry::<u32>::new(100, count_shed);
        let run = |carry: &Arc<Carry<u32>>, fresh: &[u32]| {
            let mut rows = Carried::resume(carry);
            rows.extend(fresh.iter().copied());
            assert!(!rows.contains(&0), "the insert panics on the poison row");
            let stored = rows.to_vec();
            rows.clear();
            stored
        };
        let first = std::panic::catch_unwind(AssertUnwindSafe(|| run(&carry, &[0, 1])));
        assert!(first.is_err());
        assert_eq!(SHED.load(Ordering::SeqCst), 0, "retried once first");
        let second = std::panic::catch_unwind(AssertUnwindSafe(|| run(&carry, &[2])));
        assert!(second.is_err(), "the retry meets the poison row again");
        assert_eq!(SHED.load(Ordering::SeqCst), 2, "0 and 1 shed, 2 carried");
        assert_eq!(run(&carry, &[3]), [2, 3], "the third run stores");
    }
}
