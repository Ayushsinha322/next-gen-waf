//! Panic containment for the data plane.
//!
//! Release builds used `panic = "abort"` until 2026-10, so a single panic
//! anywhere — a slicing bug reached by one hostile request, an `unreachable!`
//! inside a dependency when Valkey closed a connection mid-setup — killed the
//! whole node: every site, every in-flight request, every connection. Builds now
//! unwind, and this module is what turns that into isolation:
//!
//!  * [`install_panic_hook`] logs every panic as one structured line (location
//!    and message, never request data) and counts it in `sentinel_panics_total`.
//!  * The pipeline guard in `proxy` (via [`pipeline_panicked`]) and
//!    [`contain_request`] answer a panicking request with a 500 carrying its
//!    Support ID. It is never forwarded, and the connection keeps serving.
//!  * [`supervise`] and [`supervised!`] restart a background loop after a panic,
//!    with backoff, instead of letting it silently stop.
//!
//! Unwinding is a backstop, not a licence: every panic is still a bug, and each
//! one is made loud on purpose.

use std::any::Any;
use std::cell::RefCell;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::FutureExt as _;
use http::{header, Response, StatusCode};
use sentinel_core::context::{Phase, RequestContext};
use tracing::{debug, error};

use crate::BoxBody;

// ---------------------------------------------------------------------------
// The panic hook
// ---------------------------------------------------------------------------

thread_local! {
    /// Where the latest panic on this thread happened, recorded by the hook. A
    /// panic is caught on the thread that raised it, so the request and task
    /// guards pick it up here and put the location on their own error line.
    static LAST_PANIC_LOCATION: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Install the process-wide panic hook. Idempotent; called by the binary once
/// tracing is up.
///
/// Every panic is counted (`sentinel_panics_total`) and logged as one ERROR line
/// with its source location and a redacted message — see [`panic_message`]. The
/// default hook is replaced rather than chained because it prints the raw
/// message, which can hold request data, as a second, unstructured line. With no
/// tracing subscriber installed (a test binary, a tool linking this crate) the
/// default hook still runs, because otherwise the panic would not be seen at all.
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
            let _ = LAST_PANIC_LOCATION.try_with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut() {
                    *slot = Some(location.clone());
                }
            });
            if !tracing::dispatcher::has_been_set() {
                fallback(info);
                return;
            }
            let thread = std::thread::current();
            let thread = thread.name().unwrap_or("unnamed");
            error!(
                thread,
                location = %location,
                panic = %panic_message(info.payload()),
                "{}",
                hook_line(thread, &location)
            );
        }));
    });
}

/// The hook's message. Keeps the default hook's `thread '…' panicked at` wording
/// because deploy/docker/verify-deploy.sh finds panics in container logs by
/// exactly that text.
fn hook_line(thread: &str, location: &str) -> String {
    format!("thread '{thread}' panicked at {location}")
}

/// Take the location the hook recorded for the panic just caught on this
/// thread. "unknown" when the hook is not installed.
fn take_panic_location() -> String {
    LAST_PANIC_LOCATION
        .try_with(|slot| slot.try_borrow_mut().ok().and_then(|mut s| s.take()))
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string())
}

/// Longest panic message carried onto a log line.
const PANIC_MESSAGE_MAX: usize = 200;

/// Backtick spans std's own panic messages use for method and variant names.
/// Every other span is redacted — see [`panic_message`].
const STD_MESSAGE_TERMS: &[&str] = &[
    "Option::unwrap()",
    "Result::unwrap()",
    "Result::unwrap_err()",
    "None",
    "Err",
    "Ok",
];

/// The panic's message, reduced to what is safe to log.
///
/// std quotes the operand of a failed str slice between backticks — "byte index
/// 7 is not a char boundary; it is inside 'é' (bytes 6..8) of `<the string>`" —
/// and on the request path that operand is request data: a header, a query
/// value, a cookie. So backtick spans are redacted unless they are one of std's
/// own terms, and the whole message is capped. An `unwrap()` on an error whose
/// Debug output embeds input can still carry a fragment, never a whole value.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    let raw = if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        return "non-string panic payload".to_string();
    };
    let mut out = String::with_capacity(raw.len().min(PANIC_MESSAGE_MAX) + 16);
    // Odd segments sit between backticks; an unpaired backtick redacts the rest.
    for (i, part) in raw.split('`').enumerate() {
        if i > 0 {
            out.push('`');
        }
        if i % 2 == 0 || STD_MESSAGE_TERMS.contains(&part) {
            out.push_str(part);
        } else {
            out.push_str("<redacted>");
        }
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
// Requests
// ---------------------------------------------------------------------------

/// Run `fut`, handing back the panic payload instead of unwinding if it panics.
pub(crate) async fn catch<F: Future>(fut: F) -> Result<F::Output, Box<dyn Any + Send>> {
    AssertUnwindSafe(fut).catch_unwind().await
}

/// Reason recorded on the request's log line. Reaches waf.log and the console,
/// so it names the outcome, not the code.
const REQUEST_PANIC_REASON: &str =
    "internal error: request processing failed; answered 500 and not forwarded";

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
/// marked ERROR like any other request that failed before reaching the origin.
pub(crate) fn pipeline_panicked(
    ctx: &mut RequestContext,
    payload: Box<dyn Any + Send>,
) -> Response<BoxBody> {
    sentinel_telemetry::note_request_panic();
    error!(
        request_id = %ctx.request_id,
        client_ip = %ctx.client_ip,
        site = ctx.site_id.as_deref().unwrap_or("-"),
        phase = ?ctx.phase,
        location = %take_panic_location(),
        panic = %panic_message(&*payload),
        "request processing panicked; answered 500, not forwarded"
    );
    let resp = panic_response(&ctx.request_id.to_string());
    crate::stamp_response(ctx, &resp);
    ctx.gateway_error = Some(REQUEST_PANIC_REASON.to_string());
    ctx.advance_phase(Phase::Logging);
    // The panic may have come from logging itself; a second one must not cost
    // the client its 500.
    if std::panic::catch_unwind(AssertUnwindSafe(|| crate::log_request(ctx))).is_err() {
        error!(request_id = %ctx.request_id, "request log record could not be written after a panic");
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
    match AssertUnwindSafe(fut).catch_unwind().await {
        Ok(resp) => resp,
        Err(payload) => {
            sentinel_telemetry::note_request_panic();
            let support_id = uuid::Uuid::new_v4().to_string();
            error!(
                request_id = %support_id,
                client_ip = %peer.ip(),
                location = %take_panic_location(),
                panic = %panic_message(&*payload),
                "request panicked outside the WAF pipeline; answered 500"
            );
            Ok(panic_response(&support_id))
        }
    }
}

/// Request path that makes the pipeline panic, in test builds only: the request
/// tests need a real panic inside the real pipeline.
#[cfg(test)]
pub(crate) const INJECT_PANIC_PATH: &str = "/__panic_guard_test__";

#[cfg(test)]
pub(crate) fn inject_test_panic<B>(req: &http::Request<B>) {
    if req.uri().path() == INJECT_PANIC_PATH {
        panic!("injected test panic");
    }
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

// ---------------------------------------------------------------------------
// Background loops
// ---------------------------------------------------------------------------

/// How a supervised loop is restarted after a panic.
#[derive(Clone, Copy)]
struct RestartPolicy {
    /// First delay; doubles with each consecutive panic.
    min: Duration,
    /// Ceiling: a loop that panics deterministically retries about this often,
    /// instead of spinning a core and flooding the log.
    max: Duration,
    /// A run that lasted this long was healthy, so its panic restarts at `min`.
    reset_after: Duration,
}

const RESTART_POLICY: RestartPolicy = RestartPolicy {
    min: Duration::from_secs(1),
    max: Duration::from_secs(60),
    reset_after: Duration::from_secs(300),
};

/// Spawn `make()`'s future as a background task and restart it, with backoff,
/// whenever it panics. A normal return ends the task.
///
/// The future runs inside the supervising task, not a child of it, so aborting
/// the returned handle stops the loop too (the listener shutdown relies on it).
/// [`supervised!`] is the usual way to call this.
pub(crate) fn supervise<F, Fut>(name: &'static str, make: F) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(run_supervised(name, make, RESTART_POLICY))
}

async fn run_supervised<F, Fut>(name: &'static str, mut make: F, policy: RestartPolicy)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut delay = policy.min;
    loop {
        let started = Instant::now();
        match AssertUnwindSafe(make()).catch_unwind().await {
            Ok(()) => {
                debug!(task = name, "background task finished");
                return;
            }
            Err(payload) => {
                if started.elapsed() >= policy.reset_after {
                    delay = policy.min;
                }
                let restarts = sentinel_telemetry::note_task_restart();
                error!(
                    task = name,
                    location = %take_panic_location(),
                    panic = %panic_message(&*payload),
                    restart_in_ms = delay.as_millis() as u64,
                    restarts_total = restarts,
                    "background task panicked; restarting it"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(policy.max);
            }
        }
    }
}

/// Spawn a background loop under [`supervise`]: a panic restarts it, with
/// backoff, instead of ending it for the life of the process.
///
/// ```ignore
/// panic_guard::supervised!("config sync", {
///     per_run!(sync_url, poll_cfg);
///     let mut ticker = tokio::time::interval(Duration::from_secs(5));
///     loop { /* ... */ }
/// });
/// ```
///
/// The body is written exactly as inside `tokio::spawn(async move { .. })`.
/// `per_run!`, when present, must be its first statement: it names the captured
/// values the loop moves in, and every run gets its own clone of them, because a
/// restarted loop cannot reuse what the run that panicked consumed. Forgetting
/// one is a compile error ("cannot move out of ... an `FnMut` closure"), never a
/// silent bug. A macro rather than a closure so each loop keeps its shape; the
/// closure form re-indents all of them.
macro_rules! supervised {
    ($name:expr, { per_run!($($cap:ident),* $(,)?); $($body:tt)* }) => {
        $crate::panic_guard::supervise($name, move || {
            $(
                #[allow(unused_mut)]
                let mut $cap = ::std::clone::Clone::clone(&$cap);
            )*
            async move { $($body)* }
        })
    };
    ($name:expr, { $($body:tt)* }) => {
        $crate::panic_guard::supervise($name, move || async move { $($body)* })
    };
}
pub(crate) use supervised;

/// What `/healthz` reports under `panics`.
pub(crate) fn status() -> serde_json::Value {
    serde_json::json!({
        "total": sentinel_telemetry::panics_total(),
        "requests_contained": sentinel_telemetry::request_panics_total(),
        "task_restarts": sentinel_telemetry::task_restarts_total(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use sentinel_core::config::{
        ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig, UpstreamConfig,
        UpstreamServer, WafConfig, WafMode,
    };

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
        assert!(logged.contains("`<redacted>`"), "{logged}");
    }

    #[test]
    fn std_terms_survive_and_unpaired_backticks_redact_the_rest() {
        let unwrap = "called `Option::unwrap()` on a `None` value";
        assert_eq!(panic_message(&unwrap), unwrap);
        assert_eq!(panic_message(&"ok `then dangling"), "ok `<redacted>");
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

    // -- requests -----------------------------------------------------------

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

    /// Mock origin that counts what reaches it.
    async fn counting_origin() -> (SocketAddr, Arc<AtomicUsize>) {
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

    fn proxy_config(listen: SocketAddr, origin: SocketAddr) -> SentinelConfig {
        site_config(listen, origin, "panic-site", vec![])
    }

    fn site_config(
        listen: SocketAddr,
        origin: SocketAddr,
        site_id: &str,
        rules: Vec<String>,
    ) -> SentinelConfig {
        SentinelConfig {
            listeners: vec![ListenerConfig {
                name: "panic-test".into(),
                bind: listen.to_string(),
                protocol: ProtocolSpec::Single(Protocol::Http1),
                tls: None,
                default_site: Some(site_id.into()),
                role: Default::default(),
                proxy_protocol: false,
            }],
            sites: vec![SiteConfig {
                id: site_id.into(),
                tenant_id: String::new(),
                domains: vec!["panic-site.local".into()],
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
                    anomaly_threshold: 5,
                    paranoia_level: 2,
                    ..Default::default()
                },
                plugins: vec![],
                tls: Default::default(),
                origin: Default::default(),
            }],
            ..Default::default()
        }
    }

    async fn get(
        sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Empty<Bytes>>,
        path: &str,
    ) -> (StatusCode, Bytes) {
        let req = http::Request::get(path)
            .header(header::HOST, "panic-site.local")
            .body(http_body_util::Empty::new())
            .unwrap();
        let resp = sender.send_request(req).await.expect("response");
        let status = resp.status();
        (status, resp.into_body().collect().await.unwrap().to_bytes())
    }

    async fn connect(
        addr: SocketAddr,
    ) -> hyper::client::conn::http1::SendRequest<http_body_util::Empty<Bytes>> {
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        sender
    }

    fn free_port() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    }

    fn config_handle(cfg: SentinelConfig) -> sentinel_core::ConfigHandle {
        Arc::new(arc_swap::ArcSwap::new(Arc::new(cfg)))
    }

    async fn start_proxy(
        listen: SocketAddr,
        handle: sentinel_core::ConfigHandle,
    ) -> (
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let proxy = tokio::spawn(crate::ProxyServer::new(handle).run(shutdown_rx));
        let deadline = Instant::now() + Duration::from_secs(30);
        while tokio::net::TcpStream::connect(listen).await.is_err() {
            assert!(!proxy.is_finished(), "proxy exited before binding");
            assert!(Instant::now() < deadline, "proxy never bound {listen}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (shutdown_tx, proxy)
    }

    /// The whole point of unwinding: a request that panics the pipeline costs
    /// that request a 500 with its Support ID — not the connection, not the
    /// listener, not the node — and it never reaches the origin.
    #[tokio::test]
    async fn a_panicking_request_gets_a_500_and_the_listener_keeps_serving() {
        install_panic_hook();
        let panics_before = sentinel_telemetry::panics_total();
        let contained_before = sentinel_telemetry::request_panics_total();

        let (origin, hits) = counting_origin().await;
        let listen = free_port();
        let handle = config_handle(proxy_config(listen, origin));
        let (shutdown_tx, proxy) = start_proxy(listen, handle).await;

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
            "a panicked request is never forwarded"
        );

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
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(30), proxy).await;
    }

    /// The hot-reload watcher was the one loop that already had a restart, and
    /// it never ran: under panic=abort the process died first. Run for real, it
    /// restarted from "the current config is built", so the rebuild that
    /// panicked was never retried — the site that triggered it stayed without an
    /// engine, refused with 503, until some unrelated config change came along.
    #[tokio::test]
    async fn a_panicked_engine_rebuild_is_retried_after_the_restart() {
        let restarts_before = sentinel_telemetry::task_restarts_total();
        let (origin, _hits) = counting_origin().await;
        let listen = free_port();
        let unruled = site_config(listen, origin, INJECT_REBUILD_PANIC_SITE, vec![]);
        let handle = config_handle(unruled.clone());
        let (shutdown_tx, proxy) = start_proxy(listen, handle.clone()).await;
        let mut conn = connect(listen).await;
        assert_eq!(get(&mut conn, "/before").await.0, StatusCode::OK);

        // Give the site rules, as a reload would. Its first rebuild panics.
        let crs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
        let mut ruled = unruled;
        ruled.sites[0].waf.rules = vec![crs.to_string_lossy().into_owned()];
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
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(30), proxy).await;
    }

    // -- poisoned locks -------------------------------------------------------

    /// A poisoned sync-status lock used to be skipped: failures stopped being
    /// recorded and the heartbeat kept reporting a healthy sync while this node
    /// stopped taking config.
    #[test]
    fn config_sync_status_survives_a_poisoned_lock() {
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
}
