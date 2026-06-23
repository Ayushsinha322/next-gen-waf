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
    ConfigHandle, ListenerConfig, Protocol, ProtocolSpec, SentinelConfig,
    SiteConfig, UpstreamConfig, UpstreamServer, WafConfig, WafMode,
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

fn test_config(listen_port: u16, upstream_port: u16, rule_file: &str, mode: WafMode) -> SentinelConfig {
    let rule_path = crs_rule_dir().join(rule_file);
    SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "test".into(),
            bind: format!("127.0.0.1:{listen_port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: Some("test-site".into()),
        }],
        sites: vec![SiteConfig {
            id: "test-site".into(),
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
            },
            waf: WafConfig {
                mode,
                rules: vec![rule_path.to_string_lossy().to_string()],
                anomaly_threshold: 5,
                paranoia_level: 2,
                ..Default::default()
            },
            plugins: vec![],
        }],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// mock upstream
// ---------------------------------------------------------------------------

async fn start_mock_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock upstream");
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
                    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
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
) -> (watch::Sender<bool>, tokio::task::JoinHandle<anyhow::Result<()>>) {
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

async fn send_request(listen_port: u16, host: &str, uri: &str, method: Method, body: &str) -> (StatusCode, Vec<u8>) {
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
        .header(header::USER_AGENT, "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0");

    let req = if !body.is_empty() {
        req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(http_body_util::Full::new(bytes::Bytes::from(body.to_string())))
            .unwrap()
    } else {
        req.body(http_body_util::Full::new(bytes::Bytes::new())).unwrap()
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
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(listen_port, "test-site.local", "/hello?name=world", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"upstream-ok:"));
}

#[tokio::test]
async fn sqli_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(listen_port, "test-site.local", "/search?q=1%27%20OR%201%3D1--", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "SQLi attack should be 403");
}

#[tokio::test]
async fn xss_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-941-APPLICATION-ATTACK-XSS.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(listen_port, "test-site.local", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "XSS attack should be 403");
}

#[tokio::test]
async fn health_check_endpoint() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(listen_port, "test-site.local", "/healthz", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK, "healthz should return 200");
}

#[tokio::test]
async fn post_body_sqli_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(listen_port, "test-site.local", "/login", Method::POST, "user=admin' OR 1=1--&pass=foo").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "POST SQLi body should be 403");
}

#[tokio::test]
async fn learning_mode_passes_attack() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", WafMode::Learning);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(listen_port, "test-site.local", "/search?q=1%20UNION%20SELECT%20*%20FROM%20users", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK, "learning mode should forward");
    assert!(body.starts_with(b"upstream-ok:"), "learning mode should reach upstream");
}

#[tokio::test]
async fn e2e_lfi_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-930-APPLICATION-ATTACK-LFI.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(listen_port, "test-site.local", "/?file=../../etc/passwd", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "LFI attack should be 403");
}

#[tokio::test]
async fn e2e_rce_attack_is_blocked() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-932-APPLICATION-ATTACK-RCE.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, _) = send_request(listen_port, "test-site.local", "/exec?cmd=cat%20/etc/passwd", Method::GET, "").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "RCE attack should be 403");
}

#[tokio::test]
async fn clean_post_passes_through() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;
    let listen_port = next_port();
    let cfg = test_config(listen_port, upstream_addr.port(), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", WafMode::Blocking);
    let (shutdown_tx, jh) = start_proxy(cfg).await;

    let (status, body) = send_request(listen_port, "test-site.local", "/api/users", Method::POST, "name=John&email=john@example.com").await;

    shutdown_proxy(shutdown_tx, jh).await;
    assert_eq!(status, StatusCode::OK, "clean POST should pass");
    assert!(body.starts_with(b"upstream-ok:"));
}