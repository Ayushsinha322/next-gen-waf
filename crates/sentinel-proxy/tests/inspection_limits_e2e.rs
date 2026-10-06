//! Inspection limits end to end: a real proxy, a real origin, real HTTP.
//!
//! The site's policy is parsed from JSON, as the control plane delivers it, so
//! these run unchanged against a build that does not know the keys — and fail
//! there, because such a build ignores them and inspects (or forwards) every
//! argument.
//!
//! Ports come from 30000–32767, below Linux's ephemeral range and apart from
//! `e2e_pipeline.rs` (20000–29999), so the two binaries can run side by side.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::{header, Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use sentinel_core::config::{
    ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig, UpstreamConfig,
    UpstreamServer, WafConfig,
};
use sentinel_proxy::ProxyServer;
use tokio::net::TcpListener;
use tokio::sync::watch;

static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn next_port() -> u16 {
    30_000
        + (std::process::id() as u16 % 27) * 100
        + NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// An origin that answers every request `200 upstream-ok`, so a status other
/// than 200 means the proxy answered itself.
async fn start_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body("upstream-ok".to_string())
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// One site in `mode` whose policy adds `limits` to the SQLi rules.
fn config(
    listen_port: u16,
    origin: SocketAddr,
    mode: &str,
    limits: serde_json::Value,
) -> SentinelConfig {
    let rules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    let mut policy = serde_json::json!({
        "mode": mode,
        "rules": [rules.to_string_lossy()],
        "anomaly_threshold": 5,
        "paranoia_level": 2,
    });
    policy
        .as_object_mut()
        .unwrap()
        .extend(limits.as_object().unwrap().clone());
    let waf: WafConfig = serde_json::from_value(policy).expect("policy");
    SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "test".into(),
            bind: format!("127.0.0.1:{listen_port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: Some("limits".into()),
            role: Default::default(),
            proxy_protocol: false,
        }],
        sites: vec![SiteConfig {
            id: "limits".into(),
            tenant_id: String::new(),
            domains: vec!["limits.local".into()],
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
            waf,
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }],
        ..Default::default()
    }
}

/// Start the proxy and wait until it accepts.
async fn start_proxy(cfg: SentinelConfig) -> watch::Sender<bool> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bind = cfg.listeners[0].bind.clone();
    let proxy = ProxyServer::new(Arc::new(ArcSwap::new(Arc::new(cfg))));
    let (tx, rx) = watch::channel(false);
    let jh = tokio::spawn(async move { proxy.run(rx).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::net::TcpStream::connect(&bind).await.is_err() {
        assert!(!jh.is_finished(), "proxy on {bind} exited before accepting");
        assert!(
            std::time::Instant::now() < deadline,
            "proxy never accepted on {bind}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tx
}

async fn send(port: u16, method: Method, uri: &str, body: String) -> (StatusCode, String) {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "limits.local")
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0",
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    use http_body_util::BodyExt;
    let body = resp.collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// `n` form fields `fN=v`.
fn fields(n: usize) -> String {
    (0..n)
        .map(|i| format!("f{i}=v"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `sentinel_inspection_limit_exceeded_total{reason}`: the proxy runs in this
/// process, so its counter is this one.
fn exceeded(reason: &str) -> u64 {
    sentinel_telemetry::inspection_limit_exceeded_total(reason)
}

/// The counter is process-wide and these tests run in parallel, so each holds
/// this for its whole run: a count one test reads moved for its own requests
/// only, and can be asserted exactly. (Held across awaits, so a tokio mutex.)
static COUNTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The counts of every reason, to compare after a test's requests.
fn counts() -> [u64; 3] {
    ["args", "arg_bytes", "time"].map(exceeded)
}

/// Blocking mode: a request past either argument limit never reaches the
/// origin — 413, or 414 for a query string over the limit on its own — and a
/// request at the limits is inspected and forwarded as before.
#[tokio::test]
async fn blocking_mode_refuses_requests_past_the_argument_limits() {
    let _counter = COUNTER.lock().await;
    let before = counts();
    let origin = start_origin().await;
    let port = next_port();
    let limits = serde_json::json!({"max_inspected_args": 50, "max_inspected_arg_bytes": 2000});
    let shutdown = start_proxy(config(port, origin, "blocking", limits)).await;

    let (status, body) = send(port, Method::POST, "/form", fields(50)).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "upstream-ok"));
    let (status, body) = send(port, Method::POST, "/form", fields(51)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_ne!(body, "upstream-ok");
    let (status, _) = send(
        port,
        Method::GET,
        &format!("/search?{}", fields(51)),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::URI_TOO_LONG);

    // Name `v` and a 1999-byte value: exactly the byte limit.
    let at = format!("v={}", "x".repeat(1999));
    let (status, _) = send(port, Method::POST, "/form", at).await;
    assert_eq!(status, StatusCode::OK);
    let past = format!("v={}", "x".repeat(2000));
    let (status, _) = send(port, Method::POST, "/form", past).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // One count per refused request: two over the argument limit, one over
    // the byte limit, none for the time budget.
    let [args, bytes, time] = before;
    assert_eq!(counts(), [args + 2, bytes + 1, time]);
    let _ = shutdown.send(true);
}

/// Learning mode: the same requests reach the origin, and are counted.
#[tokio::test]
async fn learning_mode_forwards_requests_past_the_argument_limits_and_counts_them() {
    let _counter = COUNTER.lock().await;
    let origin = start_origin().await;
    let port = next_port();
    let limits = serde_json::json!({"max_inspected_args": 50});
    let shutdown = start_proxy(config(port, origin, "learning", limits)).await;

    let [args, bytes, time] = counts();
    let (status, body) = send(port, Method::POST, "/form", fields(51)).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "upstream-ok"));
    // Once, though learning mode runs the rules of every phase after it.
    assert_eq!(counts(), [args + 1, bytes, time]);
    let _ = shutdown.send(true);
}

/// A policy that does not name the limits gets the defaults, which an
/// ordinary large form is well within.
#[tokio::test]
async fn an_ordinary_large_form_is_within_the_default_limits() {
    let _counter = COUNTER.lock().await;
    let before = counts();
    let origin = start_origin().await;
    let port = next_port();
    let shutdown = start_proxy(config(port, origin, "blocking", serde_json::json!({}))).await;
    let form = (0..1000)
        .map(|i| format!("field_{i:04}=the+quick+brown+fox+jumps+over+the+lazy+dog"))
        .collect::<Vec<_>>()
        .join("&");
    let (status, body) = send(port, Method::POST, "/form", form).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "upstream-ok"));
    assert_eq!(counts(), before, "nothing refused");
    let _ = shutdown.send(true);
}
