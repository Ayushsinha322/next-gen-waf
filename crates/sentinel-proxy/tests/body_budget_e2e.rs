//! The node-wide body-buffer budget, end to end.
//!
//! Its own test binary — so its own process — because the budget is a
//! process-wide value fixed on first use: setting a small one here cannot leak
//! into any other test. Ports 33000–33999, apart from the other binaries.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::{header, Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use sentinel_core::config::{
    ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig, UpstreamConfig,
    UpstreamServer, WafConfig,
};
use sentinel_proxy::ProxyServer;
use tokio::net::TcpListener;
use tokio::sync::watch;

const MIB: usize = 1024 * 1024;

async fn start_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    use http_body_util::BodyExt;
                    let n = req.into_body().collect().await.map(|b| b.to_bytes().len());
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(format!("origin got {} bytes", n.unwrap_or(0)))
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

fn config(listen_port: u16, origin: SocketAddr) -> SentinelConfig {
    let rules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
    // max_body_size 0: no per-body cap, so the budget is the only bound — the
    // path that used to be a plain, unbounded collect().
    let waf: WafConfig = serde_json::from_value(serde_json::json!({
        "mode": "learning",
        "rules": [rules.to_string_lossy()],
        "max_body_size": 0,
    }))
    .expect("policy");
    SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "test".into(),
            bind: format!("127.0.0.1:{listen_port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: Some("budget".into()),
            role: Default::default(),
            proxy_protocol: false,
        }],
        sites: vec![SiteConfig {
            id: "budget".into(),
            tenant_id: String::new(),
            domains: vec!["budget.local".into()],
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

async fn post(port: u16, len: usize) -> (StatusCode, Option<String>, String) {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header(header::HOST, "budget.local")
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0",
        )
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(http_body_util::Full::new(bytes::Bytes::from(vec![
            b'z';
            len
        ])))
        .unwrap();
    // The proxy may answer before reading the whole body; the send can then
    // fail on the write side after the response is in. Either way the status
    // is what is asserted.
    let resp = sender.send_request(req).await.expect("response");
    let status = resp.status();
    let ra = resp
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    use http_body_util::BodyExt;
    let body = resp
        .collect()
        .await
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();
    (status, ra, body)
}

#[tokio::test]
async fn a_body_past_the_node_budget_is_shed_503_and_the_node_keeps_serving() {
    // The smallest budget the proxy accepts. Set before the proxy reads it.
    std::env::set_var("SENTINEL_BODY_BUFFER_BUDGET_MB", "64");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let origin = start_origin().await;
    let port = 33_000 + (std::process::id() as u16 % 900);
    let cfg = config(port, origin);
    let bind = cfg.listeners[0].bind.clone();
    let proxy = ProxyServer::new(Arc::new(ArcSwap::new(Arc::new(cfg))));
    let (tx, rx) = watch::channel(false);
    let jh = tokio::spawn(async move { proxy.run(rx).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::net::TcpStream::connect(&bind).await.is_err() {
        assert!(!jh.is_finished(), "proxy exited before accepting");
        assert!(std::time::Instant::now() < deadline, "proxy never accepted");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let shed_before = sentinel_telemetry::body_buffer_shed_total();

    // Larger than the whole budget: refused while buffering, never inspected,
    // never forwarded. Before the budget this was collected whole, unbounded.
    let (status, retry_after, _) = post(port, 65 * MIB).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry_after.as_deref(), Some("1"));
    assert_eq!(
        sentinel_telemetry::body_buffer_shed_total(),
        shed_before + 1
    );

    // What it had read is back in the budget: a body using most of it passes.
    let (status, _, body) = post(port, 48 * MIB).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, format!("origin got {} bytes", 48 * MIB));

    let _ = tx.send(true);
    let _ = jh.await;
}
