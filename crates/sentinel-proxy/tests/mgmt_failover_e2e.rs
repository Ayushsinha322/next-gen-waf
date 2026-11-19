//! The admin console's API path fails over between control-plane nodes.
//!
//! Its own test binary, because the management upstreams come from process
//! environment. Ports 34000–34999.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::{Request, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use sentinel_core::config::{ListenerConfig, ListenerRole, Protocol, ProtocolSpec, SentinelConfig};
use sentinel_proxy::ProxyServer;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A stand-in control-plane node answering every request with its own name.
async fn control_plane(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(name.to_string())
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

async fn call(port: u16, method: &str, path: &str, body: &'static str) -> (StatusCode, String) {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, "console.local")
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            body.as_bytes(),
        )))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    use http_body_util::BodyExt;
    let b = resp.collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&b).into_owned())
}

#[tokio::test]
async fn the_console_api_fails_over_to_the_next_control_plane_node() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let live = control_plane("cp2").await;
    // Bound and dropped: a port with nothing listening — control-plane node 1.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    std::env::set_var(
        "SENTINEL_MGMT_API_UPSTREAM",
        format!("http://{dead},http://{live}"),
    );
    std::env::set_var("SENTINEL_MGMT_DASHBOARD_UPSTREAM", format!("http://{live}"));

    let port = 34_000 + (std::process::id() as u16 % 900);
    let cfg = SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "management".into(),
            bind: format!("127.0.0.1:{port}"),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: None,
            role: ListenerRole::Management,
            proxy_protocol: false,
        }],
        ..Default::default()
    };
    let proxy = ProxyServer::new(Arc::new(ArcSwap::new(Arc::new(cfg))));
    let (tx, rx) = watch::channel(false);
    let jh = tokio::spawn(async move { proxy.run(rx).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(!jh.is_finished(), "proxy exited before accepting");
        assert!(std::time::Instant::now() < deadline, "proxy never accepted");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // A request with no body is re-sent to the next node: the console never
    // sees node 1 was down.
    let (status, body) = call(port, "GET", "/api/v1/sites", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "cp2");

    // And the switch sticks for what follows, bodies included.
    let (status, body) = call(port, "POST", "/api/v1/sites", "{\"name\":\"x\"}").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "cp2");

    let _ = tx.send(true);
    let _ = jh.await;
}
