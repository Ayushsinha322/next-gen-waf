//! HTTP/3 through the whole WAF pipeline: QUIC client → `ProxyServer` (h3
//! listener, `run_pipeline`) → a real HTTP/1.1 origin.
//!
//! The relay itself is unit-tested in `src/http3.rs`. These tests pin what only
//! the assembled proxy can show: an uninspected response streams from the
//! origin to an h3 client chunk by chunk, and an inspected one reaches the h3
//! client in its post-inspection form.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::{Buf, Bytes};
use http::{header, Request, Response, StatusCode};
use hyper::body::{Body, Frame, Incoming};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use sentinel_core::config::{
    DlpAction, DlpConfig, ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig,
    TlsFileConfig, UpstreamConfig, UpstreamServer, WafConfig, WafMode,
};
use sentinel_proxy::ProxyServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

type OriginFrame = Result<Frame<Bytes>, String>;
type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// A response body the test feeds, so the origin sends exactly when told to.
struct ChanBody(mpsc::Receiver<OriginFrame>);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = String;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<OriginFrame>> {
        self.0.poll_recv(cx)
    }
}

/// Origin text DLP must mask. Sent as `text/plain`, a type DLP reads.
const PII: &str = "customer ssn 123-45-6789 on file";

/// An HTTP/1.1 origin. `/stream` answers `application/octet-stream` (a type
/// nothing inspects) with a body whose frames the test sends through the
/// channel handed out on `streams`. `/partial` answers `text/plain` (a type DLP
/// reads), sends part of the body and then fails. Any other path answers
/// [`PII`].
async fn start_origin() -> (SocketAddr, mpsc::Receiver<mpsc::Sender<OriginFrame>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (streams_tx, streams_rx) = mpsc::channel(4);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let streams_tx = streams_tx.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let streams_tx = streams_tx.clone();
                    async move {
                        let (tx, rx) = mpsc::channel(1);
                        let ctype = match req.uri().path() {
                            "/stream" => {
                                let _ = streams_tx.send(tx).await;
                                "application/octet-stream"
                            }
                            "/partial" => {
                                // A body error makes hyper abort the chunked
                                // response, so the proxy reads a truncated body.
                                tokio::spawn(async move {
                                    let part = Frame::data(Bytes::from_static(b"record 1 of 2\n"));
                                    let _ = tx.send(Ok(part)).await;
                                    let _ = tx.send(Err("origin died mid-body".into())).await;
                                });
                                "text/plain"
                            }
                            _ => {
                                tx.send(Ok(Frame::data(Bytes::from_static(PII.as_bytes()))))
                                    .await
                                    .unwrap();
                                drop(tx);
                                "text/plain"
                            }
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header(header::CONTENT_TYPE, ctype)
                                .body(ChanBody(rx))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, streams_rx)
}

/// An origin that answers every request with `raw`, written verbatim. For
/// framing a hyper server will not produce: it sends chunked trailers only to a
/// client that asked with `TE: trailers`.
async fn start_raw_origin(raw: &'static [u8]) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                // The test requests carry no body: the head is the request.
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tcp.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tcp.write_all(raw).await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    addr
}

/// A port free on both TCP and UDP: the h3 endpoint binds the listener's own
/// address over UDP.
fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A running proxy with one TLS listener offering h1/h2/h3, in front of
/// `origin`. The site has no rules and DLP set to mask.
struct Proxy {
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    cert_dir: std::path::PathBuf,
}

async fn start_proxy(origin: SocketAddr) -> Proxy {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // Self-signed certs are generated into here on first use.
    let cert_dir =
        std::env::temp_dir().join(format!("sk-h3-pipeline-{}-{port}", std::process::id()));
    let cfg = SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "h3".into(),
            bind: addr.to_string(),
            protocol: ProtocolSpec::Multiple(vec![
                Protocol::Http1,
                Protocol::Http2,
                Protocol::Http3,
            ]),
            // No cert/key: the SNI resolver path, the one h3 is wired for.
            tls: Some(TlsFileConfig::default()),
            default_site: Some("h3-site".into()),
            role: Default::default(),
            proxy_protocol: false,
        }],
        sites: vec![SiteConfig {
            id: "h3-site".into(),
            tenant_id: String::new(),
            domains: vec!["localhost".into()],
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
                rules: vec![],
                dlp: Some(DlpConfig {
                    enable: true,
                    patterns: vec![],
                    action: DlpAction::Mask,
                }),
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }],
        cert_dir: Some(cert_dir.clone()),
        ..Default::default()
    };
    let proxy = ProxyServer::new(Arc::new(ArcSwap::new(Arc::new(cfg))));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move { proxy.run(shutdown_rx).await });
    // The TCP listener binds just before the QUIC endpoint; a QUIC handshake
    // that races the UDP bind is retransmitted, so the connect below copes.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while tokio::net::TcpStream::connect(addr).await.is_err() {
        assert!(!task.is_finished(), "proxy exited before listening");
        assert!(
            std::time::Instant::now() < deadline,
            "proxy never listened on {addr}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Proxy {
        addr,
        shutdown,
        task,
        cert_dir,
    }
}

impl Proxy {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = timeout(Duration::from_secs(10), self.task).await;
        let _ = std::fs::remove_dir_all(&self.cert_dir);
    }
}

/// Accepts the proxy's self-signed certificate. The handshake is still real
/// TLS 1.3; only PKI validation is skipped.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// An h3 client with one GET in flight on `stream`. The other fields keep the
/// connection alive while the test reads.
struct Client {
    stream: ClientStream,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn h3_get(addr: SocketAddr, path: &str) -> Client {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = timeout(
        Duration::from_secs(15),
        endpoint.connect(addr, "localhost").unwrap(),
    )
    .await
    .expect("QUIC handshake with the proxy timed out")
    .expect("QUIC handshake with the proxy failed");
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    Client {
        stream,
        _send_request: send_request,
        _endpoint: endpoint,
        driver,
    }
}

async fn read_to_end(stream: &mut ClientStream, out: &mut Vec<u8>) {
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.chunk().len();
            out.extend_from_slice(chunk.chunk());
            chunk.advance(n);
        }
    }
}

/// An uninspected response streams through the pipeline to an h3 client: the
/// first chunk arrives while the origin is still holding the rest back. The h3
/// relay used to collect the whole body first, so this client got nothing until
/// the origin finished, and here, where the origin waits for the client, nothing
/// at all.
#[tokio::test]
async fn h3_streams_an_uninspected_response_through_the_pipeline() {
    let (origin, mut streams) = start_origin().await;
    let proxy = start_proxy(origin).await;

    let mut client = h3_get(proxy.addr, "/stream").await;
    let origin_tx = timeout(Duration::from_secs(10), streams.recv())
        .await
        .expect("the request never reached the origin")
        .unwrap();
    origin_tx
        .send(Ok(Frame::data(Bytes::from_static(b"first "))))
        .await
        .unwrap();

    let resp = timeout(Duration::from_secs(10), client.stream.recv_response())
        .await
        .expect("no response head")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let first = timeout(Duration::from_secs(5), client.stream.recv_data())
        .await
        .expect(
            "no body reached the h3 client while the origin was still sending: \
             the h3 path is buffering the response instead of streaming it",
        )
        .unwrap()
        .expect("the body ended before its first chunk");
    let mut body = Vec::new();
    body.extend_from_slice(first.chunk());
    assert_eq!(body, b"first ");

    origin_tx
        .send(Ok(Frame::data(Bytes::from_static(b"second"))))
        .await
        .unwrap();
    drop(origin_tx);
    read_to_end(&mut client.stream, &mut body).await;
    assert_eq!(body, b"first second");

    drop(client);
    proxy.stop().await;
}

/// What the h3 relay sends is the pipeline's post-inspection body: DLP masking
/// applies to an h3 client exactly as to a TCP one.
#[tokio::test]
async fn h3_client_receives_the_post_inspection_body() {
    let (origin, _streams) = start_origin().await;
    let proxy = start_proxy(origin).await;

    let mut client = h3_get(proxy.addr, "/pii").await;
    let resp = timeout(Duration::from_secs(10), client.stream.recv_response())
        .await
        .expect("no response head")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = Vec::new();
    timeout(
        Duration::from_secs(10),
        read_to_end(&mut client.stream, &mut body),
    )
    .await
    .expect("body never completed");
    let body = String::from_utf8(body).unwrap();
    assert_eq!(body.len(), PII.len(), "masking preserves length: {body:?}");
    assert!(
        !body.contains("123-45-6789"),
        "the h3 client received the origin's unmasked body: {body:?}"
    );
    assert!(
        body.contains("***-**-6789"),
        "expected the masked SSN: {body:?}"
    );

    drop(client);
    proxy.stop().await;
}

/// An inspected response whose origin fails part-way through the body is a
/// gateway error, never a clean response. `proxy` buffers what DLP reads, so it
/// sees the failure before any head is sent. It used to forward the origin's
/// head with an empty body: the h3 client got a complete, empty 200 and the
/// access log recorded a clean 200 with no gateway error.
#[tokio::test]
async fn h3_inspected_response_cut_short_by_the_origin_is_a_502() {
    let (origin, _streams) = start_origin().await;
    let proxy = start_proxy(origin).await;

    let mut client = h3_get(proxy.addr, "/partial").await;
    let resp = timeout(Duration::from_secs(10), client.stream.recv_response())
        .await
        .expect("no response head")
        .unwrap();
    let mut body = Vec::new();
    timeout(
        Duration::from_secs(10),
        read_to_end(&mut client.stream, &mut body),
    )
    .await
    .expect("body never completed");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "a body the origin cut short reached the h3 client as a {} with {} bytes \
         ({:?}), not as a gateway error",
        resp.status(),
        body.len(),
        String::from_utf8_lossy(&body),
    );
    assert!(
        !String::from_utf8_lossy(&body).contains("record 1 of 2"),
        "the truncated origin body must not be relayed"
    );

    drop(client);
    proxy.stop().await;
}

/// An inspected response keeps its trailers. `proxy` buffers what DLP reads
/// and rebuilds the body afterwards; the trailers used to be dropped in that
/// round trip, so an h3 client never saw them.
#[tokio::test]
async fn h3_inspected_response_keeps_its_trailers() {
    let origin = start_raw_origin(
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/plain\r\n\
          Transfer-Encoding: chunked\r\n\
          Trailer: x-record-count\r\n\
          Connection: close\r\n\
          \r\n\
          e\r\nrecord 1 of 1\n\r\n\
          0\r\nx-record-count: 1\r\n\r\n",
    )
    .await;
    let proxy = start_proxy(origin).await;

    let mut client = h3_get(proxy.addr, "/trailers").await;
    let resp = timeout(Duration::from_secs(10), client.stream.recv_response())
        .await
        .expect("no response head")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = Vec::new();
    timeout(
        Duration::from_secs(10),
        read_to_end(&mut client.stream, &mut body),
    )
    .await
    .expect("body never completed");
    assert_eq!(body, b"record 1 of 1\n");
    let trailers = timeout(Duration::from_secs(10), client.stream.recv_trailers())
        .await
        .expect("trailers never arrived")
        .unwrap()
        .expect("the inspected response reached the h3 client without its trailers");
    assert_eq!(trailers.get("x-record-count").unwrap(), "1");

    drop(client);
    proxy.stop().await;
}
