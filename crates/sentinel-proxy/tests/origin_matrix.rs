//! Origin-shape matrix: does the WAF proxy correctly to the kinds of origin that
//! real deployments put behind it?
//!
//! Why this file exists. Every origin the proxy had been tested against was a
//! plain-HTTP toy (the e2e mock upstream, Juice Shop), and the first real HTTPS
//! application behind the WAF — an APISIX gateway in front of a UAT console —
//! exposed a bug that made EVERY proxied request fail with 400: the upstream
//! connector offered h2, and over h2 the forwarded `:authority` (the upstream
//! address) contradicted the `Host` header (the client's name), which RFC 9113
//! makes malformed. No benchmark could have found it, because no benchmark origin
//! speaks h2. It took two days to find by hand. It is one test here.
//!
//! So the origin in this file behaves like a strict production gateway rather
//! than an echo server:
//!
//!   * TLS with a certificate from a PRIVATE CA, trusted by the WAF only through
//!     `SENTINEL_UPSTREAM_CA_FILE` — the enterprise case, and the exact
//!     workaround used on the UAT node (leaf-only chain, issuer trusted locally);
//!   * ALPN offers both h2 and HTTP/1.1, so whatever the WAF asks for, it gets;
//!   * enforces RFC 9113 §8.3.1: an h2 request whose `:authority` and `Host`
//!     disagree is answered 400, as APISIX/openresty do;
//!   * routes on Host like any virtual-hosted gateway: the wrong Host gets a 404
//!     "no route", so a WAF that forwards the upstream ADDRESS as the Host fails
//!     loudly instead of passing by accident.
//!
//! Each case below is a shape that has broken, or will break, a real deployment.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{header, HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sentinel_core::config::{
    ConfigHandle, ListenerConfig, Protocol, ProtocolSpec, SentinelConfig, SiteConfig,
    UpstreamConfig, UpstreamServer, WafConfig, WafMode,
};
use sentinel_proxy::ProxyServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// The name the client asks for, the certificate names, and the only Host the
/// origin will route. Deliberately NOT the upstream address.
const APP: &str = "app.test";

// ---------------------------------------------------------------------------
// PKI: one private CA per test binary, trusted via SENTINEL_UPSTREAM_CA_FILE
// ---------------------------------------------------------------------------

struct Pki {
    leaf_der: Vec<u8>,
    key_der: Vec<u8>,
}

/// Generate the CA and the origin's leaf once, and point the WAF at the CA.
///
/// Must run before ANY proxy is built in this binary: the connector reads the
/// env var when its TLS config is constructed. Every test calls this first.
fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new());
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Origin Matrix Test CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = rcgen::Certificate::from_params(ca_params).expect("test CA");

        let mut leaf_params = rcgen::CertificateParams::new(vec![APP.to_string()]);
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, APP);
        let leaf = rcgen::Certificate::from_params(leaf_params).expect("leaf");
        let leaf_der = leaf.serialize_der_with_signer(&ca).expect("sign leaf");
        let key_der = leaf.serialize_private_key_der();

        let dir = std::env::temp_dir().join(format!("sk-origin-matrix-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("ca dir");
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, ca.serialize_pem().expect("ca pem")).expect("write ca");
        std::env::set_var("SENTINEL_UPSTREAM_CA_FILE", &ca_path);

        Pki { leaf_der, key_der }
    })
}

fn trusted_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let p = pki();
    (
        CertificateDer::from(p.leaf_der.clone()),
        PrivateKeyDer::try_from(p.key_der.clone()).expect("key"),
    )
}

/// Right name, wrong issuer: self-signed, not from the trusted CA.
fn untrusted_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let c = rcgen::generate_simple_self_signed(vec![APP.to_string()]).expect("self-signed");
    (
        CertificateDer::from(c.serialize_der().expect("der")),
        PrivateKeyDer::try_from(c.serialize_private_key_der()).expect("key"),
    )
}

// ---------------------------------------------------------------------------
// The origin: a strict, virtual-hosted, h2-capable HTTPS gateway
// ---------------------------------------------------------------------------

/// What the origin actually received, for assertions on the forwarded request.
#[derive(Debug, Clone)]
struct Seen {
    version: Version,
    host: Option<String>,
    authority: Option<String>,
    xff: Option<String>,
    path: String,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

async fn start_origin(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (u16, SeenLog) {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        // Leaf only, like the UAT listener: the WAF must supply the issuer from
        // SENTINEL_UPSTREAM_CA_FILE.
        .with_single_cert(vec![cert], key)
        .expect("origin tls config");
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let port = listener.local_addr().unwrap().port();
    let seen: SeenLog = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req| origin(req, Arc::clone(&log)));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, seen)
}

fn text(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Full::new(body.into()))
        .unwrap()
}

async fn origin(
    mut req: Request<Incoming>,
    log: SeenLog,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let authority = req.uri().authority().map(|a| a.as_str().to_string());
    let seen = Seen {
        version: req.version(),
        host: host.clone(),
        authority: authority.clone(),
        xff: req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        path: req.uri().path().to_string(),
    };
    log.lock().unwrap().push(seen);

    // RFC 9113 §8.3.1 — what APISIX/openresty enforce.
    if req.version() == Version::HTTP_2 {
        if let (Some(a), Some(h)) = (&authority, &host) {
            if a != h {
                return Ok(text(
                    StatusCode::BAD_REQUEST,
                    format!("malformed: :authority {a:?} and Host {h:?} disagree"),
                ));
            }
        }
    }

    // Virtual hosting: route only the application's own name.
    let effective = host.or(authority).unwrap_or_default();
    let name = effective.split(':').next().unwrap_or_default();
    if name != APP {
        return Ok(text(
            StatusCode::NOT_FOUND,
            format!("no route for host {effective:?}"),
        ));
    }

    let resp = match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => text(StatusCode::OK, "app-ok"),

        // An SSO login hop: redirect with a long state-bearing Location, and TWO
        // cookies — a proxy that merges or drops Set-Cookie breaks the login.
        (&Method::GET, "/login") => Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, LOGIN_LOCATION)
            .header(
                header::SET_COOKIE,
                "AUTH_SESSION_ID=abc123; Path=/; Secure; HttpOnly",
            )
            .header(
                header::SET_COOKIE,
                format!("KC_RESTART={}; Path=/; Secure", "r".repeat(3000)),
            )
            .body(Full::new(Bytes::new()))
            .unwrap(),

        (&Method::GET, "/cookie-size") => {
            let n = req
                .headers()
                .get(header::COOKIE)
                .map(|v| v.len())
                .unwrap_or(0);
            text(StatusCode::OK, n.to_string())
        }

        (&Method::POST, "/upload") => {
            let n = match req.into_body().collect().await {
                Ok(b) => b.to_bytes().len(),
                Err(_) => return Ok(text(StatusCode::BAD_REQUEST, "body read failed")),
            };
            text(StatusCode::OK, n.to_string())
        }

        (&Method::GET, "/slow") => {
            tokio::time::sleep(Duration::from_secs(4)).await;
            text(StatusCode::OK, "late")
        }

        // A VM console / live-updates socket, served like a strict RFC 6455 server.
        (&Method::GET, "/ws") => {
            let on_upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(up) = on_upgrade.await {
                    let _ = strict_ws_echo(TokioIo::new(up)).await;
                }
            });
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                .body(Full::new(Bytes::new()))
                .unwrap()
        }

        _ => text(StatusCode::NOT_FOUND, "no such path"),
    };
    Ok(resp)
}

/// Echo WebSocket messages the way a standards-compliant server does.
///
/// RFC 6455 §5.1: "The server MUST close the connection upon receiving a frame
/// that is not masked." gorilla/websocket, Node `ws` and Python `websockets` all
/// do exactly this, with close code 1002 — so a relay that forwards client frames
/// unmasked gets a handshake and then nothing. Masked frames are unmasked and
/// echoed back UNMASKED, as server frames must be.
async fn strict_ws_echo<T>(mut io: T) -> std::io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut h = [0u8; 2];
        io.read_exact(&mut h).await?;
        let opcode = h[0] & 0x0F;
        let masked = h[1] & 0x80 != 0;
        let mut len = (h[1] & 0x7F) as usize;
        if len == 126 {
            let mut b = [0u8; 2];
            io.read_exact(&mut b).await?;
            len = u16::from_be_bytes(b) as usize;
        } else if len == 127 {
            let mut b = [0u8; 8];
            io.read_exact(&mut b).await?;
            len = u64::from_be_bytes(b) as usize;
        }
        if !masked {
            // Close, 1002 protocol error.
            io.write_all(&[0x88, 0x02, 0x03, 0xEA]).await?;
            return Ok(());
        }
        let mut key = [0u8; 4];
        io.read_exact(&mut key).await?;
        let mut payload = vec![0u8; len];
        io.read_exact(&mut payload).await?;
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
        let mut out = vec![0x80 | opcode];
        if len < 126 {
            out.push(len as u8);
        } else {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(&payload);
        io.write_all(&out).await?;
        if opcode == 0x8 {
            return Ok(());
        }
    }
}

const LOGIN_LOCATION: &str = "https://app.test/realms/main/protocol/openid-connect/auth?\
client_id=console&state=s-7f3a9c&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback";

// ---------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------

fn next_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    static BASE: OnceLock<u16> = OnceLock::new();
    // 12000..16950 in 50-port blocks per process: clear of e2e_pipeline.rs
    // (20000+), the ephemeral range, and the ports this project listens on.
    let base = *BASE.get_or_init(|| 12_000 + (std::process::id() as u16 % 100) * 50);
    base + NEXT.fetch_add(1, Ordering::SeqCst)
}

struct Opts {
    timeout_secs: Option<u64>,
    max_body: u64,
    mode: WafMode,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            timeout_secs: Some(10),
            max_body: 64 * 1024 * 1024,
            mode: WafMode::Learning,
        }
    }
}

/// Two listeners — HTTP/1.1, and h2c for the browser-like h2 client — in front of
/// one site whose origin is addressed by IP with `sni_name` set: the UAT shape.
fn config(h1: u16, h2: u16, origin_port: u16, o: &Opts) -> SentinelConfig {
    let listener = |name: &str, port: u16, p: Protocol| ListenerConfig {
        name: name.into(),
        bind: format!("127.0.0.1:{port}"),
        protocol: ProtocolSpec::Single(p),
        tls: None,
        // No default site: the request must match on Host like production.
        default_site: None,
        role: Default::default(),
        proxy_protocol: false,
    };
    SentinelConfig {
        listeners: vec![
            listener("h1", h1, Protocol::Http1),
            listener("h2c", h2, Protocol::Http2),
        ],
        sites: vec![SiteConfig {
            id: "app".into(),
            tenant_id: String::new(),
            domains: vec![APP.into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: origin_port,
                    weight: 1,
                    tls: true,
                }],
                health_check: None,
                timeout_secs: o.timeout_secs,
                websocket: true,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: Some(APP.into()),
            },
            waf: WafConfig {
                mode: o.mode.clone(),
                rules: vec![],
                max_body_size: o.max_body,
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }],
        ..Default::default()
    }
}

struct Proxy {
    h1: u16,
    h2: u16,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start_proxy(origin_port: u16, o: Opts) -> Proxy {
    pki();
    let (h1, h2) = (next_port(), next_port());
    let cfg = config(h1, h2, origin_port, &o);
    let handle: ConfigHandle = Arc::new(ArcSwap::new(Arc::new(cfg)));
    let (stop, rx) = watch::channel(false);
    let proxy = ProxyServer::new(handle);
    let task = tokio::spawn(async move { proxy.run(rx).await });
    for port in [h1, h2] {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(!task.is_finished(), "proxy exited before binding {port}");
            assert!(
                std::time::Instant::now() < deadline,
                "proxy never bound {port}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    Proxy { h1, h2, stop, task }
}

impl Proxy {
    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

/// HTTP/1.1 client, Host header set explicitly.
async fn h1(
    port: u16,
    method: Method,
    path: &str,
    headers: &[(&str, String)],
    body: Bytes,
) -> Reply {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect h1");
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("h1 handshake");
    tokio::spawn(conn);
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, APP);
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    let resp = tx
        .send_request(b.body(Full::new(body)).unwrap())
        .await
        .expect("h1 send");
    collect(resp).await
}

/// HTTP/2 client with prior knowledge and NO Host header — the authority travels
/// only as `:authority`, exactly as a browser sends it.
async fn h2(port: u16, path: &str) -> Reply {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect h2");
    let (mut tx, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2 handshake");
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(format!("http://{APP}{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = tx.send_request(req).await.expect("h2 send");
    collect(resp).await
}

async fn collect(resp: Response<Incoming>) -> Reply {
    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn last(seen: &SeenLog) -> Seen {
    seen.lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the origin received no request")
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

/// The UAT bug, reproduced: a browser-like h2 client, through the WAF, to an
/// h2-capable HTTPS origin behind a private CA. Before the fix this was 400
/// "malformed: :authority and Host disagree" on every request.
#[tokio::test]
async fn h2_client_to_an_h2_capable_https_origin_gets_the_application() {
    let (cert, key) = trusted_cert();
    let (origin_port, seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, Opts::default()).await;

    let r = h2(p.h2, "/").await;
    assert_eq!(r.status, StatusCode::OK, "body: {}", r.body);
    assert_eq!(r.body, "app-ok");

    let s = last(&seen);
    assert_eq!(
        s.host.as_deref(),
        Some(APP),
        "the origin must see the name the client asked for, never the upstream address"
    );
    if s.version == Version::HTTP_2 {
        assert_eq!(
            s.authority, s.host,
            "h2 upstream with a disagreeing :authority is malformed"
        );
    }
    p.stop().await;
}

/// Same origin, HTTP/1.1 client: the WAF must forward the client's Host and add
/// forwarding headers the origin can trust.
#[tokio::test]
async fn h1_client_to_an_h2_capable_https_origin_gets_the_application() {
    let (cert, key) = trusted_cert();
    let (origin_port, seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, Opts::default()).await;

    let r = h1(p.h1, Method::GET, "/", &[], Bytes::new()).await;
    assert_eq!(r.status, StatusCode::OK, "body: {}", r.body);
    assert_eq!(r.body, "app-ok");

    let s = last(&seen);
    assert_eq!(s.host.as_deref(), Some(APP));
    assert!(
        s.xff.as_deref().is_some_and(|x| x.contains("127.0.0.1")),
        "X-Forwarded-For must carry the client address, got {:?}",
        s.xff
    );
    p.stop().await;
}

/// An origin whose certificate is NOT from a trusted issuer must be refused —
/// trusting a private CA adds one anchor, it must never mean "trust anything".
#[tokio::test]
async fn an_origin_with_an_untrusted_certificate_is_refused() {
    let (cert, key) = untrusted_cert();
    let (origin_port, seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, Opts::default()).await;

    let r = h1(p.h1, Method::GET, "/", &[], Bytes::new()).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY, "body: {}", r.body);
    assert!(
        seen.lock().unwrap().is_empty(),
        "a request reached an origin whose certificate failed verification"
    );
    p.stop().await;
}

/// SSO login hop: the redirect must pass through untouched, and BOTH Set-Cookie
/// headers must arrive separately — merging them into one line breaks every
/// browser's cookie jar, and a lost KC_RESTART cookie breaks the login loop.
#[tokio::test]
async fn a_login_redirect_and_its_cookies_pass_through_unaltered() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, Opts::default()).await;

    let r = h1(p.h1, Method::GET, "/login", &[], Bytes::new()).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(
        r.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(LOGIN_LOCATION),
        "the redirect target, including its state and redirect_uri, must be forwarded verbatim"
    );
    let cookies: Vec<&str> = r
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(
        cookies.len(),
        2,
        "both Set-Cookie headers must survive, separately: {cookies:?}"
    );
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("AUTH_SESSION_ID=abc123")));
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("KC_RESTART=") && c.len() > 3000));

    // The next request carries a large cookie back — SSO sessions routinely do.
    let big = format!("AUTH_SESSION_ID=abc123; KC_RESTART={}", "r".repeat(3000));
    let r = h1(
        p.h1,
        Method::GET,
        "/cookie-size",
        &[("cookie", big.clone())],
        Bytes::new(),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "a {}-byte cookie was not forwarded: {}",
        big.len(),
        r.body
    );
    assert_eq!(
        r.body,
        big.len().to_string(),
        "the cookie reached the origin altered"
    );
    p.stop().await;
}

/// A large upload within the site's limit reaches the origin intact.
#[tokio::test]
async fn a_large_upload_within_the_limit_reaches_the_origin_intact() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, Opts::default()).await;

    let n = 24 * 1024 * 1024;
    let r = h1(
        p.h1,
        Method::POST,
        "/upload",
        &[],
        Bytes::from(vec![b'a'; n]),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "body: {}", r.body);
    assert_eq!(
        r.body,
        n.to_string(),
        "the origin received a different number of bytes"
    );
    p.stop().await;
}

/// In BLOCKING mode an over-limit body is refused with 413 before the origin
/// sees any of it.
#[tokio::test]
async fn blocking_an_upload_over_the_limit_is_413_and_never_reaches_the_origin() {
    let (cert, key) = trusted_cert();
    let (origin_port, seen) = start_origin(cert, key).await;
    let o = Opts {
        max_body: 64 * 1024,
        mode: WafMode::Blocking,
        ..Opts::default()
    };
    let p = start_proxy(origin_port, o).await;

    let r = h1(
        p.h1,
        Method::POST,
        "/upload",
        &[],
        Bytes::from(vec![b'a'; 256 * 1024]),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "body: {}", r.body);
    assert!(
        seen.lock().unwrap().iter().all(|s| s.path != "/upload"),
        "an over-limit body was forwarded to the origin in blocking mode"
    );
    p.stop().await;
}

/// In LEARNING mode the same body is recorded as would-block and FORWARDED —
/// learning relaxes the request limits along with everything else. Pinned here
/// because the operator manual said the opposite for months, and an operator who
/// sizes limits "because they reject even in learning" is sizing them on a
/// false premise; the learning report is where an over-limit request shows up.
#[tokio::test]
async fn learning_an_upload_over_the_limit_is_forwarded_intact() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let o = Opts {
        max_body: 64 * 1024,
        mode: WafMode::Learning,
        ..Opts::default()
    };
    let p = start_proxy(origin_port, o).await;

    let n = 256 * 1024;
    let r = h1(
        p.h1,
        Method::POST,
        "/upload",
        &[],
        Bytes::from(vec![b'a'; n]),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "body: {}", r.body);
    assert_eq!(
        r.body,
        n.to_string(),
        "learning mode forwarded a truncated body"
    );
    p.stop().await;
}

/// A WebSocket through an HTTPS origin that behaves like a real server: 101,
/// then a MASKED client message out and the server's unmasked echo back.
///
/// The e2e suite stopped at the 101, so for as long as WebSocket support existed
/// no test sent a single message across it. This one did, and found the relay
/// forwarding client frames unmasked — which a strict server answers with 1002
/// and a closed socket. It also fails if the origin hop ever negotiates h2 again,
/// because a WebSocket upgrade cannot happen over h2.
#[tokio::test]
async fn a_websocket_upgrade_through_an_https_origin_carries_data_both_ways() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, Opts::default()).await;

    let mut s = TcpStream::connect(("127.0.0.1", p.h1))
        .await
        .expect("connect");
    s.write_all(
        format!(
            "GET /ws HTTP/1.1\r\nHost: {APP}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut byte))
            .await
            .expect("no upgrade response within 10s")
            .unwrap();
        assert!(
            n > 0,
            "connection closed before the upgrade response: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got:\n{head}"
    );

    // A masked text frame, as every browser sends.
    let msg = b"console-keystrokes";
    let key = [0x37, 0xfa, 0x21, 0x3d];
    let mut frame = vec![0x81, 0x80 | msg.len() as u8];
    frame.extend_from_slice(&key);
    frame.extend(msg.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    s.write_all(&frame).await.unwrap();

    let mut h = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut h))
        .await
        .expect("no reply frame within 10s")
        .expect("connection closed instead of replying");
    if h[0] & 0x0F == 0x8 {
        let mut code = [0u8; 2];
        let _ = s.read_exact(&mut code).await;
        panic!(
            "the origin CLOSED the socket (code {}) instead of echoing — 1002 means it \
             received an unmasked frame, i.e. the relay forwarded the client's message \
             without the mask RFC 6455 requires",
            u16::from_be_bytes(code)
        );
    }
    assert_eq!(
        h[0], 0x81,
        "expected a final text frame back, got header byte {:#04x}",
        h[0]
    );
    assert_eq!(h[1] & 0x80, 0, "server-to-client frames must not be masked");
    let mut payload = vec![0u8; (h[1] & 0x7F) as usize];
    s.read_exact(&mut payload).await.unwrap();
    assert_eq!(
        payload, msg,
        "the message did not cross the upgraded connection intact"
    );
    p.stop().await;
}

/// An origin that accepts the connection and never answers is a 504 — distinct
/// from a 502, so "the application is hanging" and "the application is down" no
/// longer look the same. The UAT console showed exactly this state as a 502.
#[tokio::test]
async fn a_hung_origin_is_504_gateway_timeout() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(
        origin_port,
        Opts {
            timeout_secs: Some(1),
            ..Opts::default()
        },
    )
    .await;

    let t0 = std::time::Instant::now();
    let r = h1(p.h1, Method::GET, "/slow", &[], Bytes::new()).await;
    assert_eq!(r.status, StatusCode::GATEWAY_TIMEOUT, "body: {}", r.body);
    assert!(
        t0.elapsed() < Duration::from_secs(4),
        "answered only after the origin did — the timeout did not fire"
    );
    p.stop().await;
}

/// ...while an origin that refuses the connection is still a 502.
#[tokio::test]
async fn an_unreachable_origin_is_502_bad_gateway() {
    pki();
    // A port that was bound and released: nothing is listening.
    let closed: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let p = start_proxy(closed.port(), Opts::default()).await;

    let r = h1(p.h1, Method::GET, "/", &[], Bytes::new()).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY, "body: {}", r.body);
    p.stop().await;
}
