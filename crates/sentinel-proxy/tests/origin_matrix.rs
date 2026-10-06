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
            // Like Python `websockets`, Jetty and Tomcat: accept permessage-deflate
            // whenever the client offers it — and every browser offers it. From
            // then on the origin expects compressed data frames (RSV1 set).
            let deflate = req
                .headers()
                .get("sec-websocket-extensions")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("permessage-deflate"));
            let on_upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(up) = on_upgrade.await {
                    let _ = strict_ws_echo(TokioIo::new(up), deflate).await;
                }
            });
            let mut b = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
            if deflate {
                b = b.header("sec-websocket-extensions", "permessage-deflate");
            }
            b.body(Full::new(Bytes::new())).unwrap()
        }

        _ => text(StatusCode::NOT_FOUND, "no such path"),
    };
    Ok(resp)
}

/// Echo WebSocket MESSAGES the way a standards-compliant server does.
///
/// RFC 6455 §5.1: "The server MUST close the connection upon receiving a frame
/// that is not masked." gorilla/websocket, Node `ws` and Python `websockets` all
/// do exactly this, with close code 1002 — so a relay that forwards client frames
/// unmasked gets a handshake and then nothing. Masked frames are unmasked;
/// fragments are reassembled (§5.4) and the whole message is echoed back as one
/// UNMASKED frame, as server frames must be. A Close is echoed and ends the echo,
/// so the client sees the code the relay sent upstream.
///
/// `deflate`: permessage-deflate was negotiated. The first frame of every data
/// message must then carry RSV1 (RFC 7692 §6); one that does not is data this
/// server would try to inflate and fail on — it closes with 1002, which is what a
/// relay that strips RSV1 (or forwards the offer it cannot honour) produces.
async fn strict_ws_echo<T>(mut io: T, deflate: bool) -> std::io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut message: Vec<u8> = Vec::new();
    let mut message_opcode = 0u8;
    loop {
        let mut h = [0u8; 2];
        io.read_exact(&mut h).await?;
        let fin = h[0] & 0x80 != 0;
        let rsv1 = h[0] & 0x40 != 0;
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
        if deflate && (opcode == 0x1 || opcode == 0x2) && !rsv1 {
            io.write_all(&[0x88, 0x02, 0x03, 0xEA]).await?;
            return Ok(());
        }
        let whole = if opcode >= 0x8 {
            Some((opcode, payload))
        } else {
            if opcode != 0x0 {
                message_opcode = opcode;
            }
            message.extend_from_slice(&payload);
            fin.then(|| (message_opcode, std::mem::take(&mut message)))
        };
        let Some((op, body)) = whole else { continue };
        let mut out = vec![0x80 | op];
        if body.len() < 126 {
            out.push(body.len() as u8);
        } else if body.len() < 65536 {
            out.push(126);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(body.len() as u64).to_be_bytes());
        }
        out.extend_from_slice(&body);
        io.write_all(&out).await?;
        if op == 0x8 {
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
    /// CRS rule files by name, e.g. `REQUEST-941-APPLICATION-ATTACK-XSS.conf`.
    crs: Vec<&'static str>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            timeout_secs: Some(10),
            max_body: 64 * 1024 * 1024,
            mode: WafMode::Learning,
            crs: vec![],
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
                rules: o
                    .crs
                    .iter()
                    .map(|f| {
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../../rules/owasp-crs/rules")
                            .join(f)
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect(),
                anomaly_threshold: 5,
                paranoia_level: 1,
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
    let mut cfg = config(h1, h2, origin_port, &o);
    // Not the developer's own `$HOME/.config/sentinel/certs`.
    cfg.cert_dir = Some(std::env::temp_dir().join(format!(
        "sentinel-origin-matrix-certs-{}",
        std::process::id()
    )));
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

// ---------------------------------------------------------------------------
// WebSocket inspection
//
// Until 1.1.5 a WebSocket message could only be refused by an operator's
// explicit `deny` rule. The inspector ran the rule VM with the anomaly
// threshold disabled and never reached the verdict step, and it handed the
// rules a body with no content type, so the CRS ARGS rules had nothing to look
// at. It also refused regardless of learning mode, inspected only the first
// fragment of a message, silently dropped every text message past 60 a second,
// and forwarded the browser's permessage-deflate offer while stripping the RSV1
// bit the resulting frames depend on. Each test below is one of those.
// ---------------------------------------------------------------------------

const XSS: &str = r#"{"comment":"<script>alert(document.cookie)</script>"}"#;

fn ws_blocking_xss() -> Opts {
    Opts {
        mode: WafMode::Blocking,
        crs: vec!["REQUEST-941-APPLICATION-ATTACK-XSS.conf"],
        ..Opts::default()
    }
}

/// Complete the handshake. `extensions` is sent as `Sec-WebSocket-Extensions`.
async fn ws_open(port: u16, extensions: Option<&str>) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let ext = extensions
        .map(|e| format!("Sec-WebSocket-Extensions: {e}\r\n"))
        .unwrap_or_default();
    s.write_all(
        format!(
            "GET /ws HTTP/1.1\r\nHost: {APP}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{ext}\r\n"
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
        assert!(n > 0, "closed before the upgrade response");
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101, got:\n{head}"
    );
    s
}

/// One masked client frame, as a browser sends it.
async fn ws_send(s: &mut TcpStream, fin: bool, opcode: u8, payload: &[u8]) {
    let key = [0x5a, 0x13, 0xc7, 0x02];
    let mut f = vec![if fin { 0x80 } else { 0 } | opcode];
    if payload.len() < 126 {
        f.push(0x80 | payload.len() as u8);
    } else if payload.len() < 65536 {
        f.push(0x80 | 126);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    f.extend_from_slice(&key);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    s.write_all(&f).await.unwrap();
}

/// Next frame from the server: (opcode, payload). Close frames carry the code in
/// the first two payload bytes.
async fn ws_recv(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut h = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut h))
        .await
        .expect("no frame within 10s")
        .expect("connection closed without a frame");
    assert_eq!(h[1] & 0x80, 0, "server-to-client frames must not be masked");
    let mut len = (h[1] & 0x7F) as usize;
    if len == 126 {
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await.unwrap();
        len = u16::from_be_bytes(b) as usize;
    } else if len == 127 {
        let mut b = [0u8; 8];
        s.read_exact(&mut b).await.unwrap();
        len = u64::from_be_bytes(b) as usize;
    }
    let mut p = vec![0u8; len];
    s.read_exact(&mut p).await.unwrap();
    (h[0] & 0x0F, p)
}

fn close_code(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}

/// The headline: a CRS-detectable XSS in a JSON WebSocket message is refused in
/// blocking mode. Before 1.1.5 it was echoed.
#[tokio::test]
async fn blocking_a_websocket_attack_message_is_refused_with_1008() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, ws_blocking_xss()).await;
    let mut s = ws_open(p.h1, None).await;

    // A clean message first: inspection must not break ordinary traffic.
    ws_send(&mut s, true, 0x1, br#"{"comment":"hello"}"#).await;
    assert_eq!(
        ws_recv(&mut s).await,
        (0x1, br#"{"comment":"hello"}"#.to_vec())
    );

    ws_send(&mut s, true, 0x1, XSS.as_bytes()).await;
    let (op, body) = ws_recv(&mut s).await;
    assert_eq!(
        op,
        0x8,
        "the attack message was delivered ({:?}) — the WebSocket inspector did not \
         refuse a CRS-detectable XSS in blocking mode",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(close_code(&body), 1008, "expected 1008 policy violation");
    p.stop().await;
}

/// The same attack split across three fragments. Only the first fragment used to
/// be inspected, and on its own it is harmless.
#[tokio::test]
async fn blocking_a_websocket_attack_split_across_fragments_is_refused() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, ws_blocking_xss()).await;
    let mut s = ws_open(p.h1, None).await;

    let (a, rest) = XSS.as_bytes().split_at(16); // {"comment":"<scr
    let (b, c) = rest.split_at(10);
    ws_send(&mut s, false, 0x1, a).await;
    ws_send(&mut s, false, 0x0, b).await;
    // A ping between fragments is legal (RFC 6455 §5.4) and must pass straight
    // through, not end or corrupt the message being reassembled.
    ws_send(&mut s, true, 0x9, b"keepalive").await;
    ws_send(&mut s, true, 0x0, c).await;

    let first = ws_recv(&mut s).await;
    assert_eq!(
        first,
        (0x9, b"keepalive".to_vec()),
        "the interleaved ping was lost"
    );
    let (op, body) = ws_recv(&mut s).await;
    assert_eq!(
        op,
        0x8,
        "a fragmented attack was delivered ({:?}) — fragments are not being \
         reassembled before inspection",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(close_code(&body), 1008);
    p.stop().await;
}

/// Fragments of a CLEAN message are reassembled for inspection and still reach
/// the origin as the same message.
#[tokio::test]
async fn a_fragmented_clean_websocket_message_arrives_intact() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, ws_blocking_xss()).await;
    let mut s = ws_open(p.h1, None).await;

    ws_send(&mut s, false, 0x1, br#"{"status":"#).await;
    ws_send(&mut s, false, 0x0, br#""rack 4 "#).await;
    ws_send(&mut s, true, 0x0, br#"online"}"#).await;
    assert_eq!(
        ws_recv(&mut s).await,
        (0x1, br#"{"status":"rack 4 online"}"#.to_vec())
    );
    p.stop().await;
}

/// Learning mode never refuses — a WebSocket message included. The inspector
/// used to close the socket on a deny rule whatever the site's mode.
#[tokio::test]
async fn learning_a_websocket_attack_message_is_forwarded() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(
        origin_port,
        Opts {
            mode: WafMode::Learning,
            ..ws_blocking_xss()
        },
    )
    .await;
    let mut s = ws_open(p.h1, None).await;
    ws_send(&mut s, true, 0x1, XSS.as_bytes()).await;
    assert_eq!(ws_recv(&mut s).await, (0x1, XSS.as_bytes().to_vec()));
    p.stop().await;
}

/// A burst far past the old 60-a-second limit: every message arrives, in order.
/// The limit used to DROP the excess silently — characters vanishing from a web
/// terminal, updates missing from a dashboard, with nothing telling either end.
#[tokio::test]
async fn a_burst_of_websocket_messages_is_throttled_never_dropped() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, ws_blocking_xss()).await;
    let s = ws_open(p.h1, None).await;
    let (mut rd, mut wr) = s.into_split();

    const N: usize = 500;
    let writer = tokio::spawn(async move {
        let key = [1u8, 2, 3, 4];
        for i in 0..N {
            let m = format!("{{\"k\":{i}}}");
            let mut f = vec![0x81, 0x80 | m.len() as u8];
            f.extend_from_slice(&key);
            f.extend(m.bytes().enumerate().map(|(j, b)| b ^ key[j % 4]));
            wr.write_all(&f).await.unwrap();
        }
        wr
    });
    for i in 0..N {
        let mut h = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(20), rd.read_exact(&mut h))
            .await
            .unwrap_or_else(|_| panic!("message {i} of {N} never arrived — dropped"))
            .unwrap();
        assert_eq!(
            h[0], 0x81,
            "message {i}: expected a text frame, got {:#04x}",
            h[0]
        );
        let mut p = vec![0u8; (h[1] & 0x7F) as usize];
        rd.read_exact(&mut p).await.unwrap();
        assert_eq!(
            p,
            format!("{{\"k\":{i}}}").as_bytes(),
            "message {i} out of order"
        );
    }
    let _ = writer.await;
    p.stop().await;
}

/// Every browser offers permessage-deflate, and many servers accept it. The WAF
/// cannot inspect a compressed message, and the relay re-encodes frames without
/// the RSV1 bit compression depends on — so if the offer reaches the origin, the
/// first message breaks the socket. The offer must be withdrawn; messages then
/// travel uncompressed and inspectable.
#[tokio::test]
async fn a_browsers_compression_offer_does_not_break_or_blind_the_socket() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, ws_blocking_xss()).await;
    let mut s = ws_open(p.h1, Some("permessage-deflate; client_max_window_bits")).await;
    ws_send(&mut s, true, 0x1, b"after-negotiation").await;
    let (op, body) = ws_recv(&mut s).await;
    assert_ne!(
        (op, body.get(..2).map(close_code)),
        (0x8, Some(1002)),
        "the origin negotiated compression and then rejected the relay's frames"
    );
    assert_eq!((op, body), (0x1, b"after-negotiation".to_vec()));
    p.stop().await;
}

/// A text message larger than the inspector will read is refused in blocking
/// mode (1009 message too big) — the same rule as an over-limit HTTP body. It
/// used to be forwarded uninspected past 64 KiB, which is a bypass by padding.
#[tokio::test]
async fn blocking_a_websocket_message_too_large_to_inspect_is_refused_with_1009() {
    let (cert, key) = trusted_cert();
    let (origin_port, _seen) = start_origin(cert, key).await;
    let p = start_proxy(origin_port, ws_blocking_xss()).await;
    let mut s = ws_open(p.h1, None).await;
    let mut padded = vec![b' '; 2 * 1024 * 1024];
    padded.extend_from_slice(XSS.as_bytes());
    ws_send(&mut s, true, 0x1, &padded).await;
    let (op, body) = ws_recv(&mut s).await;
    assert_eq!(op, 0x8, "an oversized, uninspectable message was forwarded");
    assert_eq!(close_code(&body), 1009);
    p.stop().await;
}
