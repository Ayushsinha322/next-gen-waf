//! sentinel-proxy — async reverse proxy with WAF phase pipeline.
//!
//! Architecture:
//!   - One [`ProxyServer`] per listener (bind address).
//!   - Each accepted TCP connection is upgraded to TLS when the listener
//!     config includes a `tls` block.
//!   - hyper v1 serves HTTP/1.1 and HTTP/2 (HTTP/2 via ALPN on TLS).
//!   - A [`UpstreamPool`] holds a simple round-robin load balancer per site.
//!   - WAF phase stubs are wired in; the rules engine (sentinel-rules) will
//!     fill them in Phase 1.

pub mod upstream;

use std::convert::Infallible;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use bytes::Bytes;
use http::{header, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use sentinel_core::{
    config::{ConfigHandle, ListenerConfig, Protocol, SiteConfig, WafMode},
    context::{Phase, RequestContext, WafDecision},
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::upstream::UpstreamPool;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// ---------------------------------------------------------------------------
// ServerState — shared across all request handlers on a listener
// ---------------------------------------------------------------------------

struct ServerState {
    config: ConfigHandle,
    upstream_pool: Arc<UpstreamPool>,
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

/// Top-level proxy server.  One instance manages all configured listeners.
pub struct ProxyServer {
    config: ConfigHandle,
}

impl ProxyServer {
    pub fn new(config: ConfigHandle) -> Self {
        Self { config }
    }

    /// Bind all configured listeners and start serving.
    /// Returns when the `shutdown` receiver fires.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let cfg = self.config.load();

        if cfg.listeners.is_empty() {
            warn!("no listeners configured; proxy will not accept connections");
            shutdown.changed().await.ok();
            return Ok(());
        }

        let upstream_pool = Arc::new(UpstreamPool::from_config(&cfg));
        let state = Arc::new(ServerState {
            config: Arc::clone(&self.config),
            upstream_pool,
        });

        let mut handles = Vec::new();
        for listener_cfg in cfg.listeners.clone() {
            let state2 = Arc::clone(&state);
            let mut sd = shutdown.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_listener(listener_cfg, state2, &mut sd).await {
                    error!("listener error: {e}");
                }
            });
            handles.push(handle);
        }

        // Wait for the first shutdown signal.
        shutdown.changed().await.ok();
        info!("shutdown signal received; draining connections");

        for h in handles {
            h.abort();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-listener accept loop
// ---------------------------------------------------------------------------

async fn serve_listener(
    cfg: ListenerConfig,
    state: Arc<ServerState>,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tcp = TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding listener '{}' on {}", cfg.name, cfg.bind))?;

    info!(listener = %cfg.name, bind = %cfg.bind, tls = cfg.is_tls(), "listener started");

    let tls_acceptor = if cfg.is_tls() {
        Some(build_tls_acceptor(cfg.tls.as_ref().unwrap())?)
    } else {
        None
    };

    loop {
        tokio::select! {
            accept = tcp.accept() => {
                let (stream, peer) = accept?;
                let state = Arc::clone(&state);
                let acceptor = tls_acceptor.clone();
                let protos = cfg.protocols();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, acceptor, protos, state).await {
                        debug!(peer = %peer, "connection error: {e}");
                    }
                });
            }
            _ = shutdown.changed() => {
                info!(listener = %cfg.name, "listener shutting down");
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    protocols: Vec<Protocol>,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    if let Some(acceptor) = tls_acceptor {
        let tls = acceptor
            .accept(stream)
            .await
            .context("TLS handshake failed")?;

        // ALPN: h2 or http/1.1
        let negotiated = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| p.to_vec());

        let io = TokioIo::new(tls);

        if negotiated.as_deref() == Some(b"h2") {
            serve_http2(io, peer, state).await
        } else {
            serve_http1(io, peer, state).await
        }
    } else {
        // Plain HTTP — detect if HTTP/2 (h2c) is in the protocols list.
        // For now, always serve HTTP/1.1 on plain TCP (h2c upgrade not yet wired).
        let io = TokioIo::new(stream);
        if protocols.contains(&Protocol::Http2) && !protocols.contains(&Protocol::Http1) {
            serve_http2(io, peer, state).await
        } else {
            serve_http1(io, peer, state).await
        }
    }
}

async fn serve_http1<T>(io: TokioIo<T>, peer: SocketAddr, state: Arc<ServerState>) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                async move { handle_request(s, peer, req).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| anyhow!("http1 serve error: {e}"))
}

async fn serve_http2<T>(io: TokioIo<T>, peer: SocketAddr, state: Arc<ServerState>) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                async move { handle_request(s, peer, req).await }
            }),
        )
        .await
        .map_err(|e| anyhow!("http2 serve error: {e}"))
}

// ---------------------------------------------------------------------------
// Request handler — WAF phases + upstream proxying
// ---------------------------------------------------------------------------

async fn handle_request(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxBody>, Infallible> {
    match proxy(state, peer, req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!("proxy error: {e:#}");
            Ok(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"))
        }
    }
}

async fn proxy(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> anyhow::Result<Response<BoxBody>> {
    let cfg = state.config.load();

    // --- Phase 0: Connection (JA4/IP rep stubs — sentinel-modules Phase 2) ---
    let mut ctx = RequestContext::new(peer.ip(), peer.port());
    ctx.advance_phase(Phase::RequestHeaders);

    // --- Phase 1: Request headers ---
    let (mut parts, body) = req.into_parts();

    ctx.http_version = parts.version;
    ctx.method = parts.method.clone();
    ctx.uri = parts.uri.clone();
    ctx.request_headers = parts.headers.clone();

    // Match site by Host header.
    let host = ctx.host().map(str::to_owned);
    let site = host
        .as_deref()
        .and_then(|h| cfg.sites.iter().find(|s| site_matches(s, h)));

    if let Some(s) = &site {
        ctx.site_id = Some(s.id.clone());
    }

    // WAF phase 1 check (rule engine stub).
    phase1_headers(&mut ctx, site)?;

    if ctx.decision == WafDecision::Block {
        return Ok(block_response(&ctx));
    }

    // --- Phase 2: Request body ---
    ctx.advance_phase(Phase::RequestBody);

    // Conditionally buffer the body for inspection (skip for streaming/large).
    let should_inspect_body = site
        .map(|s| s.waf.mode != WafMode::Off)
        .unwrap_or(false);

    let boxed_body: BoxBody = if should_inspect_body {
        let collected = body
            .collect()
            .await
            .context("collecting request body")?;
        let bytes = collected.to_bytes();
        ctx.request_body = Some(bytes.clone());
        phase2_body(&mut ctx, site)?;
        if ctx.decision == WafDecision::Block {
            return Ok(block_response(&ctx));
        }
        Full::new(bytes)
            .map_err(|never: Infallible| match never {})
            .boxed()
    } else {
        body.boxed()
    };

    // --- Phase 3: Upstream ---
    ctx.advance_phase(Phase::Upstream);

    let site_cfg = site.ok_or_else(|| anyhow!("no matching site for host: {:?}", host))?;

    let upstream_addr = state
        .upstream_pool
        .next_server(&site_cfg.id)
        .ok_or_else(|| anyhow!("no healthy upstream servers for site '{}'", site_cfg.id))?;

    ctx.upstream_addr = Some(
        format!("{}:{}", upstream_addr.host, upstream_addr.port)
            .parse()
            .ok()
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
    );

    // Build the upstream request URI (absolute path).
    let upstream_uri = build_upstream_uri(&upstream_addr.host, upstream_addr.port, &parts.uri)?;

    // Remove hop-by-hop headers and inject forwarding headers.
    strip_hop_by_hop(&mut parts.headers);
    inject_forwarding_headers(&mut parts.headers, peer.ip())?;

    parts.uri = upstream_uri;

    let upstream_req = Request::from_parts(parts, boxed_body);

    let upstream_start = std::time::Instant::now();
    let upstream_resp = state
        .upstream_pool
        .send_request(&site_cfg.id, upstream_req)
        .await
        .context("upstream request failed")?;
    ctx.upstream_latency_us = Some(upstream_start.elapsed().as_micros() as u64);

    // --- Phase 4: Response headers ---
    ctx.advance_phase(Phase::ResponseHeaders);
    let (mut resp_parts, resp_body) = upstream_resp.into_parts();
    ctx.response_status = Some(resp_parts.status);
    ctx.response_headers = Some(resp_parts.headers.clone());

    strip_hop_by_hop(&mut resp_parts.headers);

    // Inject security headers.
    inject_security_headers(&mut resp_parts.headers);

    // --- Phase 5: Response body (DLP stub) ---
    ctx.advance_phase(Phase::ResponseBody);

    // --- Phase 6: Logging ---
    ctx.advance_phase(Phase::Logging);
    log_request(&ctx);

    Ok(Response::from_parts(resp_parts, resp_body.boxed()))
}

// ---------------------------------------------------------------------------
// WAF phase stubs — will be filled by sentinel-rules / sentinel-modules
// ---------------------------------------------------------------------------

fn phase1_headers(ctx: &mut RequestContext, site: Option<&SiteConfig>) -> anyhow::Result<()> {
    let Some(site) = site else { return Ok(()) };
    if site.waf.mode == WafMode::Off {
        return Ok(());
    }

    // Rate limit, bot detection, IP rep checks will register here (Phase 2).
    // Rule engine hooks will register here (Phase 1).
    let _ = ctx;
    Ok(())
}

fn phase2_body(ctx: &mut RequestContext, site: Option<&SiteConfig>) -> anyhow::Result<()> {
    let Some(site) = site else { return Ok(()) };
    if site.waf.mode == WafMode::Off {
        return Ok(());
    }

    // Payload classifier ML, CRS body rules will register here.
    let _ = ctx;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn site_matches(site: &SiteConfig, host: &str) -> bool {
    site.domains.iter().any(|d| {
        if d.starts_with("*.") {
            let suffix = &d[1..]; // ".example.com"
            host.ends_with(suffix) || host == &d[2..]
        } else {
            d == host
        }
    })
}

fn build_upstream_uri(host: &str, port: u16, original: &Uri) -> anyhow::Result<Uri> {
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let s = format!("http://{}:{}{}", host, port, path_and_query);
    s.parse().context("building upstream URI")
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    // Also remove headers listed in the Connection header value.
    if let Some(conn) = headers
        .remove(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok().map(str::to_owned))
    {
        for token in conn.split(',') {
            headers.remove(token.trim());
        }
    }
}

fn inject_forwarding_headers(
    headers: &mut http::HeaderMap,
    client_ip: std::net::IpAddr,
) -> anyhow::Result<()> {
    let ip_str = client_ip.to_string();
    // Extend X-Forwarded-For if already present.
    if let Some(existing) = headers.get(header::HeaderName::from_static("x-forwarded-for")) {
        let val = format!("{}, {}", existing.to_str().unwrap_or(""), ip_str);
        headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            val.parse()?,
        );
    } else {
        headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            ip_str.parse()?,
        );
    }
    headers.insert(
        header::HeaderName::from_static("x-real-ip"),
        client_ip.to_string().parse()?,
    );
    Ok(())
}

fn inject_security_headers(headers: &mut http::HeaderMap) {
    let insert = |h: &mut http::HeaderMap, name: &'static str, value: &'static str| {
        h.entry(header::HeaderName::from_static(name))
            .or_insert_with(|| value.parse().unwrap());
    };
    insert(headers, "x-content-type-options", "nosniff");
    insert(headers, "x-frame-options", "SAMEORIGIN");
    insert(
        headers,
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
}

fn block_response(ctx: &RequestContext) -> Response<BoxBody> {
    let reason = ctx
        .block_reason
        .as_deref()
        .unwrap_or("Blocked by Sentinel WAF");
    let body = serde_json::json!({
        "error": "Forbidden",
        "message": reason,
        "request_id": ctx.request_id.to_string(),
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .unwrap()
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(
            Full::new(Bytes::from(message.to_string()))
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .unwrap()
}

fn log_request(ctx: &RequestContext) {
    let status = ctx
        .response_status
        .map(|s| s.as_u16())
        .unwrap_or(0);
    tracing::info!(
        request_id = %ctx.request_id,
        method = %ctx.method,
        uri = %ctx.uri,
        client_ip = %ctx.client_ip,
        site = ctx.site_id.as_deref().unwrap_or("-"),
        status,
        latency_ms = ctx.elapsed_ms(),
        anomaly_score = ctx.anomaly_score,
        decision = ?ctx.decision,
        "request"
    );
}

// ---------------------------------------------------------------------------
// TLS acceptor builder
// ---------------------------------------------------------------------------

fn build_tls_acceptor(tls: &sentinel_core::config::TlsFileConfig) -> anyhow::Result<TlsAcceptor> {
    let cert_path = tls
        .cert
        .as_ref()
        .ok_or_else(|| anyhow!("listener TLS config missing 'cert' path"))?;
    let key_path = tls
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("listener TLS config missing 'key' path"))?;

    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("opening TLS cert: {}", cert_path.display()))?;
    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("opening TLS key: {}", key_path.display()))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .context("reading TLS certificates")?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("reading TLS private key")?
        .ok_or_else(|| anyhow!("no private key found in {}", key_path.display()))?;

    let mut server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server config")?;

    // Advertise h2 and http/1.1 via ALPN.
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}
