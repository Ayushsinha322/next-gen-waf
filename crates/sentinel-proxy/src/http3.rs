//! HTTP/3 (QUIC) support.
//!
//! HTTP/3 is HTTP semantics over **QUIC** (a UDP transport with built-in TLS
//! 1.3), not TCP. This module runs a QUIC endpoint on the same address as the
//! TCP listener and feeds every HTTP/3 request into the *same*, transport-
//! agnostic WAF pipeline the TCP path uses ([`crate::run_pipeline`]) — so all
//! inspection, rules, correlation, and logging apply identically over h3.
//!
//! Stack: `quinn` (QUIC/UDP) + `h3` (HTTP/3 framing + QPACK) + `h3-quinn`
//! (adapter). TLS reuses the live [`crate::tls::SentinelCertResolver`], so h3
//! serves the exact same cert repository (SNI / ACME / management) as TCP — no
//! separate PKI. QUIC mandates TLS 1.3; `QuicServerConfig::try_from` derives the
//! initial cipher suite from the rustls config's crypto provider (the ring
//! provider installed process-wide in `sentinel-bin::main`).
//!
//! Wiring: `serve_listener` binds the endpoint ([`bind_quic`]) and runs
//! [`serve_quic`] on it, supervised, alongside the TCP accept loop when a
//! listener advertises `Protocol::Http3`, and advertises discovery via the
//! `Alt-Svc` header on TCP responses while that loop runs (browsers connect over
//! TCP first, then upgrade). See `crate::serve_listener`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use http::{header, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use sentinel_telemetry::inc_load_shed_connections;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::{run_pipeline, ActiveConnGuard, BoxBody, ServerState};

/// The QUIC backend type used throughout. `h3` is generic over the QUIC impl;
/// `h3-quinn` is our only one, so we pin it here rather than threading `h3::quic`
/// trait bounds through every signature.
type H3Conn = h3_quinn::Connection;

/// One HTTP/3 request stream over [`H3Conn`], as the server side sees it.
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// ALPN identifier for HTTP/3. Clients advertise this over QUIC; the server must
/// select it or the handshake completes with no application protocol.
pub const ALPN_H3: &[u8] = b"h3";

/// Hard ceiling on how much of an HTTP/3 request body we buffer before handing
/// it to the pipeline. This is an out-of-memory guard only — the real, per-site
/// `max_body_size` limit is still enforced downstream in `proxy`. QUIC bodies
/// are buffered (not streamed) into the WAF request context for inspection,
/// exactly as the TCP path buffers bodies it inspects.
const MAX_H3_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Strip response headers that are illegal or meaningless over HTTP/3
/// (RFC 9114 §4.2). QUIC provides framing/multiplexing, so hop-by-hop TCP
/// framing headers must not be relayed onto an h3 stream.
fn strip_forbidden_h3_headers(headers: &mut header::HeaderMap) {
    headers.remove(header::CONNECTION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::UPGRADE);
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

// ---------------------------------------------------------------------------
// Server-config construction
// ---------------------------------------------------------------------------

/// Wrap a `rustls::ServerConfig` into a QUIC-capable `quinn::ServerConfig`.
///
/// Forces the ALPN list to exactly `["h3"]` (QUIC has no HTTP/1.1 fallback) and
/// converts via `QuicServerConfig`. Errors only if the config's crypto provider
/// lacks a QUIC-usable initial cipher suite (never the case for ring/aws-lc-rs).
pub fn quic_server_config(mut rustls_config: rustls::ServerConfig) -> Result<quinn::ServerConfig> {
    rustls_config.alpn_protocols = vec![ALPN_H3.to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| anyhow!("rustls ServerConfig is not QUIC-compatible: {e}"))?;
    // Wrapped so every QUIC session is fingerprinted — see `ja4_quic`. Without
    // this wrapper h3 clients reach the pipeline with no JA4 at all, which makes
    // the malicious-JA4 bot signal and the JA4 blocklist inert for h3 while they
    // stay active for TCP. `ja4_quic::fingerprint_for` logs at ERROR if it ever
    // finds the wrapper missing.
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        crate::ja4_quic::Ja4ServerConfig::new(Arc::new(quic)),
    )))
}

/// Build a QUIC server config that serves certificates from the live
/// [`crate::tls::SentinelCertResolver`] — i.e. the same SNI/ACME/management cert
/// repository the TCP listener resolves against. This is how HTTP/3 reuses the
/// product's whole certificate story with no new PKI.
pub fn quic_server_config_from_resolver(
    resolver: Arc<crate::tls::SentinelCertResolver>,
) -> Result<quinn::ServerConfig> {
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    quic_server_config(rustls_config)
}

// ---------------------------------------------------------------------------
// Endpoint + accept loops
// ---------------------------------------------------------------------------

/// Bind a listener's QUIC (UDP) endpoint.
///
/// Done once, outside the supervised accept loop ([`serve_quic`]), so a loop
/// restarted after a panic accepts on the same socket. Rebinding instead failed
/// with EADDRINUSE: quinn keeps the socket open while any connection of the old
/// endpoint is alive, so HTTP/3 stayed down for the rest of the process while
/// `Alt-Svc` went on advertising it.
pub(crate) fn bind_quic(
    bind: SocketAddr,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint> {
    let endpoint = new_endpoint(bind, server_config)
        .with_context(|| format!("binding QUIC/HTTP3 endpoint on udp://{bind}"))?;
    // A fresh endpoint on this address is up, whatever became of the last one.
    endpoints_down_lock().remove(&bind);
    info!(%bind, "HTTP/3 (QUIC) endpoint listening");
    Ok(endpoint)
}

/// `quinn::Endpoint::server`, spelled out so that a test can put a socket of
/// its own under the endpoint.
fn new_endpoint(
    bind: SocketAddr,
    server_config: quinn::ServerConfig,
) -> std::io::Result<quinn::Endpoint> {
    let socket = std::net::UdpSocket::bind(bind)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| std::io::Error::other("no async runtime found"))?;
    let socket = runtime.wrap_udp_socket(socket)?;
    #[cfg(test)]
    let socket = inject::FailingSocket::wrap(socket);
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
}

// ---------------------------------------------------------------------------
// Endpoints lost for good
// ---------------------------------------------------------------------------

/// An HTTP/3 endpoint that stopped serving for the rest of the process.
struct EndpointDown {
    reason: &'static str,
    /// Unix seconds.
    since: u64,
}

/// Endpoints whose accept loop stopped for good, by bind address: reported in
/// `/healthz` (`http3.down`) and the heartbeat, which reads "degraded" while
/// any is listed. The accept loop used to return without a word when its
/// endpoint's I/O driver stopped (a socket error ends it): the supervisor took
/// that for a clean finish, Alt-Svc was withdrawn, and `/healthz` went on
/// saying HTTP/3 was enabled.
static ENDPOINTS_DOWN: std::sync::Mutex<std::collections::BTreeMap<SocketAddr, EndpointDown>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn endpoints_down_lock(
) -> std::sync::MutexGuard<'static, std::collections::BTreeMap<SocketAddr, EndpointDown>> {
    ENDPOINTS_DOWN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn note_endpoint_down(bind: SocketAddr, reason: &'static str) {
    error!(
        %bind,
        reason,
        "HTTP/3 endpoint is gone; HTTP/3 is OFF on this listener until the process \
         restarts (TCP is unaffected and Alt-Svc is withdrawn). Queryable at \
         /healthz -> http3.down."
    );
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    endpoints_down_lock().insert(bind, EndpointDown { reason, since });
}

/// Whether any HTTP/3 endpoint of this node has stopped for good.
pub(crate) fn any_endpoint_down() -> bool {
    !endpoints_down_lock().is_empty()
}

/// The endpoints that stopped for good, for `/healthz` and the heartbeat.
pub(crate) fn endpoints_down() -> serde_json::Value {
    endpoints_down_lock()
        .iter()
        .map(|(bind, d)| {
            serde_json::json!({ "bind": bind.to_string(), "reason": d.reason, "since": d.since })
        })
        .collect()
}

/// A listener's `Alt-Svc` advertisement, attached to TCP responses only while
/// its HTTP/3 accept loop is running. A client sent to an endpoint nobody is
/// accepting on stalls its QUIC handshake before falling back to TCP, and
/// `ma=86400` makes it keep trying for a day.
#[derive(Clone)]
pub(crate) struct AltSvc {
    value: header::HeaderValue,
    serving: Arc<AtomicBool>,
}

impl AltSvc {
    pub(crate) fn new(value: header::HeaderValue, serving: Arc<AtomicBool>) -> Self {
        Self { value, serving }
    }

    /// The header to send, or `None` while the endpoint is not accepting.
    pub(crate) fn header(&self) -> Option<&header::HeaderValue> {
        self.serving.load(Ordering::Acquire).then_some(&self.value)
    }
}

/// Holds `serving` true for the life of an accept loop, and clears it however
/// the loop ends — a panic included.
struct Serving<'a>(&'a AtomicBool);

impl<'a> Serving<'a> {
    fn start(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Release);
        Self(flag)
    }
}

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The next accepted connection panics the accept loop, in test builds only.
#[cfg(test)]
pub(crate) static INJECT_ACCEPT_PANIC: AtomicBool = AtomicBool::new(false);

/// Serve HTTP/3 on a bound endpoint until shutdown is signalled. `serving` is
/// true while this accepts connections (not while it drains); it gates the
/// listener's [`AltSvc`].
///
/// One QUIC connection multiplexes many HTTP/3 requests; each connection and
/// each request runs on its own task, mirroring the TCP accept loop.
///
/// Shutdown drains rather than cuts. Connection and request tasks run on the
/// same `conn_tracker` as TCP connections, so `run` waits for them (bounded by
/// the drain grace). Each connection sends GOAWAY and finishes the requests it
/// already accepted; the endpoint refuses new connections and stays up until
/// every connection has closed or the grace runs out. It used to close at
/// once, cutting every in-flight h3 download and stream on each deploy while
/// TCP clients got the grace.
///
/// An endpoint whose I/O driver stopped ends the loop for good: nothing more
/// can arrive on it. That is recorded for `/healthz` and the heartbeat, and the
/// loop returns normally, so the supervisor does not restart it on the same
/// dead endpoint.
///
/// What this cannot report is an endpoint POISONED by a panic inside one of
/// quinn's critical sections: quinn's driver unwraps the poisoned lock on the
/// next datagram, and its `Drop` unwraps it again during that unwind, which
/// aborts the process. Our own code that quinn runs under that lock (the TLS
/// session decorator) is therefore kept from unwinding; see `ja4_quic`.
pub(crate) async fn serve_quic(
    endpoint: quinn::Endpoint,
    bind: SocketAddr,
    state: Arc<ServerState>,
    default_site: Option<String>,
    mut shutdown: watch::Receiver<bool>,
    serving: &AtomicBool,
) {
    let serving_guard = Serving::start(serving);
    loop {
        tokio::select! {
            maybe_incoming = endpoint.accept() => {
                match maybe_incoming {
                    Some(incoming) => {
                        #[cfg(test)]
                        if INJECT_ACCEPT_PANIC.swap(false, Ordering::SeqCst) {
                            panic!("injected HTTP/3 accept-loop panic");
                        }
                        // Connection admission control — share the global
                        // connection limiter with the TCP accept loop so the
                        // cap is truly process-wide across both transports.
                        // Over capacity: refuse the QUIC handshake (transport
                        // close) rather than spawn an unbounded task.
                        let permit = match Arc::clone(&state.conn_limiter).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                inc_load_shed_connections();
                                debug!("HTTP/3 connection admission: at max_connections, refusing");
                                incoming.refuse();
                                continue;
                            }
                        };
                        let state = Arc::clone(&state);
                        let ds = default_site.clone();
                        let conn_shutdown = shutdown.clone();
                        let tracker = state.conn_tracker.clone();
                        tracker.spawn(async move {
                            // Permit + gauge guard held for the connection's life.
                            let _permit = permit;
                            let _active = ActiveConnGuard::new();
                            if let Err(e) =
                                handle_quic_connection(incoming, state, ds, conn_shutdown).await
                            {
                                debug!("HTTP/3 connection error: {e}");
                            }
                        });
                    }
                    // The endpoint is closed only after this loop, so its I/O
                    // driver has stopped: nothing more can arrive.
                    None => {
                        note_endpoint_down(bind, "the endpoint's I/O driver stopped");
                        return;
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }

    // From here the endpoint only refuses, so it is no longer advertised.
    drop(serving_guard);
    let bind = endpoint.local_addr().ok();
    let grace = crate::drain_grace();
    info!(bind = ?bind, grace_secs = grace.as_secs(), "HTTP/3 endpoint draining");
    if drain_endpoint(&endpoint, grace).await {
        info!(bind = ?bind, "HTTP/3 connections drained");
    } else {
        warn!(
            bind = ?bind,
            grace_secs = grace.as_secs(),
            "drain grace elapsed; closing remaining HTTP/3 connections"
        );
    }
    endpoint.close(0u32.into(), b"shutdown");
}

/// Keep the endpoint up while its connections finish, refusing new ones, for
/// at most `grace`. True when every connection closed in time.
async fn drain_endpoint(endpoint: &quinn::Endpoint, grace: Duration) -> bool {
    let drained = async {
        let idle = endpoint.wait_idle();
        tokio::pin!(idle);
        loop {
            tokio::select! {
                biased;
                () = &mut idle => return,
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => incoming.refuse(),
                    // Closed elsewhere: nothing new can arrive.
                    None => return (&mut idle).await,
                },
            }
        }
    };
    tokio::time::timeout(grace, drained).await.is_ok()
}

/// Longest a QUIC handshake may take: the TCP path's TLS handshake bound, and
/// shorter in tests, which wait one out.
const H3_HANDSHAKE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(4)
} else {
    crate::HANDSHAKE_TIMEOUT
};

/// Complete the QUIC handshake for one connection, then run its HTTP/3 request
/// loop. The QUIC peer address is the client IP the WAF pipeline sees.
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    state: Arc<ServerState>,
    default_site: Option<String>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // Bounded like the TCP handshake. quinn has no handshake deadline of its
    // own, only the idle timeout, which every packet the client sends re-arms:
    // a client that kept retransmitting its hello held this task, and the
    // connection permit TCP shares, for as long as it liked.
    let conn = tokio::time::timeout(
        H3_HANDSHAKE_TIMEOUT,
        incoming.accept().context("accepting QUIC connection")?,
    )
    .await
    .context("QUIC handshake timed out")?
    .context("QUIC handshake failed")?;
    let peer = conn.remote_address();
    // Must happen BEFORE `conn` is moved into h3_quinn below: the fingerprint
    // rides in the connection's own TLS session, so there is no side table to
    // consult afterwards.
    let (tls_fp, ja4_outcome) = crate::ja4_quic::fingerprint_for(&conn);
    sentinel_telemetry::note_ja4_h3(tls_fp.is_some());
    if tls_fp.is_none() {
        // Not an error on its own — a refused hello is a legitimate outcome —
        // but the REASON must be recoverable, or "h3 has no fingerprint" is
        // once again a fact with no explanation.
        debug!(%peer, outcome = ja4_outcome.as_str(), "no h3 JA4 fingerprint");
    }
    debug!(%peer, ja4 = tls_fp.as_deref().unwrap_or("-"), "HTTP/3 connection established");
    // A handle on the QUIC connection itself, kept beside the h3 one: response
    // relays watch it to learn that the client has gone (see `relay_h3_body`).
    let quic = conn.clone();

    let mut h3_conn: h3::server::Connection<H3Conn, Bytes> = h3::server::builder()
        .build(h3_quinn::Connection::new(conn))
        .await
        .context("HTTP/3 connection setup")?;

    let mut goaway_sent = false;
    loop {
        tokio::select! {
            accepted = h3_conn.accept() => match accepted {
                // A new request on a fresh QUIC stream.
                Ok(Some(resolver)) => {
                    let ds = default_site.clone();
                    // Cloned per request: one connection's fingerprint serves
                    // every request multiplexed over it, exactly as on a
                    // keep-alive TCP connection.
                    let fp = tls_fp.clone();
                    let quic = quic.clone();
                    // Tracked like the connection, so a drain also waits for a
                    // request whose client has already gone.
                    let tracker = state.conn_tracker.clone();
                    let state = Arc::clone(&state);
                    tracker.spawn(async move {
                        if let Err(e) = handle_h3_request(resolver, state, ds, peer, fp, quic).await
                        {
                            debug!("HTTP/3 request error: {e}");
                        }
                    });
                }
                // Client closed the connection cleanly.
                Ok(None) => break,
                Err(e) => {
                    debug!("HTTP/3 accept error: {e}");
                    break;
                }
            },
            // Graceful shutdown. GOAWAY tells the client to send no new
            // requests here; the ones already accepted finish normally. Keep
            // accepting, so h3 refuses late streams, until the client closes
            // the connection or the drain grace ends and `serve_quic` closes
            // the endpoint. Closing it ourselves when the last response is
            // finished could cut off data quinn has not yet delivered.
            _ = shutdown.changed(), if !goaway_sent => {
                goaway_sent = true;
                if let Err(e) = h3_conn.shutdown(0).await {
                    debug!(%peer, "HTTP/3 GOAWAY failed: {e}");
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Adapt one HTTP/3 request into the shared WAF pipeline and stream the response
/// back over the QUIC stream.
///
/// The request head arrives as `http::Request<()>` (h3 maps the `:method`,
/// `:scheme`, `:authority`, `:path` pseudo-headers into the URI + headers, so
/// `proxy`'s existing `:authority`→`Host` synthesis works unchanged). The body
/// is read from the QUIC stream and buffered into a `BoxBody` so the pipeline
/// sees the same request shape it does over TCP.
///
/// The whole request task runs under panic guards, as `proxy` and
/// `contain_request` guard a TCP request. The pipeline keeps its own guard,
/// which answers 500 with the request's Support ID; these cover the rest of
/// the request's task. A panic before the response head is answered 500 with
/// a fresh Support ID, as on TCP; one while the response goes out resets the
/// stream (see [`respond_h3`]). One while the head is decoded (QPACK, in `h3`)
/// is counted and logged like the others, rate-limited; there is no stream yet
/// to answer on, so the client sees it ended.
async fn handle_h3_request(
    resolver: h3::server::RequestResolver<H3Conn, Bytes>,
    state: Arc<ServerState>,
    default_site: Option<String>,
    peer: SocketAddr,
    tls_fp: Option<String>,
    quic: quinn::Connection,
) -> Result<()> {
    let resolved = crate::panic_guard::catch_request(async {
        #[cfg(test)]
        if INJECT_RESOLVE_PANIC.swap(false, Ordering::SeqCst) {
            panic!("injected HTTP/3 request-head panic");
        }
        resolver.resolve_request().await
    })
    .await;
    let (req, mut stream) = match resolved {
        Ok(resolved) => resolved.context("resolving HTTP/3 request headers")?,
        Err(payload) => {
            crate::panic_guard::outside_pipeline_panicked(
                peer,
                &*payload,
                "its stream ended before the request head was read",
            );
            return Ok(());
        }
    };
    let (mut parts, ()) = req.into_parts();
    // h3 delivers the request head without an http::Version tag; stamp it so the
    // WAF pipeline, NDJSON logs, and ClickHouse all record this request as h3.
    parts.version = http::Version::HTTP_3;
    // QUIC is always TLS (`client_https`).
    parts.extensions.insert(crate::ClientTls);
    // Redacted as the access log is: the query can carry credentials.
    debug!(method = %parts.method, uri = %crate::logged_uri(&parts.uri), "HTTP/3 request");
    // For the log lines below. Path only: the query can carry credentials, and
    // the access log already holds its redacted form.
    let method = parts.method.clone();
    let path = crate::cap_field(parts.uri.path(), 256);

    let prepared = crate::panic_guard::catch_request(prepare_h3_response(
        &mut stream,
        parts,
        state,
        default_site,
        peer,
        tls_fp,
    ))
    .await;
    let resp = match prepared {
        Ok(Ok(H3Prepared::Response(resp))) => resp,
        Ok(Ok(H3Prepared::Refused(status))) => {
            // This runs before the pipeline, so there is no access-log line;
            // this event is the record.
            info!(%peer, %method, %path, %status, "HTTP/3 request body refused");
            refuse_h3_request(&mut stream, status).await;
            return Ok(());
        }
        Ok(Err(e)) => return Err(e),
        Err(payload) => {
            let support_id =
                crate::panic_guard::outside_pipeline_panicked(peer, &*payload, "answered 500");
            crate::panic_guard::panic_response(&support_id)
        }
    };
    respond_h3(&mut stream, &quic, peer, &method, &path, resp).await;
    Ok(())
}

/// Request path that panics once the request body is read, before the
/// pipeline, in test builds only.
#[cfg(test)]
pub(crate) const INJECT_PREPARE_PANIC_PATH: &str = "/__h3_panic_before_pipeline__";

/// The next HTTP/3 request panics while its head is read, in test builds only.
/// Only proxy tests reach `handle_h3_request`, and they run one at a time.
#[cfg(test)]
pub(crate) static INJECT_RESOLVE_PANIC: AtomicBool = AtomicBool::new(false);

/// What a request came to before its response head.
enum H3Prepared {
    /// The pipeline's response.
    Response(Response<BoxBody>),
    /// The body cannot be taken: answer with this status instead.
    Refused(StatusCode),
}

/// Read the request body off the stream, then run the WAF pipeline on it.
async fn prepare_h3_response(
    stream: &mut H3Stream,
    parts: http::request::Parts,
    state: Arc<ServerState>,
    default_site: Option<String>,
    peer: SocketAddr,
    tls_fp: Option<String>,
) -> Result<H3Prepared> {
    // Buffer the request body from the QUIC stream (capped as an OOM guard;
    // per-site size limits are enforced downstream in `proxy`).
    let body_buf = match read_h3_request_body(stream, crate::body_read_timeout()).await? {
        H3RequestBody::Complete(body) => body,
        H3RequestBody::Refused(status) => return Ok(H3Prepared::Refused(status)),
    };
    #[cfg(test)]
    if parts.uri.path() == INJECT_PREPARE_PANIC_PATH {
        panic!("injected HTTP/3 request panic");
    }

    let body: BoxBody = Full::new(Bytes::from(body_buf))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let pipeline_req = Request::from_parts(parts, body);

    // Run the full WAF pipeline — identical to the TCP path, JA4 included: the
    // fingerprint was extracted from this connection's TLS session at accept
    // time (see `ja4_quic`) and reaches `ctx.tls_fingerprint` exactly as the TCP
    // path's peeked fingerprint does.
    Ok(H3Prepared::Response(
        run_pipeline(state, peer, pipeline_req, default_site, tls_fp).await,
    ))
}

/// Send `resp` and relay its body ([`send_h3_response`]), under a panic guard
/// of its own.
///
/// The relay polls the response body after `proxy`'s guard has returned. A
/// panic there used to unwind the request's task and drop the stream, and
/// quinn FINISHES a send stream that is dropped unfinished: the client took
/// the truncated body for the whole response, which is what resetting the
/// stream on an origin failure exists to prevent. A panic resets it the same
/// way, also when it came before the head, so the client sees an error.
async fn respond_h3<B>(
    stream: &mut H3Stream,
    quic: &quinn::Connection,
    peer: SocketAddr,
    method: &http::Method,
    path: &str,
    resp: Response<B>,
) where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    match crate::panic_guard::catch_request(send_h3_response(stream, quic, resp)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // The access-log line was written with the head and records a
            // complete response, so this is the only trace of the truncation.
            // Client cancels and closed connections end the relay with Ok and
            // never get here, so this does not fire for ordinary abandoned
            // downloads.
            sentinel_telemetry::metrics::note_h3_response_reset();
            warn!(%peer, %method, %path, "HTTP/3 response cut short, stream reset: {e:#}");
        }
        Err(payload) => {
            stream.stop_stream(Code::H3_INTERNAL_ERROR);
            sentinel_telemetry::metrics::note_h3_response_reset();
            crate::panic_guard::outside_pipeline_panicked(
                peer,
                &*payload,
                "HTTP/3 response stream reset",
            );
        }
    }
}

/// What reading an HTTP/3 request body produced.
enum H3RequestBody {
    Complete(Vec<u8>),
    /// The body cannot be taken: answer with this status instead.
    Refused(StatusCode),
}

/// Read a request body off the QUIC stream: at most [`MAX_H3_BODY_BYTES`]
/// (else 413), and the whole of it within `deadline` (else 408).
///
/// The deadline is the TCP path's slow-body deadline (`body_read_timeout`).
/// There used to be none: a client could send part of a body and stop, and the
/// stream held its buffer (up to 64 MiB) for as long as the connection lived,
/// outside the request permit, which is taken only in `run_pipeline`. One QUIC
/// connection carries up to 100 such streams.
async fn read_h3_request_body(stream: &mut H3Stream, deadline: Duration) -> Result<H3RequestBody> {
    let read = async {
        let mut body = Vec::new();
        while let Some(chunk) = stream
            .recv_data()
            .await
            .context("reading HTTP/3 request body")?
        {
            if body.len().saturating_add(chunk.remaining()) > MAX_H3_BODY_BYTES {
                return Ok(H3RequestBody::Refused(StatusCode::PAYLOAD_TOO_LARGE));
            }
            append_buf(&mut body, chunk);
        }
        Ok(H3RequestBody::Complete(body))
    };
    tokio::time::timeout(deadline, read)
        .await
        .unwrap_or(Ok(H3RequestBody::Refused(StatusCode::REQUEST_TIMEOUT)))
}

/// Answer a request without reading the rest of its body.
///
/// No explicit STOP_SENDING: after a timed-out read, h3-quinn 0.0.10 still
/// holds the quinn receive stream inside the cancelled read, and its
/// `stop_sending` unwraps it and panics. Dropping the request stream when the
/// task ends sends STOP_SENDING anyway.
async fn refuse_h3_request(stream: &mut H3Stream, status: StatusCode) {
    let resp = Response::builder()
        .status(status)
        .body(())
        .expect("static response always builds");
    stream.send_response(resp).await.ok();
    stream.finish().await.ok();
}

/// Relay a pipeline response over an HTTP/3 request stream: the head, then the
/// body as it arrives (see [`relay_h3_body`]).
async fn send_h3_response<B>(
    stream: &mut H3Stream,
    quic: &quinn::Connection,
    resp: Response<B>,
) -> Result<()>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let (mut parts, body) = resp.into_parts();
    strip_forbidden_h3_headers(&mut parts.headers);
    // Through `end_on_send_error` like every other send: a client that
    // cancelled while the pipeline ran is not a failure of ours.
    if let Err(e) = stream.send_response(Response::from_parts(parts, ())).await {
        return end_on_send_error(stream, e, "sending HTTP/3 response headers");
    }
    relay_h3_body(stream, quic, body).await
}

/// Stream a response body onto an HTTP/3 request stream, frame by frame.
///
/// This used to `collect()` the whole body and send it as one DATA frame. An h3
/// client then got nothing until the origin had finished: a large download sat
/// whole in WAF memory (per stream, and one connection multiplexes many), an
/// event stream that never ends never arrived at all, and trailers (gRPC's
/// `grpc-status`) were dropped. TCP clients had none of this, because hyper
/// streams the same body as it arrives.
///
/// `body` is the response exactly as `run_pipeline` returned it, so it is
/// already past response inspection: a body that DLP or response rules had to
/// see was buffered and judged inside `proxy` and arrives here complete (an
/// origin that fails while it is being buffered is answered there with a logged
/// 502, since no head has been sent yet); anything else is the origin's own
/// stream. Nothing here inspects, so nothing here needs to buffer.
///
/// Accounting matches the TCP path because all of it happened before this
/// point. The access-log line, `bytes_sent` and the request-duration histogram
/// were recorded when `proxy` produced the response head, and the in-flight
/// request permit was released when `run_pipeline` returned. hyper streams a
/// TCP body after the service future has returned, outside the request permit,
/// and so does this.
///
/// How the relay ends:
/// - the origin finished: trailers if it sent any, then FIN;
/// - the client cancelled (STOP_SENDING) or its connection is gone: stop and
///   drop the origin body, which releases its upstream connection. That is
///   `Ok`, because an abandoned download is not a WAF failure. h3 exposes no
///   STOP_SENDING notification, so a cancel is noticed on the next write. A
///   closed connection is noticed at once, even while the origin is quiet
///   (long-poll, an idle event stream, a stalled origin): by then the
///   connection and request permits are both released, so a relay that waited
///   for the origin's next frame would hold the task and the upstream
///   connection with nothing bounding it;
/// - the origin failed mid-body: RESET the stream. A FIN would present a
///   truncated body as a complete one, and returning without finishing is not
///   enough, because quinn FINISHES a send stream that is dropped unfinished.
async fn relay_h3_body<B>(
    stream: &mut H3Stream,
    quic: &quinn::Connection,
    mut body: B,
) -> Result<()>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let closed = quic.closed();
    tokio::pin!(closed);
    loop {
        // `frame()` is cancel-safe: losing the race to `closed` loses no data.
        let frame = tokio::select! {
            biased;
            e = &mut closed => {
                debug!("HTTP/3 connection closed mid-response; relay stopped: {e}");
                return Ok(());
            }
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else { break };
        let frame = match frame {
            Ok(frame) => frame,
            Err(e) => {
                stream.stop_stream(Code::H3_INTERNAL_ERROR);
                return Err(anyhow!(
                    "response body failed mid-stream; HTTP/3 stream reset: {e}"
                ));
            }
        };
        let (sent, trailers_sent) = match frame.into_data() {
            Ok(data) if data.is_empty() => continue,
            Ok(data) => (stream.send_data(data).await, false),
            Err(frame) => match frame.into_trailers() {
                Ok(mut trailers) => {
                    strip_forbidden_h3_headers(&mut trailers);
                    (stream.send_trailers(trailers).await, true)
                }
                // A frame kind this relay does not know carries nothing to send.
                Err(_) => continue,
            },
        };
        if let Err(e) = sent {
            return end_on_send_error(stream, e, "sending HTTP/3 response body");
        }
        // Trailers end the message (RFC 9114 §4.1): no DATA may follow them.
        if trailers_sent {
            break;
        }
    }
    if let Err(e) = stream.finish().await {
        return end_on_send_error(stream, e, "finishing HTTP/3 stream");
    }
    Ok(())
}

/// Turn a failed send into the relay's result. A client that cancelled the
/// stream, or whose connection has closed, ends the response normally (`Ok`):
/// there is nobody left to tell. Anything else is our failure, and the stream
/// is reset so the client sees an error rather than a clean end to a short body.
fn end_on_send_error(stream: &mut H3Stream, e: StreamError, what: &'static str) -> Result<()> {
    match e {
        StreamError::RemoteTerminate { code, .. } => {
            debug!(%code, "HTTP/3 client cancelled the response; relay stopped");
            Ok(())
        }
        // Brace syntax: the variant is `#[non_exhaustive]`, so its tuple form
        // cannot be matched from outside h3.
        StreamError::ConnectionError { 0: e, .. } => {
            debug!("HTTP/3 connection closed mid-response; relay stopped: {e}");
            Ok(())
        }
        e => {
            stream.stop_stream(Code::H3_INTERNAL_ERROR);
            Err(anyhow::Error::new(e).context(what))
        }
    }
}

/// Append every segment of a `Buf` to `out`. `Buf::chunk` only exposes the first
/// contiguous slice, so drain until empty (h3-quinn yields contiguous `Bytes`,
/// but this stays correct for any multi-segment `Buf`).
fn append_buf(out: &mut Vec<u8>, mut b: impl Buf) {
    while b.has_remaining() {
        let chunk = b.chunk();
        out.extend_from_slice(chunk);
        let n = chunk.len();
        b.advance(n);
    }
}

/// Failures on demand under a real endpoint, in test builds only.
#[cfg(test)]
pub(crate) mod inject {
    use std::io::{self, IoSliceMut};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use quinn::udp::{RecvMeta, Transmit};
    use quinn::{AsyncUdpSocket, UdpPoller};

    /// Ports whose endpoint socket fails its next receive, as a socket whose
    /// interface went away does. quinn's I/O driver stops on it.
    pub(crate) static FAIL_RECV: Mutex<Vec<u16>> = Mutex::new(Vec::new());

    /// The endpoint's real socket, with [`FAIL_RECV`] in front of its receive.
    #[derive(Debug)]
    pub(crate) struct FailingSocket(Arc<dyn AsyncUdpSocket>);

    impl FailingSocket {
        pub(crate) fn wrap(inner: Arc<dyn AsyncUdpSocket>) -> Arc<dyn AsyncUdpSocket> {
            Arc::new(Self(inner))
        }
    }

    impl AsyncUdpSocket for FailingSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Arc::clone(&self.0).create_io_poller()
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            self.0.try_send(transmit)
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let port = self.0.local_addr().map(|a| a.port()).unwrap_or(0);
            let fail = FAIL_RECV
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&port);
            if fail {
                return Poll::Ready(Err(io::Error::other("injected socket failure")));
            }
            self.0.poll_recv(cx, bufs, meta)
        }

        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            self.0.local_addr()
        }

        fn max_transmit_segments(&self) -> usize {
            self.0.max_transmit_segments()
        }

        fn max_receive_segments(&self) -> usize {
            self.0.max_receive_segments()
        }

        fn may_fragment(&self) -> bool {
            self.0.may_fragment()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// Self-signed `localhost` server config, converted to a QUIC server config
    /// through the same `quic_server_config` used in production.
    fn test_server_config() -> quinn::ServerConfig {
        // Match sentinel-bin: ring is the process-default crypto provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.serialize_der().unwrap());
        let key_der = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());

        let rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
            .unwrap();

        quic_server_config(rustls_cfg).unwrap()
    }

    /// Test-only handler proving the QUIC + h3 transport end-to-end without a
    /// full `ServerState` (the pipeline itself is covered by the crate's WAF
    /// tests). Serves a canned 200 + body, mirroring what `handle_h3_request`
    /// does minus the `run_pipeline` call.
    async fn serve_canned_connection(incoming: quinn::Incoming) -> Result<()> {
        let conn = incoming.accept()?.await?;
        let mut h3_conn: h3::server::Connection<H3Conn, Bytes> = h3::server::builder()
            .build(h3_quinn::Connection::new(conn))
            .await?;
        while let Ok(Some(resolver)) = h3_conn.accept().await {
            let (_req, mut stream) = resolver.resolve_request().await?;
            while stream.recv_data().await?.is_some() {}
            let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
            stream.send_response(resp).await?;
            stream
                .send_data(Bytes::from_static(b"hello from the WAF over HTTP/3\n"))
                .await?;
            stream.finish().await?;
        }
        Ok(())
    }

    /// Test-only client verifier that accepts any server certificate. QUIC still
    /// runs a real TLS 1.3 handshake; we only skip PKI validation of the
    /// self-signed test cert. NEVER used outside `#[cfg(test)]`.
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

    fn test_client_config() -> quinn::ClientConfig {
        let mut rustls_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        rustls_cfg.alpn_protocols = vec![ALPN_H3.to_vec()];
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap();
        quinn::ClientConfig::new(Arc::new(qcc))
    }

    /// End-to-end proof: a real QUIC/HTTP-3 client GETs from the server and
    /// receives a 200 + body. Exercises the quinn/h3/h3-quinn stack against our
    /// rustls (ring) crypto and the `quic_server_config` conversion.
    #[tokio::test]
    async fn http3_round_trip() {
        let endpoint =
            quinn::Endpoint::server(test_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = endpoint.local_addr().unwrap();

        let server = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = serve_canned_connection(incoming).await;
            }
        });

        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(test_client_config());
        let conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await.unwrap() {
            append_buf(&mut body, chunk);
        }
        assert_eq!(&body, b"hello from the WAF over HTTP/3\n");

        drop(send_request);
        client.wait_idle().await;
        drive.abort();
        server.abort();
    }

    // -----------------------------------------------------------------------
    // Response streaming: `send_h3_response` / `relay_h3_body`
    // -----------------------------------------------------------------------

    use hyper::body::Frame;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context as TaskCx, Poll};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::timeout;

    type OriginFrame = std::result::Result<Frame<Bytes>, String>;
    type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

    /// A response body the test feeds frame by frame, standing in for an origin
    /// that sends when the test says so. The channel holds one frame, so the
    /// origin cannot run ahead of what the relay has taken. Dropping the body
    /// closes the channel, which is how a test sees the relay let go of it.
    struct ChanBody(mpsc::Receiver<OriginFrame>);

    impl Body for ChanBody {
        type Data = Bytes;
        type Error = String;
        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<Option<OriginFrame>> {
            self.0.poll_recv(cx)
        }
    }

    fn origin() -> (mpsc::Sender<OriginFrame>, ChanBody) {
        let (tx, rx) = mpsc::channel(1);
        (tx, ChanBody(rx))
    }

    fn data(b: &'static [u8]) -> OriginFrame {
        Ok(Frame::data(Bytes::from_static(b)))
    }

    /// A body of `total` bytes generated on demand, `LAZY_CHUNK` per frame, that
    /// records how much the relay has pulled from it. Each byte is derived from
    /// its offset, so the client can verify the whole body.
    struct LazyBody {
        total: usize,
        pulled: Arc<AtomicUsize>,
    }

    const LAZY_CHUNK: usize = 64 * 1024;

    fn byte_at(offset: usize) -> u8 {
        (offset % 251) as u8
    }

    impl Body for LazyBody {
        type Data = Bytes;
        type Error = String;
        fn poll_frame(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<Option<OriginFrame>> {
            let done = self.pulled.load(Ordering::SeqCst);
            if done >= self.total {
                return Poll::Ready(None);
            }
            let n = LAZY_CHUNK.min(self.total - done);
            let chunk: Vec<u8> = (done..done + n).map(byte_at).collect();
            self.pulled.store(done + n, Ordering::SeqCst);
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))))
        }
    }

    /// Bind a QUIC endpoint that hands ONE request stream, and the QUIC
    /// connection it arrived on, to `handler`. The receiver yields the
    /// handler's result, so a test can assert how the server side ended as well
    /// as what the client saw. The connection is driven as
    /// `handle_quic_connection` drives it, until the client leaves: quinn's
    /// `finish` does not wait for delivery, so closing the connection when the
    /// handler returns would cut off data still in flight.
    fn serve_one_with<F, Fut>(handler: F) -> (SocketAddr, oneshot::Receiver<Result<()>>)
    where
        F: FnOnce(H3Stream, quinn::Connection) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let endpoint =
            quinn::Endpoint::server(test_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("a client connects");
            let conn = incoming.accept().unwrap().await.unwrap();
            let quic = conn.clone();
            let mut h3_conn: h3::server::Connection<H3Conn, Bytes> = h3::server::builder()
                .build(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
            let resolver = h3_conn.accept().await.unwrap().expect("one request");
            tokio::spawn(async move {
                let (_req, stream) = resolver.resolve_request().await.unwrap();
                let _ = done_tx.send(handler(stream, quic).await);
            });
            while let Ok(Some(_)) = h3_conn.accept().await {}
        });
        (addr, done_rx)
    }

    /// [`serve_one_with`] answering with `resp` through the production
    /// `send_h3_response`; the receiver yields the relay's own result.
    fn serve_one<B>(resp: Response<B>) -> (SocketAddr, oneshot::Receiver<Result<()>>)
    where
        B: Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: std::fmt::Display + Send,
    {
        serve_one_with(move |mut stream, quic| async move {
            send_h3_response(&mut stream, &quic, resp).await
        })
    }

    /// A test client with one request in flight on `stream`. The other fields
    /// keep the connection alive for as long as the test reads; `conn` lets a
    /// test close it.
    struct Client {
        stream: ClientStream,
        conn: quinn::Connection,
        _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        _endpoint: quinn::Endpoint,
        driver: tokio::task::JoinHandle<()>,
    }

    impl Drop for Client {
        fn drop(&mut self) {
            self.driver.abort();
        }
    }

    /// Connect and send `req`'s head. The request body stays open.
    async fn open(addr: SocketAddr, cfg: quinn::ClientConfig, req: http::Request<()>) -> Client {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(cfg);
        let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(conn.clone()))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let stream = send_request.send_request(req).await.unwrap();
        Client {
            stream,
            conn,
            _send_request: send_request,
            _endpoint: endpoint,
            driver,
        }
    }

    async fn get(addr: SocketAddr, cfg: quinn::ClientConfig) -> Client {
        let req = http::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut client = open(addr, cfg, req).await;
        client.stream.finish().await.unwrap();
        client
    }

    /// Read the rest of the body into `out`. A reset stream is returned as the
    /// error, not unwrapped: some tests expect one.
    async fn read_to_end(
        stream: &mut ClientStream,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), StreamError> {
        while let Some(chunk) = stream.recv_data().await? {
            append_buf(out, chunk);
        }
        Ok(())
    }

    /// The first body chunk reaches the client while the origin is still
    /// sending. This origin sends one chunk and then WAITS for the client to
    /// confirm it before sending the rest, so a relay that collects the body
    /// before sending delivers nothing (the old relay timed out here).
    #[tokio::test]
    async fn h3_first_body_chunk_reaches_client_before_origin_finishes() {
        let (origin_tx, body) = origin();
        let (addr, relay_done) = serve_one(Response::new(body));
        let (got_first_tx, got_first_rx) = oneshot::channel::<()>();
        let origin_task = tokio::spawn(async move {
            origin_tx.send(data(b"first ")).await.unwrap();
            if got_first_rx.await.is_ok() {
                origin_tx.send(data(b"second")).await.unwrap();
            }
            // Dropping the sender ends the body.
        });

        let mut client = get(addr, test_client_config()).await;
        let resp = client.stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let first = timeout(Duration::from_secs(5), client.stream.recv_data())
            .await
            .expect(
                "no body reached the h3 client while the origin was still sending: \
                 the relay is buffering the response instead of streaming it",
            )
            .unwrap()
            .expect("the body ended before its first chunk");
        let mut body = Vec::new();
        append_buf(&mut body, first);
        assert_eq!(body, b"first ");

        got_first_tx.send(()).unwrap();
        read_to_end(&mut client.stream, &mut body).await.unwrap();
        assert_eq!(body, b"first second");
        relay_done.await.unwrap().unwrap();
        origin_task.await.unwrap();
    }

    /// A 16 MiB body arrives intact, and the relay never runs far ahead of the
    /// client. The client's stream window is pinned at 1 MiB, so QUIC flow
    /// control lets the relay hand quinn at most what the client has read plus
    /// that window; a streaming relay therefore pulls little more than the
    /// window beyond the client's position. The old relay pulled all 16 MiB into
    /// memory before the first byte left.
    #[tokio::test]
    async fn h3_large_body_streams_under_flow_control() {
        const TOTAL: usize = 16 * 1024 * 1024;
        const WINDOW: u32 = 1024 * 1024;
        // Twice the window covers quinn re-advertising credit before the client
        // reads it all; the chunks cover the frame the relay holds.
        const MAX_AHEAD: usize = 2 * WINDOW as usize + 4 * LAZY_CHUNK;

        let pulled = Arc::new(AtomicUsize::new(0));
        let body = LazyBody {
            total: TOTAL,
            pulled: Arc::clone(&pulled),
        };
        let resp = Response::builder()
            .header(header::CONTENT_LENGTH, TOTAL)
            .body(body)
            .unwrap();
        let (addr, relay_done) = serve_one(resp);

        let mut cfg = test_client_config();
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(WINDOW));
        cfg.transport_config(Arc::new(transport));
        let mut client = get(addr, cfg).await;
        let resp = client.stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut received = 0usize;
        let mut max_ahead = 0usize;
        let mut first_bad_offset = None;
        while let Some(mut chunk) = timeout(Duration::from_secs(30), client.stream.recv_data())
            .await
            .expect("large h3 body stalled")
            .unwrap()
        {
            max_ahead = max_ahead.max(pulled.load(Ordering::SeqCst).saturating_sub(received));
            while chunk.has_remaining() {
                let piece = chunk.chunk();
                if first_bad_offset.is_none() {
                    first_bad_offset = piece
                        .iter()
                        .enumerate()
                        .find(|&(i, &b)| b != byte_at(received + i))
                        .map(|(i, _)| received + i);
                }
                let n = piece.len();
                received += n;
                chunk.advance(n);
            }
        }

        assert_eq!(received, TOTAL, "the whole body must arrive");
        assert_eq!(first_bad_offset, None, "body bytes corrupted in transit");
        assert!(
            max_ahead <= MAX_AHEAD,
            "the relay pulled {max_ahead} bytes beyond what the client had read \
             (bound {MAX_AHEAD}): it is buffering the body, not streaming it"
        );
        relay_done.await.unwrap().unwrap();
    }

    /// Trailers reach the client after the body. gRPC carries its status in
    /// trailers, so losing them fails every gRPC call; the old relay dropped
    /// them in `collect().to_bytes()`.
    #[tokio::test]
    async fn h3_response_trailers_are_relayed() {
        let (origin_tx, body) = origin();
        let (addr, relay_done) = serve_one(Response::new(body));
        tokio::spawn(async move {
            origin_tx.send(data(b"\0\0\0\0\x05hello")).await.unwrap();
            let mut trailers = header::HeaderMap::new();
            trailers.insert("grpc-status", header::HeaderValue::from_static("0"));
            trailers.insert("grpc-message", header::HeaderValue::from_static("ok"));
            origin_tx.send(Ok(Frame::trailers(trailers))).await.unwrap();
        });

        let mut client = get(addr, test_client_config()).await;
        client.stream.recv_response().await.unwrap();
        let mut body = Vec::new();
        read_to_end(&mut client.stream, &mut body).await.unwrap();
        assert_eq!(body, b"\0\0\0\0\x05hello");
        let trailers = client
            .stream
            .recv_trailers()
            .await
            .unwrap()
            .expect("the origin's trailers must reach the h3 client");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");
        assert_eq!(trailers.get("grpc-message").unwrap(), "ok");
        relay_done.await.unwrap().unwrap();
    }

    /// A client that cancels mid-body (STOP_SENDING) ends the relay promptly and
    /// cleanly: `Ok`, with the origin body dropped so its upstream connection is
    /// released. This origin would keep sending for seconds; the old relay kept
    /// collecting until it finished, then reported an error.
    #[tokio::test]
    async fn h3_client_cancel_stops_relay_and_releases_origin() {
        const ORIGIN_RUN: Duration = Duration::from_secs(5);
        let (origin_tx, body) = origin();
        let (addr, relay_done) = serve_one(Response::new(body));
        // Streams until ORIGIN_RUN elapses or the relay drops the body; says which.
        let origin_task = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + ORIGIN_RUN;
            while tokio::time::Instant::now() < deadline {
                let chunk = Ok(Frame::data(Bytes::from(vec![b'x'; 16 * 1024])));
                if origin_tx.send(chunk).await.is_err() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            false
        });

        let mut client = get(addr, test_client_config()).await;
        client.stream.recv_response().await.unwrap();
        client
            .stream
            .recv_data()
            .await
            .unwrap()
            .expect("some body arrives before the cancel");
        client.stream.stop_sending(Code::H3_REQUEST_CANCELLED);

        let relay = timeout(Duration::from_secs(3), relay_done)
            .await
            .expect("the relay kept going after the client cancelled")
            .unwrap();
        assert!(
            relay.is_ok(),
            "a client cancel is a normal end, not a relay error: {relay:?}"
        );
        assert!(
            origin_task.await.unwrap(),
            "the relay must drop the origin body when the client cancels"
        );
    }

    /// A client whose connection closes while the origin is quiet (long-poll,
    /// an idle event stream, a stalled origin) releases the origin at once. The
    /// relay used to notice the client only on its next write, so it held its
    /// task and the upstream connection for as long as the origin stayed quiet,
    /// with the connection and request permits already released.
    #[tokio::test]
    async fn h3_connection_closing_while_the_origin_is_quiet_releases_the_origin() {
        let (origin_tx, body) = origin();
        let (addr, relay_done) = serve_one(Response::new(body));
        let mut client = get(addr, test_client_config()).await;
        client.stream.recv_response().await.unwrap();
        // One event proves the relay is past the head and waiting on the origin.
        origin_tx.send(data(b"data: hello\n\n")).await.unwrap();
        client
            .stream
            .recv_data()
            .await
            .unwrap()
            .expect("the first event arrives");

        // The origin goes quiet, and the client leaves.
        client.conn.close(0u32.into(), b"leaving");
        timeout(Duration::from_secs(5), origin_tx.closed())
            .await
            .expect("the relay kept the origin body after the client's connection closed");
        let relay = timeout(Duration::from_secs(5), relay_done)
            .await
            .expect("the relay outlived its client's connection")
            .unwrap();
        assert!(
            relay.is_ok(),
            "a departed client is a normal end, not a relay error: {relay:?}"
        );
    }

    /// A client that leaves before the head is sent (it gave up while the
    /// pipeline waited on the origin) is an ordinary end, not a failure. The
    /// head send used to return an error, and errors from here are now warned
    /// about and counted as truncated responses.
    #[tokio::test]
    async fn h3_client_leaving_before_the_head_is_not_a_failure() {
        let (got_request_tx, got_request_rx) = oneshot::channel();
        let (addr, relay_done) = serve_one_with(|mut stream, quic| async move {
            let _ = got_request_tx.send(());
            // Stands in for a pipeline still waiting on its origin.
            quic.closed().await;
            let resp = Response::new(Full::new(Bytes::from_static(b"too late")));
            send_h3_response(&mut stream, &quic, resp).await
        });
        let client = get(addr, test_client_config()).await;
        got_request_rx.await.unwrap();
        client.conn.close(0u32.into(), b"leaving");
        let relay = timeout(Duration::from_secs(5), relay_done)
            .await
            .expect("the server side never finished")
            .unwrap();
        assert!(
            relay.is_ok(),
            "a client that left before the head is not a relay error: {relay:?}"
        );
    }

    /// POST `body` and leave the request open when `finish` is false.
    async fn post(addr: SocketAddr, body: &'static [u8], finish: bool) -> Client {
        let req = http::Request::builder()
            .method("POST")
            .uri("https://localhost/upload")
            .body(())
            .unwrap();
        let mut client = open(addr, test_client_config(), req).await;
        client
            .stream
            .send_data(Bytes::from_static(body))
            .await
            .unwrap();
        if finish {
            client.stream.finish().await.unwrap();
        }
        client
    }

    /// Serve one request the way `handle_h3_request` takes its body, with a
    /// short read deadline. The receiver yields the body when it was read.
    fn serve_body_read(
        deadline: Duration,
    ) -> (
        SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        oneshot::Receiver<Result<()>>,
    ) {
        let (body_tx, body_rx) = oneshot::channel();
        let (addr, done) = serve_one_with(move |mut stream, quic| async move {
            match read_h3_request_body(&mut stream, deadline).await? {
                H3RequestBody::Complete(body) => {
                    let _ = body_tx.send(body);
                    let resp = Response::new(Full::new(Bytes::from_static(b"stored")));
                    send_h3_response(&mut stream, &quic, resp).await
                }
                H3RequestBody::Refused(status) => {
                    refuse_h3_request(&mut stream, status).await;
                    Ok(())
                }
            }
        });
        (addr, body_rx, done)
    }

    /// A request body that stalls is answered 408 once the read deadline
    /// passes. There was no deadline: this client would have held its stream
    /// and buffer for as long as the connection lived.
    #[tokio::test]
    async fn h3_request_body_that_stalls_is_answered_408() {
        let (addr, _body, done) = serve_body_read(Duration::from_millis(200));
        let mut client = post(addr, b"part of a body", false).await;
        let resp = timeout(Duration::from_secs(5), client.stream.recv_response())
            .await
            .expect("a stalled request body was never answered")
            .unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        timeout(Duration::from_secs(5), done)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// A body that arrives within the deadline is read whole.
    #[tokio::test]
    async fn h3_request_body_within_the_deadline_is_read_whole() {
        let (addr, body, done) = serve_body_read(Duration::from_secs(5));
        let mut client = post(addr, b"the whole body", true).await;
        let resp = client.stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body.await.unwrap(), b"the whole body");
        let mut out = Vec::new();
        read_to_end(&mut client.stream, &mut out).await.unwrap();
        assert_eq!(out, b"stored");
        done.await.unwrap().unwrap();
    }

    /// An origin that fails mid-body reaches the client as a stream error, never
    /// as a clean end to a short body. The old relay returned early once the head
    /// was sent, quinn finished the dropped stream, and the client saw a
    /// complete, empty 200.
    #[tokio::test]
    async fn h3_origin_failure_mid_body_resets_the_stream() {
        let (origin_tx, body) = origin();
        let (addr, relay_done) = serve_one(Response::new(body));
        tokio::spawn(async move {
            origin_tx.send(data(b"partial")).await.unwrap();
            let _ = origin_tx
                .send(Err("origin reset the connection".into()))
                .await;
        });

        let mut client = get(addr, test_client_config()).await;
        // The error may surface at the head: a RESET_STREAM lets the receiver
        // discard whatever it has not yet read, the head included.
        let outcome = timeout(Duration::from_secs(5), async {
            client.stream.recv_response().await?;
            let mut body = Vec::new();
            read_to_end(&mut client.stream, &mut body).await?;
            Ok::<_, StreamError>(body)
        })
        .await
        .expect("the client never learned how the body ended");
        if let Ok(body) = outcome {
            panic!(
                "a body the origin cut short must reach the client as a stream error, \
                 not a clean end ({} bytes then FIN)",
                body.len()
            );
        }
        assert!(relay_done.await.unwrap().is_err());
    }

    /// The shutdown drain is bounded and ends early. A client that stays holds
    /// the endpoint only for the grace; once it leaves, the drain completes.
    #[tokio::test]
    async fn endpoint_drain_waits_for_clients_and_is_bounded() {
        let endpoint =
            quinn::Endpoint::server(test_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(test_client_config());
        let (client, _server) = tokio::join!(
            async {
                client_endpoint
                    .connect(addr, "localhost")
                    .unwrap()
                    .await
                    .unwrap()
            },
            async { endpoint.accept().await.unwrap().await.unwrap() },
        );

        let started = tokio::time::Instant::now();
        assert!(
            !drain_endpoint(&endpoint, Duration::from_millis(200)).await,
            "the drain reported success with a client still connected"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the drain outlived its grace"
        );

        client.close(0u32.into(), b"leaving");
        assert!(
            timeout(
                Duration::from_secs(5),
                drain_endpoint(&endpoint, Duration::from_secs(30))
            )
            .await
            .expect("the drain kept waiting after the last client left"),
            "the drain should end once every connection has closed"
        );
    }

    /// `Alt-Svc` follows the accept loop: set while it runs, cleared however it
    /// ends. It used to be attached unconditionally, so after the endpoint died
    /// every TCP response still sent clients to it for a day (`ma=86400`).
    #[test]
    fn alt_svc_is_advertised_only_while_the_endpoint_accepts() {
        let flag = Arc::new(AtomicBool::new(false));
        let alt = AltSvc::new(
            header::HeaderValue::from_static("h3=\":443\"; ma=86400"),
            Arc::clone(&flag),
        );
        assert!(alt.header().is_none(), "not accepting yet");
        {
            let _serving = Serving::start(&flag);
            assert_eq!(alt.header().unwrap(), "h3=\":443\"; ma=86400");
        }
        assert!(alt.header().is_none(), "the loop returned");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _serving = Serving::start(&flag);
            panic!("accept loop panic");
        }));
        assert!(unwound.is_err());
        assert!(alt.header().is_none(), "the loop panicked");
    }

    /// Client side of the proxy tests below: one HTTP/3 connection and its
    /// driver.
    struct H3Client {
        send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        driver: tokio::task::JoinHandle<()>,
    }

    impl H3Client {
        async fn connect(client: &quinn::Endpoint, addr: SocketAddr) -> Result<Self> {
            Self::connect_using(client, addr, None).await
        }

        /// [`H3Client::connect`] with a client config other than the default.
        async fn connect_using(
            client: &quinn::Endpoint,
            addr: SocketAddr,
            cfg: Option<&quinn::ClientConfig>,
        ) -> Result<Self> {
            let connecting = match cfg {
                Some(cfg) => client.connect_with(cfg.clone(), addr, "panic-site.local")?,
                None => client.connect(addr, "panic-site.local")?,
            };
            let conn = connecting.await?;
            let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
            let driver = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            Ok(Self { send, driver })
        }

        /// Keep trying for `within`: the endpoint may be between runs.
        async fn connect_within(
            client: &quinn::Endpoint,
            addr: SocketAddr,
            within: std::time::Duration,
        ) -> Self {
            Self::connect_within_using(client, addr, within, None).await
        }

        async fn connect_within_using(
            client: &quinn::Endpoint,
            addr: SocketAddr,
            within: std::time::Duration,
            cfg: Option<&quinn::ClientConfig>,
        ) -> Self {
            let deadline = std::time::Instant::now() + within;
            loop {
                let attempt = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    Self::connect_using(client, addr, cfg),
                )
                .await;
                match attempt {
                    Ok(Ok(c)) => return c,
                    Ok(Err(e)) => assert!(
                        std::time::Instant::now() < deadline,
                        "no HTTP/3 connection: {e:#}"
                    ),
                    Err(_) => assert!(
                        std::time::Instant::now() < deadline,
                        "no HTTP/3 connection: handshake timed out"
                    ),
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }

        async fn request(&mut self, path: &str) -> (StatusCode, Vec<u8>) {
            let req = http::Request::get(format!("https://panic-site.local{path}"))
                .body(())
                .unwrap();
            let mut stream = self.send.send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            let resp = stream.recv_response().await.unwrap();
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.unwrap() {
                append_buf(&mut body, chunk);
            }
            (resp.status(), body)
        }

        async fn get(&mut self, path: &str) -> StatusCode {
            self.request(path).await.0
        }
    }

    /// A running proxy serving `panic-site.local` over HTTP/1.1 and HTTP/3,
    /// and a client endpoint for it.
    struct H3Proxy {
        proxy: crate::panic_guard::testkit::RunningProxy,
        listen: SocketAddr,
        /// Requests that reached the origin.
        hits: Arc<AtomicUsize>,
        cert_dir: std::path::PathBuf,
        client: quinn::Endpoint,
    }

    impl H3Proxy {
        /// Callers hold `proxy_state_lock`, as for every test that runs a proxy.
        async fn start() -> Self {
            Self::start_with(|_| {}).await
        }

        /// [`H3Proxy::start`], with `tweak` applied to the config first.
        async fn start_with(
            tweak: impl FnOnce(&mut sentinel_core::config::SentinelConfig),
        ) -> Self {
            use crate::panic_guard::testkit::*;
            use sentinel_core::config::{Protocol, ProtocolSpec, TlsFileConfig};

            let (origin, hits) = counting_origin().await;
            let listen = free_port();
            let cert_dir =
                std::env::temp_dir().join(format!("sk-h3-panic-{}", uuid::Uuid::new_v4()));
            let mut cfg = site_config(listen, origin, "panic-site", vec![]);
            cfg.cert_dir = Some(cert_dir.clone());
            cfg.listeners[0].tls = Some(TlsFileConfig {
                ca: None,
                cert: None,
                key: None,
                min_version: Default::default(),
                post_quantum: Default::default(),
            });
            cfg.listeners[0].protocol =
                ProtocolSpec::Multiple(vec![Protocol::Http1, Protocol::Http3]);
            tweak(&mut cfg);
            let proxy = start_proxy(listen, config_handle(cfg)).await;

            let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(Self::client_config(vec![ALPN_H3.to_vec()]));
            Self {
                proxy,
                listen,
                hits,
                cert_dir,
                client,
            }
        }

        /// The client config: `alpn` offered, and a short idle timeout.
        fn client_config(alpn: Vec<Vec<u8>>) -> quinn::ClientConfig {
            let mut rustls_cfg = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth();
            rustls_cfg.alpn_protocols = alpn;
            let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap();
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(qcc));
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(Duration::from_secs(5).try_into().unwrap()));
            transport.keep_alive_interval(Some(Duration::from_secs(1)));
            client_cfg.transport_config(Arc::new(transport));
            client_cfg
        }

        async fn stop(self) {
            self.client.close(0u32.into(), b"done");
            self.proxy.stop().await;
            let _ = std::fs::remove_dir_all(&self.cert_dir);
        }
    }

    /// A panic in the accept loop used to cost HTTP/3 for the rest of the
    /// process. The restarted loop bound a new endpoint, which failed with
    /// EADDRINUSE while any connection of the old one was alive; the failure
    /// was a normal return, so nothing retried, and handshakes to the old
    /// socket stalled unaccepted. Now the restart accepts on the same socket.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_panic_in_the_accept_loop_does_not_take_http3_down() {
        let _serial = crate::panic_guard::testkit::proxy_state_lock();
        let h3 = H3Proxy::start().await;
        let (client, listen) = (&h3.client, h3.listen);

        // An established connection, kept open: it is what kept the old
        // endpoint's socket bound.
        let mut first = H3Client::connect_within(client, listen, Duration::from_secs(20)).await;
        assert_eq!(first.get("/one").await, StatusCode::OK);

        // The next handshake panics the accept loop.
        INJECT_ACCEPT_PANIC.store(true, Ordering::SeqCst);
        let _ =
            tokio::time::timeout(Duration::from_secs(3), H3Client::connect(client, listen)).await;
        assert!(
            !INJECT_ACCEPT_PANIC.load(Ordering::SeqCst),
            "the injected panic fired"
        );

        // After the restart, a new connection is accepted and served...
        let mut fresh = H3Client::connect_within(client, listen, Duration::from_secs(20)).await;
        assert_eq!(fresh.get("/after-the-panic").await, StatusCode::OK);
        // ...and the first connection was never affected.
        assert_eq!(first.get("/one-again").await, StatusCode::OK);
        assert_eq!(h3.hits.load(Ordering::SeqCst), 3);

        first.driver.abort();
        fresh.driver.abort();
        drop((first, fresh));
        h3.stop().await;
    }

    /// The proxy side of ja4_quic's handshake-panic tests. A panic in the
    /// handshake ran inside quinn's locks: on the first Initial packet it
    /// poisoned the endpoint and HTTP/3 stopped for good; on a later one it
    /// killed the connection's driver, and the accepting task waited for ever
    /// holding its connection permit, which TCP shares. With max_connections = 1
    /// each connection here is accepted only once the one before it gave its
    /// permit back.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_panicking_handshake_costs_only_that_connection() {
        use crate::ja4_quic::inject;

        let _serial = crate::panic_guard::testkit::proxy_state_lock();
        let h3 = H3Proxy::start_with(|cfg| cfg.limits.max_connections = 1).await;
        let within = Duration::from_secs(20);

        let mut plain = H3Client::connect_within(&h3.client, h3.listen, within).await;
        assert_eq!(plain.get("/before").await, StatusCode::OK);
        plain.driver.abort();
        drop(plain);

        // The cert resolver panics: that handshake fails, promptly.
        let mut refused = None;
        let deadline = std::time::Instant::now() + within;
        while refused.is_none() {
            let connecting = h3
                .client
                .connect(h3.listen, crate::tls::cert_store::INJECT_RESOLVER_PANIC_SNI)
                .unwrap();
            match timeout(Duration::from_secs(10), connecting).await {
                // Refused for want of a permit while the last connection ends.
                Ok(Err(quinn::ConnectionError::ConnectionClosed(close)))
                    if close.error_code == quinn_proto::TransportErrorCode::CONNECTION_REFUSED => {}
                Ok(Err(quinn::ConnectionError::ConnectionClosed(close))) => refused = Some(close),
                other => panic!("the handshake whose resolver panicked: {other:?}"),
            }
            assert!(std::time::Instant::now() < deadline, "never got a permit");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let refused = refused.unwrap();
        assert_eq!(
            refused.error_code,
            quinn_proto::TransportErrorCode::INTERNAL_ERROR,
            "{refused:?}"
        );

        // The fingerprinting panics, on the first packet or a later one: the
        // connection is served, unfingerprinted.
        let padding: Vec<Vec<u8>> = (0..6u8).map(|i| vec![b'a' + i; 250]).collect();
        for alpn in [
            vec![ALPN_H3.to_vec(), inject::FIRST_CHUNK.to_vec()],
            [
                vec![ALPN_H3.to_vec()],
                padding,
                vec![inject::LATER_CHUNK.to_vec()],
            ]
            .concat(),
        ] {
            let cfg = H3Proxy::client_config(alpn);
            let mut conn =
                H3Client::connect_within_using(&h3.client, h3.listen, within, Some(&cfg)).await;
            assert_eq!(conn.get("/unfingerprinted").await, StatusCode::OK);
            conn.driver.abort();
            drop(conn);
        }

        let mut after = H3Client::connect_within(&h3.client, h3.listen, within).await;
        assert_eq!(after.get("/after").await, StatusCode::OK);
        assert_eq!(h3.hits.load(Ordering::SeqCst), 4);
        after.driver.abort();
        drop(after);
        h3.stop().await;
    }

    /// A handshake that never completes (here the server's flight is never
    /// written, so the client keeps retransmitting its hello) held its task
    /// and its connection permit, which TCP shares, for as long as the client
    /// kept the connection from idling: quinn has no handshake deadline. Enough
    /// of them and the node accepted nothing on either transport. The
    /// handshake is bounded now, like TCP's, and the permit comes back.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_stalled_handshake_gives_its_permit_back() {
        let _serial = crate::panic_guard::testkit::proxy_state_lock();
        let h3 = H3Proxy::start_with(|cfg| cfg.limits.max_connections = 1).await;
        let within = Duration::from_secs(20);
        let refused = |r: &std::result::Result<quinn::Connection, quinn::ConnectionError>| {
            matches!(r, Err(quinn::ConnectionError::ConnectionClosed(c))
                if c.error_code == quinn_proto::TransportErrorCode::CONNECTION_REFUSED)
        };

        // A patient client: its own idle timeout must not end the handshake.
        let mut cfg = H3Proxy::client_config(vec![
            ALPN_H3.to_vec(),
            crate::ja4_quic::inject::STALL.to_vec(),
        ]);
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        cfg.transport_config(Arc::new(transport));

        // Until the stalled handshake holds the one permit (start-up's TCP
        // probe can hold it for a moment, and then this one is refused).
        let deadline = std::time::Instant::now() + within;
        let stalled = loop {
            let attempt = h3
                .client
                .connect_with(cfg.clone(), h3.listen, "panic-site.local")
                .unwrap();
            let mut attempt = tokio::spawn(attempt);
            match timeout(Duration::from_secs(1), &mut attempt).await {
                Err(_) => break attempt,
                Ok(r) => assert!(refused(&r.unwrap()), "the stall did not stall"),
            }
            assert!(std::time::Instant::now() < deadline, "never got a permit");
        };
        let probe = h3.client.connect(h3.listen, "panic-site.local").unwrap();
        let probe = timeout(Duration::from_secs(3), probe).await;
        assert!(
            probe.as_ref().is_ok_and(refused),
            "the stalled handshake must hold the permit: {probe:?}"
        );
        let held_since = std::time::Instant::now();

        // Accepted only once the stalled handshake's permit is back.
        let mut next = H3Client::connect_within(
            &h3.client,
            h3.listen,
            H3_HANDSHAKE_TIMEOUT + Duration::from_secs(10),
        )
        .await;
        assert_eq!(next.get("/after").await, StatusCode::OK);
        assert!(
            held_since.elapsed() < H3_HANDSHAKE_TIMEOUT + Duration::from_secs(10),
            "held for {:?}",
            held_since.elapsed()
        );
        let ended = timeout(Duration::from_secs(5), stalled)
            .await
            .expect("the stalled client never learned its handshake was over")
            .unwrap();
        assert!(
            ended.is_err() && !refused(&ended),
            "the stalled handshake: {ended:?}"
        );
        next.driver.abort();
        drop(next);
        h3.stop().await;
    }

    /// An endpoint whose I/O driver stopped (a socket error ends it) made the
    /// accept loop return without a word: the supervisor took it for a clean
    /// finish, and `/healthz` and the heartbeat went on reporting HTTP/3
    /// enabled and the node healthy while nothing was served over it. It is
    /// recorded now, once, and the loop is not restarted on the dead endpoint.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_lost_endpoint_is_reported_and_not_restarted() {
        let _serial = crate::panic_guard::testkit::proxy_state_lock();
        let h3 = H3Proxy::start().await;
        let restarts = crate::panic_guard::task_restarts("HTTP/3 endpoint");

        inject::FAIL_RECV.lock().unwrap().push(h3.listen.port());
        // A datagram for the driver to fail on.
        let _ = timeout(
            Duration::from_secs(3),
            H3Client::connect(&h3.client, h3.listen),
        )
        .await;

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let reason = loop {
            if let Some(d) = endpoints_down_lock().get(&h3.listen) {
                break d.reason;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the lost endpoint was never reported: {}",
                endpoints_down()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert!(reason.contains("driver stopped"), "{reason}");
        assert!(any_endpoint_down(), "the heartbeat must read degraded");
        assert!(
            endpoints_down()
                .as_array()
                .is_some_and(|d| d.iter().any(|e| e["bind"] == h3.listen.to_string())),
            "/healthz: {}",
            endpoints_down()
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            crate::panic_guard::task_restarts("HTTP/3 endpoint"),
            restarts,
            "the accept loop was restarted on a dead endpoint"
        );

        inject::FAIL_RECV
            .lock()
            .unwrap()
            .retain(|p| *p != h3.listen.port());
        endpoints_down_lock().remove(&h3.listen);
        h3.stop().await;
    }

    /// An HTTP/3 request that panics is contained like a TCP one: answered 500
    /// with a Support ID, never forwarded, and the connection keeps serving.
    /// A panic in the pipeline is `proxy`'s guard, reached through
    /// `run_pipeline`. One in the h3 request task outside the pipeline (here,
    /// once the body is read) had no guard: it unwound the task and the client
    /// got a stream that ended with no response at all.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // serialises whole server runs; see proxy_state_lock
    async fn a_panicking_h3_request_gets_a_500_and_the_connection_keeps_serving() {
        let _serial = crate::panic_guard::testkit::proxy_state_lock();
        let h3 = H3Proxy::start().await;
        let mut conn =
            H3Client::connect_within(&h3.client, h3.listen, Duration::from_secs(20)).await;

        for path in [
            INJECT_PREPARE_PANIC_PATH,
            crate::panic_guard::INJECT_PANIC_PATH,
        ] {
            let (status, body) = conn.request(path).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
            let json: serde_json::Value = serde_json::from_slice(&body)
                .unwrap_or_else(|e| panic!("{path}: {e}: {}", String::from_utf8_lossy(&body)));
            let id = json["support_id"].as_str().unwrap_or_default();
            assert!(uuid::Uuid::parse_str(id).is_ok(), "{path}: {json}");
        }
        assert_eq!(conn.get("/after-the-panics").await, StatusCode::OK);
        assert_eq!(
            h3.hits.load(Ordering::SeqCst),
            1,
            "a panicking request reached the origin"
        );
        conn.driver.abort();
        drop(conn);

        // A panic while the head is read has no stream to answer on, but is
        // counted like the others (and logged, rate-limited); the node serves
        // on.
        let before = sentinel_telemetry::request_panics_total();
        INJECT_RESOLVE_PANIC.store(true, Ordering::SeqCst);
        let mut conn =
            H3Client::connect_within(&h3.client, h3.listen, Duration::from_secs(20)).await;
        let req = http::Request::get("https://panic-site.local/head")
            .body(())
            .unwrap();
        if let Ok(mut stream) = conn.send.send_request(req).await {
            let _ = stream.finish().await;
            let _ = timeout(Duration::from_secs(5), stream.recv_response()).await;
        }
        assert!(!INJECT_RESOLVE_PANIC.load(Ordering::SeqCst), "it fired");
        assert!(sentinel_telemetry::request_panics_total() > before);
        conn.driver.abort();
        drop(conn);
        let mut conn =
            H3Client::connect_within(&h3.client, h3.listen, Duration::from_secs(20)).await;
        assert_eq!(conn.get("/after-the-head").await, StatusCode::OK);
        conn.driver.abort();
        drop(conn);
        h3.stop().await;
    }

    /// A response body that yields one chunk, then panics once `go` fires: a
    /// bug reached while the relay polls a body, after the pipeline's guard has
    /// returned. Waiting for `go` lets the client take the head and the first
    /// chunk before the panic.
    struct PanicAfterFirstChunk {
        sent: bool,
        go: oneshot::Receiver<()>,
    }

    impl Body for PanicAfterFirstChunk {
        type Data = Bytes;
        type Error = String;
        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<Option<OriginFrame>> {
            if !std::mem::replace(&mut self.sent, true) {
                return Poll::Ready(Some(data(b"partial ")));
            }
            match std::future::Future::poll(Pin::new(&mut self.go), cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(_) => panic!("injected response-body panic"),
            }
        }
    }

    /// A panic while the body is relayed resets the stream. It used to unwind
    /// the request's task; quinn finished the dropped stream, and the client
    /// read the truncated body as the complete response.
    #[tokio::test]
    async fn h3_panic_while_relaying_resets_the_stream() {
        let before = sentinel_telemetry::request_panics_total();
        let peer: SocketAddr = "198.51.100.7:4433".parse().unwrap();
        let (go_tx, go) = oneshot::channel();
        let (addr, relay_done) = serve_one_with(move |mut stream, quic| async move {
            let resp = Response::new(PanicAfterFirstChunk { sent: false, go });
            respond_h3(&mut stream, &quic, peer, &http::Method::GET, "/", resp).await;
            Ok(())
        });

        let mut client = get(addr, test_client_config()).await;
        let resp = client.stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let first = timeout(Duration::from_secs(5), client.stream.recv_data())
            .await
            .expect("the first chunk never arrived")
            .unwrap()
            .expect("the body ended before its first chunk");
        let mut body = Vec::new();
        append_buf(&mut body, first);
        go_tx.send(()).unwrap();

        let end = timeout(
            Duration::from_secs(5),
            read_to_end(&mut client.stream, &mut body),
        )
        .await
        .expect("the stream neither ended nor was reset");
        assert!(
            end.is_err(),
            "a truncated body ended as a complete one: {:?}",
            String::from_utf8_lossy(&body)
        );
        relay_done.await.unwrap().unwrap();
        assert!(sentinel_telemetry::request_panics_total() > before);
    }

    /// The resolver-backed config path (Phase 1) produces a usable QUIC server
    /// config from an empty cert store (certs are resolved lazily at handshake).
    #[test]
    fn resolver_config_builds() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Its own directory: building the resolver persists the default cert,
        // and a fixed shared path would collect keys from every run and user.
        let dir = std::env::temp_dir().join(format!("sentinel-h3-test-{}", std::process::id()));
        let store = crate::tls::CertStore::new(dir.clone());
        let resolver = crate::tls::SentinelCertResolver::new(store);
        assert!(quic_server_config_from_resolver(resolver).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
