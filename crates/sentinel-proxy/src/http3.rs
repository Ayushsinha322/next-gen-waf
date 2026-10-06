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
//! Wiring: `serve_listener` spawns [`serve_quic`] alongside the TCP accept loop
//! when a listener advertises `Protocol::Http3`, and advertises discovery via
//! the `Alt-Svc` header on TCP responses (browsers connect over TCP first, then
//! upgrade). See `crate::serve_listener`.

use std::convert::Infallible;
use std::net::SocketAddr;
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
use tracing::{debug, info, warn};

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

/// Bind a QUIC (UDP) endpoint and serve HTTP/3 until shutdown is signalled.
///
/// One QUIC connection multiplexes many HTTP/3 requests; each connection and
/// each request runs on its own task, mirroring the TCP accept loop.
pub(crate) async fn serve_quic(
    bind: SocketAddr,
    server_config: quinn::ServerConfig,
    state: Arc<ServerState>,
    default_site: Option<String>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, bind)
        .with_context(|| format!("binding QUIC/HTTP3 endpoint on udp://{bind}"))?;
    info!(%bind, "HTTP/3 (QUIC) endpoint listening");

    loop {
        tokio::select! {
            maybe_incoming = endpoint.accept() => {
                match maybe_incoming {
                    Some(incoming) => {
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
                        tokio::spawn(async move {
                            // Permit + gauge guard held for the connection's life.
                            let _permit = permit;
                            let _active = ActiveConnGuard::new();
                            if let Err(e) = handle_quic_connection(incoming, state, ds).await {
                                debug!("HTTP/3 connection error: {e}");
                            }
                        });
                    }
                    // Endpoint closed / no more connections.
                    None => break,
                }
            }
            _ = shutdown.changed() => {
                info!(%bind, "HTTP/3 endpoint shutting down");
                // Tell peers we're going away; give in-flight streams a moment.
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
        }
    }
    Ok(())
}

/// Complete the QUIC handshake for one connection, then run its HTTP/3 request
/// loop. The QUIC peer address is the client IP the WAF pipeline sees.
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    state: Arc<ServerState>,
    default_site: Option<String>,
) -> Result<()> {
    let conn = incoming
        .accept()
        .context("accepting QUIC connection")?
        .await
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

    loop {
        match h3_conn.accept().await {
            // A new request on a fresh QUIC stream.
            Ok(Some(resolver)) => {
                let state = Arc::clone(&state);
                let ds = default_site.clone();
                // Cloned per request: one connection's fingerprint serves every
                // request multiplexed over it, exactly as on a keep-alive TCP
                // connection.
                let fp = tls_fp.clone();
                let quic = quic.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(resolver, state, ds, peer, fp, quic).await {
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
async fn handle_h3_request(
    resolver: h3::server::RequestResolver<H3Conn, Bytes>,
    state: Arc<ServerState>,
    default_site: Option<String>,
    peer: SocketAddr,
    tls_fp: Option<String>,
    quic: quinn::Connection,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .context("resolving HTTP/3 request headers")?;
    let (mut parts, ()) = req.into_parts();
    // h3 delivers the request head without an http::Version tag; stamp it so the
    // WAF pipeline, NDJSON logs, and ClickHouse all record this request as h3.
    parts.version = http::Version::HTTP_3;
    debug!(method = %parts.method, uri = %parts.uri, "HTTP/3 request");
    // For the log lines below. Path only: the query can carry credentials, and
    // the access log already holds its redacted form.
    let method = parts.method.clone();
    let path = crate::cap_field(parts.uri.path(), 256);

    // Buffer the request body from the QUIC stream (capped as an OOM guard;
    // per-site size limits are enforced downstream in `proxy`).
    let body_buf = match read_h3_request_body(&mut stream, crate::body_read_timeout()).await? {
        H3RequestBody::Complete(body) => body,
        H3RequestBody::Refused(status) => {
            // This runs before the pipeline, so there is no access-log line;
            // this event is the record.
            info!(%peer, %method, %path, %status, "HTTP/3 request body refused");
            refuse_h3_request(&mut stream, status).await;
            return Ok(());
        }
    };

    let body: BoxBody = Full::new(Bytes::from(body_buf))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let pipeline_req = Request::from_parts(parts, body);

    // Run the full WAF pipeline — identical to the TCP path, JA4 included: the
    // fingerprint was extracted from this connection's TLS session at accept
    // time (see `ja4_quic`) and reaches `ctx.tls_fingerprint` exactly as the TCP
    // path's peeked fingerprint does.
    let resp = run_pipeline(state, peer, pipeline_req, default_site, tls_fp).await;
    if let Err(e) = send_h3_response(&mut stream, &quic, resp).await {
        // The access-log line was written with the head and records a complete
        // response, so this is the only trace of the truncation. Client
        // cancels and closed connections end the relay with Ok and never get
        // here, so this does not fire for ordinary abandoned downloads.
        sentinel_telemetry::metrics::note_h3_response_reset();
        warn!(%peer, %method, %path, "HTTP/3 response cut short, stream reset: {e:#}");
    }
    Ok(())
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

    /// The resolver-backed config path (Phase 1) produces a usable QUIC server
    /// config from an empty cert store (certs are resolved lazily at handshake).
    #[test]
    fn resolver_config_builds() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = crate::tls::CertStore::new(std::path::PathBuf::from("/tmp/sentinel-h3-test"));
        let resolver = crate::tls::SentinelCertResolver::new(store);
        assert!(quic_server_config_from_resolver(resolver).is_ok());
    }
}
