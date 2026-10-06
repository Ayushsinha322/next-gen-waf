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

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use http::{header, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use sentinel_telemetry::inc_load_shed_connections;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::{run_pipeline, ActiveConnGuard, BoxBody, ServerState};

/// The QUIC backend type used throughout. `h3` is generic over the QUIC impl;
/// `h3-quinn` is our only one, so we pin it here rather than threading `h3::quic`
/// trait bounds through every signature.
type H3Conn = h3_quinn::Connection;

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
                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(resolver, state, ds, peer, fp).await {
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

    // Buffer the request body from the QUIC stream (capped as an OOM guard;
    // per-site size limits are enforced downstream in `proxy`).
    let mut body_buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .context("reading HTTP/3 request body")?
    {
        if body_buf.len().saturating_add(chunk.remaining()) > MAX_H3_BODY_BYTES {
            let resp = Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .expect("static response always builds");
            stream.send_response(resp).await.ok();
            stream.finish().await.ok();
            return Ok(());
        }
        append_buf(&mut body_buf, chunk);
    }

    let body: BoxBody = Full::new(Bytes::from(body_buf))
        .map_err(|never: Infallible| match never {})
        .boxed();
    let pipeline_req = Request::from_parts(parts, body);

    // Run the full WAF pipeline — identical to the TCP path, JA4 included: the
    // fingerprint was extracted from this connection's TLS session at accept
    // time (see `ja4_quic`) and reaches `ctx.tls_fingerprint` exactly as the TCP
    // path's peeked fingerprint does.
    let resp = run_pipeline(state, peer, pipeline_req, default_site, tls_fp).await;

    // Relay the response over the QUIC stream: headers first, then body.
    let (mut resp_parts, resp_body) = resp.into_parts();
    strip_forbidden_h3_headers(&mut resp_parts.headers);
    let head = Response::from_parts(resp_parts, ());
    stream
        .send_response(head)
        .await
        .context("sending HTTP/3 response headers")?;

    let bytes = resp_body
        .collect()
        .await
        .map_err(|e| anyhow!("collecting response body for HTTP/3: {e}"))?
        .to_bytes();
    if !bytes.is_empty() {
        stream
            .send_data(bytes)
            .await
            .context("sending HTTP/3 response body")?;
    }
    stream.finish().await.context("finishing HTTP/3 stream")?;
    Ok(())
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
