//! WebSocket upgrade proxying with WAF frame inspection.
//!
//! After the HTTP/1.1 upgrade handshake (101 Switching Protocols) the proxy
//! performs a fully transparent bidirectional relay between the client and
//! upstream with per-frame WAF inspection of text frames.
//!
//! ## WAF inspection
//! Only WebSocket text frames (opcode 0x1) are inspected; binary frames and
//! control frames (ping/pong/close) are passed through unmodified.  Text
//! frames are evaluated through the full sentinel-rules RuleEngine using a
//! synthetic RequestContext with the frame payload as the request body and
//! Phase::RequestBody.  This means the same CRS/SRL rules that protect HTTP
//! requests also protect WebSocket messages — no substring bypasses.
//!
//! Matched frames are **dropped** and the connection is closed with a 1008
//! (policy violation) close frame sent to the client.
//!
//! ## Rate limiting
//! Text frame rate limiting: up to [`MAX_FRAMES_PER_SEC`] text frames per
//! second per connection; excess frames are silently dropped.  This prevents
//! frame-flooding attacks.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use http::{Method, Uri, Version};
use sentinel_core::context::{Phase, RequestContext, WafDecision};
use sentinel_rules::RuleEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Frame-level constants (RFC 6455)
// ---------------------------------------------------------------------------

const OPCODE_TEXT: u8 = 0x1;
const OPCODE_CLOSE: u8 = 0x8;

/// Maximum text frames per second per WebSocket connection before rate-limiting.
const MAX_FRAMES_PER_SEC: u32 = 60;

/// Maximum individual frame payload size we inspect (bytes).  Frames larger
/// than this are passed through without content inspection.
const MAX_INSPECT_FRAME_BYTES: usize = 64 * 1024; // 64 KiB

/// Absolute maximum WebSocket frame payload we will buffer and relay (bytes).
/// A frame declaring a larger length is rejected and the connection is torn
/// down.  This guard runs *before* any allocation, so a malicious length field
/// cannot trigger an allocation-capacity panic (release builds use
/// `panic = "abort"`, so such a panic would crash the entire proxy process)
/// or exhaust worker memory.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Synthetic URI used when constructing a RequestContext for frame inspection.
const WS_INSPECT_URI: &str = "/__sentinel_ws_frame__";

// ---------------------------------------------------------------------------
// Frame reader / writer helpers (RFC 6455 §5.2)
// ---------------------------------------------------------------------------

/// A decoded WebSocket frame.
pub struct WsFrame {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    pub mask: [u8; 4],
    pub payload: Vec<u8>,
    /// Raw bytes of the complete frame (for transparent forwarding).
    pub raw: Vec<u8>,
}

/// Read one WebSocket frame from `reader`.  Returns `None` on clean EOF.
pub async fn read_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<WsFrame>> {
    // Read 2-byte header.
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0F;
    let masked = header[1] & 0x80 != 0;
    let len_byte = header[1] & 0x7F;

    let payload_len: usize = match len_byte {
        126 => {
            let mut ext = [0u8; 2];
            reader
                .read_exact(&mut ext)
                .await
                .context("WS frame 16-bit length")?;
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            reader
                .read_exact(&mut ext)
                .await
                .context("WS frame 64-bit length")?;
            u64::from_be_bytes(ext) as usize
        }
        n => n as usize,
    };

    // Hard-cap the declared length BEFORE allocating.  Without this, a ~10-byte
    // frame declaring a huge length reaches `vec![0u8; payload_len]` below and
    // aborts the process (capacity-overflow panic under panic=abort) or OOMs
    // the worker.  Reject oversized frames and let the caller close the relay.
    if payload_len > MAX_FRAME_BYTES {
        anyhow::bail!("WS frame payload length {payload_len} exceeds maximum {MAX_FRAME_BYTES}");
    }

    let mask = if masked {
        let mut m = [0u8; 4];
        reader.read_exact(&mut m).await.context("WS masking key")?;
        m
    } else {
        [0u8; 4]
    };

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("WS frame payload")?;
    }

    // Unmask if needed.
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }

    // Re-encode the raw frame for forwarding (without mask for simplicity).
    let raw = encode_frame(fin, opcode, false, [0u8; 4], &payload);

    Ok(Some(WsFrame {
        fin,
        opcode,
        masked,
        mask,
        payload,
        raw,
    }))
}

/// Encode a WebSocket frame.
fn encode_frame(fin: bool, opcode: u8, masked: bool, mask: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    let byte0 = if fin { 0x80 } else { 0x00 } | (opcode & 0x0F);
    out.push(byte0);

    let mask_bit: u8 = if masked { 0x80 } else { 0x00 };
    let plen = payload.len();
    if plen < 126 {
        out.push(mask_bit | plen as u8);
    } else if plen < 65536 {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(plen as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(plen as u64).to_be_bytes());
    }

    if masked {
        out.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// Build a WebSocket close frame with a 4-byte body `[status_hi, status_lo, ...]`.
fn close_frame(code: u16, reason: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(reason.len() + 2);
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason);
    encode_frame(true, OPCODE_CLOSE, true, fresh_mask(), &payload)
}

/// A fresh, unpredictable masking key for a client-to-server frame.
///
/// RFC 6455 §5.1: a client MUST mask every frame it sends, and a server MUST
/// close the connection on receiving an unmasked one. Toward the origin this
/// relay IS the client. §5.3 requires the key to be unpredictable — it exists so
/// a hostile page cannot choose the bytes an intermediary sees on the wire — so
/// it comes from the system CSPRNG, never a counter.
///
/// `fill` failing means the OS RNG is unavailable, which on Linux does not
/// happen after boot. The zero key it would leave is still a SET mask bit —
/// correct framing that strict servers accept — only predictable, which is the
/// lesser failure than breaking every WebSocket on the node.
fn fresh_mask() -> [u8; 4] {
    use ring::rand::SecureRandom as _;
    let mut m = [0u8; 4];
    let _ = ring::rand::SystemRandom::new().fill(&mut m);
    m
}

/// Re-encode a frame read from the CLIENT for forwarding to the ORIGIN.
///
/// `read_frame` unmasks the payload so the rule engine can inspect it, and its
/// `raw` is the UNMASKED encoding — right for the origin→client direction, where
/// frames must not be masked, and wrong for this one. Forwarding `raw` upstream
/// sent every client frame unmasked, so any strict WebSocket server (gorilla,
/// Node `ws`, Python `websockets`) closed the connection with 1002 on the first
/// message: VM consoles and live dashboards behind the WAF could complete the
/// handshake and then carry nothing. The e2e suite never noticed because it
/// checked for the 101 and stopped.
fn to_origin(frame: &WsFrame) -> Vec<u8> {
    encode_frame(frame.fin, frame.opcode, true, fresh_mask(), &frame.payload)
}

// ---------------------------------------------------------------------------
// Bidirectional relay with WAF inspection
// ---------------------------------------------------------------------------

/// Relay WebSocket traffic between two halves of an upgraded connection.
///
/// `client_io` is the byte stream to the browser; `upstream_io` is the byte
/// stream to the backend server.  Text frames from the client are evaluated
/// through the sentinel-rules RuleEngine before forwarding; all other frames
/// (binary, control, server→client) are forwarded transparently.
///
/// If `rule_engine` is `None`, text frames pass through uninspected (used
/// when a site has no rule engine configured).
pub async fn relay<C, U>(
    client_io: C,
    upstream_io: U,
    client_ip: IpAddr,
    site_id: String,
    rule_engine: Option<Arc<RuleEngine>>,
) where
    C: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    U: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut client_read, mut client_write) = tokio::io::split(client_io);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_io);

    // Client → Upstream (with WAF inspection on text frames).
    let c2u_site = site_id.clone();
    let c2u_engine = rule_engine.clone();
    let c2u = tokio::spawn(async move {
        let mut frame_count_this_sec: u32 = 0;
        let mut window_start = Instant::now();

        loop {
            let frame = match read_frame(&mut client_read).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    debug!(client_ip = %client_ip, "WS c→u: read error: {e}");
                    break;
                }
            };

            match frame.opcode {
                OPCODE_TEXT if frame.payload.len() <= MAX_INSPECT_FRAME_BYTES => {
                    // Rate limit text frames.
                    if Instant::now().duration_since(window_start) >= Duration::from_secs(1) {
                        frame_count_this_sec = 0;
                        window_start = Instant::now();
                    }
                    frame_count_this_sec += 1;
                    if frame_count_this_sec > MAX_FRAMES_PER_SEC {
                        warn!(
                            client_ip = %client_ip,
                            site = %c2u_site,
                            "WS rate limit: too many text frames, dropping"
                        );
                        continue; // drop frame silently
                    }

                    // WAF inspection via full RuleEngine.
                    if let Some(ref engine) = c2u_engine {
                        let mut ctx = RequestContext::new(client_ip, 0);
                        ctx.uri = WS_INSPECT_URI
                            .parse()
                            .unwrap_or_else(|_| Uri::from_static(WS_INSPECT_URI));
                        ctx.http_version = Version::HTTP_11;
                        ctx.method = Method::POST;
                        ctx.site_id = Some(c2u_site.clone());
                        ctx.request_body = Some(bytes::Bytes::copy_from_slice(&frame.payload));
                        let decision = engine.evaluate(&mut ctx, Phase::RequestBody, 0);
                        if decision == WafDecision::Block {
                            warn!(
                                client_ip = %client_ip,
                                site = %c2u_site,
                                anomaly_score = ctx.anomaly_score,
                                matches = ctx.rule_matches.len(),
                                payload_len = frame.payload.len(),
                                "WS frame blocked by rule engine"
                            );
                            // Ask the ORIGIN to close with 1008 (policy violation).
                            // The client write half belongs to the u→c task, so
                            // the client learns of it the protocol's way: the
                            // origin answers a Close with a Close, and that
                            // crosses the u→c relay. This comment used to say the
                            // frame went "to client"; it never did — and it went
                            // unmasked, so a strict origin rejected even the close
                            // and the client was left with a silent socket.
                            let cf = close_frame(1008, b"WAF: attack detected");
                            let _ = upstream_write.write_all(&cf).await;
                            break;
                        }
                    }
                    // Clean — forward, masked (see `to_origin`).
                    if upstream_write.write_all(&to_origin(&frame)).await.is_err() {
                        break;
                    }
                }
                OPCODE_CLOSE => {
                    // Forward close and stop.
                    let _ = upstream_write.write_all(&to_origin(&frame)).await;
                    break;
                }
                _ => {
                    // Binary / continuation / ping / pong — pass through, masked.
                    if upstream_write.write_all(&to_origin(&frame)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Upstream → Client (fully transparent — we don't inspect server responses).
    let u2c = tokio::spawn(async move {
        loop {
            let frame = match read_frame(&mut upstream_read).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    debug!("WS u→c: read error: {e}");
                    break;
                }
            };
            if client_write.write_all(&frame.raw).await.is_err() {
                break;
            }
            if frame.opcode == OPCODE_CLOSE {
                break;
            }
        }
    });

    // Either direction closing terminates the whole relay.
    tokio::select! {
        _ = c2u => {}
        _ = u2c => {}
    }

    debug!(client_ip = %client_ip, "WebSocket relay closed");
}
