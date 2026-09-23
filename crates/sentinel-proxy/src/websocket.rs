//! WebSocket upgrade proxying with WAF message inspection.
//!
//! After the HTTP/1.1 upgrade handshake (101 Switching Protocols) the proxy
//! relays frames in both directions, inspecting every client TEXT MESSAGE.
//!
//! ## WAF inspection
//! A text message is reassembled from its fragments (RFC 6455 §5.4) and handed
//! whole to a [`MessageInspector`] — in the proxy, the same rule-engine, ML and
//! verdict path an HTTP request body takes, honouring the site's mode. Nothing
//! of the message reaches the origin until the whole of it has been judged, so
//! an attack cannot be split across fragments to dodge the rules. Control frames
//! interleaved between fragments pass straight through, as the RFC allows.
//!
//! Binary messages are relayed uninspected: they are an application's own
//! encoding (msgpack, protobuf, VNC framebuffers) and text rules run over them
//! produce false positives, not detections.
//!
//! A refused message is never forwarded: the relay sends the origin a Close —
//! 1008 policy violation, 1009 too big to inspect, 1002 protocol error — and the
//! origin's answering Close reaches the client over the other direction.
//!
//! Compression (permessage-deflate) is never negotiated through the relay; the
//! proxy withdraws the client's offer at the handshake. A compressed message
//! cannot be inspected, and a frame with a reserved bit set is refused.
//!
//! ## Rate limiting
//! Inspection costs CPU, so inspected messages draw from a per-connection token
//! bucket ([`INSPECT_RATE_PER_SEC`], burst [`INSPECT_BURST`]). A client over the
//! rate is SLOWED — the relay stops reading its socket and TCP pushes back — and
//! nothing is ever dropped. Dropping, as this module once did past 60 messages a
//! second, silently lost characters from web terminals.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Frame-level constants (RFC 6455)
// ---------------------------------------------------------------------------

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// Close codes (RFC 6455 §7.4.1).
pub const CLOSE_PROTOCOL_ERROR: u16 = 1002;
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;
pub const CLOSE_TOO_BIG: u16 = 1009;
pub const CLOSE_INTERNAL_ERROR: u16 = 1011;

/// Sustained inspected messages per second per connection. Above it the relay
/// slows the client down; it never drops a message.
pub const INSPECT_RATE_PER_SEC: f64 = 200.0;

/// Messages a client may send at once before the sustained rate applies — a
/// dashboard's burst of subscriptions on connect, a paste into a terminal.
pub const INSPECT_BURST: f64 = 400.0;

/// Largest text message the inspector reads (bytes), however it is fragmented.
/// A larger one is handed to [`MessageInspector::too_large`] — refused in
/// blocking mode, forwarded uninspected (and logged) in learning mode — the same
/// rule as an HTTP body over its limit. It used to be 64 KiB per FRAME, and a
/// frame over it was forwarded uninspected in every mode: a bypass by padding.
pub const MAX_INSPECT_MESSAGE_BYTES: usize = 1024 * 1024;

/// Absolute maximum WebSocket frame payload we will buffer and relay (bytes).
/// A frame declaring a larger length is rejected and the connection is torn
/// down.  This guard runs *before* any allocation, so a malicious length field
/// cannot trigger an allocation-capacity panic (release builds use
/// `panic = "abort"`, so such a panic would crash the entire proxy process)
/// or exhaust worker memory.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

// ---------------------------------------------------------------------------
// Frame reader / writer helpers (RFC 6455 §5.2)
// ---------------------------------------------------------------------------

/// A decoded WebSocket frame.
pub struct WsFrame {
    pub fin: bool,
    /// RSV1-3 (bits 6..4 of the first byte). Must be zero: no extension is ever
    /// negotiated through the relay.
    pub rsv: u8,
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
    let rsv = (header[0] >> 4) & 0x07;
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
        rsv,
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
// Inspection interface
// ---------------------------------------------------------------------------

/// What to do with one client message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Forward,
    /// Do not forward; close the socket with this code.
    Refuse(u16),
}

/// Judges client text messages. The proxy implements it over the site's rule
/// engine and verdict path; the relay knows nothing of rules or modes.
pub trait MessageInspector: Send + Sync {
    /// One complete text message, reassembled.
    fn inspect(&self, message: &[u8]) -> Verdict;
    /// A text message that grew past [`MAX_INSPECT_MESSAGE_BYTES`] (`len` so
    /// far). `Forward` means relay the rest of it uninspected.
    fn too_large(&self, len: usize) -> Verdict;
}

/// Per-connection token bucket. `take` waits rather than refuses.
struct Throttle {
    tokens: f64,
    last: Instant,
    throttled: bool,
}

impl Throttle {
    fn new() -> Self {
        Self {
            tokens: INSPECT_BURST,
            last: Instant::now(),
            throttled: false,
        }
    }

    /// Cost of a message: one token, plus one per 64 KiB, so a stream of large
    /// messages is paced by the bytes it makes the rule engine read.
    fn cost(len: usize) -> f64 {
        1.0 + (len / (64 * 1024)) as f64
    }

    /// How long to wait before `cost` is available, taking it.
    fn reserve(&mut self, cost: f64) -> Option<Duration> {
        let now = Instant::now();
        self.tokens = (self.tokens
            + now.duration_since(self.last).as_secs_f64() * INSPECT_RATE_PER_SEC)
            .min(INSPECT_BURST);
        self.last = now;
        self.tokens -= cost;
        (self.tokens < 0.0).then(|| Duration::from_secs_f64(-self.tokens / INSPECT_RATE_PER_SEC))
    }
}

/// A client text message being reassembled.
enum Pending {
    /// Held back until the final fragment arrives and the whole is judged.
    Text { frames: Vec<WsFrame>, len: usize },
    /// Being relayed frame by frame: binary, uninspected (no inspector), or a
    /// text message `too_large` let through.
    Passthrough,
}

// ---------------------------------------------------------------------------
// Bidirectional relay with WAF inspection
// ---------------------------------------------------------------------------

/// Relay WebSocket traffic between two halves of an upgraded connection.
///
/// `client_io` is the byte stream to the browser; `upstream_io` is the byte
/// stream to the backend server. Client text messages go through `inspector`
/// before any of their bytes are forwarded; everything else, and the whole
/// server→client direction, is relayed as-is.
///
/// With no `inspector` (a site with no rule engine) text passes uninspected.
pub async fn relay<C, U>(
    client_io: C,
    upstream_io: U,
    client_ip: IpAddr,
    site_id: String,
    inspector: Option<Arc<dyn MessageInspector>>,
) where
    C: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    U: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut client_read, mut client_write) = tokio::io::split(client_io);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_io);

    // Client → Upstream (with inspection of text messages).
    let c2u_site = site_id.clone();
    let c2u = tokio::spawn(async move {
        let mut throttle = Throttle::new();
        let mut pending: Option<Pending> = None;

        // Ask the ORIGIN to close. The client write half belongs to the u→c
        // task, so the client learns of it the protocol's way: the origin answers
        // a Close with a Close, and that crosses the u→c relay.
        macro_rules! refuse {
            ($code:expr, $why:expr) => {{
                debug!(client_ip = %client_ip, site = %c2u_site, code = $code, "WS: closing: {}", $why);
                let _ = upstream_write.write_all(&close_frame($code, $why.as_bytes())).await;
                break;
            }};
        }

        loop {
            let frame = match read_frame(&mut client_read).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    debug!(client_ip = %client_ip, "WS c→u: read error: {e}");
                    break;
                }
            };

            // No extension is negotiated through the relay (the handshake's
            // offer is withdrawn), so a reserved bit means compressed or
            // otherwise-encoded data the rules cannot read.
            if frame.rsv != 0 {
                refuse!(CLOSE_PROTOCOL_ERROR, "reserved bits set");
            }

            match frame.opcode {
                // Control frames: legal between fragments, never fragmented.
                OPCODE_CLOSE | OPCODE_PING | OPCODE_PONG => {
                    if !frame.fin || frame.payload.len() > 125 {
                        refuse!(CLOSE_PROTOCOL_ERROR, "malformed control frame");
                    }
                    let is_close = frame.opcode == OPCODE_CLOSE;
                    if upstream_write.write_all(&to_origin(&frame)).await.is_err() || is_close {
                        break;
                    }
                    continue;
                }
                OPCODE_TEXT | OPCODE_BINARY => {
                    if pending.is_some() {
                        refuse!(CLOSE_PROTOCOL_ERROR, "new message inside a fragmented one");
                    }
                    pending = Some(if frame.opcode == OPCODE_TEXT && inspector.is_some() {
                        Pending::Text {
                            frames: Vec::new(),
                            len: 0,
                        }
                    } else {
                        Pending::Passthrough
                    });
                }
                OPCODE_CONTINUATION => {
                    if pending.is_none() {
                        refuse!(CLOSE_PROTOCOL_ERROR, "continuation with no message");
                    }
                }
                _ => refuse!(CLOSE_PROTOCOL_ERROR, "unknown opcode"),
            }

            let fin = frame.fin;
            match pending.as_mut().expect("set above") {
                Pending::Passthrough => {
                    if upstream_write.write_all(&to_origin(&frame)).await.is_err() {
                        break;
                    }
                }
                Pending::Text { frames, len } => {
                    *len += frame.payload.len();
                    frames.push(frame);
                    let inspector = inspector.as_ref().expect("Text implies an inspector");

                    if *len > MAX_INSPECT_MESSAGE_BYTES {
                        match inspector.too_large(*len) {
                            Verdict::Refuse(code) => refuse!(code, "message too large to inspect"),
                            Verdict::Forward => {
                                let held = std::mem::take(frames);
                                let mut ok = true;
                                for f in &held {
                                    ok &= upstream_write.write_all(&to_origin(f)).await.is_ok();
                                }
                                if !ok {
                                    break;
                                }
                                pending = Some(Pending::Passthrough);
                            }
                        }
                    } else if fin {
                        if let Some(wait) = throttle.reserve(Throttle::cost(*len)) {
                            if !throttle.throttled {
                                throttle.throttled = true;
                                warn!(
                                    client_ip = %client_ip,
                                    site = %c2u_site,
                                    rate = INSPECT_RATE_PER_SEC,
                                    "WS: client over the inspection rate — slowing it down (nothing is dropped)"
                                );
                            }
                            tokio::time::sleep(wait).await;
                        }
                        let message: Vec<u8> = if frames.len() == 1 {
                            std::mem::take(&mut frames[0].payload)
                        } else {
                            frames
                                .iter()
                                .flat_map(|f| f.payload.iter().copied())
                                .collect()
                        };
                        match inspector.inspect(&message) {
                            Verdict::Refuse(code) => refuse!(code, "WAF: attack detected"),
                            Verdict::Forward => {
                                // Forwarded as ONE frame: fragmentation is a
                                // transport detail (§5.4 lets intermediaries
                                // re-fragment), and the held payloads were moved
                                // into `message` above.
                                let whole =
                                    encode_frame(true, OPCODE_TEXT, true, fresh_mask(), &message);
                                if upstream_write.write_all(&whole).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if fin {
                pending = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Refuses nothing it inspects; `too_large` answers as configured.
    struct Fake {
        oversize: Verdict,
    }
    impl MessageInspector for Fake {
        fn inspect(&self, _: &[u8]) -> Verdict {
            Verdict::Forward
        }
        fn too_large(&self, _: usize) -> Verdict {
            self.oversize
        }
    }

    fn client_frame(first_byte: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = encode_frame(true, 0, true, [9, 8, 7, 6], payload);
        f[0] = first_byte;
        f
    }

    /// Run a relay, write `client_bytes` from the client side, and return every
    /// frame the origin receives until the relay closes.
    async fn origin_sees(client_bytes: Vec<u8>, oversize: Verdict) -> Vec<WsFrame> {
        let (client, mut client_peer) = duplex(8 << 20);
        let (origin, mut origin_peer) = duplex(8 << 20);
        let inspector: Arc<dyn MessageInspector> = Arc::new(Fake { oversize });
        let relay = tokio::spawn(relay(
            client,
            origin,
            "127.0.0.1".parse().unwrap(),
            "s".into(),
            Some(inspector),
        ));
        client_peer.write_all(&client_bytes).await.unwrap();
        let mut seen = Vec::new();
        while let Ok(Ok(Some(f))) =
            tokio::time::timeout(Duration::from_secs(2), read_frame(&mut origin_peer)).await
        {
            let close = f.opcode == OPCODE_CLOSE;
            seen.push(f);
            if close {
                break;
            }
        }
        drop(client_peer);
        drop(origin_peer);
        let _ = relay.await;
        seen
    }

    fn close_code(f: &WsFrame) -> u16 {
        u16::from_be_bytes([f.payload[0], f.payload[1]])
    }

    #[tokio::test]
    async fn a_continuation_with_no_message_is_a_protocol_error() {
        let seen = origin_sees(client_frame(0x80, b"orphan"), Verdict::Forward).await;
        assert_eq!(seen.len(), 1, "the orphan continuation was forwarded");
        assert_eq!(seen[0].opcode, OPCODE_CLOSE);
        assert_eq!(close_code(&seen[0]), CLOSE_PROTOCOL_ERROR);
    }

    /// RSV1 is permessage-deflate's "this message is compressed". Nothing is
    /// negotiated through the relay, so it can only be data the rules cannot read.
    #[tokio::test]
    async fn a_frame_with_a_reserved_bit_is_refused_not_forwarded() {
        let seen = origin_sees(
            client_frame(0x80 | 0x40 | OPCODE_TEXT, b"x"),
            Verdict::Forward,
        )
        .await;
        assert_eq!(seen.len(), 1);
        assert_eq!(close_code(&seen[0]), CLOSE_PROTOCOL_ERROR);
    }

    #[tokio::test]
    async fn a_new_message_inside_a_fragmented_one_is_a_protocol_error() {
        let mut b = client_frame(OPCODE_TEXT, b"part"); // FIN clear
        b.extend(client_frame(0x80 | OPCODE_TEXT, b"interloper"));
        let seen = origin_sees(b, Verdict::Forward).await;
        assert_eq!(seen.len(), 1, "a fragment of the unfinished message leaked");
        assert_eq!(close_code(&seen[0]), CLOSE_PROTOCOL_ERROR);
    }

    /// Learning mode's answer to an oversized message: every byte still arrives,
    /// the held fragments first and the rest streamed, never buffered unbounded.
    #[tokio::test]
    async fn an_oversized_message_let_through_arrives_whole() {
        let chunk = vec![b'a'; 512 * 1024];
        let mut b = client_frame(OPCODE_TEXT, &chunk);
        b.extend(client_frame(OPCODE_CONTINUATION, &chunk));
        b.extend(client_frame(OPCODE_CONTINUATION, &chunk));
        b.extend(client_frame(0x80 | OPCODE_CONTINUATION, &chunk));
        b.extend(client_frame(0x80 | OPCODE_CLOSE, &[0x03, 0xE8]));
        let seen = origin_sees(b, Verdict::Forward).await;
        let data: usize = seen
            .iter()
            .filter(|f| f.opcode != OPCODE_CLOSE)
            .map(|f| f.payload.len())
            .sum();
        assert_eq!(data, 4 * chunk.len());
        assert_eq!(seen[0].opcode, OPCODE_TEXT);
        assert!(seen
            .iter()
            .skip(1)
            .filter(|f| f.opcode != OPCODE_CLOSE)
            .all(|f| f.opcode == OPCODE_CONTINUATION));
    }

    #[tokio::test]
    async fn an_oversized_message_refused_sends_nothing_of_it() {
        let chunk = vec![b'a'; 700 * 1024];
        let mut b = client_frame(OPCODE_TEXT, &chunk);
        b.extend(client_frame(0x80 | OPCODE_CONTINUATION, &chunk));
        let seen = origin_sees(b, Verdict::Refuse(CLOSE_TOO_BIG)).await;
        assert_eq!(
            seen.len(),
            1,
            "part of a refused message reached the origin"
        );
        assert_eq!(close_code(&seen[0]), CLOSE_TOO_BIG);
    }

    #[test]
    fn the_throttle_allows_the_burst_then_paces_never_refuses() {
        let mut t = Throttle::new();
        for _ in 0..INSPECT_BURST as usize {
            assert!(
                t.reserve(1.0).is_none(),
                "the burst must pass without waiting"
            );
        }
        let wait = t.reserve(1.0).expect("past the burst the client waits");
        assert!(
            wait <= Duration::from_millis(50),
            "one message's wait is ~1/rate, got {wait:?}"
        );
        assert_eq!(Throttle::cost(10), 1.0);
        assert_eq!(Throttle::cost(1024 * 1024), 17.0);
    }
}
