//! HAProxy PROXY protocol (v1 text and v2 binary) on accept.
//!
//! # Why this exists
//!
//! On one host only one container can bind `:443`, so HTTPS high availability
//! means putting a load balancer in front of the fleet. HAProxy can only inject
//! `X-Forwarded-For` when it is parsing HTTP — and it must NOT parse HTTP here,
//! because TLS has to terminate at the WAF: that is where the SNI cert
//! resolver, ACME, hot-reload and the JA4 fingerprint live.
//!
//! So the LB runs `mode tcp` and passes the bytes through untouched. Without
//! this module the transport peer of every HTTPS connection is then the load
//! balancer, and four controls silently stop working at once — the IP blocklist
//! matches the LB instead of the attacker, per-source rate limits collapse onto
//! one key, correlation attributes every client's history to one address, and
//! XDP auto-ban has nothing real to ban. Each of those fails quietly, which is
//! the failure mode this codebase keeps rediscovering.
//!
//! PROXY protocol is the answer the LB already speaks: a small header before the
//! first byte of TLS, carrying the original source and destination.
//!
//! # Trust
//!
//! The header is plaintext and self-asserted, so anyone who can reach the
//! listener directly could claim any source address — bypassing a block, or
//! framing someone else for an attack. It is therefore only believed when the
//! TRANSPORT PEER is already a trusted proxy, using the same
//! `SENTINEL_TRUSTED_PROXIES` boundary that gates `X-Forwarded-For`. One list,
//! not two: a second trust boundary is a second thing to get wrong.
//!
//! A connection from an untrusted peer to a proxy-protocol listener is REJECTED
//! rather than read as raw traffic. Such a listener is not published to the host
//! in this topology, so a direct connection is either a misconfiguration or
//! someone probing — and silently treating it as ordinary traffic is how a
//! spoofable path stays open.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// `\r\n\r\n\0\r\nQUIT\n` — the 12-byte v2 signature.
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// v2 is signature + ver/cmd + fam/proto + 2-byte length.
const V2_PREFIX_LEN: usize = 16;
/// A v1 line is at most 107 bytes including CRLF (RFC-ish, per the spec).
const V1_MAX_LEN: usize = 107;

/// What a PROXY header said about the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// A proxied connection: use this as the client address.
    Proxied(SocketAddr),
    /// The `LOCAL` command, or `UNKNOWN` in v1: the LB is talking to us on its
    /// own behalf — a health check, typically. There is no client to name, so
    /// the real transport peer stands. Getting this wrong would make every
    /// health check look like traffic from 0.0.0.0.
    Local,
}

/// Total bytes the header occupies, and what it said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub consumed: usize,
    pub peer: Peer,
}

/// Parse a PROXY header from the start of `buf`.
///
/// Returns `Ok(None)` when `buf` holds a valid prefix but not yet the whole
/// header — the caller should read more. An error means the bytes are not a
/// PROXY header at all, which on a proxy-protocol listener is fatal for that
/// connection: continuing would mean serving traffic whose source we cannot
/// establish.
pub fn parse(buf: &[u8]) -> Result<Option<Parsed>> {
    if buf.len() >= 6 && &buf[..6] == b"PROXY " {
        return parse_v1(buf);
    }
    // A short buffer may still become either form.
    if buf.len() < V2_SIG.len() {
        if V2_SIG.starts_with(buf) || b"PROXY ".starts_with(buf) {
            return Ok(None);
        }
        bail!("not a PROXY protocol header");
    }
    if buf[..V2_SIG.len()] == V2_SIG {
        return parse_v2(buf);
    }
    bail!("not a PROXY protocol header")
}

fn parse_v1(buf: &[u8]) -> Result<Option<Parsed>> {
    let end = match buf.windows(2).position(|w| w == b"\r\n") {
        Some(i) => i,
        None => {
            if buf.len() > V1_MAX_LEN {
                bail!("PROXY v1 header exceeds {V1_MAX_LEN} bytes with no CRLF");
            }
            return Ok(None);
        }
    };
    let line = std::str::from_utf8(&buf[..end]).context("PROXY v1 header is not UTF-8")?;
    let consumed = end + 2;
    let mut f = line.split(' ');
    // "PROXY"
    f.next();
    match f.next() {
        Some("TCP4") | Some("TCP6") => {}
        // UNKNOWN is explicitly allowed and means "no address information".
        Some("UNKNOWN") => {
            return Ok(Some(Parsed {
                consumed,
                peer: Peer::Local,
            }))
        }
        other => bail!("unsupported PROXY v1 family {other:?}"),
    }
    let src = f.next().context("PROXY v1 missing source address")?;
    let _dst = f.next().context("PROXY v1 missing destination address")?;
    let sport = f.next().context("PROXY v1 missing source port")?;
    let ip: IpAddr = src
        .parse()
        .with_context(|| format!("PROXY v1 source address {src:?}"))?;
    let port: u16 = sport
        .parse()
        .with_context(|| format!("PROXY v1 source port {sport:?}"))?;
    Ok(Some(Parsed {
        consumed,
        peer: Peer::Proxied(SocketAddr::new(ip, port)),
    }))
}

fn parse_v2(buf: &[u8]) -> Result<Option<Parsed>> {
    if buf.len() < V2_PREFIX_LEN {
        return Ok(None);
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 0x2 {
        bail!("PROXY header claims version {}", ver_cmd >> 4);
    }
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = V2_PREFIX_LEN + addr_len;
    if buf.len() < total {
        return Ok(None);
    }
    // LOCAL (0x0) carries no usable addresses even if a block is present.
    if ver_cmd & 0x0F == 0x0 {
        return Ok(Some(Parsed {
            consumed: total,
            peer: Peer::Local,
        }));
    }
    let fam = buf[13] >> 4;
    let body = &buf[V2_PREFIX_LEN..total];
    let peer = match fam {
        // AF_INET: src(4) dst(4) sport(2) dport(2)
        0x1 => {
            if body.len() < 12 {
                bail!("PROXY v2 IPv4 block is {} bytes, want 12", body.len());
            }
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Peer::Proxied(SocketAddr::new(IpAddr::V4(ip), port))
        }
        // AF_INET6: src(16) dst(16) sport(2) dport(2)
        0x2 => {
            if body.len() < 36 {
                bail!("PROXY v2 IPv6 block is {} bytes, want 36", body.len());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Peer::Proxied(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        // AF_UNSPEC (0x0) or AF_UNIX (0x3): nothing to name.
        _ => Peer::Local,
    };
    Ok(Some(Parsed {
        consumed: total,
        peer,
    }))
}

/// Read and CONSUME a PROXY header from `stream`.
///
/// Consumes rather than peeks, deliberately: the TLS ClientHello follows
/// immediately, and `peek_ja4` and rustls both read from the front of the
/// socket. Leaving the header in place would corrupt the handshake and make the
/// JA4 fingerprint nonsense.
///
/// Reads a byte at a time up to the header boundary — a header is at most ~107
/// (v1) or 16+65535 (v2) bytes and arrives once per connection, so this is not a
/// hot path, and reading in blocks risks swallowing ClientHello bytes we must
/// leave for rustls.
pub async fn read_header(stream: &mut TcpStream, timeout: std::time::Duration) -> Result<Peer> {
    let mut buf = Vec::with_capacity(V2_PREFIX_LEN + 64);
    tokio::time::timeout(timeout, async {
        loop {
            let mut b = [0u8; 1];
            let n = stream.read(&mut b).await.context("reading PROXY header")?;
            if n == 0 {
                bail!("connection closed inside PROXY header");
            }
            buf.push(b[0]);
            match parse(&buf) {
                Ok(Some(p)) => return Ok(p.peer),
                Ok(None) => {
                    // Bound the wait so a peer that opens a connection and
                    // dribbles cannot pin a task for ever.
                    if buf.len() > V2_PREFIX_LEN + 1024 {
                        bail!("PROXY header did not terminate within 1KB");
                    }
                }
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .context("timed out reading PROXY header")?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_ipv4(src: [u8; 4], sport: u16) -> Vec<u8> {
        let mut h = V2_SIG.to_vec();
        h.push(0x21); // v2 | PROXY
        h.push(0x11); // AF_INET | STREAM
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&src);
        h.extend_from_slice(&[10, 0, 0, 1]); // dst
        h.extend_from_slice(&sport.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        h
    }

    #[test]
    fn v2_ipv4_source_is_recovered() {
        let h = v2_ipv4([203, 0, 113, 9], 51234);
        let p = parse(&h).unwrap().unwrap();
        assert_eq!(p.consumed, h.len());
        assert_eq!(
            p.peer,
            Peer::Proxied("203.0.113.9:51234".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn v2_ipv6_source_is_recovered() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21);
        h.push(0x21); // AF_INET6 | STREAM
        h.extend_from_slice(&36u16.to_be_bytes());
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&[0u8; 16]);
        h.extend_from_slice(&9999u16.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        let p = parse(&h).unwrap().unwrap();
        assert_eq!(
            p.peer,
            Peer::Proxied(SocketAddr::new(IpAddr::V6(src), 9999))
        );
    }

    /// A health check arrives as LOCAL. If that were read as an address, every
    /// health check would look like traffic from 0.0.0.0 — and on a 300ms
    /// interval that is most of the "traffic" on a quiet box.
    #[test]
    fn v2_local_command_leaves_the_real_peer_alone() {
        let mut h = V2_SIG.to_vec();
        h.push(0x20); // v2 | LOCAL
        h.push(0x00);
        h.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse(&h).unwrap().unwrap().peer, Peer::Local);
    }

    #[test]
    fn a_partial_header_asks_for_more_rather_than_failing() {
        let h = v2_ipv4([203, 0, 113, 9], 1234);
        for cut in 1..h.len() {
            assert_eq!(
                parse(&h[..cut]).unwrap(),
                None,
                "prefix of {cut} bytes should be incomplete, not an error"
            );
        }
        assert!(parse(&h).unwrap().is_some());
    }

    #[test]
    fn v1_text_form_is_supported() {
        let h = b"PROXY TCP4 198.51.100.7 10.0.0.1 4242 443\r\nsome-tls-bytes";
        let p = parse(h).unwrap().unwrap();
        assert_eq!(
            p.peer,
            Peer::Proxied("198.51.100.7:4242".parse::<SocketAddr>().unwrap())
        );
        // Must consume EXACTLY the header — one byte over and the ClientHello
        // loses its first byte, one byte under and rustls sees CRLF as TLS.
        assert_eq!(p.consumed, h.len() - b"some-tls-bytes".len());
    }

    #[test]
    fn v1_unknown_leaves_the_real_peer_alone() {
        let h = b"PROXY UNKNOWN\r\n";
        assert_eq!(parse(h).unwrap().unwrap().peer, Peer::Local);
    }

    /// Traffic that is not PROXY protocol must be a hard error on a
    /// proxy-protocol listener, not silently accepted. Accepting it would mean
    /// serving a request whose source cannot be established, on a listener whose
    /// whole purpose is establishing it.
    #[test]
    fn non_proxy_traffic_is_rejected_not_guessed() {
        // A raw TLS ClientHello.
        assert!(parse(&[
            0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x00, 0x00
        ])
        .is_err());
        // A plain HTTP request.
        assert!(parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        // Something that starts like the v2 signature and then diverges.
        let mut bad = V2_SIG.to_vec();
        bad[5] = 0xFF;
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn a_truncated_address_block_is_an_error_not_a_wrong_address() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21);
        h.push(0x11); // AF_INET, but claim a 4-byte block
        h.extend_from_slice(&4u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 9]);
        assert!(parse(&h).is_err());
    }

    #[test]
    fn a_v1_line_with_no_crlf_eventually_fails() {
        let long = format!("PROXY TCP4 {}\r", "1".repeat(V1_MAX_LEN + 10));
        assert!(parse(long.as_bytes()).is_err());
    }
}
