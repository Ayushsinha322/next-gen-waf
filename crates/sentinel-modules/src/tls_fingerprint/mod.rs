//! TLS ClientHello fingerprinting (JA4).
//!
//! Computes the [FoxIO JA4] fingerprint of a TLS `ClientHello` so the WAF can
//! identify clients by the *shape* of their TLS handshake rather than by an
//! easily-forged `User-Agent`. The resulting string is fed to
//! [`crate::bot_detect`] to match against known-malicious tool fingerprints.
//!
//! The input is the raw bytes peeked from the connection socket. It may begin
//! either at the TLS *record* layer (a 5-byte `0x16` handshake record header)
//! or directly at the *handshake* layer (`0x01` ClientHello); both are handled.
//!
//! # Safety / robustness
//!
//! Every parse step is bounds-checked (`get`/checked arithmetic, no unchecked
//! indexing or slicing). Any malformed, truncated, or over-long input yields
//! `None` — this code must never panic on hostile network data.
//!
//! # JA4 layout
//!
//! The output is `"${a}_${b}_${c}"`:
//! - `a` = `<p><ver><sni><nc><ne><al>` — protocol, TLS version, SNI flag,
//!   (GREASE-excluded) cipher count, extension count, and first/last ALPN char.
//! - `b` = first 12 hex of `sha256` over the lex-sorted, GREASE-excluded cipher
//!   suites.
//! - `c` = first 12 hex of `sha256` over the lex-sorted, GREASE-excluded
//!   extension types (minus SNI/ALPN) `_` the signature algorithms in order.
//!
//! [FoxIO JA4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

use sha2::{Digest, Sha256};

/// Parsed fields of a TLS `ClientHello` needed to compute a JA4 fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Effective TLS version: the highest non-GREASE value from the
    /// `supported_versions` extension (0x002b) if present, otherwise the
    /// legacy `client_version` field. Stored as the raw 2-byte value
    /// (e.g. `0x0304` for TLS 1.3).
    pub version: u16,
    /// Whether a `server_name` (SNI, ext 0x0000) extension is present.
    pub sni_present: bool,
    /// Cipher suites in wire order (GREASE values are retained here; they are
    /// excluded only when the fingerprint is computed).
    pub ciphers: Vec<u16>,
    /// Extension types in wire order (GREASE retained, see above).
    pub extensions: Vec<u16>,
    /// ALPN protocol identifiers (ext 0x0010) in wire order.
    pub alpn: Vec<String>,
    /// Signature algorithms (ext 0x000d) in wire order.
    pub sig_algs: Vec<u16>,
}

/// Peek-friendly entry point: parse `raw` and return its JA4 fingerprint.
///
/// `raw` may start at the TLS record layer or the handshake layer. `is_quic`
/// selects the `q` (QUIC) vs `t` (TCP) protocol prefix. Returns `None` on any
/// malformed or truncated input.
pub fn ja4_from_client_hello(raw: &[u8], is_quic: bool) -> Option<String> {
    let info = parse_client_hello(raw)?;
    Some(ja4(&info, is_quic))
}

/// Parse a TLS `ClientHello` into the fields needed for JA4.
///
/// Strips a leading TLS record header if present. Returns `None` on any
/// malformed or truncated input; never panics.
pub fn parse_client_hello(raw: &[u8]) -> Option<ClientHelloInfo> {
    let handshake = strip_record_header(raw);
    let mut r = Reader::new(handshake);

    // Handshake header: type (1) must be ClientHello, then a 24-bit length.
    if r.u8()? != 0x01 {
        return None;
    }
    let body_len = r.u24()? as usize;
    let body = r.bytes(body_len)?;

    let mut b = Reader::new(body);
    let legacy_version = b.u16()?; // client_version
    b.skip(32)?; // random
    let session_id_len = b.u8()? as usize;
    b.skip(session_id_len)?;

    // Cipher suites (2 bytes each).
    let cs_len = b.u16()? as usize;
    if cs_len % 2 != 0 {
        return None;
    }
    let cs_bytes = b.bytes(cs_len)?;
    let ciphers: Vec<u16> = cs_bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();

    // Compression methods.
    let comp_len = b.u8()? as usize;
    b.skip(comp_len)?;

    // Extensions (the block is optional — absent means zero remaining bytes).
    let mut extensions = Vec::new();
    let mut alpn = Vec::new();
    let mut sig_algs = Vec::new();
    let mut sni_present = false;
    let mut supported_versions_max: Option<u16> = None;

    if b.remaining() > 0 {
        let ext_total = b.u16()? as usize;
        let ext_bytes = b.bytes(ext_total)?;
        let mut e = Reader::new(ext_bytes);
        while e.remaining() > 0 {
            let ext_type = e.u16()?;
            let ext_len = e.u16()? as usize;
            let ext_data = e.bytes(ext_len)?;
            extensions.push(ext_type);
            match ext_type {
                0x0000 => sni_present = true,
                0x0010 => alpn = parse_alpn(ext_data),
                0x000d => sig_algs = parse_sig_algs(ext_data),
                0x002b => {
                    if let Some(v) = parse_supported_versions(ext_data) {
                        supported_versions_max = Some(v);
                    }
                }
                _ => {}
            }
        }
    }

    Some(ClientHelloInfo {
        version: supported_versions_max.unwrap_or(legacy_version),
        sni_present,
        ciphers,
        extensions,
        alpn,
        sig_algs,
    })
}

/// Build the JA4 string from parsed [`ClientHelloInfo`].
pub fn ja4(info: &ClientHelloInfo, is_quic: bool) -> String {
    let p = if is_quic { 'q' } else { 't' };
    let ver = version_code(info.version);
    let sni = if info.sni_present { 'd' } else { 'i' };

    let ciphers: Vec<u16> = info
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let nc = two_digit(ciphers.len());

    let exts: Vec<u16> = info
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let ne = two_digit(exts.len());

    let al = alpn_code(&info.alpn);

    let a = format!("{p}{ver}{sni}{nc}{ne}{al}");

    // Section b: lex-sorted GREASE-excluded cipher suites.
    let b = if ciphers.is_empty() {
        ZERO12.to_string()
    } else {
        let mut hexes: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
        hexes.sort();
        hash12(&hexes.join(","))
    };

    // Section c: lex-sorted extension types (minus SNI 0x0000 and ALPN 0x0010),
    // then "_", then signature algorithms in ORIGINAL order.
    let mut ext_hexes: Vec<String> = exts
        .iter()
        .filter(|&&e| e != 0x0000 && e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    ext_hexes.sort();
    let sig_hexes: Vec<String> = info.sig_algs.iter().map(|s| format!("{s:04x}")).collect();
    let c = if ext_hexes.is_empty() && sig_hexes.is_empty() {
        ZERO12.to_string()
    } else {
        hash12(&format!("{}_{}", ext_hexes.join(","), sig_hexes.join(",")))
    };

    format!("{a}_{b}_{c}")
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// The 12-zero placeholder used when a JA4 hash section has no input.
const ZERO12: &str = "000000000000";

/// A GREASE value per RFC 8701: `(v & 0x0f0f) == 0x0a0a`
/// (0x0a0a, 0x1a1a, ..., 0xfafa).
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

/// Strip a 5-byte TLS record header (`0x16` handshake) if it precedes the
/// ClientHello handshake byte (`0x01`); otherwise return the input unchanged.
/// How many bytes a buffered TLS handshake record needs in total, so a caller
/// peeking a socket can tell "not arrived yet" from "not a ClientHello".
///
/// Returns:
///   - `Ok(need)` — this looks like a TLS handshake record and `need` bytes are
///     required in total (record header + body). Keep reading until the buffer
///     holds that many.
///   - `Err(NotHandshake)` — the first bytes are definitively not a TLS
///     handshake record, so waiting for more will never help.
///
/// This exists because [`parse_client_hello`] cannot distinguish those two: it
/// returns `None` for both, and a caller peeking a live socket then has no way to
/// know whether to retry. A single `peek` returns as soon as ANY bytes are
/// readable, so on a ClientHello split across TCP segments — the normal case for
/// modern post-quantum hellos, which run past 1500 bytes — it sees a truncated
/// record and the fingerprint is silently lost. Measured on a live fleet:
/// 508 fingerprints from 977 handshakes, a ~50/50 split that is the signature of
/// a segment-boundary race rather than any property of the clients.
pub fn client_hello_needed_len(raw: &[u8]) -> Result<usize, NotHandshake> {
    // Need the 5-byte record header to say anything at all.
    if raw.len() < 5 {
        // A handshake record starts with 0x16; if we already have that byte and
        // it is wrong, do not wait.
        return match raw.first() {
            Some(&0x16) | None => Ok(5),
            Some(_) => Err(NotHandshake),
        };
    }
    if raw[0] != 0x16 {
        return Err(NotHandshake);
    }
    let record_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    // A ClientHello record of zero length, or one larger than the TLS maximum,
    // is not something to keep waiting for.
    if record_len == 0 || record_len > 16_384 {
        return Err(NotHandshake);
    }
    Ok(5 + record_len)
}

/// The first bytes on the connection are not a TLS handshake record — a plain
/// TCP probe, a port scan, an abandoned connection, or a different protocol.
/// Distinct from "incomplete" so a caller does not wait on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotHandshake;

fn strip_record_header(raw: &[u8]) -> &[u8] {
    if raw.first() == Some(&0x16) && raw.get(5) == Some(&0x01) {
        // content_type(1) + legacy_version(2) + length(2) = 5 bytes.
        raw.get(5..).unwrap_or(raw)
    } else {
        raw
    }
}

/// Map a raw TLS version value to its 2-char JA4 code.
fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

/// Zero-padded 2-digit count, capped at "99".
fn two_digit(n: usize) -> String {
    if n > 99 {
        "99".to_string()
    } else {
        format!("{n:02}")
    }
}

/// First + last byte of the first ALPN protocol as chars; "00" if no ALPN.
fn alpn_code(alpn: &[String]) -> String {
    let Some(first) = alpn.first() else {
        return "00".to_string();
    };
    let bytes = first.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(&f), Some(&l)) => format!("{}{}", f as char, l as char),
        _ => "00".to_string(),
    }
}

/// First 12 hex chars of `sha256(input)`.
fn hash12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize()).chars().take(12).collect()
}

/// ALPN extension body: 2-byte list length, then `len(1) + bytes` entries.
/// Best-effort — returns whatever entries parse cleanly.
fn parse_alpn(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    if r.u16().is_none() {
        return out; // list length
    }
    while r.remaining() > 0 {
        let Some(len) = r.u8() else { break };
        let Some(bytes) = r.bytes(len as usize) else {
            break;
        };
        out.push(String::from_utf8_lossy(bytes).into_owned());
    }
    out
}

/// signature_algorithms extension body: 2-byte list length, then 2-byte algs.
/// Best-effort; preserves wire order.
fn parse_sig_algs(data: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    if r.u16().is_none() {
        return out; // list length
    }
    while r.remaining() >= 2 {
        match r.u16() {
            Some(v) => out.push(v),
            None => break,
        }
    }
    out
}

/// supported_versions (ClientHello) body: 1-byte list length, then 2-byte
/// versions. Returns the highest non-GREASE version, if any.
fn parse_supported_versions(data: &[u8]) -> Option<u16> {
    let mut r = Reader::new(data);
    r.u8()?; // list length (in bytes)
    let mut best: Option<u16> = None;
    while r.remaining() >= 2 {
        let Some(v) = r.u16() else { break };
        if is_grease(v) {
            continue;
        }
        best = Some(match best {
            Some(b) => b.max(v),
            None => v,
        });
    }
    best
}

/// A bounds-checked big-endian byte cursor. Every read returns `None` rather
/// than panicking when the buffer is exhausted.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }

    fn u24(&mut self) -> Option<u32> {
        let a = self.u8()? as u32;
        let b = self.u8()? as u32;
        let c = self.u8()? as u32;
        Some((a << 16) | (b << 8) | c)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `(type, data)` into a wire extension: type(2) + len(2) + data.
    fn ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&ext_type.to_be_bytes());
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    /// A minimal but valid ClientHello (handshake layer) with:
    /// - ciphers: GREASE(0x0a0a) + 0x1301 + 0xc02b
    /// - supported_versions advertising GREASE(0x0a0a) + TLS 1.3 (0x0304)
    /// - SNI "example.com", ALPN "h2", sig_algs 0x0403 + 0x0804
    fn sample_client_hello() -> Vec<u8> {
        // SNI (0x0000)
        let host = b"example.com";
        let mut sni_entry = vec![0x00]; // name_type: host_name
        sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_entry.extend_from_slice(host);
        let mut sni_data = (sni_entry.len() as u16).to_be_bytes().to_vec();
        sni_data.extend_from_slice(&sni_entry);
        let sni = ext(0x0000, &sni_data);

        // supported_versions (0x002b): GREASE + TLS 1.3
        let sv_list = [0x0a_u8, 0x0a, 0x03, 0x04];
        let mut sv_data = vec![sv_list.len() as u8];
        sv_data.extend_from_slice(&sv_list);
        let sv = ext(0x002b, &sv_data);

        // ALPN (0x0010): "h2"
        let proto = b"h2";
        let mut alpn_entries = vec![proto.len() as u8];
        alpn_entries.extend_from_slice(proto);
        let mut alpn_data = (alpn_entries.len() as u16).to_be_bytes().to_vec();
        alpn_data.extend_from_slice(&alpn_entries);
        let alpn = ext(0x0010, &alpn_data);

        // signature_algorithms (0x000d): 0x0403, 0x0804
        let sig_list = [0x04_u8, 0x03, 0x08, 0x04];
        let mut sig_data = (sig_list.len() as u16).to_be_bytes().to_vec();
        sig_data.extend_from_slice(&sig_list);
        let sig = ext(0x000d, &sig_data);

        let mut exts = Vec::new();
        exts.extend_from_slice(&sni);
        exts.extend_from_slice(&sv);
        exts.extend_from_slice(&alpn);
        exts.extend_from_slice(&sig);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length
        let ciphers = [0x0a_u8, 0x0a, 0x13, 0x01, 0xc0, 0x2b];
        body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
        body.extend_from_slice(&ciphers);
        body.push(0x01); // compression methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01]; // ClientHello
        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn parses_and_builds_ja4() {
        let hs = sample_client_hello();
        let info = parse_client_hello(&hs).expect("valid ClientHello should parse");

        // GREASE is retained in the raw list but excluded from the fingerprint.
        assert_eq!(info.ciphers, vec![0x0a0a, 0x1301, 0xc02b]);
        let non_grease: Vec<u16> = info
            .ciphers
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();
        assert_eq!(non_grease, vec![0x1301, 0xc02b]);

        assert!(info.sni_present);
        assert_eq!(info.alpn, vec!["h2".to_string()]);
        assert_eq!(info.sig_algs, vec![0x0403, 0x0804]);
        // Version comes from supported_versions, GREASE ignored -> TLS 1.3.
        assert_eq!(info.version, 0x0304);

        let s = ja4(&info, false);

        // a = t(TCP) 13(TLS1.3) d(SNI) 02(2 ciphers) 04(4 exts incl SNI+ALPN) h2
        assert!(s.starts_with("t13d"), "got {s}");
        let parts: Vec<&str> = s.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "JA4 must have three '_'-separated parts: {s}"
        );
        assert_eq!(parts[0], "t13d0204h2");
        assert_eq!(&parts[0][3..4], "d"); // SNI present flag
        assert_eq!(&parts[0][8..10], "h2"); // first/last ALPN char

        // b and c are each 12 hex chars.
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));

        // The convenience wrapper matches, at both handshake and record layer.
        assert_eq!(ja4_from_client_hello(&hs, false), Some(s.clone()));
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(ja4_from_client_hello(&rec, false), Some(s));
    }

    #[test]
    fn malformed_inputs_return_none() {
        // Empty.
        assert_eq!(parse_client_hello(&[]), None);
        assert_eq!(ja4_from_client_hello(&[], false), None);

        // Too short (partial handshake header).
        assert_eq!(parse_client_hello(&[0x01, 0x00, 0x00]), None);

        // Wrong handshake type (not ClientHello).
        assert_eq!(parse_client_hello(&[0x02, 0x00, 0x00, 0x00]), None);

        // Declared handshake length exceeds the buffer.
        assert_eq!(parse_client_hello(&[0x01, 0x00, 0xff, 0xff, 0x00]), None);

        // Well-framed handshake, but extensions_length overruns the buffer.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // session id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // ciphers: len 2 + one suite
        body.extend_from_slice(&[0x01, 0x00]); // compression: len 1 + null
        body.extend_from_slice(&[0x00, 0xff]); // extensions_length = 255 (a lie)
        body.extend_from_slice(&[0x00, 0x0d, 0x00, 0x00]); // only 4 bytes follow
        let mut hs = vec![0x01];
        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);
        assert_eq!(parse_client_hello(&hs), None);

        // Truncating a valid hello anywhere must never panic.
        let full = sample_client_hello();
        for cut in 0..full.len() {
            let _ = parse_client_hello(&full[..cut]);
        }
    }

    #[test]
    fn quic_prefix() {
        let hs = sample_client_hello();
        let s = ja4_from_client_hello(&hs, true).expect("valid ClientHello");
        assert!(
            s.starts_with('q'),
            "QUIC fingerprint must start with 'q': {s}"
        );
        assert!(s.starts_with("q13d"), "got {s}");
    }
}

/// The segment-boundary race that silently halved JA4 coverage.
///
/// `TcpStream::peek` returns as soon as ANY bytes are readable, and
/// `parse_client_hello` returns `None` for a truncated record exactly as it does
/// for a malformed one — so the proxy could not tell "wait for more" from "give
/// up", and gave up. `client_hello_needed_len` is the missing distinction.
#[cfg(test)]
mod completeness_tests {
    use super::*;

    /// A realistic ClientHello: one record, body longer than a single small
    /// segment, so the split case below is not contrived.
    fn client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0xAB; 32]); // random
        body.push(0); // session_id_len
        body.extend_from_slice(&[0x00, 0x04]); // cipher suites, 2 entries
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        body.push(1); // compression methods
        body.push(0);
        // One large extension (a stand-in for a post-quantum key share), so the
        // hello spans well past a small segment.
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x2b]); // supported_versions
        exts.extend_from_slice(&[0x00, 0x03]);
        exts.extend_from_slice(&[0x02, 0x03, 0x04]);
        exts.extend_from_slice(&[0x00, 0x33]); // key_share
        let big = vec![0x42u8; 1200];
        exts.extend_from_slice(&(big.len() as u16).to_be_bytes());
        exts.extend_from_slice(&big);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01]; // ClientHello
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn a_complete_hello_reports_its_own_length_and_fingerprints() {
        let hello = client_hello();
        assert!(hello.len() > 1200, "fixture must exceed one small segment");
        assert_eq!(client_hello_needed_len(&hello), Ok(hello.len()));
        assert!(
            ja4_from_client_hello(&hello, false).is_some(),
            "the fixture must be a parseable ClientHello, or the split test below \
             proves nothing"
        );
    }

    /// THE BUG: a first peek that catches only the first segment.
    #[test]
    fn a_split_hello_is_reported_incomplete_rather_than_unparseable() {
        let hello = client_hello();
        for cut in [1, 4, 5, 6, 64, 300, 1000, hello.len() - 1] {
            let partial = &hello[..cut];
            // The old code's only signal: indistinguishable from garbage.
            assert!(
                ja4_from_client_hello(partial, false).is_none(),
                "a truncated hello cannot be fingerprinted (cut={cut})"
            );
            // The new signal: keep waiting, and here is how much is needed.
            match client_hello_needed_len(partial) {
                Ok(need) => assert!(
                    need > cut,
                    "cut={cut}: needed_len must exceed what has arrived, got {need}"
                ),
                Err(_) => panic!(
                    "cut={cut}: a partial TLS handshake record must be reported as \
                     INCOMPLETE, not as 'not a handshake' — that is the whole \
                     distinction, and getting it wrong drops the fingerprint"
                ),
            }
        }
    }

    /// The other direction: a connection that is not TLS at all must be rejected
    /// immediately, not waited on. Otherwise every port scan holds a task for the
    /// peek budget.
    #[test]
    fn non_tls_traffic_is_rejected_without_waiting() {
        for (label, bytes) in [
            ("http", &b"GET / HTTP/1.1\r\n"[..]),
            ("ssh", &b"SSH-2.0-OpenSSH_9.6"[..]),
            ("single wrong byte", &b"\x47"[..]),
            // A handshake byte but an impossible record length.
            ("zero-length record", &b"\x16\x03\x01\x00\x00"[..]),
            ("oversized record", &b"\x16\x03\x01\xff\xff"[..]),
        ] {
            assert_eq!(
                client_hello_needed_len(bytes),
                Err(NotHandshake),
                "{label} must be rejected immediately"
            );
        }
    }

    /// An empty buffer, or a lone 0x16, is "keep reading" — we cannot yet tell.
    #[test]
    fn too_few_bytes_to_judge_means_keep_reading() {
        assert_eq!(client_hello_needed_len(&[]), Ok(5));
        assert_eq!(client_hello_needed_len(&[0x16]), Ok(5));
        assert_eq!(client_hello_needed_len(&[0x16, 0x03]), Ok(5));
    }
}
