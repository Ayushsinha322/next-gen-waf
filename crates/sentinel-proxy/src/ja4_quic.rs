//! JA4 fingerprinting for HTTP/3 (QUIC) clients.
//!
//! # Why this is not the same problem as the TCP path
//!
//! On TCP the ClientHello arrives in cleartext and the proxy peeks the socket
//! (`peek_ja4`). Over QUIC the ClientHello lives inside CRYPTO frames in an
//! Initial packet, encrypted under keys derived from the connection ID
//! (RFC 9001 §5.2) — there is nothing to peek. `http3.rs` therefore passed a
//! literal `None` into the pipeline, so every JA4-dependent control was blind to
//! h3: bot scoring's malicious-JA4 signal and the JA4 blocklist. Since the
//! listener advertises h3 via Alt-Svc, a client whose fingerprint is blocklisted
//! could evade it by simply preferring h3.
//!
//! # Two approaches rejected, and why
//!
//! **Compute JA4 from rustls's `ClientHello` callback.** `SentinelCertResolver`
//! already receives one during the QUIC handshake, so this looks free. It is
//! not: rustls 0.23 exposes `cipher_suites`, `signature_schemes`, `alpn`,
//! `server_name` and `named_groups`, but NOT the extension type list and NOT the
//! offered version list. JA4's `c` section is a hash over sorted extension types
//! and its `a` section carries the extension count, so a fingerprint built from
//! that callback would be WRONG while looking right — silently failing to match
//! a real JA4 blocklist. A wrong fingerprint under a trusted name is worse than
//! an honest gap.
//!
//! **Tap the UDP socket and decrypt the Initial packet ourselves.** Correct in
//! principle, and how passive tools do it, but it means reimplementing RFC 9001
//! §5.2/§5.4 (initial secrets, header protection, AES-GCM) plus CRYPTO-frame
//! reassembly — and then *agreeing byte-for-byte with rustls*. Where a
//! second parser disagrees with the real endpoint, that difference is a WAF
//! evasion primitive, not merely a bug. RFC 9000 §19.6 permits overlapping
//! retransmitted CRYPTO ranges and quinn does not enforce the "differing bytes"
//! prohibition; quinn resolves overlaps first-delivered-byte-wins
//! (`Assembler::insert` trims below `bytes_read`), while a naive
//! `BTreeMap<offset, Bytes>` is last-write-wins. An attacker who can make the
//! two disagree fingerprints as benign while the server negotiates normally.
//! Reassembly state would also be allocated before quinn's address validation,
//! upstream of our own admission control — a new pre-handshake DoS surface.
//!
//! # What this does instead
//!
//! Decorates quinn's **public** `crypto::ServerConfig` / `crypto::Session`
//! traits — the seam quinn exposes for alternative TLS backends. The decorator
//! is handed the *same `&[u8]` rustls is handed*, by the only caller
//! (`quinn_proto::connection::Connection::read_crypto`):
//!
//! ```text
//! while let Some(chunk) = space.crypto_stream.read(usize::MAX, true) {
//!     if self.crypto.read_handshake(&chunk.bytes)? { ... }
//! }
//! ```
//!
//! That `true` is `ordered` (`Assembler::read(max_length, ordered)`), so chunks
//! arrive in strictly increasing stream order with no gaps: a plain
//! `extend_from_slice` is not an approximation, it *is* the reassembler. Every
//! hazard above — coalesced packets, both initial salts, overlapping offsets,
//! Retry, retransmits, duplicates, GRO batching, the crypto-buffer bound — is
//! handled by code we do not write and therefore cannot diverge from.
//!
//! **There is no second parse, so there is nothing to disagree.** That is a
//! structural guarantee rather than a probabilistic one, and it is the whole
//! reason this approach was chosen over the socket tap.
//!
//! # Keying
//!
//! None. The accumulator lives inside the connection's own TLS session, so there
//! is no CID- or address-keyed side table to get wrong. `orig_dst_cid` would
//! have been the obvious key and is a trap: it reports the pre-Retry DCID while
//! the post-Retry Initial carries a different one. Connection migration is
//! likewise a non-issue — a client changing its 4-tuple mid-connection cannot
//! lose or swap its fingerprint, whereas an address-keyed table could blend two
//! clients. `start_session` runs once per accepted connection, after token
//! validation, so our state is also downstream of quinn's own DoS protection.

use std::any::Any;
use std::sync::{Arc, Mutex};

use quinn::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session, UnsupportedVersion,
};
use quinn::{ConnectionId, Side};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::TransportError;
use tracing::error;

/// Mirrors quinn's own `crypto_buffer_size` default (16 KiB, quinn-proto
/// `config/transport.rs`). quinn returns `CRYPTO_BUFFER_EXCEEDED` and kills the
/// connection past this, so we can never legitimately need more.
const MAX_HANDSHAKE_ACCUM: usize = 16 * 1024;

/// Why a connection has no h3 fingerprint. Every variant is counted, because
/// "no fingerprint" with no reason is how a dead control stays invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H3Ja4Outcome {
    /// A fingerprint was produced.
    Ok,
    /// The ClientHello, or the accumulator, exceeded quinn's crypto buffer.
    /// quinn is about to tear the connection down anyway.
    RefusedOversize,
    /// The first handshake byte was not `0x01`, or a length-complete
    /// ClientHello did not parse. Never emit a partial fingerprint.
    RefusedUnparseable,
    /// The handshake completed but we hold no result — including the case where
    /// the decorator is not installed at all. See [`fingerprint_for`].
    Absent,
}

impl H3Ja4Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::RefusedOversize => "refused_oversize",
            Self::RefusedUnparseable => "refused_unparseable",
            Self::Absent => "absent",
        }
    }
}

/// Wraps the real QUIC TLS config so every session it starts is decorated.
pub(crate) struct Ja4ServerConfig {
    inner: Arc<dyn quinn::crypto::ServerConfig>,
}

impl Ja4ServerConfig {
    pub(crate) fn new(inner: Arc<dyn quinn::crypto::ServerConfig>) -> Self {
        Self { inner }
    }
}

impl quinn::crypto::ServerConfig for Ja4ServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        self.inner.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(Ja4Session {
            inner: Arc::clone(&self.inner).start_session(version, params),
            accum: Vec::new(),
            result: Arc::new(Mutex::new((None, H3Ja4Outcome::Absent))),
            done: false,
        })
    }
}

struct Ja4Session {
    inner: Box<dyn Session>,
    /// Bytes of the client's first handshake flight, in stream order.
    accum: Vec<u8>,
    /// Published through `handshake_data`, which is the only per-connection
    /// channel quinn exposes to the accepting task.
    result: Arc<Mutex<(Option<String>, H3Ja4Outcome)>>,
    /// Latched once the first ClientHello is resolved, so a second one (a
    /// HelloRetryRequest flight) or any later handshake message cannot overwrite
    /// it. CH1 is what passive tooling fingerprints, so CH1 is what a blocklist
    /// entry was generated from.
    done: bool,
}

/// What `quinn::Connection::handshake_data()` returns once the decorator is
/// installed.
///
/// The real rustls `HandshakeData` is kept NESTED rather than replaced. Nothing
/// in this workspace, in `h3`, in `h3-quinn`, or in quinn itself downcasts it
/// today — `Connecting::handshake_data` is a user-facing accessor and ALPN is
/// negotiated inside rustls — but discarding another crate's data because we
/// happen not to need it is how the next person's feature breaks mysteriously.
pub(crate) struct Ja4HandshakeData {
    /// rustls's own `HandshakeData`, kept so replacing the return type of
    /// `handshake_data()` does not destroy information this crate happens not to
    /// consume. Reachable via [`Ja4HandshakeData::into_inner`].
    inner: Box<dyn Any>,
    pub(crate) ja4: Option<String>,
    pub(crate) outcome: H3Ja4Outcome,
}

impl Ja4HandshakeData {
    /// Recover the TLS backend's original handshake data.
    ///
    /// `allow(dead_code)` is deliberate and narrow: nothing calls this in a
    /// non-test build, and the alternative — dropping `inner` — would mean
    /// `handshake_data()` silently discards rustls's data because we happen not
    /// to need it. If a future `h3-quinn` starts reading it, that would break in
    /// a way nobody would look for here.
    #[allow(dead_code)]
    ///
    /// Unused today — nothing in this workspace, in `h3`, in `h3-quinn`, or in
    /// quinn downcasts it, and ALPN is negotiated inside rustls rather than read
    /// from here. It exists because the decorator REPLACES the type
    /// `quinn::Connection::handshake_data()` returns, and a future need for
    /// rustls's version (server_name, negotiated protocol) must not require
    /// unpicking this wrapper first. Verified reachable by the test below.
    pub(crate) fn into_inner(self) -> Box<dyn Any> {
        self.inner
    }
}

/// Total bytes a QUIC handshake message needs: 1 type byte + a 24-bit length.
///
/// Deliberately NOT `client_hello_needed_len` from the TCP path, which requires
/// a `0x16` TLS record header. QUIC has no record layer (RFC 9001 §4), so that
/// function can never match here and reusing it would silently refuse every h3
/// connection.
///
/// `None` means "not a ClientHello, stop"; `Some(n)` means "n bytes are needed
/// in total" — which for a short buffer is just the header length, i.e. keep
/// reading.
fn quic_handshake_needed_len(accum: &[u8]) -> Option<usize> {
    match accum.first() {
        // Nothing yet: we need at least the 4-byte header to say anything.
        None => Some(4),
        Some(&0x01) => {
            if accum.len() < 4 {
                Some(4)
            } else {
                Some(4 + u32::from_be_bytes([0, accum[1], accum[2], accum[3]]) as usize)
            }
        }
        // A first flight that does not begin with ClientHello. Do not scan
        // forward hunting for one.
        Some(_) => None,
    }
}

impl Ja4Session {
    fn accumulate(&mut self, buf: &[u8]) {
        if self.done {
            return;
        }
        if self.accum.len().saturating_add(buf.len()) > MAX_HANDSHAKE_ACCUM {
            self.finish(None, H3Ja4Outcome::RefusedOversize);
            return;
        }
        self.accum.extend_from_slice(buf);

        let need = match quic_handshake_needed_len(&self.accum) {
            Some(n) => n,
            None => {
                self.finish(None, H3Ja4Outcome::RefusedUnparseable);
                return;
            }
        };
        if need > MAX_HANDSHAKE_ACCUM {
            self.finish(None, H3Ja4Outcome::RefusedOversize);
            return;
        }
        if self.accum.len() < need {
            // Incomplete, and this is the NORMAL case in production rather than
            // an edge: a 1200-byte Initial budgets roughly 1154 bytes of hello,
            // while an X25519MLKEM768 key share alone is 1216 bytes. Getting
            // this wrong would be the deterministic version of the TCP peek race
            // — it would lose most modern browsers, not half of them.
            return;
        }

        // Slice to exactly `need`: a chunk carrying trailing bytes must never be
        // allowed to inflate the extension list.
        match sentinel_modules::ja4_from_client_hello(&self.accum[..need], true) {
            Some(fp) => self.finish(Some(fp), H3Ja4Outcome::Ok),
            None => self.finish(None, H3Ja4Outcome::RefusedUnparseable),
        }
    }

    fn finish(&mut self, fp: Option<String>, outcome: H3Ja4Outcome) {
        self.done = true;
        // Release the buffer: one connection's worth is small, but this runs per
        // connection and there is no reason to hold it for the session's life.
        self.accum = Vec::new();
        if let Ok(mut g) = self.result.lock() {
            *g = (fp, outcome);
        }
    }
}

impl Session for Ja4Session {
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // Delegate FIRST and propagate the error before accumulating, so we can
        // never fingerprint a handshake the real TLS stack rejected.
        let ready = self.inner.read_handshake(buf)?;
        self.accumulate(buf);
        Ok(ready)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let inner = self.inner.handshake_data()?;
        let (ja4, outcome) = match self.result.lock() {
            Ok(g) => (g.0.clone(), g.1),
            // A poisoned lock must yield "absent", never a stale or partial
            // value.
            Err(_) => (None, H3Ja4Outcome::Absent),
        };
        Some(Box::new(Ja4HandshakeData {
            inner,
            ja4,
            outcome,
        }))
    }

    // ---- everything below is pure delegation ----

    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

/// Read the fingerprint an accepted QUIC connection produced.
///
/// Call after `accept().await` and before the connection is moved into
/// `h3_quinn::Connection::new`.
///
/// ⚠️ A failed downcast is the silently-inert detector for this whole feature: it
/// means the decorator is not in the config chain, because someone reverted the
/// wrapper in `quic_server_config` or added a second construction site that
/// skipped it. That is the exact "adding a feature is TWO changes" shape this
/// codebase keeps paying for, so it logs at ERROR naming the consequence rather
/// than returning a quiet `None`.
pub(crate) fn fingerprint_for(conn: &quinn::Connection) -> (Option<String>, H3Ja4Outcome) {
    match conn.handshake_data() {
        Some(any) => match any.downcast::<Ja4HandshakeData>() {
            Ok(d) => (d.ja4, d.outcome),
            Err(_) => {
                error!(
                    "h3 JA4 decorator is NOT installed — every HTTP/3 client is unfingerprinted, \
                     so bot scoring's malicious-JA4 signal and the JA4 blocklist are inert for \
                     h3 while remaining active for TCP. quic_server_config must wrap the TLS \
                     config in Ja4ServerConfig. Queryable at /healthz -> modules.ja4.h3."
                );
                (None, H3Ja4Outcome::Absent)
            }
        },
        // Should be unreachable once the handshake has completed; counted rather
        // than assumed away.
        None => (None, H3Ja4Outcome::Absent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a QUIC-shaped handshake ClientHello: NO TLS record header, because
    /// QUIC has no record layer. Large enough that the split case below is
    /// realistic rather than contrived.
    fn quic_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x5A; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x04]);
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        body.push(1);
        body.push(0);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x2b]); // supported_versions
        exts.extend_from_slice(&[0x00, 0x03]);
        exts.extend_from_slice(&[0x02, 0x03, 0x04]);
        exts.extend_from_slice(&[0x00, 0x10]); // ALPN
        let alpn = [0x00u8, 0x03, 0x02, b'h', b'3'];
        exts.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn);
        exts.extend_from_slice(&[0x00, 0x33]); // key_share, PQ-sized
        let big = vec![0x42u8; 1216];
        exts.extend_from_slice(&(big.len() as u16).to_be_bytes());
        exts.extend_from_slice(&big);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn a_quic_hello_fingerprints_with_the_q_prefix() {
        let hello = quic_client_hello();
        let fp = sentinel_modules::ja4_from_client_hello(&hello, true)
            .expect("the fixture must be a parseable ClientHello");
        assert!(
            fp.starts_with('q'),
            "JA4 over QUIC must carry the q prefix, not t: {fp}"
        );
        // And the TCP variant of the same bytes must differ only in that prefix,
        // which is what makes a shared blocklist entry meaningful.
        let tcp = sentinel_modules::ja4_from_client_hello(&hello, false).unwrap();
        assert_eq!(fp[1..], tcp[1..], "only the protocol prefix may differ");
    }

    /// The production case: a hello larger than one Initial packet arrives in
    /// several ordered chunks. Anything that fingerprints early gets it wrong.
    #[test]
    fn a_hello_split_across_chunks_needs_every_chunk_before_it_resolves() {
        let hello = quic_client_hello();
        assert!(
            hello.len() > 1200,
            "fixture must exceed one Initial's hello budget"
        );
        for cut in [1, 3, 4, 5, 600, 1154, hello.len() - 1] {
            let need = quic_handshake_needed_len(&hello[..cut])
                .unwrap_or_else(|| panic!("cut={cut} must be reported incomplete, not rejected"));
            assert!(
                need > cut,
                "cut={cut}: needed_len {need} must exceed what has arrived"
            );
        }
        // Complete: the length is exactly the fixture's.
        assert_eq!(quic_handshake_needed_len(&hello), Some(hello.len()));
    }

    /// A first flight that is not a ClientHello must be refused outright, not
    /// searched for one.
    #[test]
    fn a_non_client_hello_first_flight_is_refused() {
        for (label, first) in [
            ("ServerHello", 0x02u8),
            ("Certificate", 0x0b),
            ("Finished", 0x14),
            ("a TLS record header, which QUIC never carries", 0x16),
        ] {
            assert_eq!(
                quic_handshake_needed_len(&[first, 0, 0, 8]),
                None,
                "{label} must be refused"
            );
        }
    }

    /// The wrapper must PRESERVE the TLS backend's handshake data, not replace
    /// it. Uses a stand-in payload because a real `rustls::HandshakeData` cannot
    /// be constructed without a live handshake — what is under test is that the
    /// nesting round-trips, which is the property that matters.
    #[test]
    fn the_wrapper_preserves_the_inner_handshake_data() {
        let d = Ja4HandshakeData {
            inner: Box::new("inner-payload".to_string()),
            ja4: Some("q13d0310h3_aabbccddeeff_112233445566".to_string()),
            outcome: H3Ja4Outcome::Ok,
        };
        assert_eq!(d.outcome, H3Ja4Outcome::Ok);
        let recovered = d
            .into_inner()
            .downcast::<String>()
            .expect("the nested payload must survive the wrapper");
        assert_eq!(
            *recovered, "inner-payload",
            "replacing the handshake_data type must not destroy the backend's own data"
        );
    }

    /// Every non-Ok outcome must have a distinct, greppable name — "no
    /// fingerprint" with no reason is how a dead control stays invisible.
    #[test]
    fn every_outcome_has_a_distinct_name() {
        let all = [
            H3Ja4Outcome::Ok,
            H3Ja4Outcome::RefusedOversize,
            H3Ja4Outcome::RefusedUnparseable,
            H3Ja4Outcome::Absent,
        ];
        let names: Vec<&str> = all.iter().map(|o| o.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "outcome names must be distinct: {names:?}"
        );
        assert!(names.iter().all(|n| !n.is_empty()));
    }

    // ---- END-TO-END: a real quinn client, a real rustls handshake ----------
    //
    // The tests above only prove the PARSER. They cannot catch the failure that
    // actually matters: the decorator not being reached at all, or
    // `handshake_data()` arriving before the accumulator resolves. Those are
    // exactly the silently-inert shapes this codebase keeps paying for, so the
    // guard has to drive a genuine handshake.
    //
    // No `ServerState` and no WAF pipeline here — just quinn + rustls + this
    // decorator, which is the seam under test.

    fn test_server_config() -> (quinn::ServerConfig, Vec<u8>) {
        let cert =
            rcgen::generate_simple_self_signed(vec!["ja4-test.local".to_string()]).expect("rcgen");
        let der = cert.serialize_der().expect("cert der");
        let key = cert.serialize_private_key_der();
        let chain = vec![rustls::pki_types::CertificateDer::from(der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key).expect("key der");

        let mut rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];

        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg).expect("quic cfg");
        // THE THING UNDER TEST: the same wrapper `quic_server_config` installs.
        let wrapped =
            quinn::ServerConfig::with_crypto(Arc::new(Ja4ServerConfig::new(Arc::new(quic))));
        (wrapped, der)
    }

    fn test_client_config(server_cert: &[u8]) -> quinn::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                server_cert.to_vec(),
            ))
            .expect("add root");
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(cfg).expect("quic client cfg");
        quinn::ClientConfig::new(Arc::new(quic))
    }

    /// A real QUIC handshake must yield a real JA4, with the `q` prefix.
    #[tokio::test]
    async fn a_live_quic_handshake_produces_a_fingerprint() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_cfg, cert_der) = test_server_config();
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap())
            .expect("server endpoint");
        let server_addr = server.local_addr().expect("local addr");

        let accepted = tokio::spawn(async move {
            let incoming = server.accept().await.expect("an incoming connection");
            let conn = incoming.accept().expect("accept").await.expect("handshake");
            fingerprint_for(&conn)
        });

        let mut client =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        client.set_default_client_config(test_client_config(&cert_der));
        let conn = client
            .connect(server_addr, "ja4-test.local")
            .expect("connect")
            .await
            .expect("client handshake");

        let (fp, outcome) = tokio::time::timeout(std::time::Duration::from_secs(10), accepted)
            .await
            .expect("server task did not finish in time")
            .expect("server task panicked");
        drop(conn);

        assert_eq!(
            outcome,
            H3Ja4Outcome::Ok,
            "a healthy handshake must produce outcome Ok, got {outcome:?}"
        );
        let fp = fp.expect(
            "a real QUIC handshake produced NO fingerprint — the decorator is not being reached,              or handshake_data() is read before the accumulator resolves. This is the failure the              parser tests cannot see.",
        );
        assert!(
            fp.starts_with('q'),
            "JA4 over QUIC must use the q prefix: {fp}"
        );
        // Shape: a_b_c with 12-hex b and c sections.
        let parts: Vec<&str> = fp.split('_').collect();
        assert_eq!(parts.len(), 3, "JA4 has three sections: {fp}");
        assert_eq!(parts[1].len(), 12, "section b is 12 hex: {fp}");
        assert!(parts[2].len() == 12, "section c is 12 hex: {fp}");
    }

    /// The negative control: WITHOUT the wrapper, `fingerprint_for` must report
    /// `Absent` rather than inventing something. This is what makes the test
    /// above meaningful — it proves the wrapper is the reason the fingerprint
    /// exists, so reverting the one-line change in `quic_server_config` fails
    /// the suite instead of passing quietly.
    #[tokio::test]
    async fn without_the_decorator_there_is_no_fingerprint() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert =
            rcgen::generate_simple_self_signed(vec!["ja4-test.local".to_string()]).expect("rcgen");
        let der = cert.serialize_der().expect("cert der");
        let key = cert.serialize_private_key_der();
        let chain = vec![rustls::pki_types::CertificateDer::from(der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key).expect("key der");
        let mut rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg).expect("quic cfg");
        // NOT wrapped — the pre-fix state.
        let bare = quinn::ServerConfig::with_crypto(Arc::new(quic));

        let server = quinn::Endpoint::server(bare, "127.0.0.1:0".parse().unwrap()).expect("server");
        let server_addr = server.local_addr().expect("addr");
        let accepted = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.accept().expect("accept").await.expect("handshake");
            fingerprint_for(&conn)
        });

        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client");
        client.set_default_client_config(test_client_config(&der));
        let conn = client
            .connect(server_addr, "ja4-test.local")
            .expect("connect")
            .await
            .expect("client handshake");

        let (fp, outcome) = tokio::time::timeout(std::time::Duration::from_secs(10), accepted)
            .await
            .expect("timeout")
            .expect("panic");
        drop(conn);

        assert!(
            fp.is_none(),
            "an unwrapped config must yield no fingerprint"
        );
        assert_eq!(
            outcome,
            H3Ja4Outcome::Absent,
            "an unwrapped config must report Absent — that is the signal that says \
             'the decorator is not installed', and it is logged at ERROR"
        );
    }

    /// THE WIRING GUARD.
    ///
    /// The two tests above build their own wrapped config, so they prove the
    /// decorator works — but they would keep passing if someone reverted the
    /// one-line wrapper in `http3::quic_server_config`, which is the actual
    /// production path. That is the "adding a feature is TWO changes" shape, and
    /// it is worth its own test: this one goes through the real constructor.
    #[tokio::test]
    async fn the_production_quic_config_installs_the_decorator() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert =
            rcgen::generate_simple_self_signed(vec!["ja4-test.local".to_string()]).expect("rcgen");
        let der = cert.serialize_der().expect("cert der");
        let key = cert.serialize_private_key_der();
        let chain = vec![rustls::pki_types::CertificateDer::from(der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key).expect("key der");
        let rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");

        // The real constructor — not a hand-wrapped copy of it.
        let server_cfg = crate::http3::quic_server_config(rustls_cfg).expect("quic_server_config");

        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap())
            .expect("server endpoint");
        let server_addr = server.local_addr().expect("addr");
        let accepted = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.accept().expect("accept").await.expect("handshake");
            fingerprint_for(&conn)
        });

        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client");
        client.set_default_client_config(test_client_config(&der));
        let conn = client
            .connect(server_addr, "ja4-test.local")
            .expect("connect")
            .await
            .expect("client handshake");

        let (fp, outcome) = tokio::time::timeout(std::time::Duration::from_secs(10), accepted)
            .await
            .expect("timeout")
            .expect("panic");
        drop(conn);

        assert_eq!(
            outcome,
            H3Ja4Outcome::Ok,
            "http3::quic_server_config must wrap the TLS config in Ja4ServerConfig — \
             without that wrapper every h3 client reaches the pipeline unfingerprinted \
             and the JA4 blocklist is inert for h3 while staying active for TCP"
        );
        assert!(
            fp.is_some_and(|f| f.starts_with('q')),
            "the production config must yield a q-prefixed JA4"
        );
    }

    /// The TCP helper must NOT be reused here — it demands a 0x16 record header,
    /// so it would refuse every genuine QUIC hello. Pinned because the two
    /// functions look interchangeable.
    #[test]
    fn the_tcp_record_helper_would_refuse_every_quic_hello() {
        let hello = quic_client_hello();
        assert!(
            sentinel_modules::client_hello_needed_len(&hello).is_err(),
            "the TCP helper requires a TLS record header; if this ever succeeds, \
             re-check whether the two helpers can be unified"
        );
        assert!(quic_handshake_needed_len(&hello).is_some());
    }
}
