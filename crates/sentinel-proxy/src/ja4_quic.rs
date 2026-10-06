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
//!
//! # Panics must not unwind into quinn
//!
//! quinn calls the session while it holds its own `std::sync::Mutex`es and
//! takes them with `.lock().unwrap()` every time. The first Initial packet (and
//! any datagram buffered before the accept) is read inside the ENDPOINT's lock
//! (`EndpointInner::accept` → `handle_first_packet` → `read_crypto`); later
//! handshake packets inside the CONNECTION's lock, on its driver task. What
//! runs there is ours and client-reachable: the accumulator, the JA4 parser on
//! raw client bytes, and rustls's ClientHello handling, which calls the SNI
//! cert resolver. A panic that unwound out of it poisoned that lock:
//!
//! - the endpoint's: its driver panicked on the next datagram, then again in
//!   its own `Drop` during that unwind (it unwraps the same lock), and a panic
//!   while unwinding aborts the process;
//! - a connection's, on its driver: the driver's handle is dropped during that
//!   unwind, and while the handshake is under way it is the one that takes the
//!   lock to close the connection, so the same abort.
//!
//! Either way one ClientHello took the node down, as under `panic = "abort"`.
//! On TCP the same parser or resolver panic costs that one connection, and so
//! it does here: `read_handshake` and `write_handshake` contain any panic and
//! fail the handshake (INTERNAL_ERROR), so quinn closes the connection and
//! nothing else. A panic in the fingerprinting alone leaves the handshake to
//! complete without a fingerprint, like any hello the parser refuses.

use std::any::Any;
use std::sync::{Arc, Mutex};

use quinn::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session, UnsupportedVersion,
};
use quinn::{ConnectionId, Side};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{TransportError, TransportErrorCode};
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
            broken: false,
            #[cfg(test)]
            stalled: false,
        })
    }
}

struct Ja4Session {
    inner: Box<dyn Session>,
    /// The TLS session panicked: it is never driven again, and the handshake
    /// fails. Whatever rustls left half-updated stays unread.
    broken: bool,
    /// See [`inject::STALL`].
    #[cfg(test)]
    stalled: bool,
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
        #[cfg(test)]
        inject::fingerprinting(&self.accum, buf);

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

/// The handshake error for a TLS session that panicked. quinn answers it with
/// CONNECTION_CLOSE and drops that one connection.
fn handshake_panicked() -> TransportError {
    TransportError {
        code: TransportErrorCode::INTERNAL_ERROR,
        frame: None,
        reason: "TLS handshake failed".into(),
    }
}

impl Session for Ja4Session {
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if self.broken {
            return Err(handshake_panicked());
        }
        #[cfg(test)]
        inject::stall(&mut self.stalled, buf);
        // Delegate FIRST and propagate the error before accumulating, so we can
        // never fingerprint a handshake the real TLS stack rejected. Both run
        // inside quinn's locks, so neither may unwind (see the module docs).
        let ready = match crate::panic_guard::catch_request_sync(|| self.inner.read_handshake(buf))
        {
            Ok(ready) => ready?,
            Err(payload) => {
                self.broken = true;
                self.finish(None, H3Ja4Outcome::Absent);
                crate::panic_guard::client_step_panicked(
                    "the HTTP/3 TLS handshake",
                    &*payload,
                    "that connection is closed",
                );
                return Err(handshake_panicked());
            }
        };
        if let Err(payload) = crate::panic_guard::catch_request_sync(|| self.accumulate(buf)) {
            // The handshake is rustls's and went fine: it completes, without a
            // fingerprint, as for a hello the parser refuses.
            self.finish(None, H3Ja4Outcome::RefusedUnparseable);
            crate::panic_guard::client_step_panicked(
                "HTTP/3 JA4 fingerprinting",
                &*payload,
                "that connection has no fingerprint",
            );
        }
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
        if self.broken {
            return None;
        }
        #[cfg(test)]
        if self.stalled {
            return None;
        }
        // Inside quinn's locks too. Nothing more is written for a session that
        // panicked; its next read fails the handshake.
        match crate::panic_guard::catch_request_sync(|| self.inner.write_handshake(buf)) {
            Ok(keys) => keys,
            Err(payload) => {
                self.broken = true;
                crate::panic_guard::client_step_panicked(
                    "the HTTP/3 TLS handshake",
                    &*payload,
                    "that connection is closed",
                );
                None
            }
        }
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

/// Failures on demand inside the handshake, in test builds only. Each is keyed on
/// a marker the test client offers as an ALPN protocol, so it fires in that
/// client's handshake and in no other test's.
#[cfg(test)]
pub(crate) mod inject {
    /// Panics the fingerprinting on the hello's first chunk: the first Initial
    /// packet, read inside quinn's ENDPOINT lock.
    pub(crate) const FIRST_CHUNK: &[u8] = b"panic-guard-ja4-first";
    /// Panics the fingerprinting on a later chunk of a hello that spans
    /// packets, read inside the CONNECTION's lock.
    pub(crate) const LATER_CHUNK: &[u8] = b"panic-guard-ja4-later";
    /// Stalls the handshake: the server's flight is never written, so the
    /// client retransmits its hello and the handshake never completes.
    pub(crate) const STALL: &[u8] = b"panic-guard-stall";

    fn has(hay: &[u8], marker: &[u8]) -> bool {
        hay.windows(marker.len()).any(|w| w == marker)
    }

    pub(super) fn stall(stalled: &mut bool, chunk: &[u8]) {
        *stalled |= has(chunk, STALL);
    }

    pub(super) fn fingerprinting(accum: &[u8], chunk: &[u8]) {
        let first = accum.len() == chunk.len();
        if first && has(chunk, FIRST_CHUNK) {
            panic!("injected JA4 panic on the first handshake chunk");
        }
        if !first && has(accum, LATER_CHUNK) {
            panic!("injected JA4 panic on a later handshake chunk");
        }
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

    // ---- PANICS INSIDE THE HANDSHAKE ---------------------------------------
    //
    // quinn drives the session under its own locks (see the module docs), so
    // these run real handshakes against a real endpoint: what matters is that
    // the endpoint, and every other connection, outlive the panic.

    /// A client config like `test_client_config` that offers `alpn`.
    fn client_config_offering(server_cert: &[u8], alpn: Vec<Vec<u8>>) -> quinn::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                server_cert.to_vec(),
            ))
            .expect("add root");
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn;
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(cfg).expect("quic client cfg");
        quinn::ClientConfig::new(Arc::new(quic))
    }

    type HandshakeResult = Result<(Option<String>, H3Ja4Outcome), String>;

    /// Accept every connection on its own task, as `serve_quic` does, and
    /// report how each handshake ended. A task the panic unwound reports
    /// nothing; one whose handshake never ends reports nothing either.
    fn serve_handshakes(
        server_cfg: quinn::ServerConfig,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<HandshakeResult>,
    ) {
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap())
            .expect("server endpoint");
        let addr = server.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let ended = match incoming.accept() {
                        Ok(connecting) => match connecting.await {
                            Ok(conn) => Ok(fingerprint_for(&conn)),
                            Err(e) => Err(e.to_string()),
                        },
                        Err(e) => Err(e.to_string()),
                    };
                    let _ = tx.send(ended);
                });
            }
        });
        (addr, rx)
    }

    async fn handshake(
        addr: std::net::SocketAddr,
        cfg: quinn::ClientConfig,
        sni: &str,
    ) -> Result<quinn::Connection, String> {
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client");
        let connecting = client
            .connect_with(cfg, addr, sni)
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(std::time::Duration::from_secs(10), connecting)
            .await
            .map_err(|_| "the client's handshake timed out".to_string())?
            .map_err(|e| e.to_string())
    }

    async fn server_side(
        outcomes: &mut tokio::sync::mpsc::UnboundedReceiver<HandshakeResult>,
        what: &str,
    ) -> HandshakeResult {
        tokio::time::timeout(std::time::Duration::from_secs(10), outcomes.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("{what}: the server's handshake never ended — the panic left it waiting")
            })
            .unwrap_or_else(|| panic!("{what}: the server stopped accepting"))
    }

    /// Serves `cert` for every name but one, for which it panics: rustls calls
    /// it while it reads the ClientHello, inside quinn's endpoint lock.
    #[derive(Debug)]
    struct PanicsForOneName(Arc<rustls::sign::CertifiedKey>);

    const PANIC_SNI: &str = "panic.ja4-test.local";

    impl rustls::server::ResolvesServerCert for PanicsForOneName {
        fn resolve(
            &self,
            hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            if hello.server_name() == Some(PANIC_SNI) {
                panic!("injected certificate resolver panic");
            }
            Some(Arc::clone(&self.0))
        }
    }

    /// A panic in rustls's handshake (here its cert resolver) on the first
    /// Initial packet unwound through quinn's endpoint lock and poisoned it:
    /// the endpoint's driver panicked on the next datagram, and no connection
    /// on the listener was ever served again. It now fails that one handshake.
    #[tokio::test]
    async fn a_tls_handshake_panic_costs_only_that_connection() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert =
            rcgen::generate_simple_self_signed(vec!["ja4-test.local".to_string()]).expect("rcgen");
        let der = cert.serialize_der().expect("cert der");
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.serialize_private_key_der())
            .expect("key der");
        let signing = rustls::crypto::ring::sign::any_supported_type(&key).expect("signing key");
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(der.clone())],
            signing,
        ));
        let rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(PanicsForOneName(certified)));
        let (addr, mut outcomes) =
            serve_handshakes(crate::http3::quic_server_config(rustls_cfg).expect("quic config"));

        let refused = handshake(addr, test_client_config(&der), PANIC_SNI).await;
        assert!(refused.is_err(), "the handshake whose resolver panicked");
        let ended = server_side(&mut outcomes, "the panicking handshake").await;
        assert!(
            ended.is_err(),
            "the server failed that handshake: {ended:?}"
        );

        // The endpoint, and the next client, never noticed.
        for n in 0..2 {
            let conn = handshake(addr, test_client_config(&der), "ja4-test.local")
                .await
                .unwrap_or_else(|e| panic!("handshake {n} after the panic: {e}"));
            let (fp, outcome) = server_side(&mut outcomes, "a later handshake")
                .await
                .unwrap_or_else(|e| panic!("handshake {n} after the panic, server side: {e}"));
            assert_eq!(outcome, H3Ja4Outcome::Ok);
            assert!(fp.is_some_and(|f| f.starts_with('q')));
            drop(conn);
        }
    }

    /// A panic in the fingerprinting, on the hello's first chunk (inside
    /// quinn's endpoint lock) or on a later one (a hello that spans Initial
    /// packets, inside the connection's lock on its driver: the common case for
    /// post-quantum hellos). The first poisoned the endpoint; the second killed
    /// the connection's driver, and the accepting side waited for ever on a
    /// handshake nobody would finish. The handshake is rustls's and went fine,
    /// so it now completes, without a fingerprint, like a hello the parser
    /// refuses.
    #[tokio::test]
    async fn a_fingerprinting_panic_completes_the_handshake_unfingerprinted() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server_cfg, der) = test_server_config();
        let (addr, mut outcomes) = serve_handshakes(server_cfg);

        // Six 250-byte protocols put the hello past one Initial packet.
        let padding: Vec<Vec<u8>> = (0..6u8).map(|i| vec![b'a' + i; 250]).collect();
        let cases = [
            (
                "first chunk",
                vec![b"h3".to_vec(), inject::FIRST_CHUNK.to_vec()],
            ),
            (
                "later chunk",
                [
                    vec![b"h3".to_vec()],
                    padding,
                    vec![inject::LATER_CHUNK.to_vec()],
                ]
                .concat(),
            ),
        ];
        for (label, alpn) in cases {
            let conn = handshake(addr, client_config_offering(&der, alpn), "ja4-test.local")
                .await
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            let (fp, outcome) = server_side(&mut outcomes, label)
                .await
                .unwrap_or_else(|e| panic!("{label}: the server failed the handshake: {e}"));
            assert_eq!(outcome, H3Ja4Outcome::RefusedUnparseable, "{label}");
            assert!(fp.is_none(), "{label}: a partial fingerprint: {fp:?}");
            drop(conn);
        }

        let conn = handshake(addr, test_client_config(&der), "ja4-test.local")
            .await
            .expect("a hello that does not panic");
        let (fp, outcome) = server_side(&mut outcomes, "a plain hello")
            .await
            .expect("the plain handshake, server side");
        assert_eq!(outcome, H3Ja4Outcome::Ok);
        assert!(fp.is_some());
        drop(conn);
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
