//! Upstream connection pool, load balancer, health checks, and circuit breaker.
//!
//! ## Connection pooling
//! A single [`hyper_util::client::legacy::Client`] with an HTTPS connector is
//! shared for all upstream requests.  hyper's built-in pool reuses keep-alive
//! connections (up to 32 idle per host, 90 s idle timeout), eliminating the
//! per-request TCP handshake overhead of the previous implementation.
//!
//! ## Load balancing
//! All five strategies from config are implemented:
//! - **RoundRobin** (default) — uniform distribution via atomic cursor.
//! - **LeastConn** — dispatches to the server with the fewest in-flight requests.
//! - **IpHash** — consistent hashing on client IP for session affinity.
//! - **Random** — random selection via nanosecond-timestamp entropy.
//! - **Adaptive** — alias for RoundRobin; reserved for future latency-aware logic.
//!
//! ## Health checks + circuit breaker
//! Each server tracks consecutive failures.  After
//! [`CIRCUIT_OPEN_THRESHOLD`] consecutive failures the circuit OPENS and the
//! server is not sent requests for [`CIRCUIT_OPEN_BASE_MS`]. Then it is
//! HALF-OPEN: exactly one request goes through as a probe. Success closes the
//! circuit; failure re-opens it for twice as long, up to [`CIRCUIT_OPEN_MAX_MS`].
//!
//! When every server of a site is open, the request is answered 503 with a
//! Retry-After at once ([`OriginUnavailable`]) — the origin is known to be down,
//! so the visitor is not made to wait out a connect timeout to learn it.
//!
//! ## Per-site bulkhead
//! Each site may have at most [`site_inflight_limit`] requests waiting on its
//! origin at once; past that it is shed with 503 ([`SiteBusy`]). The node-wide
//! in-flight limit is shared by every site, so without this one site with a hung
//! origin held every permit it could get and the node shed ALL sites.
//!
//! Active health checks can be enabled via the `health_check` block in the
//! upstream config:
//! ```yaml
//! health_check:
//!   path: /healthz
//!   interval: 10s
//!   timeout: 2s
//! ```
//! Call [`UpstreamPool::spawn_health_checks`] after construction to start
//! background probers.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use http::Request;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt as _;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use sentinel_core::config::{LoadBalancerStrategy, SentinelConfig, UpstreamServer};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Circuit-breaker tunables
// ---------------------------------------------------------------------------

/// Number of consecutive upstream failures before a server's circuit opens.
const CIRCUIT_OPEN_THRESHOLD: usize = 5;

/// How long a circuit stays open before one probe is let through.
///
/// Short on purpose. While every origin of a site is open the site answers 503,
/// so this is also how long a site stays down after its origin comes back from
/// a restart. A probe that fails doubles the wait, up to the ceiling below, so
/// an origin that stays down costs one request per 30 s, not one per 5 s.
const CIRCUIT_OPEN_BASE_MS: u64 = 5_000;

/// Longest a circuit stays open between probes.
const CIRCUIT_OPEN_MAX_MS: u64 = 30_000;

/// Default upstream connect timeout (bounds TCP + TLS establishment). Override
/// with `SENTINEL_UPSTREAM_CONNECT_TIMEOUT_SECS`.
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Upper bound on a per-site connect timeout.
const MAX_SITE_CONNECT_TIMEOUT_SECS: u64 = 60;

/// How many DISTINCT per-site connect timeouts get their own connection pool.
///
/// Connect timeout is a property of the connector, so honouring it per site means
/// one hyper client — and therefore one idle-connection pool and its file
/// descriptors — per distinct value. That is fine for the handful of values a
/// real deployment uses and not fine if a large tenant base picks arbitrary ones,
/// so the count is capped: sites beyond the cap fall back to the node default and
/// log it, rather than quietly multiplying pools until the node runs out of
/// descriptors.
const MAX_CONNECT_TIMEOUT_CLIENTS: usize = 8;

/// Default overall upstream request timeout (connect + send + first byte +
/// response headers). Without this a slow/hung origin pins the request task and
/// its in-flight admission permit forever — enough stalls shed ALL traffic
/// (fail-closed self-DoS). A timeout is recorded as a circuit-breaker failure.
/// Override with `SENTINEL_UPSTREAM_TIMEOUT_SECS`.
const UPSTREAM_TIMEOUT_SECS: u64 = 30;

/// Parse a positive-seconds env override, falling back to `default`.
fn env_secs(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Per-server health + circuit-breaker state
// ---------------------------------------------------------------------------

/// Milliseconds on a monotonic clock local to this process. Wall-clock time
/// would let an NTP step open or close every circuit at once.
fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Where a server's circuit stands at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Circuit {
    Closed,
    /// No request may be sent for `retry_in_ms` more milliseconds.
    Open {
        retry_in_ms: u64,
    },
    /// One probe may be sent, if no other probe is already out.
    HalfOpen,
}

/// All runtime tracking for a single upstream server.
struct ServerHealth {
    server: UpstreamServer,

    /// `true` = server considers itself healthy. Reporting only (`stats`).
    healthy: AtomicBool,

    /// Number of requests currently being sent to this server (LeastConn).
    active_conns: AtomicUsize,

    /// How many upstream errors have occurred in a row.
    consecutive_failures: AtomicUsize,

    /// `now_ms()` when the circuit last opened.
    opened_at_ms: AtomicU64,

    /// How long the circuit stays open this time; doubles per failed probe.
    open_for_ms: AtomicU64,

    /// A half-open probe is out. Cleared by the probe's [`Lease`] however the
    /// request ends — including the client going away mid-request, which used
    /// to be the way a breaker got stuck.
    probe_in_flight: AtomicBool,
}

impl ServerHealth {
    fn new(server: UpstreamServer) -> Self {
        Self {
            server,
            healthy: AtomicBool::new(true),
            active_conns: AtomicUsize::new(0),
            consecutive_failures: AtomicUsize::new(0),
            opened_at_ms: AtomicU64::new(0),
            open_for_ms: AtomicU64::new(CIRCUIT_OPEN_BASE_MS),
            probe_in_flight: AtomicBool::new(false),
        }
    }

    fn circuit_at(&self, now: u64) -> Circuit {
        if self.consecutive_failures.load(Ordering::Acquire) < CIRCUIT_OPEN_THRESHOLD {
            return Circuit::Closed;
        }
        let until =
            self.opened_at_ms.load(Ordering::Acquire) + self.open_for_ms.load(Ordering::Acquire);
        if now < until {
            Circuit::Open {
                retry_in_ms: until - now,
            }
        } else {
            Circuit::HalfOpen
        }
    }

    /// Claim the one half-open probe. False if another request holds it.
    fn try_claim_probe(&self) -> bool {
        self.probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn record_success(&self) {
        let failures = self.consecutive_failures.swap(0, Ordering::AcqRel);
        self.open_for_ms
            .store(CIRCUIT_OPEN_BASE_MS, Ordering::Release);
        let was_down = !self.healthy.swap(true, Ordering::AcqRel);
        if was_down || failures >= CIRCUIT_OPEN_THRESHOLD {
            info!(
                host = %self.server.host,
                port = self.server.port,
                "upstream circuit closed: origin answering again"
            );
        }
    }

    /// `probe`: this failure is the outcome of the half-open probe.
    fn record_failure_at(&self, probe: bool, now: u64) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if probe {
            // The origin is still down: wait twice as long before the next try.
            let next = (self.open_for_ms.load(Ordering::Acquire) * 2).min(CIRCUIT_OPEN_MAX_MS);
            self.open_for_ms.store(next, Ordering::Release);
            self.opened_at_ms.store(now, Ordering::Release);
            self.healthy.store(false, Ordering::Release);
            debug!(
                host = %self.server.host,
                port = self.server.port,
                next_probe_in_ms = next,
                "upstream circuit probe failed; staying open"
            );
        } else if failures == CIRCUIT_OPEN_THRESHOLD {
            self.open_for_ms
                .store(CIRCUIT_OPEN_BASE_MS, Ordering::Release);
            self.opened_at_ms.store(now, Ordering::Release);
            self.healthy.store(false, Ordering::Release);
            warn!(
                host = %self.server.host,
                port = self.server.port,
                failures,
                "upstream circuit breaker opened: requests answered 503 until a probe succeeds"
            );
        }
        // Past the threshold and not a probe: a request sent before the circuit
        // opened, finishing late. The window is already running; leave it.
    }

    fn record_failure(&self, probe: bool) {
        self.record_failure_at(probe, now_ms())
    }
}

// ---------------------------------------------------------------------------
// Fast-fail errors — typed, so the gateway maps them to 503 without parsing
// ---------------------------------------------------------------------------

/// Every origin of the site has an open circuit. Answered 503 at once.
#[derive(Debug, Clone, Copy)]
pub struct OriginUnavailable {
    /// When a probe will next be let through — the Retry-After.
    pub retry_after: Duration,
}

impl std::fmt::Display for OriginUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "origin unavailable: every upstream server's circuit is open (next probe in {} ms)",
            self.retry_after.as_millis()
        )
    }
}

impl std::error::Error for OriginUnavailable {}

/// The site already has its limit of requests waiting on its origin.
#[derive(Debug, Clone, Copy)]
pub struct SiteBusy {
    pub limit: usize,
}

impl std::fmt::Display for SiteBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "site at its in-flight limit ({} requests waiting on the origin)",
            self.limit
        )
    }
}

impl std::error::Error for SiteBusy {}

/// The right to send one request to one server: which server, whether the
/// request is that server's half-open probe, and the site's in-flight permit.
///
/// Everything it accounts for is undone when it drops, however the request
/// ends: the permit returns, the active-connection count comes down, and a
/// probe that produced no outcome — the client went away mid-request — frees
/// the probe for the next request. Before this, a request future dropped
/// mid-send never decremented `active_conns`, skewing LeastConn for good.
pub struct Lease {
    health: Arc<ServerHealth>,
    probe: bool,
    settled: bool,
    timeout: Duration,
    connect_timeout: Option<Duration>,
    _site_permit: Option<OwnedSemaphorePermit>,
}

impl Lease {
    fn new(
        health: Arc<ServerHealth>,
        probe: bool,
        timeout: Duration,
        connect_timeout: Option<Duration>,
        site_permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        health.active_conns.fetch_add(1, Ordering::AcqRel);
        Self {
            health,
            probe,
            settled: false,
            timeout,
            connect_timeout,
            _site_permit: site_permit,
        }
    }

    /// The server this lease is for.
    pub fn server(&self) -> &UpstreamServer {
        &self.health.server
    }

    /// Whether this request is the server's half-open probe.
    pub fn is_probe(&self) -> bool {
        self.probe
    }

    fn settle(&mut self, ok: bool) {
        if self.settled {
            return;
        }
        self.settled = true;
        if ok {
            self.health.record_success();
        } else {
            self.health.record_failure(self.probe);
        }
        if self.probe {
            self.health.probe_in_flight.store(false, Ordering::Release);
        }
    }
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field(
                "server",
                &format_args!("{}:{}", self.health.server.host, self.health.server.port),
            )
            .field("probe", &self.probe)
            .field("settled", &self.settled)
            .finish()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.health.active_conns.fetch_sub(1, Ordering::AcqRel);
        if self.probe && !self.settled {
            // No outcome — not evidence either way. Free the probe.
            self.health.probe_in_flight.store(false, Ordering::Release);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-site upstream list with load-balancing strategy
// ---------------------------------------------------------------------------

pub(crate) struct SiteUpstream {
    servers: Vec<Arc<ServerHealth>>,
    cursor: AtomicUsize,
    strategy: LoadBalancerStrategy,
    /// Per-site override for the response-header timeout.  `None` = use the
    /// deployment-wide default.  See [`UpstreamConfig::timeout_secs`].
    timeout: Option<Duration>,
    /// Per-site override for the CONNECT timeout, already clamped.  `None` = use
    /// the deployment-wide connector.  See [`UpstreamConfig::connect_timeout_secs`].
    connect_timeout: Option<Duration>,
    /// The site's bulkhead: one permit per request waiting on its origin.
    /// Carried across config syncs, so a sync does not hand a busy site a
    /// fresh, empty allowance.
    inflight: Arc<Semaphore>,
    inflight_limit: usize,
}

/// Clamp a per-site connect timeout into something defensible.
///
/// Absent or `0` means "no override". Sub-second is not expressible here and a
/// very long connect timeout defeats the purpose of having one — it would pin a
/// request task on an unreachable origin for minutes — so the range is bounded
/// at both ends rather than trusted.
fn site_connect_timeout(secs: Option<u64>) -> Option<Duration> {
    secs.filter(|&s| s > 0)
        .map(|s| Duration::from_secs(s.clamp(1, MAX_SITE_CONNECT_TIMEOUT_SECS)))
}

/// Interpret a per-site `timeout_secs` setting.  Absent or `0` means "no
/// override" — never "no timeout", which would let a hung origin pin a request
/// task (and its admission permit) forever.
fn site_timeout(secs: Option<u64>) -> Option<Duration> {
    secs.filter(|&s| s > 0).map(Duration::from_secs)
}

/// What [`SiteUpstream::choose`] decided, before any permit is taken.
enum Choice {
    /// Send to this server; `probe` if it is that server's half-open probe.
    Server {
        health: Arc<ServerHealth>,
        probe: bool,
    },
    /// Every server is open (or half-open with its probe already out).
    AllOpen { retry_after: Duration },
    /// The site has no servers configured.
    NoServers,
}

impl SiteUpstream {
    fn new(
        servers: Vec<UpstreamServer>,
        strategy: LoadBalancerStrategy,
        timeout: Option<Duration>,
        connect_timeout: Option<Duration>,
        inflight_limit: usize,
    ) -> Self {
        Self {
            servers: servers
                .into_iter()
                .map(|s| Arc::new(ServerHealth::new(s)))
                .collect(),
            cursor: AtomicUsize::new(0),
            strategy,
            timeout,
            connect_timeout,
            inflight: Arc::new(Semaphore::new(inflight_limit)),
            inflight_limit,
        }
    }

    /// Pick a server at `now`.
    ///
    /// A half-open server with no probe out gets this request as its probe —
    /// even when other servers are closed, or a recovered server would never be
    /// tried again. Otherwise the strategy picks among the closed ones. With
    /// none closed, the answer is [`Choice::AllOpen`]: the request fails fast.
    ///
    /// This used to force-reset every circuit when all were open and send the
    /// request anyway, "so traffic is never silently dropped". For the usual
    /// single-origin site that meant the breaker never shed a thing: each
    /// request to a dead origin waited out the connect timeout, holding a
    /// node-wide in-flight permit, and logged a warning — every request.
    fn choose(&self, client_ip: Option<IpAddr>, now: u64) -> Choice {
        if self.servers.is_empty() {
            return Choice::NoServers;
        }
        let mut closed: Vec<Arc<ServerHealth>> = Vec::with_capacity(self.servers.len());
        let mut soonest_ms: Option<u64> = None;
        for s in &self.servers {
            match s.circuit_at(now) {
                Circuit::Closed => closed.push(Arc::clone(s)),
                Circuit::HalfOpen => {
                    if s.try_claim_probe() {
                        return Choice::Server {
                            health: Arc::clone(s),
                            probe: true,
                        };
                    }
                    // Probe already out: its answer is due within a timeout.
                    soonest_ms = Some(soonest_ms.map_or(1_000, |m| m.min(1_000)));
                }
                Circuit::Open { retry_in_ms } => {
                    soonest_ms = Some(soonest_ms.map_or(retry_in_ms, |m| m.min(retry_in_ms)));
                }
            }
        }
        if closed.is_empty() {
            return Choice::AllOpen {
                retry_after: Duration::from_millis(soonest_ms.unwrap_or(CIRCUIT_OPEN_BASE_MS)),
            };
        }
        Choice::Server {
            health: self.pick(&closed, client_ip),
            probe: false,
        }
    }

    /// Apply the load-balancing strategy to a non-empty candidate list.
    fn pick(&self, pool: &[Arc<ServerHealth>], client_ip: Option<IpAddr>) -> Arc<ServerHealth> {
        match self.strategy {
            LoadBalancerStrategy::RoundRobin | LoadBalancerStrategy::Adaptive => {
                let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % pool.len();
                Arc::clone(&pool[idx])
            }
            LoadBalancerStrategy::LeastConn => pool
                .iter()
                .min_by_key(|s| s.active_conns.load(Ordering::Relaxed))
                .cloned()
                .unwrap_or_else(|| Arc::clone(&pool[0])),
            LoadBalancerStrategy::IpHash => {
                let hash = if let Some(ip) = client_ip {
                    let mut h = DefaultHasher::new();
                    ip.hash(&mut h);
                    h.finish() as usize
                } else {
                    self.cursor.fetch_add(1, Ordering::Relaxed)
                };
                Arc::clone(&pool[hash % pool.len()])
            }
            LoadBalancerStrategy::Random => {
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as usize;
                Arc::clone(&pool[seed % pool.len()])
            }
        }
    }
}

/// Default per-site in-flight limit: half the node's in-flight limit, so one
/// site with a hung origin can hold at most half the node and every other site
/// keeps the rest. `SENTINEL_SITE_MAX_INFLIGHT_REQUESTS` overrides it.
fn site_inflight_limit(node_limit: usize) -> usize {
    std::env::var("SENTINEL_SITE_MAX_INFLIGHT_REQUESTS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| (node_limit / 2).max(1))
}

// ---------------------------------------------------------------------------
// UpstreamPool
// ---------------------------------------------------------------------------

type PooledClient = Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, hyper::Error>>;

/// Snapshot of pool health for observability.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub healthy: usize,
    pub total: usize,
}

/// SNI overrides for HTTPS origins, keyed by the upstream authority `host:port`
/// exactly as it appears in the URI the proxy builds.
///
/// Keyed by authority rather than site id because the only thing the TLS layer
/// gets to see at handshake time is the destination URI — see
/// [`UpstreamPool::sni_overrides`].
type SniRegistry = DashMap<String, rustls::pki_types::ServerName<'static>>;

/// Resolve the SNI name for a destination URI, honouring any registered override.
///
/// The fallback path reproduces hyper-rustls's `DefaultServerNameResolver`
/// (including stripping the brackets from an IPv6 literal), so a site with no
/// override behaves exactly as it did before this existed.
fn resolve_sni(
    overrides: &SniRegistry,
    uri: &http::Uri,
) -> Result<rustls::pki_types::ServerName<'static>, rustls::pki_types::InvalidDnsNameError> {
    if let Some(auth) = uri.authority().map(|a| a.as_str()) {
        if let Some(found) = overrides.get(auth) {
            return Ok(found.clone());
        }
    }
    let mut hostname = uri.host().unwrap_or_default();
    if let Some(trimmed) = hostname.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        hostname = trimmed;
    }
    rustls::pki_types::ServerName::try_from(hostname.to_string())
}

/// Build a client (and its connection pool) with a given connect timeout.
///
/// Factored out because there is now more than one: the node default plus one per
/// distinct per-site connect timeout. Everything except the connect timeout —
/// The origin accepted the connection but sent no response headers within the
/// site's read timeout.
///
/// A distinct error TYPE, because the answer to the client depends on it: an
/// origin that is reachable but slow is a 504 Gateway Timeout, while one that
/// refused the connection, failed TLS or sent garbage is a 502 Bad Gateway. Every
/// upstream failure used to be 502, so "the application is hanging" and "the
/// application is down" looked identical in the browser and in the logs — on the
/// first real UAT deployment the operator saw 502 for an app that was accepting
/// connections and never answering. Matched by type in
/// `gateway_error_status`, never by message text.
#[derive(Debug)]
pub struct UpstreamTimeout(pub Duration);

impl std::fmt::Display for UpstreamTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream request timed out after {:?}", self.0)
    }
}

impl std::error::Error for UpstreamTimeout {}

/// Extra trust anchors for ORIGIN connections, from `SENTINEL_UPSTREAM_CA_FILE`.
///
/// `Ok(vec![])` — not configured.
/// `Ok(certs)`  — parsed; these are ADDED to the public roots.
/// `Err`        — configured but unusable; the caller logs and keeps the public
///                roots (see the note on additive semantics below).
///
/// # Why this exists
///
/// The connector trusted the webpki roots and nothing else, with no override, so
/// an origin whose certificate chains to a corporate/internal CA — the ordinary
/// enterprise case for the application a WAF sits in front of — failed
/// verification and 502'd for ever. Nothing in the UI said so: the wizard's
/// "Upstream uses HTTPS" toggle warned about SNI and never mentioned the CA.
///
/// # Why ADDITIVE, unlike the ClickHouse and SIEM loaders
///
/// Those two talk to exactly ONE peer, so a configured CA REPLACES the public
/// roots and narrows trust to that peer — and there, failing to load it and
/// falling back genuinely widens trust, which is why they fail closed.
///
/// A WAF fronts MANY origins, and a deployment can legitimately mix internal-CA
/// and public-CA backends. Replacing the roots the moment one internal CA is
/// configured would silently break every public-CA origin that was working. So
/// the file ADDS anchors.
///
/// That flips the error case, and deliberately: because the baseline is the
/// public roots, failing to load the extra CA leaves trust exactly where the
/// operator already had it. It does not widen anything — it fails to widen. The
/// internal-CA origins keep 502ing, which is the symptom the operator is already
/// chasing, and the ERROR log now names the cause. Emptying the root store here
/// would instead take down every HTTPS origin on the node over a typo in an env
/// var, turning a config error into a total outage.
fn upstream_ca_certs() -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let path = match std::env::var("SENTINEL_UPSTREAM_CA_FILE") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return Ok(vec![]),
    };
    let pem = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let mut rd = std::io::BufReader::new(std::io::Cursor::new(pem));
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut rd) {
        certs.push(cert.map_err(|e| format!("parse {path}: {e}"))?);
    }
    if certs.is_empty() {
        return Err(format!("{path} contained no CERTIFICATE blocks"));
    }
    Ok(certs)
}

/// The rustls config every upstream connector uses: public roots, plus any
/// private CA the operator has configured.
///
/// The `ring` provider is passed explicitly rather than relying on the
/// process-default. sentinel-bin installs it at startup, but this code also runs
/// from unit tests where nothing has, and `ClientConfig::builder()` panics in
/// that state — the same reasoning as the ClickHouse connector.
fn upstream_tls_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports the default protocol versions")
    .with_root_certificates(upstream_roots())
    .with_no_client_auth()
}

/// The trust anchors for origin connections: the public roots, plus any private
/// CA. Split out from `upstream_tls_config` because `rustls::ClientConfig` does
/// not expose its root store, so this is the only way to assert what is actually
/// trusted — and what is trusted is the whole point of this code.
fn upstream_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let public = roots.len();

    match upstream_ca_certs() {
        Ok(certs) if !certs.is_empty() => {
            let mut added = 0usize;
            for c in certs {
                match roots.add(c) {
                    Ok(()) => added += 1,
                    // One bad anchor in a bundle must not discard the good ones.
                    Err(e) => {
                        warn!(error = %e, "upstream TLS: skipping an unusable certificate in SENTINEL_UPSTREAM_CA_FILE")
                    }
                }
            }
            if added == 0 {
                error!(
                    "upstream TLS: SENTINEL_UPSTREAM_CA_FILE parsed but NO certificate in it was \
                     usable as a trust anchor — origins behind that CA will keep failing \
                     verification (502)"
                );
            } else {
                info!(
                    certs = added,
                    public_roots = public,
                    "upstream TLS: trusting a private CA for origin connections, in addition to the public roots"
                );
            }
        }
        Ok(_) => {}
        Err(e) => error!(
            error = %e,
            "upstream TLS: SENTINEL_UPSTREAM_CA_FILE is set but unusable — origins whose \
             certificate chains to that CA will FAIL verification and 502. Trust is unchanged \
             (the public roots), so public-CA origins keep working; fix the path or the file."
        ),
    }
    roots
}

/// TLS roots, ALPN, idle sizing, the SNI resolver — must stay identical between
/// them, and it does so by construction here rather than by two call sites being
/// kept in step.
///
/// `sni_overrides` is shared (not copied) so that a hot config change registering
/// a new override reaches every pool, including ones built earlier.
fn build_client(connect_timeout: Duration, sni_overrides: Arc<SniRegistry>) -> PooledClient {
    // Own the base HTTP connector so we can bound connect (TCP+TLS) time; the
    // default builder gives no connect timeout, so an unreachable origin would
    // hang the connect indefinitely. enforce_http(false) lets https:// URIs
    // through to the TLS layer.
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(connect_timeout));
    http.enforce_http(false);
    // Per-site SNI. hyper-rustls uses the resolved name BOTH as the SNI sent in
    // the ClientHello and as the name the origin's certificate is verified
    // against — which is the correct coupling: presenting a name we would not
    // then verify would be theatre. The practical consequence is that an
    // sni_name the origin's certificate does not cover fails the handshake
    // rather than silently connecting, so a wrong value is loud.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(upstream_tls_config())
        .https_or_http()
        .with_server_name_resolver(move |uri: &http::Uri| resolve_sni(&sni_overrides, uri))
        // HTTP/1.1 ONLY to the origin, deliberately.
        //
        // `.enable_http2()` advertised h2 in ALPN, so any origin that speaks h2
        // negotiated it — and the request we then sent was malformed, because
        // the two halves of the forwarded request disagree about the authority:
        //
        //   * the URI is rebuilt for the connection (build_upstream_uri), so its
        //     authority is the upstream ADDRESS — `10.0.0.5:443`. Over h2 hyper
        //     turns that into `:authority`.
        //   * the Host header carries the name the CLIENT asked for, which is
        //     what a virtual-hosted origin must route on.
        //
        // RFC 9113 §8.3.1 requires `:authority` and `Host` to be identical when
        // both are present, and a server MUST treat a mismatch as malformed. So
        // an h2-capable origin answered every proxied request with a generic 400
        // while the same request over HTTP/1.1 — where Host alone is
        // authoritative and an absolute-form target is legal — worked.
        //
        // Found on the first HTTPS origin behind this WAF that speaks h2 (an
        // APISIX gateway): identical curl to the origin returned 301, everything
        // through the WAF returned 400. It was invisible until then because the
        // only other origin we had ever proxied was plain HTTP.
        //
        // Two lines elsewhere already ASSUMED this hop is HTTP/1.1 — the request
        // version is forced to HTTP_11, and per-site keep-alive sends
        // `Connection: close`, which is a protocol error in h2. The connector was
        // the odd one out; this makes the code agree with itself.
        //
        // Keeping h2 upstream would mean making the URI authority the client's
        // hostname and teaching the connector to dial the configured address
        // instead — worth doing if an origin ever needs h2, and not for the
        // marginal gain on a proxy→origin hop that nginx also defaults to 1.1.
        .enable_http1()
        .wrap_connector(http);

    // Keep-alive pool sizing. 32 idle/host is far too low for a reverse proxy:
    // once in-flight concurrency to an upstream exceeds it, the surplus
    // connections are closed when briefly idle and reopened on the next burst —
    // churning TCP handshakes and piling up TIME_WAIT sockets
    // (ephemeral-port-exhaustion risk under load). Default high; override with
    // SENTINEL_UPSTREAM_MAX_IDLE for very large fleets / FD limits.
    let max_idle = std::env::var("SENTINEL_UPSTREAM_MAX_IDLE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(256);

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(max_idle)
        .build(https)
}

/// Manages pooled upstream connections and per-site load balancing.
pub struct UpstreamPool {
    sites: DashMap<String, Arc<SiteUpstream>>,
    /// Shared HTTP/HTTPS keep-alive pool used by every site that does not
    /// override the connect timeout — i.e. nearly all of them.
    client: PooledClient,
    /// Additional pools, one per distinct per-site connect timeout, created on
    /// first use and capped at [`MAX_CONNECT_TIMEOUT_CLIENTS`]. Keyed by whole
    /// seconds because that is the granularity the config exposes.
    connect_timeout_clients: DashMap<u64, PooledClient>,
    /// SNI overrides, shared with every client's TLS connector.
    ///
    /// Keyed by upstream authority (`host:port`), not by site, because the TLS
    /// layer resolves the name from the destination URI and has no idea which
    /// site the request belongs to. Two sites pointing at the SAME origin
    /// authority therefore cannot hold different overrides; that collision is
    /// detected and logged when the registry is built rather than resolved
    /// arbitrarily in the dark.
    sni_overrides: Arc<SniRegistry>,
    /// Overall per-request upstream timeout (see [`UPSTREAM_TIMEOUT_SECS`]).
    upstream_timeout: Duration,
    /// Each site's bulkhead size (see [`site_inflight_limit`]).
    site_inflight_limit: usize,
}

impl UpstreamPool {
    /// Snapshot of pool health for observability.
    pub fn stats(&self) -> PoolStats {
        let mut healthy = 0usize;
        let mut total = 0usize;
        for entry in self.sites.iter() {
            for sh in &entry.servers {
                total += 1;
                if sh.healthy.load(Ordering::Relaxed) {
                    healthy += 1;
                }
            }
        }
        PoolStats { healthy, total }
    }

    /// Client whose connector carries `ct` as its connect timeout, created on
    /// first use.
    ///
    /// Falls back to the node-default client once [`MAX_CONNECT_TIMEOUT_CLIENTS`]
    /// distinct values exist. That fallback is a deliberate, logged degradation:
    /// the alternative is one more connection pool — and its idle sockets and file
    /// descriptors — for every distinct value any tenant happens to type, which
    /// ends in descriptor exhaustion on a busy node. A node hitting this cap has a
    /// configuration problem worth seeing in the log, not a reason to stop serving
    /// traffic.
    /// Rebuild the SNI override registry from a site list.
    ///
    /// Called on load and on every hot config sync. Overrides are only meaningful
    /// for a TLS origin, so a plaintext server is skipped — registering one would
    /// be inert and misleading.
    fn refresh_sni_overrides(registry: &SniRegistry, sites: &[sentinel_core::config::SiteConfig]) {
        // Compute the new set first, then reconcile, so a removed override is
        // actually removed. Leaving stale entries would mean deleting an sni_name
        // from a site's config had no effect until restart — the silently-inert
        // shape this whole exercise is about.
        let mut wanted: Vec<(String, String, String)> = Vec::new(); // (authority, sni, site_id)
        for site in sites {
            let Some(sni) = site
                .upstream
                .sni_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            for srv in &site.upstream.servers {
                if !srv.tls {
                    warn!(
                        site = %site.id, server = %srv.host,
                        "sni_name is set but this server is plaintext (tls: false); \
                         there is no handshake to put a server name in — ignoring"
                    );
                    continue;
                }
                wanted.push((
                    format!("{}:{}", srv.host, srv.port),
                    sni.to_string(),
                    site.id.clone(),
                ));
            }
        }

        for (authority, sni, site_id) in &wanted {
            match rustls::pki_types::ServerName::try_from(sni.clone()) {
                Ok(name) => {
                    if let Some(prev) = registry.get(authority) {
                        if *prev != name {
                            warn!(
                                site = %site_id, authority = %authority, sni = %sni,
                                "two sites set a DIFFERENT sni_name for the same origin \
                                 authority; SNI is resolved from the destination URI, which \
                                 cannot distinguish them. Last one wins — give the origins \
                                 distinct addresses if they need distinct names."
                            );
                        }
                    }
                    registry.insert(authority.clone(), name);
                }
                Err(e) => warn!(
                    site = %site_id, sni = %sni,
                    "invalid sni_name, not a valid DNS name; using the upstream host: {e}"
                ),
            }
        }

        // Drop entries no longer wanted by any site.
        let keep: std::collections::HashSet<&str> =
            wanted.iter().map(|(a, _, _)| a.as_str()).collect();
        registry.retain(|k, _| keep.contains(k.as_str()));
    }

    fn client_for_connect_timeout(&self, ct: Duration) -> PooledClient {
        let key = ct.as_secs();
        if let Some(existing) = self.connect_timeout_clients.get(&key) {
            return existing.clone();
        }
        if self.connect_timeout_clients.len() >= MAX_CONNECT_TIMEOUT_CLIENTS {
            warn!(
                requested_connect_timeout_secs = key,
                distinct_clients = self.connect_timeout_clients.len(),
                cap = MAX_CONNECT_TIMEOUT_CLIENTS,
                "too many distinct per-site connect timeouts; using the node default \
                 for this site. Consolidate the configured values."
            );
            return self.client.clone();
        }
        // entry() so two concurrent first-requests for the same value cannot each
        // build a pool and have one of them immediately orphaned.
        self.connect_timeout_clients
            .entry(key)
            .or_insert_with(|| {
                info!(
                    connect_timeout_secs = key,
                    "creating a dedicated upstream connection pool for a per-site connect timeout"
                );
                build_client(ct, Arc::clone(&self.sni_overrides))
            })
            .clone()
    }

    /// Build the pool from the initial config.
    pub fn from_config(cfg: &SentinelConfig) -> Self {
        let connect_timeout = Duration::from_secs(env_secs(
            "SENTINEL_UPSTREAM_CONNECT_TIMEOUT_SECS",
            UPSTREAM_CONNECT_TIMEOUT_SECS,
        ));
        let upstream_timeout = Duration::from_secs(env_secs(
            "SENTINEL_UPSTREAM_TIMEOUT_SECS",
            UPSTREAM_TIMEOUT_SECS,
        ));

        // Built BEFORE the client, because the client's TLS connector captures a
        // handle to it.
        let sni_overrides: Arc<SniRegistry> = Arc::new(DashMap::new());
        Self::refresh_sni_overrides(&sni_overrides, &cfg.sites);

        // The node limit as the proxy resolves it (env over config), so the
        // default share is half of what is really enforced.
        let node_inflight = std::env::var("SENTINEL_MAX_INFLIGHT_REQUESTS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(cfg.limits.max_inflight_requests)
            .max(1);
        let site_inflight_limit = site_inflight_limit(node_inflight);

        let pool = Self {
            sites: DashMap::new(),
            client: build_client(connect_timeout, Arc::clone(&sni_overrides)),
            connect_timeout_clients: DashMap::new(),
            sni_overrides,
            upstream_timeout,
            site_inflight_limit,
        };

        for site in &cfg.sites {
            pool.sites.insert(
                site.id.clone(),
                Arc::new(SiteUpstream::new(
                    site.upstream.servers.clone(),
                    site.upstream.load_balancer.clone(),
                    site_timeout(site.upstream.timeout_secs),
                    site_connect_timeout(site.upstream.connect_timeout_secs),
                    site_inflight_limit,
                )),
            );
        }
        pool
    }

    // -----------------------------------------------------------------------
    // Server selection
    // -----------------------------------------------------------------------

    /// Take the right to send one request for `site_id`: a server, chosen by
    /// the site's strategy and circuit state, and a place in the site's
    /// bulkhead.
    ///
    /// Fails fast, and typed: [`OriginUnavailable`] when every origin's circuit
    /// is open, [`SiteBusy`] when the site already has its limit of requests
    /// waiting on the origin. The gateway answers both 503 with a Retry-After.
    pub fn lease(&self, site_id: &str, client_ip: Option<IpAddr>) -> anyhow::Result<Lease> {
        let site = self
            .sites
            .get(site_id)
            .map(|s| Arc::clone(s.value()))
            .ok_or_else(|| anyhow::anyhow!("no upstream configured for site '{site_id}'"))?;
        let (health, probe) = match site.choose(client_ip, now_ms()) {
            Choice::Server { health, probe } => (health, probe),
            Choice::AllOpen { retry_after } => {
                return Err(anyhow::Error::new(OriginUnavailable { retry_after }));
            }
            Choice::NoServers => {
                return Err(anyhow::anyhow!(
                    "no upstream servers configured for site '{site_id}'"
                ));
            }
        };
        let permit = match Arc::clone(&site.inflight).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if probe {
                    // Never sent: give the probe back for the next request.
                    health.probe_in_flight.store(false, Ordering::Release);
                }
                return Err(anyhow::Error::new(SiteBusy {
                    limit: site.inflight_limit,
                }));
            }
        };
        Ok(Lease::new(
            health,
            probe,
            site.timeout.unwrap_or(self.upstream_timeout),
            site.connect_timeout,
            Some(permit),
        ))
    }

    /// Requests of `site_id` currently waiting on its origin. Tests and
    /// diagnostics.
    pub fn site_inflight(&self, site_id: &str) -> Option<usize> {
        self.sites
            .get(site_id)
            .map(|s| s.inflight_limit - s.inflight.available_permits())
    }

    // -----------------------------------------------------------------------
    // Request forwarding
    // -----------------------------------------------------------------------

    /// Forward a pre-built request straight to the host in its URI, using the
    /// shared keep-alive pool but WITHOUT site selection / load-balancing /
    /// circuit-breaker bookkeeping. Used by the management listener to
    /// reverse-proxy the admin console (dashboard + control-plane API). Streams
    /// both request and response bodies, so Server-Sent Events pass through
    /// unbuffered.
    pub async fn forward(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> anyhow::Result<http::Response<hyper::body::Incoming>> {
        // The hyper error is kept as the source, not flattened into text: the
        // caller fails over to another control-plane node only on a CONNECT
        // failure, and must be able to ask.
        self.client
            .request(req)
            .await
            .map_err(|e| anyhow::Error::new(e).context("management upstream request failed"))
    }

    /// Send a pre-built upstream request under `lease` and return the response.
    ///
    /// The request URI must already point at the lease's server. The outcome is
    /// recorded on that server's circuit: any response — whatever its status —
    /// is a success; a connect, TLS or transport error, or no response headers
    /// within the site's timeout, is a failure.
    pub async fn send(
        &self,
        lease: &mut Lease,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> anyhow::Result<http::Response<hyper::body::Incoming>> {
        // Pick the connection pool. Almost every site uses the shared default; a
        // site with its own connect timeout gets the pool built for that value.
        // Cloning is cheap and shares the pool — hyper's Client is Arc-backed —
        // and avoids holding a DashMap guard across the await below, which would
        // block any concurrent insert for the whole upstream round-trip.
        let client = match lease.connect_timeout {
            None => self.client.clone(),
            Some(ct) => self.client_for_connect_timeout(ct),
        };
        let timeout = lease.timeout;

        debug!(
            upstream = ?format!("{}:{}", lease.server().host, lease.server().port),
            probe = lease.probe,
            "forwarding to upstream (pooled)"
        );

        // Bound time-to-response-headers: a hung origin must not pin this task
        // (and its in-flight admission permit) forever. `client.request()`
        // resolves once headers arrive, so this does NOT cut long downloads or
        // SSE streams. A timeout is a breaker failure.
        let result = match tokio::time::timeout(timeout, client.request(req)).await {
            Ok(r) => r.context("upstream request failed"),
            // Typed, not a formatted string: the gateway answers 504 for this and
            // 502 for everything else, and it must be able to tell them apart
            // without parsing an error message. See `UpstreamTimeout`.
            Err(_) => Err(anyhow::Error::new(UpstreamTimeout(timeout))),
        };
        lease.settle(result.is_ok());
        result
    }

    /// Send to a NAMED server of `site_id`, outside the circuit breaker's
    /// admission (no fast-fail, no bulkhead) but recording the outcome on its
    /// circuit. For callers that already know where the request goes.
    pub async fn send_request(
        &self,
        site_id: &str,
        server_host: &str,
        server_port: u16,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> anyhow::Result<http::Response<hyper::body::Incoming>> {
        let site = self.sites.get(site_id).map(|s| Arc::clone(s.value()));
        let health = site
            .as_ref()
            .and_then(|s| {
                s.servers
                    .iter()
                    .find(|h| h.server.host == server_host && h.server.port == server_port)
                    .cloned()
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{server_host}:{server_port} is not an upstream of site '{site_id}'"
                )
            })?;
        let (timeout, connect_timeout) = match &site {
            Some(s) => (
                s.timeout.unwrap_or(self.upstream_timeout),
                s.connect_timeout,
            ),
            None => (self.upstream_timeout, None),
        };
        let mut lease = Lease::new(health, false, timeout, connect_timeout, None);
        self.send(&mut lease, req).await
    }

    // -----------------------------------------------------------------------
    // Hot-reload — atomic site sync from control plane
    // -----------------------------------------------------------------------

    /// Atomically sync the pool from a new site list received from the control
    /// plane.  Adds / updates entries and removes stale ones.  Health state for
    /// servers that still exist is preserved across the sync.
    pub fn sync_sites(&self, sites: &[sentinel_core::config::SiteConfig]) {
        use std::collections::HashSet;

        // Re-derive SNI overrides on every sync. The registry is shared with every
        // client's connector, so this takes effect without rebuilding any pool.
        Self::refresh_sni_overrides(&self.sni_overrides, sites);

        for site in sites {
            let strategy = site.upstream.load_balancer.clone();
            let timeout = site_timeout(site.upstream.timeout_secs);
            // Must be re-read on every sync, including the carry-over branch
            // below: a hot config change that alters only the connect timeout has
            // to take effect, and reconstructing SiteUpstream field-by-field is
            // exactly where a new field gets forgotten and silently reverts to
            // the node default.
            let connect_timeout = site_connect_timeout(site.upstream.connect_timeout_secs);
            let new_upstream = if let Some(existing) = self.sites.get(&site.id) {
                // Preserve health state for servers that carry over.
                let new_servers: Vec<Arc<ServerHealth>> = site
                    .upstream
                    .servers
                    .iter()
                    .map(|new_srv| {
                        if let Some(old_h) = existing.servers.iter().find(|old| {
                            old.server.host == new_srv.host && old.server.port == new_srv.port
                        }) {
                            Arc::clone(old_h)
                        } else {
                            Arc::new(ServerHealth::new(new_srv.clone()))
                        }
                    })
                    .collect();

                Arc::new(SiteUpstream {
                    servers: new_servers,
                    cursor: AtomicUsize::new(existing.cursor.load(Ordering::Relaxed)),
                    strategy,
                    timeout,
                    connect_timeout,
                    inflight: Arc::clone(&existing.inflight),
                    inflight_limit: existing.inflight_limit,
                })
            } else {
                Arc::new(SiteUpstream::new(
                    site.upstream.servers.clone(),
                    strategy,
                    timeout,
                    connect_timeout,
                    self.site_inflight_limit,
                ))
            };

            self.sites.insert(site.id.clone(), new_upstream);
        }

        let live: HashSet<&str> = sites.iter().map(|s| s.id.as_str()).collect();
        self.sites.retain(|id, _| live.contains(id.as_str()));
    }

    // -----------------------------------------------------------------------
    // Background health checks
    // -----------------------------------------------------------------------

    /// Spawn active health-check tasks for every site that has a
    /// `health_check` block in its upstream config.
    ///
    /// Each task sends `GET <health_check.path>` to every server on the
    /// configured interval.  Any non-5xx response marks the server healthy;
    /// timeouts or 5xx responses increment the failure counter and may open
    /// the circuit breaker.
    ///
    /// All tasks honour the `shutdown` watch channel and stop cleanly.
    pub fn spawn_health_checks(
        pool: Arc<Self>,
        cfg: &SentinelConfig,
        shutdown: watch::Receiver<bool>,
    ) {
        for site in &cfg.sites {
            let Some(ref hc_cfg) = site.upstream.health_check else {
                continue;
            };

            let path = hc_cfg.path.clone();
            let interval_secs = parse_duration_secs(&hc_cfg.interval).unwrap_or(10);
            let timeout_secs = parse_duration_secs(&hc_cfg.timeout).unwrap_or(2);
            let pool2 = Arc::clone(&pool);
            let site_id = site.id.clone();
            let sd = shutdown.clone();

            // Supervised: a panic restarts the probe loop. Unsupervised, the
            // site's servers kept whatever health they last had for good — a
            // dead origin stayed "healthy", a recovered one stayed out.
            crate::panic_guard::supervised!("upstream health check", {
                per_run!(path, pool2, site_id, sd);
                let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let Some(site_up) = pool2.sites.get(&site_id) else { continue };
                            let servers: Vec<Arc<ServerHealth>> = site_up.servers.to_vec();
                            drop(site_up); // release DashMap read guard

                            for srv in servers {
                                let scheme = if srv.server.tls { "https" } else { "http" };
                                let url = format!(
                                    "{}://{}:{}{}",
                                    scheme, srv.server.host, srv.server.port, path
                                );
                                let req = match Request::builder()
                                    .method("GET")
                                    .uri(&url)
                                    .header("User-Agent", "sentinel-healthcheck/1.0")
                                    .body(
                                        http_body_util::Empty::<Bytes>::new()
                                            .map_err(|n: std::convert::Infallible| match n {})
                                            .boxed(),
                                    ) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        warn!(url = %url, "health-check: bad request: {e}");
                                        continue;
                                    }
                                };

                                let result = tokio::time::timeout(
                                    Duration::from_secs(timeout_secs),
                                    pool2.client.request(req),
                                )
                                .await;

                                match result {
                                    Ok(Ok(resp))
                                        if resp.status().as_u16() < 500 =>
                                    {
                                        // Closes an open circuit at once: the
                                        // check is a probe that costs no visitor
                                        // a 503.
                                        srv.record_success();
                                    }
                                    Ok(Ok(resp)) => {
                                        srv.record_failure(false);
                                        debug!(
                                            host = %srv.server.host,
                                            port = srv.server.port,
                                            status = resp.status().as_u16(),
                                            "health check failed (5xx)"
                                        );
                                    }
                                    Ok(Err(e)) => {
                                        srv.record_failure(false);
                                        debug!(
                                            host = %srv.server.host,
                                            port = srv.server.port,
                                            "health check error: {e}"
                                        );
                                    }
                                    Err(_elapsed) => {
                                        srv.record_failure(false);
                                        debug!(
                                            host = %srv.server.host,
                                            port = srv.server.port,
                                            "health check timed out"
                                        );
                                    }
                                }
                            }
                        }
                        _ = sd.changed() => {
                            debug!(site = %site_id, "health-check task shutting down");
                            break;
                        }
                    }
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse duration strings like `"10s"`, `"2m"`, `"30"` (bare seconds).
pub(crate) fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse().ok()
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>().ok().map(|m| m * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>().ok().map(|h| h * 3600)
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// `timeout_secs` is an OVERRIDE, not an on/off switch. Absent or zero must
    /// fall back to the deployment default — never to "wait forever", which
    /// would let a hung origin pin a request task and its admission permit.
    #[test]
    fn absent_or_zero_timeout_means_use_the_default() {
        assert_eq!(site_timeout(None), None);
        assert_eq!(site_timeout(Some(0)), None);
    }

    #[test]
    fn positive_timeout_overrides_the_default() {
        assert_eq!(site_timeout(Some(1)), Some(Duration::from_secs(1)));
        assert_eq!(site_timeout(Some(180)), Some(Duration::from_secs(180)));
    }

    /// A site that sets no override resolves to the pool-wide timeout, and a
    /// site that sets one resolves to its own — the resolution `send_request`
    /// performs per request.
    #[test]
    fn resolution_prefers_the_site_value() {
        let default = Duration::from_secs(30);
        let slow = SiteUpstream::new(
            vec![],
            LoadBalancerStrategy::RoundRobin,
            site_timeout(Some(180)),
            None,
            8,
        );
        let plain = SiteUpstream::new(
            vec![],
            LoadBalancerStrategy::RoundRobin,
            site_timeout(None),
            None,
            8,
        );

        assert_eq!(slow.timeout.unwrap_or(default), Duration::from_secs(180));
        assert_eq!(plain.timeout.unwrap_or(default), default);
    }

    /// Connect timeout resolution, including the clamp. Absent or zero must mean
    /// "use the node default" rather than "connect with no bound".
    #[test]
    fn connect_timeout_absent_or_zero_means_use_the_default() {
        assert_eq!(site_connect_timeout(None), None);
        assert_eq!(site_connect_timeout(Some(0)), None);
    }

    #[test]
    fn connect_timeout_is_clamped_at_both_ends() {
        assert_eq!(site_connect_timeout(Some(5)), Some(Duration::from_secs(5)));
        // Above the ceiling clamps down rather than being honoured: a multi-minute
        // connect timeout defeats the point of having one.
        assert_eq!(
            site_connect_timeout(Some(9_999)),
            Some(Duration::from_secs(MAX_SITE_CONNECT_TIMEOUT_SECS))
        );
    }

    /// The per-value client map must hand back the SAME pool for a repeated
    /// value — a fresh pool per request would defeat keep-alive entirely.
    #[test]
    fn connect_timeout_clients_are_reused_and_capped() {
        let sni_overrides: Arc<SniRegistry> = Arc::new(DashMap::new());
        let pool = UpstreamPool {
            sites: DashMap::new(),
            client: build_client(Duration::from_secs(10), Arc::clone(&sni_overrides)),
            connect_timeout_clients: DashMap::new(),
            sni_overrides,
            upstream_timeout: Duration::from_secs(30),
            site_inflight_limit: 8,
        };

        let _ = pool.client_for_connect_timeout(Duration::from_secs(3));
        let _ = pool.client_for_connect_timeout(Duration::from_secs(3));
        assert_eq!(
            pool.connect_timeout_clients.len(),
            1,
            "the same connect timeout must reuse one pool, not build another"
        );

        // Past the cap, extra values fall back to the default client instead of
        // creating an unbounded number of connection pools.
        for s in 4..(4 + MAX_CONNECT_TIMEOUT_CLIENTS as u64 + 5) {
            let _ = pool.client_for_connect_timeout(Duration::from_secs(s));
        }
        assert_eq!(
            pool.connect_timeout_clients.len(),
            MAX_CONNECT_TIMEOUT_CLIENTS,
            "distinct connect-timeout pools must be capped"
        );
    }
}

#[cfg(test)]
mod sni_tests {
    use super::*;
    use sentinel_core::config::{SiteConfig, UpstreamConfig, WafConfig};

    fn uri(s: &str) -> http::Uri {
        s.parse().unwrap()
    }

    fn site_with(id: &str, sni: Option<&str>, host: &str, port: u16, tls: bool) -> SiteConfig {
        SiteConfig {
            id: id.into(),
            tenant_id: String::new(),
            domains: vec![format!("{id}.local")],
            upstream: UpstreamConfig {
                load_balancer: LoadBalancerStrategy::RoundRobin,
                servers: vec![UpstreamServer {
                    host: host.into(),
                    port,
                    weight: 1,
                    tls,
                }],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: sni.map(str::to_string),
            },
            waf: WafConfig::default(),
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    /// With no override the resolver must behave exactly like hyper-rustls's
    /// default, or enabling this feature would change TLS for every existing site.
    #[test]
    fn without_an_override_the_uri_host_is_used() {
        let reg: SniRegistry = DashMap::new();
        let got = resolve_sni(&reg, &uri("https://origin.example.com:443/x")).unwrap();
        assert_eq!(
            got,
            rustls::pki_types::ServerName::try_from("origin.example.com".to_string()).unwrap()
        );
    }

    /// The case the feature exists for: origin addressed by bare IP. TLS forbids
    /// an IP literal as a server name, so without an override rustls sends no SNI
    /// and an SNI-vhosting origin answers with the wrong certificate.
    #[test]
    fn an_override_replaces_the_name_for_an_ip_addressed_origin() {
        let reg: SniRegistry = DashMap::new();
        reg.insert(
            "10.0.0.5:443".to_string(),
            rustls::pki_types::ServerName::try_from("app.internal".to_string()).unwrap(),
        );

        let overridden = resolve_sni(&reg, &uri("https://10.0.0.5:443/x")).unwrap();
        assert_eq!(
            overridden,
            rustls::pki_types::ServerName::try_from("app.internal".to_string()).unwrap()
        );

        // Without the override the same URI yields the IP form, which is what
        // makes such an origin unusable — this pins the difference.
        let bare = resolve_sni(&DashMap::new(), &uri("https://10.0.0.5:443/x")).unwrap();
        assert_ne!(bare, overridden);
    }

    /// Keyed by authority, so the override must not leak to a different port or
    /// host that happens to share part of the key.
    #[test]
    fn an_override_is_scoped_to_its_exact_authority() {
        let reg: SniRegistry = DashMap::new();
        reg.insert(
            "10.0.0.5:443".to_string(),
            rustls::pki_types::ServerName::try_from("app.internal".to_string()).unwrap(),
        );
        let other_port = resolve_sni(&reg, &uri("https://10.0.0.5:8443/x")).unwrap();
        assert_eq!(
            other_port,
            rustls::pki_types::ServerName::try_from("10.0.0.5".to_string()).unwrap(),
            "an override for :443 must not apply to :8443"
        );
    }

    /// IPv6 literals arrive bracketed in a URI; the fallback must strip them the
    /// way hyper-rustls's default does.
    #[test]
    fn ipv6_brackets_are_stripped_in_the_fallback() {
        let reg: SniRegistry = DashMap::new();
        let got = resolve_sni(&reg, &uri("https://[::1]:443/x")).unwrap();
        assert_eq!(
            got,
            rustls::pki_types::ServerName::try_from("::1".to_string()).unwrap()
        );
    }

    #[test]
    fn registry_is_built_from_site_config() {
        let reg: SniRegistry = DashMap::new();
        let sites = vec![site_with("a", Some("app.internal"), "10.0.0.5", 443, true)];
        UpstreamPool::refresh_sni_overrides(&reg, &sites);
        assert_eq!(reg.len(), 1);
        assert!(reg.contains_key("10.0.0.5:443"));
    }

    /// A plaintext server has no handshake to carry a name, so registering one
    /// would be inert. Skipped, not silently accepted.
    #[test]
    fn plaintext_servers_are_skipped() {
        let reg: SniRegistry = DashMap::new();
        let sites = vec![site_with("a", Some("app.internal"), "10.0.0.5", 80, false)];
        UpstreamPool::refresh_sni_overrides(&reg, &sites);
        assert!(
            reg.is_empty(),
            "sni_name on a tls:false server must not be registered"
        );
    }

    /// Removing sni_name from a config must actually remove the override. A
    /// registry that only ever grew would mean the setting could be turned on but
    /// never off until restart — the silently-inert shape this work is about.
    #[test]
    fn removing_the_setting_removes_the_override() {
        let reg: SniRegistry = DashMap::new();
        UpstreamPool::refresh_sni_overrides(
            &reg,
            &[site_with("a", Some("app.internal"), "10.0.0.5", 443, true)],
        );
        assert_eq!(reg.len(), 1);

        UpstreamPool::refresh_sni_overrides(&reg, &[site_with("a", None, "10.0.0.5", 443, true)]);
        assert!(
            reg.is_empty(),
            "clearing sni_name must drop the override, not leave it live until restart"
        );
    }

    /// An unparseable name must fall back to the upstream host rather than
    /// poisoning the registry or failing the connection.
    #[test]
    fn an_invalid_name_is_rejected_not_registered() {
        let reg: SniRegistry = DashMap::new();
        UpstreamPool::refresh_sni_overrides(
            &reg,
            &[site_with(
                "a",
                Some("not a valid dns name"),
                "10.0.0.5",
                443,
                true,
            )],
        );
        assert!(reg.is_empty(), "an invalid sni_name must not be registered");
    }
}

#[cfg(test)]
mod upstream_protocol_tests {
    /// The origin hop must stay HTTP/1.1.
    ///
    /// Re-enabling h2 here sends `:authority` = the upstream ADDRESS alongside a
    /// `Host` header carrying the client's NAME. RFC 9113 §8.3.1 makes that
    /// mismatch malformed, and an h2-capable origin answers every proxied request
    /// with a generic 400 — which is exactly how this was found, on an APISIX
    /// gateway where curl got 301 and everything through the WAF got 400.
    ///
    /// Source-level because the alternative is an h2 origin in the test rig, and
    /// this is the line that must not change without the URI/Host rework the
    /// comment beside it describes.
    #[test]
    fn origin_connections_do_not_offer_http2() {
        let src = include_str!("upstream.rs");
        // Assembled at compile time so the needle never exists as literal text in
        // this file — a guard that matches its own source reports the correct
        // code as broken, which is how several checks in this repo first failed.
        let needle = concat!(".enable_", "http2", "()");
        let builder_uses_h2 = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .any(|l| l.contains(needle));
        assert!(
            !builder_uses_h2,
            "the upstream connector offers h2 again: over h2 the forwarded \
             :authority (upstream address) and Host (client name) disagree, which \
             RFC 9113 makes malformed and origins answer with 400"
        );
        assert!(
            src.contains(".enable_http1()"),
            "the upstream connector must still enable HTTP/1.1"
        );
    }
}

#[cfg(test)]
mod upstream_ca_tests {
    use super::*;

    /// `SENTINEL_UPSTREAM_CA_FILE` is process-wide, so these tests must not run
    /// concurrently with each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_ca_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("SENTINEL_UPSTREAM_CA_FILE").ok();
        match value {
            Some(v) => std::env::set_var("SENTINEL_UPSTREAM_CA_FILE", v),
            None => std::env::remove_var("SENTINEL_UPSTREAM_CA_FILE"),
        }
        let out = f();
        match prev {
            Some(p) => std::env::set_var("SENTINEL_UPSTREAM_CA_FILE", p),
            None => std::env::remove_var("SENTINEL_UPSTREAM_CA_FILE"),
        }
        out
    }

    fn tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sentinel-upstream-ca-{}-{name}",
            std::process::id()
        ));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// A genuine CA (basicConstraints CA:TRUE), so `RootCertStore::add` accepts
    /// it as a trust anchor. A self-signed leaf may be rejected, which would make
    /// the additive assertion below vacuous.
    fn real_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::new(vec!["sentinel-test-ca".to_string()]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        rcgen::Certificate::from_params(params)
            .unwrap()
            .serialize_pem()
            .unwrap()
    }

    fn public_root_count() -> usize {
        let mut r = rustls::RootCertStore::empty();
        r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        r.len()
    }

    #[test]
    fn unset_and_empty_both_mean_no_private_ca() {
        with_ca_env(None, || assert_eq!(upstream_ca_certs().unwrap().len(), 0));
        with_ca_env(Some(""), || {
            assert_eq!(upstream_ca_certs().unwrap().len(), 0)
        });
        with_ca_env(Some("   "), || {
            assert_eq!(upstream_ca_certs().unwrap().len(), 0)
        });
    }

    #[test]
    fn a_missing_ca_file_is_an_error_not_a_silent_success() {
        with_ca_env(Some("/nonexistent/sentinel/origin-ca.pem"), || {
            assert!(upstream_ca_certs().is_err(), "a bad path must be reported");
        });
    }

    #[test]
    fn a_file_with_no_certificates_is_an_error() {
        let p = tmp("empty.pem", b"this is not a certificate\n");
        with_ca_env(Some(p.to_str().unwrap()), || {
            let e = upstream_ca_certs().unwrap_err();
            assert!(e.contains("no CERTIFICATE"), "unexpected error: {e}");
        });
        let _ = std::fs::remove_file(&p);
    }

    /// THE SEMANTIC THAT MATTERS. Unlike the ClickHouse and SIEM loaders — which
    /// talk to one peer and REPLACE the public roots — a WAF fronts many origins,
    /// and a deployment can mix internal-CA and public-CA backends. Configuring
    /// an internal CA must ADD an anchor, never swap the set, or every public-CA
    /// origin that was working would break the moment one internal CA is added.
    #[test]
    fn a_private_ca_is_added_to_the_public_roots_not_substituted_for_them() {
        let pem = real_ca_pem();
        let p = tmp("ca.pem", pem.as_bytes());
        let public = public_root_count();
        assert!(public > 100, "expected the webpki bundle, got {public}");

        with_ca_env(Some(p.to_str().unwrap()), || {
            let certs = upstream_ca_certs().expect("a real CA PEM must parse");
            assert_eq!(certs.len(), 1);

            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots.add(certs.into_iter().next().unwrap()).unwrap();
            assert_eq!(
                roots.len(),
                public + 1,
                "the private CA must be an ADDITIONAL anchor; replacing the public \
                 roots would break every public-CA origin already working"
            );
        });
        let _ = std::fs::remove_file(&p);
    }

    /// The fail-SAFE contract, and the one place this deliberately differs from
    /// the ClickHouse loader. There, a broken CA file empties the root store so
    /// TLS fails loudly, because trust would otherwise WIDEN back to the public
    /// roots. Here the public roots are the baseline, so failing to load the
    /// extra CA widens nothing — it fails to widen. Emptying the store instead
    /// would take every HTTPS origin on the node down over a typo in an env var.
    #[test]
    fn a_broken_ca_file_leaves_the_public_roots_intact() {
        let public = public_root_count();
        with_ca_env(Some("/nonexistent/sentinel/origin-ca.pem"), || {
            assert_eq!(
                upstream_roots().len(),
                public,
                "a broken CA path must leave trust exactly where it was — neither \
                 widened, nor emptied into a node-wide origin outage"
            );
        });
    }

    #[test]
    fn a_configured_ca_reaches_the_tls_config_the_connector_uses() {
        let pem = real_ca_pem();
        let p = tmp("wired.pem", pem.as_bytes());
        let public = public_root_count();
        with_ca_env(Some(p.to_str().unwrap()), || {
            // Guards the wiring, not just the loader: build_client calls this.
            assert_eq!(upstream_roots().len(), public + 1);
        });
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod circuit_tests {
    //! The breaker is driven with explicit clock values (`circuit_at`,
    //! `record_failure_at`, `choose(_, now)`) so nothing here sleeps.
    use super::*;

    fn srv(port: u16) -> UpstreamServer {
        UpstreamServer {
            host: "10.0.0.5".into(),
            port,
            weight: 1,
            tls: false,
        }
    }

    fn site(ports: &[u16], limit: usize) -> SiteUpstream {
        SiteUpstream::new(
            ports.iter().map(|&p| srv(p)).collect(),
            LoadBalancerStrategy::RoundRobin,
            None,
            None,
            limit,
        )
    }

    fn trip(h: &ServerHealth, now: u64) {
        for _ in 0..CIRCUIT_OPEN_THRESHOLD {
            h.record_failure_at(false, now);
        }
    }

    fn chosen(c: Choice) -> (u16, bool) {
        match c {
            Choice::Server { health, probe } => (health.server.port, probe),
            Choice::AllOpen { retry_after } => panic!("all open, retry {retry_after:?}"),
            Choice::NoServers => panic!("no servers"),
        }
    }

    #[test]
    fn a_dead_single_origin_fails_fast_instead_of_being_retried() {
        let s = site(&[8080], 8);
        let t0 = 1_000_000;
        trip(&s.servers[0], t0);
        // The old code force-reset the circuit here and sent the request
        // anyway — the breaker could never shed for a one-origin site.
        match s.choose(None, t0 + 1) {
            Choice::AllOpen { retry_after } => {
                assert!(retry_after <= Duration::from_millis(CIRCUIT_OPEN_BASE_MS));
                assert!(retry_after > Duration::ZERO);
            }
            _ => panic!("an open circuit on the only origin must fail fast"),
        }
        assert_eq!(
            s.servers[0].consecutive_failures.load(Ordering::Relaxed),
            CIRCUIT_OPEN_THRESHOLD,
            "choosing must not reset the evidence"
        );
    }

    #[test]
    fn half_open_admits_exactly_one_probe() {
        let s = site(&[8080], 8);
        let t0 = 1_000_000;
        trip(&s.servers[0], t0);
        let later = t0 + CIRCUIT_OPEN_BASE_MS;
        assert_eq!(chosen(s.choose(None, later)), (8080, true));
        // While the probe is out, everyone else still fails fast.
        for _ in 0..3 {
            assert!(matches!(s.choose(None, later), Choice::AllOpen { .. }));
        }
    }

    #[test]
    fn a_successful_probe_closes_the_circuit() {
        let s = site(&[8080], 8);
        let t0 = 1_000_000;
        trip(&s.servers[0], t0);
        let Choice::Server { health, probe } = s.choose(None, t0 + CIRCUIT_OPEN_BASE_MS) else {
            panic!("no probe")
        };
        let mut lease = Lease::new(health, probe, Duration::from_secs(1), None, None);
        lease.settle(true);
        drop(lease);
        assert_eq!(
            s.servers[0].circuit_at(t0 + CIRCUIT_OPEN_BASE_MS),
            Circuit::Closed
        );
        assert_eq!(
            chosen(s.choose(None, t0 + CIRCUIT_OPEN_BASE_MS)),
            (8080, false)
        );
    }

    #[test]
    fn a_failed_probe_backs_off_to_the_ceiling() {
        let h = ServerHealth::new(srv(8080));
        let mut now = 1_000_000;
        trip(&h, now);
        let mut waits = vec![];
        for _ in 0..6 {
            let Circuit::Open { retry_in_ms } = h.circuit_at(now) else {
                panic!("not open")
            };
            waits.push(retry_in_ms);
            now += retry_in_ms;
            assert_eq!(h.circuit_at(now), Circuit::HalfOpen);
            assert!(h.try_claim_probe());
            h.record_failure_at(true, now);
            h.probe_in_flight.store(false, Ordering::Release);
        }
        assert_eq!(waits, vec![5_000, 10_000, 20_000, 30_000, 30_000, 30_000]);
    }

    #[test]
    fn a_probe_whose_client_left_frees_the_probe() {
        let s = site(&[8080], 8);
        let t0 = 1_000_000;
        trip(&s.servers[0], t0);
        let later = t0 + CIRCUIT_OPEN_BASE_MS;
        let Choice::Server { health, probe } = s.choose(None, later) else {
            panic!("no probe")
        };
        let lease = Lease::new(health, probe, Duration::from_secs(1), None, None);
        // The request future is dropped mid-send: no outcome recorded.
        drop(lease);
        // Without the Drop the flag stayed set and the site 503'd for good.
        assert_eq!(chosen(s.choose(None, later)), (8080, true));
        assert_eq!(s.servers[0].active_conns.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_recovered_server_is_probed_even_while_others_are_healthy() {
        let s = site(&[8080, 8081], 8);
        let t0 = 1_000_000;
        trip(&s.servers[0], t0);
        // Open: only the healthy one is chosen.
        for _ in 0..4 {
            assert_eq!(chosen(s.choose(None, t0 + 1)), (8081, false));
        }
        // Half-open: the next request probes it, the rest go to the healthy one.
        let later = t0 + CIRCUIT_OPEN_BASE_MS;
        assert_eq!(chosen(s.choose(None, later)), (8080, true));
        assert_eq!(chosen(s.choose(None, later)), (8081, false));
    }

    #[test]
    fn late_failures_from_before_the_trip_do_not_extend_the_backoff() {
        let h = ServerHealth::new(srv(8080));
        let t0 = 1_000_000;
        trip(&h, t0);
        // Requests sent while the circuit was still closed, failing late.
        for _ in 0..20 {
            h.record_failure_at(false, t0 + 4_000);
        }
        assert_eq!(h.circuit_at(t0 + CIRCUIT_OPEN_BASE_MS), Circuit::HalfOpen);
        assert_eq!(h.open_for_ms.load(Ordering::Relaxed), CIRCUIT_OPEN_BASE_MS);
    }

    #[test]
    fn success_resets_the_backoff() {
        let h = ServerHealth::new(srv(8080));
        let t0 = 1_000_000;
        trip(&h, t0);
        h.record_failure_at(true, t0 + 5_000);
        assert_eq!(h.open_for_ms.load(Ordering::Relaxed), 10_000);
        h.record_success();
        assert_eq!(h.open_for_ms.load(Ordering::Relaxed), CIRCUIT_OPEN_BASE_MS);
        assert_eq!(h.circuit_at(t0 + 6_000), Circuit::Closed);
    }

    fn site_cfg() -> sentinel_core::config::SiteConfig {
        use sentinel_core::config::{SiteConfig, UpstreamConfig, WafConfig};
        SiteConfig {
            id: "s".into(),
            tenant_id: String::new(),
            domains: vec!["s.local".into()],
            upstream: UpstreamConfig {
                load_balancer: LoadBalancerStrategy::RoundRobin,
                servers: vec![srv(8080)],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: WafConfig::default(),
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    fn pool_with(limit: usize) -> UpstreamPool {
        let cfg = SentinelConfig {
            sites: vec![site_cfg()],
            ..Default::default()
        };
        let mut pool = UpstreamPool::from_config(&cfg);
        pool.site_inflight_limit = limit;
        // Rebuild the site with the test's limit.
        pool.sites.clear();
        pool.sync_sites(&cfg.sites);
        pool
    }

    #[test]
    fn the_site_bulkhead_sheds_past_its_limit_and_refills() {
        let pool = pool_with(2);
        let a = pool.lease("s", None).expect("first");
        let b = pool.lease("s", None).expect("second");
        assert_eq!(pool.site_inflight("s"), Some(2));
        let err = pool.lease("s", None).expect_err("third must be shed");
        assert!(err.chain().any(|c| c.is::<SiteBusy>()), "{err:#}");
        drop(a);
        let _c = pool.lease("s", None).expect("a permit came back");
        drop(b);
        assert_eq!(pool.site_inflight("s"), Some(1));
    }

    #[test]
    fn a_config_sync_keeps_the_sites_bulkhead() {
        let pool = pool_with(1);
        let held = pool.lease("s", None).expect("lease");
        pool.sync_sites(&[site_cfg()]);
        // A fresh semaphore here would have doubled the site's allowance.
        assert!(pool.lease("s", None).is_err());
        drop(held);
        assert!(pool.lease("s", None).is_ok());
    }

    #[test]
    fn a_shed_probe_is_given_back() {
        let pool = pool_with(1);
        let h = Arc::clone(&pool.sites.get("s").unwrap().servers[0]);
        let _held = Lease::new(
            Arc::clone(&h),
            false,
            Duration::from_secs(1),
            None,
            Some(
                Arc::clone(&pool.sites.get("s").unwrap().inflight)
                    .try_acquire_owned()
                    .unwrap(),
            ),
        );
        // Trip it with a zero-length window so it is half-open now, whatever
        // the process clock reads (it starts at 0 when the process does).
        trip(&h, 0);
        h.open_for_ms.store(0, Ordering::Relaxed);
        let err = pool.lease("s", None).expect_err("bulkhead full");
        assert!(err.chain().any(|c| c.is::<SiteBusy>()));
        assert!(
            !h.probe_in_flight.load(Ordering::Relaxed),
            "a probe that was never sent must not hold the half-open slot"
        );
    }

    #[test]
    fn default_site_limit_is_half_the_node() {
        std::env::remove_var("SENTINEL_SITE_MAX_INFLIGHT_REQUESTS");
        assert_eq!(site_inflight_limit(8192), 4096);
        assert_eq!(site_inflight_limit(1), 1);
    }
}
