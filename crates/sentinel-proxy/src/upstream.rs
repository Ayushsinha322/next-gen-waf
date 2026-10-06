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
//! [`CIRCUIT_OPEN_THRESHOLD`] consecutive failures the circuit is opened and the
//! server is excluded from selection for [`CIRCUIT_HALF_OPEN_SECS`] seconds.
//! After that window the circuit transitions to half-open: the next request is
//! allowed through; a success closes the circuit, a failure re-opens it.
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Circuit-breaker tunables
// ---------------------------------------------------------------------------

/// Number of consecutive upstream failures before a server's circuit opens.
const CIRCUIT_OPEN_THRESHOLD: usize = 5;

/// Seconds an open circuit waits before allowing a single half-open probe.
const CIRCUIT_HALF_OPEN_SECS: u64 = 30;

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

/// All runtime tracking for a single upstream server.
struct ServerHealth {
    server: UpstreamServer,

    /// `true` = server considers itself healthy (gates selection).
    healthy: AtomicBool,

    /// Number of requests currently being sent to this server (LeastConn).
    active_conns: AtomicUsize,

    /// How many upstream errors have occurred in a row.
    consecutive_failures: AtomicUsize,

    /// UNIX timestamp (seconds) when the circuit was last opened.
    circuit_opened_at: AtomicUsize,
}

impl ServerHealth {
    fn new(server: UpstreamServer) -> Self {
        Self {
            server,
            healthy: AtomicBool::new(true),
            active_conns: AtomicUsize::new(0),
            consecutive_failures: AtomicUsize::new(0),
            circuit_opened_at: AtomicUsize::new(0),
        }
    }

    /// Return `true` if this server may receive traffic right now.
    fn is_available(&self) -> bool {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        if failures < CIRCUIT_OPEN_THRESHOLD {
            return true;
        }
        // Circuit open — check half-open window.
        let opened_at = self.circuit_opened_at.load(Ordering::Relaxed) as u64;
        let now = unix_now_secs();
        if now >= opened_at + CIRCUIT_HALF_OPEN_SECS {
            // Reset failures so the next request is a half-open probe.
            self.consecutive_failures.store(0, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= CIRCUIT_OPEN_THRESHOLD {
            self.healthy.store(false, Ordering::Relaxed);
            self.circuit_opened_at
                .store(unix_now_secs() as usize, Ordering::Relaxed);
            warn!(
                host = %self.server.host,
                port = self.server.port,
                failures,
                "upstream circuit breaker opened"
            );
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

impl SiteUpstream {
    fn new(
        servers: Vec<UpstreamServer>,
        strategy: LoadBalancerStrategy,
        timeout: Option<Duration>,
        connect_timeout: Option<Duration>,
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
        }
    }

    /// Select a server according to the configured strategy.
    ///
    /// Only considers servers where `is_available()` returns `true`.  If all
    /// servers have open circuits, force-resets them all and falls back to the
    /// first server so traffic is never silently dropped.
    fn select(&self, client_ip: Option<IpAddr>) -> Option<Arc<ServerHealth>> {
        let available: Vec<Arc<ServerHealth>> = self
            .servers
            .iter()
            .filter(|s| s.is_available())
            .cloned()
            .collect();

        let pool = if available.is_empty() {
            if self.servers.is_empty() {
                return None;
            }
            warn!("all upstream servers have open circuits; forcing reset");
            for s in &self.servers {
                s.consecutive_failures.store(0, Ordering::Relaxed);
                s.healthy.store(true, Ordering::Relaxed);
            }
            self.servers.clone()
        } else {
            available
        };

        match self.strategy {
            LoadBalancerStrategy::RoundRobin | LoadBalancerStrategy::Adaptive => {
                let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % pool.len();
                Some(Arc::clone(&pool[idx]))
            }
            LoadBalancerStrategy::LeastConn => pool
                .iter()
                .min_by_key(|s| s.active_conns.load(Ordering::Relaxed))
                .cloned(),
            LoadBalancerStrategy::IpHash => {
                let hash = if let Some(ip) = client_ip {
                    let mut h = DefaultHasher::new();
                    ip.hash(&mut h);
                    h.finish() as usize
                } else {
                    self.cursor.fetch_add(1, Ordering::Relaxed)
                };
                Some(Arc::clone(&pool[hash % pool.len()]))
            }
            LoadBalancerStrategy::Random => {
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as usize;
                Some(Arc::clone(&pool[seed % pool.len()]))
            }
        }
    }
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

        let pool = Self {
            sites: DashMap::new(),
            client: build_client(connect_timeout, Arc::clone(&sni_overrides)),
            connect_timeout_clients: DashMap::new(),
            sni_overrides,
            upstream_timeout,
        };

        for site in &cfg.sites {
            pool.sites.insert(
                site.id.clone(),
                Arc::new(SiteUpstream::new(
                    site.upstream.servers.clone(),
                    site.upstream.load_balancer.clone(),
                    site_timeout(site.upstream.timeout_secs),
                    site_connect_timeout(site.upstream.connect_timeout_secs),
                )),
            );
        }
        pool
    }

    // -----------------------------------------------------------------------
    // Server selection
    // -----------------------------------------------------------------------

    /// Select the next server for `site_id` using round-robin.
    pub fn next_server(&self, site_id: &str) -> Option<UpstreamServer> {
        self.select_server(site_id, None)
    }

    /// Select a server using the configured LB strategy and an optional client
    /// IP (used for IpHash session affinity).
    pub fn select_server(
        &self,
        site_id: &str,
        client_ip: Option<IpAddr>,
    ) -> Option<UpstreamServer> {
        self.sites
            .get(site_id)?
            .select(client_ip)
            .map(|h| h.server.clone())
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
        self.client
            .request(req)
            .await
            .map_err(|e| anyhow::anyhow!("management upstream request failed: {e}"))
    }

    /// Send a pre-built upstream request and return the response.
    ///
    /// The request URI must already point at the upstream server.  Connection
    /// pooling is handled by the pooled client; the correct pool entry is
    /// selected by the `Host` / authority in the URI.
    ///
    /// Per-server circuit-breaker state is updated: success resets the failure
    /// counter, failure increments it and may open the circuit.
    pub async fn send_request(
        &self,
        site_id: &str,
        server_host: &str,
        server_port: u16,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> anyhow::Result<http::Response<hyper::body::Incoming>> {
        // Locate the ServerHealth for this specific server so we can track
        // active connections and circuit-breaker state, and pick up the site's
        // timeout override in the same lookup.
        let (srv_health, timeout, connect_timeout): (
            Option<Arc<ServerHealth>>,
            Duration,
            Option<Duration>,
        ) = match self.sites.get(site_id) {
            Some(site) => (
                site.servers
                    .iter()
                    .find(|h| h.server.host == server_host && h.server.port == server_port)
                    .cloned(),
                site.timeout.unwrap_or(self.upstream_timeout),
                site.connect_timeout,
            ),
            None => (None, self.upstream_timeout, None),
        };

        // Pick the connection pool. Almost every site uses the shared default; a
        // site with its own connect timeout gets the pool built for that value.
        // Cloning is cheap and shares the pool — hyper's Client is Arc-backed —
        // and avoids holding a DashMap guard across the await below, which would
        // block any concurrent insert for the whole upstream round-trip.
        let client = match connect_timeout {
            None => self.client.clone(),
            Some(ct) => self.client_for_connect_timeout(ct),
        };

        if let Some(ref h) = srv_health {
            h.active_conns.fetch_add(1, Ordering::Relaxed);
        }

        debug!(
            upstream = ?format!("{}:{}", server_host, server_port),
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

        if let Some(ref h) = srv_health {
            h.active_conns.fetch_sub(1, Ordering::Relaxed);
            match &result {
                Ok(_) => h.record_success(),
                Err(_) => h.record_failure(),
            }
        }

        result
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
                })
            } else {
                Arc::new(SiteUpstream::new(
                    site.upstream.servers.clone(),
                    strategy,
                    timeout,
                    connect_timeout,
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
                                        let was_down = !srv.healthy.swap(true, Ordering::Relaxed);
                                        srv.consecutive_failures.store(0, Ordering::Relaxed);
                                        if was_down {
                                            info!(
                                                host = %srv.server.host,
                                                port = srv.server.port,
                                                "upstream server recovered"
                                            );
                                        }
                                    }
                                    Ok(Ok(resp)) => {
                                        srv.record_failure();
                                        debug!(
                                            host = %srv.server.host,
                                            port = srv.server.port,
                                            status = resp.status().as_u16(),
                                            "health check failed (5xx)"
                                        );
                                    }
                                    Ok(Err(e)) => {
                                        srv.record_failure();
                                        debug!(
                                            host = %srv.server.host,
                                            port = srv.server.port,
                                            "health check error: {e}"
                                        );
                                    }
                                    Err(_elapsed) => {
                                        srv.record_failure();
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

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
        );
        let plain = SiteUpstream::new(
            vec![],
            LoadBalancerStrategy::RoundRobin,
            site_timeout(None),
            None,
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
