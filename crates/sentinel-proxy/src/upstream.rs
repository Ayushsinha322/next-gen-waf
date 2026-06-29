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
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Circuit-breaker tunables
// ---------------------------------------------------------------------------

/// Number of consecutive upstream failures before a server's circuit opens.
const CIRCUIT_OPEN_THRESHOLD: usize = 5;

/// Seconds an open circuit waits before allowing a single half-open probe.
const CIRCUIT_HALF_OPEN_SECS: u64 = 30;

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
            self.circuit_opened_at.store(unix_now_secs() as usize, Ordering::Relaxed);
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
}

impl SiteUpstream {
    fn new(servers: Vec<UpstreamServer>, strategy: LoadBalancerStrategy) -> Self {
        Self {
            servers: servers.into_iter().map(|s| Arc::new(ServerHealth::new(s))).collect(),
            cursor: AtomicUsize::new(0),
            strategy,
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

/// Manages pooled upstream connections and per-site load balancing.
pub struct UpstreamPool {
    sites: DashMap<String, Arc<SiteUpstream>>,
    /// Single shared HTTP/HTTPS keep-alive connection pool.
    client: PooledClient,
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

    /// Build the pool from the initial config.
    pub fn from_config(cfg: &SentinelConfig) -> Self {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        // Keep-alive pool sizing. 32 idle/host is far too low for a reverse
        // proxy: once in-flight concurrency to an upstream exceeds it, the
        // surplus connections are closed when briefly idle and reopened on the
        // next burst — churning TCP handshakes and piling up TIME_WAIT sockets
        // (ephemeral-port-exhaustion risk under load). Default high; override
        // with SENTINEL_UPSTREAM_MAX_IDLE for very large fleets / FD limits.
        let max_idle = std::env::var("SENTINEL_UPSTREAM_MAX_IDLE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(256);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(max_idle)
            .build(https);

        let pool = Self {
            sites: DashMap::new(),
            client,
        };

        for site in &cfg.sites {
            pool.sites.insert(
                site.id.clone(),
                Arc::new(SiteUpstream::new(
                    site.upstream.servers.clone(),
                    site.upstream.load_balancer.clone(),
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
    pub fn select_server(&self, site_id: &str, client_ip: Option<IpAddr>) -> Option<UpstreamServer> {
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
        // active connections and circuit-breaker state.
        let srv_health: Option<Arc<ServerHealth>> =
            self.sites.get(site_id).and_then(|site| {
                site.servers
                    .iter()
                    .find(|h| h.server.host == server_host && h.server.port == server_port)
                    .cloned()
            });

        if let Some(ref h) = srv_health {
            h.active_conns.fetch_add(1, Ordering::Relaxed);
        }

        debug!(
            upstream = ?format!("{}:{}", server_host, server_port),
            "forwarding to upstream (pooled)"
        );

        let result = self
            .client
            .request(req)
            .await
            .context("upstream request failed");

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

        for site in sites {
            let strategy = site.upstream.load_balancer.clone();
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
                    cursor: AtomicUsize::new(
                        existing.cursor.load(Ordering::Relaxed),
                    ),
                    strategy,
                })
            } else {
                Arc::new(SiteUpstream::new(site.upstream.servers.clone(), strategy))
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
            let mut sd = shutdown.clone();

            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(Duration::from_secs(interval_secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let Some(site_up) = pool2.sites.get(&site_id) else { continue };
                            let servers: Vec<Arc<ServerHealth>> = site_up.servers.iter().cloned().collect();
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
