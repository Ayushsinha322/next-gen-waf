//! sentinel-proxy — async reverse proxy with WAF phase pipeline.
//!
//! Architecture:
//!   - One [`ProxyServer`] per listener (bind address).
//!   - Each accepted TCP connection is upgraded to TLS when the listener
//!     config includes a `tls` block.
//!   - hyper v1 serves HTTP/1.1 and HTTP/2 (HTTP/2 via ALPN on TLS).
//!   - A [`UpstreamPool`] holds a pooled HTTP/HTTPS keep-alive client and
//!     per-site load-balancer state (RoundRobin, LeastConn, IpHash, Random).
//!   - WAF phases 0–5 are wired: security modules, rule engine, ML, DLP, and
//!     the cross-request correlation engine.
//!
//! ## Phase pipeline
//! ```text
//! Phase 0: anti-DDoS (conn rate) → IP reputation → correlation check
//! Phase 1: rate limit → bot detect → GeoIP → size limits (URI/headers)
//!          → rule engine (CRS/SRL) → WASM plugins
//! Phase 2: size limit (body) → body inspection → ML scoring → anomaly gate
//! Phase 3: upstream (pooled, HTTP/1.1+H2+TLS, circuit-broken, health-checked)
//! Phase 4: response headers (strip hop-by-hop, inject security headers)
//! Phase 5: DLP response body scan (PII / secret detection)
//! Phase 6: logging + correlation state update
//! ```

pub mod captcha;
pub mod challenge;
pub mod http3;
mod jwks;
pub mod tls;
pub mod upstream;
pub mod websocket;

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Context};
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use http::{header, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ServerConfig;
use sentinel_core::{
    config::{
        BotDetectionConfig, ChallengeMode, ConfigHandle, DlpAction, DlpConfig, FusionConfig,
        IpReputationConfig, ListenerConfig, Protocol, SecurityHeadersConfig, SentinelConfig,
        SiteConfig, WafConfig, WafMode,
    },
    context::{Phase, RequestContext, WafDecision},
};
use sentinel_ebpf::{EbpfConfig, EbpfManager, IpNet};
use sentinel_ml::MlEngine;
use sentinel_modules::{
    check_grpc_body, check_grpc_request, detect_smuggling, inspect_graphql, is_grpc, token_header,
    validate_jwt, AntiDdos, BotDetector, BotSignals, BotTier, DdosVerdict, DlpEngine, GeoIp,
    GeoVerdict, GraphqlLimits, GrpcLimits, IpReputation, IpVerdict, JwtPolicy, RateLimiter,
    RawTier, SmugglingVerdict, ThreatFeed, ThreatVerdict,
};
use sentinel_plugins::PluginRuntime;
use sentinel_rules::RuleEngine;
use sentinel_telemetry::{
    dec_active_connections, inc_active_connections, inc_blocked, inc_ebpf_drops,
    inc_load_shed_connections, inc_load_shed_requests, inc_requests, inc_rule_hits,
    observe_duration, prometheus_text,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn, Instrument};

use crate::upstream::UpstreamPool;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

pub(crate) type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Maps `site_id` → compiled [`RuleEngine`].
type RuleEngineMap = HashMap<String, RuleEngine>;

/// Maps `site_id` → [`GeoIp`] filter (per-site country rules).
type GeoIpMap = HashMap<String, GeoIp>;

/// Maps `site_id` → compiled [`DlpScanner`].
type DlpMap = HashMap<String, DlpScanner>;

/// Cached suspect CIDRs fetched from external reputation feeds.
type FeedCache = Arc<ArcSwap<Vec<(String, Vec<String>)>>>;

// ---------------------------------------------------------------------------
// DLP scanner — Phase 5 response-body PII / secret detection
// ---------------------------------------------------------------------------

/// Per-site DLP scanner.  Built once at startup / reload; scans response
/// bodies for PII and secret patterns via the shared [`DlpEngine`] (builtin
/// card/SSN/AWS/token/key patterns + India PII: PAN, Aadhaar, mobile) and
/// applies the configured action (block / mask / detect).
struct DlpScanner {
    engine: DlpEngine,
    enabled: bool,
    action: DlpAction,
}

impl DlpScanner {
    fn from_config(cfg: &DlpConfig) -> Self {
        Self {
            engine: DlpEngine::new(&cfg.patterns),
            enabled: cfg.enable,
            action: cfg.action,
        }
    }

    /// Scan `body` for sensitive data — first matched label, or `None` if clean
    /// (only the first 512 KiB is inspected).
    fn scan(&self, body: &[u8]) -> Option<&'static str> {
        if !self.enabled {
            return None;
        }
        self.engine.scan(body)
    }

    /// Redact every match in place (length-preserving) and return the sanitized
    /// body plus the hit labels, or `None` if nothing matched.
    fn mask(&self, body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
        if !self.enabled {
            return None;
        }
        self.engine.mask(body)
    }
}

// ---------------------------------------------------------------------------
// Correlation engine — cross-request attack history per source IP
// ---------------------------------------------------------------------------

/// Per-IP attack-history record.
struct IpAttackRecord {
    /// Number of blocked requests in the rolling window.
    blocks: AtomicUsize,
    /// UNIX timestamp of the most recent block (seconds).
    last_block_at: AtomicUsize,
}

impl IpAttackRecord {
    fn new() -> Self {
        Self {
            blocks: AtomicUsize::new(0),
            last_block_at: AtomicUsize::new(0),
        }
    }
}

/// Cross-request correlation state.  Shared across all request handlers.
struct CorrelationEngine {
    /// IP → attack history.  Entries are lazily expired by the GC task.
    state: DashMap<IpAddr, Arc<IpAttackRecord>>,
    /// Rolling window in seconds.  Blocks older than this are ignored.
    window_secs: u64,
    /// If an IP accumulates this many blocks in the window, add extra score.
    escalate_threshold: usize,
    /// Hard cap on tracked IPs; oldest entry evicted when exceeded.
    max_entries: usize,
}

impl CorrelationEngine {
    fn new() -> Self {
        Self {
            state: DashMap::new(),
            window_secs: 60,
            escalate_threshold: 3,
            max_entries: 100_000,
        }
    }

    /// Returns additional anomaly score contribution for this IP based on
    /// its recent block history.
    fn score_for_ip(&self, ip: IpAddr) -> u32 {
        let Some(rec) = self.state.get(&ip) else {
            return 0;
        };
        let last = rec.last_block_at.load(Ordering::Relaxed) as u64;
        let now = unix_now_secs();
        if now.saturating_sub(last) > self.window_secs {
            return 0;
        }
        let blocks = rec.blocks.load(Ordering::Relaxed);
        if blocks >= self.escalate_threshold * 3 {
            8 // persistent attacker
        } else if blocks >= self.escalate_threshold {
            3 // repeated attacker
        } else {
            0
        }
    }

    /// Number of blocks recorded for `ip` within the current rolling window
    /// (0 if unknown or the window has expired). Used by the XDP auto-ban.
    fn block_count_for_ip(&self, ip: IpAddr) -> u32 {
        let Some(rec) = self.state.get(&ip) else {
            return 0;
        };
        let last = rec.last_block_at.load(Ordering::Relaxed) as u64;
        if unix_now_secs().saturating_sub(last) > self.window_secs {
            return 0;
        }
        rec.blocks.load(Ordering::Relaxed) as u32
    }

    /// Record that `ip` was just blocked.
    fn record_block(&self, ip: IpAddr) {
        // Cap the map before inserting to bound memory under spoofed-IP floods.
        while self.state.len() >= self.max_entries {
            let mut oldest_ip: Option<IpAddr> = None;
            let mut oldest_ts = u64::MAX;
            for entry in self.state.iter() {
                let ts = entry.value().last_block_at.load(Ordering::Relaxed) as u64;
                if ts < oldest_ts {
                    oldest_ts = ts;
                    oldest_ip = Some(*entry.key());
                }
            }
            match oldest_ip {
                Some(ip) => {
                    self.state.remove(&ip);
                }
                None => break,
            }
        }
        let rec = self
            .state
            .entry(ip)
            .or_insert_with(|| Arc::new(IpAttackRecord::new()))
            .clone();
        let now = unix_now_secs();
        let last = rec.last_block_at.load(Ordering::Relaxed) as u64;
        if now.saturating_sub(last) > self.window_secs {
            // Window expired — reset counter.
            rec.blocks.store(1, Ordering::Relaxed);
        } else {
            rec.blocks.fetch_add(1, Ordering::Relaxed);
        }
        rec.last_block_at.store(now as usize, Ordering::Relaxed);
    }

    /// Remove entries older than the window.  Call periodically.
    fn gc(&self) {
        let now = unix_now_secs();
        let window = self.window_secs;
        self.state.retain(|_, rec| {
            let last = rec.last_block_at.load(Ordering::Relaxed) as u64;
            now.saturating_sub(last) <= window * 2
        });
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// ModulesState — Phase 0/1 security module state shared across all handlers
// ---------------------------------------------------------------------------

/// Holds all Phase 0/1 runtime security module state.
///
/// Fields marked "state preserved" are NOT rebuilt on SIGHUP so that
/// in-memory counters and block-lists survive config reloads.
struct ModulesState {
    /// Global IP reputation (merged across all sites, includes feed CIDRs).
    ip_rep: ArcSwap<IpReputation>,

    /// Token-bucket rate limiter — state preserved across reloads.
    rate_limiter: RateLimiter,

    /// Bot / UA / JA4 classifier — rebuilt on reload (stateless).
    bot_detector: ArcSwap<BotDetector>,

    /// Per-site GeoIP country filters — rebuilt on reload.
    geoip_map: ArcSwap<GeoIpMap>,

    /// Connection-rate DDoS protector — state preserved across reloads.
    anti_ddos: AntiDdos,

    /// Cross-request correlation — state preserved across reloads.
    correlation: CorrelationEngine,

    /// Suspect CIDRs from external feeds; updated by the feed-loader task.
    feed_cache: FeedCache,

    /// Global threat-intelligence feed (malicious IPs/CIDRs/UAs/domains/URL
    /// patterns) hot-synced from the control plane. Atomically swapped by the
    /// threat-intel poller — updates never block a live request.
    threat_intel: ArcSwap<ThreatFeed>,

    /// Per-endpoint JWKS cache for edge-JWT validation (fetched on demand,
    /// rotated by `kid`). Persists across config reloads so cached keys are
    /// not dropped when a site's policy changes.
    jwks: jwks::JwksCache,
}

// ---------------------------------------------------------------------------
// ServerState — shared across all request handlers on a listener
// ---------------------------------------------------------------------------

struct ServerState {
    config: ConfigHandle,
    upstream_pool: Arc<UpstreamPool>,
    engines: Arc<ArcSwap<RuleEngineMap>>,
    dlp_map: Arc<ArcSwap<DlpMap>>,
    modules: Arc<ModulesState>,
    plugin_runtime: Arc<ArcSwap<PluginRuntime>>,
    ml_engine: Arc<MlEngine>,
    ebpf: Arc<EbpfManager>,
    /// ACME/TLS certificate manager — hot-swaps certs without listener restart.
    cert_manager: Arc<tls::CertManager>,
    /// HTTP-01 ACME challenge tokens: token → key_authorization.
    /// Checked in handle_request before any WAF pipeline work.
    http01_tokens: Arc<DashMap<String, String>>,
    /// Admission control — bounds concurrent client connections across all
    /// listeners (TCP + QUIC). Excess connections are rejected at accept so a
    /// flood cannot exhaust file descriptors or memory. See `serve_listener`.
    conn_limiter: Arc<Semaphore>,
    /// Admission control — bounds concurrent in-flight WAF-processed requests
    /// across all transports (h1/h2/h3). Excess requests shed with 503; this
    /// specifically caps HTTP/2 & HTTP/3 stream fan-out. See `run_pipeline`.
    request_limiter: Arc<Semaphore>,
    /// Set true on SIGTERM so `/readyz` flips to 503 FIRST — the LB/k8s pulls
    /// this node from rotation before we drain, so new traffic is diverted
    /// while in-flight requests finish (R6, graceful shutdown).
    draining: Arc<std::sync::atomic::AtomicBool>,
    /// Tracks live per-connection tasks so shutdown can wait for in-flight
    /// requests to finish (bounded) instead of severing them → 502s (R6).
    conn_tracker: tokio_util::task::TaskTracker,
}

/// Resolve an admission-control limit: an environment variable (if set to a
/// positive integer) overrides the config value; otherwise the config value is
/// used. A resolved value of 0 is clamped to 1 (a Semaphore needs ≥1 permit).
fn resolve_limit(env_key: &str, config_value: usize) -> usize {
    std::env::var(env_key)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(config_value)
        .max(1)
}

/// RAII guard that keeps the live active-connection gauge in sync with the set
/// of admitted connections: increments on construction, decrements on drop
/// (drop runs even if the connection task panics).
pub(crate) struct ActiveConnGuard;

impl ActiveConnGuard {
    pub(crate) fn new() -> Self {
        inc_active_connections();
        Self
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        dec_active_connections();
    }
}

/// Upstreams the dedicated management listener reverse-proxies to. The admin
/// console is served by the WAF's own engine (no third-party proxy): requests
/// to `/api/*` go to the control plane, everything else to the dashboard.
#[derive(Debug)]
struct ManagementUpstreams {
    /// Base URL of the dashboard UI, e.g. "http://dashboard:3000".
    dashboard: String,
    /// Base URL of the control-plane REST/SSE API, e.g. "http://controlplane:9501".
    api: String,
}

impl ManagementUpstreams {
    /// Build from env, with co-located-dev defaults.
    fn from_env() -> Self {
        let dashboard = std::env::var("SENTINEL_MGMT_DASHBOARD_UPSTREAM")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let api = std::env::var("SENTINEL_MGMT_API_UPSTREAM")
            .unwrap_or_else(|_| "http://127.0.0.1:9501".to_string());
        Self { dashboard, api }
    }
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ConfigSyncResponse {
    version: u64,
    sites: Vec<SiteConfig>,
}

/// On-disk snapshot of the last-good synced config (R5). Lets the data plane
/// keep protecting DB-created sites across a restart that happens DURING a
/// control-plane / Postgres outage — boot would otherwise see only local YAML
/// and every UI/DB-created site would vanish. Overwritten by the first
/// successful config-sync poll.
#[derive(serde::Deserialize)]
struct CachedSyncConfig {
    version: u64,
    sites: Vec<SiteConfig>,
}

/// Resolve the config-cache path: `SENTINEL_CONFIG_CACHE_PATH`, else
/// `$HOME/.config/sentinel/config-cache.json`, else `/var/lib/sentinel/...`.
fn config_cache_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("SENTINEL_CONFIG_CACHE_PATH") {
        if !p.is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return std::path::Path::new(&home).join(".config/sentinel/config-cache.json");
        }
    }
    std::path::PathBuf::from("/var/lib/sentinel/config-cache.json")
}

/// Atomically persist the last-good synced sites (write tmp → fsync → rename, so
/// a crash mid-write never yields a truncated cache). Errors are logged only,
/// never propagated into the sync path.
fn write_cached_sites(path: &std::path::Path, version: u64, sites: &[SiteConfig]) {
    use std::io::Write as _;
    let body = match serde_json::to_vec(&serde_json::json!({ "version": version, "sites": sites }))
    {
        Ok(b) => b,
        Err(e) => {
            warn!("config cache: serialize failed: {e}");
            return;
        }
    };
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!("config cache: mkdir {}: {e}", dir.display());
            return;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        warn!("config cache: atomic write {}: {e}", path.display());
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Load the last-good cached config, if present and parseable.
fn load_cached_sites() -> Option<CachedSyncConfig> {
    let path = config_cache_path();
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice::<CachedSyncConfig>(&bytes) {
        Ok(c) => Some(c),
        Err(e) => {
            warn!("config cache: parse {}: {e}", path.display());
            None
        }
    }
}

/// Response from the control-plane `/api/v1/internal/threat-intel` endpoint —
/// IOCs pre-split into block (high-confidence → reject) and watch (→ score)
/// tiers. See `sentinel_modules::threat_intel`.
#[derive(serde::Deserialize, Default)]
struct ThreatIntelSyncResponse {
    version: i64,
    #[serde(default)]
    block: ThreatTierResponse,
    #[serde(default)]
    watch: ThreatTierResponse,
}

#[derive(serde::Deserialize, Default)]
struct ThreatTierResponse {
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    user_agents: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    url_substrings: Vec<String>,
}

impl From<ThreatTierResponse> for RawTier {
    fn from(t: ThreatTierResponse) -> Self {
        RawTier {
            ips: t.ips,
            cidrs: t.cidrs,
            user_agents: t.user_agents,
            domains: t.domains,
            url_substrings: t.url_substrings,
        }
    }
}

/// Top-level proxy server.  One instance manages all configured listeners.
pub struct ProxyServer {
    config: ConfigHandle,
}

impl ProxyServer {
    pub fn new(config: ConfigHandle) -> Self {
        Self { config }
    }

    /// Bind all configured listeners and start serving.
    /// Returns when the `shutdown` receiver fires.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        // R5: replay the last-good synced sites from the on-disk cache before
        // building the pool/engines, so protection survives a restart during a
        // control-plane/Postgres outage. The first successful sync poll below
        // overwrites both the live config and the cache.
        if let Some(cached) = load_cached_sites() {
            let n = cached.sites.len();
            sentinel_core::config::update_sites(&self.config, cached.sites);
            info!(
                sites = n,
                version = cached.version,
                "restored sites from local config cache"
            );
        }
        let cfg = self.config.load_full();

        if cfg.listeners.is_empty() {
            warn!("no listeners configured; proxy will not accept connections");
            shutdown.changed().await.ok();
            return Ok(());
        }

        // Admission control — global concurrency ceilings so a connection or
        // request flood sheds gracefully instead of exhausting FDs / memory.
        // Env vars override the config file (see `LimitsConfig`).
        let max_connections = resolve_limit("SENTINEL_MAX_CONNECTIONS", cfg.limits.max_connections);
        let max_inflight_requests = resolve_limit(
            "SENTINEL_MAX_INFLIGHT_REQUESTS",
            cfg.limits.max_inflight_requests,
        );
        info!(
            max_connections,
            max_inflight_requests, "connection admission control enabled"
        );
        let conn_limiter = Arc::new(Semaphore::new(max_connections));
        let request_limiter = Arc::new(Semaphore::new(max_inflight_requests));

        let upstream_pool = Arc::new(UpstreamPool::from_config(&cfg));

        // Spawn active health-check tasks for sites that configure them.
        UpstreamPool::spawn_health_checks(Arc::clone(&upstream_pool), &cfg, shutdown.clone());

        let initial_engines = build_rule_engines(&cfg, &RuleEngineMap::new());
        let engines: Arc<ArcSwap<RuleEngineMap>> =
            Arc::new(ArcSwap::new(Arc::new(initial_engines)));

        let initial_dlp = build_dlp_map(&cfg);
        let dlp_map: Arc<ArcSwap<DlpMap>> = Arc::new(ArcSwap::new(Arc::new(initial_dlp)));

        let feed_cache: FeedCache = Arc::new(ArcSwap::new(Arc::new(Vec::new())));

        // Connect storage backends (Redis for distributed rate limiting,
        // ClickHouse for traffic history).  Missing/unreachable backends
        // degrade gracefully — the rate limiter falls back to in-memory.
        // File config first, then SENTINEL_CLICKHOUSE_*/SENTINEL_REDIS_URL env
        // overlay so the data plane is configured identically to the Go control
        // plane (same Secret in compose/K8s; no CH password in the proxy YAML).
        let storage_backend_cfg =
            sentinel_storage::StorageBackendConfig::from_core(&cfg.storage).with_env_overrides();
        let storage = sentinel_storage::StorageHandle::connect(&storage_backend_cfg).await;
        if storage.has_redis() {
            info!("rate limiting: distributed mode (Redis backend active)");
        } else {
            info!("rate limiting: in-memory mode (no Redis backend)");
        }

        // Guardrail: refuse to silently fill RAM. /tmp and /dev/shm are tmpfs on
        // most distros, so high-volume NDJSON logs there would OOM the host.
        {
            let ld = resolve_log_dir();
            let lds = ld.to_string_lossy();
            if lds.starts_with("/tmp") || lds.starts_with("/dev/shm") {
                warn!(
                    log_dir = %lds,
                    "log directory is on tmpfs (RAM) — logs can exhaust memory under load; \
                     set SENTINEL_LOG_DIR to a real-disk path (e.g. /var/log/sentinel)"
                );
            } else {
                info!(log_dir = %lds, "ndjson logs (rotating) → real disk");
            }
        }

        // ClickHouse traffic + event flusher. Spawned whenever a ClickHouse URL
        // is configured — even if the INITIAL connect failed — so the writer is
        // SELF-HEALING: it (re)connects in the background with backoff and starts
        // persisting once ClickHouse is reachable, with no data-plane restart.
        //
        // Why this matters: the data plane must boot WITHOUT waiting on ClickHouse
        // (request availability comes first), and K8s gives no cross-pod start
        // ordering, so the writer routinely races a not-yet-ready ClickHouse
        // StatefulSet on cold start. A one-shot connect would leave the writer a
        // permanent silent no-op until someone restarted the proxy. CLICKHOUSE_ENABLED
        // gates buffering and is true ONLY while connected, so the in-memory
        // buffers stay bounded whenever ClickHouse is down.
        if storage_backend_cfg.clickhouse_url.is_some() {
            let initial = storage.clickhouse.clone();
            if initial.is_some() {
                CLICKHOUSE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let ch_cfg = storage_backend_cfg.clone();
            tokio::spawn(async move {
                let mut ch: Option<std::sync::Arc<sentinel_storage::ClickHouseClient>> = initial;
                let mut buf: Vec<sentinel_storage::TrafficRow> = Vec::new();
                let mut evbuf: Vec<sentinel_storage::WafEventRow> = Vec::new();
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
                let mut ticks = 0u32;
                // Seconds remaining until the next reconnect attempt while down.
                let mut reconnect_in = 0u32;
                loop {
                    ticker.tick().await;

                    // --- (re)connect in the background when we have no client ---
                    if ch.is_none() {
                        if reconnect_in == 0 {
                            if let Some(url) = ch_cfg.clickhouse_url.as_deref() {
                                let db = ch_cfg.clickhouse_db.as_deref().unwrap_or("sentinel_logs");
                                let client = sentinel_storage::ClickHouseClient::with_auth(
                                    url,
                                    db,
                                    ch_cfg.clickhouse_user.clone(),
                                    ch_cfg.clickhouse_password.clone(),
                                );
                                match client.ping().await {
                                    Ok(()) => {
                                        match client.ensure_schema().await {
                                            Ok(()) => {
                                                info!(url, database = db, "clickhouse connected — waf history writer enabled");
                                                ch = Some(std::sync::Arc::new(client));
                                                CLICKHOUSE_ENABLED.store(
                                                    true,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "clickhouse reachable but schema init failed — retrying in 10s");
                                                reconnect_in = 10;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "clickhouse unreachable — waf history writer disabled, retrying in 10s");
                                        reconnect_in = 10;
                                    }
                                }
                            }
                        } else {
                            reconnect_in -= 1;
                        }
                    }

                    // Always drain to keep buffers bounded; record_* only fills
                    // them while CLICKHOUSE_ENABLED (i.e. while connected).
                    buf.extend(drain_traffic(unix_now()));
                    evbuf.extend(drain_events());
                    ticks += 1;
                    // Both streams flush on the same 5s-or-500-row cadence.
                    let time_due = ticks >= 5;

                    if let Some(client) = ch.clone() {
                        let mut conn_lost = false;
                        if (time_due || buf.len() >= 500) && !buf.is_empty() {
                            if let Err(e) = client.insert_traffic_batch(&buf).await {
                                warn!(error = %e, rows = buf.len(), "clickhouse traffic flush failed — dropping batch, will reconnect");
                                conn_lost = true;
                            } else {
                                debug!(rows = buf.len(), "clickhouse traffic flushed");
                            }
                            buf.clear(); // bounded: drop after every attempt
                        }

                        if (time_due || evbuf.len() >= 500) && !evbuf.is_empty() {
                            if let Err(e) = client.insert_events_batch(&evbuf).await {
                                warn!(error = %e, rows = evbuf.len(), "clickhouse events flush failed — dropping batch, will reconnect");
                                conn_lost = true;
                            } else {
                                debug!(rows = evbuf.len(), "clickhouse events flushed");
                            }
                            evbuf.clear(); // bounded: drop after every attempt
                        }

                        // A failed insert usually means the server/connection went
                        // away — drop the client so the loop reconnects, and stop
                        // buffering (CLICKHOUSE_ENABLED=false) until it does.
                        if conn_lost {
                            CLICKHOUSE_ENABLED.store(false, std::sync::atomic::Ordering::Relaxed);
                            ch = None;
                            reconnect_in = 5;
                        }
                    } else {
                        // Disconnected: discard anything drained to stay bounded.
                        buf.clear();
                        evbuf.clear();
                    }

                    if time_due {
                        ticks = 0;
                    }
                }
            });
            info!("clickhouse flusher started (1s sample · 5s/500-row flush → traffic_buckets + waf_events; self-healing reconnect)");
        }

        let modules = Arc::new(ModulesState {
            ip_rep: ArcSwap::new(Arc::new(build_ip_reputation(&cfg, &[]))),
            rate_limiter: RateLimiter::with_redis(storage.redis.clone()),
            bot_detector: ArcSwap::new(Arc::new(BotDetector::new())),
            geoip_map: ArcSwap::new(Arc::new(build_geoip_map(&cfg))),
            anti_ddos: build_anti_ddos(&cfg),
            correlation: CorrelationEngine::new(),
            feed_cache: Arc::clone(&feed_cache),
            threat_intel: ArcSwap::new(Arc::new(ThreatFeed::empty())),
            jwks: jwks::JwksCache::new(),
        });

        let plugin_runtime = build_plugin_runtime(&cfg).unwrap_or_else(|e| {
            warn!("failed to load plugins: {e:#}");
            PluginRuntime::new().expect("create empty plugin runtime")
        });
        let plugin_runtime: Arc<ArcSwap<PluginRuntime>> =
            Arc::new(ArcSwap::new(Arc::new(plugin_runtime)));

        let ml_engine = {
            let model_dir = std::path::Path::new("ml-models");
            let engine = Arc::new(MlEngine::new(
                4096,
                256,
                if model_dir.exists() {
                    Some(model_dir)
                } else {
                    None
                },
            ));
            // Warm-start the anomaly model so it scores meaningfully from the
            // first request instead of cold-starting at neutral 0.5.
            engine.warm_start();
            engine
        };

        let ebpf = Arc::new(
            EbpfManager::new(build_ebpf_config())
                .await
                .context("EbpfManager init")?,
        );
        // Mirror operator-configured static IP-reputation blocks into the eBPF
        // blocklist so they're dropped at XDP (or the userspace fast-fail).
        seed_ebpf_from_ip_reputation(&ebpf, &cfg);

        // Certificate manager — loads persisted ACME/manual certs from disk,
        // then runs background renewal every hour.
        let cert_dir = cfg.cert_dir.clone().unwrap_or_else(|| {
            // $HOME/.config/sentinel/certs, or /var/lib/sentinel/certs as fallback.
            std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".config/sentinel/certs"))
                .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/sentinel/certs"))
        });
        let cert_manager = tls::CertManager::new(cert_dir.clone());
        match cert_manager.load_from_disk() {
            Ok(n) if n > 0 => info!(certs = n, "loaded persisted TLS certs from disk"),
            Ok(_) => {}
            Err(e) => warn!("cert disk load: {e:#}"),
        }
        let http01_tokens = Arc::clone(&cert_manager.http01_tokens);

        // Trigger initial ACME issuance for any site that has tls.mode = acme
        // but no cert on disk yet.
        for site in &cfg.sites {
            if site.tls.mode == sentinel_core::config::TlsCertMode::Acme {
                if let Some(acme_cfg) = &site.tls.acme {
                    let has_all = site
                        .domains
                        .iter()
                        .all(|d| cert_manager.store.get_meta(d).is_some());
                    if !has_all {
                        let cm = Arc::clone(&cert_manager);
                        let domains = site.domains.clone();
                        let acme = acme_cfg.clone();
                        tokio::spawn(async move {
                            if let Err(e) = cm.issue_acme(domains.clone(), &acme).await {
                                warn!(?domains, "initial ACME issuance failed: {e:#}");
                            }
                        });
                    }
                }
            }
        }

        // Renewal background task (checks every hour).
        {
            let cm = Arc::clone(&cert_manager);
            let cfg_handle = Arc::clone(&self.config);
            tokio::spawn(async move {
                tls::renewal::renewal_loop(cm, cfg_handle).await;
            });
        }

        let state = Arc::new(ServerState {
            config: Arc::clone(&self.config),
            upstream_pool,
            engines: Arc::clone(&engines),
            dlp_map: Arc::clone(&dlp_map),
            modules: Arc::clone(&modules),
            plugin_runtime: Arc::clone(&plugin_runtime),
            ml_engine: Arc::clone(&ml_engine),
            ebpf: Arc::clone(&ebpf),
            cert_manager,
            http01_tokens,
            conn_limiter,
            request_limiter,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            conn_tracker: tokio_util::task::TaskTracker::new(),
        });

        // --- Background: config hot-reload watcher ---
        {
            let config_watch = Arc::clone(&self.config);
            let engines_swap = Arc::clone(&engines);
            let dlp_swap = Arc::clone(&dlp_map);
            let modules_ref = Arc::clone(&modules);
            let plugin_swap = Arc::clone(&plugin_runtime);
            tokio::spawn(async move {
                loop {
                    let cw = Arc::clone(&config_watch);
                    let es = Arc::clone(&engines_swap);
                    let ds = Arc::clone(&dlp_swap);
                    let mr = Arc::clone(&modules_ref);
                    let ps = Arc::clone(&plugin_swap);
                    let handle = tokio::spawn(async move {
                        let mut last_ptr = Arc::as_ptr(&cw.load_full()) as usize;
                        loop {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            let current = cw.load_full();
                            let ptr = Arc::as_ptr(&current) as usize;
                            if ptr != last_ptr {
                                last_ptr = ptr;
                                let prev_engines = es.load_full();
                                let new_engines = build_rule_engines(&current, &prev_engines);
                                let rule_count: usize =
                                    new_engines.values().map(|e| e.rule_count()).sum();
                                es.store(Arc::new(new_engines));
                                ds.store(Arc::new(build_dlp_map(&current)));

                                let feed_cidrs = mr.feed_cache.load_full();
                                mr.ip_rep
                                    .store(Arc::new(build_ip_reputation(&current, &feed_cidrs)));
                                mr.bot_detector.store(Arc::new(BotDetector::new()));
                                mr.geoip_map.store(Arc::new(build_geoip_map(&current)));

                                match build_plugin_runtime(&current) {
                                    Ok(new_pr) => {
                                        ps.store(Arc::new(new_pr));
                                        info!("plugin runtime hot-reloaded");
                                    }
                                    Err(e) => {
                                        warn!("failed to reload plugins — keeping current: {e:#}");
                                    }
                                }

                                info!(rules = rule_count, "rule engines + modules hot-reloaded");
                            }
                        }
                    });
                    if let Err(e) = handle.await {
                        if e.is_panic() {
                            error!("config hot-reload watcher panicked, restarting: {e}");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }

        // --- Background: control-plane site sync ---
        if let Some(sync_url) = cfg.cluster.sync_url.clone() {
            let poll_cfg = Arc::clone(&state.config);
            let poll_pool = Arc::clone(&state.upstream_pool);
            let secs = cfg.cluster.sync_interval_secs.max(1);
            tokio::spawn(async move {
                use http_body_util::BodyExt as _;
                type EmptyBody = http_body_util::Empty<bytes::Bytes>;
                let client: Client<_, EmptyBody> =
                    Client::builder(TokioExecutor::new()).build_http();
                let mut last_version: u64 = u64::MAX;
                // Authenticate the config-sync poll with the shared internal
                // secret when configured, so the control plane's internal/config
                // endpoint can be gated (not exposed unauthenticated). Unset =
                // co-located dev (no header sent; control plane allows).
                let internal_secret = std::env::var("SENTINEL_INTERNAL_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty());
                let mut ticker = tokio::time::interval(Duration::from_secs(secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let url = format!("{}/api/v1/internal/config", sync_url);
                    let uri: hyper::Uri = match url.parse() {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("config sync: bad url: {e}");
                            continue;
                        }
                    };
                    let mut builder = hyper::Request::builder().method("GET").uri(uri);
                    if let Some(secret) = &internal_secret {
                        builder = builder.header("x-sentinel-internal", secret);
                    }
                    let req = builder
                        .body(http_body_util::Empty::new())
                        .expect("BUG: building config-sync request");
                    let resp = match client.request(req).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("config sync fetch: {e}");
                            continue;
                        }
                    };
                    let bytes = match resp.collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(e) => {
                            warn!("config sync body: {e}");
                            continue;
                        }
                    };
                    let sync: ConfigSyncResponse = match serde_json::from_slice(&bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "config sync parse: {e} — snippet: {}",
                                String::from_utf8_lossy(&bytes)
                                    .chars()
                                    .take(120)
                                    .collect::<String>()
                            );
                            continue;
                        }
                    };
                    if sync.version != last_version {
                        let count = sync.sites.len();
                        // R5: persist the last-good config before applying, so a
                        // restart during a control-plane outage keeps these sites.
                        write_cached_sites(&config_cache_path(), sync.version, &sync.sites);
                        poll_pool.sync_sites(&sync.sites);
                        sentinel_core::config::update_sites(&poll_cfg, sync.sites);
                        last_version = sync.version;
                        info!(version = last_version, sites = count, "sites hot-synced");
                    }
                }
            });
        }

        // --- Background: control-plane threat-intelligence sync (every 60 s) ---
        // Mirrors the site-config sync above: polls the internal threat-intel
        // endpoint, and on a version change rebuilds + atomically swaps the
        // ThreatFeed so hundreds of thousands of IOCs update without dropping a
        // live request. Uses the same shared-secret auth as config sync.
        if let Some(sync_url) = cfg.cluster.sync_url.clone() {
            let ti_modules = Arc::clone(&modules);
            // Optionally offload high-confidence threat-intel IPs to XDP. Off by
            // default: the block tier is already enforced in userspace, and the
            // feed can carry 100k+ churny IOCs — enable only to drop them in-kernel.
            let ti_ebpf = Arc::clone(&ebpf);
            let seed_ti_xdp = std::env::var("SENTINEL_XDP_SEED_THREATINTEL")
                .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false);
            let secs = std::env::var("SENTINEL_TI_SYNC_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(60);
            // Anomaly score added when a watch-tier (lower-confidence) IOC matches.
            let watch_score = std::env::var("SENTINEL_TI_WATCH_SCORE")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(3);
            tokio::spawn(async move {
                use http_body_util::BodyExt as _;
                type EmptyBody = http_body_util::Empty<bytes::Bytes>;
                let client: Client<_, EmptyBody> =
                    Client::builder(TokioExecutor::new()).build_http();
                let internal_secret = std::env::var("SENTINEL_INTERNAL_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty());
                let mut last_version: i64 = i64::MIN;
                let mut ticker = tokio::time::interval(Duration::from_secs(secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let url = format!("{}/api/v1/internal/threat-intel", sync_url);
                    let uri: hyper::Uri = match url.parse() {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("threat-intel sync: bad url: {e}");
                            continue;
                        }
                    };
                    let mut builder = hyper::Request::builder().method("GET").uri(uri);
                    if let Some(secret) = &internal_secret {
                        builder = builder.header("x-sentinel-internal", secret);
                    }
                    let req = builder
                        .body(http_body_util::Empty::new())
                        .expect("BUG: building threat-intel sync request");
                    let resp = match client.request(req).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("threat-intel sync fetch: {e}");
                            continue;
                        }
                    };
                    let bytes = match resp.collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(e) => {
                            warn!("threat-intel sync body: {e}");
                            continue;
                        }
                    };
                    let sync: ThreatIntelSyncResponse = match serde_json::from_slice(&bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "threat-intel sync parse: {e} — snippet: {}",
                                String::from_utf8_lossy(&bytes)
                                    .chars()
                                    .take(120)
                                    .collect::<String>()
                            );
                            continue;
                        }
                    };
                    if sync.version != last_version {
                        // Mirror block-tier IPs/CIDRs into the eBPF/XDP blocklist
                        // (insert-only, capped) before the tier is consumed below.
                        if seed_ti_xdp {
                            const CAP: usize = 60_000;
                            let mut n = 0usize;
                            for ip_s in sync.block.ips.iter().take(CAP) {
                                if let Ok(ip) = ip_s.parse::<std::net::IpAddr>() {
                                    ti_ebpf.block_ip(ip);
                                    n += 1;
                                }
                            }
                            for cidr in sync.block.cidrs.iter().take(CAP.saturating_sub(n)) {
                                if let Some(net) = parse_block_cidr(cidr) {
                                    ti_ebpf.block_net(net);
                                    n += 1;
                                }
                            }
                            if n > 0 {
                                info!(
                                    entries = n,
                                    "seeded eBPF/XDP blocklist from threat-intel block tier"
                                );
                            }
                        }
                        let feed = ThreatFeed::from_parts(
                            sync.version,
                            watch_score,
                            sync.block.into(),
                            sync.watch.into(),
                        );
                        let count = feed.entry_count();
                        last_version = sync.version;
                        ti_modules.threat_intel.store(Arc::new(feed));
                        info!(
                            version = last_version,
                            iocs = count,
                            "threat-intel hot-synced"
                        );
                    }
                }
            });
        }

        // --- Background: control-plane node heartbeat (every 10 s) ---
        // Mirrors the config-sync loop above: POSTs this node's health to the
        // control plane so the cluster view knows the data plane is alive and
        // how it's doing. Same shared-secret auth. Never blocks the proxy: on
        // any error we warn and keep ticking.
        if let Some(sync_url) = cfg.cluster.sync_url.clone() {
            let hb_cfg = Arc::clone(&state.config);
            let hb_pool = Arc::clone(&state.upstream_pool);
            // Resolve the node identity once (the configured id defaults to the
            // literal "auto", which we resolve from env / hostname).
            let node_id = if cfg.cluster.node_id != "auto" {
                cfg.cluster.node_id.clone()
            } else {
                std::env::var("SENTINEL_NODE_ID")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
                    .unwrap_or_else(|| "node".to_string())
            };
            let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| node_id.clone());
            tokio::spawn(async move {
                type JsonBody = http_body_util::Full<bytes::Bytes>;
                let client: Client<_, JsonBody> =
                    Client::builder(TokioExecutor::new()).build_http();
                let internal_secret = std::env::var("SENTINEL_INTERNAL_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty());
                let version = env!("CARGO_PKG_VERSION");
                let mut ticker = tokio::time::interval(Duration::from_secs(10));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;

                    // Snapshot health for this tick (mirrors health_response()).
                    let cfg_snap = hb_cfg.load();
                    let sites = cfg_snap.sites.len();
                    let listeners: Vec<String> = cfg_snap
                        .listeners
                        .iter()
                        .map(|l| format!("{}:{}", l.name, l.bind))
                        .collect();
                    let http3_enabled = cfg_snap.listeners.iter().any(|l| {
                        l.is_tls() && !l.is_management() && l.protocols().contains(&Protocol::Http3)
                    });
                    let pool = hb_pool.stats();
                    let uptime = START_TIME
                        .get_or_init(SystemTime::now)
                        .elapsed()
                        .unwrap_or_default()
                        .as_secs();
                    // Degraded when we have origins configured but none reachable.
                    let status = if pool.total > 0 && pool.healthy == 0 {
                        "degraded"
                    } else {
                        "healthy"
                    };

                    let body = serde_json::json!({
                        "id": node_id,
                        "hostname": hostname,
                        "role": "data-plane",
                        "version": version,
                        "status": status,
                        "metadata": {
                            "uptime_secs": uptime,
                            "sites": sites,
                            "listeners": listeners,
                            "upstreams_healthy": pool.healthy,
                            "upstreams_total": pool.total,
                            "http3_enabled": http3_enabled,
                        }
                    })
                    .to_string();

                    let url = format!("{}/api/v1/internal/nodes/heartbeat", sync_url);
                    let uri: hyper::Uri = match url.parse() {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("heartbeat: bad url: {e}");
                            continue;
                        }
                    };
                    let mut builder = hyper::Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json");
                    if let Some(secret) = &internal_secret {
                        builder = builder.header("x-sentinel-internal", secret);
                    }
                    let req = builder
                        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                        .expect("BUG: building heartbeat request");
                    match client.request(req).await {
                        Ok(resp) => {
                            debug!(status = %resp.status(), "heartbeat posted");
                        }
                        Err(e) => {
                            warn!("heartbeat post: {e}");
                        }
                    }
                }
            });
        }

        // --- Background: RateLimiter GC (every 60 s) ---
        {
            let modules_ref = Arc::clone(&modules);
            watchdog_task("rate-limiter GC", async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    modules_ref.rate_limiter.gc();
                    debug!(
                        ip_buckets = modules_ref.rate_limiter.per_ip_bucket_count(),
                        site_buckets = modules_ref.rate_limiter.per_site_bucket_count(),
                        "rate-limiter GC"
                    );
                }
            });
        }

        // --- Background: AntiDdos GC (every 60 s) ---
        {
            let modules_ref = Arc::clone(&modules);
            watchdog_task("anti-DDoS GC", async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    modules_ref.anti_ddos.gc();
                    debug!(
                        blocked = modules_ref.anti_ddos.blocked_count(),
                        tracked = modules_ref.anti_ddos.tracked_count(),
                        "anti-DDoS GC"
                    );
                }
            });
        }

        // --- Background: Correlation GC (every 120 s) ---
        {
            let modules_ref = Arc::clone(&modules);
            watchdog_task("correlation GC", async move {
                let mut interval = tokio::time::interval(Duration::from_secs(120));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    modules_ref.correlation.gc();
                    debug!("correlation engine GC");
                }
            });
        }

        // --- Background: IP reputation feed loader (every 5 min) ---
        {
            let config_watch = Arc::clone(&self.config);
            let modules_ref = Arc::clone(&modules);
            watchdog_task("IP feed loader", async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let cfg = config_watch.load_full();
                    let feeds: Vec<_> = cfg
                        .sites
                        .iter()
                        .filter_map(|s| s.waf.ip_reputation.as_ref())
                        .flat_map(|r| r.feeds.iter().cloned())
                        .collect();
                    if feeds.is_empty() {
                        continue;
                    }
                    let mut new_cidrs: Vec<(String, Vec<String>)> = Vec::new();
                    for feed in &feeds {
                        match fetch_feed_cidrs(&feed.url).await {
                            Ok(cidrs) => {
                                info!(url = %feed.url, count = cidrs.len(), "IP feed loaded");
                                for cidr in cidrs {
                                    new_cidrs.push((cidr, vec!["feed".to_string()]));
                                }
                            }
                            Err(e) => warn!(url = %feed.url, "IP feed fetch failed: {e}"),
                        }
                    }
                    let new_arc: Arc<Vec<_>> = Arc::new(new_cidrs);
                    modules_ref.feed_cache.store(Arc::clone(&new_arc));
                    let new_ip_rep = build_ip_reputation(&cfg, &new_arc);
                    let count = new_ip_rep.entry_count();
                    modules_ref.ip_rep.store(Arc::new(new_ip_rep));
                    info!(entries = count, "IP reputation table rebuilt");
                }
            });
        }

        let mut handles = Vec::new();
        for listener_cfg in cfg.listeners.clone() {
            let state2 = Arc::clone(&state);
            let mut sd = shutdown.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = serve_listener(listener_cfg, state2, &mut sd).await {
                    error!("listener error: {e}");
                }
            }));
        }

        shutdown.changed().await.ok();
        // R6 graceful shutdown: (1) flip readiness so /readyz → 503 and the LB/k8s
        // pulls this node from rotation (new traffic diverted); (2) stop accepting
        // new connections (abort the listener accept loops); (3) wait — bounded by
        // SENTINEL_DRAIN_GRACE_SECS — for in-flight per-connection tasks to finish
        // before returning, since the runtime is dropped once run() returns and
        // would otherwise sever them mid-request → 502s on every deploy.
        state
            .draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!("shutdown signal received; draining in-flight connections");
        for h in handles {
            h.abort();
        }
        let grace = Duration::from_secs(
            std::env::var("SENTINEL_DRAIN_GRACE_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(25),
        );
        state.conn_tracker.close();
        match tokio::time::timeout(grace, state.conn_tracker.wait()).await {
            Ok(_) => info!("all in-flight connections drained"),
            Err(_) => warn!(
                grace_secs = grace.as_secs(),
                "drain grace elapsed; closing remaining connections"
            ),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Watchdog helper — restarts panic-crashed background tasks
// ---------------------------------------------------------------------------

fn watchdog_task<Fut>(name: &'static str, make_fut: Fut)
where
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = tokio::spawn(make_fut).await {
            if e.is_panic() {
                error!("{name} task panicked: {e}");
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Per-listener accept loop
// ---------------------------------------------------------------------------

async fn serve_listener(
    cfg: ListenerConfig,
    state: Arc<ServerState>,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tcp = TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding listener '{}' on {}", cfg.name, cfg.bind))?;

    // The management listener is a dedicated admin-console endpoint: it bypasses
    // the WAF pipeline and reverse-proxies the dashboard + control-plane API,
    // presenting the hot-swappable management certificate (F5 "device cert").
    let management: Option<Arc<ManagementUpstreams>> = if cfg.is_management() {
        let up = Arc::new(ManagementUpstreams::from_env());
        info!(
            listener = %cfg.name, dashboard = %up.dashboard, api = %up.api,
            "management listener: serving admin console over this endpoint"
        );
        if !cfg.is_tls() {
            warn!(listener = %cfg.name, "management listener has no TLS — admin console will be served over cleartext");
        }
        Some(up)
    } else {
        None
    };

    info!(listener = %cfg.name, bind = %cfg.bind, tls = cfg.is_tls(), management = management.is_some(), "listener started");

    // HTTP/3 is offered on TLS, non-management listeners whose protocol set
    // includes `http3`. QUIC reuses the exact same cert resolver as TCP.
    let h3_enabled =
        cfg.is_tls() && !cfg.is_management() && cfg.protocols().contains(&Protocol::Http3);

    let (tls_acceptor, quic_config): (Option<TlsAcceptor>, Option<quinn::ServerConfig>) = if cfg
        .is_tls()
    {
        let tls_cfg = cfg.tls.as_ref().unwrap();
        if management.is_some() {
            // Management listener: always serve the single management cert
            // (ignores SNI), with a self-signed fallback until one is uploaded.
            let resolver = tls::SentinelCertResolver::new_fixed(
                Arc::clone(&state.cert_manager.store),
                tls::MANAGEMENT_CERT_KEY,
            );
            let mut server_cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            (Some(TlsAcceptor::from(Arc::new(server_cfg))), None)
        } else if tls_cfg.cert.is_some() && tls_cfg.key.is_some() {
            // Explicit cert/key paths — used directly for TCP.
            if h3_enabled {
                warn!(listener = %cfg.name, "HTTP/3 is only wired for the SNI cert-resolver path, not explicit cert/key listeners; serving TCP only");
            }
            (Some(build_tls_acceptor(tls_cfg)?), None)
        } else {
            // SNI-based per-domain resolution across all sites.
            let cfg_snap = state.config.load();
            let domains: Vec<String> = cfg_snap
                .sites
                .iter()
                .flat_map(|s| s.domains.iter().cloned())
                .collect();
            let resolver = tls::SentinelCertResolver::new(Arc::clone(&state.cert_manager.store));
            if !domains.is_empty() {
                resolver.pre_warm(&domains);
            }

            // Same resolver → QUIC server config (ALPN h3), when enabled. Build
            // this from a clone *before* the TCP config consumes the resolver.
            let quic = if h3_enabled {
                match http3::quic_server_config_from_resolver(Arc::clone(&resolver)) {
                    Ok(q) => Some(q),
                    Err(e) => {
                        error!(listener = %cfg.name, "failed to build HTTP/3 server config: {e}; serving TCP only");
                        None
                    }
                }
            } else {
                None
            };

            let mut server_cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            (Some(TlsAcceptor::from(Arc::new(server_cfg))), quic)
        }
    } else {
        (None, None)
    };

    let default_site = cfg.default_site.clone();

    // Spawn the HTTP/3 (QUIC over UDP) endpoint on the same address as the TCP
    // listener. It shares the listener's shutdown signal and feeds requests into
    // the same WAF pipeline (see `http3::serve_quic`).
    if let Some(qcfg) = quic_config {
        match cfg.bind.parse::<SocketAddr>() {
            Ok(quic_bind) => {
                let state_q = Arc::clone(&state);
                let ds_q = default_site.clone();
                let shutdown_q = shutdown.clone();
                let lname = cfg.name.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        http3::serve_quic(quic_bind, qcfg, state_q, ds_q, shutdown_q).await
                    {
                        error!(listener = %lname, "HTTP/3 endpoint error: {e}");
                    }
                });
                info!(listener = %cfg.name, bind = %cfg.bind, "HTTP/3 (QUIC) enabled on this listener");
            }
            Err(e) => {
                error!(listener = %cfg.name, bind = %cfg.bind, "HTTP/3 requested but bind is not a socket address ({e}); h3 disabled");
            }
        }
    }

    // Alt-Svc advertisement — browsers connect over TCP first, then upgrade to
    // h3 on the advertised UDP port. Defaults to this listener's bind port;
    // override with SENTINEL_HTTP3_ADVERTISE_PORT when the public port differs
    // (e.g. a container mapping host :443/udp → container :8443/udp).
    let alt_svc: Option<header::HeaderValue> = if h3_enabled {
        let bind_port = cfg
            .bind
            .parse::<SocketAddr>()
            .map(|a| a.port())
            .unwrap_or(0);
        let port = std::env::var("SENTINEL_HTTP3_ADVERTISE_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(bind_port);
        header::HeaderValue::from_str(&format!("h3=\":{port}\"; ma=86400")).ok()
    } else {
        None
    };

    loop {
        tokio::select! {
            accept = tcp.accept() => {
                let (stream, peer) = accept?;
                // Connection admission control: acquire a permit from the global
                // connection semaphore *before* spawning a task. When the box is
                // at `max_connections`, the permit is unavailable and the freshly
                // accepted socket is dropped here (connection reject) — bounding
                // file descriptors and memory so a flood sheds instead of OOMing.
                let permit = match Arc::clone(&state.conn_limiter).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        inc_load_shed_connections();
                        debug!(peer = %peer, "connection admission: at max_connections, rejecting");
                        continue;
                    }
                };
                let state = Arc::clone(&state);
                let acceptor = tls_acceptor.clone();
                let protos = cfg.protocols();
                let ds = default_site.clone();
                let mgmt = management.clone();
                let av = alt_svc.clone();
                // Spawn on the connection tracker so a graceful shutdown can wait
                // for this in-flight request to finish (bounded) instead of the
                // runtime dropping it mid-request → 502 (R6).
                let tracker = state.conn_tracker.clone();
                tracker.spawn(async move {
                    // Permit is held for the connection's lifetime and released
                    // (freeing a slot) when this task ends; the guard keeps the
                    // active-connection gauge in sync even on panic.
                    let _permit = permit;
                    let _active = ActiveConnGuard::new();
                    if let Err(e) = handle_connection(stream, peer, acceptor, protos, state, ds, mgmt, av).await {
                        debug!(peer = %peer, "connection error: {e}");
                    }
                });
            }
            _ = shutdown.changed() => {
                info!(listener = %cfg.name, "listener shutting down");
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Max time a client may take to send the complete request head before the
/// HTTP/1 connection is dropped — bounds slowloris header-dribbling.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Max wall-clock to read a complete request BODY. `HEADER_READ_TIMEOUT` only
/// covers the head; without a body deadline a trickled/slow POST (slow-body
/// slowloris) holds its in-flight admission permit indefinitely, and enough of
/// them shed all traffic. Env override: `SENTINEL_BODY_READ_TIMEOUT_SECS`.
const BODY_READ_TIMEOUT_SECS: u64 = 30;
fn body_read_timeout() -> Duration {
    static T: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *T.get_or_init(|| {
        Duration::from_secs(
            std::env::var("SENTINEL_BODY_READ_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(BODY_READ_TIMEOUT_SECS),
        )
    })
}
/// Max time allowed for the TLS handshake to complete, so a client that opens a
/// socket and then stalls the handshake can't pin a worker task indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// HTTP/2 stream-concurrency cap (bounds stream-flood / rapid-reset amplification).
const H2_MAX_CONCURRENT_STREAMS: u32 = 256;
/// HTTP/2 keep-alive ping cadence + timeout, so stalled/dead peers are reaped.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

#[allow(clippy::too_many_arguments)] // connection handler threads through per-listener state
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    protocols: Vec<Protocol>,
    state: Arc<ServerState>,
    default_site: Option<String>,
    management: Option<Arc<ManagementUpstreams>>,
    alt_svc: Option<header::HeaderValue>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    if let Some(acceptor) = tls_acceptor {
        // Fingerprint the TLS ClientHello (JA4) by peeking the socket without
        // consuming it — rustls then reads the same bytes for the handshake.
        let tls_fp = peek_ja4(&stream).await;
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .await
            .context("TLS handshake timed out")?
            .context("TLS handshake failed")?;
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let io = TokioIo::new(tls);
        if negotiated.as_deref() == Some(b"h2") {
            serve_http2(io, peer, state, default_site, management, alt_svc, tls_fp).await
        } else {
            serve_http1(io, peer, state, default_site, management, alt_svc, tls_fp).await
        }
    } else {
        let io = TokioIo::new(stream);
        if protocols.contains(&Protocol::Http2) && !protocols.contains(&Protocol::Http1) {
            serve_http2(io, peer, state, default_site, management, alt_svc, None).await
        } else {
            serve_http1(io, peer, state, default_site, management, alt_svc, None).await
        }
    }
}

/// Peek the TLS ClientHello off the accepted TCP stream WITHOUT consuming it
/// (`peek` leaves the bytes in the socket buffer for rustls to read during the
/// handshake) and compute a JA4 fingerprint. Best-effort: returns `None` on a
/// partial/absent ClientHello or timeout, so it never delays or breaks the
/// handshake. HTTP/3 (QUIC) connections don't take this path (fingerprint None).
async fn peek_ja4(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => sentinel_modules::ja4_from_client_hello(&buf[..n], false),
        _ => None,
    }
}

async fn serve_http1<T>(
    io: TokioIo<T>,
    peer: SocketAddr,
    state: Arc<ServerState>,
    default_site: Option<String>,
    management: Option<Arc<ManagementUpstreams>>,
    alt_svc: Option<header::HeaderValue>,
    tls_fp: Option<String>,
) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http1::Builder::new()
        // A timer must be configured for header_read_timeout to arm (hyper
        // panics at runtime otherwise).
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                let ds = default_site.clone();
                let mgmt = management.clone();
                let av = alt_svc.clone();
                let fp = tls_fp.clone();
                async move { with_alt_svc(handle_request(s, peer, req, ds, mgmt, fp).await, av) }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| anyhow!("http1 serve error: {e}"))
}

async fn serve_http2<T>(
    io: TokioIo<T>,
    peer: SocketAddr,
    state: Arc<ServerState>,
    default_site: Option<String>,
    management: Option<Arc<ManagementUpstreams>>,
    alt_svc: Option<header::HeaderValue>,
    tls_fp: Option<String>,
) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        // Timer required for the keep-alive interval/timeout to arm.
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                let ds = default_site.clone();
                let mgmt = management.clone();
                let av = alt_svc.clone();
                let fp = tls_fp.clone();
                async move { with_alt_svc(handle_request(s, peer, req, ds, mgmt, fp).await, av) }
            }),
        )
        .await
        .map_err(|e| anyhow!("http2 serve error: {e}"))
}

/// Attach the `Alt-Svc` header (advertising HTTP/3) to a TCP response when the
/// listener has h3 enabled. No-op when `alt_svc` is `None`.
fn with_alt_svc(
    resp: Result<Response<BoxBody>, Infallible>,
    alt_svc: Option<header::HeaderValue>,
) -> Result<Response<BoxBody>, Infallible> {
    match (resp, alt_svc) {
        (Ok(mut r), Some(v)) => {
            r.headers_mut().insert(header::ALT_SVC, v);
            Ok(r)
        }
        (other, _) => other,
    }
}

// ---------------------------------------------------------------------------
// Request handler — WAF phases + upstream proxying
// ---------------------------------------------------------------------------

async fn handle_request(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<Incoming>,
    default_site: Option<String>,
    management: Option<Arc<ManagementUpstreams>>,
    tls_fp: Option<String>,
) -> Result<Response<BoxBody>, Infallible> {
    // Health / readiness endpoint — served before any WAF pipeline work.
    // GET /healthz or GET /health returns JSON with proxy uptime, site
    // count, and listener status.  No auth required; internal-only.
    if req.uri().path() == "/healthz" || req.uri().path() == "/health" {
        return Ok(health_response(&state));
    }

    // Kubernetes READINESS probe. Unlike /healthz (liveness — "the process is
    // up"), /readyz reports whether this node can actually protect traffic: it
    // returns 200 only once the WAF config has synced from the control plane
    // (sites > 0). A freshly-started or rejoining pod reports 503 until its
    // rules are loaded, so the Service / load balancer won't route to it early
    // → no 502s on rollout or recovery. No auth required; internal-only.
    if req.uri().path() == "/readyz" || req.uri().path() == "/ready" {
        return Ok(readyz_response(&state));
    }

    // Prometheus metrics — served before any WAF pipeline work so every proxy
    // pod is scrapeable at GET /metrics (requests/blocked/latency/rule-hits/
    // eBPF-drops/active-connections/load-shed). Like the health probes above,
    // this is internal-only (no auth) and expected to be network-restricted;
    // it is served on every listener, including the management endpoint.
    if req.method() == http::Method::GET && req.uri().path() == "/metrics" {
        return Ok(metrics_response());
    }

    // Management listener: this is the dedicated admin-console endpoint. It
    // bypasses the WAF pipeline entirely and reverse-proxies the dashboard +
    // control-plane API (the admin UI is auth-gated by the control plane). Done
    // by our own engine — no third-party proxy.
    if let Some(mgmt) = management {
        return handle_management_request(state, peer, req, mgmt).await;
    }

    // ACME HTTP-01 challenge — intercepted BEFORE eBPF, before site routing.
    // The ACME server fetches /.well-known/acme-challenge/<token> on port 80
    // to verify domain ownership.
    const ACME_PREFIX: &str = "/.well-known/acme-challenge/";
    if let Some(token) = req.uri().path().strip_prefix(ACME_PREFIX) {
        if let Some(key_auth) = state.http01_tokens.get(token) {
            let body = Bytes::from(key_auth.clone());
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(full_body(body))
                .unwrap());
        }
        // Unknown token — fall through to normal routing (will 404 from upstream).
    }

    // Internal control-plane bridge API (cert + management-TLS management).
    // Loopback-only: these endpoints share the public listener, so anything
    // under /api/v1/internal/ is refused unless the peer is on localhost OR the
    // caller presents the shared secret (control plane → data plane across
    // containers).
    if req.uri().path().starts_with("/api/v1/internal/") {
        if !peer.ip().is_loopback() && !internal_auth_ok(req.headers()) {
            return Ok(error_response(StatusCode::FORBIDDEN, "internal endpoint"));
        }
        if req
            .uri()
            .path()
            .starts_with("/api/v1/internal/management-tls")
        {
            return Ok(handle_internal_mgmt_tls_api(state, req).await);
        }
        if req.uri().path().starts_with("/api/v1/internal/certs") {
            return Ok(handle_internal_cert_api(state, req).await);
        }
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown internal endpoint",
        ));
    }

    // Hand off to the shared WAF pipeline. The TCP body (`Incoming`) is boxed
    // into `BoxBody` so one pipeline serves both TCP (h1/h2) and QUIC (h3) — see
    // `run_pipeline`, also called by the HTTP/3 adapter in `http3.rs`. `.map()`
    // preserves request extensions, so the WebSocket `OnUpgrade` handle captured
    // by hyper survives the body swap (`CanUpgrade` is generic over the body).
    Ok(run_pipeline(state, peer, req.map(|b| b.boxed()), default_site, tls_fp).await)
}

/// Shared request pipeline, transport-agnostic over the request body type.
///
/// Runs the eBPF fast-fail, sets up the tracing span, drives the WAF pipeline
/// (`proxy`), and records metrics. Called by the TCP handler (`handle_request`,
/// after its health/management/ACME routing boxes the `Incoming` body) and by
/// the HTTP/3 adapter (`crate::http3`), which builds a `BoxBody` from the QUIC
/// request stream. Never returns an error — upstream failures become responses.
pub(crate) async fn run_pipeline(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<BoxBody>,
    default_site: Option<String>,
    tls_fp: Option<String>,
) -> Response<BoxBody> {
    // Blocklist fast-fail: known-blocked addresses never enter the WAF pipeline.
    // Runs before body reads and before any WAF work.
    //
    // This checks the TRANSPORT PEER *and* the resolved client IP, and the second half
    // is not optional. Checking only `peer.ip()` made this control INERT in the shipped
    // HA topology: behind HAProxy (or any load balancer, CDN, or ingress) every request
    // arrives with the proxy as its peer, so the blocklist compared the proxy's address
    // — never the attacker's — and matched nothing. It appeared to work only in the
    // single-VM demo, where the client happened to be the immediate peer. A feature that
    // silently does nothing in production is worse than an absent one, because it is
    // counted as coverage.
    //
    // The peer check is retained rather than replaced: it is the only thing that applies
    // when there is no proxy in front, and it is what the in-kernel XDP program can see
    // (XDP runs at L3 and has no access to X-Forwarded-For at all — see
    // crates/sentinel-ebpf, and the deployment note in the DDoS guide about placing
    // per-source enforcement at the edge where the peer IS the client).
    //
    // resolve_client_ip only trusts XFF when the peer is a configured trusted proxy and
    // walks the chain right-to-left, so a client-supplied header cannot spoof its way
    // *past* a block, nor forge someone else's address into one.
    if blocklist_hit(
        peer.ip(),
        req.headers(),
        |ip| state.ebpf.is_blocked(ip),
        is_trusted_proxy,
    ) {
        inc_ebpf_drops();
        inc_requests();
        inc_blocked();
        return error_response(StatusCode::FORBIDDEN, "Forbidden");
    }

    // Request admission control: acquire a permit from the global in-flight
    // request semaphore. This is the per-request half of admission control (the
    // accept loop bounds connections); it specifically caps HTTP/2 and HTTP/3
    // stream multiplexing, where one connection may open hundreds of concurrent
    // streams that would otherwise all enter the (expensive) WAF pipeline at
    // once. Excess sheds with 503 + Retry-After. Health/readiness/metrics and
    // the management console are handled upstream of this and are never shed.
    let _req_permit = match Arc::clone(&state.request_limiter).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            inc_requests();
            inc_load_shed_requests();
            return overloaded_response();
        }
    };

    let t0 = Instant::now();

    // Tracing span — attached via .instrument() so it is Send and re-entered
    // correctly across every await point in the proxy future.
    let span = tracing::info_span!(
        "request",
        method = %req.method(),
        path   = %req.uri().path(),
        ip     = %peer.ip(),
    );

    let resp = async move {
        match proxy(state, peer, req, default_site, tls_fp).await {
            Ok(r) => r,
            Err(e) => {
                error!("proxy error: {e:#}");
                error_response(StatusCode::BAD_GATEWAY, "Bad Gateway")
            }
        }
    }
    .instrument(span)
    .await;

    // Metrics — recorded unconditionally on every request that clears eBPF.
    let status = resp.status();
    inc_requests();
    if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
        inc_blocked();
    }
    observe_duration(t0.elapsed().as_secs_f64() * 1000.0);

    resp
}

async fn proxy(
    state: Arc<ServerState>,
    peer: SocketAddr,
    mut req: Request<BoxBody>,
    default_site: Option<String>,
    tls_fp: Option<String>,
) -> anyhow::Result<Response<BoxBody>> {
    let cfg = state.config.load();
    let engine_map = state.engines.load_full();

    // Capture WebSocket upgrade future early (must happen before into_parts()).
    let is_ws = is_websocket_upgrade(req.headers());
    let ws_upgrade = if is_ws {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    // --- Phase 0: Connection ---
    let mut ctx = RequestContext::new(peer.ip(), peer.port());
    // Resolve the REAL client IP from X-Forwarded-For when the immediate peer is
    // a trusted proxy (our HAProxy in the shipped HA topology). Without this,
    // behind the LB every per-IP control (anti-DDoS, IP-reputation, rate-limit,
    // GeoIP, threat-intel, correlation, XDP auto-ban) and the forensic client_ip
    // see the proxy's address, collapsing all of them. Trusting XFF from an
    // UNtrusted peer would let attackers spoof past IP blocks, so this is gated
    // on SENTINEL_TRUSTED_PROXIES (empty = never trust XFF — the safe default).
    // Done before Phase-0 checks so they all key off the true client.
    if let Some(real) = resolve_client_ip(peer.ip(), req.headers()) {
        ctx.client_ip = real;
    }
    // JA4 TLS fingerprint computed from the ClientHello during the handshake
    // (None for plaintext/HTTP-3 listeners). Consumed by the bot classifier.
    ctx.tls_fingerprint = tls_fp;

    // Anti-DDoS: connection-rate check.
    match state.modules.anti_ddos.check_connection(ctx.client_ip) {
        DdosVerdict::Block { reason } => {
            ctx.decision = WafDecision::Block;
            ctx.block_reason = Some(reason);
            note_block(&state, ctx.client_ip);
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);
            return Ok(block_response(&ctx));
        }
        DdosVerdict::Allow => {}
    }

    // IP reputation: explicit blocklist / suspect scoring.
    {
        let ip_rep = state.modules.ip_rep.load();
        match ip_rep.check(ctx.client_ip) {
            IpVerdict::Block { reason } => {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!("IP reputation: {reason}"));
                note_block(&state, ctx.client_ip);
                ctx.advance_phase(Phase::Logging);
                log_request(&ctx);
                return Ok(block_response(&ctx));
            }
            IpVerdict::Suspect { tags } => {
                ctx.tx_vars
                    .insert("ip_rep_tags".to_string(), tags.join(","));
                ctx.add_engine_score("reputation", 2);
            }
            IpVerdict::Allow => {}
        }
    }

    // Threat intelligence: dynamic global IOC feed (malicious IPs/CIDRs, botnet
    // C2, Tor exits, scanner UAs, malicious domains/URL patterns) hot-synced from
    // the control plane. Block tier = high-confidence → reject now (like an
    // explicit blocklist, mode-independent); watch tier = add anomaly score and
    // let the rule engine / ML decide.
    {
        let ti = state.modules.threat_intel.load();
        if !ti.is_empty() {
            let ua = req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            let host = req
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri().authority().map(|a| a.as_str()));
            match ti.check(ctx.client_ip, ua, host, req.uri().path()) {
                ThreatVerdict::Block { reason } => {
                    ctx.threat_intel_hit = true;
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!("threat intel: {reason}"));
                    note_block(&state, ctx.client_ip);
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(block_response(&ctx));
                }
                ThreatVerdict::Score { score, tag } => {
                    // Feed the ML "learning" loop: this flag becomes a strongly-
                    // weighted feature so the classifier treats feed-matched
                    // traffic as highly anomalous (see sentinel-ml).
                    ctx.threat_intel_hit = true;
                    ctx.tx_vars.insert("threat_intel".to_string(), tag);
                    ctx.add_engine_score("threat_intel", score);
                }
                ThreatVerdict::None => {}
            }
        }
    }

    // Correlation engine: add extra score for repeat attackers. Can be disabled
    // via SENTINEL_DISABLE_CORRELATION (e.g. rule-engine benchmarking) so a
    // single-source scanner isn't escalated by cross-request block history —
    // letting a tool like GoTestWAF measure per-request rule detection cleanly.
    let corr_score = {
        use std::sync::OnceLock;
        static DISABLED: OnceLock<bool> = OnceLock::new();
        let disabled = *DISABLED.get_or_init(|| {
            matches!(
                std::env::var("SENTINEL_DISABLE_CORRELATION")
                    .ok()
                    .as_deref(),
                Some("1") | Some("true") | Some("yes") | Some("on")
            )
        });
        if disabled || is_shared_egress(ctx.client_ip) {
            // Shared egress: the address is not an actor, so its history is not its
            // fault. See shared_egress_nets().
            0
        } else {
            // Capped so reputation can escalate a borderline request but never block a
            // clean one on its own — the uncapped contribution (8) exceeded the default
            // threshold (5).
            state
                .modules
                .correlation
                .score_for_ip(ctx.client_ip)
                .min(correlation_max_score())
        }
    };
    if corr_score > 0 {
        ctx.add_engine_score("correlation", corr_score);
        ctx.tx_vars
            .insert("correlation_score".to_string(), corr_score.to_string());
    }

    ctx.advance_phase(Phase::RequestHeaders);

    // --- Phase 1: Request headers ---
    let (mut parts, body) = req.into_parts();

    // HTTP/2 carries the authority in the `:authority` pseudo-header (surfaced as
    // the request URI's authority) rather than a `Host` header. Synthesize a Host
    // header from it when absent, so site-matching, WAF rules, logging, and
    // upstream forwarding all see a consistent host — otherwise h2 requests match
    // no site and 502.
    if !parts.headers.contains_key(header::HOST) {
        if let Some(auth) = parts.uri.authority().map(|a| a.as_str().to_owned()) {
            if let Ok(hv) = header::HeaderValue::from_str(&auth) {
                parts.headers.insert(header::HOST, hv);
            }
        }
    }

    ctx.http_version = parts.version;
    ctx.method = parts.method.clone();
    ctx.uri = parts.uri.clone();
    ctx.request_headers = parts.headers.clone();

    // Match site.
    let host = ctx.host().map(str::to_owned);
    let site = host
        .as_deref()
        .and_then(|h| cfg.sites.iter().find(|s| site_matches(s, h)))
        .or_else(|| {
            default_site
                .as_deref()
                .and_then(|ds| cfg.sites.iter().find(|s| s.id == ds))
        });

    if let Some(s) = &site {
        ctx.site_id = Some(s.id.clone());
        ctx.tenant_id = Some(s.tenant_id.clone());
    }

    // Request size limits: URI and header count (Phase 1, before body read).
    if let Some(s) = &site {
        if s.waf.mode != WafMode::Off {
            // URI length limit.
            if s.waf.max_uri_length > 0 {
                let uri_len = ctx.uri.to_string().len() as u32;
                if uri_len > s.waf.max_uri_length {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!(
                        "URI too long: {} bytes (limit {})",
                        uri_len, s.waf.max_uri_length
                    ));
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(error_response(StatusCode::URI_TOO_LONG, "URI Too Long"));
                }
            }
            // Request header count limit.
            if s.waf.max_header_count > 0 {
                let hcount = ctx.request_headers.len() as u32;
                if hcount > s.waf.max_header_count {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!(
                        "too many headers: {} (limit {})",
                        hcount, s.waf.max_header_count
                    ));
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(error_response(
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                        "Too Many Headers",
                    ));
                }
            }
            // HTTP method allow-list (empty = allow all). Case-insensitive.
            if !s.waf.allowed_methods.is_empty() {
                let m = ctx.method.as_str();
                if !s
                    .waf
                    .allowed_methods
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(m))
                {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!("method not allowed: {m}"));
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(error_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "Method Not Allowed",
                    ));
                }
            }
        }
    }

    // WAF phase 1: rate limit → bot → GeoIP → rule engine → plugins.
    {
        let pr = state.plugin_runtime.load();
        phase1_headers(&mut ctx, site, &engine_map, &state.modules, &pr).await?;
    }

    // Browser challenge (Proof-of-Work) — serve an interstitial or, if the
    // client already solved it, grant clearance and bounce back.  A client that
    // already holds valid clearance gets `None` here (regardless of which
    // subsystem asked for the challenge) and proceeds to origin — no re-loop.
    if ctx.decision == WafDecision::Challenge {
        let bot_cfg = site.and_then(|s| s.waf.bot_detection.as_ref());
        let challenge_mode = bot_cfg
            .map(|b| b.challenge)
            .unwrap_or(ChallengeMode::NativePow);
        if let Some(resp) = challenge_response(&mut ctx, challenge_mode, bot_cfg).await {
            ctx.response_status = Some(resp.status());
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);
            return Ok(resp);
        }
        // Cleared (or an in-line grant for an unsafe method) — proceed to origin.
        ctx.decision = WafDecision::Allow;
    }

    if ctx.decision == WafDecision::Block {
        note_block(&state, ctx.client_ip);
        let reason = ctx.block_reason.as_deref().unwrap_or("");
        let resp = if reason.starts_with("HTTP request smuggling") {
            // RFC 7230 §3.3.3: malformed requests MUST be rejected with 400.
            error_response(
                StatusCode::BAD_REQUEST,
                ctx.block_reason.as_deref().unwrap_or("Bad Request"),
            )
        } else if reason.starts_with("jwt:") {
            // Authentication failure — 401 Unauthorized. The specific reason is
            // logged server-side but never leaked to the client.
            error_response(StatusCode::UNAUTHORIZED, "Unauthorized")
        } else {
            block_response(&ctx)
        };
        ctx.response_status = Some(resp.status());
        ctx.advance_phase(Phase::Logging);
        log_request(&ctx);
        return Ok(resp);
    }

    // --- Phase 2: Request body ---
    ctx.advance_phase(Phase::RequestBody);

    let should_inspect_body = site.map(|s| s.waf.mode != WafMode::Off).unwrap_or(false);

    let boxed_body: BoxBody = if should_inspect_body {
        let max_bytes = site.map(|s| s.waf.max_body_size).unwrap_or(0);

        // Enforce max body size.  We check size_hint for an early reject (no
        // data read), then verify again after buffering for chunked bodies that
        // lack a Content-Length header.
        let bytes = if max_bytes > 0 {
            // Cheap early reject when the client declares an oversized
            // Content-Length (no body bytes read yet).
            let upper = body.size_hint().upper().unwrap_or(0);
            if upper > max_bytes {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!(
                    "request body too large (limit {} bytes)",
                    max_bytes
                ));
                ctx.advance_phase(Phase::Logging);
                log_request(&ctx);
                return Ok(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request Entity Too Large",
                ));
            }
            // Enforce the cap WHILE streaming. For `Transfer-Encoding: chunked`
            // bodies size_hint is None (→0), so without this an attacker could
            // stream gigabytes into memory before the post-collection check ever
            // ran. `Limited` aborts collection the instant the body exceeds the
            // cap, bounding memory to `max_bytes`.
            match tokio::time::timeout(
                body_read_timeout(),
                http_body_util::Limited::new(body, max_bytes as usize).collect(),
            )
            .await
            {
                Ok(Ok(collected)) => collected.to_bytes(),
                Ok(Err(e))
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some() =>
                {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!(
                        "request body too large (limit {} bytes)",
                        max_bytes
                    ));
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request Entity Too Large",
                    ));
                }
                Ok(Err(e)) => return Err(anyhow::anyhow!("collecting request body: {e}")),
                Err(_) => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some("request body read timed out (slow-body)".into());
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(error_response(
                        StatusCode::REQUEST_TIMEOUT,
                        "Request Timeout",
                    ));
                }
            }
        } else {
            match tokio::time::timeout(body_read_timeout(), body.collect()).await {
                Ok(r) => r.context("collecting request body")?.to_bytes(),
                Err(_) => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some("request body read timed out (slow-body)".into());
                    ctx.advance_phase(Phase::Logging);
                    log_request(&ctx);
                    return Ok(error_response(
                        StatusCode::REQUEST_TIMEOUT,
                        "Request Timeout",
                    ));
                }
            }
        };

        ctx.request_body = Some(bytes.clone());
        phase2_body(&mut ctx, site, &engine_map, &state.ml_engine)?;

        // GraphQL firewall — query depth / complexity / introspection on the
        // body. Gated to GraphQL endpoints so nested REST-JSON bodies aren't
        // misread as GraphQL queries.
        if ctx.decision == WafDecision::Allow {
            if let Some(gql) = site
                .and_then(|s| s.waf.graphql.as_ref())
                .filter(|g| g.enable)
            {
                let is_graphql = ctx.method == http::Method::POST
                    && (ctx.uri.path().contains("graphql")
                        || ctx
                            .request_headers
                            .get(http::header::CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .is_some_and(|ct| ct.contains("application/graphql")));
                if is_graphql {
                    let limits = GraphqlLimits {
                        max_depth: gql.max_depth,
                        max_complexity: gql.max_complexity,
                        block_introspection: gql.block_introspection,
                    };
                    if let Some(reason) = inspect_graphql(&bytes, &limits) {
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason = Some(reason);
                    }
                }
            }
        }

        // gRPC firewall — message/frame-size limits on the buffered body.
        if ctx.decision == WafDecision::Allow {
            if let Some(grpc_cfg) = site.and_then(|s| s.waf.grpc.as_ref()).filter(|g| g.enable) {
                let is_grpc_ct = ctx
                    .request_headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(is_grpc);
                if is_grpc_ct {
                    let limits = GrpcLimits {
                        max_message_bytes: grpc_cfg.max_message_bytes,
                        max_frames: grpc_cfg.max_frames,
                        block_reflection: grpc_cfg.block_reflection,
                        allowed_methods: grpc_cfg.allowed_methods.clone(),
                        blocked_methods: grpc_cfg.blocked_methods.clone(),
                    };
                    if let Some(reason) = check_grpc_body(&bytes, &limits) {
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason = Some(format!("grpc: {reason}"));
                    }
                }
            }
        }

        if ctx.decision == WafDecision::Limit {
            // Soft-deny from weighted fusion — throttle with 429 (configurable),
            // do not auto-ban (uncertain traffic).
            let resp = limit_response(&ctx, site);
            ctx.response_status = Some(resp.status());
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);
            return Ok(resp);
        }
        if ctx.decision == WafDecision::Block {
            note_block(&state, ctx.client_ip);
            let resp = block_response(&ctx);
            ctx.response_status = Some(resp.status());
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);
            return Ok(resp);
        }

        Full::new(bytes)
            .map_err(|never: Infallible| match never {})
            .boxed()
    } else {
        // Already a `BoxBody` (TCP: boxed `Incoming`; h3: buffered QUIC body).
        body
    };

    // --- Phase 3: Upstream ---
    ctx.advance_phase(Phase::Upstream);

    let site_cfg = site.ok_or_else(|| anyhow!("no matching site for host: {:?}", host))?;

    let upstream_srv = state
        .upstream_pool
        .select_server(&site_cfg.id, Some(ctx.client_ip))
        .ok_or_else(|| anyhow!("no healthy upstream for site '{}'", site_cfg.id))?;

    ctx.upstream_addr = Some(
        format!("{}:{}", upstream_srv.host, upstream_srv.port)
            .parse()
            .ok()
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
    );

    let upstream_uri = build_upstream_uri(
        &upstream_srv.host,
        upstream_srv.port,
        upstream_srv.tls,
        &parts.uri,
    )?;

    // For WebSocket upgrades, preserve the Upgrade and Connection headers so
    // the upstream's HTTP/1.1 upgrade handshake succeeds.
    if is_ws {
        strip_hop_by_hop_except_upgrade(&mut parts.headers);
    } else {
        strip_hop_by_hop(&mut parts.headers);
    }
    inject_forwarding_headers(&mut parts.headers, peer.ip())?;

    parts.uri = upstream_uri;
    // Forward to the upstream as HTTP/1.1 regardless of the client's protocol.
    // An h2 client request still carries version=HTTP/2, which the HTTP/1.1
    // upstream client cannot send (→ "upstream request failed" / 502).
    parts.version = http::Version::HTTP_11;
    let upstream_req = Request::from_parts(parts, boxed_body);

    let upstream_start = std::time::Instant::now();
    let upstream_resp = state
        .upstream_pool
        .send_request(
            &site_cfg.id,
            &upstream_srv.host,
            upstream_srv.port,
            upstream_req,
        )
        .await
        .context("upstream request failed")?;
    ctx.upstream_latency_us = Some(upstream_start.elapsed().as_micros() as u64);

    // --- Phase 4: Response headers ---
    ctx.advance_phase(Phase::ResponseHeaders);
    let (mut resp_parts, resp_body) = upstream_resp.into_parts();
    ctx.response_status = Some(resp_parts.status);
    ctx.response_headers = Some(resp_parts.headers.clone());

    // --- WebSocket upgrade relay ---
    // If the upstream accepted the upgrade (101 Switching Protocols), wire up
    // the bidirectional relay with WAF frame inspection and return immediately.
    if resp_parts.status == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade_fut) = ws_upgrade {
            let upstream_upgrade_fut = hyper::upgrade::on(Response::from_parts(
                resp_parts.clone(),
                http_body_util::Empty::<Bytes>::new(),
            ));
            let client_ip = ctx.client_ip;
            let site_id = site_cfg.id.clone();
            let ws_engine = engine_map.get(&site_id).cloned().map(Arc::new);
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);

            // Spawn background relay after returning 101 to the client.
            tokio::spawn(async move {
                let client_io = match client_upgrade_fut.await {
                    Ok(io) => io,
                    Err(e) => {
                        warn!("WS: client upgrade failed: {e}");
                        return;
                    }
                };
                let upstream_io = match upstream_upgrade_fut.await {
                    Ok(io) => io,
                    Err(e) => {
                        warn!("WS: upstream upgrade failed: {e}");
                        return;
                    }
                };
                websocket::relay(
                    TokioIo::new(client_io),
                    TokioIo::new(upstream_io),
                    client_ip,
                    site_id,
                    ws_engine,
                )
                .await;
            });

            // Return the 101 response to the client immediately.
            let switching = Response::from_parts(resp_parts, resp_body.boxed());
            return Ok(switching);
        }
    }

    strip_hop_by_hop(&mut resp_parts.headers);
    inject_security_headers(
        &mut resp_parts.headers,
        site_cfg.waf.security_headers.as_ref(),
    );

    // Attach any clearance cookies from an in-line PoW grant (challenged POST/PUT
    // that proceeded to origin instead of being 302'd to a bodyless GET).
    for cookie in ctx.pending_set_cookies.drain(..) {
        if let Ok(val) = header::HeaderValue::from_str(&cookie) {
            resp_parts.headers.append(header::SET_COOKIE, val);
        }
    }

    // --- Phase 5: Response body — rule engine + DLP scan ---
    ctx.advance_phase(Phase::ResponseBody);

    let dlp_map = state.dlp_map.load_full();
    let resp_engines = state.engines.load_full();

    // Inspect the response body only when something actually needs it: a DLP
    // scanner is enabled for the site, OR the site's rule set has response-body
    // rules (e.g. CRS RESPONSE-* data-leakage rules).  Most sites have neither,
    // so the response streams straight through with zero added latency.
    let dlp = dlp_map.get(&site_cfg.id).filter(|d| d.enabled);
    let resp_engine = resp_engines
        .get(&site_cfg.id)
        .filter(|e| e.has_response_body_rules());
    let needs_inspection = dlp.is_some() || resp_engine.is_some();

    let final_body: BoxBody = if needs_inspection {
        // Only buffer text-ish responses; skip binary/media to avoid breaking
        // streaming downloads.
        let ct = resp_parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let is_scannable = ct.contains("text")
            || ct.contains("json")
            || ct.contains("xml")
            || ct.contains("javascript")
            || ct.is_empty();

        if is_scannable {
            // Collect up to 512 KiB for scanning.  Larger responses pass
            // through uninspected (streaming inspection is a future change).
            const SCAN_CAP: u64 = 512 * 1024;
            let upper = resp_body.size_hint().upper().unwrap_or(0);
            if upper <= SCAN_CAP || upper == u64::MAX {
                match resp_body.collect().await {
                    Ok(collected) => {
                        let mut bytes = collected.to_bytes();

                        // (1) Response-body rule engine (CRS RESPONSE-* etc.).
                        if let Some(engine) = resp_engine {
                            ctx.response_body = Some(bytes.clone());
                            engine.evaluate(
                                &mut ctx,
                                Phase::ResponseBody,
                                site_cfg.waf.anomaly_threshold,
                            );
                            // Respect learning mode (downgrade Block → Log).
                            enforce_mode(&mut ctx, &site_cfg.waf.mode);
                            if ctx.decision == WafDecision::Block {
                                warn!(
                                    site = %site_cfg.id,
                                    client_ip = %ctx.client_ip,
                                    "response-body rule matched — blocking"
                                );
                                ctx.advance_phase(Phase::Logging);
                                log_request(&ctx);
                                return Ok(block_response(&ctx));
                            }
                        }

                        // (2) DLP — scan / mask / detect on PII & secret
                        // leakage, per the site's configured action.
                        if let Some(dlp) = dlp {
                            match dlp.action {
                                // Block the whole response on any match.
                                DlpAction::Block => {
                                    if let Some(matched) = dlp.scan(&bytes) {
                                        ctx.decision = WafDecision::Block;
                                        ctx.block_reason = Some(format!(
                                            "DLP: sensitive data pattern matched: {matched}"
                                        ));
                                        // Learning mode downgrades Block → Log —
                                        // must not block or rewrite, only record.
                                        enforce_mode(&mut ctx, &site_cfg.waf.mode);
                                        if ctx.decision == WafDecision::Block {
                                            warn!(
                                                site = %site_cfg.id,
                                                client_ip = %ctx.client_ip,
                                                pattern = matched,
                                                "DLP: sensitive data in response — blocking"
                                            );
                                            ctx.advance_phase(Phase::Logging);
                                            log_request(&ctx);
                                            return Ok(block_response(&ctx));
                                        }
                                        warn!(
                                            site = %site_cfg.id,
                                            client_ip = %ctx.client_ip,
                                            pattern = matched,
                                            "DLP: sensitive data in response — would block (learning mode)"
                                        );
                                    }
                                }
                                // Redact matched data in place (length-preserving)
                                // and forward the sanitized response.
                                DlpAction::Mask => {
                                    if site_cfg.waf.mode == WafMode::Learning {
                                        // Observe only — never rewrite in learning mode.
                                        if let Some(matched) = dlp.scan(&bytes) {
                                            ctx.tx_vars.insert(
                                                "dlp_would_mask".to_string(),
                                                matched.to_string(),
                                            );
                                            warn!(
                                                site = %site_cfg.id,
                                                client_ip = %ctx.client_ip,
                                                pattern = matched,
                                                "DLP: sensitive data in response — would mask (learning mode)"
                                            );
                                        }
                                    } else if let Some((masked, hits)) = dlp.mask(&bytes) {
                                        let hits_str = hits.join(", ");
                                        ctx.tx_vars
                                            .insert("dlp_masked".to_string(), hits_str.clone());
                                        warn!(
                                            site = %site_cfg.id,
                                            client_ip = %ctx.client_ip,
                                            hits = %hits_str,
                                            "DLP: masked sensitive data in response"
                                        );
                                        bytes = Bytes::from(masked);
                                    }
                                }
                                // Log the finding but forward unchanged.
                                DlpAction::Detect => {
                                    if let Some(matched) = dlp.scan(&bytes) {
                                        ctx.tx_vars.insert(
                                            "dlp_detected".to_string(),
                                            matched.to_string(),
                                        );
                                        warn!(
                                            site = %site_cfg.id,
                                            client_ip = %ctx.client_ip,
                                            pattern = matched,
                                            "DLP: sensitive data in response — detected (forwarded unchanged)"
                                        );
                                    }
                                }
                            }
                        }

                        Full::new(bytes)
                            .map_err(|never: Infallible| match never {})
                            .boxed()
                    }
                    Err(e) => {
                        warn!("response-body collection error: {e}");
                        http_body_util::Empty::<Bytes>::new()
                            .map_err(|never: Infallible| match never {})
                            .boxed()
                    }
                }
            } else {
                // Response too large to buffer — pass through uninspected.
                resp_body.boxed()
            }
        } else {
            resp_body.boxed()
        }
    } else {
        resp_body.boxed()
    };

    // --- Phase 6: Logging ---
    ctx.advance_phase(Phase::Logging);
    log_request(&ctx);

    Ok(Response::from_parts(resp_parts, final_body))
}

// ---------------------------------------------------------------------------
// WAF phases
// ---------------------------------------------------------------------------

/// Phase 1: rate limit → bot detect → GeoIP → rule engine → plugins.
async fn phase1_headers(
    ctx: &mut RequestContext,
    site: Option<&SiteConfig>,
    engines: &RuleEngineMap,
    modules: &ModulesState,
    plugin_runtime: &PluginRuntime,
) -> anyhow::Result<()> {
    let Some(site) = site else { return Ok(()) };
    if site.waf.mode == WafMode::Off {
        return Ok(());
    }

    ctx.tx_vars.insert(
        "DETECTION_PARANOIA_LEVEL".to_owned(),
        site.waf.paranoia_level.to_string(),
    );

    // --- HTTP request smuggling / desync detection ---
    // Runs before any other Phase 1 checks — a smuggling attempt invalidates
    // the entire request. Reject with 400 Bad Request.
    if ctx.decision == WafDecision::Allow {
        match detect_smuggling(&ctx.request_headers) {
            SmugglingVerdict::Reject { reason } => {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(reason);
            }
            SmugglingVerdict::Clean => {}
        }
    }

    if ctx.decision == WafDecision::Block {
        return Ok(());
    }

    // --- Rate limiting ---
    if ctx.decision == WafDecision::Allow {
        if let Some(ref rl_cfg) = site.waf.rate_limit {
            if modules
                .rate_limiter
                .check_async(&site.id, ctx.client_ip, rl_cfg)
                .await
            {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!("rate limit exceeded for {}", ctx.client_ip));
            }
        }
    }

    // --- Bot detection ---
    if ctx.decision == WafDecision::Allow {
        if let Some(ref bot_cfg) = site.waf.bot_detection {
            let ua = ctx
                .request_headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let bot_det = modules.bot_detector.load();
            // Weighted 0-100 bot score fusing JA4, UA patterns, browser-header
            // presence, and repeat-offender velocity → tiered response.
            let sig = BotSignals {
                user_agent: ua,
                ja4: ctx.tls_fingerprint.as_deref(),
                has_accept: ctx.request_headers.contains_key(http::header::ACCEPT),
                has_accept_language: ctx
                    .request_headers
                    .contains_key(http::header::ACCEPT_LANGUAGE),
                recent_block_score: modules.correlation.score_for_ip(ctx.client_ip),
            };
            let bs = bot_det.score(&sig);
            ctx.tx_vars
                .insert("bot_score".to_string(), bs.score.to_string());
            if bs.verified_good_bot {
                ctx.tx_vars.insert("bot_good".to_string(), "1".to_string());
            }
            let challenge_enabled = bot_cfg.challenge != ChallengeMode::Off;
            // Skip a challenge if the client already solved one (valid, unexpired
            // clearance cookie bound to its IP).
            let has_clearance =
                crate::challenge::clearance_valid(&ctx.request_headers, ctx.client_ip);
            match bs.tier {
                BotTier::Block => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!(
                        "bot score {} ({})",
                        bs.score,
                        bs.reasons.join(", ")
                    ));
                }
                BotTier::Captcha | BotTier::JsChallenge if challenge_enabled && !has_clearance => {
                    ctx.decision = WafDecision::Challenge;
                    ctx.block_reason = Some(format!(
                        "bot score {} — browser challenge required ({})",
                        bs.score,
                        bs.reasons.join(", ")
                    ));
                }
                BotTier::Captcha | BotTier::JsChallenge => {
                    ctx.add_engine_score("bot", (bs.score / 10) as u32);
                }
                BotTier::Allow => {
                    if bs.score >= 15 {
                        ctx.add_engine_score("bot", 2);
                    }
                }
            }
        }
    }

    // --- GeoIP ---
    if ctx.decision == WafDecision::Allow && site.waf.geoip.is_some() {
        let geoip_map = modules.geoip_map.load();
        if let Some(geoip) = geoip_map.get(&site.id) {
            match geoip.check(ctx.client_ip) {
                GeoVerdict::Block { country_code } => {
                    ctx.block_reason = Some(format!("country blocked: {country_code}"));
                    ctx.geo_country = Some(country_code);
                    ctx.decision = WafDecision::Block;
                }
                GeoVerdict::Allow | GeoVerdict::Unknown => {}
            }
        }
    }

    // --- Edge JWT (bearer-token) validation ---
    // Verifies signature + expiry + issuer/audience/scopes against a fixed
    // algorithm allow-list before the request reaches origin. Key material is
    // a static HS256 secret, a static public-key PEM, or an IdP's JWKS endpoint
    // (fetched + cached, rotated by `kid`). Reasons are prefixed "jwt:" so the
    // block renderer returns 401 (not the generic 403) without leaking the
    // reason to clients. A *present* token that fails validation is always
    // rejected; `required` only governs whether a *missing* token is allowed.
    if ctx.decision == WafDecision::Allow {
        if let Some(ref jwt_cfg) = site.waf.jwt {
            if jwt_cfg.enable {
                let bearer = ctx
                    .request_headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        s.strip_prefix("Bearer ")
                            .or_else(|| s.strip_prefix("bearer "))
                    })
                    .map(str::trim)
                    .filter(|t| !t.is_empty());
                match bearer {
                    None => {
                        if jwt_cfg.required {
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason = Some("jwt: missing bearer token".to_string());
                        }
                    }
                    Some(token) => {
                        let policy = JwtPolicy {
                            algorithms: jwt_cfg.algorithms.clone(),
                            issuer: jwt_cfg.issuer.clone(),
                            audience: jwt_cfg.audience.clone(),
                            required_scopes: jwt_cfg.required_scopes.clone(),
                            scope_claim: jwt_cfg.scope_claim.clone(),
                        };
                        // Select key material in priority order: static HS
                        // secret → static public PEM → JWKS endpoint. A public
                        // PEM is parsed as EC when the policy lists an ES*
                        // algorithm, otherwise as RSA.
                        let result: Result<(), String> = if let Some(secret) =
                            jwt_cfg.hs_secret.as_deref()
                        {
                            let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
                            validate_jwt(token, &key, &policy)
                        } else if let Some(pem) = jwt_cfg.public_key_pem.as_deref() {
                            let is_ec = jwt_cfg.algorithms.iter().any(|a| a.starts_with("ES"));
                            let built = if is_ec {
                                jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes())
                            } else {
                                jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())
                            };
                            match built {
                                Ok(key) => validate_jwt(token, &key, &policy),
                                Err(_) => Err("misconfigured public key".to_string()),
                            }
                        } else if let Some(url) = jwt_cfg.jwks_url.as_deref() {
                            // JWKS: pick the key by the token's `kid`. An
                            // unknown `kid` forces a cache refresh (rotation).
                            match token_header(token) {
                                Some((Some(kid), _alg)) => {
                                    let keys = modules.jwks.keys(url, Some(kid.as_str())).await;
                                    match keys.get(&kid) {
                                        Some(key) => validate_jwt(token, key, &policy),
                                        None => Err(format!("unknown key id: {kid}")),
                                    }
                                }
                                Some((None, _)) => {
                                    Err("token header missing kid (required for JWKS)".to_string())
                                }
                                None => Err("malformed token header".to_string()),
                            }
                        } else {
                            Err("no verification key configured".to_string())
                        };
                        // A token was presented; if it does not validate, reject
                        // regardless of `required` (WafMode::Learning still
                        // downgrades Block → Log via enforce_mode below).
                        if let Err(reason) = result {
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason = Some(format!("jwt: {reason}"));
                        }
                    }
                }
            }
        }
    }

    // --- gRPC firewall (method / reflection gate) ---
    // Path-level checks on gRPC traffic before the body is buffered: per-method
    // allow/deny and server-reflection blocking. Frame/size limits run later in
    // phase2 once the body is available.
    if ctx.decision == WafDecision::Allow {
        if let Some(ref grpc_cfg) = site.waf.grpc {
            if grpc_cfg.enable {
                let is_grpc_ct = ctx
                    .request_headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(is_grpc);
                if is_grpc_ct {
                    let limits = GrpcLimits {
                        max_message_bytes: grpc_cfg.max_message_bytes,
                        max_frames: grpc_cfg.max_frames,
                        block_reflection: grpc_cfg.block_reflection,
                        allowed_methods: grpc_cfg.allowed_methods.clone(),
                        blocked_methods: grpc_cfg.blocked_methods.clone(),
                    };
                    if let Some(reason) = check_grpc_request(ctx.uri.path(), &limits) {
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason = Some(format!("grpc: {reason}"));
                    }
                }
            }
        }
    }

    // --- Rule engine (CRS / SRL) ---
    if ctx.decision == WafDecision::Allow {
        if let Some(engine) = engines.get(&site.id) {
            eval_rules(ctx, engine, Phase::RequestHeaders, &site.waf);
        }
    }

    // --- WASM plugins ---
    if ctx.decision == WafDecision::Allow {
        for plugin_name in &plugin_runtime.plugin_names() {
            let result = plugin_runtime.evaluate_plugin(plugin_name, ctx).await;
            if result.anomaly_score_delta > 0 {
                ctx.add_engine_score("plugin", result.anomaly_score_delta);
            }
            match result.decision {
                WafDecision::Block => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!("plugin '{plugin_name}' set decision"));
                    break;
                }
                WafDecision::Challenge if ctx.decision == WafDecision::Allow => {
                    ctx.decision = WafDecision::Challenge;
                    ctx.block_reason = Some(format!("plugin '{plugin_name}' requested challenge"));
                }
                _ => {}
            }
            for (name, value) in &result.response_headers {
                ctx.tx_vars
                    .insert(format!("plugin_response_header:{name}"), value.clone());
            }
            if let Some(ref callouts) = result.pending_callouts {
                if !callouts.is_empty() {
                    plugin_runtime
                        .execute_pending_callouts(callouts.clone())
                        .await;
                    let result2 = plugin_runtime.evaluate_plugin(plugin_name, ctx).await;
                    if result2.anomaly_score_delta > 0 {
                        ctx.add_engine_score("plugin", result2.anomaly_score_delta);
                    }
                    match result2.decision {
                        WafDecision::Block => {
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason = Some(format!("plugin '{plugin_name}' set decision"));
                            break;
                        }
                        WafDecision::Challenge if ctx.decision == WafDecision::Allow => {
                            ctx.decision = WafDecision::Challenge;
                            ctx.block_reason =
                                Some(format!("plugin '{plugin_name}' requested challenge"));
                        }
                        _ => {}
                    }
                    for (name, value) in &result2.response_headers {
                        ctx.tx_vars
                            .insert(format!("plugin_response_header:{name}"), value.clone());
                    }
                }
            }
        }
    }

    enforce_mode(ctx, &site.waf.mode);
    Ok(())
}

/// Phase 2: body inspection + ML scoring + anomaly threshold catch-all.
fn phase2_body(
    ctx: &mut RequestContext,
    site: Option<&SiteConfig>,
    engines: &RuleEngineMap,
    ml_engine: &MlEngine,
) -> anyhow::Result<()> {
    let Some(site) = site else { return Ok(()) };
    if site.waf.mode == WafMode::Off {
        return Ok(());
    }

    if let Some(engine) = engines.get(&site.id) {
        eval_rules(ctx, engine, Phase::RequestBody, &site.waf);
    }

    if let Some(ref ml_cfg) = site.waf.ml {
        if ml_cfg.enable {
            let ml_scores = ml_engine.evaluate(ctx);

            ctx.ml_scores
                .insert("anomaly".to_string(), ml_scores.anomaly_score);
            ctx.ml_scores
                .insert("payload_attack".to_string(), ml_scores.payload_attack_score);
            for (model, score) in &ml_scores.onnx_scores {
                ctx.ml_scores.insert(format!("onnx:{model}"), *score);
            }
            ctx.ml_scores
                .insert("combined".to_string(), ml_scores.combined_score);

            if ml_scores.combined_score >= ml_cfg.sensitivity {
                // The supervised n-gram classifier is high-precision, so a
                // confident detection (combined >= sensitivity, e.g. 0.9)
                // contributes a blocking amount of anomaly score on its own
                // (scaled to reach the block threshold), rather than only a
                // small additive nudge. Below sensitivity it contributes 0.
                let delta: u32 = (ml_scores.combined_score * 12.0).round() as u32;
                let delta = delta.min(12);
                if delta > 0 {
                    let reason = if ml_scores.anomaly_score >= ml_cfg.sensitivity {
                        format!(
                            "ML anomaly: {:.3} (threshold: {:.3})",
                            ml_scores.anomaly_score, ml_cfg.sensitivity
                        )
                    } else {
                        format!(
                            "ML combined: {:.3} (threshold: {:.3})",
                            ml_scores.combined_score, ml_cfg.sensitivity
                        )
                    };
                    ctx.add_engine_score("ml", delta);
                    ctx.rule_matches.push(sentinel_core::context::RuleMatch {
                        rule_id: "ML-ANOMALY".to_string(),
                        message: reason,
                        severity: sentinel_core::context::Severity::Medium,
                        score: delta,
                        target: "ML".to_string(),
                        phase: Phase::RequestBody,
                    });
                }
            }
        }
    }

    apply_verdict(ctx, &site.waf);

    enforce_mode(ctx, &site.waf.mode);
    Ok(())
}

// ---------------------------------------------------------------------------
// Weighted verdict fusion (#11)
// ---------------------------------------------------------------------------

/// Whether weighted fusion is active for this site.
fn fusion_enabled(waf: &WafConfig) -> bool {
    waf.fusion.as_ref().is_some_and(|f| f.enable)
}

/// Threshold for the site's (1-based) paranoia level from a per-PL list; the
/// last entry repeats when the list is shorter than the level. `None` if empty.
fn threshold_for_pl(list: &[u32], pl: u8) -> Option<u32> {
    if list.is_empty() {
        return None;
    }
    let idx = (pl.max(1) as usize - 1).min(list.len() - 1);
    Some(list[idx])
}

/// Weighted fused score: Σ weight[engine]·bucket[engine], plus any anomaly
/// score not attributed to an engine (counted at weight 1, so no contribution
/// is ever silently dropped).
fn fused_score(ctx: &RequestContext, f: &FusionConfig) -> u32 {
    let mut weighted = 0f32;
    let mut bucketed: u32 = 0;
    for (engine, raw) in &ctx.engine_scores {
        let w = f.weights.get(engine).copied().unwrap_or(1.0).max(0.0);
        weighted += w * (*raw as f32);
        bucketed = bucketed.saturating_add(*raw);
    }
    let remainder = ctx.anomaly_score.saturating_sub(bucketed);
    (weighted.round().max(0.0) as u32).saturating_add(remainder)
}

/// Final verdict fusion. With fusion enabled: weighted score vs per-paranoia
/// block/limit thresholds (→ Block / Limit / Allow). Otherwise the legacy flat
/// `anomaly_threshold`. An explicit Block from an earlier phase is preserved.
fn apply_verdict(ctx: &mut RequestContext, waf: &WafConfig) {
    if ctx.decision == WafDecision::Block {
        return;
    }
    match waf.fusion.as_ref().filter(|f| f.enable) {
        Some(f) => {
            let score = fused_score(ctx, f);
            ctx.tx_vars
                .insert("fused_score".to_string(), score.to_string());
            let block_t = threshold_for_pl(&f.block_thresholds, waf.paranoia_level)
                .unwrap_or(waf.anomaly_threshold);
            if score > 0 && score >= block_t {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!(
                    "fused anomaly score {score} >= block threshold {block_t} (PL{})",
                    waf.paranoia_level
                ));
            } else if ctx.decision == WafDecision::Allow {
                if let Some(limit_t) = threshold_for_pl(&f.limit_thresholds, waf.paranoia_level) {
                    if score > 0 && score >= limit_t {
                        ctx.decision = WafDecision::Limit;
                        ctx.block_reason = Some(format!(
                            "fused anomaly score {score} >= limit threshold {limit_t} (PL{})",
                            waf.paranoia_level
                        ));
                    }
                }
            }
        }
        None => {
            if ctx.anomaly_score > 0 && ctx.anomaly_score >= waf.anomaly_threshold {
                // ML suppression: when the n-gram classifier is loaded and
                // scores the payload as benign (< 0.15), suppress CRS-only
                // blocks. The ML model acts as a precision layer — if it
                // doesn't see an attack, a CRS-only match is likely a false
                // positive on benign prose. Only suppress when:
                // 1. No coverage rule (99002xx) fired
                // 2. Anomaly score is moderate (< 20, i.e. 2-3 rules)
                // 3. ML score is low (< 0.15)
                let has_coverage_match = ctx
                    .rule_matches
                    .iter()
                    .any(|m| m.rule_id.starts_with("99002"));
                let ml_benign = sentinel_ml::models::ngram_classifier::is_loaded()
                    && !has_coverage_match
                    && ctx.ml_scores.get("payload_attack").copied().unwrap_or(1.0) < 0.15
                    && ctx.anomaly_score < 20;
                if !ml_benign {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!(
                        "anomaly score {} >= threshold {}",
                        ctx.anomaly_score, waf.anomaly_threshold
                    ));
                }
            }
        }
    }
}

/// Run the rule engine for `phase`, disabling its internal flat-threshold
/// early-exit when fusion is on (rules then only accumulate score and honor
/// explicit `deny` rules — the proxy makes the final weighted verdict), and
/// attribute the score delta to the `rules` engine bucket.
fn eval_rules(ctx: &mut RequestContext, engine: &RuleEngine, phase: Phase, waf: &WafConfig) {
    let threshold = if fusion_enabled(waf) {
        0
    } else {
        waf.anomaly_threshold
    };
    let before = ctx.anomaly_score;
    let matches_before = ctx.rule_matches.len();
    engine.evaluate(ctx, phase, threshold);
    let delta = ctx.anomaly_score.saturating_sub(before);
    if delta > 0 {
        *ctx.engine_scores.entry("rules".to_string()).or_insert(0) += delta;
    }
    // Metrics: each rule that matched during this phase is one rule-hit event.
    // `rule_matches` only grows here, so the difference is the new-match count.
    let new_matches = ctx.rule_matches.len().saturating_sub(matches_before);
    for _ in 0..new_matches {
        inc_rule_hits();
    }
}

fn enforce_mode(ctx: &mut RequestContext, mode: &WafMode) {
    if *mode == WafMode::Learning
        && matches!(
            ctx.decision,
            WafDecision::Block | WafDecision::Challenge | WafDecision::Limit
        )
    {
        ctx.decision = WafDecision::Log;
        // Record the would-have-blocked signal for the learning report. We keep
        // `block_reason` so the report can explain *why* the rule would fire;
        // the downgraded decision (Log) means traffic still passes through.
        ctx.would_block = true;
    }
}

// ---------------------------------------------------------------------------
// Module / engine builders
// ---------------------------------------------------------------------------

/// Build the per-site rule engines. `previous` is the currently-live engine map
/// (empty at startup): on a rule-compile failure we FAIL SAFE by retaining that
/// site's last-good engine rather than silently dropping it to zero rules. This
/// closes the reload fail-open hole where one malformed CRS/SRL push from the
/// control plane would unprotect a previously-protected site cluster-wide.
fn build_rule_engines(cfg: &SentinelConfig, previous: &RuleEngineMap) -> RuleEngineMap {
    let mut map = RuleEngineMap::new();
    for site in &cfg.sites {
        if site.waf.mode == WafMode::Off || site.waf.rules.is_empty() {
            continue;
        }
        match load_site_engine(site) {
            Ok(engine) => {
                info!(site = %site.id, rules = engine.rule_count(), "rule engine loaded");
                map.insert(site.id.clone(), engine);
            }
            Err(e) => {
                // RuleEngine is Arc-backed → clone is cheap.
                if let Some(prev) = previous.get(&site.id) {
                    warn!(site = %site.id, rules = prev.rule_count(),
                        "rule engine reload FAILED — retaining last-good ruleset, new rules rejected: {e:#}");
                    map.insert(site.id.clone(), prev.clone());
                } else {
                    warn!(site = %site.id,
                        "rule engine load failed and no prior ruleset — site has NO signature protection until the config is fixed: {e:#}");
                }
            }
        }
    }
    map
}

fn build_dlp_map(cfg: &SentinelConfig) -> DlpMap {
    let mut map = DlpMap::new();
    for site in &cfg.sites {
        if let Some(ref dlp_cfg) = site.waf.dlp {
            map.insert(site.id.clone(), DlpScanner::from_config(dlp_cfg));
        }
    }
    map
}

/// Trusted downstream proxy CIDRs (`SENTINEL_TRUSTED_PROXIES`, comma-separated).
/// Only when the immediate TCP peer is inside one of these do we believe its
/// `X-Forwarded-For`. Empty (default) = never trust XFF, so a direct client
/// cannot spoof its source IP past our per-IP defenses.
fn trusted_proxies() -> &'static [IpNet] {
    static P: std::sync::OnceLock<Vec<IpNet>> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        std::env::var("SENTINEL_TRUSTED_PROXIES")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|c| parse_block_cidr(c.trim()))
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn is_trusted_proxy(ip: std::net::IpAddr) -> bool {
    trusted_proxies().iter().any(|n| n.contains(&ip))
}

/// Resolve the real client IP from `X-Forwarded-For`, but only when `peer` is a
/// trusted proxy. Walks the XFF list right-to-left (the right-most entry is what
/// our trusted proxy actually observed) and returns the first address that is
/// not itself a trusted proxy — so a client-supplied left-most spoof can never
/// win, and proxy chains resolve correctly. Returns `None` (keep the TCP peer)
/// when the peer is untrusted or no usable XFF address is present.
fn resolve_client_ip(
    peer: std::net::IpAddr,
    headers: &http::HeaderMap,
) -> Option<std::net::IpAddr> {
    resolve_client_ip_with(peer, headers, is_trusted_proxy)
}

/// Decide whether a request is from a blocklisted address.
///
/// Checks the transport peer AND the resolved client IP. Extracted so the decision is
/// testable without constructing a whole server: the bug this replaced was invisible in
/// unit terms (the call looked correct) and only wrong in a topology, which is exactly
/// the sort of thing that needs an explicit test rather than a reading.
fn blocklist_hit(
    peer: std::net::IpAddr,
    headers: &http::HeaderMap,
    is_blocked: impl Fn(std::net::IpAddr) -> bool,
    is_trusted: impl Fn(std::net::IpAddr) -> bool + Copy,
) -> bool {
    if is_blocked(peer) {
        return true;
    }
    // Only consults XFF when the peer is a trusted proxy, so an untrusted client cannot
    // use the header to have someone else blocked — or to slip past its own block.
    resolve_client_ip_with(peer, headers, is_trusted).is_some_and(is_blocked)
}

/// Testable core: `is_trusted` decides which addresses are trusted proxies.
fn resolve_client_ip_with(
    peer: std::net::IpAddr,
    headers: &http::HeaderMap,
    is_trusted: impl Fn(std::net::IpAddr) -> bool,
) -> Option<std::net::IpAddr> {
    if !is_trusted(peer) {
        return None;
    }
    let xff = headers.get("x-forwarded-for")?.to_str().ok()?;
    xff.split(',')
        .rev()
        .filter_map(|p| p.trim().parse::<std::net::IpAddr>().ok())
        .find(|ip| !is_trusted(*ip))
        .or_else(|| {
            // All hops trusted → fall back to the left-most parseable address.
            xff.split(',')
                .filter_map(|p| p.trim().parse::<std::net::IpAddr>().ok())
                .next()
        })
}

/// CIDRs whose addresses are SHARED EGRESS rather than identities.
///
/// Configure with `SENTINEL_SHARED_EGRESS_CIDRS` (comma-separated CIDRs or bare IPs),
/// e.g. a corporate NAT range, a CGNAT block, or a VPN concentrator's public address.
///
/// # Why this exists
///
/// Every per-IP reputation mechanism here assumes an IP identifies an actor. Behind NAT
/// that assumption is false — one address is thousands of people — and the mechanisms
/// then punish bystanders for a neighbour's behaviour:
///
///   * The correlation engine adds up to 8 anomaly score for an IP with recent blocks.
///     With the default `anomaly_threshold` of 5, that alone exceeds the threshold, so a
///     COMPLETELY CLEAN request from a shared address gets blocked on reputation with no
///     rule match at all. Reproduced at 500 rps: a target list of 9 clean requests to 1
///     attack returned 99.4% 403.
///   * Worse, the XDP auto-ban excludes only PRIVATE ranges, and a corporate NAT egress
///     address is PUBLIC. After `SENTINEL_XDP_AUTOBAN_BLOCKS` (default 20) blocks, one
///     person running a scanner gets the entire office's egress IP dropped in-kernel.
///     That is a hard cutoff for every colleague, not a degradation.
///
/// Listing a range here means "this address is not an actor": no correlation escalation
/// and no auto-ban. Detection is unaffected — an attack from a shared address is still
/// blocked on its own merits by the rules. What stops is holding the address responsible
/// for its history.
fn shared_egress_nets() -> &'static [IpNet] {
    static NETS: std::sync::OnceLock<Vec<IpNet>> = std::sync::OnceLock::new();
    NETS.get_or_init(|| {
        std::env::var("SENTINEL_SHARED_EGRESS_CIDRS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .filter_map(|s| parse_block_cidr(s.trim()))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Whether `ip` is shared egress and therefore exempt from per-IP reputation.
fn is_shared_egress(ip: std::net::IpAddr) -> bool {
    shared_egress_nets().iter().any(|n| n.contains(&ip))
}

/// Hard cap on the correlation engine's anomaly-score contribution.
///
/// Default 4, which is deliberately BELOW the default `anomaly_threshold` of 5 so that
/// reputation can tip a borderline request over the line but can never, by itself,
/// block a request that matched no rule. Before this cap the "persistent attacker"
/// contribution was 8 — larger than the threshold — so reputation alone decided.
///
/// If you lower a site's `anomaly_threshold` below 5, lower this to match, or reputation
/// regains the ability to block clean traffic on its own.
fn correlation_max_score() -> u32 {
    static MAX: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("SENTINEL_CORRELATION_MAX_SCORE")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(4)
    })
}

/// Parse a `SENTINEL_XDP_BLOCK` entry — either a bare IP (`1.2.3.4`, treated as
/// a /32 or /128) or a CIDR (`10.0.0.0/8`) — into an [`IpNet`].
fn parse_block_cidr(s: &str) -> Option<IpNet> {
    let (addr_str, pfx) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.trim().parse::<u8>().ok()?)),
        None => (s, None),
    };
    let addr: std::net::IpAddr = addr_str.trim().parse().ok()?;
    let prefix = pfx.unwrap_or(if addr.is_ipv4() { 32 } else { 128 });
    Some(IpNet::new(addr, prefix))
}

/// Build the eBPF/XDP configuration from the environment. Kernel XDP is
/// opt-in and needs CAP_BPF/CAP_NET_ADMIN plus the `kernel` build feature;
/// otherwise the manager runs the userspace software fast-fail:
///   `SENTINEL_XDP_ENABLE=1`                    — attempt kernel XDP attach
///   `SENTINEL_XDP_IFACE=eth0`                  — interface to attach to
///   `SENTINEL_XDP_BLOCK=1.2.3.4,10.0.0.0/8`    — seed CIDRs to drop at XDP
fn build_ebpf_config() -> EbpfConfig {
    let enable_kernel = std::env::var("SENTINEL_XDP_ENABLE")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let interface = std::env::var("SENTINEL_XDP_IFACE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "eth0".to_string());
    let blocklist: Vec<IpNet> = std::env::var("SENTINEL_XDP_BLOCK")
        .unwrap_or_default()
        .split(',')
        .filter_map(parse_block_cidr)
        .collect();
    if enable_kernel || !blocklist.is_empty() {
        info!(
            interface = %interface,
            enable_kernel,
            seed_entries = blocklist.len(),
            "eBPF/XDP config from environment"
        );
    }
    EbpfConfig {
        interface,
        blocklist,
        enable_kernel,
        stats_interval_secs: 5,
    }
}

/// XDP auto-ban policy: when a source IP is blocked by the WAF often enough
/// within the correlation window, add it to the eBPF blocklist so its packets
/// are dropped in-kernel (or by the userspace fast-fail in software mode).
#[derive(Clone, Copy)]
struct AutoBanConfig {
    enabled: bool,
    threshold_blocks: u32,
    include_private: bool,
}

/// Read the auto-ban policy from the environment (once):
///   `SENTINEL_XDP_AUTOBAN=0`                 — disable (default on)
///   `SENTINEL_XDP_AUTOBAN_BLOCKS=20`         — blocks-in-window before banning
///   `SENTINEL_XDP_AUTOBAN_INCLUDE_PRIVATE=1` — also ban RFC1918/loopback (test only)
fn autoban_config() -> AutoBanConfig {
    static CFG: std::sync::OnceLock<AutoBanConfig> = std::sync::OnceLock::new();
    *CFG.get_or_init(|| {
        let threshold = std::env::var("SENTINEL_XDP_AUTOBAN_BLOCKS")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        let enabled = std::env::var("SENTINEL_XDP_AUTOBAN")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true)
            && threshold != Some(0);
        AutoBanConfig {
            enabled,
            threshold_blocks: threshold.unwrap_or(20).max(1),
            include_private: std::env::var("SENTINEL_XDP_AUTOBAN_INCLUDE_PRIVATE")
                .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false),
        }
    })
}

/// IPs already pushed to the eBPF blocklist by the auto-ban, so we ban + log
/// each offender once instead of on every subsequent block.
fn xdp_autobanned() -> &'static DashSet<std::net::IpAddr> {
    static SET: std::sync::OnceLock<DashSet<std::net::IpAddr>> = std::sync::OnceLock::new();
    SET.get_or_init(DashSet::new)
}

/// Whether an IP is eligible for auto-ban. Private/loopback/link-local/etc. are
/// excluded by default so the single-node demo (where every client appears as
/// the docker gateway) never bans itself; a real edge deployment sees public
/// client IPs and bans normally.
fn autoban_eligible(ip: std::net::IpAddr, include_private: bool) -> bool {
    use std::net::IpAddr;
    // Shared egress is never auto-banned, regardless of include_private. A corporate NAT
    // or CGNAT address is PUBLIC, so the private-range carve-out below does not cover it
    // — without this, one scanner behind an office NAT gets every colleague dropped in
    // the kernel. This check is first precisely because include_private would otherwise
    // bypass it.
    if is_shared_egress(ip) {
        return false;
    }
    if include_private {
        return !ip.is_unspecified();
    }
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let unique_local = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
            let link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
            !(v6.is_loopback() || v6.is_unspecified() || unique_local || link_local)
        }
    }
}

/// Record a WAF block against `ip` and, if it has crossed the auto-ban
/// threshold, push it to the eBPF/XDP blocklist (idempotent; logged once).
fn note_block(state: &ServerState, ip: std::net::IpAddr) {
    state.modules.correlation.record_block(ip);
    let ab = autoban_config();
    if !ab.enabled || !autoban_eligible(ip, ab.include_private) {
        return;
    }
    if state.modules.correlation.block_count_for_ip(ip) >= ab.threshold_blocks
        && xdp_autobanned().insert(ip)
    {
        state.ebpf.block_ip(ip);
        warn!(
            %ip,
            threshold = ab.threshold_blocks,
            mode = %state.ebpf.mode(),
            "auto-banned repeat offender — added to eBPF/XDP blocklist"
        );
    }
}

/// Seed the eBPF blocklist from operator-configured IP-reputation block CIDRs
/// (`waf.ip_reputation.block`). These are static, curated, low-volume bans, so
/// mirroring them into XDP drops those sources in-kernel from the first packet.
fn seed_ebpf_from_ip_reputation(ebpf: &EbpfManager, cfg: &SentinelConfig) {
    let mut seeded = 0usize;
    for site in &cfg.sites {
        let Some(rep) = site.waf.ip_reputation.as_ref() else {
            continue;
        };
        for cidr in &rep.block {
            if let Some(net) = parse_block_cidr(cidr) {
                ebpf.block_net(net);
                seeded += 1;
            }
        }
    }
    if seeded > 0 {
        info!(
            entries = seeded,
            "seeded eBPF blocklist from ip_reputation.block"
        );
    }
}

fn build_ip_reputation(cfg: &SentinelConfig, feed_cidrs: &[(String, Vec<String>)]) -> IpReputation {
    let configs: Vec<&IpReputationConfig> = cfg
        .sites
        .iter()
        .filter_map(|s| s.waf.ip_reputation.as_ref())
        .collect();
    let mut rep = IpReputation::from_configs(&configs);
    for (cidr, tags) in feed_cidrs {
        if let Err(e) = rep.add_suspect_cidr(cidr, tags.clone()) {
            warn!(cidr = %cidr, "feed: invalid CIDR skipped: {e}");
        }
    }
    if rep.entry_count() > 0 {
        info!(entries = rep.entry_count(), "IP reputation table built");
    }
    rep
}

fn build_geoip_map(cfg: &SentinelConfig) -> GeoIpMap {
    let mut map = GeoIpMap::new();
    for site in &cfg.sites {
        if let Some(ref gc) = site.waf.geoip {
            let geoip = GeoIp::from_path(
                &gc.db_path,
                gc.block_countries.clone(),
                gc.allow_countries.clone(),
            );
            map.insert(site.id.clone(), geoip);
        }
    }
    map
}

fn build_anti_ddos(cfg: &SentinelConfig) -> AntiDdos {
    for site in &cfg.sites {
        if let Some(ref dd) = site.waf.anti_ddos {
            if dd.enabled {
                return AntiDdos::new(dd);
            }
        }
    }
    AntiDdos::disabled()
}

fn target_name(t: &sentinel_rules::dsl::ast::Target) -> String {
    use sentinel_rules::dsl::ast::Target;
    match t {
        Target::Args => "ARGS".into(),
        Target::ArgsNames => "ARGS_NAMES".into(),
        Target::RequestBody => "REQUEST_BODY".into(),
        Target::RequestUri => "REQUEST_URI".into(),
        Target::RequestFilename => "REQUEST_FILENAME".into(),
        Target::RequestMethod => "REQUEST_METHOD".into(),
        Target::RequestLine => "REQUEST_LINE".into(),
        Target::RequestHeaders(None) => "REQUEST_HEADERS".into(),
        Target::RequestHeaders(Some(h)) => format!("REQUEST_HEADERS:{h}"),
        Target::RequestCookies(None) => "REQUEST_COOKIES".into(),
        Target::RequestCookies(Some(c)) => format!("REQUEST_COOKIES:{c}"),
        Target::ResponseHeaders(None) => "RESPONSE_HEADERS".into(),
        Target::ResponseHeaders(Some(h)) => format!("RESPONSE_HEADERS:{h}"),
        Target::ResponseBody => "RESPONSE_BODY".into(),
        Target::Files => "FILES".into(),
        Target::FilesNames => "FILES_NAMES".into(),
        Target::FilesCombinedSize => "FILES_COMBINED_SIZE".into(),
        Target::RemoteAddr => "REMOTE_ADDR".into(),
        Target::Geo => "GEO".into(),
        Target::TxVar(v) => format!("TX:{v}"),
        Target::CountOf(_) => "COUNT_OF".into(),
    }
}

fn load_site_engine(site: &SiteConfig) -> anyhow::Result<RuleEngine> {
    use sentinel_rules::dsl::ast::{RuleFile, RuleItem};

    let mut merged = RuleFile::default();
    for path_str in &site.waf.rules {
        let path = std::path::Path::new(path_str);
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("reading rule file '{path_str}'"))?;

        let file: RuleFile = if path.extension().and_then(|e| e.to_str()) == Some("conf") {
            let data_dir = path.parent();
            sentinel_rules::import_secrule_conf_dir(&source, data_dir)
                .with_context(|| format!("importing CRS conf '{path_str}'"))?
        } else {
            sentinel_rules::parse_srl(&source)
                .map_err(|e| anyhow!("SRL parse error in '{path_str}': {e}"))?
        };
        merged.items.extend(file.items);
    }

    // Paranoia level gating.
    let pl = site.waf.paranoia_level;
    let before = merged.items.len();
    merged.items.retain(|item| match item {
        RuleItem::Rule(rule) => {
            let rule_pl = rule
                .tags
                .iter()
                .find_map(|t| {
                    t.strip_prefix("paranoia-level/")
                        .and_then(|s| s.parse::<u8>().ok())
                })
                .unwrap_or(1);
            rule_pl <= pl
        }
        _ => true,
    });
    let filtered = before - merged.items.len();
    if filtered > 0 {
        info!(
            site = %site.id,
            paranoia_level = pl,
            filtered,
            "rule engine: paranoia level gating applied"
        );
    }

    // Whole-rule exclusions (disable). Applied first so a disabled rule is gone
    // regardless of any target-level entry for the same ID.
    let disabled_ids: std::collections::HashSet<u32> = site
        .waf
        .rule_exclusions
        .iter()
        .filter(|e| e.disable)
        .map(|e| e.rule_id)
        .collect();
    if !disabled_ids.is_empty() {
        let before = merged.items.len();
        merged.items.retain(|item| match item {
            RuleItem::Rule(rule) => !disabled_ids.contains(&rule.id),
            _ => true,
        });
        debug!(
            site = %site.id,
            removed = before - merged.items.len(),
            disabled_ids = ?disabled_ids,
            "whole-rule exclusions applied"
        );
    }

    // Rule target exclusions.
    for exclusion in &site.waf.rule_exclusions {
        if exclusion.disable || exclusion.exclude_targets.is_empty() {
            continue;
        }
        let excl_upper: Vec<String> = exclusion
            .exclude_targets
            .iter()
            .map(|t| t.to_ascii_uppercase())
            .collect();
        for item in &mut merged.items {
            if let RuleItem::Rule(rule) = item {
                if rule.id == exclusion.rule_id {
                    let before_len = rule.targets.len();
                    rule.targets.retain(|t| {
                        !excl_upper.contains(&target_name(&t.target).to_ascii_uppercase())
                    });
                    if rule.targets.len() < before_len {
                        debug!(
                            site = %site.id,
                            rule_id = exclusion.rule_id,
                            excluded = ?excl_upper,
                            "rule exclusion applied"
                        );
                    }
                }
            }
        }
    }

    sentinel_rules::compile(merged)
        .map(RuleEngine::new)
        .with_context(|| format!("compiling rules for site '{}'", site.id))
}

fn build_plugin_runtime(cfg: &SentinelConfig) -> anyhow::Result<PluginRuntime> {
    let mut rt = PluginRuntime::new()?;
    let mut loaded = 0usize;
    let mut failed = 0usize;
    for site in &cfg.sites {
        for manifest_path in &site.waf.plugins {
            match rt.load_from_manifest(std::path::Path::new(manifest_path)) {
                Ok(()) => loaded += 1,
                Err(e) => {
                    warn!(site = %site.id, path = %manifest_path, "plugin load failed: {e:#}");
                    failed += 1;
                }
            }
        }
    }
    if loaded > 0 || failed > 0 {
        info!(loaded, failed, "plugin runtime built");
    }
    Ok(rt)
}

// ---------------------------------------------------------------------------
// IP feed loader helpers
// ---------------------------------------------------------------------------

async fn fetch_feed_cidrs(url: &str) -> anyhow::Result<Vec<String>> {
    if let Some(path) = url.strip_prefix("file://") {
        let text = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("reading file feed: {path}"))?;
        return Ok(parse_cidr_text(&text));
    }

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, http_body_util::combinators::BoxBody<Bytes, hyper::Error>> =
        Client::builder(TokioExecutor::new()).build(https);

    let uri: Uri = url
        .parse()
        .with_context(|| format!("invalid feed URL: {url}"))?;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("User-Agent", "sentinel-waf/1.0 ip-reputation-feed-fetcher")
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .context("building feed request")?;

    let resp = tokio::time::timeout(Duration::from_secs(30), client.request(req))
        .await
        .context("feed request timed out after 30s")?
        .context("feed HTTP request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("feed returned HTTP {}", resp.status());
    }

    let body = resp
        .collect()
        .await
        .context("reading feed body")?
        .to_bytes();
    let text = std::str::from_utf8(&body).context("feed body is not valid UTF-8")?;
    Ok(parse_cidr_text(text))
}

fn parse_cidr_text(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constant-time byte comparison to avoid leaking the shared secret via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Permit the otherwise loopback-only internal cert API when the caller presents
/// the shared internal secret (env `SENTINEL_INTERNAL_SECRET`) via the
/// `X-Sentinel-Internal` header. This lets the control plane reach the data
/// plane across containers. Returns false when the secret is unset/empty.
fn internal_auth_ok(headers: &http::HeaderMap) -> bool {
    match std::env::var("SENTINEL_INTERNAL_SECRET") {
        Ok(secret) if !secret.is_empty() => headers
            .get("x-sentinel-internal")
            .and_then(|v| v.to_str().ok())
            .map(|got| constant_time_eq(got.as_bytes(), secret.as_bytes()))
            .unwrap_or(false),
        _ => false,
    }
}

// Wildcard host matching indexes the domain by byte offset after a "*." check;
// keep the explicit slicing rather than strip_prefix — it is security-sensitive
// and the manual form is unambiguous.
#[allow(clippy::manual_strip)]
fn site_matches(site: &SiteConfig, host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    site.domains.iter().any(|d| {
        let d_lc = d.to_ascii_lowercase();
        if d_lc.starts_with("*.") {
            let suffix = &d_lc[1..];
            host_lc.ends_with(suffix) || host_lc == d_lc[2..]
        } else {
            d_lc == host_lc
        }
    })
}

fn build_upstream_uri(host: &str, port: u16, tls: bool, original: &Uri) -> anyhow::Result<Uri> {
    let scheme = if tls { "https" } else { "http" };
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let s = format!("{scheme}://{}:{}{}", host, port, path_and_query);
    s.parse().context("building upstream URI")
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Return `true` when the request carries a valid WebSocket upgrade handshake.
fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    let upgrade = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let connection = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    upgrade.to_ascii_lowercase().contains("websocket")
        && connection.to_ascii_lowercase().contains("upgrade")
}

fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    if let Some(conn) = headers
        .remove(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok().map(str::to_owned))
    {
        for token in conn.split(',') {
            headers.remove(token.trim());
        }
    }
}

/// Strip hop-by-hop headers but preserve `Upgrade` and `Connection` so that
/// WebSocket upgrade handshakes pass through to the upstream correctly.
fn strip_hop_by_hop_except_upgrade(headers: &mut http::HeaderMap) {
    const PRESERVE: &[&str] = &[
        "upgrade",
        "connection",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        "sec-websocket-protocol",
    ];
    for name in HOP_BY_HOP {
        if !PRESERVE.contains(name) {
            headers.remove(*name);
        }
    }
}

fn inject_forwarding_headers(
    headers: &mut http::HeaderMap,
    client_ip: IpAddr,
) -> anyhow::Result<()> {
    let ip_str = client_ip.to_string();
    if let Some(existing) = headers.get(header::HeaderName::from_static("x-forwarded-for")) {
        let val = format!("{}, {}", existing.to_str().unwrap_or(""), ip_str);
        headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            val.parse()?,
        );
    } else {
        headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            ip_str.parse()?,
        );
    }
    headers.insert(
        header::HeaderName::from_static("x-real-ip"),
        client_ip.to_string().parse()?,
    );
    Ok(())
}

fn inject_security_headers(headers: &mut http::HeaderMap, cfg: Option<&SecurityHeadersConfig>) {
    // Secure defaults — only when the upstream didn't already set them.
    let default = |h: &mut http::HeaderMap, name: &'static str, value: &str| {
        if let Ok(v) = http::HeaderValue::from_str(value) {
            h.entry(header::HeaderName::from_static(name)).or_insert(v);
        }
    };
    default(headers, "x-content-type-options", "nosniff");
    default(headers, "x-frame-options", "SAMEORIGIN");
    default(headers, "x-xss-protection", "1; mode=block");

    // Referrer-Policy / Permissions-Policy: force the operator's value when
    // configured, otherwise fall back to a secure default.
    let force = |h: &mut http::HeaderMap, name: &'static str, value: &str| {
        if let Ok(v) = http::HeaderValue::from_str(value) {
            h.insert(header::HeaderName::from_static(name), v);
        }
    };
    match cfg
        .and_then(|c| c.referrer_policy.as_deref())
        .filter(|s| !s.is_empty())
    {
        Some(rp) => force(headers, "referrer-policy", rp),
        None => default(
            headers,
            "referrer-policy",
            "strict-origin-when-cross-origin",
        ),
    }
    match cfg
        .and_then(|c| c.permissions_policy.as_deref())
        .filter(|s| !s.is_empty())
    {
        Some(pp) => force(headers, "permissions-policy", pp),
        None => default(
            headers,
            "permissions-policy",
            "geolocation=(), microphone=(), camera=()",
        ),
    }

    let Some(cfg) = cfg else { return };

    // CSP has no default (it can break apps) — emit only when configured.
    if let Some(csp) = cfg
        .content_security_policy
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        if let Ok(v) = http::HeaderValue::from_str(csp) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v);
        }
    }
    // CORS allow-origin.
    if let Some(cors) = &cfg.cors {
        if cors.enabled && !cors.allow_origin.is_empty() {
            if let Ok(v) = http::HeaderValue::from_str(&cors.allow_origin) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }
        }
    }
    // Operator-defined custom headers, applied last so they win.
    for h in &cfg.custom {
        if h.name.is_empty() {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            header::HeaderName::from_bytes(h.name.as_bytes()),
            http::HeaderValue::from_str(&h.value),
        ) {
            headers.insert(name, val);
        }
    }
}

/// Build the HTTP response for a `Challenge` decision: either the interstitial
/// Proof-of-Work page, or (when the client submitted a valid proof) a 302 that
/// sets the clearance cookie and bounces back to the original URL.
///
/// Returns `None` when the request must proceed to origin instead of receiving
/// a challenge response — either because the client already holds valid
/// clearance, or because a Proof-of-Work grant was consumed in-line for an
/// unsafe method (see below).
///
/// `mode` is the site's configured challenge backend. Only `NativePow` is
/// implemented today; a configured third-party CAPTCHA provider is logged once
/// and falls back to native Proof-of-Work rather than being silently ignored.
///
/// On a grant we normally 302 back to the original URL. That is correct for
/// safe methods (GET/HEAD) but downgrades a challenged POST/PUT to a bodyless
/// GET — the form submission is silently lost. For unsafe methods we instead
/// stash the clearance cookies on `ctx` and return `None`, letting the request
/// continue to origin with its method and body intact; the cookies are attached
/// to the origin response by the caller.
async fn challenge_response(
    ctx: &mut RequestContext,
    mode: ChallengeMode,
    bot: Option<&BotDetectionConfig>,
) -> Option<Response<BoxBody>> {
    // Third-party interactive CAPTCHA path (reCAPTCHA / hCaptcha / Turnstile).
    // Requires configured provider credentials; otherwise we fall through to the
    // native Proof-of-Work challenge so the client is never left un-challenged.
    if let Some(kind) = captcha::CaptchaKind::from_mode(mode) {
        let provider = bot.and_then(|b| kind.provider(b));
        match provider {
            Some(p) if !p.sitekey.is_empty() && !p.secret.is_empty() => {
                // Already cleared (any subsystem) → don't re-challenge.
                if challenge::clearance_valid(&ctx.request_headers, ctx.client_ip) {
                    return None;
                }
                // A token from a prior solve → verify it server-side (single-use).
                if let Some(token) = challenge::captcha_token(&ctx.request_headers) {
                    let ok = captcha::verify(
                        kind,
                        &p.secret,
                        &token,
                        &ctx.client_ip.to_string(),
                        p.score,
                    )
                    .await;
                    if ok {
                        let set_cookie = challenge::clearance_cookie(ctx.client_ip);
                        let expire = challenge::expire_captcha_cookie();
                        let safe = matches!(ctx.method, http::Method::GET | http::Method::HEAD);
                        if !safe {
                            ctx.pending_set_cookies.push(set_cookie);
                            ctx.pending_set_cookies.push(expire);
                            return None;
                        }
                        let location = ctx
                            .uri
                            .path_and_query()
                            .map(|p| p.as_str().to_string())
                            .unwrap_or_else(|| "/".to_string());
                        return Some(
                            Response::builder()
                                .status(StatusCode::FOUND)
                                .header(header::LOCATION, location)
                                .header(header::SET_COOKIE, set_cookie)
                                .header(header::SET_COOKIE, expire)
                                .header(header::CACHE_CONTROL, "no-store")
                                .body(
                                    Full::new(Bytes::new())
                                        .map_err(|never: Infallible| match never {})
                                        .boxed(),
                                )
                                .unwrap(),
                        );
                    }
                    // Verification failed → expire the bad token and re-serve.
                    ctx.pending_set_cookies
                        .push(challenge::expire_captcha_cookie());
                }
                return Some(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .header(header::CACHE_CONTROL, "no-store")
                        .header("X-Sentinel-Challenge", "captcha")
                        .body(
                            Full::new(Bytes::from(captcha::interstitial(kind, &p.sitekey)))
                                .map_err(|never: Infallible| match never {})
                                .boxed(),
                        )
                        .unwrap(),
                );
            }
            _ => warn_captcha_misconfigured(mode),
        }
    }
    match challenge::resolve(&ctx.request_headers, ctx.client_ip, &ctx.uri) {
        challenge::Outcome::Pass => None,
        challenge::Outcome::Grant {
            location,
            set_cookie,
            expire_pow,
        } => {
            // Idempotent/safe methods can take the clean 302 redirect.
            let safe = matches!(ctx.method, http::Method::GET | http::Method::HEAD);
            if !safe {
                ctx.pending_set_cookies.push(set_cookie);
                ctx.pending_set_cookies.push(expire_pow);
                return None;
            }
            Some(
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, location)
                    .header(header::SET_COOKIE, set_cookie)
                    .header(header::SET_COOKIE, expire_pow)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(
                        Full::new(Bytes::new())
                            .map_err(|never: Infallible| match never {})
                            .boxed(),
                    )
                    .unwrap(),
            )
        }
        challenge::Outcome::Serve { html } => Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-store")
                .header("X-Sentinel-Challenge", "pow")
                .body(
                    Full::new(Bytes::from(html))
                        .map_err(|never: Infallible| match never {})
                        .boxed(),
                )
                .unwrap(),
        ),
    }
}

/// Warn at most once per provider that a third-party CAPTCHA mode is selected
/// but its site key / secret are missing, so native Proof-of-Work is served
/// instead (fail-safe — a suspicious client is still challenged).
fn warn_captcha_misconfigured(mode: ChallengeMode) {
    use std::sync::atomic::{AtomicU8, Ordering};
    static WARNED: AtomicU8 = AtomicU8::new(0);
    let bit = match mode {
        ChallengeMode::Recaptcha => 0b001,
        ChallengeMode::Hcaptcha => 0b010,
        ChallengeMode::Turnstile => 0b100,
        _ => return,
    };
    if WARNED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        warn!(
            "challenge mode {:?} selected but sitekey/secret missing; serving native Proof-of-Work instead",
            mode
        );
    }
}

/// Response for a LIMIT verdict (weighted fusion soft-deny). Uses the site's
/// configured `limit_status` (default 429 Too Many Requests).
fn limit_response(ctx: &RequestContext, site: Option<&SiteConfig>) -> Response<BoxBody> {
    let status = site
        .and_then(|s| s.waf.fusion.as_ref())
        .and_then(|f| StatusCode::from_u16(f.limit_status).ok())
        .unwrap_or(StatusCode::TOO_MANY_REQUESTS);
    let reason = ctx
        .block_reason
        .as_deref()
        .unwrap_or("Request rate-limited by Sentinel WAF");
    error_response(status, reason)
}

fn block_response(ctx: &RequestContext) -> Response<BoxBody> {
    let reason = ctx
        .block_reason
        .as_deref()
        .unwrap_or("Blocked by Sentinel WAF");
    let body = serde_json::json!({
        "error": "Forbidden",
        "message": reason,
        "request_id": ctx.request_id.to_string(),
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Internal certificate-management API.  Loopback-only (enforced by the caller).
///
/// Routes:
///   GET    /api/v1/internal/certs                 → list cert metadata
///   POST   /api/v1/internal/certs/manual          → install operator-supplied PEM
///   POST   /api/v1/internal/certs/acme            → issue/renew via ACME (blocking)
///   POST   /api/v1/internal/certs/{domain}/renew  → force ACME re-issue
///   DELETE /api/v1/internal/certs/{domain}        → remove cert
/// Cert keys beginning with "__" are reserved for internal use (e.g. the
/// management cert "__management__"). The customer cert repository API must not
/// be able to create, overwrite, rename, or delete them — that's the Management
/// TLS API's job, which is separately RBAC-gated. This closes a privilege gap
/// where a Site:Update editor could otherwise hijack the management cert.
fn is_reserved_cert_key(domain: &str) -> bool {
    domain.trim().starts_with("__")
}

async fn handle_internal_cert_api(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // GET list — no body needed.
    if method == hyper::Method::GET && path == "/api/v1/internal/certs" {
        let meta = state.cert_manager.store.all_meta();
        let json = serde_json::to_string(&meta).unwrap_or_else(|_| "[]".to_string());
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(Bytes::from(json)))
            .unwrap();
    }

    // DELETE /api/v1/internal/certs/{domain}
    if method == hyper::Method::DELETE {
        if let Some(domain) = path.strip_prefix("/api/v1/internal/certs/") {
            let domain = domain.trim_end_matches('/');
            if is_reserved_cert_key(domain) {
                return json_err(
                    StatusCode::FORBIDDEN,
                    "reserved certificate key — use the Management TLS API",
                );
            }
            return match state.cert_manager.store.remove(domain) {
                Ok(()) => json_ok(serde_json::json!({"removed": domain})),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
            };
        }
    }

    // From here on we need the request body.
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("body read failed: {e}")),
    };

    // POST /api/v1/internal/certs/manual  { domain, name?, cert_pem, key_pem }
    if method == hyper::Method::POST && path == "/api/v1/internal/certs/manual" {
        #[derive(serde::Deserialize)]
        struct ManualReq {
            domain: String,
            #[serde(default)]
            name: String,
            cert_pem: String,
            key_pem: String,
        }
        let r: ManualReq = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
        };
        if is_reserved_cert_key(&r.domain) {
            return json_err(
                StatusCode::FORBIDDEN,
                "reserved certificate key — use the Management TLS API",
            );
        }
        return match state
            .cert_manager
            .install_manual(&r.domain, &r.name, &r.cert_pem, &r.key_pem)
        {
            Ok(()) => json_ok(serde_json::json!({"installed": r.domain})),
            Err(e) => json_err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        };
    }

    // PATCH /api/v1/internal/certs/{domain}  { name }  — set friendly profile name
    if method == hyper::Method::PATCH {
        if let Some(rest) = path.strip_prefix("/api/v1/internal/certs/") {
            let domain = rest.trim_end_matches('/');
            if is_reserved_cert_key(domain) {
                return json_err(
                    StatusCode::FORBIDDEN,
                    "reserved certificate key — use the Management TLS API",
                );
            }
            #[derive(serde::Deserialize)]
            struct RenameReq {
                name: String,
            }
            let r: RenameReq = match serde_json::from_slice(&body_bytes) {
                Ok(r) => r,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
            };
            return match state.cert_manager.store.set_name(domain, &r.name) {
                Ok(()) => json_ok(serde_json::json!({"renamed": domain, "name": r.name})),
                Err(e) => json_err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
            };
        }
    }

    // POST /api/v1/internal/certs/acme  { domains:[..], email, provider, challenge, renew_before_days? }
    // POST /api/v1/internal/certs/{domain}/renew  (re-uses the matching site's ACME config)
    if method == hyper::Method::POST
        && (path == "/api/v1/internal/certs/acme" || path.ends_with("/renew"))
    {
        use sentinel_core::config::{AcmeChallengeType, AcmeProvider, SiteAcmeConfig};

        let (domains, acme_cfg) = if path.ends_with("/renew") {
            // Look up the site whose TLS config owns this domain.
            let domain = path
                .strip_prefix("/api/v1/internal/certs/")
                .and_then(|s| s.strip_suffix("/renew"))
                .unwrap_or("")
                .to_string();
            let cfg = state.config.load();
            let site = cfg
                .sites
                .iter()
                .find(|s| s.domains.iter().any(|d| d == &domain) && s.tls.acme.is_some());
            match site {
                Some(s) => (s.domains.clone(), s.tls.acme.clone().unwrap()),
                None => {
                    return json_err(
                        StatusCode::NOT_FOUND,
                        "no ACME-configured site owns that domain",
                    )
                }
            }
        } else {
            #[derive(serde::Deserialize)]
            struct AcmeReq {
                domains: Vec<String>,
                email: String,
                #[serde(default)]
                provider: Option<String>,
                #[serde(default)]
                challenge: Option<String>,
                #[serde(default)]
                renew_before_days: Option<u32>,
            }
            let r: AcmeReq = match serde_json::from_slice(&body_bytes) {
                Ok(r) => r,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
            };
            if r.domains.is_empty() {
                return json_err(StatusCode::BAD_REQUEST, "domains must not be empty");
            }
            let provider = match r.provider.as_deref() {
                Some("letsencrypt_staging") | Some("staging") => AcmeProvider::LetsEncryptStaging,
                Some("zerossl") => AcmeProvider::ZeroSsl,
                _ => AcmeProvider::LetsEncrypt,
            };
            let challenge = match r.challenge.as_deref() {
                Some("tls_alpn_01") | Some("tls-alpn-01") => AcmeChallengeType::TlsAlpn01,
                _ => AcmeChallengeType::Http01,
            };
            let cfg = SiteAcmeConfig {
                email: r.email,
                provider,
                challenge,
                renew_before_days: r.renew_before_days.unwrap_or(30),
            };
            (r.domains, cfg)
        };

        return match state
            .cert_manager
            .issue_acme(domains.clone(), &acme_cfg)
            .await
        {
            Ok(()) => json_ok(serde_json::json!({"issued": domains})),
            Err(e) => json_err(
                StatusCode::BAD_GATEWAY,
                &format!("ACME issuance failed: {e:#}"),
            ),
        };
    }

    json_err(StatusCode::NOT_FOUND, "unknown cert endpoint")
}

// ---------------------------------------------------------------------------
// Management listener: reverse-proxy the admin console (our own engine)
// ---------------------------------------------------------------------------

/// Reverse-proxy a request arriving on the management listener. Path `/api/*`
/// (REST + SSE) goes to the control plane; everything else to the dashboard.
/// Bodies stream in both directions, so Server-Sent Events are unbuffered.
async fn handle_management_request(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<Incoming>,
    mgmt: Arc<ManagementUpstreams>,
) -> Result<Response<BoxBody>, Infallible> {
    let path = req.uri().path();
    // Never expose the control plane's unauthenticated internal endpoints (e.g.
    // /api/v1/internal/config, which leaks upstream topology) through the public
    // management console. The admin UI only needs /api/v1/<feature> routes.
    if path.starts_with("/api/v1/internal") {
        return Ok(error_response(StatusCode::NOT_FOUND, "not found"));
    }
    let base = if path.starts_with("/api/") {
        &mgmt.api
    } else {
        &mgmt.dashboard
    };
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target = format!("{base}{pq}");
    let target_uri: Uri = match target.parse() {
        Ok(u) => u,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("bad management target: {e}"),
            ))
        }
    };

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    // This listener is directly client-facing (no trusted forwarder in front),
    // so RESET the forwarding headers to the real peer — never trust a
    // client-supplied X-Forwarded-For chain (it would spoof the audit-logged IP).
    let peer_ip = peer.ip().to_string();
    if let Ok(hv) = header::HeaderValue::from_str(&peer_ip) {
        parts.headers.insert(
            header::HeaderName::from_static("x-forwarded-for"),
            hv.clone(),
        );
        parts
            .headers
            .insert(header::HeaderName::from_static("x-real-ip"), hv);
    }
    // The management listener terminates TLS; tell the upstream the original
    // scheme so the dashboard/control plane generate correct https URLs/cookies.
    parts.headers.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        header::HeaderValue::from_static("https"),
    );
    // Set Host to the upstream authority so behavior doesn't depend on the
    // client-supplied Host or undocumented client Host-derivation.
    if let Some(auth) = target_uri.authority() {
        if let Ok(hv) = header::HeaderValue::from_str(auth.as_str()) {
            parts.headers.insert(header::HOST, hv);
        }
    }
    parts.uri = target_uri;
    parts.version = http::Version::HTTP_11;
    let upstream_req = Request::from_parts(parts, body.boxed());

    match state.upstream_pool.forward(upstream_req).await {
        Ok(resp) => {
            let (rp, rb) = resp.into_parts();
            Ok(Response::from_parts(rp, rb.boxed()))
        }
        Err(e) => Ok(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("management upstream unreachable: {e}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Internal management-TLS API (control-plane bridge)
//
//   GET    /api/v1/internal/management-tls   → current management cert metadata
//   POST   /api/v1/internal/management-tls   → install validated PEM (hot-swap)
//   DELETE /api/v1/internal/management-tls   → revert to self-signed default
// ---------------------------------------------------------------------------

async fn handle_internal_mgmt_tls_api(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let method = req.method().clone();

    if method == hyper::Method::GET {
        return match state.cert_manager.store.get_meta(tls::MANAGEMENT_CERT_KEY) {
            Some(m) => {
                let mut v = serde_json::to_value(&m).unwrap_or_else(|_| serde_json::json!({}));
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("self_signed".to_string(), serde_json::json!(false));
                }
                json_ok(v)
            }
            None => json_ok(serde_json::json!({"self_signed": true})),
        };
    }

    if method == hyper::Method::DELETE {
        return match state.cert_manager.store.revert_management() {
            Ok(()) => json_ok(serde_json::json!({"reverted": true})),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}")),
        };
    }

    if method == hyper::Method::POST {
        let body_bytes = match req.into_body().collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("body read failed: {e}")),
        };
        #[derive(serde::Deserialize)]
        struct MgmtReq {
            cert_pem: String,
            key_pem: String,
            #[serde(default)]
            name: String,
            #[serde(default)]
            subject: String,
            #[serde(default)]
            issuer: String,
            #[serde(default)]
            san: Vec<String>,
            #[serde(default)]
            issued_at: u64,
            #[serde(default)]
            expires_at: u64,
            #[serde(default)]
            fingerprint: String,
            #[serde(default)]
            key_type: String,
        }
        let r: MgmtReq = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
        };
        let display_name = if r.name.is_empty() {
            if r.subject.is_empty() {
                "Management TLS".to_string()
            } else {
                r.subject.clone()
            }
        } else {
            r.name
        };
        let meta = tls::CertMeta {
            domain: tls::MANAGEMENT_CERT_KEY.to_string(),
            name: display_name,
            san: r.san,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            fingerprint: r.fingerprint,
            source: tls::CertSource::Manual,
            issuer: r.issuer,
            key_type: r.key_type,
        };
        return match state
            .cert_manager
            .store
            .install_management(&r.cert_pem, &r.key_pem, meta)
        {
            Ok(prev) => {
                json_ok(serde_json::json!({"installed": true, "previous_fingerprint": prev}))
            }
            Err(e) => json_err(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        };
    }

    json_err(StatusCode::METHOD_NOT_ALLOWED, "unsupported method")
}

fn json_ok(value: serde_json::Value) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(value.to_string())))
        .unwrap()
}

fn json_err(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = serde_json::json!({"error": message}).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body)))
        .unwrap()
}

fn health_response(state: &ServerState) -> Response<BoxBody> {
    use std::time::SystemTime;

    let cfg = state.config.load();
    let site_count = cfg.sites.len();
    let listeners: Vec<String> = cfg
        .listeners
        .iter()
        .map(|l| format!("{}:{}", l.name, l.bind))
        .collect();

    // HTTP/3 summary for the dashboard status card. Mirrors the enable logic in
    // `serve_listener`: h3 is offered on a TLS, non-management listener whose
    // protocol set includes Http3. The advertised UDP port is what browsers
    // reach (SENTINEL_HTTP3_ADVERTISE_PORT, else the listener's bind port).
    let h3_listener = cfg
        .listeners
        .iter()
        .find(|l| l.is_tls() && !l.is_management() && l.protocols().contains(&Protocol::Http3));
    let http3 = match h3_listener {
        Some(l) => {
            let bind_port = l.bind.parse::<SocketAddr>().map(|a| a.port()).unwrap_or(0);
            let advertise_port = std::env::var("SENTINEL_HTTP3_ADVERTISE_PORT")
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(bind_port);
            serde_json::json!({
                "enabled": true,
                "listener": l.name,
                "bind": l.bind,
                "advertise_port": advertise_port,
            })
        }
        None => serde_json::json!({ "enabled": false }),
    };

    let pool_stats = state.upstream_pool.stats();
    let start = *START_TIME.get_or_init(SystemTime::now);
    let uptime_secs = start.elapsed().unwrap_or_default().as_secs();

    let body = serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
        "sites": site_count,
        "listeners": listeners,
        "http3": http3,
        "upstreams_healthy": pool_stats.healthy,
        "upstreams_total": pool_stats.total,
        "version": env!("CARGO_PKG_VERSION"),
    })
    .to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .unwrap()
}

// Kubernetes readiness: 200 only when the WAF config has synced (sites > 0),
// otherwise 503. Cheap and self-contained (no upstream hit) so kubelet can poll
// it every second. Distinct from /healthz, which is liveness — a node whose
// process is up but hasn't synced rules is live-but-not-ready.
fn readyz_response(state: &ServerState) -> Response<BoxBody> {
    let site_count = state.config.load().sites.len();
    let draining = state.draining.load(std::sync::atomic::Ordering::Relaxed);
    let ready = site_count > 0 && !draining;
    let (status, body) = if ready {
        (
            StatusCode::OK,
            serde_json::json!({ "status": "ready", "sites": site_count }),
        )
    } else {
        let reason = if draining {
            "draining"
        } else {
            "config not synced"
        };
        (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({ "status": "not_ready", "reason": reason, "sites": site_count }),
        )
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

// Server start time — captured once, shared across health responses.
static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

fn full_body(bytes: Bytes) -> BoxBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(full_body(Bytes::from(message.to_string())))
        .unwrap()
}

/// `GET /metrics` — the global WAF metrics registry rendered in Prometheus text
/// exposition format. Content-Type follows the Prometheus text format spec so
/// scrapers parse it without a manual override.
fn metrics_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(full_body(Bytes::from(prometheus_text())))
        .unwrap()
}

/// Load-shed response returned when the global in-flight request limit is
/// saturated. `503` + `Retry-After: 1` tells well-behaved clients and upstream
/// load balancers to back off and retry rather than hammer an overloaded node.
fn overloaded_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(header::RETRY_AFTER, "1")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(full_body(Bytes::from_static(
            b"503 Service Unavailable: server at capacity\n",
        )))
        .unwrap()
}

fn log_request(ctx: &RequestContext) {
    let status = ctx.response_status.map(|s| s.as_u16()).unwrap_or(0);
    let rule_ids: Vec<&str> = ctx
        .rule_matches
        .iter()
        .take(8)
        .map(|m| m.rule_id.as_str())
        .collect();
    tracing::info!(
        request_id = %ctx.request_id,
        method = %ctx.method,
        uri = %ctx.uri,
        client_ip = %ctx.client_ip,
        site = ctx.site_id.as_deref().unwrap_or("-"),
        status,
        latency_ms = ctx.elapsed_ms(),
        ja4 = ctx.tls_fingerprint.as_deref().unwrap_or("-"),
        anomaly_score = ctx.anomaly_score,
        rule_matches = ctx.rule_matches.len(),
        rule_ids = rule_ids.join(","),
        decision = ?ctx.decision,
        block_reason = ctx.block_reason.as_deref().unwrap_or(""),
        "request"
    );
    ndjson_log(ctx);

    // Feed the per-second traffic accumulator (drained by the ClickHouse
    // flusher, when ClickHouse is configured). Cheap; no-op when CH is off.
    let blocked = matches!(ctx.decision, WafDecision::Block | WafDecision::Challenge);
    record_traffic(
        ctx.tenant_id.as_deref().unwrap_or(""),
        ctx.site_id.as_deref().unwrap_or("-"),
        blocked,
        ctx.elapsed_ms(),
    );
    record_event(ctx);
}

// ---------------------------------------------------------------------------
// Per-second traffic accumulator → ClickHouse traffic_buckets
// ---------------------------------------------------------------------------

/// Upper bounds (ms) of the per-site latency buckets. Mirrors the telemetry
/// histogram's bounds so a site's p99 is comparable to the global one.
const SITE_LAT_BOUNDS: [f64; 15] = [
    0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10_000.0,
    30_000.0,
];
const SITE_LAT_BUCKETS: usize = SITE_LAT_BOUNDS.len() + 1;

/// Per-(tenant,site) counters for the current rollup window.
///
/// Every field is atomic so recording needs no exclusive access. Previously this
/// struct was plain `u64`/`Vec<f64>` behind ONE process-wide
/// `Mutex<HashMap<..>>`: with ClickHouse enabled every request serialized through
/// that single lock, and each also pushed onto a `Vec` (up to 4096 f64s per site)
/// that had to be sorted on every drain.
struct SiteAccum {
    reqs: AtomicU64,
    blocked: AtomicU64,
    /// Latency distribution as fixed buckets — bounded memory, no sorting, and no
    /// per-site sample cap to distort p99 under load.
    lat: [AtomicU64; SITE_LAT_BUCKETS],
}

impl SiteAccum {
    fn new() -> Self {
        Self {
            reqs: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            lat: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn record(&self, blocked: bool, latency_ms: f64) {
        self.reqs.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        }
        if latency_ms > 0.0 {
            let idx = SITE_LAT_BOUNDS
                .iter()
                .position(|b| latency_ms <= *b)
                .unwrap_or(SITE_LAT_BUCKETS - 1);
            self.lat[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Atomically take and reset this window's tallies, returning
    /// `(reqs, blocked, p99_ms)`.
    fn take(&self) -> (u64, u64, f64) {
        let reqs = self.reqs.swap(0, Ordering::Relaxed);
        let blocked = self.blocked.swap(0, Ordering::Relaxed);
        let counts: [u64; SITE_LAT_BUCKETS] =
            std::array::from_fn(|i| self.lat[i].swap(0, Ordering::Relaxed));

        let total: u64 = counts.iter().sum();
        if total == 0 {
            return (reqs, blocked, 0.0);
        }
        // Rank of the p99 observation, matching the previous ceil-based indexing.
        let target = (((total as f64) * 0.99).ceil() as u64).saturating_sub(1);
        let mut cumulative = 0u64;
        for (i, &c) in counts.iter().enumerate() {
            if c == 0 {
                continue;
            }
            if cumulative + c > target {
                // Report the bucket's upper bound: for a latency SLO an estimate
                // must never read lower than the samples it represents.
                return (
                    reqs,
                    blocked,
                    SITE_LAT_BOUNDS
                        .get(i)
                        .copied()
                        .unwrap_or(*SITE_LAT_BOUNDS.last().unwrap()),
                );
            }
            cumulative += c;
        }
        (reqs, blocked, *SITE_LAT_BOUNDS.last().unwrap())
    }
}

// Keyed by "tenant\0site" so per-tenant traffic never merges across tenants. A
// single string key (rather than a (String, String) tuple) lets the hot path look
// the entry up by &str, so a hit borrows instead of allocating. DashMap shards
// internally, so concurrent sites touch different locks.
static TRAFFIC_ACC: std::sync::OnceLock<dashmap::DashMap<String, SiteAccum>> =
    std::sync::OnceLock::new();

fn traffic_acc() -> &'static dashmap::DashMap<String, SiteAccum> {
    TRAFFIC_ACC.get_or_init(dashmap::DashMap::new)
}

thread_local! {
    /// Scratch buffer for the composite key, so building it allocates once per
    /// worker thread rather than once per request.
    static TRAFFIC_KEY_BUF: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Record one request into the current window's tally.
///
/// Lock-free with respect to other requests for the same site: only atomic adds,
/// under a DashMap shard read-guard.
fn record_traffic(tenant: &str, site: &str, blocked: bool, latency_ms: f64) {
    // No sink → no accumulation (the drainer only runs when ClickHouse is on).
    if !CLICKHOUSE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    TRAFFIC_KEY_BUF.with(|buf| {
        let mut key = buf.borrow_mut();
        key.clear();
        key.push_str(tenant);
        key.push('\0');
        key.push_str(site);

        // Fast path: entry exists, no allocation and no map mutation.
        if let Some(acc) = traffic_acc().get(key.as_str()) {
            acc.record(blocked, latency_ms);
            return;
        }
        // First request for this site in this process — allocate the owned key once.
        traffic_acc()
            .entry(key.clone())
            .or_insert_with(SiteAccum::new)
            .record(blocked, latency_ms);
    });
}

/// Drain the accumulator into one TrafficRow per site, stamped with `ts`.
///
/// Entries are reset in place rather than removed from the map. Removing them
/// would race with an in-flight `record_traffic` holding a reference to the entry,
/// silently discarding those requests; swapping each counter to zero cannot lose a
/// completed increment. The key set is bounded by the number of configured sites,
/// so retaining entries does not grow without bound.
fn drain_traffic(ts: i64) -> Vec<sentinel_storage::TrafficRow> {
    let acc = traffic_acc();
    let mut out = Vec::with_capacity(acc.len());
    for entry in acc.iter() {
        let (reqs, blocked, p99) = entry.value().take();
        // Nothing happened for this site in this window — emit no row rather than
        // a misleading all-zero one.
        if reqs == 0 {
            continue;
        }
        let (tenant, site) = match entry.key().split_once('\0') {
            Some((t, s)) => (t.to_string(), s.to_string()),
            None => continue,
        };
        out.push(sentinel_storage::TrafficRow {
            ts,
            tenant,
            site_id: site,
            reqs: reqs as i64,
            blocked: blocked as i64,
            p99_ms: p99,
        });
    }
    out
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// --- Detailed event buffer → ClickHouse waf_events ---

static WAF_EVENTS: std::sync::OnceLock<std::sync::Mutex<Vec<sentinel_storage::WafEventRow>>> =
    std::sync::OnceLock::new();

/// Set true once the ClickHouse flusher task is running. When ClickHouse is not
/// configured nothing ever drains the buffers, so we must not buffer at all —
/// otherwise the event buffer grows to its cap and is pinned in memory forever.
static CLICKHOUSE_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn waf_events() -> &'static std::sync::Mutex<Vec<sentinel_storage::WafEventRow>> {
    WAF_EVENTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Buffer one notable event (block or learning DETECT) for ClickHouse. Plain
/// passes are skipped to keep volume sane. Buffer is capped to bound memory if
/// ClickHouse is down/slow.
fn record_event(ctx: &RequestContext) {
    // No sink → no buffering (the drainer only runs when ClickHouse is enabled).
    if !CLICKHOUSE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let action = match ctx.decision {
        WafDecision::Block | WafDecision::Challenge => "BLOCK",
        _ if ctx.would_block => "DETECT",
        _ => return, // not notable — don't store
    };
    let top = ctx.rule_matches.first();
    // Tag non-rule blocks so waf_events stays queryable. A threat-intel block
    // carries no RuleMatch and its reason isn't otherwise persisted here, so
    // surface it as rule="THREATINTEL" with the reason in `attack`; other
    // non-rule blocks (geoip/rate-limit/smuggling) reuse classify_nonrule_block.
    // Key the THREATINTEL tag on the actual block reason, NOT ctx.threat_intel_hit:
    // a watch-tier IOC match sets threat_intel_hit=true without blocking, so a
    // later geoip/rate-limit/anomaly block on that same request must not be
    // mislabeled. A genuine threat-intel block always carries the "threat intel:"
    // reason prefix; everything else falls through to classify_nonrule_block.
    let (ev_rule, ev_attack) = match top {
        Some(r) => (r.rule_id.clone(), r.message.clone()),
        None if ctx
            .block_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("threat intel:")) =>
        {
            (
                "THREATINTEL".to_string(),
                ctx.block_reason.clone().unwrap_or_default(),
            )
        }
        None => {
            let (r, a) = classify_nonrule_block(ctx.block_reason.as_deref().unwrap_or(""));
            (r.to_string(), a.to_string())
        }
    };
    let row = sentinel_storage::WafEventRow {
        ts: unix_now(),
        ip: ctx.client_ip.to_string(),
        country: ctx.geo_country.clone().unwrap_or_default(), // set when GeoIP resolved a country
        site: ctx.site_id.clone().unwrap_or_else(|| "-".to_string()),
        tenant: ctx.tenant_id.clone().unwrap_or_default(),
        method: ctx.method.as_str().to_string(),
        path: ctx.uri.path().to_string(),
        rule: ev_rule,
        attack: ev_attack,
        action: action.to_string(),
        severity: top
            .map(|r| format!("{:?}", r.severity).to_uppercase())
            .unwrap_or_default(),
        score: ctx.anomaly_score,
        status: ctx.response_status.map(|s| s.as_u16()).unwrap_or(0),
        protocol: protocol_label(ctx.http_version).to_string(),
    };
    if let Ok(mut buf) = waf_events().lock() {
        if buf.len() < 20_000 {
            buf.push(row);
        }
    }
}

/// Drain up to all buffered events for flushing.
fn drain_events() -> Vec<sentinel_storage::WafEventRow> {
    match waf_events().lock() {
        Ok(mut buf) => std::mem::take(&mut *buf),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// NDJSON file logger
// ---------------------------------------------------------------------------

/// Resolve the NDJSON log directory. Order: `SENTINEL_LOG_DIR` env →
/// `$HOME/.local/share/sentinel/logs` (real disk, no root) → `/var/log/sentinel`.
/// Deliberately NOT `/tmp` — that is tmpfs (RAM) on most distros and would let
/// logs exhaust memory under sustained load.
fn resolve_log_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("SENTINEL_LOG_DIR") {
        if !d.is_empty() {
            return std::path::PathBuf::from(d);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return std::path::PathBuf::from(home).join(".local/share/sentinel/logs");
        }
    }
    std::path::PathBuf::from("/var/log/sentinel")
}

// ── Async NDJSON writer ──────────────────────────────────────────────────────
//
// Logging runs off the request hot path. Each request formats its line(s) and
// hands them to a single dedicated OS thread over a bounded channel; the thread
// is the sole writer, so it needs no lock, keeps file handles open (no per-line
// `open`/`metadata` syscall), tracks size in memory for rotation, and batches
// flushes. A full channel drops lines (and counts them) rather than blocking a
// tokio worker — under extreme load, shedding access-log lines beats stalling
// traffic.

struct LogRecord {
    name: &'static str,
    line: String,
}

static LOG_TX: std::sync::OnceLock<std::sync::mpsc::SyncSender<LogRecord>> =
    std::sync::OnceLock::new();
static LOG_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn log_sender() -> &'static std::sync::mpsc::SyncSender<LogRecord> {
    LOG_TX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<LogRecord>(65_536);
        std::thread::Builder::new()
            .name("sentinel-logwriter".into())
            .spawn(move || log_writer_loop(rx))
            .expect("spawn ndjson log writer");
        tx
    })
}

/// Hand a pre-formatted line to the writer thread. Non-blocking: drops (and
/// counts) when the queue is saturated so the request path never stalls on I/O.
fn enqueue_log(name: &'static str, line: String) {
    if log_sender().try_send(LogRecord { name, line }).is_err() {
        LOG_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A single rotating log stream owned by the writer thread. Holds an open handle
/// and tracks the on-disk size in memory, so writing a line costs no extra
/// syscall beyond the buffered write itself. Rotation shifts `name.{k-1}` →
/// `name.k` (dropping the oldest) and `name` → `name.1`; `keep == 0` discards the
/// file outright. Bounds on-disk size to `max_bytes * (keep + 1)` per stream.
struct RotatingFile {
    dir: std::path::PathBuf,
    name: &'static str,
    max_bytes: u64,
    keep: u32,
    size: u64,
    w: std::io::BufWriter<std::fs::File>,
}

impl RotatingFile {
    fn open(
        dir: &std::path::Path,
        name: &'static str,
        max_bytes: u64,
        keep: u32,
    ) -> std::io::Result<Self> {
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.join(name))?;
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            dir: dir.to_path_buf(),
            name,
            max_bytes,
            keep,
            size,
            w: std::io::BufWriter::new(f),
        })
    }

    fn write_line(&mut self, line: &str) {
        use std::io::Write;
        let n = line.len() as u64 + 1;
        if self.max_bytes > 0 && self.size + n > self.max_bytes {
            let _ = self.rotate();
        }
        if writeln!(self.w, "{line}").is_ok() {
            self.size += n;
        }
    }

    fn flush(&mut self) {
        use std::io::Write;
        let _ = self.w.flush();
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        let _ = self.w.flush(); // land buffered bytes in the file we're retiring
        let (dir, name, keep) = (&self.dir, self.name, self.keep);
        let path = dir.join(name);
        if keep == 0 {
            // Keep zero backups: discard the full file outright.
            let _ = std::fs::remove_file(&path);
        } else {
            let _ = std::fs::remove_file(dir.join(format!("{name}.{keep}")));
            for i in (1..keep).rev() {
                let from = dir.join(format!("{name}.{i}"));
                let to = dir.join(format!("{name}.{}", i + 1));
                if from.exists() {
                    let _ = std::fs::rename(&from, &to);
                }
            }
            let _ = std::fs::rename(&path, dir.join(format!("{name}.1")));
        }
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)?;
        self.w = std::io::BufWriter::new(f);
        self.size = 0;
        Ok(())
    }
}

/// The dedicated writer thread: resolve config once, then drain the channel,
/// batching writes and flushing per batch.
fn log_writer_loop(rx: std::sync::mpsc::Receiver<LogRecord>) {
    let dir = resolve_log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let max_bytes = std::env::var("SENTINEL_LOG_MAX_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(100)
        .saturating_mul(1024 * 1024);
    let keep = std::env::var("SENTINEL_LOG_KEEP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(5);

    let mut files: std::collections::HashMap<&'static str, RotatingFile> =
        std::collections::HashMap::new();
    let mut last_dropped = 0u64;

    let write_one = |files: &mut std::collections::HashMap<&'static str, RotatingFile>,
                     rec: LogRecord| {
        if !files.contains_key(rec.name) {
            match RotatingFile::open(&dir, rec.name, max_bytes, keep) {
                Ok(rf) => {
                    files.insert(rec.name, rf);
                }
                Err(_) => return, // can't open the file — drop the line
            }
        }
        if let Some(rf) = files.get_mut(rec.name) {
            rf.write_line(&rec.line);
        }
    };

    loop {
        let rec = match rx.recv() {
            Ok(r) => r,
            Err(_) => return, // all senders gone (process shutdown)
        };
        write_one(&mut files, rec);
        // Opportunistically drain whatever else is queued, then flush once.
        while let Ok(rec) = rx.try_recv() {
            write_one(&mut files, rec);
        }
        for f in files.values_mut() {
            f.flush();
        }
        let dropped = LOG_DROPPED.load(std::sync::atomic::Ordering::Relaxed);
        if dropped > last_dropped {
            warn!(
                dropped = dropped - last_dropped,
                total = dropped,
                "ndjson log writer: dropped lines (channel saturated)"
            );
            last_dropped = dropped;
        }
    }
}

/// File-based NDJSON logging is on by default; set `SENTINEL_NDJSON_LOG=0`
/// (or false/off) to disable it — useful when shipping events to ClickHouse
/// only, or when the synchronous per-request file write is a throughput limit.
fn ndjson_logging_enabled() -> bool {
    static EN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EN.get_or_init(|| {
        !matches!(
            std::env::var("SENTINEL_NDJSON_LOG").ok().as_deref(),
            Some("0") | Some("false") | Some("off")
        )
    })
}

/// Canonical short protocol label used everywhere protocol is surfaced — NDJSON
/// logs, the ClickHouse `waf_events.protocol` column, and the dashboard
/// filters/facets: HTTP/1.x → `h1`, HTTP/2 → `h2`, HTTP/3 → `h3`. Keeping a
/// single vocabulary is what lets the Threat Search facet/filter join line up
/// across the Rust writer, the Go reader, and the UI.
fn protocol_label(v: http::Version) -> &'static str {
    match v {
        http::Version::HTTP_2 => "h2",
        http::Version::HTTP_3 => "h3",
        // HTTP/0.9, 1.0 and 1.1 all bucket as h1.
        _ => "h1",
    }
}

fn ndjson_log(ctx: &RequestContext) {
    if !ndjson_logging_enabled() {
        return;
    }
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let status = ctx.response_status.map(|s| s.as_u16()).unwrap_or(0);
    let ua = ctx
        .request_headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    let action = match ctx.decision {
        WafDecision::Block | WafDecision::Challenge => "BLOCK",
        // Learning mode: the request passed through, but a rule *would* have
        // blocked it. Marked distinctly so the learning report can aggregate it.
        _ if ctx.would_block => "DETECT",
        _ => "PASS",
    };
    let site = ctx.site_id.as_deref().unwrap_or("-");
    let tenant = ctx.tenant_id.as_deref().unwrap_or("");

    let access = serde_json::json!({
        "ts":      ts,
        "ip":      ctx.client_ip.to_string(),
        "method":  ctx.method.as_str(),
        "path":    ctx.uri.path(),
        "status":  status,
        "latency": format!("{:.2}", ctx.elapsed_ms()),
        "bytes":    ctx.bytes_sent,
        "site":     site,
        "tenant":   tenant,
        "protocol": protocol_label(ctx.http_version),
        "ua":       ua,
        "action":   action,
        "score":    ctx.anomaly_score,
    });
    enqueue_log("access.log", access.to_string());

    // Emit a waf.log line for anything the WAF acted on or *would* have acted on:
    // any rule match, an enforced block, or a learning-mode would-block. The last
    // case covers GeoIP / rate-limit / bot-challenge / smuggling blocks that were
    // downgraded to Log in learning mode and carry no rule match — without it the
    // learning report (which consumes only waf.log) undercounts would-have-blocks.
    if !ctx.rule_matches.is_empty() || matches!(ctx.decision, WafDecision::Block) || ctx.would_block
    {
        let top = ctx.rule_matches.first();
        let sev_str = top
            .map(|r| format!("{:?}", r.severity).to_uppercase())
            .unwrap_or_else(|| "MEDIUM".to_string());
        // For non-rule blocks (GeoIP, rate limit, smuggling, bot challenge, bare
        // anomaly threshold) synthesize a stable rule label and attack name from
        // the block reason, so the dashboard's attack breakdown and the learning
        // report can categorize them instead of collapsing them into "-"/"other".
        let (rule, attack): (&str, &str) = match top {
            Some(r) => (r.rule_id.as_str(), r.message.as_str()),
            None => classify_nonrule_block(ctx.block_reason.as_deref().unwrap_or("")),
        };

        let waf = serde_json::json!({
            "ts":     ts,
            "ip":     ctx.client_ip.to_string(),
            "method": ctx.method.as_str(),
            "path":   ctx.uri.path(),
            "rule":   rule,
            "score":  ctx.anomaly_score,
            "sev":    sev_str,
            "attack": attack,
            "action": action,
            "site":   site,
            "tenant": tenant,
            "protocol": protocol_label(ctx.http_version),
            "msg":    ctx.block_reason.as_deref().unwrap_or(""),
            "would_block": ctx.would_block,
            "ml_scores": ctx.ml_scores,
        });
        enqueue_log("waf.log", waf.to_string());
    }
}

/// Map a non-rule block reason to a stable `(rule, attack)` label pair. These
/// synthetic rule labels mirror the categories the control-plane recognizes in
/// `attackCategory`, so GeoIP / rate-limit / smuggling / bot blocks are counted
/// distinctly rather than lumped under "-"/"other".
fn classify_nonrule_block(reason: &str) -> (&'static str, &'static str) {
    let r = reason.to_ascii_lowercase();
    if r.contains("country blocked") || r.contains("geoip") {
        ("GEOIP", "GeoIP country block")
    } else if r.contains("rate limit") {
        ("RATELIMIT", "Rate limit exceeded")
    } else if r.contains("smuggling") {
        ("SMUGGLING", "HTTP request smuggling")
    } else if r.contains("bot") || r.contains("challenge") {
        ("BOT", "Bot challenge")
    } else {
        ("ANOMALY", "anomaly threshold exceeded")
    }
}

// ---------------------------------------------------------------------------
// TLS acceptor builder
// ---------------------------------------------------------------------------

fn build_tls_acceptor(tls: &sentinel_core::config::TlsFileConfig) -> anyhow::Result<TlsAcceptor> {
    let cert_path = tls
        .cert
        .as_ref()
        .ok_or_else(|| anyhow!("TLS config missing 'cert' path"))?;
    let key_path = tls
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("TLS config missing 'key' path"))?;

    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("opening TLS cert: {}", cert_path.display()))?;
    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("opening TLS key: {}", key_path.display()))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .context("reading TLS certificates")?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("reading TLS private key")?
        .ok_or_else(|| anyhow!("no private key found in {}", key_path.display()))?;

    let mut server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server config")?;

    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

#[cfg(test)]
mod log_rotation_tests {
    use super::*;

    #[test]
    fn rotating_file_caps_size_and_prunes_backups() {
        let dir = std::env::temp_dir().join(format!("sentinel-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1 MB cap, keep 2 backups. ~10 KB lines, ~3.4 MB → several rotations.
        let line = "x".repeat(10_000);
        {
            let mut rf = RotatingFile::open(&dir, "access.log", 1024 * 1024, 2).unwrap();
            for _ in 0..340 {
                rf.write_line(&line);
            }
            rf.flush();
        } // drop closes the handle

        let live = dir.join("access.log");
        assert!(live.exists(), "live log must exist");
        assert!(
            std::fs::metadata(&live).unwrap().len() <= 1024 * 1024,
            "live log must stay under the 1MB cap"
        );
        // Backups are bounded to keep=2: .1 and .2 exist, .3 must be pruned.
        assert!(dir.join("access.log.1").exists(), "expected access.log.1");
        assert!(dir.join("access.log.2").exists(), "expected access.log.2");
        assert!(
            !dir.join("access.log.3").exists(),
            "keep=2 must drop access.log.3"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotating_file_keep_zero_retains_no_backup() {
        let dir = std::env::temp_dir().join(format!("sentinel-rot0-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let line = "y".repeat(10_000);
        {
            let mut rf = RotatingFile::open(&dir, "access.log", 1024 * 1024, 0).unwrap();
            for _ in 0..340 {
                rf.write_line(&line);
            }
            rf.flush();
        }
        assert!(dir.join("access.log").exists(), "live log must exist");
        assert!(
            !dir.join("access.log.1").exists(),
            "keep=0 must retain no backup"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod threat_intel_contract_tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    // Locks the Go↔Rust wire contract: this is byte-for-byte the shape the
    // control-plane /api/v1/internal/threat-intel endpoint emits. If either side
    // drifts (field rename, tier restructure), this fails.
    const SAMPLE: &str = r#"{
        "version": 1783337955,
        "generated_at": "2026-07-06T00:00:00Z",
        "count": 3,
        "block_confidence": 80,
        "block": {
            "ips": ["9.9.9.9"],
            "cidrs": ["203.0.113.0/24"],
            "user_agents": ["sqlmap"],
            "domains": ["evil.example"],
            "url_substrings": []
        },
        "watch": {
            "ips": ["8.8.8.8"],
            "cidrs": [],
            "user_agents": [],
            "domains": [],
            "url_substrings": []
        }
    }"#;

    #[test]
    fn deserializes_and_enforces_tiers() {
        let sync: ThreatIntelSyncResponse =
            serde_json::from_str(SAMPLE).expect("parse threat-intel sync JSON");
        assert_eq!(sync.version, 1783337955);

        let feed = ThreatFeed::from_parts(sync.version, 3, sync.block.into(), sync.watch.into());
        assert_eq!(feed.version(), 1783337955);
        assert!(!feed.is_empty());

        let ip = |s: &str| IpAddr::from_str(s).unwrap();

        // Block tier → reject.
        assert!(matches!(
            feed.check(ip("9.9.9.9"), None, None, "/"),
            ThreatVerdict::Block { .. }
        ));
        assert!(matches!(
            feed.check(ip("203.0.113.200"), None, None, "/"),
            ThreatVerdict::Block { .. }
        ));
        assert!(matches!(
            feed.check(ip("1.1.1.1"), Some("curl sqlmap/1.0"), None, "/"),
            ThreatVerdict::Block { .. }
        ));

        // Watch tier → score, not block.
        assert!(matches!(
            feed.check(ip("8.8.8.8"), None, None, "/"),
            ThreatVerdict::Score { score: 3, .. }
        ));

        // Clean traffic → pass.
        assert_eq!(
            feed.check(
                ip("1.1.1.1"),
                Some("Mozilla/5.0"),
                Some("good.example"),
                "/"
            ),
            ThreatVerdict::None
        );
    }
}

#[cfg(test)]
mod fusion_tests {
    use super::*;
    use std::collections::HashMap;

    fn waf(pl: u8, threshold: u32, fusion: Option<FusionConfig>) -> WafConfig {
        WafConfig {
            paranoia_level: pl,
            anomaly_threshold: threshold,
            fusion,
            ..WafConfig::default()
        }
    }
    fn ctx() -> RequestContext {
        RequestContext::new("203.0.113.7".parse().unwrap(), 1234)
    }
    fn fusion(
        enable: bool,
        weights: &[(&str, f32)],
        block: Vec<u32>,
        limit: Vec<u32>,
    ) -> FusionConfig {
        FusionConfig {
            enable,
            weights: weights
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect::<HashMap<_, _>>(),
            block_thresholds: block,
            limit_thresholds: limit,
            limit_status: 429,
        }
    }

    #[test]
    fn threshold_for_pl_indexes_and_repeats_last() {
        let l = [10u32, 8, 6, 4];
        assert_eq!(threshold_for_pl(&l, 1), Some(10));
        assert_eq!(threshold_for_pl(&l, 2), Some(8));
        assert_eq!(threshold_for_pl(&l, 4), Some(4));
        assert_eq!(threshold_for_pl(&l, 9), Some(4)); // repeats last
        assert_eq!(threshold_for_pl(&l, 0), Some(10)); // clamps to PL1
        assert_eq!(threshold_for_pl(&[], 2), None);
    }

    #[test]
    fn fused_score_applies_weights_and_counts_remainder() {
        let f = fusion(true, &[("bot", 3.0)], vec![100], vec![50]);
        let mut c = ctx();
        c.add_engine_score("bot", 3); // weighted 3*3 = 9
        c.add_engine_score("rules", 2); // weight 1 = 2
        c.anomaly_score = c.anomaly_score.saturating_add(5); // unbucketed remainder @ weight 1
        assert_eq!(fused_score(&c, &f), 16); // 9 + 2 + 5
    }

    #[test]
    fn legacy_flat_threshold_when_fusion_absent() {
        let w = waf(2, 5, None);
        let mut c = ctx();
        c.add_engine_score("rules", 5);
        apply_verdict(&mut c, &w);
        assert_eq!(c.decision, WafDecision::Block);
    }

    #[test]
    fn fusion_block_limit_allow_bands() {
        let f = fusion(true, &[], vec![10, 8, 6, 4], vec![5, 4, 3, 2]); // PL2 → block 8, limit 4
        let w = waf(2, 100, Some(f));
        let mut c = ctx();
        c.add_engine_score("rules", 9);
        apply_verdict(&mut c, &w);
        assert_eq!(c.decision, WafDecision::Block);

        let mut c = ctx();
        c.add_engine_score("rules", 5);
        apply_verdict(&mut c, &w);
        assert_eq!(c.decision, WafDecision::Limit);

        let mut c = ctx();
        c.add_engine_score("rules", 3);
        apply_verdict(&mut c, &w);
        assert_eq!(c.decision, WafDecision::Allow);
    }

    #[test]
    fn weights_change_the_verdict() {
        let mut c = ctx();
        c.add_engine_score("bot", 4);
        apply_verdict(
            &mut c,
            &waf(
                1,
                100,
                Some(fusion(true, &[("bot", 1.0)], vec![10], vec![])),
            ),
        );
        assert_eq!(c.decision, WafDecision::Allow); // 4 < 10

        let mut c2 = ctx();
        c2.add_engine_score("bot", 4);
        apply_verdict(
            &mut c2,
            &waf(
                1,
                100,
                Some(fusion(true, &[("bot", 3.0)], vec![10], vec![])),
            ),
        );
        assert_eq!(c2.decision, WafDecision::Block); // 12 >= 10
    }

    #[test]
    fn existing_block_is_preserved() {
        let w = waf(2, 100, Some(fusion(true, &[], vec![10], vec![5])));
        let mut c = ctx();
        c.decision = WafDecision::Block;
        c.add_engine_score("rules", 1);
        apply_verdict(&mut c, &w);
        assert_eq!(c.decision, WafDecision::Block);
    }
}

#[cfg(test)]
mod admission_control_tests {
    use super::*;

    // A unique env-var name per assertion keeps these tests independent even
    // when the test binary runs them on multiple threads (env is process-global).

    #[test]
    fn resolve_limit_uses_config_when_env_unset() {
        // Guaranteed-unset key.
        assert_eq!(
            resolve_limit("SENTINEL_TEST_ADMISSION_UNSET_XZ", 4096),
            4096
        );
    }

    #[test]
    fn resolve_limit_env_overrides_config() {
        let key = "SENTINEL_TEST_ADMISSION_OVERRIDE";
        std::env::set_var(key, "250");
        assert_eq!(resolve_limit(key, 4096), 250);
        std::env::remove_var(key);
    }

    #[test]
    fn resolve_limit_ignores_invalid_and_zero_env() {
        let key = "SENTINEL_TEST_ADMISSION_INVALID";
        std::env::set_var(key, "not-a-number");
        assert_eq!(resolve_limit(key, 4096), 4096);
        std::env::set_var(key, "0"); // 0 permits is invalid → fall back to config
        assert_eq!(resolve_limit(key, 4096), 4096);
        std::env::remove_var(key);
    }

    #[test]
    fn resolve_limit_clamps_zero_config_to_one() {
        // A Semaphore needs at least one permit; a misconfigured 0 must not
        // deadlock every connection.
        assert_eq!(resolve_limit("SENTINEL_TEST_ADMISSION_UNSET_ZERO", 0), 1);
    }

    #[test]
    fn overloaded_response_is_503_with_retry_after() {
        let resp = overloaded_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get(header::RETRY_AFTER).unwrap(),
            "1",
            "503 shed responses must tell clients/LBs to back off"
        );
    }

    // Proves the semaphore-based admission primitive actually sheds: once every
    // permit is held, the next acquisition fails (which is exactly what the
    // accept loop / run_pipeline treat as the shed signal).
    #[test]
    fn semaphore_sheds_when_saturated() {
        let sem = Arc::new(Semaphore::new(2));
        let p1 = Arc::clone(&sem).try_acquire_owned();
        let p2 = Arc::clone(&sem).try_acquire_owned();
        assert!(p1.is_ok() && p2.is_ok(), "first two permits granted");
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "third acquisition must fail → load shed"
        );
        drop(p1); // a connection ends → a slot frees
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_ok(),
            "freed slot is reusable"
        );
    }
}

#[cfg(test)]
mod metrics_endpoint_tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn metrics_response_serves_prometheus_text() {
        // Exercise the hot-path counters so the registry has real content.
        inc_requests();
        inc_rule_hits();
        let resp = metrics_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.starts_with("text/plain"),
            "prometheus text content-type, got {ct}"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        // The registry exposes the WAF counters, including the now-wired
        // rule-hits counter, in Prometheus exposition format.
        assert!(text.contains("sentinel_requests_total"));
        assert!(text.contains("sentinel_rule_hits_total"));
        assert!(text.contains("# TYPE sentinel_requests_total counter"));
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;
    use std::net::IpAddr;

    fn xff(v: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }
    // Trust 10.0.0.0/8 as the proxy subnet (stand-in for our HAProxy network).
    fn trusted(ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 10)
    }

    // ── Blocklist behind a proxy ──────────────────────────────────────────────
    //
    // The regression these guard: the fast-fail checked only the transport peer, so
    // behind HAProxy it compared the PROXY's address on every request and the blocklist
    // matched nothing at all. It passed in the single-VM demo purely because the client
    // was the immediate peer there.

    /// Blocked address arriving DIRECTLY (no proxy) — must still be caught.
    // ── Shared-egress exemption (NAT bystander protection) ────────────────────
    //
    // These guard two mechanisms that both assume "IP == actor", which is false behind
    // NAT. Env-var-driven config is process-global and cached in a OnceLock, so these
    // tests exercise the pure predicates rather than mutating the environment (which
    // would race across the parallel test runner and be order-dependent).

    /// The correlation contribution must be capped BELOW the default anomaly threshold,
    /// or reputation alone blocks a request that matched no rule. The uncapped
    /// "persistent attacker" value was 8 against a default threshold of 5.
    #[test]
    fn correlation_cap_cannot_alone_cross_the_default_threshold() {
        const DEFAULT_ANOMALY_THRESHOLD: u32 = 5;
        let cap = correlation_max_score();
        assert!(
            cap < DEFAULT_ANOMALY_THRESHOLD,
            "correlation cap {cap} >= default threshold {DEFAULT_ANOMALY_THRESHOLD} — \
             reputation could block a clean request with zero rule matches"
        );
        // And the raw engine value it caps really was above the threshold, which is why
        // the cap is needed at all.
        let engine = CorrelationEngine::new();
        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        for _ in 0..(engine.escalate_threshold * 3) {
            engine.record_block(ip);
        }
        let raw = engine.score_for_ip(ip);
        assert!(
            raw > DEFAULT_ANOMALY_THRESHOLD,
            "expected the uncapped persistent-attacker score to exceed the threshold \
             (that is the bug being capped), got {raw}"
        );
        assert!(
            raw.min(cap) < DEFAULT_ANOMALY_THRESHOLD,
            "cap did not bound the score"
        );
    }

    /// A clean request from a shared address must not be blocked because a neighbour
    /// attacked. This is the office-NAT scenario.
    #[test]
    fn shared_egress_predicate_matches_configured_ranges() {
        let nets: Vec<IpNet> = ["203.0.113.0/24", "198.51.100.7"]
            .iter()
            .filter_map(|s| parse_block_cidr(s))
            .collect();
        let contains = |ip: &str| {
            let a: IpAddr = ip.parse().unwrap();
            nets.iter().any(|n| n.contains(&a))
        };
        assert!(contains("203.0.113.1"), "CIDR member not matched");
        assert!(contains("203.0.113.255"), "CIDR upper bound not matched");
        assert!(contains("198.51.100.7"), "bare IP not treated as /32");
        assert!(
            !contains("203.0.114.1"),
            "address outside the range matched"
        );
        assert!(!contains("198.51.100.8"), "neighbour of a bare IP matched");
    }

    /// The auto-ban carve-out for private ranges does NOT cover a corporate NAT egress
    /// address, because that address is public. Without the shared-egress check, one
    /// scanner gets every colleague dropped in-kernel.
    #[test]
    fn public_nat_egress_is_autoban_eligible_without_the_exemption() {
        // A genuinely ROUTABLE public address. 203.0.113.0/24 would not do: it is RFC
        // 5737 documentation space, which autoban_eligible already excludes via
        // is_documentation() — using it would make this test pass for the wrong reason
        // and hide the very gap it is meant to demonstrate.
        let office_nat: IpAddr = "103.24.8.122".parse().unwrap();
        assert!(
            autoban_eligible(office_nat, false),
            "a PUBLIC NAT egress address is auto-ban eligible by the private-range rules \
             alone — which is exactly why the shared-egress list exists"
        );
        // Private ranges are still excluded by default, as before.
        assert!(!autoban_eligible("10.1.2.3".parse().unwrap(), false));
        assert!(!autoban_eligible("192.168.1.1".parse().unwrap(), false));
    }

    /// Exempting a range must not weaken detection: an attack from a shared address is
    /// still blocked on its own merits. Only the *history* is forgiven, and the
    /// blocklist still applies to the address if an operator adds it explicitly.
    #[test]
    fn exempting_shared_egress_does_not_disable_the_blocklist() {
        let shared: IpAddr = "203.0.113.10".parse().unwrap();
        let blocked = move |ip: IpAddr| ip == shared;
        assert!(
            blocklist_hit(shared, &http::HeaderMap::new(), blocked, trusted),
            "an explicitly blocklisted address must still be blocked even if it is \
             shared egress — exemption covers reputation, not explicit policy"
        );
    }

    #[test]
    fn blocklist_catches_direct_peer() {
        let attacker: IpAddr = "45.155.205.233".parse().unwrap();
        let blocked = move |ip: IpAddr| ip == attacker;
        assert!(blocklist_hit(
            attacker,
            &http::HeaderMap::new(),
            blocked,
            trusted
        ));
    }

    /// THE BUG: blocked client behind a trusted proxy. Before the fix this returned
    /// false, because only the proxy's address was ever checked.
    #[test]
    fn blocklist_catches_client_behind_trusted_proxy() {
        let proxy: IpAddr = "10.0.0.5".parse().unwrap();
        let attacker: IpAddr = "45.155.205.233".parse().unwrap();
        let blocked = move |ip: IpAddr| ip == attacker;
        assert!(
            blocklist_hit(proxy, &xff("45.155.205.233"), blocked, trusted),
            "blocked client was NOT caught behind a proxy — the blocklist is inert in \
             the shipped HA topology"
        );
    }

    /// A proxy chain must still resolve to the real client.
    #[test]
    fn blocklist_catches_client_through_a_proxy_chain() {
        let proxy: IpAddr = "10.0.0.5".parse().unwrap();
        let attacker: IpAddr = "45.155.205.233".parse().unwrap();
        let blocked = move |ip: IpAddr| ip == attacker;
        assert!(blocklist_hit(
            proxy,
            &xff("45.155.205.233, 10.0.0.9"),
            blocked,
            trusted
        ));
    }

    /// An UNTRUSTED peer's XFF must be ignored, so a blocked attacker cannot escape its
    /// own block by claiming to be someone else.
    #[test]
    fn blocked_attacker_cannot_escape_by_forging_xff() {
        let attacker: IpAddr = "45.155.205.233".parse().unwrap();
        let blocked = move |ip: IpAddr| ip == attacker;
        assert!(
            blocklist_hit(attacker, &xff("8.8.8.8"), blocked, trusted),
            "a blocked client escaped its block by forging X-Forwarded-For"
        );
    }

    /// And the inverse: an untrusted client must not be able to get an innocent third
    /// party blocked by naming it in XFF.
    #[test]
    fn untrusted_xff_cannot_frame_a_third_party() {
        let visitor: IpAddr = "203.0.113.9".parse().unwrap();
        let victim: IpAddr = "45.155.205.233".parse().unwrap();
        let blocked = move |ip: IpAddr| ip == victim;
        assert!(
            !blocklist_hit(visitor, &xff("45.155.205.233"), blocked, trusted),
            "an untrusted client's XFF was honoured — it could have a third party blocked"
        );
    }

    /// Clean traffic must pass, from either position.
    #[test]
    fn blocklist_passes_clean_traffic() {
        let proxy: IpAddr = "10.0.0.5".parse().unwrap();
        let visitor: IpAddr = "203.0.113.9".parse().unwrap();
        let blocked = |ip: IpAddr| ip == "45.155.205.233".parse::<IpAddr>().unwrap();
        assert!(!blocklist_hit(
            visitor,
            &http::HeaderMap::new(),
            blocked,
            trusted
        ));
        assert!(!blocklist_hit(proxy, &xff("203.0.113.9"), blocked, trusted));
    }

    #[test]
    fn untrusted_peer_ignores_xff_no_spoof() {
        // A direct client that is NOT a trusted proxy cannot spoof its IP.
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(resolve_client_ip_with(peer, &xff("1.2.3.4"), trusted), None);
    }

    #[test]
    fn trusted_proxy_resolves_rightmost_real_client() {
        // HAProxy (trusted) appends the observed client on the right; a left-most
        // client-forged entry must lose.
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let got = resolve_client_ip_with(peer, &xff("6.6.6.6, 45.155.205.233"), trusted);
        assert_eq!(got, Some("45.155.205.233".parse().unwrap()));
    }

    #[test]
    fn walks_past_trusted_hops_to_first_untrusted() {
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let got = resolve_client_ip_with(peer, &xff("127.0.0.1, 8.8.8.8, 10.0.0.9"), trusted);
        // right-to-left: 10.0.0.9 trusted (skip) -> 8.8.8.8 untrusted -> win.
        assert_eq!(got, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn no_xff_keeps_peer() {
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            resolve_client_ip_with(peer, &http::HeaderMap::new(), trusted),
            None
        );
    }
}

#[cfg(test)]
mod drain_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // Proves the R6 shutdown drain lets an in-flight request FINISH rather than
    // being severed by the runtime drop (the old abort() → 502-on-deploy bug).
    #[tokio::test]
    async fn conn_tracker_drain_waits_for_inflight() {
        let tracker = tokio_util::task::TaskTracker::new();
        let done = Arc::new(AtomicBool::new(false));
        let d2 = Arc::clone(&done);
        tracker.spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await; // in-flight request
            d2.store(true, Ordering::SeqCst);
        });
        tracker.close();
        let r = tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await;
        assert!(r.is_ok(), "drain should complete within grace");
        assert!(
            done.load(Ordering::SeqCst),
            "in-flight request must FINISH, not be severed"
        );
    }

    // Proves the drain is BOUNDED — a stuck/idle keep-alive connection can't hang
    // shutdown forever; the grace timeout closes it.
    #[tokio::test]
    async fn conn_tracker_drain_is_bounded() {
        let tracker = tokio_util::task::TaskTracker::new();
        tracker.spawn(async { std::future::pending::<()>().await });
        tracker.close();
        let r = tokio::time::timeout(Duration::from_millis(150), tracker.wait()).await;
        assert!(
            r.is_err(),
            "drain must be bounded by grace on a stuck connection"
        );
    }
}
