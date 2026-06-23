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

pub mod upstream;
pub mod websocket;
pub mod tls;

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Context};
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use http::{header, Request, Response, StatusCode, Uri};
use hyper::body::Body;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use regex::Regex;
use rustls::ServerConfig;
use sentinel_core::{
    config::{
        ChallengeMode, ConfigHandle, DlpConfig, IpReputationConfig, ListenerConfig, Protocol,
        SentinelConfig, SiteConfig, WafMode,
    },
    context::{Phase, RequestContext, WafDecision},
};
use sentinel_ebpf::{EbpfConfig, EbpfManager};
use sentinel_ml::MlEngine;
use sentinel_modules::{
    AntiDdos, BotDetector, BotVerdict, DdosVerdict, GeoIp, GeoVerdict, IpReputation, IpVerdict,
    RateLimiter, SmugglingVerdict, detect_smuggling,
};
use sentinel_plugins::PluginRuntime;
use sentinel_rules::RuleEngine;
use sentinel_telemetry::{inc_blocked, inc_ebpf_drops, inc_requests, observe_duration};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn, Instrument};

use crate::upstream::UpstreamPool;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

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
/// bodies for PII and secret patterns.
struct DlpScanner {
    patterns: Vec<(Regex, &'static str)>,
    user_patterns: Vec<Regex>,
    enabled: bool,
}

impl DlpScanner {
    fn from_config(cfg: &DlpConfig) -> Self {
        let builtin: &[(&str, &str)] = &[
            // Credit / debit card numbers (Luhn-shaped 13-19 digit groups)
            (r"(?<!\d)(?:4[0-9]{12,15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})(?!\d)", "credit_card"),
            // US Social Security Number
            (r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", "ssn"),
            // PEM private key header
            (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key"),
            // AWS access key
            (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
            // AWS secret key (contextual — next to known keyword)
            (r#"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key["'\s:=]+[A-Za-z0-9/+]{40}"#, "aws_secret_key"),
            // Generic high-entropy API tokens / bearer tokens in JSON
            (r#"(?i)(?:"|\b)(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|secret)["\s]*[:=]+\s*["']?[A-Za-z0-9/+_\-]{32,}"#, "api_token"),
            // Password leaked in JSON response
            (r#""(?:password|passwd|pwd)"\s*:\s*"[^"]{4,}""#, "password_in_json"),
            // Generic private-looking 40-char hex string (git-style secrets)
            (r"\b[0-9a-f]{40}\b", "hex_secret"),
        ];

        let mut compiled_builtins: Vec<(Regex, &'static str)> = Vec::new();
        for (pat, label) in builtin {
            match Regex::new(pat) {
                Ok(re) => compiled_builtins.push((re, label)),
                Err(e) => warn!("DLP built-in pattern compile error ({label}): {e}"),
            }
        }

        let user_patterns: Vec<Regex> = cfg
            .patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    warn!("DLP user pattern compile error ({p}): {e}");
                    None
                }
            })
            .collect();

        Self {
            patterns: compiled_builtins,
            user_patterns,
            enabled: cfg.enable,
        }
    }

    /// Scan `body` for sensitive data.  Returns the first matched label, or
    /// `None` if clean.  Only scans the first 512 KiB of a large body.
    fn scan(&self, body: &[u8]) -> Option<&'static str> {
        if !self.enabled {
            return None;
        }
        let cap = body.len().min(512 * 1024);
        let text = std::str::from_utf8(&body[..cap]).ok()?;
        for (re, label) in &self.patterns {
            if re.is_match(text) {
                return Some(label);
            }
        }
        for re in &self.user_patterns {
            if re.is_match(text) {
                return Some("user_pattern");
            }
        }
        None
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
                Some(ip) => { self.state.remove(&ip); }
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
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ConfigSyncResponse {
    version: u64,
    sites: Vec<SiteConfig>,
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
        let cfg = self.config.load_full();

        if cfg.listeners.is_empty() {
            warn!("no listeners configured; proxy will not accept connections");
            shutdown.changed().await.ok();
            return Ok(());
        }

        let upstream_pool = Arc::new(UpstreamPool::from_config(&cfg));

        // Spawn active health-check tasks for sites that configure them.
        UpstreamPool::spawn_health_checks(
            Arc::clone(&upstream_pool),
            &cfg,
            shutdown.clone(),
        );

        let initial_engines = build_rule_engines(&cfg);
        let engines: Arc<ArcSwap<RuleEngineMap>> =
            Arc::new(ArcSwap::new(Arc::new(initial_engines)));

        let initial_dlp = build_dlp_map(&cfg);
        let dlp_map: Arc<ArcSwap<DlpMap>> = Arc::new(ArcSwap::new(Arc::new(initial_dlp)));

        let feed_cache: FeedCache = Arc::new(ArcSwap::new(Arc::new(Vec::new())));

        // Connect storage backends (Redis for distributed rate limiting,
        // ClickHouse for traffic history).  Missing/unreachable backends
        // degrade gracefully — the rate limiter falls back to in-memory.
        let storage = sentinel_storage::StorageHandle::connect(
            &sentinel_storage::StorageBackendConfig::from_core(&cfg.storage),
        )
        .await;
        if storage.has_redis() {
            info!("rate limiting: distributed mode (Redis backend active)");
        } else {
            info!("rate limiting: in-memory mode (no Redis backend)");
        }

        let modules = Arc::new(ModulesState {
            ip_rep: ArcSwap::new(Arc::new(build_ip_reputation(&cfg, &[]))),
            rate_limiter: RateLimiter::with_redis(storage.redis.clone()),
            bot_detector: ArcSwap::new(Arc::new(BotDetector::new())),
            geoip_map: ArcSwap::new(Arc::new(build_geoip_map(&cfg))),
            anti_ddos: build_anti_ddos(&cfg),
            correlation: CorrelationEngine::new(),
            feed_cache: Arc::clone(&feed_cache),
        });

        let plugin_runtime = build_plugin_runtime(&cfg).unwrap_or_else(|e| {
            warn!("failed to load plugins: {e:#}");
            PluginRuntime::new().expect("create empty plugin runtime")
        });
        let plugin_runtime: Arc<ArcSwap<PluginRuntime>> =
            Arc::new(ArcSwap::new(Arc::new(plugin_runtime)));

        let ml_engine = {
            let model_dir = std::path::Path::new("ml-models");
            Arc::new(MlEngine::new(
                4096,
                256,
                if model_dir.exists() { Some(model_dir) } else { None },
            ))
        };

        let ebpf = Arc::new(
            EbpfManager::new(EbpfConfig::default())
                .await
                .context("EbpfManager init")?,
        );

        let state = Arc::new(ServerState {
            config: Arc::clone(&self.config),
            upstream_pool,
            engines: Arc::clone(&engines),
            dlp_map: Arc::clone(&dlp_map),
            modules: Arc::clone(&modules),
            plugin_runtime: Arc::clone(&plugin_runtime),
            ml_engine: Arc::clone(&ml_engine),
            ebpf,
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
                                let new_engines = build_rule_engines(&current);
                                let rule_count: usize =
                                    new_engines.values().map(|e| e.rule_count()).sum();
                                es.store(Arc::new(new_engines));
                                ds.store(Arc::new(build_dlp_map(&current)));

                                let feed_cidrs = mr.feed_cache.load_full();
                                mr.ip_rep.store(Arc::new(build_ip_reputation(&current, &feed_cidrs)));
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
                    let req = hyper::Request::builder()
                        .method("GET")
                        .uri(uri)
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
                        poll_pool.sync_sites(&sync.sites);
                        sentinel_core::config::update_sites(&poll_cfg, sync.sites);
                        last_version = sync.version;
                        info!(version = last_version, sites = count, "sites hot-synced");
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
        info!("shutdown signal received; draining connections");
        for h in handles {
            h.abort();
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

    info!(listener = %cfg.name, bind = %cfg.bind, tls = cfg.is_tls(), "listener started");

    let tls_acceptor = if cfg.is_tls() {
        let tls_cfg = cfg.tls.as_ref().unwrap();
        // If explicit cert/key paths are provided, use them directly.
        // Otherwise, use SNI-based auto-generation for all sites.
        if tls_cfg.cert.is_some() && tls_cfg.key.is_some() {
            Some(build_tls_acceptor(tls_cfg)?)
        } else {
            let cfg_snap = state.config.load();
            let domains: Vec<String> = cfg_snap
                .sites
                .iter()
                .flat_map(|s| s.domains.iter().cloned())
                .collect();
            let resolved = tls::AutoCertResolver::new(std::collections::HashMap::new());
            if !domains.is_empty() {
                resolved.pre_warm(&domains);
            }
            let mut server_cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolved));
            server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(TlsAcceptor::from(Arc::new(server_cfg)))
        }
    } else {
        None
    };

    let default_site = cfg.default_site.clone();

    loop {
        tokio::select! {
            accept = tcp.accept() => {
                let (stream, peer) = accept?;
                let state = Arc::clone(&state);
                let acceptor = tls_acceptor.clone();
                let protos = cfg.protocols();
                let ds = default_site.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, acceptor, protos, state, ds).await {
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

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    protocols: Vec<Protocol>,
    state: Arc<ServerState>,
    default_site: Option<String>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    if let Some(acceptor) = tls_acceptor {
        let tls = acceptor.accept(stream).await.context("TLS handshake failed")?;
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let io = TokioIo::new(tls);
        if negotiated.as_deref() == Some(b"h2") {
            serve_http2(io, peer, state, default_site).await
        } else {
            serve_http1(io, peer, state, default_site).await
        }
    } else {
        let io = TokioIo::new(stream);
        if protocols.contains(&Protocol::Http2) && !protocols.contains(&Protocol::Http1) {
            serve_http2(io, peer, state, default_site).await
        } else {
            serve_http1(io, peer, state, default_site).await
        }
    }
}

async fn serve_http1<T>(
    io: TokioIo<T>,
    peer: SocketAddr,
    state: Arc<ServerState>,
    default_site: Option<String>,
) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                let ds = default_site.clone();
                async move { handle_request(s, peer, req, ds).await }
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
) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                let ds = default_site.clone();
                async move { handle_request(s, peer, req, ds).await }
            }),
        )
        .await
        .map_err(|e| anyhow!("http2 serve error: {e}"))
}

// ---------------------------------------------------------------------------
// Request handler — WAF phases + upstream proxying
// ---------------------------------------------------------------------------

async fn handle_request(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<Incoming>,
    default_site: Option<String>,
) -> Result<Response<BoxBody>, Infallible> {
    // Health / readiness endpoint — served before any WAF pipeline work.
    // GET /healthz or GET /health returns JSON with proxy uptime, site
    // count, and listener status.  No auth required; internal-only.
    if req.uri().path() == "/healthz" || req.uri().path() == "/health" {
        return Ok(health_response(&state));
    }

    // eBPF fast-fail: known-blocked IPs never enter the WAF pipeline.
    // Runs before body reads, header parsing, or any other work.
    if state.ebpf.is_blocked(peer.ip()) {
        inc_ebpf_drops();
        inc_requests();
        inc_blocked();
        return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
    }

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
        match proxy(state, peer, req, default_site).await {
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

    Ok(resp)
}

async fn proxy(
    state: Arc<ServerState>,
    peer: SocketAddr,
    mut req: Request<Incoming>,
    default_site: Option<String>,
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

    // Anti-DDoS: connection-rate check.
    match state.modules.anti_ddos.check_connection(ctx.client_ip) {
        DdosVerdict::Block { reason } => {
            ctx.decision = WafDecision::Block;
            ctx.block_reason = Some(reason);
            state.modules.correlation.record_block(ctx.client_ip);
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
                state.modules.correlation.record_block(ctx.client_ip);
                ctx.advance_phase(Phase::Logging);
                log_request(&ctx);
                return Ok(block_response(&ctx));
            }
            IpVerdict::Suspect { tags } => {
                ctx.tx_vars.insert("ip_rep_tags".to_string(), tags.join(","));
                ctx.anomaly_score = ctx.anomaly_score.saturating_add(2);
            }
            IpVerdict::Allow => {}
        }
    }

    // Correlation engine: add extra score for repeat attackers.
    let corr_score = state.modules.correlation.score_for_ip(ctx.client_ip);
    if corr_score > 0 {
        ctx.anomaly_score = ctx.anomaly_score.saturating_add(corr_score);
        ctx.tx_vars
            .insert("correlation_score".to_string(), corr_score.to_string());
    }

    ctx.advance_phase(Phase::RequestHeaders);

    // --- Phase 1: Request headers ---
    let (mut parts, body) = req.into_parts();

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
        }
    }

    // WAF phase 1: rate limit → bot → GeoIP → rule engine → plugins.
    {
        let pr = state.plugin_runtime.load();
        phase1_headers(&mut ctx, site, &engine_map, &state.modules, &pr).await?;
    }

    if ctx.decision == WafDecision::Block || ctx.decision == WafDecision::Challenge {
        state.modules.correlation.record_block(ctx.client_ip);
        let resp = if ctx
            .block_reason
            .as_deref()
            .unwrap_or("")
            .starts_with("HTTP request smuggling")
        {
            // RFC 7230 §3.3.3: malformed requests MUST be rejected with 400.
            error_response(StatusCode::BAD_REQUEST, ctx.block_reason.as_deref().unwrap_or("Bad Request"))
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
            let b = body.collect().await.context("collecting request body")?.to_bytes();
            if b.len() as u64 > max_bytes {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!(
                    "request body too large: {} bytes (limit {})",
                    b.len(),
                    max_bytes
                ));
                ctx.advance_phase(Phase::Logging);
                log_request(&ctx);
                return Ok(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request Entity Too Large",
                ));
            }
            b
        } else {
            body.collect().await.context("collecting request body")?.to_bytes()
        };

        ctx.request_body = Some(bytes.clone());
        phase2_body(&mut ctx, site, &engine_map, &state.ml_engine)?;

        if ctx.decision == WafDecision::Block {
            state.modules.correlation.record_block(ctx.client_ip);
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
        body.boxed()
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
            let upstream_upgrade_fut = hyper::upgrade::on(
                &mut Response::from_parts(resp_parts.clone(), http_body_util::Empty::<Bytes>::new()),
            );
            let client_ip = ctx.client_ip;
            let site_id = site_cfg.id.clone();
            let ws_engine = engine_map.get(&site_id).cloned().map(Arc::new);
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);

            // Spawn background relay after returning 101 to the client.
            tokio::spawn(async move {
                let client_io = match client_upgrade_fut.await {
                    Ok(io) => io,
                    Err(e) => { warn!("WS: client upgrade failed: {e}"); return; }
                };
                let upstream_io = match upstream_upgrade_fut.await {
                    Ok(io) => io,
                    Err(e) => { warn!("WS: upstream upgrade failed: {e}"); return; }
                };
                websocket::relay(
                    TokioIo::new(client_io),
                    TokioIo::new(upstream_io),
                    client_ip,
                    site_id,
                    ws_engine,
                ).await;
            });

            // Return the 101 response to the client immediately.
            let switching = Response::from_parts(resp_parts, resp_body.boxed());
            return Ok(switching);
        }
    }

    strip_hop_by_hop(&mut resp_parts.headers);
    inject_security_headers(&mut resp_parts.headers);

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
                        let bytes = collected.to_bytes();

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

                        // (2) DLP scan (PII / secret leakage).
                        if let Some(dlp) = dlp {
                            if let Some(matched) = dlp.scan(&bytes) {
                                warn!(
                                    site = %site_cfg.id,
                                    client_ip = %ctx.client_ip,
                                    pattern = matched,
                                    "DLP: sensitive data in response — blocking"
                                );
                                ctx.decision = WafDecision::Block;
                                ctx.block_reason = Some(format!(
                                    "DLP: sensitive data pattern matched: {matched}"
                                ));
                                ctx.advance_phase(Phase::Logging);
                                log_request(&ctx);
                                return Ok(block_response(&ctx));
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
                ctx.block_reason =
                    Some(format!("rate limit exceeded for {}", ctx.client_ip));
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
            let verdict = bot_det.classify(ua, ctx.tls_fingerprint.as_deref());

            match &verdict {
                BotVerdict::KnownAttacker(tool) => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!("known attack tool: {tool}"));
                }
                BotVerdict::SuspiciousBot => {
                    ctx.tx_vars.insert("bot_suspicious".to_string(), "1".to_string());
                    ctx.anomaly_score = ctx.anomaly_score.saturating_add(2);
                    if bot_cfg.challenge != ChallengeMode::Off {
                        ctx.decision = WafDecision::Challenge;
                        ctx.block_reason =
                            Some("suspicious bot UA — browser challenge required".to_string());
                    }
                }
                BotVerdict::GoodBot(name) => {
                    ctx.tx_vars.insert("bot_good".to_string(), name.clone());
                }
                _ => {}
            }
        }
    }

    // --- GeoIP ---
    if ctx.decision == WafDecision::Allow {
        if site.waf.geoip.is_some() {
            let geoip_map = modules.geoip_map.load();
            if let Some(geoip) = geoip_map.get(&site.id) {
                match geoip.check(ctx.client_ip) {
                    GeoVerdict::Block { country_code } => {
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason = Some(format!("country blocked: {country_code}"));
                    }
                    GeoVerdict::Allow | GeoVerdict::Unknown => {}
                }
            }
        }
    }

    // --- Rule engine (CRS / SRL) ---
    if ctx.decision == WafDecision::Allow {
        if let Some(engine) = engines.get(&site.id) {
            engine.evaluate(ctx, Phase::RequestHeaders, site.waf.anomaly_threshold);
        }
    }

    // --- WASM plugins ---
    if ctx.decision == WafDecision::Allow {
        for plugin_name in &plugin_runtime.plugin_names() {
            let result = plugin_runtime.evaluate_plugin(plugin_name, ctx).await;
            if result.anomaly_score_delta > 0 {
                ctx.anomaly_score =
                    ctx.anomaly_score.saturating_add(result.anomaly_score_delta);
            }
            match result.decision {
                WafDecision::Block => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason =
                        Some(format!("plugin '{plugin_name}' set decision"));
                    break;
                }
                WafDecision::Challenge if ctx.decision == WafDecision::Allow => {
                    ctx.decision = WafDecision::Challenge;
                    ctx.block_reason =
                        Some(format!("plugin '{plugin_name}' requested challenge"));
                }
                _ => {}
            }
            for (name, value) in &result.response_headers {
                ctx.tx_vars.insert(
                    format!("plugin_response_header:{name}"),
                    value.clone(),
                );
            }
            if let Some(ref callouts) = result.pending_callouts {
                if !callouts.is_empty() {
                    plugin_runtime.execute_pending_callouts(callouts.clone()).await;
                    let result2 = plugin_runtime.evaluate_plugin(plugin_name, ctx).await;
                    if result2.anomaly_score_delta > 0 {
                        ctx.anomaly_score =
                            ctx.anomaly_score.saturating_add(result2.anomaly_score_delta);
                    }
                    match result2.decision {
                        WafDecision::Block => {
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason =
                                Some(format!("plugin '{plugin_name}' set decision"));
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
                        ctx.tx_vars.insert(
                            format!("plugin_response_header:{name}"),
                            value.clone(),
                        );
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
        engine.evaluate(ctx, Phase::RequestBody, site.waf.anomaly_threshold);
    }

    if let Some(ref ml_cfg) = site.waf.ml {
        if ml_cfg.enable {
            let ml_scores = ml_engine.evaluate(ctx);

            ctx.ml_scores.insert("anomaly".to_string(), ml_scores.anomaly_score);
            ctx.ml_scores
                .insert("payload_attack".to_string(), ml_scores.payload_attack_score);
            for (model, score) in &ml_scores.onnx_scores {
                ctx.ml_scores.insert(format!("onnx:{model}"), *score);
            }
            ctx.ml_scores.insert("combined".to_string(), ml_scores.combined_score);

            if ml_scores.combined_score >= ml_cfg.sensitivity {
                let delta: u32 =
                    ((ml_scores.combined_score - ml_cfg.sensitivity) * 10.0).ceil() as u32;
                let delta = delta.min(8);
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
                    ctx.anomaly_score = ctx.anomaly_score.saturating_add(delta);
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

    if ctx.decision != WafDecision::Block
        && ctx.anomaly_score > 0
        && ctx.anomaly_score >= site.waf.anomaly_threshold
    {
        ctx.decision = WafDecision::Block;
        ctx.block_reason = Some(format!(
            "anomaly score {} >= threshold {}",
            ctx.anomaly_score, site.waf.anomaly_threshold
        ));
    }

    enforce_mode(ctx, &site.waf.mode);
    Ok(())
}

fn enforce_mode(ctx: &mut RequestContext, mode: &WafMode) {
    if *mode == WafMode::Learning
        && (ctx.decision == WafDecision::Block || ctx.decision == WafDecision::Challenge)
    {
        ctx.decision = WafDecision::Log;
        ctx.block_reason = None;
    }
}

// ---------------------------------------------------------------------------
// Module / engine builders
// ---------------------------------------------------------------------------

fn build_rule_engines(cfg: &SentinelConfig) -> RuleEngineMap {
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
                warn!(site = %site.id, "rule engine load failed — site unprotected: {e:#}");
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

fn build_ip_reputation(
    cfg: &SentinelConfig,
    feed_cidrs: &[(String, Vec<String>)],
) -> IpReputation {
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

    // Rule target exclusions.
    for exclusion in &site.waf.rule_exclusions {
        if exclusion.exclude_targets.is_empty() {
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

    let uri: Uri = url.parse().with_context(|| format!("invalid feed URL: {url}"))?;
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

    let body = resp.collect().await.context("reading feed body")?.to_bytes();
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

fn site_matches(site: &SiteConfig, host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    site.domains.iter().any(|d| {
        let d_lc = d.to_ascii_lowercase();
        if d_lc.starts_with("*.") {
            let suffix = &d_lc[1..];
            host_lc.ends_with(&*suffix) || host_lc == &d_lc[2..]
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
    const PRESERVE: &[&str] = &["upgrade", "connection", "sec-websocket-key",
                                 "sec-websocket-version", "sec-websocket-extensions",
                                 "sec-websocket-protocol"];
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

fn inject_security_headers(headers: &mut http::HeaderMap) {
    let insert = |h: &mut http::HeaderMap, name: &'static str, value: &'static str| {
        h.entry(header::HeaderName::from_static(name))
            .or_insert_with(|| value.parse().unwrap());
    };
    insert(headers, "x-content-type-options", "nosniff");
    insert(headers, "x-frame-options", "SAMEORIGIN");
    insert(headers, "referrer-policy", "strict-origin-when-cross-origin");
    insert(headers, "x-xss-protection", "1; mode=block");
    insert(headers, "permissions-policy", "geolocation=(), microphone=(), camera=()");
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

fn health_response(state: &ServerState) -> Response<BoxBody> {
    use std::time::SystemTime;

    let cfg = state.config.load();
    let site_count = cfg.sites.len();
    let listeners: Vec<String> = cfg
        .listeners
        .iter()
        .map(|l| format!("{}:{}", l.name, l.bind))
        .collect();
    let pool_stats = state.upstream_pool.stats();
    let start = *START_TIME.get_or_init(SystemTime::now);
    let uptime_secs = start.elapsed().unwrap_or_default().as_secs();

    let body = serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
        "sites": site_count,
        "listeners": listeners,
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

// Server start time — captured once, shared across health responses.
static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(
            Full::new(Bytes::from(message.to_string()))
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
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
        anomaly_score = ctx.anomaly_score,
        rule_matches = ctx.rule_matches.len(),
        rule_ids = rule_ids.join(","),
        decision = ?ctx.decision,
        block_reason = ctx.block_reason.as_deref().unwrap_or(""),
        "request"
    );
    if let Err(e) = ndjson_log(ctx) {
        tracing::warn!(error = %e, "ndjson log write failed");
    }
}

// ---------------------------------------------------------------------------
// NDJSON file logger
// ---------------------------------------------------------------------------

fn ndjson_log(ctx: &RequestContext) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let log_dir = std::env::var("SENTINEL_LOG_DIR")
        .unwrap_or_else(|_| "/tmp/sentinel-logs".to_string());
    let dir = std::path::Path::new(&log_dir);
    std::fs::create_dir_all(dir)?;

    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let status = ctx.response_status.map(|s| s.as_u16()).unwrap_or(0);
    let ua = ctx
        .request_headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    let action = match ctx.decision {
        WafDecision::Block | WafDecision::Challenge => "BLOCK",
        _ => "PASS",
    };
    let site = ctx.site_id.as_deref().unwrap_or("-");

    let access = serde_json::json!({
        "ts":      ts,
        "ip":      ctx.client_ip.to_string(),
        "method":  ctx.method.as_str(),
        "path":    ctx.uri.path(),
        "status":  status,
        "latency": format!("{:.2}", ctx.elapsed_ms()),
        "bytes":   ctx.bytes_sent,
        "site":    site,
        "ua":      ua,
        "action":  action,
        "score":   ctx.anomaly_score,
    });
    {
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.join("access.log"))?;
        writeln!(f, "{}", access)?;
    }

    if !ctx.rule_matches.is_empty() || matches!(ctx.decision, WafDecision::Block) {
        let top = ctx.rule_matches.first();
        let sev_str = top
            .map(|r| format!("{:?}", r.severity).to_uppercase())
            .unwrap_or_else(|| "MEDIUM".to_string());
        let attack = top
            .map(|r| r.message.as_str())
            .unwrap_or("anomaly threshold exceeded");

        let waf = serde_json::json!({
            "ts":     ts,
            "ip":     ctx.client_ip.to_string(),
            "method": ctx.method.as_str(),
            "path":   ctx.uri.path(),
            "rule":   top.map(|r| r.rule_id.as_str()).unwrap_or("-"),
            "score":  ctx.anomaly_score,
            "sev":    sev_str,
            "attack": attack,
            "action": action,
            "site":   site,
            "msg":    ctx.block_reason.as_deref().unwrap_or(""),
            "ml_scores": ctx.ml_scores,
        });
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.join("waf.log"))?;
        writeln!(f, "{}", waf)?;
    }

    Ok(())
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
