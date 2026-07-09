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

pub mod challenge;
pub mod http3;
pub mod tls;
pub mod upstream;
pub mod websocket;

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
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use regex::Regex;
use rustls::ServerConfig;
use sentinel_core::{
    config::{
        ChallengeMode, ConfigHandle, DlpConfig, IpReputationConfig, ListenerConfig, Protocol,
        SecurityHeadersConfig, SentinelConfig, SiteConfig, WafMode,
    },
    context::{Phase, RequestContext, WafDecision},
};
use sentinel_ebpf::{EbpfConfig, EbpfManager};
use sentinel_ml::MlEngine;
use sentinel_modules::{
    detect_smuggling, inspect_graphql, validate_jwt, AntiDdos, BotDetector, BotSignals, BotTier,
    DdosVerdict, GeoIp, GeoVerdict, GraphqlLimits, IpReputation, IpVerdict, JwtPolicy, RateLimiter,
    RawTier, SmugglingVerdict, ThreatFeed, ThreatVerdict,
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
            (
                r"(?<!\d)(?:4[0-9]{12,15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})(?!\d)",
                "credit_card",
            ),
            // US Social Security Number
            (
                r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
                "ssn",
            ),
            // PEM private key header
            (
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                "private_key",
            ),
            // AWS access key
            (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
            // AWS secret key (contextual — next to known keyword)
            (
                r#"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key["'\s:=]+[A-Za-z0-9/+]{40}"#,
                "aws_secret_key",
            ),
            // Generic high-entropy API tokens / bearer tokens in JSON
            (
                r#"(?i)(?:"|\b)(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|secret)["\s]*[:=]+\s*["']?[A-Za-z0-9/+_\-]{32,}"#,
                "api_token",
            ),
            // Password leaked in JSON response
            (
                r#""(?:password|passwd|pwd)"\s*:\s*"[^"]{4,}""#,
                "password_in_json",
            ),
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
        let cfg = self.config.load_full();

        if cfg.listeners.is_empty() {
            warn!("no listeners configured; proxy will not accept connections");
            shutdown.changed().await.ok();
            return Ok(());
        }

        let upstream_pool = Arc::new(UpstreamPool::from_config(&cfg));

        // Spawn active health-check tasks for sites that configure them.
        UpstreamPool::spawn_health_checks(Arc::clone(&upstream_pool), &cfg, shutdown.clone());

        let initial_engines = build_rule_engines(&cfg);
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
            EbpfManager::new(EbpfConfig::default())
                .await
                .context("EbpfManager init")?,
        );

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
            ebpf,
            cert_manager,
            http01_tokens,
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
                let state = Arc::clone(&state);
                let acceptor = tls_acceptor.clone();
                let protos = cfg.protocols();
                let ds = default_site.clone();
                let mgmt = management.clone();
                let av = alt_svc.clone();
                tokio::spawn(async move {
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
    // eBPF fast-fail: known-blocked IPs never enter the WAF pipeline.
    // Runs before body reads, header parsing, or any other work.
    if state.ebpf.is_blocked(peer.ip()) {
        inc_ebpf_drops();
        inc_requests();
        inc_blocked();
        return error_response(StatusCode::FORBIDDEN, "Forbidden");
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
    // JA4 TLS fingerprint computed from the ClientHello during the handshake
    // (None for plaintext/HTTP-3 listeners). Consumed by the bot classifier.
    ctx.tls_fingerprint = tls_fp;

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
                ctx.tx_vars
                    .insert("ip_rep_tags".to_string(), tags.join(","));
                ctx.anomaly_score = ctx.anomaly_score.saturating_add(2);
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
                    state.modules.correlation.record_block(ctx.client_ip);
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
                    ctx.anomaly_score = ctx.anomaly_score.saturating_add(score);
                }
                ThreatVerdict::None => {}
            }
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
        let challenge_mode = site
            .and_then(|s| s.waf.bot_detection.as_ref())
            .map(|b| b.challenge)
            .unwrap_or(ChallengeMode::NativePow);
        if let Some(resp) = challenge_response(&mut ctx, challenge_mode) {
            ctx.response_status = Some(resp.status());
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);
            return Ok(resp);
        }
        // Cleared (or an in-line grant for an unsafe method) — proceed to origin.
        ctx.decision = WafDecision::Allow;
    }

    if ctx.decision == WafDecision::Block {
        state.modules.correlation.record_block(ctx.client_ip);
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
            match http_body_util::Limited::new(body, max_bytes as usize)
                .collect()
                .await
            {
                Ok(collected) => collected.to_bytes(),
                Err(e)
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
                Err(e) => return Err(anyhow::anyhow!("collecting request body: {e}")),
            }
        } else {
            body.collect()
                .await
                .context("collecting request body")?
                .to_bytes()
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
                                ctx.decision = WafDecision::Block;
                                ctx.block_reason =
                                    Some(format!("DLP: sensitive data pattern matched: {matched}"));
                                // Respect learning mode (downgrade Block → Log)
                                // exactly like the response-body rule path above —
                                // a learning-mode site must not block or rewrite
                                // the response, only record the would-block.
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
                    ctx.anomaly_score = ctx.anomaly_score.saturating_add((bs.score / 10) as u32);
                }
                BotTier::Allow => {
                    if bs.score >= 15 {
                        ctx.anomaly_score = ctx.anomaly_score.saturating_add(2);
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
    // algorithm allow-list before the request reaches origin. Static key
    // material only (HS256 secret or public-key PEM); JWKS-by-`kid` is a
    // documented follow-up. Reasons are prefixed "jwt:" so the block renderer
    // returns 401 (not the generic 403) without leaking the reason to clients.
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
                        // Build the verification key from the site's static key
                        // material. A public-key PEM is parsed as EC when the
                        // policy lists an ES* algorithm, otherwise as RSA.
                        let key = if let Some(secret) = jwt_cfg.hs_secret.as_deref() {
                            Some(jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()))
                        } else if let Some(pem) = jwt_cfg.public_key_pem.as_deref() {
                            let is_ec = jwt_cfg.algorithms.iter().any(|a| a.starts_with("ES"));
                            if is_ec {
                                jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()).ok()
                            } else {
                                jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()).ok()
                            }
                        } else {
                            None
                        };
                        match key {
                            Some(key) => {
                                let policy = JwtPolicy {
                                    algorithms: jwt_cfg.algorithms.clone(),
                                    issuer: jwt_cfg.issuer.clone(),
                                    audience: jwt_cfg.audience.clone(),
                                    required_scopes: jwt_cfg.required_scopes.clone(),
                                    scope_claim: jwt_cfg.scope_claim.clone(),
                                };
                                if let Err(reason) = validate_jwt(token, &key, &policy) {
                                    if jwt_cfg.required {
                                        ctx.decision = WafDecision::Block;
                                        ctx.block_reason = Some(format!("jwt: {reason}"));
                                    }
                                }
                            }
                            None => {
                                // No usable static key (JWKS-only or an
                                // unparseable PEM). Fail closed when required.
                                if jwt_cfg.required {
                                    ctx.decision = WafDecision::Block;
                                    ctx.block_reason = Some(
                                        "jwt: no usable verification key configured".to_string(),
                                    );
                                }
                            }
                        }
                    }
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
                ctx.anomaly_score = ctx.anomaly_score.saturating_add(result.anomaly_score_delta);
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
                        ctx.anomaly_score = ctx
                            .anomaly_score
                            .saturating_add(result2.anomaly_score_delta);
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
        engine.evaluate(ctx, Phase::RequestBody, site.waf.anomaly_threshold);
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
        // Record the would-have-blocked signal for the learning report. We keep
        // `block_reason` so the report can explain *why* the rule would fire;
        // the downgraded decision (Log) means traffic still passes through.
        ctx.would_block = true;
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
fn challenge_response(ctx: &mut RequestContext, mode: ChallengeMode) -> Option<Response<BoxBody>> {
    if matches!(
        mode,
        ChallengeMode::Recaptcha | ChallengeMode::Hcaptcha | ChallengeMode::Turnstile
    ) {
        warn_unsupported_challenge(mode);
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

/// Warn at most once per provider that a configured third-party CAPTCHA mode is
/// not implemented and native Proof-of-Work is served instead.
fn warn_unsupported_challenge(mode: ChallengeMode) {
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
            "challenge mode {:?} is configured but not implemented; serving native Proof-of-Work instead",
            mode
        );
    }
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
        ctx.site_id.as_deref().unwrap_or("-"),
        blocked,
        ctx.elapsed_ms(),
    );
    record_event(ctx);
}

// ---------------------------------------------------------------------------
// Per-second traffic accumulator → ClickHouse traffic_buckets
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SiteAccum {
    reqs: u64,
    blocked: u64,
    lat: Vec<f64>,
}

static TRAFFIC_ACC: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, SiteAccum>>,
> = std::sync::OnceLock::new();

fn traffic_acc() -> &'static std::sync::Mutex<std::collections::HashMap<String, SiteAccum>> {
    TRAFFIC_ACC.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Record one request into the current second's tally. Latency samples are
/// capped per-site to bound memory under floods.
fn record_traffic(site: &str, blocked: bool, latency_ms: f64) {
    // No sink → no accumulation (the drainer only runs when ClickHouse is on).
    if !CLICKHOUSE_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    if let Ok(mut m) = traffic_acc().lock() {
        let e = m.entry(site.to_string()).or_default();
        e.reqs += 1;
        if blocked {
            e.blocked += 1;
        }
        if latency_ms > 0.0 && e.lat.len() < 4096 {
            e.lat.push(latency_ms);
        }
    }
}

/// Drain the accumulator into one TrafficRow per site, stamped with `ts`.
fn drain_traffic(ts: i64) -> Vec<sentinel_storage::TrafficRow> {
    let mut m = match traffic_acc().lock() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::with_capacity(m.len());
    for (site, mut a) in m.drain() {
        a.lat
            .sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        let p99 = if a.lat.is_empty() {
            0.0
        } else {
            let idx = (((a.lat.len() as f64) * 0.99).ceil() as usize).saturating_sub(1);
            a.lat[idx.min(a.lat.len() - 1)]
        };
        out.push(sentinel_storage::TrafficRow {
            ts,
            site_id: site,
            reqs: a.reqs as i64,
            blocked: a.blocked as i64,
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

    let access = serde_json::json!({
        "ts":      ts,
        "ip":      ctx.client_ip.to_string(),
        "method":  ctx.method.as_str(),
        "path":    ctx.uri.path(),
        "status":  status,
        "latency": format!("{:.2}", ctx.elapsed_ms()),
        "bytes":    ctx.bytes_sent,
        "site":     site,
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
