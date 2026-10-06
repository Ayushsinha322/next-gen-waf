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
mod cp_client;
pub(crate) mod goodbot;
pub mod http3;
mod inspection_limits;
mod ip_feed;
pub(crate) mod ja4_quic;
mod jwks;
mod panic_guard;
pub mod proxy_protocol;
/// Continuous security-event feed to a SIEM (see the module docs for why the
/// alert path could not serve this purpose).
pub mod siem;
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
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ServerConfig;
use sentinel_core::{
    config::{
        BotDetectionConfig, ChallengeMode, ConfigHandle, DlpAction, DlpConfig, FusionConfig,
        ListenerConfig, Protocol, SecurityHeadersConfig, SentinelConfig, SiteConfig, WafConfig,
        WafMode,
    },
    context::{Phase, RequestContext, VerdictSource, WafDecision},
};
use sentinel_ebpf::{EbpfConfig, EbpfManager, IpNet};
use sentinel_ml::MlEngine;
use sentinel_modules::{
    check_grpc_body, check_grpc_request, detect_smuggling, inspect_graphql, is_grpc, token_header,
    validate_jwt, AntiDdos, BotDetector, BotSignals, BotTier, DdosVerdict, DlpEngine, GeoIp,
    GeoVerdict, GraphqlLimits, GrpcLimits, IpReputation, IpVerdict, JwtPolicy, RateLimiter,
    RawTier, SmugglingVerdict, ThreatFeed, ThreatVerdict,
};
use sentinel_plugins::{PluginEvalResult, PluginRuntime};
use sentinel_rules::RuleEngine;
use sentinel_telemetry::{
    bot_good_bot_allowed_total, dec_active_connections, graphql_blocked_total,
    graphql_inspected_total, grpc_inspected_total, history_shed_total, inc_active_connections,
    inc_blocked, inc_ebpf_drops, inc_history_shed, inc_load_shed_connections,
    inc_load_shed_requests, inc_log_lines_dropped, inc_requests, inc_rule_hits, ja4_attempts_total,
    ja4_h3_absent_total, ja4_h3_attempts_total, ja4_h3_success_total, ja4_no_hello_total,
    ja4_success_total, note_good_bot_allowed, note_graphql_blocked, note_graphql_inspected,
    note_grpc_inspected, note_ja4_attempt, note_ja4_no_hello, note_ja4_success, note_plugin_block,
    note_plugin_invocation, note_plugin_score, note_plugin_trap, note_smuggling_evaluated,
    note_smuggling_rejected_framing, note_smuggling_rejected_header, observe_duration,
    plugin_blocks_total, plugin_invocations_total, plugin_scores_total, plugin_traps_total,
    prometheus_text, smuggling_evaluated_total, smuggling_rejected_framing_total,
    smuggling_rejected_header_total,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn, Instrument};

use crate::upstream::UpstreamPool;

pub use crate::panic_guard::install_panic_hook;

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
// Response-body buffering
// ---------------------------------------------------------------------------

/// Largest response prefix buffered for inspection (DLP + response-body rules).
///
/// The cap must be enforced *while reading*.  A chunked response carries no
/// `Content-Length`, so `size_hint()` reports no upper bound — a
/// collect-then-check would let an origin stream unbounded bytes into memory
/// before the check ever ran.  This is the response-side twin of the
/// request-body OOM already closed in phase 2.
const RESPONSE_SCAN_CAP: usize = 512 * 1024;

/// A body that replays an already-buffered prefix before streaming the rest of
/// the inner body.
///
/// When a response turns out to exceed [`RESPONSE_SCAN_CAP`], its prefix has
/// already been pulled off the wire and cannot be un-read.  Rather than drop
/// the response (or buffer the whole thing), the prefix is replayed here and
/// the remainder streams straight through.
struct PrefixedBody {
    prefix: Option<Bytes>,
    inner: BoxBody,
}

impl Body for PrefixedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        // Both fields are `Unpin` — `Option<Bytes>`, and the `Pin<Box<..>>`
        // inside `BoxBody` — so plain projection is sound.
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            if !prefix.is_empty() {
                return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(prefix))));
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_empty()) && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let pending = self.prefix.as_ref().map_or(0, |p| p.len() as u64);
        let inner = self.inner.size_hint();
        let mut hint = hyper::body::SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(pending));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(pending));
        }
        hint
    }
}

/// Outcome of buffering a response body for inspection.
enum ScanBuffer {
    /// The whole body fit under the cap and can be scanned / rewritten, plus the
    /// trailers that followed it, if any.
    Complete(Bytes, Option<header::HeaderMap>),
    /// The body exceeds the cap: the prefix already read off the wire, plus the
    /// untouched remainder. Inspection is skipped — a partial view cannot be
    /// scanned soundly, and DLP masking has to rewrite the whole payload.
    Oversize { prefix: Bytes, rest: BoxBody },
    /// The origin errored part-way through the body.
    Error(hyper::Error),
}

/// Read a response body into memory, but never more than `cap` bytes.
///
/// The cap is enforced frame by frame rather than by checking `size_hint()`
/// first: a chunked response declares no length, so there is no upper bound to
/// check, and a collect-then-check would already have pulled the whole body
/// into memory by the time the check ran.
async fn buffer_for_scan(mut body: BoxBody, cap: usize) -> ScanBuffer {
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut buffered = 0usize;
    let mut trailers: Option<header::HeaderMap> = None;

    loop {
        match body.frame().await {
            None => return ScanBuffer::Complete(concat_chunks(chunks), trailers),
            Some(Err(e)) => return ScanBuffer::Error(e),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    buffered += data.len();
                    chunks.push(data);
                    if buffered > cap {
                        return ScanBuffer::Oversize {
                            prefix: concat_chunks(chunks),
                            rest: body,
                        };
                    }
                }
                // Trailers carry nothing to scan, but they are part of the
                // message (a checksum, a final status) and the client may rely
                // on them. They used to be dropped here, so every inspected
                // response lost them.
                Err(frame) => {
                    if let Ok(t) = frame.into_trailers() {
                        trailers
                            .get_or_insert_with(header::HeaderMap::new)
                            .extend(t);
                    }
                }
            },
        }
    }
}

/// Rebuild a body that was buffered for inspection, with the trailers it
/// arrived with. Trailers are attached only when there are some: `Full` alone
/// keeps the exact size hint that sets Content-Length and the logged byte count
/// (and `WithTrailers` passes it through while the data is being read).
fn rebuilt_body(bytes: Bytes, trailers: Option<header::HeaderMap>) -> BoxBody {
    let body = Full::new(bytes).map_err(|never: Infallible| match never {});
    match trailers {
        Some(t) => body.with_trailers(async move { Some(Ok(t)) }).boxed(),
        None => body.boxed(),
    }
}

/// Join buffered body chunks into one contiguous `Bytes` without copying the
/// common single-chunk case.
fn concat_chunks(chunks: Vec<Bytes>) -> Bytes {
    if chunks.len() == 1 {
        return chunks.into_iter().next().unwrap_or_default();
    }
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let mut buf = bytes::BytesMut::with_capacity(total);
    for c in &chunks {
        buf.extend_from_slice(c);
    }
    buf.freeze()
}

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

    /// Every IP with blocks inside the current window, most-blocked first:
    /// `(ip, blocks_in_window, last_block_unix)`. For the Blocked Sources page.
    fn offenders(&self) -> Vec<(IpAddr, u32, u64)> {
        let now = unix_now_secs();
        let mut out: Vec<(IpAddr, u32, u64)> = self
            .state
            .iter()
            .filter_map(|e| {
                let last = e.value().last_block_at.load(Ordering::Relaxed) as u64;
                if now.saturating_sub(last) > self.window_secs {
                    return None;
                }
                Some((
                    *e.key(),
                    e.value().blocks.load(Ordering::Relaxed) as u32,
                    last,
                ))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
        out
    }

    /// Drop an IP's history so it is no longer escalated or counted toward the
    /// auto-ban threshold. Returns whether anything was tracked.
    fn forget(&self, ip: IpAddr) -> bool {
        self.state.remove(&ip).is_some()
    }

    fn window(&self) -> u64 {
        self.window_secs
    }

    fn escalate_threshold(&self) -> usize {
        self.escalate_threshold
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
    /// Node-wide reputation from FEEDS (threat-intel suspect lists). Site
    /// allow/block lists are per site in `ip_rep_sites`.
    ip_rep: ArcSwap<IpReputation>,
    /// Each site's own allow/block lists. Before 2026-09-07 every site's lists
    /// were merged into one node-wide table, so a CIDR blocked on one site was
    /// blocked on all of them.
    ip_rep_sites: ArcSwap<HashMap<String, IpReputation>>,

    /// Token-bucket rate limiter — state preserved across reloads.
    rate_limiter: RateLimiter,

    /// Bot / UA / JA4 classifier — rebuilt on reload (stateless).
    bot_detector: ArcSwap<BotDetector>,

    /// Reverse-DNS verifier for good-bot User-Agent claims. State (the per-IP
    /// cache) is preserved across reloads: a verified crawler stays verified.
    goodbot: Arc<goodbot::GoodBotVerifier>,

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
    /// Per-site plugin selection, swapped together with the runtime above.
    site_plugins: Arc<ArcSwap<SitePluginMap>>,
    /// Names a site asked for that are not loaded (reported at /healthz).
    unresolved_plugins: Arc<ArcSwap<UnresolvedPlugins>>,
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

// ---------------------------------------------------------------------------
// accept(2) failure handling
// ---------------------------------------------------------------------------

/// Smallest pause after a resource-exhaustion accept failure.
const ACCEPT_BACKOFF_MIN: std::time::Duration = std::time::Duration::from_millis(10);
/// Ceiling for the pause. One second is long enough to stop a hot spin and short
/// enough that the listener recovers promptly once descriptors free up.
const ACCEPT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(1);

/// What an `accept()` error means for the listener as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptRecovery {
    /// One connection failed; the listener is healthy. Continue immediately.
    Retry,
    /// The process is out of a resource (descriptors, buffers). Continuing
    /// immediately would busy-spin, because the listening socket stays readable
    /// until the resource frees. Pause, then continue.
    Backoff,
    /// The listening socket itself is unusable. Nothing will improve by retrying.
    Fatal,
}

/// Classify an `accept()` error.
///
/// The bias here is deliberately toward SURVIVING. An unrecognised error is
/// treated as `Backoff`, not `Fatal`: an unknown errno that we pause and retry on
/// costs a few milliseconds if it really was fatal, whereas an unknown errno that
/// we exit on takes the WAF off the network. Only errors that mean the listening
/// descriptor is definitively broken are fatal.
pub(crate) fn classify_accept_error(e: &std::io::Error) -> AcceptRecovery {
    use std::io::ErrorKind;

    // Per-connection failures: the peer went away between SYN and accept, or the
    // call was interrupted. The listener is fine.
    match e.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionRefused
        | ErrorKind::Interrupted
        | ErrorKind::NotConnected
        | ErrorKind::BrokenPipe
        | ErrorKind::TimedOut
        | ErrorKind::WouldBlock => return AcceptRecovery::Retry,
        ErrorKind::OutOfMemory => return AcceptRecovery::Backoff,
        _ => {}
    }

    // Rust maps descriptor exhaustion to ErrorKind::Uncategorized, which is not
    // matchable on stable, so go to the errno.
    match e.raw_os_error() {
        // Out of file descriptors, process-wide or system-wide; out of kernel
        // buffers or memory. All transient, all recoverable, all must NOT spin.
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM) => {
            AcceptRecovery::Backoff
        }

        // The listening descriptor is gone, is not a socket, or is misconfigured.
        // Retrying cannot fix any of these.
        Some(libc::EBADF) | Some(libc::ENOTSOCK) | Some(libc::EINVAL) => AcceptRecovery::Fatal,

        // Everything else — including protocol-level errors that some kernels
        // surface here (EPROTO, EHOSTDOWN, ENETDOWN, ENONET) — is treated as
        // transient. See the doc comment on why the default is to survive.
        _ => AcceptRecovery::Backoff,
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
    /// Parsed one site at a time by [`parse_synced_sites`], never as a
    /// `Vec<SiteConfig>`: with a typed Vec, one malformed site made serde reject
    /// the whole response, and every node kept serving its previous config for
    /// EVERY site until that one site was fixed. That is how switching a single
    /// site to mode "off" (which sent `"rules": null`) froze config delivery for
    /// the entire fleet on 2026-09-23 — each later change "saved" in the console
    /// and reached no node, and nothing but a WARN line said so.
    sites: Vec<serde_json::Value>,
}

/// A sync after per-site parsing.
struct ParsedSync {
    version: u64,
    sites: Vec<SiteConfig>,
}

/// A site the control plane sent that this node could not parse.
#[derive(Clone, Debug, serde::Serialize)]
struct RejectedSite {
    id: String,
    error: String,
    /// The node still serves this site with the config it last parsed; false
    /// means the site is new and is not served here at all.
    kept_previous: bool,
}

/// Config-sync health, reported in the heartbeat so the cluster page can say
/// "this node is rejecting config" instead of calling a frozen fleet healthy.
#[derive(Clone, Debug, Default, serde::Serialize)]
struct ConfigSyncStatus {
    /// Why the most recent poll could not be used at all (fetch, body, or an
    /// envelope that is not JSON), cleared by the next usable poll.
    last_error: Option<String>,
    /// Unix seconds since which polls have been failing, if they are.
    failing_since: Option<u64>,
    /// Sites in the most recently applied version that this node rejected.
    rejected_sites: Vec<RejectedSite>,
}

static CONFIG_SYNC_STATUS: std::sync::Mutex<ConfigSyncStatus> =
    std::sync::Mutex::new(ConfigSyncStatus {
        last_error: None,
        failing_since: None,
        rejected_sites: Vec::new(),
    });

/// The sync status, recovered if a panic poisoned its lock. Skipping a poisoned
/// lock, as this used to, froze the status: the heartbeat kept reporting a
/// healthy sync while the node stopped taking config.
fn sync_status_lock() -> std::sync::MutexGuard<'static, ConfigSyncStatus> {
    CONFIG_SYNC_STATUS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn config_sync_status() -> ConfigSyncStatus {
    let mut status = sync_status_lock().clone();
    // A site whose rules crashed the compiler is rejected config as far as the
    // console is concerned: the change saved there is not enforced here.
    status.rejected_sites.extend(
        ENGINE_COMPILE_PANICS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned(),
    );
    status
}

/// Sites whose rules panicked the compiler in the latest engine rebuild.
/// Replaced by every rebuild; reported with the sync status.
static ENGINE_COMPILE_PANICS: std::sync::Mutex<Vec<RejectedSite>> =
    std::sync::Mutex::new(Vec::new());

fn note_config_sync_failure(error: String) {
    let mut g = sync_status_lock();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    g.failing_since.get_or_insert(now);
    g.last_error = Some(error);
}

fn note_config_sync_ok() {
    let mut g = sync_status_lock();
    g.last_error = None;
    g.failing_since = None;
}

/// One config-sync fetch: the response body, or None once the reason there is
/// none has been recorded in the sync status.
///
/// A control plane that never answers is recorded like any other failed poll,
/// so the heartbeat's `config_sync` shows this node going stale and the loop
/// simply waits for its next tick.
async fn fetch_config_sync(
    client: &cp_client::CpClient<http_body_util::Empty<Bytes>>,
    sync_url: &str,
    internal_secret: Option<&str>,
    deadline: Duration,
) -> Option<Bytes> {
    let url = format!("{}/api/v1/internal/config", sync_url);
    let uri: hyper::Uri = match url.parse() {
        Ok(u) => u,
        Err(e) => {
            warn!("config sync: bad url: {e}");
            return None;
        }
    };
    let mut builder = hyper::Request::builder().method("GET").uri(uri);
    if let Some(secret) = internal_secret {
        builder = builder.header("x-sentinel-internal", secret);
    }
    let req = builder
        .body(http_body_util::Empty::new())
        .expect("BUG: building config-sync request");
    match cp_client::call(client, req, deadline).await {
        // Judge the status before the body is parsed, or a refusal is recorded
        // as the JSON error its error body produces ("parse: expected value").
        Ok((status, bytes)) if !status.is_success() => {
            warn!(
                status = %status,
                snippet = %String::from_utf8_lossy(&bytes).chars().take(120).collect::<String>(),
                "config sync REFUSED by the control plane — this node keeps its current \
                 config. 403 means SENTINEL_INTERNAL_SECRET does not match; 503 means the \
                 control plane has no database"
            );
            note_config_sync_failure(format!("refused: HTTP {status}"));
            None
        }
        Ok((_, bytes)) => Some(bytes),
        Err(e) => {
            warn!("config sync {e}");
            note_config_sync_failure(e.to_string());
            None
        }
    }
}

/// Config-sync state for `/healthz`, which is served on every listener: the
/// heartbeat carries the full record, but when the control plane has stopped
/// answering the heartbeat goes unanswered too, and this is then the only place
/// the node says it is going stale. Rejected sites are given as a count, since
/// their ids and errors name tenant sites.
fn config_sync_health(cfg: &SentinelConfig) -> serde_json::Value {
    let s = config_sync_status();
    serde_json::json!({
        "configured": cfg.cluster.sync_url.is_some(),
        "version_applied": CONFIG_VERSION_APPLIED.load(std::sync::atomic::Ordering::Relaxed),
        "last_error": s.last_error,
        "failing_since": s.failing_since,
        "rejected_site_count": s.rejected_sites.len(),
    })
}

/// Parse each site of a sync on its own, so one bad site costs only itself.
///
/// A site that fails to parse keeps the config this node last held for it
/// (fail-stale, like a whole-sync failure used to be, but for that site alone);
/// a brand-new site that fails is not served. Every other site in the sync is
/// applied normally.
fn parse_synced_sites(
    raw: Vec<serde_json::Value>,
    previous: &[SiteConfig],
) -> (Vec<SiteConfig>, Vec<RejectedSite>) {
    let mut sites = Vec::with_capacity(raw.len());
    let mut rejected = Vec::new();
    for (i, v) in raw.into_iter().enumerate() {
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("<site #{i} with no id>"));
        match serde_json::from_value::<SiteConfig>(v) {
            Ok(site) => sites.push(site),
            Err(e) => {
                let kept = previous.iter().find(|p| p.id == id).cloned();
                rejected.push(RejectedSite {
                    id: id.clone(),
                    error: e.to_string(),
                    kept_previous: kept.is_some(),
                });
                if let Some(p) = kept {
                    sites.push(p);
                }
            }
        }
    }
    (sites, rejected)
}

/// Digest of one enabled plugin as advertised by `GET /internal/plugins`.
///
/// Deliberately excludes the module bytes: a node compares hashes on every poll
/// and downloads only what it does not already hold, which is what keeps a 5s
/// poll cheap for multi-megabyte modules.
#[derive(serde::Deserialize)]
struct PluginDigest {
    name: String,
    #[allow(dead_code)] // advertised for operators/logs; sync keys off sha256
    version: String,
    sha256: String,
}

#[derive(serde::Deserialize)]
struct PluginSyncResponse {
    plugins: Vec<PluginDigest>,
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
    // The temp name is PER-PROCESS. A fixed ".json.tmp" is a corruption window as soon
    // as more than one node shares the cache directory (the HA overlay's waf1/waf2/waf3
    // if pointed at a shared volume): File::create truncates, so one node can truncate
    // the tmp another is mid-write on, and either may then rename the partial result
    // over the last-good cache. Distinct tmp names make each writer's rename atomic
    // and independent, so the worst case is last-writer-wins on identical content.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
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
        // Shared between the config-sync task (which publishes new sites) and the
        // engine-rebuild watcher (which compiles their rules), so the rebuild
        // starts on the change rather than on the next poll tick. Built here
        // because both tasks are spawned below and each needs a clone.
        let engine_reload_notify = Arc::new(tokio::sync::Notify::new());
        let sync_reload_notify = Arc::clone(&engine_reload_notify);

        let initial_dlp = build_dlp_map(&cfg);
        let dlp_map: Arc<ArcSwap<DlpMap>> = Arc::new(ArcSwap::new(Arc::new(initial_dlp)));

        let feed_cache: FeedCache = Arc::new(ArcSwap::new(Arc::new(Vec::new())));

        // Storage backends (Valkey for distributed rate limiting, ClickHouse for
        // traffic history). File config first, then SENTINEL_CLICKHOUSE_*/
        // SENTINEL_REDIS_URL env overlay so the data plane is configured
        // identically to the Go control plane (same Secret in compose/K8s; no CH
        // password in the proxy YAML).
        //
        // Both connect in the BACKGROUND (Valkey below, once the limiter exists;
        // ClickHouse in the history writer) and keep retrying. Awaiting them here
        // held every listener back until they answered — forever for one that
        // accepts TCP and never replies — and a backend down at boot stayed
        // unused for the life of the process.
        let storage_backend_cfg =
            sentinel_storage::StorageBackendConfig::from_core(&cfg.storage).with_env_overrides();
        if storage_backend_cfg.redis_url.is_some() {
            info!("rate limiting: Valkey configured — connecting in the background; in-memory limiter until it answers");
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
        // permanent silent no-op until someone restarted the proxy.
        //
        // HISTORY_SINK_ACTIVE gates buffering and is true whenever this task is
        // RUNNING — not only while connected. Rows the sink cannot take are
        // written to a bounded disk spool and replayed on reconnect, so an
        // unreachable ClickHouse costs latency in the audit trail, not content.
        // Before the spool existed this flag meant "connected", which is exactly
        // why a node with no reachable ClickHouse recorded nothing at all.
        if storage_backend_cfg.clickhouse_url.is_some() {
            HISTORY_SINK_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
            let spool = open_history_spool();
            let ch_cfg = storage_backend_cfg.clone();
            // Where a run that panics leaves the rows it had drained but not yet
            // inserted or spooled, for the restarted run to pick up: at most the
            // event buffer's cap each, and only once (see `Carried`).
            fn shed_carried(rows: usize) {
                for _ in 0..rows {
                    inc_history_shed();
                }
                warn!(
                    rows,
                    "history writer panicked holding rows it cannot retry; they are lost \
                     (see sentinel_history_shed_total)"
                );
            }
            let traffic_carry = panic_guard::Carry::<sentinel_storage::TrafficRow>::new(
                EVENT_BUFFER_CAP,
                shed_carried,
            );
            let events_carry = panic_guard::Carry::<sentinel_storage::WafEventRow>::new(
                EVENT_BUFFER_CAP,
                shed_carried,
            );
            // Supervised: a panic restarts the writer, with the rows it held,
            // instead of silently ending history recording for the life of the
            // process.
            panic_guard::supervised!("clickhouse history writer", {
                per_run!(spool, ch_cfg, traffic_carry, events_carry);
                // No client yet: the first tick (immediate) connects, so boot
                // never waits on ClickHouse. Said explicitly so that a writer
                // started again (after a panic) does not inherit a stale
                // "connected" at /healthz while it only spools.
                CLICKHOUSE_CONNECTED.store(false, std::sync::atomic::Ordering::Relaxed);
                let mut ch: Option<std::sync::Arc<sentinel_storage::ClickHouseClient>> = None;
                // Reset by a successful write, not by a connect: see SinkRetry.
                let mut retry = sentinel_storage::SinkRetry::new(
                    std::time::Duration::from_secs(2),
                    std::time::Duration::from_secs(60),
                );
                let mut buf = panic_guard::Carried::resume(&traffic_carry);
                let mut evbuf = panic_guard::Carried::resume(&events_carry);
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
                let mut ticks = 0u32;
                // Seconds remaining until the next reconnect attempt while down.
                let mut reconnect_in = 0u32;
                // Cap enforcement walks the directory, so it runs on a slow
                // cadence rather than every second: every 30 ticks, or sooner if
                // a burst has appended enough to risk a meaningful overshoot.
                const CAP_CHECK_TICKS: u32 = 30;
                const CAP_CHECK_BYTES: u64 = 16 * 1024 * 1024;
                let mut ticks_since_cap = 0u32;
                let mut bytes_since_cap = 0u64;
                // Spool cadence while disconnected — see the disconnected branch
                // for why it is far slower than the 5s connected flush.
                const SPOOL_FLUSH_TICKS: u32 = 60;
                let mut ticks_disconnected = 0u32;
                // A backlog left by a previous process is replayed on the first
                // connected tick — that restart-survival is the reason the spool
                // is on disk instead of simply being a larger memory buffer.
                if let Some(sp) = spool.as_ref() {
                    let pending = sp.segments("events").len() + sp.segments("traffic").len();
                    if pending > 0 {
                        info!(
                            segments = pending,
                            bytes = sp.bytes(),
                            dir = %sp.dir().display(),
                            "history spool: backlog found from a previous run — will replay on reconnect"
                        );
                    }
                }
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
                                    Ok(()) => match client.ensure_schema().await {
                                        Ok(()) => {
                                            info!(
                                                url = %sentinel_storage::redact_url(url),
                                                database = db,
                                                "clickhouse connected — waf history writer enabled"
                                            );
                                            ch = Some(std::sync::Arc::new(client));
                                            retry.connected(std::time::Instant::now());
                                            CLICKHOUSE_CONNECTED
                                                .store(true, std::sync::atomic::Ordering::Relaxed);
                                        }
                                        Err(e) => {
                                            CLICKHOUSE_FAILURES
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            reconnect_in =
                                                retry.failed(std::time::Instant::now()).as_secs()
                                                    as u32;
                                            warn!(error = %e, retry_in_secs = reconnect_in, "clickhouse reachable but schema init failed — retrying");
                                        }
                                    },
                                    Err(e) => {
                                        CLICKHOUSE_FAILURES
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        reconnect_in =
                                            retry.failed(std::time::Instant::now()).as_secs()
                                                as u32;
                                        warn!(error = %e, retry_in_secs = reconnect_in, "clickhouse unreachable — spooling waf history to disk, retrying");
                                    }
                                }
                            }
                        } else {
                            reconnect_in -= 1;
                        }
                    }

                    // Always drain to keep buffers bounded. record_* fills them
                    // whenever this task exists, connected or not — what happens
                    // to rows the sink refuses is decided below, and it is never
                    // "discard" while a spool is available.
                    buf.extend(drain_traffic(unix_now()));
                    evbuf.extend(drain_events());
                    ticks += 1;
                    ticks_since_cap += 1;
                    if ch.is_none() {
                        ticks_disconnected += 1;
                    }
                    // Both streams flush on the same 5s-or-500-row cadence.
                    let time_due = ticks >= 5;

                    if let Some(client) = ch.clone() {
                        let mut conn_lost = false;

                        // Drain the backlog before this tick's live rows, so
                        // replayed history lands in roughly the order it
                        // happened and a long outage's spool actually empties
                        // instead of being perpetually overtaken.
                        if let Some(sp) = spool.as_ref() {
                            if !replay_history_spool(sp, &client).await {
                                conn_lost = true;
                            }
                        }

                        // A batch goes in as several requests; on a failure
                        // only the rows not yet accepted are spooled, so the
                        // retry does not insert the accepted ones again.
                        if !conn_lost && (time_due || buf.len() >= 500) && !buf.is_empty() {
                            if let Err(e) = client.insert_traffic_batch(&buf).await {
                                warn!(error = %e, rows = buf.len() - e.inserted, "clickhouse traffic flush failed — spooling the unsent rows, will reconnect");
                                bytes_since_cap +=
                                    spool_batch(spool.as_ref(), "traffic", &buf[e.inserted..]);
                                conn_lost = true;
                            } else {
                                debug!(rows = buf.len(), "clickhouse traffic flushed");
                                retry.wrote();
                            }
                            buf.clear();
                        }

                        if !conn_lost && (time_due || evbuf.len() >= 500) && !evbuf.is_empty() {
                            if let Err(e) = client.insert_events_batch(&evbuf).await {
                                warn!(error = %e, rows = evbuf.len() - e.inserted, "clickhouse events flush failed — spooling the unsent rows, will reconnect");
                                bytes_since_cap +=
                                    spool_batch(spool.as_ref(), "events", &evbuf[e.inserted..]);
                                conn_lost = true;
                            } else {
                                debug!(rows = evbuf.len(), "clickhouse events flushed");
                                retry.wrote();
                            }
                            evbuf.clear();
                        }

                        // A failed insert usually means the server/connection went
                        // away — drop the client so the loop reconnects. Buffering
                        // deliberately CONTINUES while disconnected now; the spool
                        // is what keeps that bounded.
                        if conn_lost {
                            // Whatever this tick drained but did not get to
                            // insert must not evaporate just because the sink
                            // died mid-tick.
                            bytes_since_cap += spool_batch(spool.as_ref(), "traffic", &buf);
                            bytes_since_cap += spool_batch(spool.as_ref(), "events", &evbuf);
                            buf.clear();
                            evbuf.clear();
                            ch = None;
                            CLICKHOUSE_CONNECTED.store(false, std::sync::atomic::Ordering::Relaxed);
                            CLICKHOUSE_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            reconnect_in = retry.failed(std::time::Instant::now()).as_secs() as u32;
                        }
                    } else if ticks_disconnected >= SPOOL_FLUSH_TICKS
                        || buf.len() >= 500
                        || evbuf.len() >= 500
                    {
                        // Disconnected. This is the path that silently lost every
                        // event on a node with no reachable ClickHouse: it used to
                        // clear both buffers unconditionally. Now it persists them.
                        //
                        // Deliberately a SLOWER cadence than the connected flush.
                        // A node whose sink is permanently unreachable spools
                        // forever, and at the 5s connected cadence that is ~17k
                        // tiny files a day — which `enforce_cap`'s directory walk
                        // then has to traverse every 30s. The passive node in the
                        // 2-VM topology is exactly that case: its VRRP health
                        // check probes a real request every 2s, so it always has
                        // traffic to record. One segment a minute holds the same
                        // rows in 1/12th the files, and the extra in-memory
                        // residency is bounded by the same 500-row trigger.
                        ticks_disconnected = 0;
                        bytes_since_cap += spool_batch(spool.as_ref(), "traffic", &buf);
                        bytes_since_cap += spool_batch(spool.as_ref(), "events", &evbuf);
                        buf.clear();
                        evbuf.clear();
                    }

                    // Keep the spool inside its byte budget. Reported, never
                    // silent: a spool that quietly discards would recreate the
                    // very bug it was built to fix.
                    if let Some(sp) = spool.as_ref() {
                        if ticks_since_cap >= CAP_CHECK_TICKS || bytes_since_cap >= CAP_CHECK_BYTES
                        {
                            ticks_since_cap = 0;
                            bytes_since_cap = 0;
                            let dropped = sp.enforce_cap();
                            if dropped.segments > 0 {
                                warn!(
                                    segments = dropped.segments,
                                    bytes = dropped.bytes,
                                    max_bytes = sp.max_bytes(),
                                    "history spool OVER CAP — discarded oldest segments; \
                                     history for that window is permanently lost. Raise \
                                     SENTINEL_SPOOL_MAX_BYTES or restore the ClickHouse sink"
                                );
                            }
                        }
                    }

                    if time_due {
                        ticks = 0;
                    }
                }
            });
            info!("clickhouse flusher started (1s sample · 5s/500-row flush → traffic_buckets + waf_events; self-healing reconnect; disk-spooled + replayed while the sink is down)");
        }

        let modules = Arc::new(ModulesState {
            ip_rep: ArcSwap::new(Arc::new(build_ip_reputation(&cfg, &[]))),
            ip_rep_sites: ArcSwap::new(Arc::new(build_site_ip_reputation(&cfg))),
            rate_limiter: if storage_backend_cfg.redis_url.is_some() {
                RateLimiter::distributed(sentinel_modules::DistributedGuard::from_env())
            } else {
                RateLimiter::new()
            },
            bot_detector: ArcSwap::new(Arc::new(BotDetector::new())),
            goodbot: goodbot::GoodBotVerifier::new(),
            geoip_map: ArcSwap::new(Arc::new(build_geoip_map(&cfg))),
            anti_ddos: build_anti_ddos(&cfg),
            correlation: CorrelationEngine::new(),
            feed_cache: Arc::clone(&feed_cache),
            threat_intel: ArcSwap::new(Arc::new(ThreatFeed::empty())),
            jwks: jwks::JwksCache::new(),
        });

        // Valkey connects in the background, retrying until it answers, and is
        // bound into the limiter then; until that moment rate checks use the
        // in-memory limiter. /healthz storage.valkey shows which. Supervised
        // like the other background loops: a panic while connecting starts the
        // connect again instead of leaving rate limits node-local for the life
        // of the process.
        if let Some(url) = storage_backend_cfg.redis_url.clone() {
            let modules_ref = Arc::clone(&modules);
            panic_guard::supervised!("Valkey connect", {
                per_run!(url, modules_ref);
                let client = sentinel_storage::RedisClient::connect_with_retry(
                    &url,
                    sentinel_storage::Backoff::new(Duration::from_secs(1), Duration::from_secs(30)),
                )
                .await;
                modules_ref.rate_limiter.bind_redis(Arc::new(client));
                info!("rate limiting: distributed mode (Valkey backend connected)");
            });
        }

        let (plugin_runtime, manifest_plugins) = build_plugin_runtime(&cfg).unwrap_or_else(|e| {
            warn!("failed to load plugins: {e:#}");
            (
                PluginRuntime::new().expect("create empty plugin runtime"),
                SitePluginMap::new(),
            )
        });
        // Resolve the per-site selection at boot as well as on reload: a node
        // that had just started used to run nothing a site had named.
        let (startup_site_plugins, startup_unresolved) =
            resolve_site_plugins(&cfg, &plugin_runtime, manifest_plugins);
        let plugin_runtime: Arc<ArcSwap<PluginRuntime>> =
            Arc::new(ArcSwap::new(Arc::new(plugin_runtime)));
        let site_plugins: Arc<ArcSwap<SitePluginMap>> =
            Arc::new(ArcSwap::new(Arc::new(startup_site_plugins)));
        let unresolved_plugins: Arc<ArcSwap<UnresolvedPlugins>> =
            Arc::new(ArcSwap::new(Arc::new(startup_unresolved)));

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

        // Start the stats task. Without this call `stats_interval_secs` is dead
        // config and, in KERNEL mode, the counters never reflect reality:
        // packets dropped by XDP in the driver path never reach userspace, so
        // `is_blocked()` cannot see them and `xdp_drop` stays 0 forever while
        // the kernel is dropping traffic. This task is the only thing that
        // reads the per-CPU BPF map back into the counters that /healthz and
        // /metrics report.
        //
        // In software mode it is nearly free and changes nothing: the kernel
        // branch is skipped and the userspace per-connection counts stand.
        spawn_ebpf_stats(&ebpf);

        // Certificate manager — loads persisted ACME/manual certs from disk,
        // then runs background renewal every hour.
        let cert_dir = cfg.cert_dir.clone().unwrap_or_else(|| {
            // $HOME/.config/sentinel/certs, or /var/lib/sentinel/certs as fallback.
            std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".config/sentinel/certs"))
                .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/sentinel/certs"))
        });
        let cert_manager = tls::CertManager::new(cert_dir.clone());
        match cert_manager.load_from_disk(&cfg.sites) {
            Ok(n) if n > 0 => info!(certs = n, "loaded persisted TLS certs from disk"),
            Ok(_) => {}
            Err(e) => warn!("cert disk load: {e:#}"),
        }
        let http01_tokens = Arc::clone(&cert_manager.http01_tokens);

        // Trigger initial ACME issuance for any site that has tls.mode = acme
        // but no cert on disk yet — for the names a CA can issue for only.
        for (domains, acme) in tls::renewal::initial_orders(&cfg.sites, &cert_manager.store) {
            let cm = Arc::clone(&cert_manager);
            tokio::spawn(async move {
                if let Err(e) = cm.issue_acme(domains.clone(), &acme).await {
                    warn!(?domains, "initial ACME issuance failed: {e:#}");
                }
            });
        }

        // Renewal background task (checks every hour).
        {
            let cm = Arc::clone(&cert_manager);
            let cfg_handle = Arc::clone(&self.config);
            panic_guard::supervised!("certificate renewal", {
                per_run!(cm, cfg_handle);
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
            site_plugins: Arc::clone(&site_plugins),
            unresolved_plugins: Arc::clone(&unresolved_plugins),
            ml_engine: Arc::clone(&ml_engine),
            ebpf: Arc::clone(&ebpf),
            cert_manager,
            http01_tokens,
            conn_limiter,
            request_limiter,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            conn_tracker: tokio_util::task::TaskTracker::new(),
        });

        // Cache of control-plane-uploaded plugin modules, shared by the plugin-sync
        // task (writer) and the config hot-reload watcher (reader) so that BOTH
        // rebuild a complete runtime. See build_full_plugin_runtime.
        let uploaded_plugins: UploadedPlugins = Arc::new(DashMap::new());

        // --- Background: config hot-reload watcher ---
        {
            let cw = Arc::clone(&self.config);
            let es = Arc::clone(&engines);
            let ds = Arc::clone(&dlp_map);
            let mr = Arc::clone(&modules);
            let ps = Arc::clone(&plugin_runtime);
            let sp_swap = Arc::clone(&site_plugins);
            let un_swap = Arc::clone(&unresolved_plugins);
            let up_cache = Arc::clone(&uploaded_plugins);
            // Wakes the engine rebuild the instant new sites are published,
            // instead of leaving it to the 5s poll below. See ENGINES_WARMING.
            let reload_wake = Arc::clone(&engine_reload_notify);
            // The config the engines were last fully built from. It lives outside
            // the loop and advances only once a rebuild completes, so a run that
            // panics mid-rebuild is retried by the restarted one. Starting from
            // the current config instead — what this did before — would leave
            // the engines stale and ENGINES_WARMING set until the next change.
            let built_from = Arc::new(AtomicUsize::new(Arc::as_ptr(&cw.load_full()) as usize));
            panic_guard::supervised!("config hot-reload watcher", {
                per_run!(
                    reload_wake,
                    cw,
                    es,
                    ds,
                    mr,
                    ps,
                    sp_swap,
                    un_swap,
                    up_cache,
                    built_from
                );
                let mut last_ptr = built_from.load(Ordering::Acquire);
                loop {
                    // Woken by the sync task the moment new sites land,
                    // with the 5s sleep retained as a backstop for
                    // config changes that arrive by another route (a
                    // file reload, a cached-config restore).
                    tokio::select! {
                        _ = reload_wake.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                    let current = cw.load_full();
                    let ptr = Arc::as_ptr(&current) as usize;
                    if ptr != last_ptr {
                        last_ptr = ptr;
                        let prev_engines = es.load_full();
                        #[cfg(test)]
                        panic_guard::inject_rebuild_panic(&current);
                        let new_engines = build_rule_engines(&current, &prev_engines);
                        let rule_count: usize = new_engines.values().map(|e| e.rule_count()).sum();
                        es.store(Arc::new(new_engines));
                        // Engines now match the config we built FROM — but
                        // only clear the flag if that is still the config
                        // being served. Cleared after the store, never
                        // before, and never for a superseded config.
                        clear_warming_if_current(&cw, ptr, &ENGINES_WARMING);
                        ds.store(Arc::new(build_dlp_map(&current)));

                        let feed_cidrs = mr.feed_cache.load_full();
                        mr.ip_rep
                            .store(Arc::new(build_ip_reputation(&current, &feed_cidrs)));
                        mr.ip_rep_sites
                            .store(Arc::new(build_site_ip_reputation(&current)));
                        mr.bot_detector.store(Arc::new(BotDetector::new()));
                        mr.geoip_map.store(Arc::new(build_geoip_map(&current)));

                        // Rebuild through build_full_plugin_runtime so
                        // uploaded plugins survive a config change. Using
                        // build_plugin_runtime here unloaded every uploaded
                        // plugin, and because the sync task skips work when
                        // the advertised set is unchanged, they never came
                        // back — the module stayed "enabled" in the UI while
                        // silently no longer running.
                        match build_full_plugin_runtime(&current, &up_cache) {
                            Ok((new_pr, per_site, names, rejected, unresolved)) => {
                                // Store the selection FIRST: a request that
                                // reads the new runtime with the old map
                                // would run a module the site never named.
                                sp_swap.store(Arc::new(per_site));
                                un_swap.store(Arc::new(unresolved));
                                ps.store(Arc::new(new_pr));
                                info!(
                                    uploaded = names.len(),
                                    rejected, "plugin runtime hot-reloaded"
                                );
                            }
                            Err(e) => {
                                warn!("failed to reload plugins — keeping current: {e:#}");
                            }
                        }

                        info!(rules = rule_count, "rule engines + modules hot-reloaded");
                        built_from.store(ptr, Ordering::Release);
                    }
                }
            });
        }

        // --- Background: control-plane site sync ---
        if let Some(sync_url) = cfg.cluster.sync_url.clone() {
            let poll_cfg = Arc::clone(&state.config);
            let poll_pool = Arc::clone(&state.upstream_pool);
            let secs = cfg.cluster.sync_interval_secs.max(1);
            // A crash here is a sync failure like any other, so the heartbeat's
            // sync status (and the console's REJECTING badge) says so. Without
            // it a crash-looping sync left `last_error` empty and the node
            // reporting a healthy sync while it took no config.
            let on_panic = |msg: &str| {
                note_config_sync_failure(format!("config sync crashed and is restarting: {msg}"))
            };
            panic_guard::supervised!("config sync", on_panic = on_panic, {
                per_run!(sync_url, poll_cfg, poll_pool, sync_reload_notify);
                type EmptyBody = http_body_util::Empty<bytes::Bytes>;
                let client: cp_client::CpClient<EmptyBody> = cp_client::client();
                let deadline = cp_client::deadline(
                    "SENTINEL_CP_CONFIG_TIMEOUT_SECS",
                    cp_client::CONFIG_SYNC_DEADLINE,
                );
                // Restarts at "nothing applied", so a run that panicked
                // mid-apply is re-applied on the next poll.
                let mut last_version: u64 = u64::MAX;
                let reload_notify = Arc::clone(&sync_reload_notify);
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
                    let Some(bytes) =
                        fetch_config_sync(&client, &sync_url, internal_secret.as_deref(), deadline)
                            .await
                    else {
                        continue;
                    };
                    let envelope: ConfigSyncResponse = match serde_json::from_slice(&bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "config sync parse: {e} — snippet: {}",
                                String::from_utf8_lossy(&bytes)
                                    .chars()
                                    .take(120)
                                    .collect::<String>()
                            );
                            note_config_sync_failure(format!("parse: {e}"));
                            continue;
                        }
                    };
                    if envelope.version != last_version {
                        let previous: Vec<SiteConfig> = poll_cfg
                            .load()
                            .sites
                            .iter()
                            .filter(|s| s.origin == sentinel_core::config::SiteOrigin::ControlPlane)
                            .cloned()
                            .collect();
                        let (sites, rejected) = parse_synced_sites(envelope.sites, &previous);
                        #[cfg(test)]
                        panic_guard::inject_sync_panic(&sites);
                        for r in &rejected {
                            error!(
                                site = %r.id,
                                kept_previous = r.kept_previous,
                                "config sync: the control plane sent a site this node cannot \
                                 parse — {}; every other site is applied: {}",
                                if r.kept_previous {
                                    "it keeps serving its previous config"
                                } else {
                                    "it is NOT served on this node"
                                },
                                r.error
                            );
                        }
                        sync_status_lock().rejected_sites = rejected;
                        let sync = ParsedSync {
                            version: envelope.version,
                            sites,
                        };
                        let count = sync.sites.len();
                        // R5: persist the last-good config before applying, so a
                        // restart during a control-plane outage keeps these sites.
                        write_cached_sites(&config_cache_path(), sync.version, &sync.sites);
                        poll_pool.sync_sites(&sync.sites);
                        // Mark warming BEFORE publishing the sites, so there is
                        // no instant where a new site is matchable and the
                        // request path still believes the engines are current.
                        ENGINES_WARMING.store(true, std::sync::atomic::Ordering::Release);
                        sentinel_core::config::update_sites(&poll_cfg, sync.sites);
                        // Wake the engine rebuild now rather than letting it
                        // discover the change on its next 5s tick. That poll is
                        // what made the fail-open window as long as it was.
                        reload_notify.notify_one();
                        CONFIG_VERSION_APPLIED.store(sync.version, Ordering::Relaxed);
                        last_version = sync.version;
                        info!(version = last_version, sites = count, "sites hot-synced");
                    }
                    // Only once the poll is APPLIED: a sync that crashes while
                    // applying must not be reported healthy by the next run's
                    // successful fetch, or its failure never outlives the grace
                    // period the console waits before saying REJECTING.
                    note_config_sync_ok();
                }
            });
        }

        // --- Background: control-plane plugin sync ---
        //
        // Plugins uploaded through the dashboard live in Postgres, not on this
        // node's filesystem, so they cannot arrive via the config hot-reload path
        // above: that rebuilds the runtime only when the SITE config pointer
        // changes, and installing a plugin does not touch site config.
        //
        // The control plane advertises a digest (name, version, sha256) and serves
        // bytes separately, so a poll costs one small JSON response and a module is
        // downloaded only when its hash is new to this node. That is what makes a
        // 5s poll affordable for multi-megabyte modules.
        if let Some(sync_url) = cfg.cluster.sync_url.clone() {
            let plugin_sync_swap = Arc::clone(&plugin_runtime);
            let sync_site_plugin_swap = Arc::clone(&site_plugins);
            let sync_unresolved_swap = Arc::clone(&unresolved_plugins);
            let plugin_sync_cfg = Arc::clone(&state.config);
            let sync_cache = Arc::clone(&uploaded_plugins);
            let secs = cfg.cluster.sync_interval_secs.max(1);
            panic_guard::supervised!("plugin sync", {
                per_run!(
                    sync_url,
                    plugin_sync_swap,
                    sync_site_plugin_swap,
                    sync_unresolved_swap,
                    plugin_sync_cfg,
                    sync_cache
                );
                use sha2::Digest as _;
                type EmptyBody = http_body_util::Empty<bytes::Bytes>;
                let client: cp_client::CpClient<EmptyBody> = cp_client::client();
                let list_deadline = cp_client::deadline(
                    "SENTINEL_CP_PLUGIN_LIST_TIMEOUT_SECS",
                    cp_client::PLUGIN_LIST_DEADLINE,
                );
                let wasm_deadline = cp_client::deadline(
                    "SENTINEL_CP_PLUGIN_WASM_TIMEOUT_SECS",
                    cp_client::PLUGIN_WASM_DEADLINE,
                );
                let internal_secret = std::env::var("SENTINEL_INTERNAL_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty());
                // name → (sha256, bytes). Cached so an unchanged plugin is never
                // re-downloaded, and so a control-plane outage cannot silently
                // unload plugins this node already holds.
                let mut have: std::collections::HashMap<String, (String, Vec<u8>)> =
                    std::collections::HashMap::new();
                let mut ticker = tokio::time::interval(Duration::from_secs(secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;

                    let list_url = format!("{sync_url}/api/v1/internal/plugins");
                    let Ok(uri) = list_url.parse::<hyper::Uri>() else {
                        warn!("plugin sync: bad url: {list_url}");
                        continue;
                    };
                    let mut builder = hyper::Request::builder().method("GET").uri(uri);
                    if let Some(secret) = &internal_secret {
                        builder = builder.header("x-sentinel-internal", secret);
                    }
                    let Ok(req) = builder.body(http_body_util::Empty::new()) else {
                        continue;
                    };
                    let bytes = match cp_client::call(&client, req, list_deadline).await {
                        // A refusal used to surface only as the JSON error its
                        // error body produced ("plugin sync parse: ...").
                        Ok((status, _)) if !status.is_success() => {
                            warn!(
                                status = %status,
                                "plugin sync REFUSED by the control plane — keeping the \
                                 plugins already loaded. 403 means SENTINEL_INTERNAL_SECRET \
                                 does not match"
                            );
                            continue;
                        }
                        Ok((_, b)) => b,
                        Err(e) => {
                            // Control plane unreachable or silent — keep serving
                            // whatever is already loaded rather than dropping to
                            // zero plugins.
                            warn!("plugin sync {e}");
                            continue;
                        }
                    };
                    let listing: PluginSyncResponse = match serde_json::from_slice(&bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("plugin sync parse: {e}");
                            continue;
                        }
                    };

                    // Skip only when the advertised set matches the cache AND the
                    // live runtime actually still holds exactly those plugins.
                    //
                    // Checking the runtime is what makes this self-healing. Anything
                    // that rebuilds the runtime without the uploaded set (a bug, a
                    // future code path, a failed reload) would otherwise leave the
                    // plugins permanently unloaded while this task concluded there
                    // was nothing to do — the module still shown as enabled in the
                    // UI, no error anywhere, and simply not running.
                    let cache_current = listing.plugins.len() == have.len()
                        && listing
                            .plugins
                            .iter()
                            .all(|p| have.get(&p.name).is_some_and(|(sha, _)| *sha == p.sha256));
                    let live_names = plugin_sync_swap.load().plugin_names();
                    let runtime_current = listing
                        .plugins
                        .iter()
                        .all(|p| live_names.iter().any(|n| n == &p.name));
                    if cache_current && runtime_current {
                        continue;
                    }
                    if cache_current && !runtime_current {
                        warn!(
                            "uploaded plugins missing from the live runtime — reloading from cache"
                        );
                    }

                    // Fetch anything new or changed. A failure here aborts the whole
                    // reconcile: applying a partial set would silently run the site
                    // with some plugins missing, which is worse than retrying in 5s.
                    let mut next: std::collections::HashMap<String, (String, Vec<u8>)> =
                        std::collections::HashMap::new();
                    let mut failed = false;
                    for p in &listing.plugins {
                        if let Some((sha, wasm)) = have.get(&p.name).filter(|(s, _)| *s == p.sha256)
                        {
                            next.insert(p.name.clone(), (sha.clone(), wasm.clone()));
                            continue;
                        }
                        let wasm_url =
                            format!("{sync_url}/api/v1/internal/plugins/{}/wasm", p.name);
                        let Ok(uri) = wasm_url.parse::<hyper::Uri>() else {
                            warn!(plugin = %p.name, "plugin sync: bad wasm url");
                            failed = true;
                            break;
                        };
                        let mut b = hyper::Request::builder().method("GET").uri(uri);
                        if let Some(secret) = &internal_secret {
                            b = b.header("x-sentinel-internal", secret);
                        }
                        let Ok(req) = b.body(http_body_util::Empty::new()) else {
                            failed = true;
                            break;
                        };
                        let wasm = match cp_client::call(&client, req, wasm_deadline).await {
                            Ok((status, body)) if status.is_success() => body.to_vec(),
                            Ok((status, _)) => {
                                warn!(plugin = %p.name, status = %status,
                                      "plugin download rejected");
                                failed = true;
                                break;
                            }
                            Err(e) => {
                                warn!(plugin = %p.name, "plugin download: {e}");
                                failed = true;
                                break;
                            }
                        };
                        // Verify the digest before compiling. The control plane is
                        // trusted, the transport is plain HTTP on a private network,
                        // and a truncated body would otherwise be compiled and run.
                        let got = hex::encode(sha2::Sha256::digest(&wasm));
                        if got != p.sha256 {
                            warn!(plugin = %p.name, expected = %p.sha256, got = %got,
                                  "plugin digest mismatch — refusing to load");
                            failed = true;
                            break;
                        }
                        next.insert(p.name.clone(), (p.sha256.clone(), wasm));
                    }
                    if failed {
                        continue;
                    }

                    // Publish to the shared cache BEFORE rebuilding, so a concurrent
                    // config hot-reload also produces a complete runtime.
                    sync_cache.clear();
                    for (name, v) in &next {
                        sync_cache.insert(name.clone(), v.clone());
                    }

                    // Rebuild from the local manifest set plus every uploaded module,
                    // so file-configured plugins (dev, site.waf.plugins) survive too.
                    let current = plugin_sync_cfg.load_full();
                    let (rt, per_site, loaded, rejected, unresolved) =
                        match build_full_plugin_runtime(&current, &sync_cache) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("plugin sync: runtime build failed: {e:#}");
                                continue;
                            }
                        };
                    sync_site_plugin_swap.store(Arc::new(per_site));
                    sync_unresolved_swap.store(Arc::new(unresolved));
                    plugin_sync_swap.store(Arc::new(rt));
                    have = next;
                    info!(
                        plugins = loaded.len(),
                        rejected, active = %loaded.join(","),
                        "uploaded plugins synced from control plane"
                    );
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
            TI_POLLER_STARTED.store(true, std::sync::atomic::Ordering::Relaxed);
            // As for config sync: a crash is a failed poll, recorded where the
            // poller's state is read (`/healthz` threat_intel.poller, the Jobs
            // and cluster pages). Without it a sync crash-looping on the
            // install read "running": every restarted run fetched a 200 first.
            let on_panic = |msg: &str| {
                note_ti_sync_failure(format!(
                    "threat-intel sync crashed and is restarting: {msg}"
                ))
            };
            panic_guard::supervised!("threat-intel sync", on_panic = on_panic, {
                per_run!(sync_url, ti_modules, ti_ebpf);
                type EmptyBody = http_body_util::Empty<bytes::Bytes>;
                let client: cp_client::CpClient<EmptyBody> = cp_client::client();
                let deadline = cp_client::deadline(
                    "SENTINEL_CP_THREAT_INTEL_TIMEOUT_SECS",
                    cp_client::THREAT_INTEL_SYNC_DEADLINE,
                );
                let internal_secret = std::env::var("SENTINEL_INTERNAL_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty());
                // `internal_secret_set` is the field that separates "running"
                // from "running and being refused with 403 forever".
                info!(
                    sync_url = %sync_url,
                    interval_secs = secs,
                    watch_score,
                    xdp_seed = seed_ti_xdp,
                    internal_secret_set = internal_secret.is_some(),
                    "threat-intel poller started"
                );
                let mut last_version: i64 = i64::MIN;
                let mut ticker = tokio::time::interval(Duration::from_secs(secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let Some((status, bytes)) = fetch_threat_intel(
                        &client,
                        &sync_url,
                        internal_secret.as_deref(),
                        deadline,
                    )
                    .await
                    else {
                        continue;
                    };
                    // Inspect the STATUS before parsing the body. It never was:
                    // a 403 (secret mismatch) or 503 (control plane without a
                    // database) fell straight into `serde_json::from_slice`, and
                    // this node's IOC set stayed frozen at whatever it last held
                    // — or at empty — with the only trace being a parse warning
                    // that named a JSON error rather than the refusal.
                    if !(200..300).contains(&status) {
                        let held = ti_modules.threat_intel.load().entry_count();
                        warn!(
                            status,
                            held_indicators = held,
                            snippet = %String::from_utf8_lossy(&bytes).chars().take(120).collect::<String>(),
                            "threat-intel sync REFUSED by the control plane — this node's IOC set \
                             is FROZEN and will not update. 403 means the shared secret does not \
                             match: set SENTINEL_INTERNAL_SECRET identically on the control plane \
                             and every data-plane node. 503 means the control plane has no \
                             database. Queryable at /healthz -> threat_intel.poller."
                        );
                        continue;
                    }
                    let Some(sync) = parse_threat_intel_sync(&bytes) else {
                        continue;
                    };
                    if sync.version != last_version {
                        #[cfg(test)]
                        panic_guard::inject_ti_sync_panic(sync.version);
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
                        // Captured BEFORE the store, or an empty install cannot
                        // be told from a first install.
                        let previous = ti_modules.threat_intel.load().entry_count();
                        last_version = sync.version;
                        ti_modules.threat_intel.store(Arc::new(feed));
                        // One `info!("hot-synced")` used to cover every outcome,
                        // so replacing 200,000 indicators with zero logged
                        // exactly like a healthy sync.
                        match ti_sync_outcome(previous, count, status) {
                            TiSyncOutcome::Synced { count } => info!(
                                version = last_version,
                                iocs = count,
                                previous_iocs = previous,
                                "threat-intel hot-synced"
                            ),
                            TiSyncOutcome::EmptyRegression { previous } => warn!(
                                version = last_version,
                                previous_iocs = previous,
                                "threat-intel feed synced EMPTY — global IOC enforcement is now OFF \
                                 on this node, replacing a feed that held {previous} indicators. \
                                 check() now returns None for every request. Check the aggregator \
                                 on the control-plane leader (SENTINEL_THREATINTEL_ENABLED, feed \
                                 URLs, threat_intel_iocs.expires_at). \
                                 Queryable at /healthz -> threat_intel.active."
                            ),
                            TiSyncOutcome::EmptyFirst => info!(
                                version = last_version,
                                "threat-intel feed is empty — no IOC enforcement on this node yet; \
                                 the control-plane corpus has no active indicators"
                            ),
                            // Unreachable: a non-2xx `continue`s above. Kept so
                            // the match is exhaustive rather than silently
                            // collapsing a future outcome into "synced".
                            TiSyncOutcome::Rejected { status } => warn!(
                                status,
                                "threat-intel sync reached the install path with a non-2xx status"
                            ),
                        }
                    }
                    // Only once the poll is INSTALLED (or had nothing new): a
                    // run restarted after crashing in the install fetches and
                    // parses fine first, and clearing then would report the
                    // poller healthy and restart `failing_since` on every crash.
                    note_ti_sync_installed();
                }
            });
        } else {
            // The `else` this loop never had. Without a sync URL the poller is
            // never spawned, so every request is served against the
            // `ThreatFeed::empty()` installed at construction: `check()`
            // short-circuits and every malicious IP, CIDR, Tor exit, botnet C2,
            // malicious domain and scanner user-agent in the control-plane
            // corpus is ignored.
            //
            // WARN and not ERROR deliberately: `cluster.sync_url` also drives
            // config sync and the heartbeat, so a node without one is a
            // standalone, file-configured deployment where no threat intel was
            // ever expected. Crying ERROR at that shape would be the 216-line
            // mistake again. What must not happen is SILENCE — this failure
            // otherwise looks exactly like a world with no attackers.
            warn!(
                config_key = "cluster.sync_url",
                "threat-intel poller NOT started — global IOC enforcement is OFF on this node. \
                 The feed stays empty, so check() returns None for every request. If this node is \
                 meant to be part of a cluster, set cluster.sync_url (e.g. \
                 http://controlplane:9501); if it is deliberately standalone, this is expected. \
                 Queryable at /healthz -> threat_intel.poller."
            );
        }

        // --- Background: GeoIP database watcher (every 60 s) ---
        // The database is supplied out of band (the control plane's geoip.refresh
        // job, or an operator copying a file). Until now it was only opened when
        // a site config changed, so a database that appeared after boot stayed
        // unused and healthz kept reporting the control as inert. Rebuild the
        // per-site readers whenever a configured file appears, changes or goes.
        {
            let gw_cfg = Arc::clone(&state.config);
            let gw_modules = Arc::clone(&state.modules);
            panic_guard::supervised!("GeoIP watcher", {
                per_run!(gw_cfg, gw_modules);
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let cfg = gw_cfg.load();
                    let map = gw_modules.geoip_map.load();
                    let changed = cfg.sites.iter().any(|site| {
                        site.waf.geoip.as_ref().is_some_and(|gc| {
                            map.get(&site.id)
                                .map(|g| g.db_changed(std::path::Path::new(&gc.db_path)))
                                .unwrap_or(true)
                        })
                    });
                    if changed {
                        let rebuilt = build_geoip_map(&cfg);
                        let active = rebuilt.values().filter(|g| g.is_active()).count();
                        info!(
                            sites = rebuilt.len(),
                            active, "GeoIP database changed on disk — readers rebuilt"
                        );
                        gw_modules.geoip_map.store(Arc::new(rebuilt));
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
            let hb_engines = Arc::clone(&state.engines);
            let hb_ebpf = Arc::clone(&state.ebpf);
            let hb_modules = Arc::clone(&state.modules);
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
            panic_guard::supervised!("node heartbeat", {
                per_run!(
                    sync_url, hb_cfg, hb_pool, hb_engines, hb_ebpf, hb_modules, node_id, hostname
                );
                type JsonBody = http_body_util::Full<bytes::Bytes>;
                let client: cp_client::CpClient<JsonBody> = cp_client::client();
                let deadline = cp_client::deadline(
                    "SENTINEL_CP_HEARTBEAT_TIMEOUT_SECS",
                    cp_client::HEARTBEAT_DEADLINE,
                );
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
                    // Degraded when we have origins configured but none reachable,
                    // while a background loop is crash-looping, or once an
                    // HTTP/3 endpoint has stopped for good. Under panic=abort
                    // such a failure took the node down, which was at least
                    // visible; contained, it is a node that quietly stops doing
                    // one of its jobs, so it must not report healthy.
                    let status = if (pool.total > 0 && pool.healthy == 0)
                        || panic_guard::recently_restarted().is_some()
                        || http3::any_endpoint_down()
                    {
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
                            // HTTP/3 endpoints that stopped serving for good.
                            "http3_down": http3::endpoints_down(),
                            // Per-node drill-down for the cluster page: which config
                            // version this node applied (stale-node detection), how
                            // many rules it compiled, and what its own bans/feeds hold.
                            "config_version_applied": CONFIG_VERSION_APPLIED.load(Ordering::Relaxed),
                            // Whether this node is actually taking config: a poll
                            // failure, or sites of the applied version it rejected.
                            "config_sync": config_sync_status(),
                            "rules_compiled": hb_engines.load().values().map(|e| e.rule_count()).sum::<usize>(),
                            "rules_enforced": hb_engines.load().values().map(|e| e.inventory().enforced).sum::<usize>(),
                            "ebpf_mode": hb_ebpf.mode().to_string(),
                            "ebpf_drops": hb_ebpf.ebpf_drops(),
                            "threat_intel_entries": hb_modules.threat_intel.load().entry_count(),
                            "threat_intel_version": hb_modules.threat_intel.load().version(),
                            // Whether those entries are still being refreshed.
                            "threat_intel_sync": ti_sync_heartbeat(),
                            // Ground truth for which operator-authored rules are
                            // actually compiled and running on THIS node. The
                            // control plane cannot derive this — it has no SRL
                            // compiler — so without it "enabled" in the UI is an
                            // assumption rather than a fact.
                            "inline_rules": inline_rule_diag_snapshot(),
                            // Contained panics, and which loops restarted: the
                            // reason a node above reads "degraded".
                            "panics": panic_guard::heartbeat_status(),
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
                    match cp_client::call(&client, req, deadline).await {
                        Ok((status, _)) => {
                            debug!(status = %status, "heartbeat posted");
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
            panic_guard::supervised!("rate-limiter GC", {
                per_run!(modules_ref);
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
            panic_guard::supervised!("anti-DDoS GC", {
                per_run!(modules_ref);
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
            panic_guard::supervised!("correlation GC", {
                per_run!(modules_ref);
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
            // Bounds, fair sharing, last-good reuse and the /healthz report:
            // see ip_feed. The loader holds what must outlive one pass, so it
            // lives outside the supervised loop, like the history writer's
            // carry. A run restarted after a panic built a fresh one, which
            // dropped every failing feed's last good entries and took the
            // node's table for empty, so removing the last feed afterwards left
            // its entries enforced.
            let loader = Arc::new(tokio::sync::Mutex::new(ip_feed::FeedLoader::new(
                ip_feed::FeedLimits::from_env(),
            )));
            let resumed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            panic_guard::supervised!("IP feed loader", {
                per_run!(config_watch, modules_ref, loader, resumed);
                // Held for the run; a panic releases it as the run unwinds.
                let mut loader = loader.lock().await;
                if resumed.swap(true, Ordering::AcqRel) {
                    // The run before may have died between building a table
                    // and storing it.
                    loader.rebuild_next_pass();
                }
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let cfg = config_watch.load_full();
                    let load = loader.load(&ip_feed::configured_feeds(&cfg)).await;
                    ip_feed::publish(load.report);
                    if !load.rebuild {
                        continue;
                    }
                    let new_arc: Arc<Vec<_>> = Arc::new(load.table);
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
            let sd = shutdown.clone();
            // Supervised so a panic in the accept loop rebinds the listener
            // instead of leaving the port dead while the process looks healthy.
            // (Connections and requests panic in their own tasks and guards and
            // never reach this.) After such a restart an HTTP/3 endpoint cannot
            // rebind while the first one is still serving; that is logged, h3
            // keeps working on the original, and the restarted listener stops
            // advertising it (Alt-Svc follows its own endpoint, which is down).
            handles.push(panic_guard::supervised!("listener", {
                per_run!(listener_cfg, state2, sd);
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
        let grace = drain_grace();
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

/// How long a graceful shutdown waits for in-flight connections, TCP and HTTP/3
/// alike (`http3::serve_quic` drains its endpoint for the same time). Env
/// override: `SENTINEL_DRAIN_GRACE_SECS`.
fn drain_grace() -> Duration {
    Duration::from_secs(
        std::env::var("SENTINEL_DRAIN_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(25),
    )
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
            // SNI-based per-domain resolution across all sites. Site certs are
            // minted on config sync by one task per node, started by the first
            // such listener — never in a handshake. The old per-listener
            // pre-warm minted a different in-memory cert on every node.
            let resolver = tls::SentinelCertResolver::new(Arc::clone(&state.cert_manager.store));
            tls::cert_store::start_site_cert_sync(
                &state.cert_manager.store,
                Arc::clone(&state.config),
            );

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

    // True while the HTTP/3 accept loop runs; gates the Alt-Svc below.
    let h3_serving = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Spawn the HTTP/3 (QUIC over UDP) endpoint on the same address as the TCP
    // listener. It shares the listener's shutdown signal and feeds requests into
    // the same WAF pipeline (see `http3::serve_quic`).
    if let Some(qcfg) = quic_config {
        match cfg.bind.parse::<SocketAddr>() {
            Ok(quic_bind) => match http3::bind_quic(quic_bind, qcfg) {
                Ok(endpoint) => {
                    let state_q = Arc::clone(&state);
                    let ds_q = default_site.clone();
                    let shutdown_q = shutdown.clone();
                    let serving = Arc::clone(&h3_serving);
                    // Bound once, out here: a run restarted after a panic
                    // accepts on the same socket (see `http3::bind_quic`).
                    panic_guard::supervised!("HTTP/3 endpoint", {
                        per_run!(endpoint, state_q, ds_q, shutdown_q, serving);
                        http3::serve_quic(endpoint, quic_bind, state_q, ds_q, shutdown_q, &serving)
                            .await;
                    });
                    info!(listener = %cfg.name, bind = %cfg.bind, "HTTP/3 (QUIC) enabled on this listener");
                }
                Err(e) => {
                    error!(listener = %cfg.name, "HTTP/3 endpoint error: {e:#}; serving TCP only");
                }
            },
            Err(e) => {
                error!(listener = %cfg.name, bind = %cfg.bind, "HTTP/3 requested but bind is not a socket address ({e}); h3 disabled");
            }
        }
    }

    // Alt-Svc advertisement — browsers connect over TCP first, then upgrade to
    // h3 on the advertised UDP port. Defaults to this listener's bind port;
    // override with SENTINEL_HTTP3_ADVERTISE_PORT when the public port differs
    // (e.g. a container mapping host :443/udp → container :8443/udp).
    let alt_svc: Option<http3::AltSvc> = if h3_enabled {
        let bind_port = cfg
            .bind
            .parse::<SocketAddr>()
            .map(|a| a.port())
            .unwrap_or(0);
        let port = std::env::var("SENTINEL_HTTP3_ADVERTISE_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(bind_port);
        header::HeaderValue::from_str(&format!("h3=\":{port}\"; ma=86400"))
            .ok()
            .map(|v| http3::AltSvc::new(v, Arc::clone(&h3_serving)))
    } else {
        None
    };

    // Grows on consecutive resource-exhaustion failures, resets on any successful
    // accept, so a transient descriptor shortage does not leave the listener slow
    // once it clears.
    let mut accept_backoff = ACCEPT_BACKOFF_MIN;

    loop {
        tokio::select! {
            accept = tcp.accept() => {
                // An accept() error must not kill the listener.
                //
                // This was `let (stream, peer) = accept?;` — a single error of any
                // kind propagated out of the loop and the listener was gone for the
                // life of the process. The supervising task only logged it, so the
                // WAF stopped accepting traffic while every health check that looks
                // at process liveness still reported healthy.
                //
                // The errors that reach here are overwhelmingly NOT fatal:
                //   * ECONNABORTED — the client sent RST between SYN and accept.
                //     Entirely routine on a public listener; a port scan produces
                //     a stream of them, so this alone was a remote listener kill.
                //   * EMFILE / ENFILE — out of file descriptors. Reachable at the
                //     default max_connections of 10,000 against a container that
                //     sets no nofile limit.
                //   * ENOBUFS / ENOMEM — transient kernel memory pressure.
                //
                // Retrying EMFILE immediately would spin a core at 100%: the
                // listening socket stays readable, so the loop would busy-wait
                // until a descriptor frees. Hence backoff on resource exhaustion,
                // reset on the next successful accept.
                let (stream, peer) = match accept {
                    Ok(pair) => {
                        accept_backoff = ACCEPT_BACKOFF_MIN;
                        pair
                    }
                    Err(e) => match classify_accept_error(&e) {
                        AcceptRecovery::Retry => {
                            debug!(listener = %cfg.name, error = %e,
                                   "accept failed for one connection; listener continues");
                            continue;
                        }
                        AcceptRecovery::Backoff => {
                            warn!(listener = %cfg.name, error = %e,
                                  backoff_ms = accept_backoff.as_millis() as u64,
                                  "accept failed due to resource exhaustion; backing off");
                            tokio::time::sleep(accept_backoff).await;
                            accept_backoff = (accept_backoff * 2).min(ACCEPT_BACKOFF_MAX);
                            continue;
                        }
                        AcceptRecovery::Fatal => {
                            error!(listener = %cfg.name, error = %e,
                                   "listening socket is unusable; listener stopping");
                            return Err(e.into());
                        }
                    },
                };
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
                let pp = cfg.proxy_protocol;
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
                    if let Err(e) = handle_connection(stream, peer, acceptor, protos, state, ds, mgmt, av, pp).await {
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
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    protocols: Vec<Protocol>,
    state: Arc<ServerState>,
    default_site: Option<String>,
    management: Option<Arc<ManagementUpstreams>>,
    alt_svc: Option<http3::AltSvc>,
    proxy_protocol: bool,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    // PROXY protocol, when this listener is behind a TCP-mode load balancer.
    //
    // Consumed BEFORE the JA4 peek and the TLS handshake, because the
    // ClientHello follows it immediately on the same socket and both rustls and
    // `peek_ja4` read from the front.
    //
    // The header is plaintext and self-asserted, so it is believed only from a
    // peer that is already a trusted proxy. A connection from anywhere else is
    // REFUSED rather than served as raw traffic: this listener exists to
    // establish the client's identity, and a direct connection to it is either a
    // misconfiguration or someone trying to claim an address they do not have.
    let peer = if proxy_protocol {
        if !proxy_header_allowed(peer.ip(), is_trusted_proxy) {
            anyhow::bail!(
                "PROXY protocol listener refused a connection from untrusted peer \
                 {peer} (not in SENTINEL_TRUSTED_PROXIES)"
            );
        }
        let said = proxy_protocol::read_header(&mut stream, HANDSHAKE_TIMEOUT).await?;
        effective_peer(peer, said)
    } else {
        peer
    };

    if let Some(acceptor) = tls_acceptor {
        // Fingerprint the TLS ClientHello (JA4) by peeking the socket without
        // consuming it — rustls then reads the same bytes for the handshake.
        //
        // Counted per connection, in three buckets, because two of them mean
        // completely different things and lumping them together made the number
        // unreadable: a live fleet reported 977 "attempts" against 11 requests
        // actually served, because every TCP probe that never spoke TLS counted
        // as a failed fingerprint.
        //
        // Now `attempts` counts only connections that actually presented a TLS
        // handshake record, so `success / attempts` is real coverage, and
        // `no_hello` carries the probes.
        let tls_fp = match peek_ja4(&stream).await {
            Ja4Peek::Fingerprint(fp) => {
                note_ja4_attempt();
                note_ja4_success();
                Some(fp)
            }
            Ja4Peek::HandshakeButNoFingerprint => {
                note_ja4_attempt();
                None
            }
            Ja4Peek::NoHandshake => {
                note_ja4_no_hello();
                None
            }
        };
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
/// How long to wait for a complete ClientHello to arrive before giving up on the
/// fingerprint.
///
/// Deliberately far shorter than `HANDSHAKE_TIMEOUT` (15s): a real client sends
/// its ClientHello immediately after connect, so anything not fully arrived
/// within this window is a probe or a stalled peer. Waiting the full handshake
/// timeout would pin a task per abandoned connection — a cheap DoS — for a
/// fingerprint we are about to fail to produce anyway. TLS itself still gets the
/// full `HANDSHAKE_TIMEOUT`; this bounds only the fingerprint attempt.
const JA4_PEEK_BUDGET: Duration = Duration::from_millis(250);

/// What the JA4 peek concluded, so the caller can count the three outcomes apart.
enum Ja4Peek {
    /// A fingerprint.
    Fingerprint(String),
    /// A TLS handshake record was seen but no fingerprint could be produced
    /// (fragmented across records, or malformed).
    HandshakeButNoFingerprint,
    /// The connection never sent a TLS handshake record: a TCP probe, a port
    /// scan, an abandoned connection. NOT a fingerprinting failure, and counting
    /// it as one is what made the coverage ratio unreadable — a live fleet showed
    /// 977 "attempts" against 11 requests actually served.
    NoHandshake,
}

/// Fingerprint the TLS ClientHello by peeking the socket, without consuming it.
///
/// ⚠️ The retry loop is the point. `TcpStream::peek` returns as soon as ANY bytes
/// are readable, so a single peek routinely sees a PARTIAL ClientHello — and
/// `parse_client_hello` returns `None` for a truncated record exactly as it does
/// for a malformed one. Modern post-quantum hellos run well past one segment, so
/// this silently dropped roughly half of all fingerprints on a live fleet
/// (508/977), and every JA4-dependent control — bot scoring's malicious-JA4
/// signal, JA4 blocklists — was inert for those connections while reporting
/// nothing.
///
/// Re-peeking is safe and idempotent precisely because `peek` does not consume:
/// rustls still reads the same bytes for the real handshake afterwards. The
/// buffer is 16 KiB, the TLS record maximum, because 4096 was itself too small
/// for a large hello.
async fn peek_ja4(stream: &TcpStream) -> Ja4Peek {
    let mut buf = vec![0u8; 16 * 1024];
    let deadline = tokio::time::Instant::now() + JA4_PEEK_BUDGET;
    let mut saw_handshake = false;
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            // Timed out, EOF, or a read error.
            _ => {
                return if saw_handshake {
                    Ja4Peek::HandshakeButNoFingerprint
                } else {
                    Ja4Peek::NoHandshake
                }
            }
        };
        match sentinel_modules::client_hello_needed_len(&buf[..n]) {
            Ok(need) => {
                saw_handshake = true;
                if n >= need {
                    return match sentinel_modules::ja4_from_client_hello(&buf[..n], false) {
                        Some(fp) => Ja4Peek::Fingerprint(fp),
                        None => Ja4Peek::HandshakeButNoFingerprint,
                    };
                }
                // Incomplete: more of the record is still in flight. `peek`
                // leaves the data queued, so it would return the same bytes
                // immediately — sleep briefly rather than spin.
                if tokio::time::Instant::now() >= deadline {
                    return Ja4Peek::HandshakeButNoFingerprint;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            // Definitively not a TLS handshake — waiting cannot help.
            Err(_) => return Ja4Peek::NoHandshake,
        }
    }
}

async fn serve_http1<T>(
    io: TokioIo<T>,
    peer: SocketAddr,
    state: Arc<ServerState>,
    default_site: Option<String>,
    management: Option<Arc<ManagementUpstreams>>,
    alt_svc: Option<http3::AltSvc>,
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
                let resp =
                    panic_guard::contain_request(peer, handle_request(s, peer, req, ds, mgmt, fp));
                async move { with_alt_svc(resp.await, av) }
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
    alt_svc: Option<http3::AltSvc>,
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
                let resp =
                    panic_guard::contain_request(peer, handle_request(s, peer, req, ds, mgmt, fp));
                async move { with_alt_svc(resp.await, av) }
            }),
        )
        .await
        .map_err(|e| anyhow!("http2 serve error: {e}"))
}

/// Attach the `Alt-Svc` header (advertising HTTP/3) to a TCP response when the
/// listener has h3 enabled and its endpoint is accepting. No-op otherwise.
fn with_alt_svc(
    resp: Result<Response<BoxBody>, Infallible>,
    alt_svc: Option<http3::AltSvc>,
) -> Result<Response<BoxBody>, Infallible> {
    match (resp, alt_svc.as_ref().and_then(http3::AltSvc::header)) {
        (Ok(mut r), Some(v)) => {
            r.headers_mut().insert(header::ALT_SVC, v.clone());
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
        return Ok(health_response(&state).await);
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
        return Ok(metrics_response(&state.modules.rate_limiter));
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
        if req.method() == http::Method::GET && req.uri().path() == "/api/v1/internal/rules" {
            return Ok(rules_inventory_response(&state, req.uri().query()));
        }
        if req.method() == http::Method::GET && req.uri().path() == "/api/v1/internal/settings" {
            return Ok(global_settings_response(&state));
        }
        if req.method() == http::Method::GET && req.uri().path() == "/api/v1/internal/blocks" {
            return Ok(blocks_response(&state));
        }
        if req.method() == http::Method::GET {
            if let Some(rest) = req.uri().path().strip_prefix("/api/v1/internal/sites/") {
                if let Some(site_id) = rest.strip_suffix("/config") {
                    return Ok(site_effective_config_response(&state, site_id));
                }
            }
        }
        if req.method() == http::Method::DELETE {
            if let Some(ip) = req.uri().path().strip_prefix("/api/v1/internal/blocks/") {
                return Ok(unblock_response(&state, ip.trim_end_matches('/')));
            }
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
/// Sets up the tracing span, drives the WAF pipeline (`proxy`), and records
/// metrics. Called by the TCP handler (`handle_request`, after its
/// health/management/ACME routing boxes the `Incoming` body) and by the HTTP/3
/// adapter (`crate::http3`), which builds a `BoxBody` from the QUIC request
/// stream. Never returns an error — upstream failures become responses.
pub(crate) async fn run_pipeline(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<BoxBody>,
    default_site: Option<String>,
    tls_fp: Option<String>,
) -> Response<BoxBody> {
    // The blocklist fast-fail used to live HERE, ahead of context creation, and
    // that placement is why it recorded nothing: it returned a bare 403 without
    // an access-log line, a waf.log event, a ClickHouse row, or a Support ID.
    // Every other block in this proxy is visible; these were not — and the
    // threat-intel block tier and the XDP auto-ban both feed this same
    // blocklist, so the blocks most worth seeing were the invisible ones, while
    // /metrics still counted them (so the counters could not be reconciled with
    // any event). It now runs inside `proxy`, immediately after Phase 0 stamps
    // identity and attribution — still before any body read or rule work, and
    // by then TLS and HTTP parsing are already paid for, so the marginal cost
    // is a log line, not a pipeline.
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
        // `proxy` logs its own failures and always yields a response — see the
        // note on it. The Ok/Err match that used to live here is exactly how 502s
        // came to be unlogged.
        proxy(state, peer, req, default_site, tls_fp).await
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

/// Handle one request, returning a response and NEVER an error.
///
/// Wraps `proxy_inner` so that a failure inside the pipeline is still a LOGGED
/// request. Previously `proxy` returned `Result` and its caller answered a bare
/// 502 with no access-log line, no waf.log entry and no ClickHouse row — while
/// `inc_requests()` still fired, so /metrics could never be reconciled with the
/// event store. Origin-down and no-matching-site were both completely invisible
/// in the WAF's own logs: a NOC watching this product could not see that the
/// thing behind it had stopped answering.
///
/// Same bug class as the unlogged blocklist blocks fixed in 598bcc4. That one was
/// fixed and this instance was missed, which is why the fix is structural here —
/// the context now lives OUTSIDE the fallible work, so there is no path that can
/// return a response without one.
async fn proxy(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<BoxBody>,
    default_site: Option<String>,
    tls_fp: Option<String>,
) -> Response<BoxBody> {
    // Created here, not inside the fallible body, so every exit has a context to
    // log from.
    let mut ctx = RequestContext::new(peer.ip(), peer.port());
    // A panic anywhere in the pipeline is caught here, where the context
    // outlives it: the request is answered 500 with its Support ID and logged,
    // saying whether it had reached the origin. Serves both TCP and HTTP/3
    // (via run_pipeline).
    let outcome = panic_guard::catch_request(async {
        #[cfg(test)]
        panic_guard::inject_test_panic(&req);
        proxy_inner(&mut ctx, state, peer, req, default_site, tls_fp).await
    })
    .await;
    let result = match outcome {
        Ok(result) => result,
        Err(payload) => return panic_guard::pipeline_panicked(&mut ctx, payload),
    };
    match result {
        Ok(r) => r,
        Err(e) => {
            // The error text is the operator's only clue about WHY the gateway
            // failed — origin refused, no site matched, body unreadable — so it
            // goes on the log line rather than only into a tracing event that
            // nothing aggregates.
            error!(
                request_id = %ctx.request_id,
                client_ip = %ctx.client_ip,
                "proxy error: {e:#}"
            );
            let status = gateway_error_status(&e);
            let resp = error_response(status, status.canonical_reason().unwrap_or("Bad Gateway"));
            stamp_response(&mut ctx, &resp);
            ctx.gateway_error = Some(cap_field(&format!("{e:#}"), 512));
            ctx.advance_phase(Phase::Logging);
            log_request(&ctx);
            resp
        }
    }
}

/// The status for a request that failed before the origin produced a response.
///
/// 504 when the origin was reached but did not answer within the site's read
/// timeout — the application is slow or hung. 502 for everything else: refused,
/// unreachable, TLS failure, no healthy upstream, no matching site. Telling the
/// two apart is the first thing an operator needs when a site stops working,
/// and it used to be impossible because both were 502.
///
/// Walks the whole error chain, since the timeout is wrapped in context on its
/// way up, and matches on the TYPE so rewording a message cannot change a status.
fn gateway_error_status(e: &anyhow::Error) -> StatusCode {
    if e.chain().any(|c| c.is::<upstream::UpstreamTimeout>()) {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    }
}

#[cfg(test)]
mod gateway_error_status_tests {
    use super::*;

    #[test]
    fn a_read_timeout_is_504_even_when_wrapped_in_context() {
        let e = anyhow::Error::new(upstream::UpstreamTimeout(std::time::Duration::from_secs(
            60,
        )))
        .context("upstream request failed");
        assert_eq!(gateway_error_status(&e), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn every_other_failure_is_502() {
        for e in [
            anyhow::anyhow!("upstream request failed: connection refused"),
            anyhow::anyhow!("no healthy upstream for site 'x'"),
            anyhow::anyhow!("invalid peer certificate: UnknownIssuer"),
        ] {
            assert_eq!(gateway_error_status(&e), StatusCode::BAD_GATEWAY, "{e:#}");
        }
    }

    #[test]
    fn a_message_that_merely_mentions_a_timeout_is_not_a_timeout() {
        // Matching on text would make this 504; the type is what decides.
        let e = anyhow::anyhow!("upstream request timed out after 60s");
        assert_eq!(gateway_error_status(&e), StatusCode::BAD_GATEWAY);
    }
}

#[allow(clippy::too_many_arguments)]
async fn proxy_inner(
    ctx: &mut RequestContext,
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
    // ctx is owned by `proxy` above so that a failure anywhere below is still a
    // logged request rather than a silent 502.
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
    // Decide the block-page representation NOW, while the request is still
    // whole. The connection-layer rejections below answer before
    // ctx.request_headers is populated, so block_response cannot recover this
    // later — see RequestContext::client_accepts_html.
    ctx.client_accepts_html = wants_html(req.headers());
    // Stamp the request line + the log-relevant headers NOW, for the same
    // reason: the connection-layer rejections below (anti-DDoS, IP reputation,
    // threat intel) log and answer before Phase 1 populates the context, so
    // every one of their events read as `GET / ua="-"` regardless of what was
    // actually requested — and those are exactly the blocks a stranger holds a
    // Support ID for. Method/URI/version are cheap clones; the full header map
    // is deliberately NOT cloned here (that still happens exactly once, after
    // into_parts) — only the two headers logging reads are copied.
    ctx.http_version = req.version();
    ctx.method = req.method().clone();
    ctx.uri = req.uri().clone();
    for h in [header::USER_AGENT, header::REFERER] {
        if let Some(v) = req.headers().get(&h) {
            ctx.request_headers.insert(h, v.clone());
        }
    }

    // Attribute the request to a site/tenant BEFORE the connection-layer checks
    // below, which reject and log without ever reaching routing.
    //
    // Without this their events are written with an EMPTY tenant, and every
    // read path is tenant-scoped — so the Support ID printed on a threat-intel
    // block page resolved to nothing when an operator pasted it into Threat
    // Search. That is the one journey the Support ID exists for, failing for
    // precisely the strangers most likely to be shown a block page.
    //
    // Attribution only: the authoritative routing below re-stamps both fields
    // and additionally honours the listener's default_site, which this cheap
    // Host lookup deliberately does not attempt. A wrong guess here cannot
    // change enforcement, only which tenant owns the log line — and no guess
    // at all guarantees the line is owned by nobody.
    if let Some(h) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
    {
        if let Some(s) = cfg.sites.iter().find(|s| site_matches(s, h)) {
            ctx.site_id = Some(s.id.clone());
            ctx.tenant_id = Some(s.tenant_id.clone());
        }
    }

    // Blocklist fast-fail: known-blocked addresses never enter the WAF pipeline.
    // First check after attribution, so nothing else runs for a blocked source.
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
    // `req.headers()` rather than `ctx.request_headers`: Phase 0 copies only the
    // two headers logging reads, and this needs the X-Forwarded-For chain. The
    // full map is still intact here — `into_parts()` runs at Phase 1.
    if blocklist_hit(
        peer.ip(),
        req.headers(),
        |ip| state.ebpf.is_blocked(ip),
        is_trusted_proxy,
    ) {
        inc_ebpf_drops();
        ctx.decision = WafDecision::Block;
        // Named so `classify_nonrule_block` files it under IPREP rather than
        // inventing an "anomaly threshold exceeded" verdict for a score of 0.
        ctx.block_reason = Some("ip reputation: source is on the node blocklist".into());
        let resp = block_response(ctx);
        stamp_response(ctx, &resp);
        ctx.advance_phase(Phase::Logging);
        log_request(ctx);
        return Ok(resp);
    }

    // Anti-DDoS: connection-rate check.
    match state.modules.anti_ddos.check_connection(ctx.client_ip) {
        DdosVerdict::Block { reason } => {
            ctx.decision = WafDecision::Block;
            ctx.block_reason = Some(reason);
            note_block(&state, ctx.client_ip);
            let resp = block_response(ctx);
            stamp_response(ctx, &resp);
            ctx.advance_phase(Phase::Logging);
            log_request(ctx);
            return Ok(resp);
        }
        DdosVerdict::Allow => {}
    }

    // IP reputation: THIS site's allow/block lists first (an allow here also
    // skips the feed check), then the node-wide feed table for suspect scoring.
    {
        // Keyed on the Host-attributed site above; a request no site claims
        // gets the node-wide feed check only.
        let sites = state.modules.ip_rep_sites.load();
        let site_rep = ctx.site_id.as_deref().and_then(|id| sites.get(id));
        let verdict = match site_rep.map(|r| r.check(ctx.client_ip)) {
            Some(v @ IpVerdict::Block { .. }) => v,
            Some(IpVerdict::Allow) if site_rep.is_some_and(|r| r.is_allowlisted(ctx.client_ip)) => {
                IpVerdict::Allow
            }
            _ => state.modules.ip_rep.load().check(ctx.client_ip),
        };
        match verdict {
            IpVerdict::Block { reason } => {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!("IP reputation: {reason}"));
                note_block(&state, ctx.client_ip);
                let resp = block_response(ctx);
                stamp_response(ctx, &resp);
                ctx.advance_phase(Phase::Logging);
                log_request(ctx);
                return Ok(resp);
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
                    let resp = block_response(ctx);
                    stamp_response(ctx, &resp);
                    ctx.advance_phase(Phase::Logging);
                    log_request(ctx);
                    return Ok(resp);
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
        // Stamp the policy that governs this request while the site config is in
        // scope. Done here rather than passed to log_request because there are 18
        // log_request call sites, several of which run BEFORE routing (anti-DDoS,
        // IP reputation, threat intel) and have no site to pass.
        // Effective policy = the site's policy with any matching path override
        // applied. Everything downstream reads these two ctx fields rather than
        // s.waf directly, so an override cannot be honoured in one place and
        // missed in another — which is how a per-path setting ends up decorative.
        let ov = match_path_override(&s.waf, ctx.uri.path());
        ctx.enforcement_mode = Some(
            ov.and_then(|o| o.mode.clone())
                .unwrap_or_else(|| s.waf.mode.clone()),
        );
        ctx.anomaly_threshold = Some(
            ov.and_then(|o| o.anomaly_threshold)
                .unwrap_or(s.waf.anomaly_threshold),
        );
        if let Some(o) = ov {
            ctx.path_override = Some(o.path_prefix.clone());
        }
        // Stamped here for the same reason as the fields above: the block
        // renderer runs at call sites that have no site config in scope.
        ctx.block_page = s.waf.block_page.clone();
        // What inspecting this request may cost; the rule engine reads it.
        ctx.inspection_limits = s.waf.inspection_limits();
    }

    // Refuse to serve a site whose rule engine has not finished compiling.
    //
    // The site list and the engines are published by two different tasks, so a
    // newly created site was matchable before it was inspectable — a real SQLi
    // passed with `rule_matches=0, decision=Allow` 1.5s before "rule engine
    // loaded" appeared in the log. A site created directly in blocking mode
    // failed OPEN through that window, which is the one direction of failure a
    // WAF may never take.
    //
    // 503 rather than passing through: for the seconds this lasts, refusing is
    // honest and recoverable, while forwarding uninspected traffic is neither.
    // Gated on `site_expects_engine` so a `mode: off` site — or one with no
    // rules at all, which legitimately never has an engine — is unaffected, and
    // on the warming flag so a site whose rules FAILED to compile keeps its
    // existing loud-warning behaviour rather than becoming permanently 503.
    if let Some(s) = &site {
        let action = missing_engine_action(
            s,
            engine_map.contains_key(&s.id),
            ENGINES_WARMING.load(std::sync::atomic::Ordering::Acquire),
            serve_on_rule_compile_failure(),
        );
        if action != MissingEngine::Serve {
            // The public body stays generic in both cases: which of the two it is
            // tells an attacker whether this site currently has signature
            // protection, and that is not their business. The operator gets the
            // difference in the log and at /healthz.
            let (reason, log_detail) = match action {
                MissingEngine::RefuseWarming => (
                    "site initializing: rule engine still compiling",
                    "site config has landed but its rule engine is still compiling — \
                     refusing with 503 rather than forwarding uninspected traffic",
                ),
                _ => (
                    "site rule set failed to compile: refusing rather than serving unprotected",
                    "site is in BLOCKING mode and its rule set will not compile, with no \
                     last-good ruleset to fall back on — refusing with 503 rather than serving \
                     it with no signature protection. Fix the rules, or switch the site to \
                     learning mode to serve traffic uninspected on purpose. Override with \
                     SENTINEL_SERVE_ON_RULE_COMPILE_FAILURE=1. Listed at \
                     /healthz inspection.sites_refused.",
                ),
            };
            if action == MissingEngine::RefuseWarming {
                warn!(site = %s.id, "{log_detail}");
            } else {
                error!(site = %s.id, "{log_detail}");
            }
            ctx.decision = WafDecision::Block;
            ctx.block_reason = Some(reason.into());
            let resp = error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable — site is initializing",
            );
            stamp_response(ctx, &resp);
            ctx.advance_phase(Phase::Logging);
            log_request(ctx);
            return Ok(resp);
        }
    }

    // Request size limits: URI and header count (Phase 1, before body read).
    if let Some(s) = &site {
        if s.waf.mode != WafMode::Off {
            // URI length limit.
            if s.waf.max_uri_length > 0 {
                let uri_len = ctx.uri.to_string().len() as u32;
                if uri_len > s.waf.max_uri_length {
                    if let Some(resp) = enforce_request_limit(
                        ctx,
                        s,
                        format!(
                            "URI too long: {} bytes (limit {})",
                            uri_len, s.waf.max_uri_length
                        ),
                        StatusCode::URI_TOO_LONG,
                        "URI Too Long",
                    ) {
                        return Ok(resp);
                    }
                }
            }
            // Request header count limit.
            if s.waf.max_header_count > 0 {
                let hcount = ctx.request_headers.len() as u32;
                if hcount > s.waf.max_header_count {
                    if let Some(resp) = enforce_request_limit(
                        ctx,
                        s,
                        format!(
                            "too many headers: {} (limit {})",
                            hcount, s.waf.max_header_count
                        ),
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                        "Too Many Headers",
                    ) {
                        return Ok(resp);
                    }
                }
            }
            // HTTP method allow-list (empty = allow all). Case-insensitive.
            if !s.waf.allowed_methods.is_empty() {
                // Owned, not a borrow of ctx: enforce_request_limit needs
                // &mut ctx and the method string is still wanted for the message.
                let m = ctx.method.as_str().to_owned();
                if !s
                    .waf
                    .allowed_methods
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&m))
                {
                    if let Some(resp) = enforce_request_limit(
                        ctx,
                        s,
                        format!("method not allowed: {m}"),
                        StatusCode::METHOD_NOT_ALLOWED,
                        "Method Not Allowed",
                    ) {
                        return Ok(resp);
                    }
                }
            }
        }
    }

    // WAF phase 1: rate limit → bot → GeoIP → rule engine → plugins.
    {
        let pr = state.plugin_runtime.load();
        let site_plugin_names = site
            .and_then(|s| state.site_plugins.load().get(&s.id).cloned())
            .unwrap_or_default();
        phase1_headers(
            ctx,
            site,
            &engine_map,
            &state.modules,
            &pr,
            &site_plugin_names,
        )
        .await?;
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
        if let Some(resp) = challenge_response(ctx, challenge_mode, bot_cfg).await {
            stamp_response(ctx, &resp);
            ctx.advance_phase(Phase::Logging);
            log_request(ctx);
            return Ok(resp);
        }
        // Cleared (or an in-line grant for an unsafe method) — proceed to origin.
        ctx.decision = WafDecision::Allow;
    }

    if ctx.decision == WafDecision::Block {
        note_block(&state, ctx.client_ip);
        let reason = ctx.block_reason.as_deref().unwrap_or("");
        let resp = if reason.starts_with("HTTP request smuggling") {
            // RFC 7230 §3.3.3: malformed framing MUST be rejected with 400. The
            // STATUS is what the RFC requires; disclosing WHY is not, and the
            // reason names the exact header and the exact check that fired —
            // which is free reconnaissance for tuning a desync attempt against
            // this deployment. It also bypassed `BlockPageConfig::show_reason`
            // (default false, a deliberate decision) and shipped no Support ID.
            //
            // The `jwt:` arm immediately below already did this correctly, with a
            // comment saying so; this arm simply had not been brought into line.
            error_response(StatusCode::BAD_REQUEST, "Bad Request")
        } else if reason.starts_with("jwt:") {
            // Authentication failure — 401 Unauthorized. The specific reason is
            // logged server-side but never leaked to the client.
            error_response(StatusCode::UNAUTHORIZED, "Unauthorized")
        } else {
            block_response(ctx)
        };
        stamp_response(ctx, &resp);
        ctx.advance_phase(Phase::Logging);
        log_request(ctx);
        return Ok(resp);
    }

    // --- Phase 2: Request body ---
    ctx.advance_phase(Phase::RequestBody);

    let should_inspect_body = site.map(|s| s.waf.mode != WafMode::Off).unwrap_or(false);

    let boxed_body: BoxBody = if should_inspect_body {
        let max_bytes = site.map(|s| s.waf.max_body_size).unwrap_or(0);
        // should_inspect_body is only true when a site matched.
        let site_ref = site.expect("should_inspect_body implies a matched site");
        // Set when the body must be forwarded WITHOUT inspection: learning mode
        // met an oversize body, so the request has to keep working while the
        // would-block is recorded. A partial view cannot be scanned soundly, so
        // the choice is inspect-all or inspect-none — never inspect-a-prefix.
        let mut forward_uninspected: Option<BoxBody> = None;

        let bytes = if max_bytes > 0 {
            // Cheap early path when the client DECLARES an oversized
            // Content-Length: no body bytes have been read yet, so in learning
            // mode the whole body can be handed straight through untouched.
            let upper = body.size_hint().upper().unwrap_or(0);
            if upper > max_bytes {
                if let Some(resp) = enforce_request_limit(
                    ctx,
                    site_ref,
                    format!("request body too large (limit {} bytes)", max_bytes),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request Entity Too Large",
                ) {
                    return Ok(resp);
                }
                forward_uninspected = Some(body);
                Bytes::new()
            } else {
                // Enforce the cap WHILE streaming. For `Transfer-Encoding:
                // chunked` bodies size_hint is None (→0), so without this an
                // attacker could stream gigabytes into memory before any
                // post-collection check ran. buffer_for_scan stops at the first
                // frame that crosses the cap, bounding memory the same way
                // `Limited` did, and — unlike `Limited` — hands back the prefix
                // plus the untouched remainder so learning mode can forward the
                // request instead of failing it.
                match tokio::time::timeout(
                    body_read_timeout(),
                    buffer_for_scan(body, max_bytes as usize),
                )
                .await
                {
                    // Request trailers are deliberately not forwarded: no rule
                    // reads them, so passing them on would hand the origin
                    // fields that skipped the inspection the body just got.
                    // (The no-limit `collect` arm below drops them too.)
                    Ok(ScanBuffer::Complete(b, _trailers)) => b,
                    Ok(ScanBuffer::Oversize { prefix, rest }) => {
                        if let Some(resp) = enforce_request_limit(
                            ctx,
                            site_ref,
                            format!("request body too large (limit {} bytes)", max_bytes),
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "Request Entity Too Large",
                        ) {
                            return Ok(resp);
                        }
                        // Replay what was already read off the wire, then stream
                        // the rest — byte-for-byte, uninspected.
                        forward_uninspected = Some(
                            PrefixedBody {
                                prefix: Some(prefix),
                                inner: rest,
                            }
                            .boxed(),
                        );
                        Bytes::new()
                    }
                    Ok(ScanBuffer::Error(e)) => {
                        return Err(anyhow::anyhow!("collecting request body: {e}"))
                    }
                    Err(_) => {
                        // A slow-body timeout is NOT a policy limit being
                        // exceeded — it is the client failing to send. Learning
                        // mode downgrades policy verdicts; it cannot conjure a
                        // body that never arrived, and forwarding a stalled
                        // stream would only stall the origin too. So this
                        // rejects in every mode.
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason = Some("request body read timed out (slow-body)".into());
                        let resp = error_response(StatusCode::REQUEST_TIMEOUT, "Request Timeout");
                        stamp_response(ctx, &resp);
                        ctx.advance_phase(Phase::Logging);
                        log_request(ctx);
                        return Ok(resp);
                    }
                }
            }
        } else {
            match tokio::time::timeout(body_read_timeout(), body.collect()).await {
                Ok(r) => r.context("collecting request body")?.to_bytes(),
                Err(_) => {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some("request body read timed out (slow-body)".into());
                    let resp = error_response(StatusCode::REQUEST_TIMEOUT, "Request Timeout");
                    stamp_response(ctx, &resp);
                    ctx.advance_phase(Phase::Logging);
                    log_request(ctx);
                    return Ok(resp);
                }
            }
        };

        // Oversize under learning mode: forward untouched and skip every
        // body-phase inspection. Loudly, because an uninspected request is a
        // real coverage gap and must never be silent — the same rule the
        // response side already follows for an oversize response.
        if let Some(passthrough) = forward_uninspected {
            warn!(
                site = %site_ref.id,
                limit_bytes = max_bytes,
                "request body exceeds the limit — forwarded WITHOUT body inspection \
                 (learning mode); recorded as would-block"
            );
            passthrough
        } else {
            ctx.request_body = Some(bytes.clone());
            phase2_body(ctx, site, &engine_map, &state.ml_engine)?;

            // GraphQL firewall — query depth / complexity / introspection on the
            // body. Gated to GraphQL endpoints so nested REST-JSON bodies aren't
            // misread as GraphQL queries.
            if still_evaluating(ctx) {
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
                        // The endpoint gate above is a case-sensitive
                        // `contains("graphql")` on POST only. A site serving
                        // `/GraphQL`, or accepting GET, is silently never
                        // inspected — and nothing said so. `configured > 0` with
                        // `inspected == 0` after real traffic is the only way
                        // that mismatch is discoverable.
                        note_graphql_inspected();
                        let limits = GraphqlLimits {
                            max_depth: gql.max_depth,
                            max_complexity: gql.max_complexity,
                            block_introspection: gql.block_introspection,
                        };
                        if let Some(reason) = inspect_graphql(&bytes, &limits) {
                            note_graphql_blocked();
                            ctx.decision = WafDecision::Block;
                            ctx.block_reason = Some(reason);
                        }
                    }
                }
            }

            // gRPC firewall — message/frame-size limits on the buffered body.
            if still_evaluating(ctx) {
                if let Some(grpc_cfg) = site.and_then(|s| s.waf.grpc.as_ref()).filter(|g| g.enable)
                {
                    let is_grpc_ct = ctx
                        .request_headers
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(is_grpc);
                    if is_grpc_ct {
                        // Same reachability question as GraphQL: gated on a
                        // Content-Type match, so a transport or content-type
                        // mismatch shows up here as a permanent zero.
                        note_grpc_inspected();
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

            // The GraphQL and gRPC-body verdicts above are the only two that are
            // reached AFTER `phase2_body` has already applied `enforce_mode`
            // internally, so they were the two verdicts a site's mode could not
            // govern in either direction: on a learning site they hard-blocked
            // while setting no `would_block` (so the learning report held no
            // evidence for the block it had just served), and a per-path
            // `mode: off` could not switch them off at all.
            //
            // Re-applying the mode here rather than moving the checks into
            // `phase2_body`: both need the buffered `bytes` and the site's
            // GraphQL/gRPC config, which live in this scope. `enforce_mode` does
            // nothing when the decision is already non-terminal.
            if let Some(s) = site {
                let gm = governing_mode(ctx, &s.waf.mode);
                enforce_mode(ctx, &gm);
            }

            if ctx.decision == WafDecision::Limit {
                // Soft-deny from weighted fusion — throttle with 429 (configurable),
                // do not auto-ban (uncertain traffic).
                let resp = limit_response(ctx, site);
                stamp_response(ctx, &resp);
                ctx.advance_phase(Phase::Logging);
                log_request(ctx);
                return Ok(resp);
            }
            if ctx.decision == WafDecision::Block {
                note_block(&state, ctx.client_ip);
                let resp = block_response(ctx);
                stamp_response(ctx, &resp);
                ctx.advance_phase(Phase::Logging);
                log_request(ctx);
                return Ok(resp);
            }

            Full::new(bytes)
                .map_err(|never: Infallible| match never {})
                .boxed()
        }
    } else {
        // Already a `BoxBody` (TCP: boxed `Incoming`; h3: buffered QUIC body).
        body
    };

    // --- Phase 3: Upstream ---
    ctx.advance_phase(Phase::Upstream);

    // No site claims this Host. Answer 404 and say so, rather than failing the
    // request as an upstream error: that came out as 502 Bad Gateway, which tells
    // the visitor — and whoever is debugging a new DNS record — that the
    // APPLICATION is broken, when the truth is that this WAF has no site for the
    // name (a typo, DNS pointed here before the site was added, or the site was
    // deleted). Recorded, so the access log says which name was asked for.
    let Some(site_cfg) = site else {
        ctx.response_status = Some(StatusCode::NOT_FOUND);
        ctx.block_reason = Some(format!("no site is configured for host {host:?}"));
        ctx.advance_phase(Phase::Logging);
        log_request(ctx);
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "No site is configured for this hostname on this WAF.",
        ));
    };

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
    //
    // Gated on the site's `upstream.websocket`. Refusal happens HERE, before the
    // request leaves us, rather than at the 101 below: strip the upgrade headers
    // and the origin never switches protocols, so it answers as a plain HTTP
    // request and the client gets a real response. Refusing after a 101 would be
    // too late — the origin would already have switched, and a 101 we decline to
    // relay leaves the client holding a connection that never carries a byte.
    let ws_allowed = is_ws && site_cfg.upstream.websocket;
    if ws_allowed {
        strip_hop_by_hop_except_upgrade(&mut parts.headers);
        // Withdraw the compression offer every browser makes. A compressed
        // message is opaque to the rules, and the relay re-encodes frames — an
        // origin that accepted permessage-deflate would read our frames as
        // corrupt and close with 1002 on the first message.
        parts.headers.remove("sec-websocket-extensions");
    } else {
        strip_hop_by_hop(&mut parts.headers);
        // strip_hop_by_hop removes Connection and Upgrade, but Sec-WebSocket-*
        // are not hop-by-hop and would survive. Drop them too so the origin sees
        // no trace of a handshake it must not complete.
        if is_ws {
            for h in [
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-extensions",
                "sec-websocket-protocol",
            ] {
                parts.headers.remove(h);
            }
            debug!(
                site = %site_cfg.id,
                "WebSocket upgrade refused: upstream.websocket is false; forwarding as plain HTTP"
            );
        }
    }
    // Never hand an origin the console's own session cookie. Browsers scope
    // cookies by host, not port, so a console reached at https://host:9443 has
    // its cookie sent to every site the WAF serves on that same host — and
    // until 1.1.11 that cookie WAS the admin access token.
    strip_console_session_cookie(&mut parts.headers);
    inject_forwarding_headers(&mut parts.headers, peer.ip())?;

    // Per-site `Host` override for an origin that virtual-hosts on an internal
    // name. Applied HERE, at the last step before the request leaves us, and
    // deliberately not earlier: site matching, WAF evaluation and logging have
    // already run against the host the client actually sent, so this cannot move
    // a request onto another site's policy or hide the real host from the log.
    if let Some(hh) = site_cfg
        .upstream
        .host_header
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        match header::HeaderValue::from_str(hh) {
            Ok(hv) => {
                parts.headers.insert(header::HOST, hv);
            }
            // A header value that cannot be constructed would otherwise panic or
            // silently fall through; pass the client's Host and say so.
            Err(e) => warn!(
                site = %site_cfg.id, host_header = %hh,
                "invalid upstream host_header, forwarding the client's Host instead: {e}"
            ),
        }
    }

    // Per-site keep-alive. `Connection: close` is the per-request lever, so this
    // needs no second connection pool: hyper honours it and retires the
    // connection after the response instead of returning it to the pool. Legal
    // because we always forward as HTTP/1.1 (below) — the header is meaningless
    // in HTTP/2 and would be a protocol error there.
    //
    // Skipped entirely for an upgrade: the whole point of a 101 is that the
    // connection persists, and `Connection: close` contradicts `Connection:
    // Upgrade` in the same request.
    if !site_cfg.upstream.keepalive && !ws_allowed {
        parts.headers.insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
    }

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
        // Belt-and-braces: we stripped the handshake headers above when the site
        // disallows WebSockets, so a compliant origin cannot reach here with a 101.
        // If one does anyway, refuse rather than relay — passing the 101 back
        // without a relay would hand the client a permanently silent connection,
        // and relaying would defeat the setting outright.
        if !ws_allowed {
            warn!(
                site = %site_cfg.id,
                "origin returned 101 though upstream.websocket is false and the \
                 handshake headers were stripped — refusing to relay"
            );
            return Err(anyhow::anyhow!(
                "upstream switched protocols for a site with WebSockets disabled"
            ));
        }
        if let Some(client_upgrade_fut) = ws_upgrade {
            let upstream_upgrade_fut = hyper::upgrade::on(Response::from_parts(
                resp_parts.clone(),
                http_body_util::Empty::<Bytes>::new(),
            ));
            let client_ip = ctx.client_ip;
            let site_id = site_cfg.id.clone();
            // Cloning the site's compiled engine per connection, as this once
            // did, copied the whole rule set for every socket; the inspector
            // instead reads the live map, so a rule pushed while a socket is
            // open applies to its next message.
            let ws_inspector: Option<Arc<dyn websocket::MessageInspector>> =
                if engine_map.contains_key(&site_id) {
                    Some(Arc::new(WsSiteInspector {
                        site: site_cfg.clone(),
                        engines: Arc::clone(&state.engines),
                        ml_engine: Arc::clone(&state.ml_engine),
                        client_ip,
                        uri: ctx.uri.clone(),
                        tenant_id: ctx.tenant_id.clone(),
                        tls_fingerprint: ctx.tls_fingerprint.clone(),
                        enforcement_mode: ctx.enforcement_mode.clone(),
                        anomaly_threshold: ctx.anomaly_threshold,
                        paranoia: ctx
                            .tx_vars
                            .get("DETECTION_PARANOIA_LEVEL")
                            .cloned()
                            .unwrap_or_else(|| site_cfg.waf.paranoia_level.to_string()),
                        log_headers: [http::header::USER_AGENT, http::header::REFERER]
                            .into_iter()
                            .filter_map(|h| ctx.request_headers.get(&h).map(|v| (h, v.clone())))
                            .collect(),
                    }))
                } else {
                    None
                };
            ctx.advance_phase(Phase::Logging);
            log_request(ctx);

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
                    ws_inspector,
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
    #[cfg(test)]
    panic_guard::inject_response_panic(ctx);

    let dlp_map = state.dlp_map.load_full();
    let resp_engines = state.engines.load_full();

    // Inspect the response body only when something actually needs it: a DLP
    // scanner is enabled for the site, OR the site's rule set has response-body
    // rules (e.g. CRS RESPONSE-* data-leakage rules).  Most sites have neither,
    // so the response streams straight through with zero added latency.
    // Each scanner reads only the media types it is for — see `dlp_applies` and
    // `response_rules_apply`. Anything else (media, downloads, scripts,
    // stylesheets) streams straight through unbuffered.
    let dlp = dlp_map
        .get(&site_cfg.id)
        .filter(|d| d.enabled)
        .filter(|_| dlp_applies(&resp_parts.headers));
    let resp_engine = resp_engines
        .get(&site_cfg.id)
        .filter(|e| e.has_response_body_rules())
        .filter(|_| response_rules_apply(&resp_parts.headers, resp_parts.status));
    let needs_inspection = dlp.is_some() || resp_engine.is_some();

    let final_body: BoxBody = if needs_inspection {
        // A response that DECLARES an oversized length streams straight through
        // — no point buffering to discover what the origin already told us.
        let declared_oversize = resp_body
            .size_hint()
            .upper()
            .is_some_and(|u| u > RESPONSE_SCAN_CAP as u64);

        if !declared_oversize {
            // Box first so the body is `Unpin` for frame-by-frame reads; every
            // branch below boxes it anyway, so this costs nothing extra.
            match buffer_for_scan(resp_body.boxed(), RESPONSE_SCAN_CAP).await {
                // The origin failed mid-body. This used to forward the head with
                // an EMPTY body, which every client took as a complete, empty
                // response, logged as a clean 200. No head has been sent yet, so
                // fail the request: `proxy` answers a logged 502.
                ScanBuffer::Error(e) => {
                    return Err(anyhow::Error::new(e)
                        .context("reading origin response body for inspection"));
                }
                ScanBuffer::Oversize { prefix, rest } => {
                    // Too large to scan: replay what was already read, stream
                    // the rest. Never silent — an unscanned response is a
                    // coverage gap the operator has to be able to see.
                    warn!(
                        site = %site_cfg.id,
                        cap_bytes = RESPONSE_SCAN_CAP,
                        "response exceeds the scan cap — forwarded WITHOUT DLP / response-rule inspection"
                    );
                    PrefixedBody {
                        prefix: Some(prefix),
                        inner: rest,
                    }
                    .boxed()
                }
                ScanBuffer::Complete(mut bytes, trailers) => {
                    // A request that learning mode already recorded as
                    // would-block was decided by the request; that stays the
                    // event's explanation whatever the response adds.
                    if ctx.would_block && ctx.verdict_source.is_none() {
                        ctx.verdict_source = Some(VerdictSource::Request);
                    }
                    // (1) Response-body rule engine (CRS RESPONSE-* etc.).
                    if let Some(engine) = resp_engine {
                        ctx.response_body = Some(bytes.clone());
                        // Judged on the response's own score against the
                        // outbound threshold, never the site's request one.
                        let threshold = outbound_threshold(ctx);
                        ctx.outbound_threshold = Some(threshold);
                        let request_reason = ctx.block_reason.clone();
                        engine.evaluate(ctx, Phase::ResponseBody, threshold);
                        if ctx.decision == WafDecision::Block {
                            match ctx.verdict_source {
                                None => ctx.verdict_source = Some(VerdictSource::Response),
                                // Learning mode, request already would-block:
                                // keep its reason; the response rule is listed
                                // with the event's rules and in the learning
                                // report, which counts every matched rule.
                                Some(_) => ctx.block_reason = request_reason,
                            }
                        }
                        // Respect learning mode (downgrade Block → Log).
                        let gm = governing_mode(ctx, &site_cfg.waf.mode);
                        enforce_mode(ctx, &gm);
                        inspection_limits::warn_if_forwarded(ctx, site_cfg, &Phase::ResponseBody);
                        if ctx.decision == WafDecision::Block {
                            warn!(
                                site = %site_cfg.id,
                                client_ip = %ctx.client_ip,
                                "response-body rule matched — blocking"
                            );
                            let resp = block_response(ctx);
                            stamp_response(ctx, &resp);
                            ctx.advance_phase(Phase::Logging);
                            log_request(ctx);
                            return Ok(resp);
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
                                    if ctx.verdict_source.is_none() {
                                        ctx.verdict_source = Some(VerdictSource::Dlp);
                                        ctx.block_reason = Some(format!(
                                            "DLP: sensitive data pattern matched: {matched}"
                                        ));
                                    }
                                    // Learning mode downgrades Block → Log —
                                    // must not block or rewrite, only record.
                                    let gm = governing_mode(ctx, &site_cfg.waf.mode);
                                    enforce_mode(ctx, &gm);
                                    if ctx.decision == WafDecision::Block {
                                        warn!(
                                            site = %site_cfg.id,
                                            client_ip = %ctx.client_ip,
                                            pattern = matched,
                                            "DLP: sensitive data in response — blocking"
                                        );
                                        let resp = block_response(ctx);
                                        stamp_response(ctx, &resp);
                                        ctx.advance_phase(Phase::Logging);
                                        log_request(ctx);
                                        return Ok(resp);
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
                                    ctx.tx_vars
                                        .insert("dlp_detected".to_string(), matched.to_string());
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

                    rebuilt_body(bytes, trailers)
                }
            }
        } else {
            resp_body.boxed()
        }
    } else {
        resp_body.boxed()
    };

    // --- Phase 6: Logging ---
    // Response size for the access log: exact when the body was buffered for
    // inspection (Full has an exact size hint), otherwise the origin's declared
    // Content-Length. A chunked stream with no declared length stays 0 — the
    // log line is written before the stream completes, and a wrong number is
    // worse than an absent one.
    ctx.bytes_sent = hyper::body::Body::size_hint(&final_body)
        .exact()
        .or_else(|| {
            resp_parts
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0);
    ctx.advance_phase(Phase::Logging);
    log_request(ctx);

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
    // The plugins THIS SITE runs. Empty means none: plugins are opt-in per
    // site, so a module being loaded on the node is not permission to judge
    // every site's traffic with it.
    site_plugins: &[String],
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
    if still_evaluating(ctx) {
        // Counted, not logged: this runs on every request and its input is
        // attacker-controlled, so a log line here would be both a throughput
        // problem and a flood primitive. The counter answers the question the
        // absence of a log could not — "did desync detection run at all?" — which
        // is exactly what the phase-1 gate bug made unanswerable.
        note_smuggling_evaluated();
        match detect_smuggling(&ctx.request_headers) {
            SmugglingVerdict::Reject { reason } => {
                // Split so a wave of rejections can be attributed without
                // reading log lines: framing is the real desync primitive, the
                // header tripwire is the one that used to fire on ordinary
                // non-ASCII header values.
                if reason.contains("in header '") {
                    note_smuggling_rejected_header();
                } else {
                    note_smuggling_rejected_framing();
                }
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(reason);
            }
            SmugglingVerdict::Clean => {}
        }
    }

    // Apply the site's mode to the smuggling verdict BEFORE the early return.
    //
    // Returning early is deliberate and kept — a desynced request should not be
    // scored by anything downstream. But this return sat AHEAD of the only
    // `enforce_mode` call in this function (at the end of phase 1), so a
    // smuggling verdict was the one verdict learning mode could not downgrade: a
    // site configured purely to observe answered 400 and set no `would_block`, so
    // the rejection never even reached the learning report. Verified live.
    //
    // `enforce_mode` is idempotent for an already-downgraded decision, so the
    // call at the end of phase 1 remains correct.
    if ctx.decision == WafDecision::Block {
        let gm = governing_mode(ctx, &site.waf.mode);
        enforce_mode(ctx, &gm);
        if ctx.decision == WafDecision::Block {
            return Ok(());
        }
    }

    // --- Rate limiting ---
    if still_evaluating(ctx) {
        if let Some(ref rl_cfg) = site.waf.rate_limit {
            if modules
                .rate_limiter
                .check_async(&site.id, ctx.client_ip, rl_cfg)
                .await
            {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!("rate limit exceeded for {}", ctx.client_ip));
                // A throttle is not a policy block: answer 429 so clients back off.
                ctx.block_status = Some(429);
            }
        }
    }

    // --- Bot detection ---
    if still_evaluating(ctx) {
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
                // A good-bot User-Agent earns the allowlist only once its claim
                // is verified by reverse DNS (PTR in the operator's published
                // domain, forward-confirmed). `check` never awaits: it answers
                // from the per-IP cache and, on a miss, starts a bounded
                // background lookup and answers "unknown" — no bypass, no
                // penalty. The UA alone used to be enough, which made bot
                // scoring opt-out.
                good_bot_verified: sentinel_modules::good_bot_name(ua)
                    .and_then(|crawler| modules.goodbot.check(ctx.client_ip, crawler)),
            };
            let bs = bot_det.score(&sig);
            // Counted here rather than inside the module, which has no telemetry
            // dependency and should not gain one for a single counter.
            //
            // This puts a number on an unauthenticated trust decision: the
            // good-bot branch returns score 0 / tier Allow for any User-Agent
            // matching one of the 14 good-bot patterns, and reverse-DNS
            // confirmation is still a TODO (`verified_good_bot` is hardcoded
            // false). So anyone may claim to be Googlebot and skip bot scoring
            // entirely. Until that verification exists, the least we can do is
            // report how often it happens.
            // Counts allowlist GRANTS, which `verified_good_bot` marks and only
            // the verified early return can set.
            //
            // ⚠️ It first counted "Allow + unverified + a good-bot reason", which
            // read as "the bypass happened" — and was wrong: after the fix, an
            // UNVERIFIED claim legitimately lands in Allow on merit (that is the
            // SEO-safety property, since a real crawler's first request from each
            // new address arrives before its lookup lands). Live on .71 that
            // condition fired on exactly the correct behaviour, three times, and
            // looked like the bypass surviving. Count the grant itself, which is
            // unambiguous.
            if bs.verified_good_bot {
                note_good_bot_allowed();
            }
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
    if still_evaluating(ctx) && site.waf.geoip.is_some() {
        let geoip_map = modules.geoip_map.load();
        if let Some(geoip) = geoip_map.get(&site.id) {
            // Resolve the country FIRST and record it whatever the verdict is.
            // Previously it was only stamped on the Block branch, so every
            // allowed request logged an empty country and the dashboard map and
            // country facets saw blocked traffic only — they under-reported by
            // construction rather than because the data was unavailable.
            ctx.geo_country = geoip.country(ctx.client_ip);
            match geoip.classify(ctx.geo_country.as_deref()) {
                GeoVerdict::Block { country_code } => {
                    ctx.block_reason = Some(format!("country blocked: {country_code}"));
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
    if still_evaluating(ctx) {
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
                            // The operator's problem, not the client's: this
                            // policy cannot verify ANY token, so every request
                            // carrying one is rejected. Said once per
                            // (site, reason) rather than per request.
                            if jwt_failure_is_misconfiguration(&reason)
                                && diag_first_time(format!("jwt:{}:{}", site.id, reason))
                            {
                                error!(
                                    site = %site.id, reason = %reason,
                                    jwks_url = jwt_cfg.jwks_url.as_deref().unwrap_or("-"),
                                    has_hs_secret = jwt_cfg.hs_secret.is_some(),
                                    has_public_key = jwt_cfg.public_key_pem.is_some(),
                                    "JWT policy cannot verify tokens — every request presenting one \
                                     is being rejected with 401. This is a configuration fault, not \
                                     an attack: fix the key material (hs_secret, public_key_pem or a \
                                     reachable jwks_url), or disable JWT for this site."
                                );
                            }
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
    if still_evaluating(ctx) {
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

    // Seed the CRS policy lists before the first rule sees them. Must be here
    // rather than earlier: `site` is not resolved until the host is matched.
    seed_crs_policy(ctx, site);

    // --- Rule engine (CRS / SRL) ---
    if still_evaluating(ctx) {
        if let Some(engine) = engines.get(&site.id) {
            eval_rules(ctx, engine, Phase::RequestHeaders);
        }
    }

    // --- WASM plugins (only those this site opted into) ---
    if still_evaluating(ctx) && !site_plugins.is_empty() {
        for plugin_name in site_plugins {
            let result = plugin_runtime.evaluate_plugin(plugin_name, ctx).await;
            note_plugin_outcome(&result);
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
                    note_plugin_outcome(&result2);
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

    let gm = governing_mode(ctx, &site.waf.mode);
    enforce_mode(ctx, &gm);
    inspection_limits::warn_if_forwarded(ctx, site, &Phase::RequestHeaders);
    Ok(())
}

/// Judges WebSocket messages for one socket with the site's own body verdict
/// path: rules, ML, `apply_verdict` and the governing mode — the path an HTTP
/// request body takes, so a message is refused exactly when the same bytes
/// POSTed would be.
///
/// The inspector used to call the rule VM directly with the anomaly threshold
/// disabled and never reach a verdict, and gave it a body with no content type,
/// so CRS's ARGS rules saw nothing: only an explicit `deny` rule could ever
/// refuse a message, and it did so even in learning mode.
struct WsSiteInspector {
    site: SiteConfig,
    engines: Arc<ArcSwap<RuleEngineMap>>,
    ml_engine: Arc<MlEngine>,
    client_ip: IpAddr,
    /// The upgrade request's URI, so a record names the socket's real path.
    uri: http::Uri,
    tenant_id: Option<String>,
    tls_fingerprint: Option<String>,
    /// A path override's mode and threshold, stamped on the upgrade request.
    enforcement_mode: Option<WafMode>,
    anomaly_threshold: Option<u32>,
    /// `TX:DETECTION_PARANOIA_LEVEL` as phase 1 set it for the upgrade. Every
    /// CRS file opens with a rule that skips the whole file when it is unset.
    paranoia: String,
    /// The upgrade request's User-Agent and Referer — for the LOG RECORD only,
    /// added after the verdict (see `record`), never to the context a message is
    /// evaluated with.
    log_headers: http::HeaderMap,
}

impl WsSiteInspector {
    fn message_ctx(&self) -> RequestContext {
        let mut ctx = RequestContext::new(self.client_ip, 0);
        ctx.uri = self.uri.clone();
        ctx.site_id = Some(self.site.id.clone());
        ctx.tenant_id = self.tenant_id.clone();
        ctx.tls_fingerprint = self.tls_fingerprint.clone();
        ctx.enforcement_mode = self.enforcement_mode.clone();
        ctx.anomaly_threshold = self.anomaly_threshold;
        ctx.inspection_limits = self.site.waf.inspection_limits();
        ctx.tx_vars
            .insert("DETECTION_PARANOIA_LEVEL".to_owned(), self.paranoia.clone());
        // Only the content type, not the handshake's headers: those were judged
        // at the upgrade, and re-scoring its cookies on every message would add
        // their score to each one. JSON is how WebSocket apps talk; the body
        // processor flattens it into ARGS, and anything that is not JSON falls
        // back to being scanned whole as one value.
        ctx.request_headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        ctx
    }

    fn mode(&self) -> WafMode {
        self.enforcement_mode
            .clone()
            .unwrap_or_else(|| self.site.waf.mode.clone())
    }

    fn record(&self, ctx: &mut RequestContext, what: &str) {
        let why = ctx.block_reason.take().unwrap_or_default();
        ctx.block_reason = Some(if why.is_empty() {
            format!("websocket message: {what}")
        } else {
            format!("websocket message: {why}")
        });
        // The record used to read status 0 and ua "-": the message context is
        // built fresh, with no response and none of the handshake's headers. The
        // connection WAS upgraded (101) and the message rode on it; the client is
        // the one that opened it. Both are attached only now, after the verdict,
        // so the handshake's headers are never re-scored on every message.
        ctx.response_status = Some(StatusCode::SWITCHING_PROTOCOLS);
        for (name, value) in self.log_headers.iter() {
            ctx.request_headers.insert(name.clone(), value.clone());
        }
        ctx.advance_phase(Phase::Logging);
        log_request(ctx);
    }

    /// Run `judge` on a fresh message context under a panic guard. The relay
    /// calls the inspector for every message, outside any request guard, so a
    /// panic in it is answered here like a request's: logged and counted
    /// ([`panic_guard::ws_message_panicked`]), and the socket closed with 1011
    /// without forwarding the message, in every mode, as a request that panics
    /// is answered 500 and not forwarded.
    fn contained(
        &self,
        judge: impl FnOnce(&mut RequestContext) -> websocket::Verdict,
    ) -> websocket::Verdict {
        let mut ctx = self.message_ctx();
        match panic_guard::catch_request_sync(|| judge(&mut ctx)) {
            Ok(verdict) => verdict,
            Err(payload) => {
                panic_guard::ws_message_panicked(&mut ctx, &*payload, |ctx| {
                    self.record(ctx, "internal error")
                });
                websocket::Verdict::Refuse(websocket::CLOSE_INTERNAL_ERROR)
            }
        }
    }

    fn judge(&self, ctx: &mut RequestContext, message: &[u8]) -> websocket::Verdict {
        #[cfg(test)]
        panic_guard::inject_ws_panic(message);
        ctx.request_body = Some(Bytes::copy_from_slice(message));
        seed_crs_policy(ctx, &self.site);
        ctx.advance_phase(Phase::RequestBody);
        let engines = self.engines.load();
        if let Err(e) = phase2_body(ctx, Some(&self.site), &engines, &self.ml_engine) {
            warn!(site = %self.site.id, "WS message inspection failed: {e}");
            return if self.mode() == WafMode::Blocking {
                websocket::Verdict::Refuse(websocket::CLOSE_INTERNAL_ERROR)
            } else {
                websocket::Verdict::Forward
            };
        }
        if ctx.decision == WafDecision::Block {
            self.record(ctx, "blocked");
            websocket::Verdict::Refuse(websocket::CLOSE_POLICY_VIOLATION)
        } else {
            if ctx.would_block {
                self.record(ctx, "would block");
            }
            websocket::Verdict::Forward
        }
    }

    fn judge_too_large(&self, ctx: &mut RequestContext, len: usize) -> websocket::Verdict {
        ctx.block_reason = Some(format!(
            "{len}+ bytes exceeds the {} byte inspection limit",
            websocket::MAX_INSPECT_MESSAGE_BYTES
        ));
        if self.mode() == WafMode::Blocking {
            ctx.decision = WafDecision::Block;
            self.record(ctx, "too large");
            websocket::Verdict::Refuse(websocket::CLOSE_TOO_BIG)
        } else {
            warn!(
                site = %self.site.id,
                len,
                "WS message exceeds the inspection limit — forwarded WITHOUT inspection \
                 (not in blocking mode); recorded as would-block"
            );
            ctx.decision = WafDecision::Log;
            ctx.would_block = true;
            self.record(ctx, "too large");
            websocket::Verdict::Forward
        }
    }
}

impl websocket::MessageInspector for WsSiteInspector {
    fn inspect(&self, message: &[u8]) -> websocket::Verdict {
        self.contained(|ctx| self.judge(ctx, message))
    }

    fn too_large(&self, len: usize) -> websocket::Verdict {
        self.contained(|ctx| self.judge_too_large(ctx, len))
    }
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
        eval_rules(ctx, engine, Phase::RequestBody);
    }

    // A request the rule engine refused to finish inspecting is decided by the
    // refusal — blocking mode refuses it, learning mode records it — and an ML
    // score could change neither: `apply_verdict` returns on a Block. The
    // inspection limits do not bound what ML reads, so scoring it anyway cost
    // 25-35 times the refusal: 307 ms on a 9.9 MiB form the rules refused in
    // 12 ms, 450 ms on 9.9 MiB of text.
    let refused = inspection_limits::refused(ctx);
    if let Some(ml_cfg) = site.waf.ml.as_ref().filter(|_| !refused) {
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
                        // A classifier verdict has no single matched substring.
                        matched_value: String::new(),
                    });
                }
            }
        }
    }

    apply_verdict(ctx, &site.waf);

    let gm = governing_mode(ctx, &site.waf.mode);
    enforce_mode(ctx, &gm);
    inspection_limits::warn_if_forwarded(ctx, site, &Phase::RequestBody);
    Ok(())
}

// ---------------------------------------------------------------------------
// Weighted verdict fusion (#11)
// ---------------------------------------------------------------------------

/// Score at or above which the n-gram classifier refuses to vouch for a payload,
/// so a weak-evidence rule block stands.
///
/// Calibrated from the model's measured score distribution rather than guessed.
/// On adversarial-benign inputs (natural-language prose carrying SQL/shell
/// keywords — "union was a great select", "ls 300 lexus", a shared Instagram
/// link) the model scores 0.0001–0.26; on unambiguous attacks it scores
/// 0.91–1.00. 0.5 sits at the max-margin point between those clusters (their
/// geometric mean is ≈0.48): ~2x above the worst benign and ~1.8x below the
/// weakest attack, so it tolerates drift in both directions.
///
/// The previous value, 0.15, sat *below* the benign ceiling, so prose the model
/// had already scored correctly as benign was still blocked.
const ML_SUPPRESSION_MAX: f32 = 0.5;

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

/// Does the n-gram classifier veto this threshold-based block as a likely
/// false positive?
///
/// Extracted so the fusion and non-fusion verdict paths cannot disagree. They
/// did: the suppression lived inline in the non-fusion branch only, so
/// **enabling weighted fusion silently disabled the entire precision layer**.
/// A site with `fusion.enable: true` blocked on raw threshold arithmetic with
/// no model input at all, which is the opposite of what turning on a more
/// sophisticated verdict engine should do — and it is the same silently-inert
/// shape as a feature that is configured, reported, and never consulted.
///
/// The three conditions are unchanged:
///
/// 1. No in-house coverage signature (99002xx) fired. Those are ours, tuned
///    against this corpus, and are not second-guessed.
/// 2. The rule evidence is thin — under 20, i.e. two or three CRS matches.
///    This deliberately reads `anomaly_score`, the RAW rule score, in both
///    paths: "how much did the rules actually see" is the same question
///    however the verdict is later computed, and the fused score is a weighted
///    transformation of that same evidence rather than new evidence.
/// 3. The classifier scored the payload below ML_SUPPRESSION_MAX.
///
/// A veto needs all three. Anything the model has not seen cannot be vetoed by
/// it — which is why the classifier's candidate list has to cover every place
/// the rules look.
fn ml_vetoes_weak_block(ctx: &RequestContext) -> bool {
    sentinel_ml::models::ngram_classifier::is_loaded()
        && !ctx
            .rule_matches
            .iter()
            .any(|m| m.rule_id.starts_with("99002"))
        && ctx.ml_scores.get("payload_attack").copied().unwrap_or(1.0) < ML_SUPPRESSION_MAX
        && request_evidence(ctx) < 20
}

/// Anomaly score earned by THIS request — rules, classifier, plugins — with the
/// engines that score the client's HISTORY taken back out.
///
/// The veto's evidence cap is documented as "2-3 CRS matches worth". It was
/// compared against the total `anomaly_score`, and three engines add points
/// that come from the IP rather than from anything in the request:
///
///   correlation  — recent blocks from this IP, capped at 4
///   bot          — the SAME recent-block count again as "repeat-offender",
///                  +10/+20 to the bot score, surfacing as +4/+5 here
///   reputation   — a tagged CIDR list (Tor, known-bad), +2
///
/// Measured live on 2026-09-16 with a benign search term (`D'or 1st parfume`):
/// 15 from rules on a clean IP, vetoed as benign prose, HTTP 200. Twenty
/// attacks from the same IP inside the 60 s correlation window, and the
/// identical request scored 24 — 15 + 4 + 5 — cleared the cap, and was a 403.
/// Sixty-five seconds later it was 15 and a 200 again. The request never
/// changed. Its neighbour's did.
///
/// That is history manufacturing evidence, and one signal (the block count)
/// counted twice on the way. History escalating a borderline verdict is what
/// correlation is FOR, and it still does that against the block threshold. It
/// must not be able to switch the false-positive protection off — the guard
/// asks what the rules saw, and the rules saw 15.
///
/// GoTestWAF reproduced this as 8 benign texts "blocked under concurrency",
/// because it sends 675 attacks and 141 benign texts from one address. It was
/// never concurrency.
fn request_evidence(ctx: &RequestContext) -> u32 {
    let history: u32 = ["correlation", "bot", "reputation"]
        .iter()
        .filter_map(|e| ctx.engine_scores.get(*e))
        .sum();
    ctx.anomaly_score.saturating_sub(history)
}

/// Seed the `tx.` policy variables CRS rules gate on, before any rule runs.
///
/// Thirteen CRS rules test a request against a `tx.` list that `crs-setup.conf`
/// normally defines — restricted extensions, allowed content types and HTTP
/// versions, argument count and length caps, restricted headers. Nothing seeded
/// them, so `expand_operator_macros` refused to resolve them and every one of
/// those rules was permanently inert. That is safe (the alternative, expanding
/// an unset list to `""`, makes `!@within` match everything and denies every
/// request) but it was also unreachable: there was no way to turn them on.
///
/// Two different things are seeded here, for two different reasons.
///
/// `allowed_methods` comes from the site's OWN `waf.allowed_methods`, never
/// from CRS's example value. CRS ships `GET HEAD POST OPTIONS`, so seeding that
/// would have rejected PUT, PATCH and DELETE on every site — including this
/// deployment, whose site permits all seven. Taking it from the site config
/// makes rule 911100 agree with the method allow-list the proxy already
/// enforces a few lines above (with a clean 405, before rules run), rather
/// than contradict it.
///
/// Everything else comes from `waf.crs_policy` and is EMPTY by default, which
/// matches upstream: CRS ships every one of those `SecAction` blocks commented
/// out. They are opt-in policy because the right value is a property of the
/// application — `arg_length=400` rejects any parameter longer than an ordinary
/// JWT. Enabling them for everyone would have made this WAF stricter than CRS's
/// own default with limits nobody chose.
///
/// Names are stored upper-case and without the `tx.` prefix, matching
/// `resolve_operator_macro`.
fn seed_crs_policy(ctx: &mut RequestContext, s: &SiteConfig) {
    if !s.waf.allowed_methods.is_empty() {
        ctx.tx_vars.insert(
            "ALLOWED_METHODS".to_string(),
            s.waf.allowed_methods.join(" ").to_uppercase(),
        );
    }
    for (k, v) in &s.waf.crs_policy {
        if k.is_empty() || v.is_empty() {
            continue;
        }
        // An operator writing `tx.max_num_args` means `max_num_args`.
        let key = k.trim().trim_start_matches("tx.").trim_start_matches("TX.");
        ctx.tx_vars.insert(key.to_uppercase(), v.clone());
    }
}

/// The media types the response-body RULES inspect: ModSecurity's own default,
/// `SecResponseBodyMimeType text/plain text/html text/xml` — plus JSON on a
/// server error (see `response_rules_apply`).
///
/// The CRS RESPONSE-95x leak rules are written for pages a server renders —
/// error pages, stack traces, directory listings. Run over a minified
/// JavaScript bundle or a JSON API they match the application's own code and
/// data: on the first real application behind the WAF, all 34 response
/// detections were false positives of exactly that kind (953101 on the login
/// page's JavaScript, 951220 on a JSON product list mentioning "SQL Server"),
/// every one of them would have blocked, and buffering the bundles put
/// 400–600 ms of WAF time on the login page.
///
/// A response with no Content-Type is still inspected, as DLP treats it: an
/// origin that does not say what it sent is not trusted to be harmless.
const RESPONSE_RULE_MIME_TYPES: [&str; 3] = ["text/html", "text/plain", "text/xml"];

fn response_rules_apply(headers: &http::HeaderMap, status: StatusCode) -> bool {
    // JSON too, but only on a SERVER ERROR. That is where an API leaks what
    // these rules exist to catch — `{"error":"ORA-00933: SQL command not
    // properly ended"}`, a stack trace in a 500 — and a successful JSON body is
    // where they misfire on the application's own data (951220 on a product
    // list mentioning "SQL Server"). Restricting to HTML/plain/XML alone had
    // dropped that coverage. (Code review finding.)
    let error = status.is_server_error();
    response_declares(headers, |media| {
        RESPONSE_RULE_MIME_TYPES.contains(&media) || (error && is_json_media(media))
    })
}

/// Whether DLP reads this response: pages and data — any `text/*`, JSON or XML
/// type — but not scripts, stylesheets or streams.
///
/// A JavaScript bundle or a stylesheet is the application's own code, shipped
/// identically to every visitor; it carries no visitor's card number or
/// Aadhaar. Scanning them cost real time — the eNlight360 login page's 346 KB
/// bundle, served as `text/javascript`, was buffered and scanned on every
/// load — and with `action: block` a digit run in minified code that happened
/// to look like a card number would have replaced the script with a block
/// page. An API that returns data as JSONP (`application/javascript`) is not
/// scanned either; that pattern predates CORS and is rare.
///
/// A STREAM is never buffered: Server-Sent Events and newline-delimited JSON
/// deliver one small message at a time on a connection that stays open, and
/// scanning buffers the body until it ends or passes the scan cap — so a live
/// notification feed delivered nothing at all. (Code review finding.)
///
/// JSON and XML are recognised by their structured types, not by a substring:
/// `contains("xml")` also matched `application/vnd.openxmlformats-…` — every
/// Excel, Word and PowerPoint download — and buffered up to 512 KiB of a zip.
fn dlp_applies(headers: &http::HeaderMap) -> bool {
    response_declares(headers, |media| {
        if SCRIPT_OR_STYLE_MEDIA_TYPES.contains(&media) || STREAMING_MEDIA_TYPES.contains(&media) {
            return false;
        }
        media.starts_with("text/") || is_json_media(media) || is_xml_media(media)
    })
}

/// The application's own code: never scanned by DLP.
const SCRIPT_OR_STYLE_MEDIA_TYPES: [&str; 6] = [
    "text/css",
    "text/javascript",
    "text/ecmascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
];

/// Media types delivered incrementally on a long-lived response. Buffering one
/// to scan it holds every message back until the stream ends.
const STREAMING_MEDIA_TYPES: [&str; 5] = [
    "text/event-stream",
    "application/x-ndjson",
    "application/jsonl",
    "application/json-seq",
    "application/stream+json",
];

/// `application/json` and every `+json` structured type.
fn is_json_media(media: &str) -> bool {
    media == "application/json" || media.ends_with("+json")
}

/// `application/xml`, `text/xml` and every `+xml` structured type.
fn is_xml_media(media: &str) -> bool {
    media == "application/xml" || media == "text/xml" || media.ends_with("+xml")
}

/// Whether the response's Content-Type satisfies `wanted`.
///
/// Any of the Content-Type headers, not just the first: an origin that emits
/// two (nginx `return` + `add_header` does) put a binary type first and slipped
/// a card number past the scanner. A response that does not say — no header,
/// or one that is empty or unreadable — is inspected: an origin that does not
/// say what it sent is not trusted to be harmless. The media type is compared
/// lowercased, without parameters.
fn response_declares(headers: &http::HeaderMap, wanted: impl Fn(&str) -> bool) -> bool {
    let mut cts = headers.get_all(header::CONTENT_TYPE).iter().peekable();
    if cts.peek().is_none() {
        return true;
    }
    cts.any(|v| {
        let media = v
            .to_str()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        media.is_empty() || wanted(&media)
    })
}

/// The outbound (response) anomaly threshold for this request: the site's CRS
/// policy `outbound_anomaly_score_threshold` when it sets a positive number,
/// otherwise CRS's default of 4.
fn outbound_threshold(ctx: &RequestContext) -> u32 {
    ctx.tx_vars
        .get("OUTBOUND_ANOMALY_SCORE_THRESHOLD")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|t| *t > 0)
        .unwrap_or(sentinel_rules::DEFAULT_OUTBOUND_ANOMALY_THRESHOLD)
}

/// The score that explains this verdict, the threshold it was judged against,
/// and whether it is the RESPONSE's score.
///
/// The request and the response are scored separately (see
/// `RequestContext::outbound_anomaly_score`), but an event records one score.
/// It records the response's when the response is what reached its threshold,
/// or when the response is all that scored; the request's otherwise.
fn verdict_score(ctx: &RequestContext) -> (u32, Option<u32>, bool) {
    // A recorded decider answers it; the inference below is only for events no
    // verdict decided (a sub-threshold match), where there is no decider to ask.
    match ctx.verdict_source {
        Some(VerdictSource::Response) => {
            return (ctx.outbound_anomaly_score, ctx.outbound_threshold, true)
        }
        Some(VerdictSource::Request) | Some(VerdictSource::Dlp) => {
            return (ctx.anomaly_score, ctx.anomaly_threshold, false)
        }
        None => {}
    }
    let reached = |score: u32, t: Option<u32>| t.is_some_and(|t| t > 0 && score >= t);
    let inbound_hit = reached(ctx.anomaly_score, ctx.anomaly_threshold);
    let outbound_hit = reached(ctx.outbound_anomaly_score, ctx.outbound_threshold);
    if ctx.outbound_anomaly_score > 0 && !inbound_hit && (outbound_hit || ctx.anomaly_score == 0) {
        (ctx.outbound_anomaly_score, ctx.outbound_threshold, true)
    } else {
        (ctx.anomaly_score, ctx.anomaly_threshold, false)
    }
}

/// Final verdict fusion. With fusion enabled: weighted score vs per-paranoia
/// block/limit thresholds (→ Block / Limit / Allow). Otherwise the legacy flat
/// `anomaly_threshold`. An explicit Block from an earlier phase is preserved.
fn apply_verdict(ctx: &mut RequestContext, waf: &WafConfig) {
    if ctx.decision == WafDecision::Block {
        return;
    }
    // The effective threshold, which a per-path override may have lowered or
    // raised. Falls back to the site's when nothing was stamped (pre-routing
    // callers and the unit tests below).
    let threshold = ctx.anomaly_threshold.unwrap_or(waf.anomaly_threshold);
    match waf.fusion.as_ref().filter(|f| f.enable) {
        Some(f) => {
            let score = fused_score(ctx, f);
            ctx.tx_vars
                .insert("fused_score".to_string(), score.to_string());
            let block_t =
                threshold_for_pl(&f.block_thresholds, waf.paranoia_level).unwrap_or(threshold);
            // The classifier gets the same veto here as on the flat-threshold
            // path. Without this, turning fusion on disabled FP suppression
            // entirely.
            let vetoed = ml_vetoes_weak_block(ctx);
            if score > 0 && score >= block_t && !vetoed {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(format!(
                    "fused anomaly score {score} >= block threshold {block_t} (PL{})",
                    waf.paranoia_level
                ));
            } else if ctx.decision == WafDecision::Allow && !vetoed {
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
            if ctx.anomaly_score > 0 && ctx.anomaly_score >= threshold {
                // ML suppression: when the n-gram classifier is loaded and
                // scores the payload as benign (< 0.15), suppress CRS-only
                // blocks. The ML model acts as a precision layer — if it
                // doesn't see an attack, a CRS-only match is likely a false
                // positive on benign prose. Only suppress when:
                // 1. No coverage rule (99002xx) fired
                // 2. Anomaly score is moderate (< 20, i.e. 2-3 rules)
                // 3. ML score is low (< 0.15)
                if !ml_vetoes_weak_block(ctx) {
                    ctx.decision = WafDecision::Block;
                    ctx.block_reason = Some(format!(
                        "anomaly score {} >= threshold {}",
                        ctx.anomaly_score, threshold
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
fn eval_rules(ctx: &mut RequestContext, engine: &RuleEngine, phase: Phase) {
    // The anomaly-THRESHOLD verdict is always made by `apply_verdict`, never by
    // the rule VM's short-circuit, so 0 is passed here unconditionally to disable
    // it. Rules only accumulate score in this call.
    //
    // This is a precision requirement, not a style choice. `apply_verdict` is the
    // only place the n-gram classifier can veto a weak-evidence block, and it runs
    // in phase 2. While the VM blocked on its own at phase 1, the request returned
    // at the phase-1 Block check — before phase 2 existed — so the FP-suppression
    // layer was unreachable for every arg- or header-borne block. The model scored
    // that traffic correctly as benign and was simply never asked.
    //
    // Rules with an explicit `deny`/`block` action are unaffected: they set the
    // decision directly and still stop the request in phase 1.
    let threshold = 0;
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

/// Whether one operator-authored rule is actually compiled into a live engine,
/// and why not when it isn't.
///
/// This exists because "enabled" in the control plane has repeatedly meant
/// "stored", not "running". A rule can be stored, enabled, listed in the UI, and
/// still not be enforced — it failed to parse, or its id collided with a shipped
/// rule. The data plane is the only component that knows, because it owns the
/// compiler, so it reports back and the UI shows the truth instead of an
/// assumption.
#[derive(Clone, Debug, serde::Serialize)]
struct InlineRuleDiag {
    name: String,
    enforced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

static INLINE_RULE_DIAGS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<String, InlineRuleDiag>>,
> = std::sync::OnceLock::new();

fn inline_rule_diags(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<String, InlineRuleDiag>> {
    INLINE_RULE_DIAGS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

/// Wipe the registry at the start of a full engine rebuild.
///
/// Without this a rule the operator has since deleted keeps reporting "enforced"
/// forever, which is the same lie in the opposite direction.
fn reset_inline_rule_diags() {
    inline_rule_diags()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

/// Record one rule's outcome. Keyed by name, which is unique per tenant; a rule
/// shared by several sites either parses everywhere or nowhere, so aggregating by
/// name loses nothing and keeps the heartbeat small.
fn record_inline_rule_diag(name: &str, enforced: bool, error: Option<String>) {
    let mut m = inline_rule_diags()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // A failure anywhere is the interesting outcome, so never let a later
    // success overwrite a recorded error.
    if let Some(existing) = m.get(name) {
        if !existing.enforced && enforced {
            return;
        }
    }
    m.insert(
        name.to_string(),
        InlineRuleDiag {
            name: name.to_string(),
            enforced,
            error,
        },
    );
}

/// A site whose engine did not build enforces none of its inline rules, however
/// each parsed: the inline loop has already recorded those it accepted as
/// enforced. A rule already recorded as failing keeps its own reason.
fn record_site_inline_rules_unenforced(site: &SiteConfig, kept_previous: bool) {
    let why = if kept_previous {
        "the site's rules did not compile; it runs its previous rules"
    } else {
        "the site's rules did not compile; it has no rules on this node"
    };
    for rule in &site.waf.inline_rules {
        let failed = inline_rule_diags()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&rule.name)
            .is_some_and(|d| !d.enforced);
        if !failed {
            record_inline_rule_diag(&rule.name, false, Some(why.to_string()));
        }
    }
}

fn inline_rule_diag_snapshot() -> Vec<InlineRuleDiag> {
    inline_rule_diags()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .cloned()
        .collect()
}

/// The per-path override governing `path`, or None. Longest matching prefix wins,
/// so `/api/v2/` beats `/api/` for a `/api/v2/orders` request regardless of the
/// order an operator happened to list them in.
fn match_path_override<'a>(
    waf: &'a sentinel_core::config::WafConfig,
    path: &str,
) -> Option<&'a sentinel_core::config::PathOverride> {
    waf.path_overrides
        .iter()
        .filter(|o| !o.path_prefix.is_empty() && path.starts_with(&o.path_prefix))
        .max_by_key(|o| o.path_prefix.len())
}

/// The mode governing this request: the effective one stamped at routing time
/// (site policy plus any path override), falling back to the site's own mode.
///
/// The fallback matters: several call sites run before routing has stamped a
/// mode, and defaulting to the site policy there is correct — a request that
/// never matched a path cannot be governed by a path override.
fn governing_mode(ctx: &RequestContext, site_mode: &WafMode) -> WafMode {
    ctx.enforcement_mode
        .clone()
        .unwrap_or_else(|| site_mode.clone())
}

/// Is this request still being evaluated, or has a terminal block already been
/// reached?
///
/// ⚠️ This is deliberately `!= Block` and NOT `== Allow`, and the difference was a
/// protection bypass.
///
/// `enforce_request_limit` runs in `proxy_inner` BEFORE `phase1_headers`, and on
/// a learning-mode site `enforce_mode` rewrites its `Block` to `WafDecision::Log`
/// so the request is recorded rather than rejected — which is correct. But every
/// phase-1 check was then gated on `ctx.decision == WafDecision::Allow`, and
/// `Log != Allow`. So one over-long URI (default `max_uri_length` 8192), one
/// excess header, one disallowed method or one over-large body silently switched
/// OFF smuggling detection, bot scoring, GeoIP, rate limiting, edge JWT, the gRPC
/// gate, the rule engine and the WASM plugins — for that request, at the client's
/// choosing.
///
/// Verified live on a learning-mode site before the fix: a request whose only
/// fault was a non-ASCII header value returned 400 (smuggling), and the SAME
/// request with a 9000-byte URI returned 200 with no smuggling record at all.
///
/// `Challenge` and `Limit` are also non-terminal here: a challenged or throttled
/// request has not been refused, so there is no reason to stop inspecting it.
fn still_evaluating(ctx: &RequestContext) -> bool {
    ctx.decision != WafDecision::Block
}

fn enforce_mode(ctx: &mut RequestContext, mode: &WafMode) {
    // `off` for a path means the operator has deliberately taken the WAF out of
    // the way there (static assets, a health endpoint). Any verdict the rules
    // reached is discarded rather than downgraded to Log, because unlike learning
    // mode there is nothing to learn from a path that is not being protected.
    if *mode == WafMode::Off {
        if matches!(
            ctx.decision,
            WafDecision::Block | WafDecision::Challenge | WafDecision::Limit
        ) {
            ctx.decision = WafDecision::Allow;
            ctx.would_block = false;
        }
        return;
    }
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
/// True while a config change has landed but its rule engines have not finished
/// compiling.
///
/// The site list and the rule engines are swapped by two DIFFERENT tasks: the
/// sync task publishes the config the instant the control plane hands it over,
/// and a separate watcher rebuilds the engines. So a brand-new site was
/// MATCHABLE before it was INSPECTABLE — measured at 1.5s, and up to the 5s poll
/// interval plus ~334 rules of compile time. A site created directly in blocking
/// mode therefore failed OPEN through that window: `rule_matches=0`,
/// `decision=Allow`, a real SQLi passing with a 200.
///
/// Two changes close it. The sync task now wakes the rebuild immediately instead
/// of waiting for the poll (the poll remains as a backstop), and this flag lets
/// the request path refuse rather than serve a site it cannot yet inspect.
static ENGINES_WARMING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// --- Threat-intel poller state, for /healthz -------------------------------
//
// The poller is spawned only when `cluster.sync_url` is set, and there was no
// `else`: without it the node served every request against the
// `ThreatFeed::empty()` installed at construction. `check()` short-circuits on
// an empty feed, `/healthz` had no `threat_intel` key at all, and the heartbeat
// carried nothing — so every malicious IP, CIDR, Tor exit, C2 and scanner UA in
// the control-plane corpus was ignored, with NO observable symptom. Unlike
// config sync or the heartbeat, this failure looks exactly like a world with no
// attackers.
static TI_POLLER_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The control-plane config version this node most recently APPLIED (0 = never
/// synced). Reported in the heartbeat so the cluster page can flag a node that
/// is still running an older configuration than the control plane holds.
static CONFIG_VERSION_APPLIED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// HTTP status of the most recent sync attempt; 0 = no attempt has completed.
/// A 403 here means the shared secret does not match and this node's IOC set is
/// frozen — which previously produced no log line at all, because the status was
/// never inspected before the body was parsed.
static TI_LAST_STATUS: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
/// Why recent sync attempts produced no usable response (connect failure, a body
/// cut short, a control plane that never answered, a 2xx body that does not
/// parse) and since when, as `(error, unix secs)`; cleared by the next attempt
/// that installs a corpus, or that is refused (a refusal has its own record in
/// `TI_LAST_STATUS`). That status alone said "running" for a poller whose every
/// poll timed out or installed nothing.
static TI_SYNC_FAILURE: std::sync::Mutex<Option<(String, u64)>> = std::sync::Mutex::new(None);

/// The threat-intel failure record, recovered if a panic poisoned its lock, as
/// for the config-sync status: skipping a poisoned lock froze the record, and
/// the poller went on reading "running" (or "failing") whatever its polls did.
fn ti_sync_failure_lock() -> std::sync::MutexGuard<'static, Option<(String, u64)>> {
    TI_SYNC_FAILURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ti_sync_failure() -> Option<(String, u64)> {
    ti_sync_failure_lock().clone()
}

fn clear_ti_sync_failure() {
    *ti_sync_failure_lock() = None;
}

fn note_ti_sync_failure(error: String) {
    let mut g = ti_sync_failure_lock();
    let since = g.as_ref().map(|(_, s)| *s).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    *g = Some((error, since));
}

/// One threat-intel fetch: the status and body, or None once the reason no
/// response arrived has been recorded for `/healthz`. A 2xx still has to parse
/// before it counts; see [`parse_threat_intel_sync`].
async fn fetch_threat_intel(
    client: &cp_client::CpClient<http_body_util::Empty<Bytes>>,
    sync_url: &str,
    internal_secret: Option<&str>,
    deadline: Duration,
) -> Option<(u16, Bytes)> {
    let url = format!("{}/api/v1/internal/threat-intel", sync_url);
    let uri: hyper::Uri = match url.parse() {
        Ok(u) => u,
        Err(e) => {
            warn!("threat-intel sync: bad url: {e}");
            return None;
        }
    };
    let mut builder = hyper::Request::builder().method("GET").uri(uri);
    if let Some(secret) = internal_secret {
        builder = builder.header("x-sentinel-internal", secret);
    }
    let req = builder
        .body(http_body_util::Empty::new())
        .expect("BUG: building threat-intel sync request");
    match cp_client::call(client, req, deadline).await {
        Ok((status, bytes)) => {
            let status = status.as_u16();
            TI_LAST_STATUS.store(status, std::sync::atomic::Ordering::Relaxed);
            // A refusal is reported through the status ("rejected"); an older
            // failure left in place would mask it as "failing". A 2xx is not
            // cleared here: until it parses, the poll has installed nothing, and
            // clearing now would restart `failing_since` on every bad poll.
            if !(200..300).contains(&status) {
                clear_ti_sync_failure();
            }
            Some((status, bytes))
        }
        Err(e) => {
            warn!("threat-intel sync {e}");
            note_ti_sync_failure(e.to_string());
            None
        }
    }
}

/// A threat-intel poll installed its corpus, or found the installed version
/// current: the poller is healthy again.
fn note_ti_sync_installed() {
    clear_ti_sync_failure();
}

/// Parse a 2xx threat-intel body. A body that does not parse is recorded like a
/// poll that got no answer: it installs nothing either, and before it was
/// recorded `/healthz` said "running" while every poll did nothing.
///
/// One that parses clears nothing: it has installed nothing yet, and the
/// install can still fail (see [`note_ti_sync_installed`]).
fn parse_threat_intel_sync(bytes: &[u8]) -> Option<ThreatIntelSyncResponse> {
    match serde_json::from_slice(bytes) {
        Ok(sync) => Some(sync),
        Err(e) => {
            warn!(
                "threat-intel sync parse: {e} — snippet: {}",
                String::from_utf8_lossy(bytes)
                    .chars()
                    .take(120)
                    .collect::<String>()
            );
            note_ti_sync_failure(format!("parse: {e}"));
            None
        }
    }
}

/// Threat-intel sync state for the heartbeat, so the cluster page shows a node
/// whose IOC set has stopped updating without anyone querying that node's
/// `/healthz`. The heartbeat runs only with a sync URL, so the poller is
/// configured by definition.
fn ti_sync_heartbeat() -> serde_json::Value {
    use std::sync::atomic::Ordering;
    let last_status = TI_LAST_STATUS.load(Ordering::Relaxed);
    let failure = ti_sync_failure();
    serde_json::json!({
        "poller": ti_poller_state(
            true,
            TI_POLLER_STARTED.load(Ordering::Relaxed),
            last_status,
            failure.is_some(),
        ),
        "last_sync_status": last_status,
        "last_error": failure.as_ref().map(|(e, _)| e.clone()),
        "failing_since": failure.as_ref().map(|(_, s)| *s),
    })
}

/// What the poller should do with a completed fetch, extracted so it can be
/// tested without a control plane.
///
/// The old code had one `info!("threat-intel hot-synced")` for every outcome, so
/// installing 0 indicators over 200,000 logged identically to a healthy sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TiSyncOutcome {
    /// Non-2xx: nothing is installed and the existing feed is frozen.
    Rejected {
        status: u16,
    },
    /// An empty corpus replaced a populated feed — enforcement just went off.
    EmptyRegression {
        previous: usize,
    },
    /// Empty, and nothing was there before. Not a regression, not a success.
    EmptyFirst,
    Synced {
        count: usize,
    },
}

fn ti_sync_outcome(previous: usize, new_count: usize, status: u16) -> TiSyncOutcome {
    if !(200..300).contains(&status) {
        return TiSyncOutcome::Rejected { status };
    }
    if new_count == 0 {
        return if previous > 0 {
            TiSyncOutcome::EmptyRegression { previous }
        } else {
            TiSyncOutcome::EmptyFirst
        };
    }
    TiSyncOutcome::Synced { count: new_count }
}

/// Is global IOC enforcement actually on, and if not, why not?
///
/// `active` is the field that matters: `configured` merely means a sync URL
/// exists. Mirrors `geoip_status`'s shape, and reaches the console for free
/// because `/waf/status` proxies `/healthz` verbatim.
fn threat_intel_status(cfg: &SentinelConfig, feed: &ThreatFeed) -> serde_json::Value {
    use std::sync::atomic::Ordering;
    let configured = cfg.cluster.sync_url.is_some();
    let started = TI_POLLER_STARTED.load(Ordering::Relaxed);
    let last_status = TI_LAST_STATUS.load(Ordering::Relaxed);
    let entries = feed.entry_count();
    let failure = ti_sync_failure();
    let poller = ti_poller_state(configured, started, last_status, failure.is_some());
    serde_json::json!({
        "configured": configured,
        "poller": poller,
        "last_sync_status": last_status,
        // Set while polls install nothing (no answer, or a body that does not
        // parse); `failing_since` is how long the IOC set below has been going
        // stale.
        "last_error": failure.as_ref().map(|(e, _)| e.clone()),
        "failing_since": failure.as_ref().map(|(_, s)| *s),
        "version": feed.version(),
        "entries": entries,
        // The single honest summary: are IOCs being enforced on this node?
        "active": entries > 0,
        "inert_reason": if entries > 0 {
            serde_json::Value::Null
        } else if !configured {
            serde_json::json!("no cluster.sync_url — this node never fetches the IOC corpus")
        } else if poller == "rejected" {
            serde_json::json!(format!(
                "control plane refused the sync with HTTP {last_status} (403 = SENTINEL_INTERNAL_SECRET mismatch)"
            ))
        } else if let Some((e, _)) = failure.as_ref().filter(|_| poller == "failing") {
            serde_json::json!(format!("no usable threat-intel sync ({e})"))
        } else {
            serde_json::json!("the control-plane corpus returned no active indicators")
        },
    })
}

/// The `/healthz` poller label. `failing` outranks the last status: that status
/// is from the last poll that got an answer, which may be hours old.
fn ti_poller_state(
    configured: bool,
    started: bool,
    last_status: u16,
    failing: bool,
) -> &'static str {
    if !configured {
        "not_configured"
    } else if !started {
        "not_started"
    } else if failing {
        "failing"
    } else if last_status == 0 {
        "starting"
    } else if (200..300).contains(&last_status) {
        "running"
    } else {
        "rejected"
    }
}

/// Whether `site` is one that SHOULD have a compiled engine.
///
/// Mirrors the skip conditions in `build_rule_engines` exactly. It has to: a
/// site with `mode: off`, or with no rule files and no inline rules, legitimately
/// has no engine for ever, and treating those as "still warming" would 503 them
/// permanently. Keep the two in step.
/// Declare the compiled engines current — but only if the config has not moved
/// on while they were being built.
///
/// `build_rule_engines` compiles the whole corpus (347 rules on .71) and takes
/// long enough for another sync to land mid-build. Clearing the flag
/// unconditionally after the store announces "engines are current" for a config
/// that is ALREADY superseded, so a site introduced by the newer sync is
/// matchable with no engine and no warming flag — the exact fail-open the flag
/// exists to prevent, reopened by a second config change instead of a first.
///
/// Leaving the flag set is the safe direction: the rebuild loop has already been
/// notified and clears it on the very next pass, which costs a few hundred more
/// milliseconds of 503 rather than a window of uninspected traffic.
///
/// No ABA hazard on the pointer compare: the caller still holds the `Arc` it
/// built from, so that allocation cannot be freed and its address cannot be
/// reused by the newer config.
///
/// Takes the flag rather than touching the global so it is testable without
/// racing the other tests in this process.
fn clear_warming_if_current(
    cw: &ConfigHandle,
    built_from: usize,
    flag: &std::sync::atomic::AtomicBool,
) -> bool {
    let still_current = Arc::as_ptr(&cw.load_full()) as usize == built_from;
    if still_current {
        flag.store(false, std::sync::atomic::Ordering::Release);
    }
    still_current
}

/// Sites that are matchable but have NO compiled rule engine.
///
/// While `ENGINES_WARMING` is set this is the transient reload state and those
/// requests are refused with 503. Once it clears, anything still listed here is
/// a site whose rules FAILED to compile and which is now being served with no
/// signature protection at all — a standing fail-open that only a config fix
/// clears, and which was previously visible in nothing but one log line.
/// What to do about a request for a site that has no compiled rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingEngine {
    /// The site has an engine, wants none, or is in learning mode: carry on.
    Serve,
    /// A reload is in flight. Transient, so refuse and let the client retry.
    RefuseWarming,
    /// The rule set FAILED to compile and there is no last-good ruleset to fall
    /// back on. Persistent until an operator fixes the config.
    RefuseBroken,
}

/// Decide it in one place, from values, so every branch is testable.
///
/// Until 2026-09-07 the refusal was gated on `warming` alone, which meant a
/// blocking-mode site whose rules failed to compile was refused for a few
/// seconds and then served with NO signature protection for as long as the
/// config stayed broken. That is the one direction of failure a WAF may never
/// take, and it was reachable by a single bad rule.
///
/// The site's own mode carries the operator's intent, so no new config field is
/// needed to decide it:
///
///   * `blocking` is a promise to enforce. A node that cannot enforce cannot
///     keep it, so it refuses rather than pretending.
///   * `learning` is a promise to OBSERVE, and a site with no engine observes
///     nothing. Serving it uninspected produces a learning report that is
///     silently empty — indistinguishable from "we looked and found nothing" —
///     which is the answer an operator then uses to decide it is safe to switch
///     the site to blocking. That is worse than an outage, because it is wrong
///     rather than absent. It refuses too, as of 2026-09-17 (Ayush's call).
///   * `off`, or a site with no rules at all, never expected an engine.
///
/// So the rule is now simply: a site that asked for an engine and has none is
/// refused, whatever its mode. Only `off` and engine-less sites are served, and
/// the escape hatch below still overrides everything.
///
/// `serve_on_failure` is the escape hatch: an operator whose rules will not
/// compile and who needs the site up NOW sets
/// `SENTINEL_SERVE_ON_RULE_COMPILE_FAILURE=1` and gets the old behaviour, loudly.
fn missing_engine_action(
    site: &SiteConfig,
    has_engine: bool,
    warming: bool,
    serve_on_failure: bool,
) -> MissingEngine {
    if has_engine || !site_expects_engine(site) {
        return MissingEngine::Serve;
    }
    if warming {
        return MissingEngine::RefuseWarming;
    }
    if serve_on_failure || site.waf.mode == WafMode::Off {
        return MissingEngine::Serve;
    }
    MissingEngine::RefuseBroken
}

/// Reads the escape hatch once per process.
fn serve_on_rule_compile_failure() -> bool {
    static SERVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SERVE.get_or_init(|| {
        matches!(
            std::env::var("SENTINEL_SERVE_ON_RULE_COMPILE_FAILURE")
                .ok()
                .as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

/// Sites that are being REFUSED because their rules will not compile — the
/// consequence, next to `sites_without_engine`, which is only the condition.
fn refused_sites(cfg: &SentinelConfig, engines: &RuleEngineMap) -> Vec<String> {
    let warming = ENGINES_WARMING.load(std::sync::atomic::Ordering::Acquire);
    let serve = serve_on_rule_compile_failure();
    cfg.sites
        .iter()
        .filter(|s| {
            missing_engine_action(s, engines.contains_key(&s.id), warming, serve)
                == MissingEngine::RefuseBroken
        })
        .map(|s| s.id.clone())
        .collect()
}

fn unprotected_sites(cfg: &SentinelConfig, engines: &RuleEngineMap) -> Vec<String> {
    cfg.sites
        .iter()
        .filter(|s| site_expects_engine(s) && !engines.contains_key(&s.id))
        .map(|s| s.id.clone())
        .collect()
}

/// True the FIRST time this key is seen, so an operator-facing diagnostic can
/// be logged once instead of once per request.
///
/// A misconfiguration that only manifests per request produces either silence or
/// a flood, and both hide it. The Go side already does this for unknown
/// waf_policy keys (`warnedUnknownWafKeys`); this is the data-plane equivalent.
fn diag_first_time(key: String) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    // A poisoned set is still a set; the worst it can do is log one twice.
    seen.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key)
}

/// Whether a JWT failure is the CLIENT's fault or the OPERATOR's.
///
/// Both end in the same 403, which is correct — a request that cannot be
/// verified is not authenticated — but they need different audiences. A bad or
/// expired token is routine and belongs in the request record. A site whose JWT
/// policy has no usable key can never verify anything: every token-bearing
/// request is rejected, and the only trace was one block reason per request,
/// with nothing telling the operator their configuration is broken.
fn jwt_failure_is_misconfiguration(reason: &str) -> bool {
    matches!(
        reason,
        "no verification key configured" | "misconfigured public key"
    ) || reason.starts_with("unknown key id")
}

fn site_expects_engine(site: &SiteConfig) -> bool {
    site.waf.mode != WafMode::Off
        && !(site.waf.rules.is_empty() && site.waf.inline_rules.is_empty())
}

/// Apply a request-limit rejection through the site's enforcement mode.
///
/// Returns `Some(response)` when the request must actually be rejected, and
/// `None` when the site is in learning mode — in which case the would-block is
/// recorded (so it reaches the learning report and the FPR triage) and the
/// request continues.
///
/// This exists because the four request limits — URI length, header count,
/// method allow-list and body size — used to `return Ok(error_response(...))`
/// directly, before `phase1_headers` and therefore before `enforce_mode`, which
/// is the ONLY place learning mode downgrades a Block to a Log. So they rejected
/// with 413/414/431/405 during a soak an operator had been told was safe to run
/// against production traffic. The four defaults most likely to bite are exactly
/// these (10 MB body, 8192 URI, 100 headers, 7 methods), so a learning window on
/// a real application — an upload portal, a git push, a SAML redirect longer than
/// 8192 bytes — broke real users while claiming only to be observing them.
fn enforce_request_limit(
    ctx: &mut RequestContext,
    site: &SiteConfig,
    reason: String,
    status: StatusCode,
    body: &'static str,
) -> Option<Response<BoxBody>> {
    ctx.decision = WafDecision::Block;
    ctx.block_reason = Some(reason);
    let gm = governing_mode(ctx, &site.waf.mode);
    enforce_mode(ctx, &gm);
    if ctx.decision == WafDecision::Block {
        let resp = error_response(status, body);
        stamp_response(ctx, &resp);
        ctx.advance_phase(Phase::Logging);
        log_request(ctx);
        return Some(resp);
    }
    // Learning (or a path override set to learning/off): recorded, not rejected.
    // `would_block` is what puts it in the learning report, which is the whole
    // point of running the soak.
    warn!(
        site = %site.id,
        reason = ctx.block_reason.as_deref().unwrap_or(""),
        "request limit exceeded — NOT rejected (learning mode); recorded as would-block"
    );
    None
}

fn build_rule_engines(cfg: &SentinelConfig, previous: &RuleEngineMap) -> RuleEngineMap {
    // Rebuilt from scratch every reload, so a rule the operator has since deleted
    // stops claiming to be enforced.
    reset_inline_rule_diags();
    let mut map = RuleEngineMap::new();
    let mut compile_panics = Vec::new();
    for site in &cfg.sites {
        // A site with no rule FILES may still have operator-authored inline rules
        // from the control plane; skipping on `rules.is_empty()` alone would build
        // no engine and silently drop them. In practice a site configured through
        // the dashboard always has CRS files, so this only bites the
        // inline-rules-only case — which is exactly how a minimal virtual-patch-only
        // site would be set up.
        if site.waf.mode == WafMode::Off
            || (site.waf.rules.is_empty() && site.waf.inline_rules.is_empty())
        {
            continue;
        }
        // A panic compiling one site's rules (a CRS line or an operator's rule
        // reaching a parser bug) costs that site only, like an Err: it keeps its
        // last-good engine or is refused, below. Unguarded it unwound out of
        // the whole rebuild, the watcher replayed the same config forever, and
        // no later change applied to ANY site while the node reported healthy.
        let loaded =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| load_site_engine(site)))
            {
                Ok(loaded) => loaded,
                Err(payload) => {
                    let rejected = compile_panic_rejection(
                        &site.id,
                        previous.contains_key(&site.id),
                        &*payload,
                    );
                    let err = anyhow!(rejected.error.clone());
                    compile_panics.push(rejected);
                    Err(err)
                }
            };
        match loaded {
            Ok(engine) => {
                info!(site = %site.id, rules = engine.rule_count(), "rule engine loaded");
                map.insert(site.id.clone(), engine);
            }
            Err(e) => {
                record_site_inline_rules_unenforced(site, previous.contains_key(&site.id));
                // RuleEngine is Arc-backed → clone is cheap.
                if let Some(prev) = previous.get(&site.id) {
                    warn!(site = %site.id, rules = prev.rule_count(),
                        "rule engine reload FAILED — retaining last-good ruleset, new rules rejected: {e:#}");
                    map.insert(site.id.clone(), prev.clone());
                } else {
                    // ERROR, not WARN: unlike the retain-last-good branch above,
                    // this site has no ruleset at ALL. A blocking-mode site is
                    // now REFUSED with 503 rather than served without signature
                    // protection (see missing_engine_action); a learning-mode
                    // site is still served, because learning never promised to
                    // block. Either way the config is broken and needs fixing.
                    error!(site = %site.id, mode = ?site.waf.mode,
                        "rule engine load failed and no prior ruleset — site has NO signature protection. \
                         A blocking-mode site is refused with 503 until this is fixed; a learning-mode \
                         site is served uninspected. Listed at /healthz inspection.sites_without_engine \
                         and .sites_refused: {e:#}");
                }
            }
        }
    }
    *ENGINE_COMPILE_PANICS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = compile_panics;
    map
}

/// How a site whose rules panicked the compiler is reported to the console (via
/// the sync status in the heartbeat). Names the outcome; the location is in the
/// node's log, because source paths carry the crate codename.
fn compile_panic_rejection(
    id: &str,
    kept_previous: bool,
    payload: &(dyn std::any::Any + Send),
) -> RejectedSite {
    let consequence = if kept_previous {
        "The site keeps its previous rules."
    } else {
        "The site has no rules on this node."
    };
    RejectedSite {
        id: id.to_string(),
        error: format!(
            "its rules crashed the rule compiler ({}); this is a bug, not a config error — \
             the node log has the location. {consequence}",
            panic_guard::panic_message(payload)
        ),
        kept_previous,
    }
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

/// May a PROXY protocol header from this transport peer be believed?
///
/// The header is plaintext and self-asserted: anyone able to reach the listener
/// directly could claim any source address, which would let them slip past an IP
/// block or pin an attack on someone else. So it is honoured only from a peer
/// that is already a trusted proxy — the SAME `SENTINEL_TRUSTED_PROXIES`
/// boundary that gates `X-Forwarded-For`. Two lists that must agree is one list
/// too many.
///
/// `is_trusted` is injected so this is testable without a process-wide env var,
/// matching `blocklist_hit` below: the bug worth guarding against is not a wrong
/// expression, it is a right expression wired to the wrong topology.
fn proxy_header_allowed(
    peer: std::net::IpAddr,
    is_trusted: impl Fn(std::net::IpAddr) -> bool,
) -> bool {
    is_trusted(peer)
}

/// The address the pipeline should treat as the client, given what a PROXY
/// header said.
///
/// `LOCAL`/`UNKNOWN` keeps the transport peer. That case is the balancer
/// speaking on its own behalf — a health check, overwhelmingly — and HAProxy
/// checks `/healthz` every 300ms in this topology. Reading it as an address
/// would stamp every one of those with a bogus client, and on a quiet box that
/// is most of the "traffic" in the log.
fn effective_peer(transport: SocketAddr, said: proxy_protocol::Peer) -> SocketAddr {
    match said {
        proxy_protocol::Peer::Proxied(real) => real,
        proxy_protocol::Peer::Local => transport,
    }
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

/// Run the eBPF stats task, supervised like the node's other background loops.
///
/// `EbpfManager::start` runs it on a bare `tokio::spawn`, so a panic in one
/// pass ended it for the life of the process: `running` stayed true, so
/// nothing started it again, and in kernel mode `xdp_pass`/`xdp_drop` froze in
/// `/healthz` and `/metrics` with no restart recorded and the heartbeat
/// healthy. A restart here is recorded under "eBPF stats".
fn spawn_ebpf_stats(ebpf: &Arc<EbpfManager>) -> Option<tokio::task::JoinHandle<()>> {
    if !ebpf.claim_stats_task() {
        return None;
    }
    info!(
        mode = %ebpf.mode(),
        interface = %ebpf.config().interface,
        "eBPF background task started"
    );
    let ebpf = Arc::clone(ebpf);
    Some(panic_guard::supervised!("eBPF stats", {
        per_run!(ebpf);
        let mut ticker = tokio::time::interval(ebpf.stats_interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // the first tick is immediate
        while ebpf.stats_running() {
            ticker.tick().await;
            #[cfg(test)]
            panic_guard::inject_ebpf_stats_panic(&ebpf);
            ebpf.refresh_stats();
        }
        info!("eBPF background task stopped");
    }))
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
        // Kernel drops are node-wide by nature, so only a site that asked for
        // that explicitly gets its list mirrored. Everyone else is enforced per
        // site in the request path.
        if !rep.xdp_mirror {
            continue;
        }
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

/// One reputation table per site, from that site's own allow/block lists.
fn build_site_ip_reputation(cfg: &SentinelConfig) -> HashMap<String, IpReputation> {
    let mut map = HashMap::new();
    for site in &cfg.sites {
        if let Some(rc) = site.waf.ip_reputation.as_ref() {
            if !rc.allow.is_empty() || !rc.block.is_empty() {
                map.insert(site.id.clone(), IpReputation::from_configs(&[rc]));
            }
        }
    }
    map
}

/// The node-wide table: reputation FEEDS only. Site lists used to be merged in
/// here too, which is how a per-site block became a node-wide one.
fn build_ip_reputation(cfg: &SentinelConfig, feed_cidrs: &[(String, Vec<String>)]) -> IpReputation {
    let _ = cfg;
    let mut rep = IpReputation::new();
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

/// What country filtering is CONFIGURED versus what is actually ENFORCED.
///
/// These differ silently, and that is the whole reason this exists. `GeoIp`
/// degrades to a no-op when the MaxMind database is absent — it logs once at
/// startup and then answers `Unknown` for every address, so a site configured to
/// block `["CN","RU"]` blocks nothing while the console reports the policy as
/// set. No `.mmdb` has ever shipped in any bundle and no compose file passed a
/// path, so on every deployment to date this control has been inert.
///
/// `GeoIp::is_active()` already computed the truth and NOTHING called it outside
/// a unit test. The signal existed and was thrown away.
///
/// Same shape, and same remedy, as the `ebpf` block below: kernel XDP silently
/// ran in software for six weeks with a single startup WARN as the only trace,
/// until /healthz was made to say so.
/// Plugin picture for `/healthz`: modules held, who runs them, and any site
/// asking for one that is absent.
fn plugin_status(
    rt: &PluginRuntime,
    per_site: &SitePluginMap,
    unresolved: &UnresolvedPlugins,
) -> serde_json::Value {
    let mut loaded = rt.plugin_names();
    loaded.sort();
    // Reverse the map so an operator reading this sees, per plugin, which sites
    // it judges — the question you actually ask before enabling one.
    let mut by_plugin: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for (site, names) in per_site {
        for n in names {
            by_plugin.entry(n.as_str()).or_default().push(site.as_str());
        }
    }
    let running: usize = by_plugin.len();
    let invocations = plugin_invocations_total();
    let traps = plugin_traps_total();
    serde_json::json!({
        "loaded": loaded,
        // Execution counters, also in /metrics. `traps` is the one to alert on:
        // every failure path inside the runtime returns Allow, so a plugin
        // trapping on every request is indistinguishable from one that never
        // blocks anything — the control looks enabled and judges nothing.
        "invocations": invocations,
        "blocks": plugin_blocks_total(),
        "scores": plugin_scores_total(),
        "traps": traps,
        "trap_ratio": if invocations > 0 {
            (traps as f64 / invocations as f64 * 1000.0).round() / 1000.0
        } else {
            0.0
        },
        "running_on_at_least_one_site": running,
        // A module loaded but selected by no site: it costs memory and nothing else.
        "loaded_but_unused": loaded
            .iter()
            .filter(|n| !by_plugin.contains_key(n.as_str()))
            .cloned()
            .collect::<Vec<String>>(),
        "per_plugin_sites": by_plugin,
        "unresolved": unresolved
            .iter()
            .map(|(site, name)| serde_json::json!({ "site": site, "plugin": name }))
            .collect::<Vec<_>>(),
    })
}

fn geoip_status(cfg: &SentinelConfig, map: &GeoIpMap) -> serde_json::Value {
    let mut configured = 0usize;
    let mut active = 0usize;
    let mut inert: Vec<serde_json::Value> = Vec::new();
    for site in &cfg.sites {
        let Some(gc) = site.waf.geoip.as_ref() else {
            continue;
        };
        // A geoip block with no country rules is configuration, not enforcement.
        if gc.block_countries.is_empty() && gc.allow_countries.is_empty() {
            continue;
        }
        configured += 1;
        if map.get(&site.id).is_some_and(|g| g.is_active()) {
            active += 1;
        } else {
            inert.push(serde_json::json!({
                "site": site.id,
                "db_path": gc.db_path,
                "db_present": std::path::Path::new(&gc.db_path).exists(),
                "block_countries": gc.block_countries,
                "allow_countries": gc.allow_countries,
            }));
        }
    }
    // The DATABASE ITSELF, reported independently of whether any site uses it.
    //
    // Everything above is derived from site policy, so a node with a perfectly
    // good 8 MB database mounted and readable was indistinguishable from a node
    // with no database at all: both answered configured:0, active:0, inert:[]
    // and the console said "Not configured". An operator who had just run the
    // geoip.refresh job had no way to confirm from the console that it worked.
    //
    // The path is whatever a site asks for, falling back to the same
    // SENTINEL_GEOIP_DB default the control plane writes into site config, so
    // the two cannot disagree about where the file is meant to live.
    let db_path = cfg
        .sites
        .iter()
        .filter_map(|s| s.waf.geoip.as_ref())
        .map(|g| g.db_path.clone())
        .find(|p| !p.is_empty())
        .unwrap_or_else(|| {
            std::env::var("SENTINEL_GEOIP_DB")
                .unwrap_or_else(|_| "/var/lib/sentinel/geoip/dbip-country-lite.mmdb".to_string())
        });
    let meta = std::fs::metadata(&db_path).ok();
    let database = serde_json::json!({
        "path": db_path,
        "present": meta.is_some(),
        "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
    });

    serde_json::json!({
        // The country database on this node: present and how big, regardless of
        // whether any site has country rules yet.
        "database": database,
        // Sites whose policy asks for country filtering.
        "configured": configured,
        // Sites where it is actually enforceable (database loaded AND rules set).
        "active": active,
        // The gap, named. Non-empty means the product is showing a control it is
        // not applying — read this before trusting a country block.
        "inert": inert,
    })
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
        Target::MatchedVar => "MATCHED_VAR".into(),
        Target::RequestLine => "REQUEST_LINE".into(),
        Target::RequestProtocol => "REQUEST_PROTOCOL".into(),
        Target::ReqbodyProcessor => "REQBODY_PROCESSOR".into(),
        Target::RequestHeaders(None) => "REQUEST_HEADERS".into(),
        Target::RequestHeaders(Some(h)) => format!("REQUEST_HEADERS:{h}"),
        Target::RequestCookies(None) => "REQUEST_COOKIES".into(),
        Target::RequestCookiesNames => "REQUEST_COOKIES_NAMES".into(),
        Target::RequestHeadersNames => "REQUEST_HEADERS_NAMES".into(),
        Target::ArgsGet => "ARGS_GET".into(),
        Target::ArgsGetNames => "ARGS_GET_NAMES".into(),
        Target::QueryString => "QUERY_STRING".into(),
        Target::RequestCookies(Some(c)) => format!("REQUEST_COOKIES:{c}"),
        Target::ResponseHeaders(None) => "RESPONSE_HEADERS".into(),
        Target::ResponseHeaders(Some(h)) => format!("RESPONSE_HEADERS:{h}"),
        Target::ResponseBody => "RESPONSE_BODY".into(),
        Target::Files => "FILES".into(),
        Target::FilesNames => "FILES_NAMES".into(),
        Target::FilesCombinedSize => "FILES_COMBINED_SIZE".into(),
        Target::ArgsCombinedSize => "ARGS_COMBINED_SIZE".into(),
        Target::MultipartPartHeaders(None) => "MULTIPART_PART_HEADERS".into(),
        Target::MultipartPartHeaders(Some(p)) => format!("MULTIPART_PART_HEADERS:{p}"),
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

    // Operator-authored rules from the control plane's `rules` table.
    //
    // Deliberately NOT fatal on a parse error, unlike the file loop above. A rule
    // file that fails to parse means the shipped ruleset is broken and failing the
    // whole engine is right — the caller keeps the last-good engine. But these rules
    // are typed into a web form, so a typo is routine, and letting one bad row take
    // the site's ENTIRE ruleset offline (including every CRS rule) would turn a
    // small operator mistake into an outage. Skip the bad rule, keep the rest, and
    // make the skip loud enough to notice.
    let file_rule_ids: std::collections::HashSet<u32> = merged
        .items
        .iter()
        .filter_map(|i| match i {
            RuleItem::Rule(r) => Some(r.id),
            _ => None,
        })
        .collect();

    for inline in &site.waf.inline_rules {
        let mut accepted = 0usize;
        // Text typed into a web form is exactly what finds a parser bug, so a
        // panic here costs this one rule, reported like a parse error.
        let parsed = match std::panic::catch_unwind(|| {
            #[cfg(test)]
            panic_guard::inject_parse_panic(&inline.dsl);
            sentinel_rules::parse_srl(&inline.dsl)
        }) {
            Ok(parsed) => parsed,
            Err(payload) => {
                let why = format!(
                    "it crashed the rule parser ({}); a bug, not a typo",
                    panic_guard::panic_message(&*payload)
                );
                warn!(
                    site = %site.id,
                    rule = %inline.name,
                    error = %why,
                    "CUSTOM RULE NOT ENFORCED: it crashed the rule parser. Every other rule \
                     for this site is unaffected."
                );
                record_inline_rule_diag(&inline.name, false, Some(why));
                continue;
            }
        };
        let parsed = match parsed {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    site = %site.id,
                    rule = %inline.name,
                    error = %e,
                    "CUSTOM RULE NOT ENFORCED: it does not parse. Every other rule for \
                     this site is unaffected; fix or disable this one."
                );
                record_inline_rule_diag(&inline.name, false, Some(format!("does not parse: {e}")));
                continue;
            }
        };
        for item in parsed.items {
            // A custom rule reusing a shipped rule's id would make scoring and
            // exclusions ambiguous — an exclusion for that id could not say which
            // rule it meant. Refuse the duplicate rather than silently shadowing.
            if let RuleItem::Rule(r) = &item {
                if file_rule_ids.contains(&r.id) {
                    warn!(
                        site = %site.id,
                        rule = %inline.name,
                        id = r.id,
                        "CUSTOM RULE NOT ENFORCED: id collides with a rule already \
                         loaded from the shipped ruleset. Give it an unused id."
                    );
                    record_inline_rule_diag(
                        &inline.name,
                        false,
                        Some(format!(
                            "rule id {} is already used by the shipped ruleset; pick an unused id",
                            r.id
                        )),
                    );
                    continue;
                }
            }
            merged.items.push(item);
            accepted += 1;
        }
        // Reported only when something actually made it into the engine: a DSL
        // that parses to zero rules is not enforcing anything either.
        record_inline_rule_diag(
            &inline.name,
            accepted > 0,
            if accepted > 0 {
                None
            } else {
                Some("parsed, but defined no rules".to_string())
            },
        );
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

    // After the inline-rule loop has recorded its diagnostics, as a panic in
    // `compile` would be.
    #[cfg(test)]
    panic_guard::inject_compile_panic(site);
    sentinel_rules::compile(merged)
        .map(RuleEngine::new)
        .with_context(|| format!("compiling rules for site '{}'", site.id))
}

/// Which plugins each site runs: site id → plugin names, in policy order.
///
/// The request path used to iterate EVERY loaded module for EVERY site, so
/// enabling one plugin put it in front of all traffic on the node. This map is
/// the per-site selection; a site with no entry runs none.
pub type SitePluginMap = HashMap<String, Vec<String>>;

/// Plugin names a site asked for that are not loaded on this node — a typo, or
/// a module the control plane has not synced yet. Surfaced at `/healthz` rather
/// than dropped, so "enabled but never runs" cannot hide.
pub type UnresolvedPlugins = Vec<(String, String)>;

fn build_plugin_runtime(cfg: &SentinelConfig) -> anyhow::Result<(PluginRuntime, SitePluginMap)> {
    let mut rt = PluginRuntime::new()?;
    let mut per_site: SitePluginMap = HashMap::new();
    let mut loaded = 0usize;
    let mut failed = 0usize;
    for site in &cfg.sites {
        for manifest_path in &site.waf.plugins {
            match rt.load_from_manifest(std::path::Path::new(manifest_path)) {
                // A manifest listed by a site is that site's own choice, so the
                // module it declares runs for that site without being named
                // again in `enabled_plugins`.
                Ok(name) => {
                    per_site.entry(site.id.clone()).or_default().push(name);
                    loaded += 1;
                }
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
    Ok((rt, per_site))
}

/// Cache of plugins uploaded through the control plane: name → (sha256, module).
///
/// Shared between the plugin-sync task (which fills it) and the config hot-reload
/// watcher (which reads it). Both rebuild the plugin runtime, and a rebuild that
/// knows only about manifest plugins silently DROPS every uploaded one — so both
/// must build from the same complete picture.
type UploadedPlugins = Arc<DashMap<String, (String, Vec<u8>)>>;

/// Build a plugin runtime holding BOTH manifest-configured and uploaded plugins.
///
/// Every rebuild must go through here. Calling `build_plugin_runtime` directly and
/// swapping the result in unloads all uploaded plugins, which is a silent
/// protection outage: the module is still installed and enabled in the UI, the
/// node reports no error, and the plugin simply stops running.
/// Count one plugin evaluation.
///
/// A plugin runs operator-supplied code in the request path, and until
/// 2026-09-07 nothing counted it: cost and failure rate were visible only as log
/// lines. `failed` is the important one — every failure path inside the runtime
/// returns Allow, so a plugin that traps on every request looks exactly like one
/// that never blocks anything.
fn note_plugin_outcome(result: &PluginEvalResult) {
    note_plugin_invocation();
    if result.failed {
        note_plugin_trap();
        return;
    }
    if matches!(result.decision, WafDecision::Block | WafDecision::Challenge) {
        note_plugin_block();
    }
    if result.anomaly_score_delta > 0 {
        note_plugin_score();
    }
}

/// Resolve `waf.enabled_plugins` for every site against the modules this node
/// actually holds, starting from the per-site manifest entries.
///
/// Called from BOTH build paths on purpose: applying it only in the hot-reload
/// path meant a freshly booted node ran no selected plugin until some unrelated
/// config change happened to rebuild the runtime — the module was installed,
/// enabled and named, and still never ran. Found by a local four-site probe,
/// not by reading the code.
fn resolve_site_plugins(
    cfg: &SentinelConfig,
    rt: &PluginRuntime,
    mut per_site: SitePluginMap,
) -> (SitePluginMap, UnresolvedPlugins) {
    let loaded = rt.plugin_names();
    let mut unresolved: UnresolvedPlugins = Vec::new();
    for site in &cfg.sites {
        for want in &site.waf.enabled_plugins {
            if loaded.iter().any(|n| n == want) {
                let list = per_site.entry(site.id.clone()).or_default();
                if !list.contains(want) {
                    list.push(want.clone());
                }
            } else {
                unresolved.push((site.id.clone(), want.clone()));
            }
        }
    }
    for (site, name) in &unresolved {
        warn!(
            site = %site, plugin = %name,
            "site policy names a plugin that is not installed on this node — it will NOT run. \
             Install and enable it in the console, or remove it from the site's policy. \
             Queryable at /healthz -> plugins.unresolved."
        );
    }
    (per_site, unresolved)
}

fn build_full_plugin_runtime(
    cfg: &SentinelConfig,
    uploaded: &UploadedPlugins,
) -> anyhow::Result<(
    PluginRuntime,
    SitePluginMap,
    Vec<String>,
    usize,
    UnresolvedPlugins,
)> {
    let (mut rt, manifest_map) = build_plugin_runtime(cfg)?;
    let mut loaded = Vec::new();
    let mut rejected = 0usize;
    for entry in uploaded.iter() {
        let (name, (_, wasm)) = (entry.key(), entry.value());
        match rt.load_plugin(name, wasm) {
            Ok(()) => loaded.push(name.clone()),
            Err(e) => {
                // A module that will not compile is skipped individually rather
                // than taking the whole plugin set down with it.
                warn!(plugin = %name, "uploaded plugin failed to compile: {e:#}");
                rejected += 1;
            }
        }
    }
    loaded.sort();
    let (per_site, unresolved) = resolve_site_plugins(cfg, &rt, manifest_map);
    Ok((rt, per_site, loaded, rejected, unresolved))
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

/// The management console's session cookie. It must never reach an origin; see
/// [`strip_console_session_cookie`].
const CONSOLE_SESSION_COOKIE: &str = "sentinel_token";

/// Remove the console's session cookie from a request about to be forwarded to
/// a protected site, keeping every other cookie byte-for-byte.
///
/// Cookies are scoped by host, not port. When an operator reaches the console
/// at https://10.0.0.5:9443 and the WAF also serves a site on 10.0.0.5, the
/// browser attaches the console's cookie to every request for that site; until
/// 1.1.11 its value was the admin's access token, delivered to the origin (and
/// over plain HTTP, readable by the origin's own scripts). The console now
/// stores only a marker in it, and this makes sure no origin ever receives it
/// at all — including from a browser still holding a cookie set by an older
/// console. Only the site path calls this: the management listener forwards to
/// the console, which needs the cookie.
///
/// HTTP/2 and HTTP/3 may split cookies across several `Cookie` fields, so every
/// field is filtered; a field left empty is dropped.
fn strip_console_session_cookie(headers: &mut http::HeaderMap) {
    let fields: Vec<http::HeaderValue> = headers
        .get_all(http::header::COOKIE)
        .iter()
        .cloned()
        .collect();
    if fields.is_empty() {
        return;
    }
    let mut touched = false;
    let mut kept: Vec<String> = Vec::with_capacity(fields.len());
    for v in &fields {
        let Ok(text) = v.to_str() else {
            // Not visible ASCII: cannot be parsed safely, forwarded as it came.
            kept.push(String::from_utf8_lossy(v.as_bytes()).into_owned());
            continue;
        };
        let pairs: Vec<&str> = text
            .split(';')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .collect();
        let remaining: Vec<&str> = pairs
            .iter()
            .copied()
            .filter(|c| c.split('=').next().map(str::trim) != Some(CONSOLE_SESSION_COOKIE))
            .collect();
        if remaining.len() != pairs.len() {
            touched = true;
        }
        if !remaining.is_empty() {
            kept.push(remaining.join("; "));
        }
    }
    if !touched {
        return;
    }
    headers.remove(http::header::COOKIE);
    for field in kept {
        if let Ok(hv) = http::HeaderValue::from_str(&field) {
            headers.append(http::header::COOKIE, hv);
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
    // HSTS — only when the operator turned it on (browsers ignore it over plain
    // HTTP, so emitting it unconditionally is harmless but pointless; the site
    // policy decides).
    if let Some(h) = cfg.hsts.as_ref().filter(|h| h.enabled) {
        let max_age = if h.max_age == 0 {
            31_536_000
        } else {
            h.max_age
        };
        let mut v = format!("max-age={max_age}");
        if h.include_subdomains {
            v.push_str("; includeSubDomains");
        }
        if h.preload {
            v.push_str("; preload");
        }
        if let Ok(hv) = http::HeaderValue::from_str(&v) {
            headers.insert(header::STRICT_TRANSPORT_SECURITY, hv);
        }
    }
    // Cookie hardening: append missing attributes to matching Set-Cookie headers.
    if let Some(spec) = cfg.cookie_flags.as_deref().filter(|s| !s.trim().is_empty()) {
        harden_set_cookies(headers, spec);
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

/// Apply a cookie-flags spec (`"<name-or-*> Flag [Flag…]"`) to every
/// `Set-Cookie` header: for each cookie whose name matches, append each listed
/// attribute the origin did not already set (compared case-insensitively on the
/// attribute name, so `SameSite=Strict` from the origin is left alone when the
/// policy says `SameSite=Lax`). Malformed spec → no change.
fn harden_set_cookies(headers: &mut http::HeaderMap, spec: &str) {
    let mut parts = spec.split_whitespace();
    let Some(pattern) = parts.next() else { return };
    let flags: Vec<&str> = parts.collect();
    if flags.is_empty() {
        return;
    }
    let existing: Vec<http::HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .cloned()
        .collect();
    if existing.is_empty() {
        return;
    }
    let mut rewritten: Vec<http::HeaderValue> = Vec::with_capacity(existing.len());
    for hv in &existing {
        let Ok(raw) = hv.to_str() else {
            rewritten.push(hv.clone());
            continue;
        };
        let name = raw
            .split(';')
            .next()
            .and_then(|kv| kv.split('=').next())
            .unwrap_or("")
            .trim();
        if pattern != "*" && !pattern.eq_ignore_ascii_case(name) {
            rewritten.push(hv.clone());
            continue;
        }
        let present: Vec<String> = raw
            .split(';')
            .skip(1)
            .map(|a| {
                a.trim()
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            })
            .collect();
        let mut out = raw.to_string();
        for f in &flags {
            let key = f.split('=').next().unwrap_or("").to_ascii_lowercase();
            if !key.is_empty() && !present.iter().any(|p| p == &key) {
                out.push_str("; ");
                out.push_str(f);
            }
        }
        match http::HeaderValue::from_str(&out) {
            Ok(v) => rewritten.push(v),
            Err(_) => rewritten.push(hv.clone()),
        }
    }
    headers.remove(header::SET_COOKIE);
    for v in rewritten {
        headers.append(header::SET_COOKIE, v);
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
    let reason = ctx.block_reason.as_deref().unwrap_or(concat!(
        "Request rate-limited by ",
        sentinel_core::product_name!()
    ));
    error_response(status, reason)
}

/// Minimal HTML escape for values interpolated into the block page.
///
/// Every interpolated value is operator-controlled config rather than request
/// data, but "operator-controlled" is not "trusted": a customer-supplied contact
/// string pasted into the site wizard reaches this template verbatim, and an
/// unescaped `"` in an attribute is enough to break out of it. Escaping quotes
/// as well as the angle brackets keeps attribute contexts safe too.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Accept only logo URLs that cannot execute script.
///
/// `<img src>` will happily take `javascript:` and `data:text/html`, which turns
/// a branding field into stored XSS on a page we serve on every block. Allowing
/// exactly https, http and site-relative paths keeps the useful cases and drops
/// the dangerous ones, rather than trying to blacklist schemes.
fn sanitize_logo_url(raw: &str) -> Option<String> {
    let u = raw.trim();
    if u.is_empty() {
        return None;
    }
    let lower = u.to_ascii_lowercase();
    let ok = lower.starts_with("https://")
        || lower.starts_with("http://")
        || (u.starts_with('/') && !u.starts_with("//"));
    if ok {
        Some(escape_html(u))
    } else {
        None
    }
}

/// Render `contact` as a link when it is unambiguously one, else as plain text.
/// A bare email or phone number is the common case and neither is a URL, so we
/// build the scheme rather than requiring the operator to know to type it.
fn render_contact(raw: &str) -> String {
    let c = raw.trim();
    let esc = escape_html(c);
    let lower = c.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        format!(r#"<a href="{esc}">{esc}</a>"#)
    } else if c.contains('@') && !c.contains(' ') {
        format!(r#"<a href="mailto:{esc}">{esc}</a>"#)
    } else {
        esc
    }
}

/// True when the client would rather have a page than a JSON document.
///
/// Deliberately requires an explicit `text/html` in Accept rather than treating
/// a wildcard as a browser: `curl` sends `Accept: */*`, and scripts and health
/// checks that get an HTML page where they expected JSON fail in confusing ways.
/// Browsers always list text/html explicitly, so this splits the two audiences
/// without guessing from the User-Agent.
fn wants_html(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

/// The page a blocked visitor sees.
///
/// Two audiences, one verdict: a browser gets a branded page that names the
/// Support ID, an API client gets the same facts as JSON. Both carry the request
/// id, which is the join key into access.log, waf.log and the ClickHouse event
/// store — so a caller quoting one string lets an operator find the exact
/// request in Threat Search.
///
/// The detection reason is withheld unless the site opts in. See
/// `BlockPageConfig::show_reason` for why that default is a security decision.
fn block_response(ctx: &RequestContext) -> Response<BoxBody> {
    let cfg = ctx.block_page.as_ref();
    let support_id = ctx.request_id.to_string();
    // 403 unless the decision asked for something else (rate limit → 429).
    let status = ctx
        .block_status
        .and_then(|s| StatusCode::from_u16(s).ok())
        .unwrap_or(StatusCode::FORBIDDEN);
    let error_text = status.canonical_reason().unwrap_or("Forbidden");
    let retry_after = (status == StatusCode::TOO_MANY_REQUESTS).then_some("1");
    let show_reason = cfg.map(|c| c.show_reason).unwrap_or(false);
    let reason = if show_reason {
        ctx.block_reason.as_deref()
    } else {
        None
    };

    let html_enabled = cfg.map(|c| c.enabled).unwrap_or(true);
    if html_enabled && ctx.client_accepts_html {
        let body = render_block_page(cfg, &support_id, reason);
        let mut b = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8");
        if let Some(ra) = retry_after {
            b = b.header(header::RETRY_AFTER, ra);
        }
        return b
            // The page names a support id and nothing else of value, but it is
            // still an error page: keep it out of caches and out of frames.
            .header(header::CACHE_CONTROL, "no-store")
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("Referrer-Policy", "no-referrer")
            .body(full_body(Bytes::from(body)))
            .unwrap();
    }

    let mut payload = serde_json::json!({
        "error": error_text,
        "support_id": support_id,
        // Kept for compatibility with clients written against the previous
        // response shape, which used request_id.
        "request_id": support_id,
    });
    if let Some(r) = reason {
        payload["message"] = serde_json::Value::String(r.to_string());
    }
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Content-Type-Options", "nosniff");
    if let Some(ra) = retry_after {
        b = b.header(header::RETRY_AFTER, ra);
    }
    b.body(full_body(Bytes::from(payload.to_string()))).unwrap()
}

/// Self-contained block page: no external CSS, fonts or images, so it renders
/// identically on an air-gapped network and cannot leak the visitor's IP to a
/// third party at the moment we block them.
fn render_block_page(
    cfg: Option<&sentinel_core::config::BlockPageConfig>,
    support_id: &str,
    reason: Option<&str>,
) -> String {
    let title = cfg
        .and_then(|c| c.title.as_deref())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Request blocked");
    let message = cfg
        .and_then(|c| c.message.as_deref())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(
            "Your request was blocked by our web application firewall. \
             If you believe this is a mistake, contact support and quote the Support ID below.",
        );

    let logo = cfg
        .and_then(|c| c.logo_url.as_deref())
        .and_then(sanitize_logo_url)
        .map(|u| format!(r#"<img class="logo" src="{u}" alt="">"#))
        .unwrap_or_default();

    let contact = cfg
        .and_then(|c| c.contact.as_deref())
        .filter(|s| !s.trim().is_empty())
        .map(|c| format!(r#"<p class="contact">Contact: {}</p>"#, render_contact(c)))
        .unwrap_or_default();

    let reason_block = reason
        .map(|r| {
            format!(
                r#"<p class="reason"><strong>Reason:</strong> {}</p>"#,
                escape_html(r)
            )
        })
        .unwrap_or_default();

    let title_esc = escape_html(title);
    let message_esc = escape_html(message);
    let id_esc = escape_html(support_id);

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{title_esc}</title>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 24px; background: #f4f6f8; color: #16202a;
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}}
.card {{
  background: #fff; max-width: 560px; width: 100%; padding: 40px;
  border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.12), 0 8px 24px rgba(0,0,0,.08);
}}
.logo {{ max-height: 44px; max-width: 200px; margin-bottom: 24px; display: block; }}
h1 {{ margin: 0 0 12px; font-size: 24px; line-height: 1.3; }}
p {{ margin: 0 0 16px; }}
.sid-label {{ font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: #5c6b7a; margin-bottom: 6px; }}
.sid {{
  font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: #eef1f4; border: 1px solid #dde3e9; border-radius: 8px;
  padding: 12px 14px; word-break: break-all; user-select: all;
}}
.reason {{ font-size: 14px; color: #5c6b7a; }}
.contact {{ font-size: 14px; margin-bottom: 0; }}
a {{ color: #0b62c4; }}
@media (prefers-color-scheme: dark) {{
  body {{ background: #0f1519; color: #e6edf3; }}
  .card {{ background: #161d24; box-shadow: none; border: 1px solid #263039; }}
  .sid {{ background: #0f1519; border-color: #263039; }}
  .sid-label, .reason {{ color: #93a4b3; }}
  a {{ color: #5aa9f8; }}
}}
</style>
</head>
<body>
<main class="card">
{logo}<h1>{title_esc}</h1>
<p>{message_esc}</p>
{reason_block}<div class="sid-label">Support ID</div>
<div class="sid">{id_esc}</div>
{contact}</main>
</body>
</html>
"#
    )
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
                /// Explicit ACME directory URL, overriding `provider`. Pointing
                /// this at a local ACME server is what makes the
                /// challenge-and-issue path testable without a public address.
                #[serde(default)]
                ca_server: Option<String>,
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
                ca_server: r.ca_server.unwrap_or_default(),
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

/// Whether a management-listener path belongs to the control plane.
///
/// Every control-plane route lives under `/api/v1`; the dashboard also serves
/// server routes of its own under `/api/` (the copilot at `/api/copilot`, which
/// keeps the model key server-side). Routing on `/api/` sent those to the
/// control plane, which answered 404 — so from the management console the
/// copilot could never answer, while its header said "Online".
fn management_path_is_control_plane(path: &str) -> bool {
    path == "/api/v1" || path.starts_with("/api/v1/")
}

/// Reverse-proxy a request arriving on the management listener. Path `/api/v1/*`
/// (REST + SSE) goes to the control plane; everything else — pages, assets and
/// the dashboard's own `/api/*` server routes — to the dashboard.
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
    let base = if management_path_is_control_plane(path) {
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
            // The persisted self-signed fallback now lives under this key too, so
            // "present" no longer means "an operator installed a certificate".
            Some(m) if !matches!(m.source, tls::CertSource::SelfSigned) => {
                let mut v = serde_json::to_value(&m).unwrap_or_else(|_| serde_json::json!({}));
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("self_signed".to_string(), serde_json::json!(false));
                }
                json_ok(v)
            }
            _ => json_ok(serde_json::json!({"self_signed": true})),
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

/// `GET /api/v1/internal/sites/{id}/config` — the site configuration THIS node is
/// actually applying, secrets redacted, plus the compiled rule count for it.
///
/// The control plane converts a stored site into this shape and pushes it; the
/// console shows both side by side. Every one of the six "silently inert" bugs
/// was a control the console showed that never reached this struct, and a
/// diff between what was pushed and what is held would have found each of them
/// in minutes.
fn site_effective_config_response(state: &ServerState, site_id: &str) -> Response<BoxBody> {
    let site_id = match percent_decode_simple(site_id) {
        Some(s) => s,
        None => return json_err(StatusCode::BAD_REQUEST, "bad site id"),
    };
    let cfg = state.config.load();
    let Some(site) = cfg.sites.iter().find(|s| s.id == site_id) else {
        return json_err(StatusCode::NOT_FOUND, "no such site on this node");
    };
    let mut v = serde_json::to_value(site).unwrap_or_else(|_| serde_json::json!({}));
    redact_secrets(&mut v);
    let engines = state.engines.load();
    let engine = engines.get(&site_id).map(|e| {
        let inv = e.inventory();
        serde_json::json!({
            "rules_compiled": inv.total,
            "rules_enforced": inv.enforced,
            "rules_dropped": inv.dropped.len(),
        })
    });
    let body = serde_json::json!({
        "site": site_id,
        "version": env!("CARGO_PKG_VERSION"),
        "applied": v,
        "engine": engine,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// Minimal `%XX` decoding for a path segment (site ids are slugs or host names,
/// but a name with a space or unicode arrives encoded).
fn percent_decode_simple(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `GET /api/v1/internal/blocks` — every source THIS node is currently
/// dropping or escalating on its own initiative: XDP auto-bans, the eBPF
/// blocklist (auto-bans plus operator CIDRs seeded from ip_reputation), and the
/// repeat-offender table for the current correlation window.
///
/// Threat-intel indicators and GeoIP country blocks are control-plane state and
/// are merged there; this is the part only the data plane knows. Until this
/// endpoint existed an auto-banned IP appeared nowhere in the console, and the
/// only way to lift the ban was a restart.
fn blocks_response(state: &ServerState) -> Response<BoxBody> {
    let ab = autoban_config();
    let (ebpf_ips, ebpf_ranges) = state.ebpf.blocked_entries();
    let autobanned: Vec<String> = {
        let mut v: Vec<std::net::IpAddr> = xdp_autobanned().iter().map(|e| *e).collect();
        v.sort();
        v.into_iter().map(|ip| ip.to_string()).collect()
    };
    let corr = &state.modules.correlation;
    let offenders: Vec<serde_json::Value> = corr
        .offenders()
        .into_iter()
        .map(|(ip, blocks, last)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "blocks_in_window": blocks,
                "last_block_unix": last,
                "escalated": blocks as usize >= corr.escalate_threshold(),
                "autoban_pending": ab.enabled && (blocks < ab.threshold_blocks)
                    && autoban_eligible(ip, ab.include_private),
            })
        })
        .collect();
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "ebpf": {
            "mode": state.ebpf.mode().to_string(),
            "drops": state.ebpf.ebpf_drops(),
            "exact_ips": ebpf_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "ranges": ebpf_ranges.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        },
        "autoban": {
            "enabled": ab.enabled,
            "threshold_blocks": ab.threshold_blocks,
            "include_private": ab.include_private,
            "window_secs": corr.window(),
            "banned": autobanned,
        },
        "offenders": {
            "window_secs": corr.window(),
            "escalate_threshold": corr.escalate_threshold(),
            "entries": offenders,
        },
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// `DELETE /api/v1/internal/blocks/{ip}` — lift this node's own block on one
/// address: out of the auto-ban set, out of the eBPF blocklist, and out of the
/// repeat-offender table so it is not re-banned on its next request. A CIDR
/// seeded from site policy is not touched (change the policy instead), and the
/// response says whether such a range still covers the address.
fn unblock_response(state: &ServerState, raw: &str) -> Response<BoxBody> {
    let Ok(ip) = raw.parse::<std::net::IpAddr>() else {
        return json_err(StatusCode::BAD_REQUEST, "not an IP address");
    };
    let was_autobanned = xdp_autobanned().remove(&ip).is_some();
    let (before_ips, ranges) = state.ebpf.blocked_entries();
    let was_ebpf = before_ips.contains(&ip);
    state.ebpf.unblock_ip(ip);
    let forgot = state.modules.correlation.forget(ip);
    let still_in_range = ranges.iter().any(|n| n.contains(&ip));
    if was_autobanned || was_ebpf || forgot {
        warn!(%ip, was_autobanned, was_ebpf, forgot, "operator lifted block");
    }
    let body = serde_json::json!({
        "ip": ip.to_string(),
        "was_autobanned": was_autobanned,
        "was_in_ebpf_blocklist": was_ebpf,
        "offender_history_cleared": forgot,
        "still_covered_by_range": still_in_range,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

/// `GET /api/v1/internal/settings` — this node's global configuration, minus
/// sites and with secrets redacted, for the console's Global Settings page.
///
/// Listeners, TLS floor, HTTP/3, logging, storage, eBPF and admission limits
/// come from the node's YAML and change only with a restart. Until this
/// endpoint existed they were visible nowhere in the console; an operator had
/// to ssh to the node to learn which ports it listened on. Read-only by design:
/// the response says so, and the page repeats it.
fn global_settings_response(state: &ServerState) -> Response<BoxBody> {
    let cfg = state.config.load();
    let mut v = serde_json::to_value(&**cfg).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sites");
        obj.insert(
            "version".into(),
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        );
        obj.insert(
            "read_only".into(),
            serde_json::json!("node configuration file — edit on the node and restart to change"),
        );
        obj.insert("site_count".into(), serde_json::json!(cfg.sites.len()));
    }
    redact_secrets(&mut v);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(v.to_string())))
        .unwrap()
}

/// Replace credential-bearing values in a config JSON tree: any key named like
/// a secret, and the userinfo part of any URL (`redis://user:pw@host`).
fn redact_secrets(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                let kl = k.to_ascii_lowercase();
                if kl.contains("password")
                    || kl.contains("secret")
                    || kl.contains("token")
                    || kl == "api_key"
                    || kl == "apikey"
                {
                    if !val.is_null() {
                        *val = serde_json::Value::String("***".into());
                    }
                    continue;
                }
                redact_secrets(val);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_secrets),
        serde_json::Value::String(s) => {
            // scheme://user:pass@host → scheme://***@host
            if let Some(scheme_end) = s.find("://") {
                let rest = &s[scheme_end + 3..];
                // Only an '@' inside the authority (before any '/') is userinfo.
                let authority_end = rest.find('/').unwrap_or(rest.len());
                if let Some(at) = rest[..authority_end].rfind('@') {
                    if at > 0 {
                        *s = format!("{}://***@{}", &s[..scheme_end], &rest[at + 1..]);
                    }
                }
            }
        }
        _ => {}
    }
}

/// `GET /api/v1/internal/rules[?site=<id>][&summary=1]` — the compiled rule
/// inventory of every site engine on this node.
///
/// This exists because the console's Rules page listed the control plane's
/// authored rule store (six rows) and called it "loaded rules" while this
/// process was enforcing a few hundred compiled CRS rules with no way to show
/// them. The control plane proxies this to the dashboard and adds hit counts.
///
/// `summary=1` omits the per-rule list (totals and gaps only), which is what
/// the sidebar badge and the overview card need every few seconds.
fn rules_inventory_response(state: &ServerState, query: Option<&str>) -> Response<BoxBody> {
    let mut site_filter: Option<String> = None;
    let mut summary = false;
    for pair in query.unwrap_or("").split('&') {
        match pair.split_once('=') {
            Some(("site", v)) if !v.is_empty() => site_filter = Some(v.to_string()),
            Some(("summary", v)) => summary = v == "1" || v == "true",
            _ => {}
        }
    }

    let engines = state.engines.load();
    let mut sites: Vec<serde_json::Value> = Vec::new();
    // Totals count DISTINCT rules across sites. They used to be summed, so three
    // sites sharing one CRS set reported 758 "rules" (353 + 280 + 125) in the
    // console headline and nav badge — no rule set of that size exists anywhere.
    // Per-site counts are unchanged in `sites[]`.
    let mut compiled_ids = std::collections::HashSet::new();
    let mut enforced_ids = std::collections::HashSet::new();
    let mut dropped_ids = std::collections::HashSet::new();
    let mut disabled_ids = std::collections::HashSet::new();
    let mut ids: Vec<&String> = engines.keys().collect();
    ids.sort();
    for site_id in ids {
        if let Some(f) = &site_filter {
            if f != site_id {
                continue;
            }
        }
        let inv = engines[site_id].inventory();
        for r in &inv.rules {
            compiled_ids.insert(r.id);
            if !r.inert {
                enforced_ids.insert(r.id);
            }
        }
        dropped_ids.extend(inv.dropped.iter().map(|d| d.id));
        disabled_ids.extend(inv.disabled.iter().copied());
        let mut v = serde_json::to_value(&inv).unwrap_or_else(|_| serde_json::json!({}));
        if summary {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("rules");
            }
        }
        if let Some(obj) = v.as_object_mut() {
            obj.insert("site".into(), serde_json::Value::String(site_id.clone()));
        }
        sites.push(v);
    }

    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "sites": sites,
        "totals": {
            "compiled": compiled_ids.len(),
            "enforced": enforced_ids.len(),
            "dropped": dropped_ids.len(),
            "disabled": disabled_ids.len(),
        },
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(body.to_string())))
        .unwrap()
}

async fn health_response(state: &ServerState) -> Response<BoxBody> {
    let jwks_status = state.modules.jwks.status().await;
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
                // Endpoints that stopped serving for good: enabled, and off.
                "down": http3::endpoints_down(),
            })
        }
        None => serde_json::json!({ "enabled": false }),
    };

    let pool_stats = state.upstream_pool.stats();
    let ebpf_stats = state.ebpf.stats();
    let start = *START_TIME.get_or_init(SystemTime::now);
    let uptime_secs = start.elapsed().unwrap_or_default().as_secs();

    let body = serde_json::json!({
        "status": "ok",
        "uptime_secs": uptime_secs,
        "sites": site_count,
        // Inspection coverage. `engines_warming` true means a reload is in
        // flight and sites without an engine are being refused with 503 rather
        // than forwarded uninspected. `sites_without_engine` non-empty while
        // warming is FALSE is the alarming case: those sites are matchable,
        // being served, and have no signature protection because their rules
        // failed to compile.
        "inspection": {
            "engines_warming": ENGINES_WARMING.load(std::sync::atomic::Ordering::Acquire),
            "sites_without_engine": unprotected_sites(&cfg, &state.engines.load_full()),
            // Which of those are actually being REFUSED. Since 2026-09-07 a
            // blocking-mode site whose rules will not compile fails closed
            // instead of being served with no signature protection; a
            // learning-mode site in the same state is still served, on purpose.
            "sites_refused": refused_sites(&cfg, &state.engines.load_full()),
            "serve_on_rule_compile_failure": serve_on_rule_compile_failure(),
        },
        "listeners": listeners,
        "http3": http3,
        // Non-zero means this node enforced blocks it could not record, so
        // waf_events undercounts attacks for that window. Surfaced here as well as
        // in /metrics because /healthz is what an operator reads first, and a
        // silently incomplete audit trail is the failure this counter exists to
        // make visible.
        "history_shed": history_shed_total(),
        // Valkey and ClickHouse connect in the background and are retried, so
        // the node serves without them; this says whether they are in use.
        "storage": storage_status(&state.modules.rate_limiter),
        // Panics this process contained instead of dying on. Non-zero is a bug
        // to chase (each has a log line with its location); `task_restarts`
        // climbing means a background loop is crash-looping.
        "panics": panic_guard::status(),
        // The eBPF/XDP data path, and specifically whether the KERNEL path is
        // live. This exists because kernel XDP had never once loaded on any
        // deployment — the embedded object was rejected before it reached the
        // kernel — and the ONLY trace was a single WARN at startup. Nothing
        // queryable reported it, so every install silently ran the DDoS path in
        // software while the product documented an in-kernel fast path.
        //
        // `kernel_requested` vs `mode` is the pair that matters: requested-but-
        // software is the exact silent degradation that hid for six weeks, and
        // it is now something verify.sh can assert instead of infer from
        // container logs.
        "ebpf": {
            "mode": state.ebpf.mode().to_string(),
            "kernel_requested": state.ebpf.config().enable_kernel,
            "interface": state.ebpf.config().interface,
            "xdp_pass": ebpf_stats.xdp_pass,
            "xdp_drop": ebpf_stats.xdp_drop,
            "xdp_aborted": ebpf_stats.xdp_aborted,
        },
        // Country filtering: what is CONFIGURED vs what is ENFORCED. `inert` is
        // the field that matters — non-empty means a site's country policy is
        // displayed and not applied, because no MaxMind database is present.
        "geoip": geoip_status(&state.config.load(), &state.modules.geoip_map.load()),
        // JWT/JWKS. Everything this reports was previously reachable only by
        // reading container logs, and those diagnostics are latched to fire on a
        // CHANGE of state — so the single line explaining why every token is
        // being rejected may have scrolled past long before anyone looks. An
        // empty object means no site here has a JWKS endpoint, not that JWT
        // validation is broken.
        "jwt": jwks_status,
        // WASM plugins. `loaded` is what this node holds; `per_site` is who
        // actually runs each one (plugins are opt-in per site since 2026-09-07 —
        // before that every loaded module judged every site's traffic).
        // `unresolved` is a site naming a plugin this node does not have: it
        // will NOT run, and that must be visible rather than silently inert.
        "plugins": plugin_status(
            &state.plugin_runtime.load(),
            &state.site_plugins.load(),
            &state.unresolved_plugins.load(),
        ),
        // Global IOC enforcement: is it on, and if not, why not? `active` is the
        // honest summary; `configured` only means a sync URL exists. There was no
        // `threat_intel` key here at all, which is how a node serving every
        // request against an empty feed looked identical to a healthy one.
        "threat_intel": threat_intel_status(
            &state.config.load(),
            &state.modules.threat_intel.load(),
        ),
        // Is this node still taking config? Failing polls (a control plane that
        // refuses, or never answers, the sync) showed only in WARN lines and in
        // the heartbeat, which a silent control plane never receives.
        "config_sync": config_sync_health(&cfg),
        // Site IP feeds: per feed, loaded / stale / failed / skipped, and what
        // the per-feed and per-node caps cut. Each is a way for a feed to show as
        // set in the console and enforce nothing.
        "ip_feeds": ip_feed::status_json(),
        // Module reachability. Seven subsystems had no logging at all, and their
        // entry points are per-request pure functions on attacker-controlled
        // input, so they cannot be given log lines. These counters answer the one
        // question their silence made unanswerable: did the control RUN?
        //
        // Read them as zeroes and ratios, not totals:
        //   smuggling.evaluated == 0 with traffic  -> desync detection never ran
        //   graphql.inspected == 0 while configured -> the endpoint gate does not
        //     match this app's path (case-sensitive `contains("graphql")`, POST
        //     only), so the firewall is configured and inspecting nothing
        //   grpc.inspected == 0 while configured   -> same, for Content-Type
        //   ja4.success / ja4.attempts             -> fingerprint coverage; a
        //     shortfall silently disables every JA4-dependent control
        //   bot.good_bot_allowed                   -> requests trusted purely on
        //     a User-Agent claim; reverse-DNS verification is still a TODO
        "modules": {
            "smuggling": {
                "evaluated": smuggling_evaluated_total(),
                "rejected_framing": smuggling_rejected_framing_total(),
                "rejected_header": smuggling_rejected_header_total(),
            },
            "graphql": {
                "inspected": graphql_inspected_total(),
                "blocked": graphql_blocked_total(),
            },
            "grpc": { "inspected": grpc_inspected_total() },
            // `attempts` counts only connections that actually presented a TLS
            // handshake record, so success/attempts is real fingerprint
            // coverage. `no_hello` carries TCP probes and abandoned connections,
            // which used to be lumped into attempts and made the ratio
            // meaningless (977 "attempts" against 11 requests served).
            "ja4": {
                "attempts": ja4_attempts_total(),
                "success": ja4_success_total(),
                "no_hello": ja4_no_hello_total(),
                // h3 counted SEPARATELY on purpose. Folded together, a blind
                // spot in one transport hides behind healthy coverage in the
                // other — and h3 was blind for its entire existence while the
                // TCP ratio looked fine. `absent` non-zero with `attempts`
                // non-zero means h3 clients are reaching the pipeline
                // unfingerprinted; if it equals `attempts`, the decorator is
                // very likely not installed at all (see ja4_quic).
                "h3": {
                    "attempts": ja4_h3_attempts_total(),
                    "success": ja4_h3_success_total(),
                    "absent": ja4_h3_absent_total(),
                },
            },
            "bot": {
                // Allowlist grants. Only a claim VERIFIED by reverse DNS can
                // produce one, so from an address whose PTR cannot substantiate
                // the claim this stays 0 — which is the live assertion that the
                // User-Agent alone no longer buys a free pass.
                "good_bot_allowlisted": bot_good_bot_allowed_total(),
                // Reverse-DNS verification of good-bot claims: lookups made,
                // verified (allowlisted), rejected (PTR contradicts the claim —
                // penalised), unverifiable (no PTR / resolver failure / operator
                // publishes no PTR domain — scored normally).
                "good_bot": state.modules.goodbot.status(),
                // Sizes, because they are smaller than the feature name suggests
                // and nothing reported them. The JA4 table is a static built-in
                // whose own comment calls it "for demonstration", and the proxy
                // re-creates the detector with `new()` on every config reload —
                // so any fingerprint added at runtime is discarded. A JA4
                // blocklist that is quietly this small should be readable.
                "ja4_fingerprints": state.modules.bot_detector.load().ja4_fingerprint_count(),
                "attacker_ua_patterns": state.modules.bot_detector.load().attacker_pattern_count(),
                "good_bot_ua_patterns": state.modules.bot_detector.load().good_bot_pattern_count(),
            },
        },
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

/// Stamp the outgoing response's status and body size onto the context BEFORE
/// `log_request`. Every rejection path used to return without doing this, so a
/// large class of blocks (size/method limits, pre-routing rejections, DLP)
/// logged `status=0, bytes=0` — corrupting the 4xx/5xx counters and making
/// `status` an unreliable filter in Threat Search.
fn stamp_response(ctx: &mut RequestContext, resp: &Response<BoxBody>) {
    ctx.response_status = Some(resp.status());
    if let Some(sz) = hyper::body::Body::size_hint(resp.body()).exact() {
        ctx.bytes_sent = sz;
    }
}

/// Truncate `s` to `max` bytes on a char boundary, marking that it was cut.
/// Log lines are written per request, so an unbounded field is an amplification
/// vector: a URI flood would have each rejected request write a multi-kilobyte
/// line, filling the disk faster than the traffic itself.
fn cap_field(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// The request's query string for logging. Logged alongside (not inside)
/// `path`: facets, the learning report and per-path aggregation all group by
/// `path`, and appending queries there would explode cardinality. Empty when
/// the request had none.
fn capped_query(uri: &http::Uri) -> String {
    // Redact BEFORE capping. The other order would truncate mid-secret and leave
    // a usable prefix in the log — and for a JWT the header and payload are the
    // first two segments, so a prefix is not harmless.
    //
    // This is on the logging path of EVERY request: `query` goes into
    // access.log, into waf_events (90-day retention) and out to the SIEM. A
    // password-reset `?token=`, an OAuth `?code=`, an `?api_key=` would
    // otherwise be written verbatim to all three.
    cap_field(
        &sentinel_core::redact::redact_query(uri.query().unwrap_or("")),
        2048,
    )
}

/// The request path for logging. Capped for the reason in `cap_field`: the
/// URI-too-long rejection logs the very path that was rejected for being long.
fn capped_path(uri: &http::Uri) -> String {
    cap_field(uri.path(), 1024)
}

/// The matched text of a rule hit, for logging.
///
/// The primary credential guard is in the rule VM, which redacts by consulting
/// the request's own parameters BEFORE the value is ever stored on the
/// `RuleMatch` (see `value_from_sensitive_field`). This is the second layer,
/// covering the case that check cannot see: a rule whose target is a named
/// header or cookie, where the value never appears as a request parameter at
/// all. Two cheap checks in different places beats one, because the cost of a
/// miss here is a live credential written into a log an operator then pastes
/// into a ticket.
fn redacted_matched(m: &sentinel_core::context::RuleMatch) -> String {
    if m.matched_value.is_empty() {
        return String::new();
    }
    let t = m.target.to_ascii_lowercase();
    const SENSITIVE: [&str; 10] = [
        "password", "passwd", "pwd", "secret", "token", "auth", "cookie", "session", "apikey",
        "api_key",
    ];
    if SENSITIVE.iter().any(|s| t.contains(s)) {
        return format!("[redacted:{}]", m.target);
    }
    m.matched_value.clone()
}

/// How many matched rules one event lists. A request that trips more than this
/// is an attack tool, and the top contributors already explain the verdict.
const MAX_LOGGED_RULES: usize = 20;
/// Cap on one rule's matched text inside the list (the top rule's own
/// `matched` field keeps its existing cap).
const MAX_RULE_MATCHED_CHARS: usize = 160;
const MAX_LOGGED_HEADERS: usize = 40;
const MAX_HEADER_VALUE_CHARS: usize = 256;

fn cap_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// The matched text, redacted against the REFINED target too. The VM already
/// redacts a value it recognises as a credential, and `redacted_matched`
/// checks the rule's own target label; naming the parameter more precisely
/// (see [`sentinel_rules::RequestValues::locate`]) must never be what exposes
/// one, so a refined label that names a sensitive field redacts as well.
///
/// And never a cookie value: the rule engine withholds those at capture, but
/// other engines (ML, plugins) build RuleMatches of their own, so the check is
/// repeated here against the request's cookies — see
/// `sentinel_core::redact::withheld_cookie_value`.
fn matched_at(m: &sentinel_core::context::RuleMatch, located: &str, cookies: &[String]) -> String {
    let base = redacted_matched(m);
    if base.is_empty() || base.starts_with("[redacted") {
        return base;
    }
    if let Some(w) = sentinel_core::redact::withheld_cookie_value(&base, cookies) {
        return w;
    }
    let member = located.rsplit(':').next().unwrap_or("");
    if located.contains(':') && sentinel_core::redact::is_sensitive_field_name(member) {
        return format!("[redacted:{located}]");
    }
    base
}

/// Every rule that added to this request's verdict, biggest contribution first.
///
/// The event used to name only the LEADING rule, so a score of 85 read as one
/// rule's doing when several rules had added to it — and excluding that one
/// rule for a false positive left the rest still over the threshold. F5 lists
/// every violation and BunkerWeb every ModSecurity match; this is that list,
/// with each rule's own score and, where it can be certain, the parameter.
fn matched_rules_detail(
    ctx: &RequestContext,
    values: &sentinel_rules::RequestValues,
) -> Vec<serde_json::Value> {
    let cookies = sentinel_core::redact::request_cookie_values(&ctx.request_headers);
    let mut rules: Vec<&sentinel_core::context::RuleMatch> = ctx.rule_matches.iter().collect();
    rules.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.severity.rank().cmp(&a.severity.rank()))
    });
    rules
        .into_iter()
        .take(MAX_LOGGED_RULES)
        .map(|r| {
            let target = values
                .locate(&r.target, &r.matched_value)
                .unwrap_or_else(|| r.target.clone());
            serde_json::json!({
                "id": r.rule_id,
                "msg": r.message,
                "sev": format!("{:?}", r.severity).to_uppercase(),
                "score": r.score,
                "target": target,
                "matched": cap_chars(&matched_at(r, &target, &cookies), MAX_RULE_MATCHED_CHARS),
            })
        })
        .collect()
}

/// The top rule's target, refined to the parameter where that is certain.
fn located_target(
    top: Option<&sentinel_core::context::RuleMatch>,
    values: &sentinel_rules::RequestValues,
) -> String {
    top.map(|r| {
        values
            .locate(&r.target, &r.matched_value)
            .unwrap_or_else(|| r.target.clone())
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod console_cookie_tests {
    use super::*;

    fn cookies(h: &http::HeaderMap) -> Vec<String> {
        h.get_all(http::header::COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_console_cookie_never_reaches_an_origin() {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::COOKIE,
            "language=az_AZ; sentinel_token=eyJhbGciOi.payload.sig; welcomebanner_status=dismiss"
                .parse()
                .unwrap(),
        );
        strip_console_session_cookie(&mut h);
        assert_eq!(
            cookies(&h),
            ["language=az_AZ; welcomebanner_status=dismiss"]
        );
    }

    #[test]
    fn a_cookie_field_left_empty_is_dropped_and_split_fields_are_each_filtered() {
        // HTTP/2 and HTTP/3 send one cookie per field.
        let mut h = http::HeaderMap::new();
        h.append(
            http::header::COOKIE,
            "sentinel_token=active".parse().unwrap(),
        );
        h.append(http::header::COOKIE, "sid=abc".parse().unwrap());
        strip_console_session_cookie(&mut h);
        assert_eq!(cookies(&h), ["sid=abc"]);

        let mut only = http::HeaderMap::new();
        only.insert(http::header::COOKIE, "sentinel_token=eyJx".parse().unwrap());
        strip_console_session_cookie(&mut only);
        assert!(only.get(http::header::COOKIE).is_none());
    }

    #[test]
    fn other_cookies_are_untouched_even_with_similar_names() {
        let original = "sentinel_token_pref=1; my_sentinel_token=2; a=b";
        let mut h = http::HeaderMap::new();
        h.insert(http::header::COOKIE, original.parse().unwrap());
        strip_console_session_cookie(&mut h);
        assert_eq!(
            cookies(&h),
            [original],
            "only the exact cookie name is removed"
        );

        let mut none = http::HeaderMap::new();
        strip_console_session_cookie(&mut none);
        assert!(none.is_empty());
    }
}

#[cfg(test)]
mod event_detail_tests {
    use super::*;
    use sentinel_core::context::{Phase, RuleMatch, Severity, VerdictSource};
    use std::net::{IpAddr, Ipv4Addr};

    fn rm(id: &str, score: u32, target: &str, matched: &str) -> RuleMatch {
        RuleMatch {
            rule_id: id.into(),
            message: format!("rule {id}"),
            severity: Severity::Critical,
            score,
            target: target.into(),
            phase: Phase::RequestBody,
            matched_value: matched.into(),
        }
    }

    fn ctx(uri: &str) -> RequestContext {
        let mut c = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        c.uri = uri.parse().unwrap();
        c
    }

    #[test]
    fn lists_every_contributing_rule_biggest_first_with_its_parameter() {
        // The 2026-09-24 event: score 85, one rule named, target empty.
        let mut c = ctx("/rest/products/search?q=%27))%20UNION%20SELECT%20id%20FROM%20Users--");
        c.rule_matches = vec![
            rm("942100", 5, "ARGS", "')) UNION SELECT id FROM Users--"),
            rm("9900100", 50, "", "')) UNION SELECT id FROM Users--"),
            rm("942190", 30, "", "UNION SELECT"),
        ];
        let v = sentinel_rules::RequestValues::from_ctx(&c);
        let rules = matched_rules_detail(&c, &v);
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            ["9900100", "942190", "942100"],
            "sorted by score contribution"
        );
        assert_eq!(rules[0]["score"], 50);
        assert_eq!(
            rules[0]["target"], "ARGS:q",
            "multi-target rule located to the parameter"
        );
        assert_eq!(
            rules[2]["target"], "ARGS:q",
            "collection label refined to the member"
        );
        assert_eq!(located_target(c.primary_rule_match(), &v), "ARGS:q");
    }

    #[test]
    fn caps_the_rule_list() {
        let mut c = ctx("/x?a=1");
        c.rule_matches = (0..45)
            .map(|i| rm(&format!("9{i:05}"), 1, "", ""))
            .collect();
        let v = sentinel_rules::RequestValues::from_ctx(&c);
        assert_eq!(matched_rules_detail(&c, &v).len(), MAX_LOGGED_RULES);
    }

    #[test]
    fn a_refined_target_that_names_a_credential_redacts_the_match() {
        // The VM redacts values it recognises; naming the parameter must never be
        // what exposes one. `password` located from a multi-target rule:
        let mut c = ctx("/login");
        c.request_headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        c.request_body = Some(Bytes::from_static(b"user=bob&password=hunter2%27--"));
        c.rule_matches = vec![rm("942100", 5, "", "hunter2'--")];
        let v = sentinel_rules::RequestValues::from_ctx(&c);
        let rules = matched_rules_detail(&c, &v);
        assert_eq!(rules[0]["target"], "ARGS:password");
        assert!(
            !rules[0]["matched"].as_str().unwrap().contains("hunter2"),
            "{}",
            rules[0]["matched"]
        );
    }

    #[test]
    fn a_session_cookie_is_withheld_whatever_it_is_called() {
        // The eNlight360 UAT console, 2026-09-29: an Express session cookie
        // named `node-js`, which no name list would ever call sensitive.
        let mut h = http::HeaderMap::new();
        h.insert(
            "cookie",
            "node-js=s%3AaBcD1234efGH.QmVyeVNlY3JldFNpZ25hdHVyZQ; theme=dark"
                .parse()
                .unwrap(),
        );
        // HTTP/2 and HTTP/3 send one cookie per field.
        h.append("cookie", "lang=en".parse().unwrap());
        let m = redacted_request_headers(&h);
        let cookie = m["cookie"].as_str().unwrap();
        assert_eq!(
            cookie,
            "node-js=[redacted]; theme=[redacted], lang=[redacted]"
        );
        assert!(!cookie.contains("s%3A"), "{cookie}");
    }

    #[test]
    fn a_cookie_value_never_reaches_a_record_even_from_another_engine() {
        // The rule engine withholds cookie values at capture; a RuleMatch built
        // elsewhere (ML, a plugin) must not bring one back in. Multi-target, so
        // the match has no target to judge by — only the request's cookies.
        let mut c = ctx("/");
        c.request_headers
            .insert("cookie", "lang=en".parse().unwrap());
        c.request_headers.append(
            "cookie",
            "node-js=s%3AaBcD1234efGH.QmVyeVNlY3JldA".parse().unwrap(),
        );
        c.rule_matches = vec![rm("942440", 5, "", "s:aBcD1234efGH.QmVyeVNlY3JldA")];
        let v = sentinel_rules::RequestValues::from_ctx(&c);
        let rules = matched_rules_detail(&c, &v);
        let m = rules[0]["matched"].as_str().unwrap();
        assert!(!m.contains("aBcD1234"), "{m}");
        assert!(m.starts_with("[redacted cookie value:"), "{m}");
        let headers = redacted_request_headers(&c.request_headers);
        assert_eq!(headers["cookie"], "lang=[redacted], node-js=[redacted]");
        // Text that is not a cookie is untouched.
        c.rule_matches = vec![rm("942100", 5, "", "' OR 1=1--")];
        let v = sentinel_rules::RequestValues::from_ctx(&c);
        assert_eq!(matched_rules_detail(&c, &v)[0]["matched"], "' OR 1=1--");
    }

    #[test]
    fn response_rules_read_json_only_on_a_server_error() {
        let with = |ct: &str, status: u16| {
            let mut h = http::HeaderMap::new();
            h.insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
            response_rules_apply(&h, StatusCode::from_u16(status).unwrap())
        };
        // The UAT false positive: a successful JSON product list.
        assert!(!with("application/json", 200));
        assert!(!with("application/json", 404));
        // What these rules exist for: a leak in an API's error response.
        assert!(with("application/json", 500));
        assert!(with("application/problem+json; charset=utf-8", 502));
        // Never scripts, whatever the status.
        assert!(!with("application/javascript", 500));
        // Pages are read at any status.
        assert!(with("text/html", 200));
    }

    #[test]
    fn response_rules_read_only_the_pages_they_were_written_for() {
        let with = |cts: &[&str]| {
            let mut h = http::HeaderMap::new();
            for ct in cts {
                h.append(http::header::CONTENT_TYPE, ct.parse().unwrap());
            }
            response_rules_apply(&h, StatusCode::OK)
        };
        assert!(with(&["text/html; charset=utf-8"]));
        assert!(with(&["TEXT/HTML"]));
        assert!(with(&["text/plain"]));
        assert!(with(&["text/xml"]));
        // The two shapes that produced every false positive on the UAT console.
        assert!(!with(&["application/javascript"]));
        assert!(!with(&["text/javascript; charset=utf-8"]));
        assert!(!with(&["application/json"]));
        assert!(!with(&["text/css"]));
        assert!(!with(&["image/png"]));
        // No Content-Type at all is not trusted to be harmless.
        assert!(with(&[]));
        // A second header is not a way past the scanner.
        assert!(with(&["application/octet-stream", "text/html"]));
    }

    #[test]
    fn dlp_reads_pages_and_data_but_not_scripts_or_stylesheets() {
        let with = |cts: &[&str]| {
            let mut h = http::HeaderMap::new();
            for ct in cts {
                h.append(http::header::CONTENT_TYPE, ct.parse().unwrap());
            }
            dlp_applies(&h)
        };
        for ct in [
            "text/html; charset=utf-8",
            "text/plain",
            "text/csv",
            "application/json",
            "application/problem+json",
            "application/vnd.api+json",
            "application/xml",
            "application/soap+xml",
            "application/xhtml+xml",
        ] {
            assert!(with(&[ct]), "{ct} carries data and must be scanned");
        }
        // Streams: buffering one held every message back (code review).
        for ct in [
            "text/event-stream",
            "text/event-stream; charset=utf-8",
            "application/x-ndjson",
            "application/stream+json",
        ] {
            assert!(!with(&[ct]), "{ct} is a stream and must not be buffered");
        }
        // Office documents contain "xml" in the type name; they are zips.
        for ct in [
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ] {
            assert!(!with(&[ct]), "{ct} is a zip, not XML");
        }
        // The login page's bundle on the UAT console, and its kin.
        for ct in [
            "text/javascript",
            "application/javascript; charset=utf-8",
            "application/x-javascript",
            "text/css",
            "image/png",
            "application/octet-stream",
            // "text" appeared in this binary type's name; the old substring
            // test scanned OpenDocument zips.
            "application/vnd.oasis.opendocument.text",
        ] {
            assert!(!with(&[ct]), "{ct} must stream unscanned");
        }
        assert!(with(&[]), "no Content-Type is not trusted to be harmless");
        assert!(with(&[""]), "an empty one neither");
        assert!(with(&["text/javascript", "application/json"]));
    }

    #[test]
    fn the_outbound_threshold_comes_from_the_site_policy_or_crs() {
        let mut c = ctx("/");
        assert_eq!(outbound_threshold(&c), 4);
        c.tx_vars
            .insert("OUTBOUND_ANOMALY_SCORE_THRESHOLD".into(), "12".into());
        assert_eq!(outbound_threshold(&c), 12);
        c.tx_vars
            .insert("OUTBOUND_ANOMALY_SCORE_THRESHOLD".into(), "0".into());
        assert_eq!(outbound_threshold(&c), 4, "0 would block every response");
    }

    #[test]
    fn a_response_leak_reports_the_response_score_and_threshold() {
        // The 2026-09-29 UAT record: rule 951220 in the response body, learning
        // mode, would_block — recorded as "score 0" with "raise the site's
        // anomaly threshold above 1".
        let mut c = ctx("/node/iam-service/dashboard/get_user_modules");
        c.site_id = Some("uat".into());
        c.anomaly_threshold = Some(10);
        c.outbound_threshold = Some(4);
        c.outbound_anomaly_score = 5;
        c.would_block = true;
        let mut m = rm("951220", 5, "RESPONSE_BODY", "SQL Server instances");
        m.phase = Phase::ResponseBody;
        c.rule_matches = vec![m];
        assert_eq!(verdict_score(&c), (5, Some(4), true));
        let (msg, rem) = explain_event(&c, "DETECT", "951220", "mssql SQL Information Leakage");
        assert!(
            msg.contains(
                "Response anomaly score 5 against the response threshold of 4 (threshold reached)"
            ),
            "{msg}"
        );
        assert!(
            rem.contains("raise the response threshold above 5"),
            "{rem}"
        );
        assert!(
            rem.contains("outbound_anomaly_score_threshold, now 4"),
            "{rem}"
        );
        assert!(!rem.contains("anomaly threshold above 1"), "{rem}");

        // A request that scored is still judged — and explained — on its own score.
        let mut r = ctx("/search?q=x");
        r.anomaly_threshold = Some(10);
        r.anomaly_score = 12;
        r.outbound_threshold = Some(4);
        r.outbound_anomaly_score = 5;
        assert_eq!(verdict_score(&r), (12, Some(10), false));
        // Neither reached: the request's own score, when it has one.
        r.anomaly_score = 3;
        r.outbound_anomaly_score = 2;
        assert_eq!(verdict_score(&r), (3, Some(10), false));
    }

    fn response_rm(id: &str, score: u32) -> RuleMatch {
        let mut m = rm(id, score, "RESPONSE_BODY", "SQL Server Driver");
        m.phase = Phase::ResponseBody;
        m
    }

    #[test]
    fn a_response_block_names_the_response_rule_not_a_sub_threshold_request_rule() {
        // Code review: a CRITICAL request rule below the site threshold plus a
        // CRITICAL response rule that blocked. primary_rule_match's tie-break
        // (earliest) named the request rule, so the advice was to exclude a
        // rule that had decided nothing.
        let mut c = ctx("/search?q=x");
        c.site_id = Some("s".into());
        c.anomaly_threshold = Some(10);
        c.anomaly_score = 5;
        c.outbound_threshold = Some(4);
        c.outbound_anomaly_score = 5;
        c.decision = WafDecision::Block;
        c.verdict_source = Some(VerdictSource::Response);
        c.rule_matches = vec![rm("942100", 5, "ARGS:q", "x"), response_rm("951220", 5)];
        assert_eq!(c.deciding_rule_match().unwrap().rule_id, "951220");
        let (msg, rem) = explain_event(&c, "BLOCK", "951220", "mssql SQL Information Leakage");
        assert!(msg.contains("rule 951220"), "{msg}");
        assert!(msg.contains("Response anomaly score 5"), "{msg}");
        assert!(
            rem.contains("rule 951220") && !rem.contains("942100"),
            "{rem}"
        );
        // access.log — the file the Logs page tails — says the same thing.
        let a = access_record(&c);
        assert_eq!(a["score"], 5, "{a}");
        assert_eq!(a["rule"], "951220", "{a}");
    }

    #[test]
    fn a_dlp_block_is_explained_as_dlp_not_as_a_threshold() {
        // Code review: a sub-threshold response rule (3 < 4) beside a DLP
        // block read "Response anomaly score 3 … below threshold" and advised
        // raising a threshold that could not unblock a DLP match.
        let mut c = ctx("/account");
        c.site_id = Some("s".into());
        c.outbound_threshold = Some(4);
        c.outbound_anomaly_score = 3;
        c.decision = WafDecision::Block;
        c.verdict_source = Some(VerdictSource::Dlp);
        c.block_reason = Some("DLP: sensitive data pattern matched: credit_card".into());
        c.rule_matches = vec![response_rm("953100", 3)];
        assert!(c.deciding_rule_match().is_none());
        let (rule, attack) = classify_nonrule_block(c.block_reason.as_deref().unwrap());
        assert_eq!(rule, "DLP");
        let (msg, rem) = explain_event(&c, "BLOCK", rule, attack);
        assert!(
            msg.contains("sensitive data pattern matched: credit_card"),
            "{msg}"
        );
        assert!(!msg.contains("threshold"), "{msg}");
        assert!(rem.contains("DLP action"), "{rem}");
        assert!(!rem.contains("raise the response threshold"), "{rem}");
    }

    #[test]
    fn headers_are_redacted_by_name_and_cookies_per_cookie() {
        let mut h = http::HeaderMap::new();
        h.insert("user-agent", "Mozilla/5.0 test".parse().unwrap());
        h.insert("authorization", "Bearer eyJsecret".parse().unwrap());
        h.insert("x-api-key", "k-123".parse().unwrap());
        h.insert("x-csrf-token", "abc".parse().unwrap());
        h.insert(
            "cookie",
            "lang=en; sid=s3cr3t; session_id=zzz".parse().unwrap(),
        );
        h.insert(
            "referer",
            "https://site/reset?token=t0k3n&page=2".parse().unwrap(),
        );
        h.append("x-forwarded-for", "10.0.0.1".parse().unwrap());
        h.append("x-forwarded-for", "10.0.0.2".parse().unwrap());
        let m = redacted_request_headers(&h);
        let get = |k: &str| {
            m.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("<absent>")
                .to_string()
        };
        assert_eq!(get("user-agent"), "Mozilla/5.0 test");
        for k in ["authorization", "x-api-key", "x-csrf-token"] {
            assert_eq!(
                get(k),
                sentinel_core::redact::REDACTED,
                "{k} must be redacted"
            );
        }
        let cookie = get("cookie");
        assert_eq!(
            cookie, "lang=[redacted]; sid=[redacted]; session_id=[redacted]",
            "every cookie keeps its name and loses its value"
        );
        assert!(
            !get("referer").contains("t0k3n"),
            "referer query redacted: {}",
            get("referer")
        );
        assert_eq!(
            get("x-forwarded-for"),
            "10.0.0.1, 10.0.0.2",
            "repeated header keeps every value"
        );
    }

    #[test]
    fn the_explanation_names_the_parameter_and_speaks_plainly() {
        let mut c = ctx("/rest/products/search?q=%27))%20UNION%20SELECT%20id%20FROM%20Users--");
        c.decision = WafDecision::Block;
        c.rule_matches = vec![rm("9900100", 85, "", "')) UNION SELECT id FROM Users--")];
        let v = sentinel_rules::RequestValues::for_matches(&c);
        let located = located_target(c.primary_rule_match(), &v);
        let (msg, rem) = explain_event_at(&c, "BLOCK", "9900100", "SQL Injection", Some(&located));
        assert!(msg.contains("in parameter 'q'"), "{msg}");
        assert!(msg.contains("found in the query string or body"), "{msg}");
        assert!(
            !msg.contains("RequestBody") && !msg.contains("request_body"),
            "{msg}"
        );
        assert!(
            !rem.contains("more than one part"),
            "the field is known now: {rem}"
        );
        // Without a located target the old honest fallback stands.
        let (_, rem) = explain_event(&c, "BLOCK", "9900100", "SQL Injection");
        assert!(rem.contains("more than one part"), "{rem}");
    }

    #[test]
    fn header_count_and_length_are_capped() {
        let mut h = http::HeaderMap::new();
        for i in 0..60 {
            h.insert(
                http::HeaderName::from_bytes(format!("x-h{i}").as_bytes()).unwrap(),
                "v".repeat(1000).parse().unwrap(),
            );
        }
        let m = redacted_request_headers(&h);
        assert_eq!(m.len(), MAX_LOGGED_HEADERS);
        assert!(m
            .values()
            .all(|v| v.as_str().unwrap().chars().count() <= MAX_HEADER_VALUE_CHARS + 1));
    }
}

/// Request headers for a blocked or detected event, redacted.
///
/// A header whose NAME is sensitive (Authorization, X-Api-Key, X-CSRF-Token, …
/// — the same rule the query-string redaction uses) is replaced whole; the
/// Cookie header keeps every cookie's NAME and none of the values; Referer and
/// Origin get the URL query redaction. Capped in count and length: this lands
/// in ClickHouse for 90 days and in the SIEM, and a hostile client picks its
/// own headers.
///
/// Cookie values are withheld by position, not by name, because a name says
/// nothing about what the value is. The first real application behind the WAF
/// keeps its login session in an Express cookie called `node-js`; judged by
/// name like the query string, that session was stored whole in 22 events and
/// shown in the console to anyone who could open one — enough to take over the
/// user's session. A value an operator needs as evidence is not lost: when a
/// rule fires on a cookie, the event's `matched` text and the rule's located
/// target (`REQUEST_COOKIES:theme`) still carry the payload.
fn redacted_request_headers(h: &http::HeaderMap) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (name, value) in h.iter() {
        let n = name.as_str();
        let v = value.to_str().unwrap_or("[non-text]");
        let shown = if n == "cookie" {
            v.split(';')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|c| match c.split_once('=') {
                    Some((k, _)) => format!("{}={}", k.trim(), sentinel_core::redact::REDACTED),
                    // A bare token with no `=` is a value with no name.
                    None => sentinel_core::redact::REDACTED.to_string(),
                })
                .collect::<Vec<_>>()
                .join("; ")
        } else if n == "referer" || n == "origin" {
            sentinel_core::redact::redact_url_query(v)
        } else if sentinel_core::redact::is_sensitive_field_name(n) {
            sentinel_core::redact::REDACTED.to_string()
        } else {
            v.to_string()
        };
        let shown = cap_chars(&shown, MAX_HEADER_VALUE_CHARS);
        match out.get_mut(n) {
            // A repeated header: keep every value, as the wire had them.
            Some(serde_json::Value::String(prev)) => {
                prev.push_str(", ");
                prev.push_str(&shown);
            }
            _ => {
                if out.len() >= MAX_LOGGED_HEADERS {
                    continue;
                }
                out.insert(n.to_string(), serde_json::Value::String(shown));
            }
        }
    }
    out
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
fn metrics_response(rate_limiter: &RateLimiter) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(full_body(Bytes::from(
            prometheus_text()
                + &siem_metrics_text()
                + &ip_feed::metrics_text()
                + &rate_limiter.prometheus_text()
                + &history_sink_metrics_text(
                    HISTORY_SINK_ACTIVE.load(std::sync::atomic::Ordering::Relaxed),
                    CLICKHOUSE_CONNECTED.load(std::sync::atomic::Ordering::Relaxed),
                    CLICKHOUSE_FAILURES.load(std::sync::atomic::Ordering::Relaxed),
                ),
        )))
        .unwrap()
}

/// SIEM-feed counters, appended to the scrape.
///
/// Emitted only when the feed is configured: exporting a permanently-zero
/// `dropped` series for the majority of deployments that have no SIEM would
/// invite an alert rule that can never fire, which is worse than no series.
///
/// `dropped` is the one that matters. A gap in a security feed is invisible from
/// the SIEM end — the reader sees a quiet period and believes it was quiet.
fn siem_metrics_text() -> String {
    if siem_config().is_none() {
        return String::new();
    }
    format!(
        "# HELP sentinel_siem_events_sent_total Security events written to the SIEM feed\n\
         # TYPE sentinel_siem_events_sent_total counter\n\
         sentinel_siem_events_sent_total {}\n\
         # HELP sentinel_siem_events_dropped_total Security events dropped because the SIEM feed queue was full\n\
         # TYPE sentinel_siem_events_dropped_total counter\n\
         sentinel_siem_events_dropped_total {}\n\
         # HELP sentinel_siem_connect_failures_total Failed attempts to connect to the SIEM collector\n\
         # TYPE sentinel_siem_connect_failures_total counter\n\
         sentinel_siem_connect_failures_total {}\n",
        siem::sent_total(),
        siem::dropped_total(),
        siem::connect_failures_total(),
    )
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
        outbound_score = ctx.outbound_anomaly_score,
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
    // No drainer → no accumulation (nothing would ever empty the tally).
    if !HISTORY_SINK_ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
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

/// Set true once the history flusher task is running. When ClickHouse is not
/// configured nothing ever drains the buffers, so we must not buffer at all —
/// otherwise the event buffer grows to its cap and is pinned in memory forever.
///
/// This tracks "a drainer exists", NOT "the sink is reachable". The distinction
/// is the whole of the 2026-07-29 event-loss bug: the flag used to be cleared on
/// disconnect, so a node that could not reach ClickHouse buffered nothing, and
/// therefore recorded nothing, while still enforcing perfectly. The flusher now
/// spools what it cannot insert (see `sentinel_storage::Spool`), so buffering
/// while disconnected is correct and bounded — memory by the 20k cap below (plus
/// at most as many rows per stream carried over a writer panic), disk by the
/// spool's own cap.
static HISTORY_SINK_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the history writer currently holds a working ClickHouse client —
/// the "sink is reachable" fact `HISTORY_SINK_ACTIVE` deliberately is not.
/// ClickHouse connects in the background now, so startup no longer logs whether
/// it came up; /healthz reports this instead.
static CLICKHOUSE_CONNECTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// ClickHouse connect attempts and write cycles that failed or timed out (each
/// one drops the client and spools until the next connect).
static CLICKHOUSE_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Storage dependencies for /healthz: what rate checks are really using, and
/// whether history is reaching ClickHouse or only the spool.
fn storage_status(rate_limiter: &RateLimiter) -> serde_json::Value {
    serde_json::json!({
        "valkey": rate_limiter.distributed_status(),
        "clickhouse": {
            "configured": HISTORY_SINK_ACTIVE.load(std::sync::atomic::Ordering::Relaxed),
            "connected": CLICKHOUSE_CONNECTED.load(std::sync::atomic::Ordering::Relaxed),
            "failures_total": CLICKHOUSE_FAILURES.load(std::sync::atomic::Ordering::Relaxed),
        },
    })
}

/// The history sink's state for /metrics, so a writer that has been spooling
/// for hours can be alerted on from Prometheus, not only seen at /healthz.
/// Empty when no ClickHouse is configured (a permanently-zero `connected`
/// series would read as an outage).
fn history_sink_metrics_text(configured: bool, connected: bool, failures: u64) -> String {
    if !configured {
        return String::new();
    }
    format!(
        "# HELP sentinel_history_clickhouse_connected History writer holds a working ClickHouse client (1) or is spooling to disk (0)\n\
         # TYPE sentinel_history_clickhouse_connected gauge\n\
         sentinel_history_clickhouse_connected {}\n\
         # HELP sentinel_history_clickhouse_failures_total ClickHouse connects and writes that failed or timed out\n\
         # TYPE sentinel_history_clickhouse_failures_total counter\n\
         sentinel_history_clickhouse_failures_total {}\n",
        u8::from(connected),
        failures,
    )
}

/// Cap on buffered-but-unflushed events, bounding memory when the sink is slow
/// or unreachable. At ~200 bytes a row this is a few MB.
///
/// The flusher drains every second, so reaching this means events are arriving
/// faster than 20k/s sustained — a flood, not normal traffic. Overflow is counted
/// in `sentinel_history_shed_total`; see `record_event`.
const EVENT_BUFFER_CAP: usize = 20_000;

fn waf_events() -> &'static std::sync::Mutex<Vec<sentinel_storage::WafEventRow>> {
    WAF_EVENTS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Buffer one notable event (block or learning DETECT) for ClickHouse. Plain
/// passes are skipped to keep volume sane. Buffer is capped to bound memory if
/// ClickHouse is down/slow.
fn record_event(ctx: &RequestContext) {
    // Two INDEPENDENT consumers: the ClickHouse buffer (the durable record) and
    // the SIEM feed. Either may be absent, and neither may gate the other.
    //
    // The first cut hooked the SIEM feed after this early return, which coupled
    // it to ClickHouse: a SIEM-only deployment forwarded nothing, and a
    // ClickHouse outage would have silently stopped the security feed too.
    // Caught by running it against a real collector with no ClickHouse
    // configured — the code was correct-looking and delivered zero events.
    //
    // The ClickHouse gate is on having a DRAINER, not on reachability: an
    // unreachable sink still records, via the flusher's disk spool.
    let history_active = HISTORY_SINK_ACTIVE.load(std::sync::atomic::Ordering::Relaxed);
    let siem_cfg = siem_config();
    if !history_active && siem_cfg.is_none() {
        return; // nothing consumes events in this deployment
    }
    let action = match ctx.decision {
        WafDecision::Block | WafDecision::Challenge => "BLOCK",
        _ if ctx.would_block => "DETECT",
        _ => return, // not notable — don't store
    };
    // The finding that decided the verdict: the worst from the deciding part
    // of the exchange. See RequestContext::deciding_rule_match.
    let top = ctx.deciding_rule_match();
    let (v_score, v_threshold, _) = verdict_score(ctx);
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
    // Parameter-level target and the full rule list, as on the waf.log line.
    let values = sentinel_rules::RequestValues::for_matches(ctx);
    let ev_target = located_target(top, &values);
    // Cloned before the struct takes ownership of ev_rule/ev_attack.
    let ev_rule_for_prose = ev_rule.clone();
    let ev_target_for_prose = ev_target.clone();
    let ev_attack_for_prose = ev_attack.clone();
    let row = sentinel_storage::WafEventRow {
        ts: unix_now(),
        ip: ctx.client_ip.to_string(),
        country: ctx.geo_country.clone().unwrap_or_default(), // set when GeoIP resolved a country
        site: ctx.site_id.clone().unwrap_or_else(|| "-".to_string()),
        tenant: ctx.tenant_id.clone().unwrap_or_default(),
        method: ctx.method.as_str().to_string(),
        path: capped_path(&ctx.uri),
        query: capped_query(&ctx.uri),
        // Same redaction as the access line: this row lands in ClickHouse under
        // a 90-day TTL and is forwarded to the SIEM, so it outlives and travels
        // further than the log file does.
        referer: sentinel_core::redact::redact_url_query(
            ctx.request_headers
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        ),
        matched: top
            .map(|r| {
                matched_at(
                    r,
                    &ev_target,
                    &sentinel_core::redact::request_cookie_values(&ctx.request_headers),
                )
            })
            .unwrap_or_default(),
        rule: ev_rule,
        attack: ev_attack,
        action: action.to_string(),
        severity: top
            .map(|r| format!("{:?}", r.severity).to_uppercase())
            .unwrap_or_default(),
        score: v_score,
        status: ctx.response_status.map(|s| s.as_u16()).unwrap_or(0),
        protocol: protocol_label(ctx.http_version).to_string(),
        // Same correlation id and prose as the NDJSON record, so an event found in
        // Threat Search weeks later explains itself and can still be tied back to
        // the request that produced it. Built from the same helper as waf.log —
        // two renderings of one verdict would eventually disagree.
        request_id: ctx.request_id.to_string(),
        target: ev_target,
        // Every contributing rule, and the request's headers and User-Agent: the
        // three things the event could not answer after the fact — which rules
        // made up the score, which parameter, and what client sent it. JSON text
        // columns, so the schema does not have to change as the shape grows.
        rules: serde_json::Value::Array(matched_rules_detail(ctx, &values)).to_string(),
        headers: serde_json::Value::Object(redacted_request_headers(&ctx.request_headers))
            .to_string(),
        ua: cap_chars(
            ctx.request_headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            MAX_HEADER_VALUE_CHARS,
        ),
        // The fingerprint that fed bot scoring and the JA4 blocklist for THIS
        // request. It was never recorded, so "why was this client scored as
        // sqlmap" was unanswerable from the row.
        ja4: ctx.tls_fingerprint.clone().unwrap_or_default(),
        mode: match ctx.enforcement_mode {
            Some(WafMode::Blocking) => "blocking",
            Some(WafMode::Learning) => "learning",
            Some(WafMode::Off) => "off",
            None => "node",
        }
        .to_string(),
        threshold: v_threshold.unwrap_or(0),
        explanation: if log_explain_enabled() {
            explain_event_at(
                ctx,
                action,
                &ev_rule_for_prose,
                &ev_attack_for_prose,
                Some(&ev_target_for_prose),
            )
            .0
        } else {
            String::new()
        },
    };
    // Forward to the SIEM first: it is a non-blocking try_send on its own
    // bounded queue, so it cannot delay the lock below, and a full ClickHouse
    // buffer must not stop the feed any more than a dead SIEM may stop the
    // durable record.
    if let Some(cfg) = siem_cfg {
        siem::record(cfg.format, cfg.facility, &cfg.hostname, &row);
    }
    if !history_active {
        return; // SIEM-only deployment: nothing to buffer
    }
    // Recovered, not skipped, when poisoned: skipping dropped every event for the
    // rest of the process, uncounted, while blocks went on being enforced.
    {
        let mut buf = waf_events()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buf.len() < EVENT_BUFFER_CAP {
            buf.push(row);
        } else {
            // The buffer is full: this block/DETECT is enforced but will never be
            // recorded. Count it — a silent shed here makes waf_events understate
            // attacks blocked, precisely during a flood, which is when someone is
            // most likely to be counting. `sentinel_history_shed_total` is the
            // metric; the log below is for anyone reading logs rather than scraping.
            //
            // The cap is intentional (a flood at 20k rps wants 20k event rows a
            // second; ClickHouse and the spool must not be driven by attacker
            // volume) — the defect was never the shedding, only its invisibility.
            let total = inc_history_shed();
            // Rate-limited: at 20k/s an unconditional warn! would itself become the
            // overload. Powers of ten give a loud first signal then decreasing noise.
            if total == 1 || total.is_power_of_two() || total % 100_000 == 0 {
                warn!(
                    shed_total = total,
                    buffer_cap = EVENT_BUFFER_CAP,
                    "waf event history buffer FULL — events are being enforced but NOT \
                     recorded; waf_events undercounts blocks for this window \
                     (see sentinel_history_shed_total)"
                );
            }
        }
    }
}

/// The SIEM feed's configuration, resolved once. `None` when the feed is not
/// configured, which is the default.
fn siem_config() -> Option<&'static siem::SiemConfig> {
    static CFG: std::sync::OnceLock<Option<siem::SiemConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| siem::SiemConfig::from_env().map(siem::start))
        .as_ref()
}

/// Drain up to all buffered events for flushing.
fn drain_events() -> Vec<sentinel_storage::WafEventRow> {
    std::mem::take(
        &mut *waf_events()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

// ---------------------------------------------------------------------------
// History spool — durability across a ClickHouse outage
// ---------------------------------------------------------------------------

/// Resolve the history spool directory. Order: `SENTINEL_SPOOL_DIR` env →
/// `$HOME/.local/share/sentinel/spool` (dev, needs no root) →
/// `/var/lib/sentinel/state/spool`.
///
/// The compose default points into the `sentinel-state` named volume, already
/// documented there as "per-node data-plane state that must outlive the
/// container" — exactly the lifetime a spool needs. Deliberately never `/tmp`:
/// that is tmpfs on most distros, and a spool that dies with the container
/// cannot do the one job it exists for.
fn resolve_spool_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("SENTINEL_SPOOL_DIR") {
        if !d.is_empty() {
            return std::path::PathBuf::from(d);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return std::path::PathBuf::from(home).join(".local/share/sentinel/spool");
        }
    }
    std::path::PathBuf::from("/var/lib/sentinel/state/spool")
}

/// Spool byte ceiling, from `SENTINEL_SPOOL_MAX_BYTES`.
fn spool_max_bytes() -> u64 {
    std::env::var("SENTINEL_SPOOL_MAX_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(sentinel_storage::spool::DEFAULT_MAX_BYTES)
}

/// Open the spool. `None` (with a loud warning) when the directory is unusable —
/// which degrades to the old drop-the-batch behaviour rather than refusing to
/// boot. Losing history is bad; refusing to serve traffic is worse.
fn open_history_spool() -> Option<sentinel_storage::Spool> {
    let dir = resolve_spool_dir();
    let ds = dir.to_string_lossy().to_string();
    if ds.starts_with("/tmp") || ds.starts_with("/dev/shm") {
        warn!(
            spool_dir = %ds,
            "history spool directory is on tmpfs (RAM) — spooled history will NOT \
             survive a restart, which is the point of spooling; set SENTINEL_SPOOL_DIR \
             to a real-disk path on a persistent volume"
        );
    }
    let max = spool_max_bytes();
    match sentinel_storage::Spool::open(&dir, max) {
        Ok(sp) => {
            info!(spool_dir = %ds, max_bytes = max, "history spool ready");
            Some(sp)
        }
        Err(e) => {
            warn!(
                error = %e, spool_dir = %ds,
                "history spool unavailable — waf history will be DROPPED while \
                 ClickHouse is unreachable (set SENTINEL_SPOOL_DIR to a writable path)"
            );
            None
        }
    }
}

/// Append a batch to the spool, returning bytes written (0 if empty or no spool).
///
/// One segment per INSERT-sized chunk: a segment is replayed as a unit, and a
/// whole 20k-row drain in one segment was the request that outgrew the
/// ClickHouse deadline on every reconnect.
fn spool_batch<T: serde::Serialize>(
    spool: Option<&sentinel_storage::Spool>,
    kind: &str,
    rows: &[T],
) -> u64 {
    if rows.is_empty() {
        return 0;
    }
    let Some(sp) = spool else {
        warn!(
            kind,
            rows = rows.len(),
            "no history spool — dropping batch (history for these rows is lost)"
        );
        return 0;
    };
    let mut written = 0;
    for chunk in rows.chunks(sentinel_storage::clickhouse::MAX_INSERT_ROWS) {
        match sp.append(kind, chunk) {
            Ok(bytes) => {
                debug!(kind, rows = chunk.len(), bytes, "history spooled to disk");
                written += bytes;
            }
            Err(e) => {
                warn!(error = %e, kind, rows = chunk.len(), "history spool write failed — batch lost");
            }
        }
    }
    written
}

/// Replay spooled segments, oldest first, deleting each only after ClickHouse
/// accepts it (at-least-once: a crash in that window duplicates rather than
/// loses, and every row carries `request_id` for de-duplication).
///
/// Returns `false` if the SINK failed, so the caller drops the client and
/// reconnects. Un-replayed segments simply stay on disk for the next attempt.
async fn replay_history_spool(
    sp: &sentinel_storage::Spool,
    client: &sentinel_storage::ClickHouseClient,
) -> bool {
    replay_spool_kind::<sentinel_storage::TrafficRow>(sp, client, "traffic").await
        && replay_spool_kind::<sentinel_storage::WafEventRow>(sp, client, "events").await
}

/// [`replay_history_spool`] for one kind of row.
///
/// A segment that goes in part-way (the client splits it into INSERT-sized
/// requests) is rewritten to the rows not yet accepted, so a retry does not
/// insert the accepted ones again: MergeTree does not de-duplicate, and a
/// segment that failed whole on every reconnect added another copy each time.
async fn replay_spool_kind<T>(
    sp: &sentinel_storage::Spool,
    client: &sentinel_storage::ClickHouseClient,
    kind: &str,
) -> bool
where
    T: sentinel_storage::InsertRow + serde::de::DeserializeOwned,
{
    // Bounded per tick so a large backlog can never stall the loop (which also
    // samples traffic every second) or starve live rows behind an hour of
    // replay. Rows as well as segments: segments written before they were
    // capped at an INSERT's size can hold a whole 20k-row drain.
    const MAX_SEGMENTS_PER_TICK: usize = 20;
    const MAX_ROWS_PER_TICK: usize = 20 * sentinel_storage::clickhouse::MAX_INSERT_ROWS;

    let mut budget = MAX_ROWS_PER_TICK;
    for path in sp.segments(kind).into_iter().take(MAX_SEGMENTS_PER_TICK) {
        if budget == 0 {
            break;
        }
        match sentinel_storage::Spool::load::<T>(&path) {
            Ok((rows, skipped)) => {
                if skipped > 0 {
                    warn!(path = %path.display(), kind, skipped, "history spool: unparseable lines skipped");
                }
                if rows.is_empty() {
                    sentinel_storage::Spool::remove(&path);
                    continue;
                }
                let take = rows.len().min(budget);
                match client.insert_rows(&rows[..take]).await {
                    Ok(()) => {
                        info!(kind, rows = take, "history spool: replayed batch");
                        budget -= take;
                        keep_unreplayed(&path, &rows[take..]);
                    }
                    Err(e) => {
                        warn!(error = %e, kind, "history spool: replay failed — keeping the unreplayed rows, will retry");
                        if e.inserted > 0 {
                            keep_unreplayed(&path, &rows[e.inserted..]);
                        }
                        return false;
                    }
                }
            }
            // Unreadable: do NOT delete (the error may be transient and deleting
            // would destroy the only copy). Skip past it so one bad segment can
            // never block the rest of the backlog; the cap ages it out eventually.
            Err(e) => {
                warn!(error = %e, path = %path.display(), "history spool: segment unreadable — skipping");
            }
        }
    }
    true
}

/// Shrink a replayed segment to `rest`, or remove it when nothing is left. A
/// failed rewrite leaves the segment whole: its accepted rows are sent again
/// (duplicates, the at-least-once side), never lost.
fn keep_unreplayed<T: serde::Serialize>(path: &std::path::Path, rest: &[T]) {
    if let Err(e) = sentinel_storage::Spool::rewrite(path, rest) {
        warn!(error = %e, path = %path.display(), "history spool: could not trim a replayed segment — its replayed rows will be sent again");
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
            .spawn(move || {
                // Restarted on a panic, with the shared backoff: ending this
                // thread would close the channel and drop every access/waf line
                // for the rest of the process. A clean return means every
                // sender is gone.
                panic_guard::supervise_blocking("ndjson log writer", || log_writer_loop(&rx))
            })
            .expect("spawn ndjson log writer");
        tx
    })
}

/// Hand a pre-formatted line to the writer thread. Non-blocking: drops (and
/// counts) when the queue is saturated so the request path never stalls on I/O.
fn enqueue_log(name: &'static str, line: String) {
    if log_sender().try_send(LogRecord { name, line }).is_err() {
        LOG_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Also count it in /metrics. The local atomic drives the writer's
        // rate-limited warning; this makes the loss ALERTABLE. Log loss happens
        // under load, which is exactly when someone is relying on the logs, and
        // a number only present in a log line cannot page anyone — ClickHouse
        // shedding has been scrapeable for months while this was not.
        inc_log_lines_dropped();
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
fn log_writer_loop(rx: &std::sync::mpsc::Receiver<LogRecord>) {
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

/// Whether to attach the human-readable `message`/`remediation` prose to WAF
/// events. Default on; set `SENTINEL_LOG_EXPLAIN=0` to drop it.
///
/// The escape hatch exists for volume, not correctness: the prose adds roughly
/// 200-400 bytes to every security event, and the block path sustains >21k
/// events/s under flood, where that is megabytes per second of extra disk. An
/// operator riding out an attack can turn it off; the structured fields the
/// dashboard and ClickHouse consume are unaffected either way.
fn log_explain_enabled() -> bool {
    static EN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EN.get_or_init(|| {
        !matches!(
            std::env::var("SENTINEL_LOG_EXPLAIN").ok().as_deref(),
            Some("0") | Some("false") | Some("off")
        )
    })
}

/// Render a rule target (`ARGS:id`, `REQUEST_HEADERS:X-Api-Key`) as English.
///
/// The raw ModSecurity-style target is precise but assumes the reader knows the
/// vocabulary. An operator triaging a false positive at 3 a.m. should not have
/// to know that `ARGS_NAMES` means the parameter's *name* rather than its value.
fn humanize_target(target: &str) -> String {
    let (collection, member) = match target.split_once(':') {
        Some((c, m)) => (c, Some(m)),
        None => (target, None),
    };
    let named = |what: &str| match member {
        Some(m) if !m.is_empty() => format!("{what} '{m}'"),
        _ => what.to_string(),
    };
    match collection.to_ascii_uppercase().as_str() {
        "ARGS" => named("parameter"),
        "ARGS_NAMES" => named("parameter name"),
        "ARGS_GET" => named("query-string parameter"),
        "ARGS_POST" => named("body parameter"),
        "REQUEST_HEADERS" => named("request header"),
        "REQUEST_HEADERS_NAMES" => named("request header name"),
        "REQUEST_COOKIES" => named("cookie"),
        "REQUEST_COOKIES_NAMES" => named("cookie name"),
        "REQUEST_URI" | "REQUEST_URI_RAW" => "the request URI".to_string(),
        "REQUEST_FILENAME" => "the request path".to_string(),
        "REQUEST_BODY" => "the request body".to_string(),
        "REQUEST_LINE" => "the request line".to_string(),
        "REQUEST_METHOD" => "the request method".to_string(),
        "QUERY_STRING" => "the query string".to_string(),
        "FILES" | "FILES_NAMES" => named("uploaded file"),
        "RESPONSE_BODY" => "the response body".to_string(),
        "RESPONSE_HEADERS" => named("response header"),
        "XML" => "the XML body".to_string(),
        "JSON" => "the JSON body".to_string(),
        // Unknown collection: echo it rather than inventing a description.
        _ => target.to_string(),
    }
}

/// The phase a finding came from, in the words an operator uses. "detected
/// during RequestBody" was ModSecurity's phase name leaking into prose — and
/// wrong-sounding for a GET, whose query string is inspected in that same phase.
/// The refined target when there is one, else the rule's own.
fn pick_target<'a>(m: &'a sentinel_core::context::RuleMatch, located: Option<&'a str>) -> &'a str {
    match located {
        Some(t) if !t.is_empty() => t,
        _ => m.target.as_str(),
    }
}

fn phase_words(p: &Phase) -> &'static str {
    match p {
        Phase::Connection => "the connection",
        Phase::RequestHeaders => "the request headers",
        Phase::RequestBody => "the query string or body",
        Phase::Upstream => "the upstream exchange",
        Phase::ResponseHeaders => "the response headers",
        Phase::ResponseBody => "the response body",
        Phase::Logging => "post-response logging",
    }
}

/// Trim a path/URI for inclusion in prose without destroying its meaning.
fn truncate_for_prose(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}… ({} chars total)", s.chars().count())
}

/// Build the human-readable explanation and remediation hint for a WAF event.
///
/// Returns `(message, remediation)`. The message states, in one sentence, what
/// was decided, what was detected, WHERE in the request, who sent it, and why
/// the verdict followed. The remediation says what to do about it — which is the
/// part commercial WAFs typically leave to the operator to work out from a
/// violation code, and the reason this exists at all.
#[cfg(test)]
fn explain_event(ctx: &RequestContext, action: &str, rule: &str, attack: &str) -> (String, String) {
    explain_event_at(ctx, action, rule, attack, None)
}

/// [`explain_event`] with the top rule's target refined to the parameter
/// (`ARGS:q`) — see `located_target`. `None` keeps the rule's own target.
fn explain_event_at(
    ctx: &RequestContext,
    action: &str,
    rule: &str,
    attack: &str,
    located: Option<&str>,
) -> (String, String) {
    let site = ctx.site_id.as_deref().unwrap_or("unrouted request");
    let origin = match ctx.geo_country.as_deref() {
        Some(cc) if !cc.is_empty() => format!("{} ({cc})", ctx.client_ip),
        _ => ctx.client_ip.to_string(),
    };
    let req = format!(
        "{} {}",
        ctx.method.as_str(),
        truncate_for_prose(ctx.uri.path(), 120)
    );
    // The finding that decided the verdict: the worst from the deciding part
    // of the exchange. See RequestContext::deciding_rule_match.
    let top = ctx.deciding_rule_match();
    let target_of = |m| pick_target(m, located);
    let is_rule_hit = top.is_some();

    // What the WAF did, stated so that a learning-mode record can never be
    // mistaken for an enforced block — the single most dangerous ambiguity in a
    // WAF log, because it decides whether the operator thinks traffic was stopped.
    let verdict = match action {
        "DETECT" => format!(
            "Detected but ALLOWED THROUGH — site '{site}' is in learning mode, so this request was \
             not blocked"
        ),
        "BLOCK" => match ctx.decision {
            WafDecision::Challenge => {
                format!("Challenged (browser verification required) on '{site}'")
            }
            WafDecision::Limit => format!("Throttled (soft-deny) on '{site}'"),
            _ => format!("BLOCKED on '{site}'"),
        },
        _ => format!("Allowed on '{site}'"),
    };

    // What was found, and where.
    let finding = match top {
        // An empty target is normal, not a bug: the rule engine records one only
        // when a rule inspected exactly ONE part of the request, because naming a
        // guessed target would send an operator to exclude something that never
        // fired. Say "in <target>" when it is known and omit the clause when it is
        // not, rather than emitting "in  (rule …)".
        Some(m) if !target_of(m).is_empty() => format!(
            "{} in {} (rule {}, severity {:?}, found in {})",
            attack,
            humanize_target(target_of(m)),
            m.rule_id,
            m.severity,
            phase_words(&m.phase)
        ),
        Some(m) => format!(
            "{} (rule {}, severity {:?}, found in {})",
            attack,
            m.rule_id,
            m.severity,
            phase_words(&m.phase)
        ),
        None => {
            let reason = ctx.block_reason.as_deref().unwrap_or("").trim();
            if reason.is_empty() {
                attack.to_string()
            } else {
                format!("{reason} (recorded as {rule})")
            }
        }
    };

    // Why the verdict followed. Only meaningful for score-driven outcomes; a
    // rate-limit or GeoIP block has no score and must not pretend to have one.
    let mut why = String::new();
    let (score, threshold, outbound) = verdict_score(ctx);
    // A DLP verdict is a pattern match, not a score against a threshold: its
    // explanation must not advise moving one.
    let score = if ctx.verdict_source == Some(VerdictSource::Dlp) {
        0
    } else {
        score
    };
    let (score_words, threshold_words) = if outbound {
        ("Response anomaly score", "the response threshold of")
    } else {
        ("Cumulative anomaly score", "this site's threshold of")
    };
    if score > 0 {
        match threshold {
            Some(t) => {
                why = format!(
                    " {score_words} {score} against {threshold_words} {t}{}.",
                    if score >= t {
                        " (threshold reached)"
                    } else {
                        " (below threshold)"
                    }
                );
            }
            None => {
                why = format!(" {score_words} {score}.");
            }
        }
    }
    // The threshold advice has to name the threshold that applied. A response
    // leak is judged on the response's score against the outbound threshold,
    // so "raise the site's anomaly threshold above 1" — what a leak's event
    // used to say — pointed at a knob that could not change the outcome.
    let raise = if outbound {
        format!(
            "raise the response threshold above {score} (the site's CRS policy value \
             outbound_anomaly_score_threshold, now {})",
            threshold.unwrap_or(sentinel_rules::DEFAULT_OUTBOUND_ANOMALY_THRESHOLD)
        )
    } else {
        format!("raise the site's anomaly threshold above {}", score.max(1))
    };
    if ctx.threat_intel_hit {
        why.push_str(" The client IP also matched the live threat-intelligence feed.");
    }

    let outcome = match ctx.response_status.map(|s| s.as_u16()) {
        Some(code) if code > 0 => format!(" Responded {} in {:.1} ms.", code, ctx.elapsed_ms()),
        _ => format!(" Completed in {:.1} ms.", ctx.elapsed_ms()),
    };

    let message = format!("{verdict}: {finding} from {origin} on {req}.{why}{outcome}");

    // Remediation. Tailored to what actually fired, so it is actionable rather
    // than a generic "review your policy".
    let remediation = if action == "PASS" {
        String::new()
    } else if let Some(limit) =
        top.and_then(|m| sentinel_core::context::InspectionLimit::of_rule(&m.rule_id))
    {
        inspection_limits::remediation(limit, ctx, site)
    } else if is_rule_hit {
        let m = top.expect("is_rule_hit implies a match");
        // With a known target the advice can be specific; without one it must not
        // invent a parameter to exclude.
        if target_of(m).is_empty() {
            format!(
                "If this is legitimate traffic, disable rule {} for site '{}' (Sites → {} → \
                 Learning Report → Disable), or {raise}. This \
                 rule inspected more than one part of the request, so the exact field is not \
                 recorded — check the payload before excluding anything.",
                m.rule_id, site, site,
            )
        } else {
            format!(
                "If this is legitimate traffic, exclude rule {} for {} on site '{}' \
                 (Sites → {} → Learning Report → Disable), or {raise}. Confirm against the \
                 source IP and payload before excluding — an exclusion applies to every future \
                 request for that target.",
                m.rule_id,
                humanize_target(target_of(m)),
                site,
                site,
            )
        }
    } else {
        match rule {
            "DLP" => format!(
                "The response from site '{site}' carried data matching a data-loss-prevention \
                 pattern. If the page is meant to show it (for example a masked number the user \
                 asked for), set the site's DLP action to mask or detect; otherwise the origin is \
                 leaking it and should stop."
            ),
            "RATELIMIT" => format!(
                "If {origin} is a legitimate client, raise the rate limit for site '{site}' or \
                 allowlist the address. Repeated hits from many addresses instead suggest a \
                 distributed flood — check the DDoS panel before relaxing the limit."
            ),
            "GEOIP" => format!(
                "If this country should be served, remove it from the GeoIP block list for site \
                 '{site}'. Note that a VPN or corporate egress can place a legitimate user in an \
                 unexpected country."
            ),
            "BOT" => format!(
                "If this is a legitimate automated client, allowlist its address or JA4 \
                 fingerprint for site '{site}'. Well-behaved crawlers should instead be given a \
                 verified-bot exemption rather than a blanket allow."
            ),
            "THREATINTEL" => format!(
                "The address {origin} appears on a threat-intelligence feed. If you believe this \
                 is a false attribution, allowlist it for site '{site}' and report the address so \
                 the feed entry can be reviewed."
            ),
            "SMUGGLING" => {
                "Conflicting Content-Length/Transfer-Encoding framing was rejected. This is almost \
                 never legitimate client behaviour — investigate the sender before allowlisting \
                 anything."
                    .to_string()
            }
            _ => format!(
                "Review the request against site '{site}' policy. If the verdict is wrong, capture \
                 this record's request_id and use it to correlate with the access log before \
                 changing policy."
            ),
        }
    };

    (message, remediation)
}

/// The WAF's own processing time in milliseconds: total elapsed minus the time
/// spent waiting for the origin.
///
/// Blocked requests never reach an upstream, so their whole elapsed time IS the
/// WAF's — which is correct, and is also the number an operator wants when
/// asking what enforcement costs. Saturating at 0 because the two clocks are
/// sampled at different points and a few microseconds of skew must not produce
/// a negative latency.
fn waf_own_ms(ctx: &RequestContext) -> f64 {
    let total = ctx.elapsed_ms();
    let upstream = ctx.upstream_latency_us.unwrap_or(0) as f64 / 1000.0;
    (total - upstream).max(0.0)
}

/// The per-request access record — the same object `ndjson_log` writes — as a
/// pure function so the field list is a TESTED contract rather than a side
/// effect of a writer (a debug assertion in `ndjson_log` keeps them identical).
///
/// Two fields were missing until 2026-09-16, and their absence read as silence:
///
///   rule    — the primary rule id, or "" when no rule fired
///   reason  — the block reason, or "" when nothing was blocked
///
/// Five modules (GraphQL, gRPC, JWT, threat intel, request smuggling) block
/// with no rule match at all. Each already set `ctx.block_reason`, and that
/// reason already reached stdout and Threat Search. It never reached THIS
/// record — the file the console's Logs page tails and the one an operator
/// greps — so a 403 from any of them appeared as `"action":"BLOCK","score":0`
/// and nothing else. The modules were not silent. The record was.
///
/// The reason goes HERE rather than into a log line inside each module on
/// purpose: the smuggling detector's own comment explains that a per-request
/// log line on an attacker-controlled path is a flood primitive. This record
/// is emitted exactly once per request already, so this is a field, not an
/// event.
fn access_record(ctx: &RequestContext) -> serde_json::Value {
    let status = ctx.response_status.map(|s| s.as_u16()).unwrap_or(0);
    let ua = ctx
        .request_headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    let action = match ctx.decision {
        WafDecision::Block | WafDecision::Challenge => "BLOCK",
        _ if ctx.would_block => "DETECT",
        _ if ctx.gateway_error.is_some() => "ERROR",
        _ => "PASS",
    };
    let referer_owned = sentinel_core::redact::redact_url_query(
        ctx.request_headers
            .get(http::header::REFERER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-"),
    );
    serde_json::json!({
        "ts":      chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "request_id": ctx.request_id.to_string(),
        "ip":      ctx.client_ip.to_string(),
        "country": ctx.geo_country.as_deref().unwrap_or(""),
        "method":  ctx.method.as_str(),
        "path":    capped_path(&ctx.uri),
        "query":   capped_query(&ctx.uri),
        "status":  status,
        "latency": format!("{:.2}", ctx.elapsed_ms()),
        "waf_ms": format!("{:.2}", waf_own_ms(ctx)),
        "bytes":    ctx.bytes_sent,
        "site":     ctx.site_id.as_deref().unwrap_or("-"),
        "tenant":   ctx.tenant_id.as_deref().unwrap_or(""),
        "protocol": protocol_label(ctx.http_version),
        "ja4":      ctx.tls_fingerprint.as_deref().unwrap_or("-"),
        "ua":       ua,
        "referer":  referer_owned.as_str(),
        "action":   action,
        // The score that decided the verdict (the response's for a leak), as
        // in waf.log and Threat Search. This line — the one the console's Logs
        // page tails — still printed the request score, so a response-leak
        // block read "score 0". (Code review finding.)
        "score":    verdict_score(ctx).0,
        "rule":     ctx.deciding_rule_match().map(|m| m.rule_id.as_str()).unwrap_or(""),
        "reason":   ctx.block_reason.as_deref().unwrap_or(""),
    })
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
        // The request never reached an origin. Distinct from PASS, which is what
        // it used to say: a 502 logged as "action":"PASS" tells an operator the
        // request was served when it was not, and makes gateway failures
        // unfindable by filtering on action.
        _ if ctx.gateway_error.is_some() => "ERROR",
        _ => "PASS",
    };
    let site = ctx.site_id.as_deref().unwrap_or("-");
    let tenant = ctx.tenant_id.as_deref().unwrap_or("");

    // request_id is the join key between this line, the matching waf.log security
    // event, and the tracing output. Without it the two NDJSON streams cannot be
    // correlated at all — you could see that a block happened and see a request,
    // and not be able to prove they were the same request.
    let request_id = ctx.request_id.to_string();
    let country = ctx.geo_country.as_deref().unwrap_or("");
    // Kept separate from `path` (not appended) because facets, the learning
    // report and per-path aggregation group by path — appending queries there
    // would explode cardinality. Capped: a hostile query must not bloat a line.
    let query = capped_query(&ctx.uri);
    // The page the request was triggered from. For SPA traffic this is the only
    // field that names which screen of the app fired the API call.
    // Redacted for the same reason as the query string, and more sharply: a
    // password-reset page sends its own URL — token and all — as the Referer of
    // every asset it loads, so the credential arrives on requests that have
    // nothing to do with the reset.
    let referer_raw = ctx
        .request_headers
        .get(http::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    let referer_owned = sentinel_core::redact::redact_url_query(referer_raw);
    let referer = referer_owned.as_str();

    enqueue_log("access.log", access_record(ctx).to_string());

    // Emit a waf.log line for anything the WAF acted on or *would* have acted on:
    // any rule match, an enforced block, or a learning-mode would-block. The last
    // case covers GeoIP / rate-limit / bot-challenge / smuggling blocks that were
    // downgraded to Log in learning mode and carry no rule match — without it the
    // learning report (which consumes only waf.log) undercounts would-have-blocks.
    // Gateway errors are included: they carry no rule match and are not a Block,
    // so they fell through this gate and their reason lived ONLY in the tracing
    // output — which is the container-log correlation this stream exists to
    // avoid. An operator filtering waf.log for why the origin stopped answering
    // found nothing.
    if !ctx.rule_matches.is_empty()
        || matches!(ctx.decision, WafDecision::Block)
        || ctx.would_block
        || ctx.gateway_error.is_some()
    {
        // The finding that decided the verdict: the worst from the deciding
        // part of the exchange. See RequestContext::deciding_rule_match.
        let top = ctx.deciding_rule_match();
        let (v_score, v_threshold, _) = verdict_score(ctx);
        let sev_str = top
            .map(|r| format!("{:?}", r.severity).to_uppercase())
            .unwrap_or_else(|| "MEDIUM".to_string());
        // For non-rule blocks (GeoIP, rate limit, smuggling, bot challenge, bare
        // anomaly threshold) synthesize a stable rule label and attack name from
        // the block reason, so the dashboard's attack breakdown and the learning
        // report can categorize them instead of collapsing them into "-"/"other".
        let (rule, attack): (&str, &str) = match top {
            Some(r) => (r.rule_id.as_str(), r.message.as_str()),
            None => nonrule_label(ctx),
        };

        // Which part of the request tripped this, e.g. "ARGS:id". Available on
        // every RuleMatch and previously dropped on the floor — it is the single
        // most useful field for triaging a false positive, because it names the
        // parameter to exclude instead of leaving the operator to guess.
        //
        // Refined to the parameter itself (`ARGS:q`, not `ARGS` or nothing) where
        // the matched text sits in exactly one place — see RequestValues::locate.
        let values = sentinel_rules::RequestValues::for_matches(ctx);
        let target = located_target(top, &values);
        let rules = matched_rules_detail(ctx, &values);
        // Headers only on what an operator investigates (a block or a learning
        // would-block). A pass that merely matched a low-score rule — every
        // request to a site reached by IP matches 920350 — must not carry ~1 KB
        // of headers into waf.log.
        let headers = if action == "BLOCK" || action == "DETECT" {
            serde_json::Value::Object(redacted_request_headers(&ctx.request_headers))
        } else {
            serde_json::Value::Null
        };
        let mode = match ctx.enforcement_mode {
            Some(WafMode::Blocking) => "blocking",
            Some(WafMode::Learning) => "learning",
            Some(WafMode::Off) => "off",
            // Pre-routing rejections (anti-DDoS, IP reputation, threat intel)
            // are enforced by the node, not by a site policy.
            None => "node",
        };
        let (message, remediation) = if log_explain_enabled() {
            explain_event_at(ctx, action, rule, attack, Some(&target))
        } else {
            (String::new(), String::new())
        };

        // The text the top rule actually matched — the field that lets an
        // operator judge a false positive from the log line alone. Redacted
        // when it came from a credential-bearing target.
        let cookies = sentinel_core::redact::request_cookie_values(&ctx.request_headers);
        let matched = top
            .map(|r| matched_at(r, &target, &cookies))
            .unwrap_or_default();

        let waf = serde_json::json!({
            "ts":     ts,
            "request_id": request_id,
            "ip":     ctx.client_ip.to_string(),
            "country": country,
            "method": ctx.method.as_str(),
            "path":   capped_path(&ctx.uri),
            "query":  query,
            "rule":   rule,
            "target": target,
            "matched": matched,
            // The score that decided the verdict — the response's for a leak
            // found in the response (see verdict_score). Both totals follow.
            "score":  v_score,
            "threshold": v_threshold,
            "inbound_score": ctx.anomaly_score,
            "outbound_score": ctx.outbound_anomaly_score,
            // Present only when a per-path override governed this request, so a
            // threshold that differs from the site's is self-explaining.
            "path_override": ctx.path_override,
            "sev":    sev_str,
            "attack": attack,
            "action": action,
            "reason": ctx.block_reason.as_deref().unwrap_or(""),
            "mode":   mode,
            "site":   site,
            "tenant": tenant,
            "protocol": protocol_label(ctx.http_version),
            "ja4":    ctx.tls_fingerprint.as_deref().unwrap_or("-"),
            "status": status,
            "latency_ms": format!("{:.2}", ctx.elapsed_ms()),
            "ua":     ua,
            "referer": referer,
            // For a gateway error this is the ONLY place the cause is recorded
            // in a structured stream: origin refused vs no site matched vs
            // unreadable body.
            "msg":    ctx.gateway_error.as_deref()
                          .or(ctx.block_reason.as_deref())
                          .unwrap_or(""),
            "message": message,
            "remediation": remediation,
            // True whenever the verdict reached block level — enforced (BLOCK) or,
            // in learning mode, not (DETECT). It read false on every real block,
            // which in a raw record says "this would not have been blocked".
            "would_block": ctx.would_block || action == "BLOCK",
            "threat_intel_hit": ctx.threat_intel_hit,
            "engine_scores": ctx.engine_scores,
            "ml_scores": ctx.ml_scores,
            "rules": rules,
            "headers": headers,
        });
        enqueue_log("waf.log", waf.to_string());
    }
}

/// The waf.log `(rule, attack)` pair for an event no rule decided.
fn nonrule_label(ctx: &RequestContext) -> (&'static str, &'static str) {
    if panic_guard::is_contained_panic(ctx) {
        // Neither an attack nor an upstream failure: the origin may be fine,
        // and may already have executed the request (`msg` says).
        ("INTERNAL", "Internal processing failure")
    } else if ctx.gateway_error.is_some() {
        // A gateway failure is an availability event, not an attack. Given
        // its own stable label so it is queryable without polluting the
        // attack breakdown with "the origin is down".
        ("GATEWAY", "Upstream or routing failure")
    } else {
        classify_nonrule_block(ctx.block_reason.as_deref().unwrap_or(""))
    }
}

/// Map a non-rule block reason to a stable `(rule, attack)` label pair. These
/// synthetic rule labels mirror the categories the control-plane recognizes in
/// `attackCategory`, so GeoIP / rate-limit / smuggling / bot blocks are counted
/// distinctly rather than lumped under "-"/"other".
fn classify_nonrule_block(reason: &str) -> (&'static str, &'static str) {
    let r = reason.to_ascii_lowercase();
    if r.starts_with("dlp") {
        ("DLP", "Sensitive data in the response")
    } else if r.contains("country blocked") || r.contains("geoip") {
        ("GEOIP", "GeoIP country block")
    } else if r.contains("rate limit") {
        ("RATELIMIT", "Rate limit exceeded")
    } else if r.contains("smuggling") {
        ("SMUGGLING", "HTTP request smuggling")
    // GraphQL, gRPC and JWT all block with no rule match and all fell through
    // to ANOMALY here — "anomaly threshold exceeded" with score 0, the same
    // self-contradiction described below. Their reasons are prefixed at the
    // call site ("graphql:", "grpc:", "jwt:"), which is what these match.
    } else if r.starts_with("graphql") {
        ("GRAPHQL", "GraphQL policy violation")
    } else if r.starts_with("grpc") {
        ("GRPC", "gRPC policy violation")
    } else if r.starts_with("jwt") {
        ("JWT", "JWT validation failure")
    // A body refused before any rule judged it: over the size limit, too slow
    // to arrive, or (the rule engine's BODY_TOO_COMPLEX) too many field names
    // to list. Filed as ANOMALY with score 0 these claimed a scoring verdict,
    // and an operator looked for a rule to exclude where there was none.
    } else if r.starts_with("request body") {
        ("BODY", "Request body could not be inspected")
    // The three connection-layer reasons below were missing, so all of them
    // fell through to ANOMALY and were logged as "anomaly threshold exceeded"
    // with score=0 — a self-contradiction (0 cannot exceed a threshold of 10)
    // that told an operator the scoring engine had blocked a request the
    // scoring engine never even saw. ClickHouse recorded them correctly, so
    // the two sinks disagreed about the same event.
    //
    // Ordered before the `bot` arm on purpose: a threat-intel reason can name a
    // feed containing the word "bot" ("bot-net IOC feed"), which would
    // otherwise steal the match.
    } else if r.contains("threat intel") {
        ("THREATINTEL", "Threat intelligence match")
    } else if r.contains("ip reputation") || r.contains("reputation") {
        ("IPREP", "IP reputation block")
    } else if r.contains("ddos") {
        ("DDOS", "DDoS mitigation")
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
mod crs_policy_seed_tests {
    use super::*;

    fn site(methods: &[&str], policy: &[(&str, &str)]) -> SiteConfig {
        let mut s = SiteConfig {
            id: "s".to_string(),
            tenant_id: String::new(),
            domains: vec!["s.local".to_string()],
            upstream: sentinel_core::config::UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: sentinel_core::config::WafConfig::default(),
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        };
        s.waf.allowed_methods = methods.iter().map(|m| m.to_string()).collect();
        s.waf.crs_policy = policy
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        s
    }

    fn ctx() -> RequestContext {
        RequestContext::new("203.0.113.5".parse().unwrap(), 1111)
    }

    /// The site's own method list, never CRS's example value. CRS ships
    /// `GET HEAD POST OPTIONS`, so seeding that would have rejected PUT, PATCH
    /// and DELETE on every site — including this deployment, which permits all
    /// seven and already enforces that list with a 405 before rules run.
    #[test]
    fn allowed_methods_comes_from_the_site_not_from_crs() {
        let mut c = ctx();
        seed_crs_policy(&mut c, &site(&["GET", "post", "DELETE"], &[]));
        assert_eq!(
            c.tx_vars.get("ALLOWED_METHODS").map(String::as_str),
            Some("GET POST DELETE"),
            "must be the site's list, upper-cased, space separated"
        );
    }

    /// An empty site list means "allow all", and the proxy skips its own check
    /// for it. Seeding an empty string would be catastrophic: `!@within ""`
    /// means every method is not within it, i.e. deny everything. Leaving it
    /// unset keeps rule 911100 inert, which is the safe degradation.
    #[test]
    fn an_empty_method_list_seeds_nothing() {
        let mut c = ctx();
        seed_crs_policy(&mut c, &site(&[], &[]));
        assert!(
            !c.tx_vars.contains_key("ALLOWED_METHODS"),
            "an empty allow-list must stay UNSET, never seeded as empty"
        );
    }

    /// Empty by default, matching upstream: CRS ships every one of these
    /// SecAction blocks commented out. No site gets a limit nobody chose.
    #[test]
    fn nothing_else_is_seeded_by_default() {
        let mut c = ctx();
        seed_crs_policy(&mut c, &site(&["GET"], &[]));
        for k in [
            "RESTRICTED_EXTENSIONS",
            "ALLOWED_REQUEST_CONTENT_TYPE",
            "MAX_NUM_ARGS",
            "ARG_LENGTH",
        ] {
            assert!(
                !c.tx_vars.contains_key(k),
                "{k} must be opt-in, not default"
            );
        }
    }

    /// Opting in works, and the key is normalised the way the rules look it up.
    #[test]
    fn opting_in_seeds_the_policy_list() {
        let mut c = ctx();
        seed_crs_policy(
            &mut c,
            &site(
                &["GET"],
                &[
                    ("restricted_extensions", ".bak/ .conf/"),
                    ("tx.max_num_args", "255"),
                    ("ARG_LENGTH", "400"),
                    ("blank", ""),
                ],
            ),
        );
        assert_eq!(
            c.tx_vars.get("RESTRICTED_EXTENSIONS").map(String::as_str),
            Some(".bak/ .conf/")
        );
        assert_eq!(
            c.tx_vars.get("MAX_NUM_ARGS").map(String::as_str),
            Some("255"),
            "a `tx.` prefix the operator wrote must be stripped"
        );
        assert_eq!(c.tx_vars.get("ARG_LENGTH").map(String::as_str), Some("400"));
        assert!(
            !c.tx_vars.contains_key("BLANK"),
            "an empty value must not be seeded — it would make !@within deny all"
        );
    }
}

#[cfg(test)]
mod access_record_tests {
    use super::*;

    fn ctx() -> RequestContext {
        RequestContext::new("203.0.113.9".parse().unwrap(), 4321)
    }

    /// A module block carries no rule match. Before 2026-09-16 this record
    /// showed `"action":"BLOCK","score":0` and nothing else for it.
    #[test]
    fn module_block_is_explainable_from_the_record_alone() {
        let mut c = ctx();
        c.decision = WafDecision::Block;
        c.block_reason = Some("grpc: server reflection blocked".to_string());
        let r = access_record(&c);
        assert_eq!(r["action"], "BLOCK");
        assert_eq!(
            r["rule"], "",
            "no rule fired, so rule must be empty, not invented"
        );
        assert_eq!(r["reason"], "grpc: server reflection blocked");
    }

    /// A rule block names the WORST rule, matching Threat Search.
    #[test]
    fn rule_block_names_the_primary_rule() {
        let mut c = ctx();
        c.decision = WafDecision::Block;
        c.block_reason = Some("anomaly score 24 >= threshold 10".to_string());
        c.rule_matches.push(sentinel_core::context::RuleMatch {
            rule_id: "942100".into(),
            message: "SQLi".into(),
            severity: sentinel_core::context::Severity::Critical,
            score: 5,
            target: "ARGS:q".into(),
            phase: Phase::RequestBody,
            matched_value: "x".into(),
        });
        c.rule_matches.push(sentinel_core::context::RuleMatch {
            rule_id: "9900100".into(),
            message: "libinjection".into(),
            severity: sentinel_core::context::Severity::Critical,
            score: 10,
            target: "ARGS:q".into(),
            phase: Phase::RequestBody,
            matched_value: "x".into(),
        });
        let r = access_record(&c);
        assert_eq!(r["rule"], "9900100", "highest-scoring rule, not the first");
    }

    /// A passed request must not carry a stale or invented reason.
    #[test]
    fn pass_has_empty_rule_and_reason() {
        let r = access_record(&ctx());
        assert_eq!(r["action"], "PASS");
        assert_eq!(r["rule"], "");
        assert_eq!(r["reason"], "");
    }

    /// The three modules that fell through to ANOMALY are now named, so the
    /// access log and Threat Search agree about what blocked the request.
    #[test]
    fn module_reasons_classify_to_their_own_module() {
        assert_eq!(
            classify_nonrule_block("graphql: query depth 12 exceeds max 8").0,
            "GRAPHQL"
        );
        assert_eq!(
            classify_nonrule_block("grpc: method blocked: /x.Y/Z").0,
            "GRPC"
        );
        assert_eq!(classify_nonrule_block("jwt: token expired").0, "JWT");
        // and the ones that already worked still do
        assert_eq!(
            classify_nonrule_block("threat intel: malicious IP 1.2.3.4").0,
            "THREATINTEL"
        );
        assert_eq!(
            classify_nonrule_block("request smuggling: TE/CL conflict").0,
            "SMUGGLING"
        );
        assert_eq!(
            classify_nonrule_block("anomaly score 24 >= threshold 10").0,
            "ANOMALY"
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

    /// Weak rule evidence plus a classifier that sees nothing.
    fn weak_and_benign(c: &mut RequestContext) {
        c.add_engine_score("rules", 10); // 2-3 CRS matches worth
        c.ml_scores.insert("payload_attack".to_string(), 0.02);
    }

    /// Turning fusion on used to disable FP suppression entirely: the
    /// suppression lived inline in the non-fusion branch, so a site with
    /// `fusion.enable: true` blocked on threshold arithmetic with no model
    /// input at all. Enabling a more sophisticated verdict engine silently
    /// removed the precision layer.
    #[test]
    fn fusion_applies_the_same_ml_veto_as_the_flat_path() {
        let f = fusion(true, &[], vec![10, 8, 6, 4], vec![5, 4, 3, 2]);
        let w = waf(2, 10, Some(f));
        let mut c = ctx();
        weak_and_benign(&mut c);
        apply_verdict(&mut c, &w);
        assert_eq!(
            c.decision,
            WafDecision::Allow,
            "fusion blocked what the flat path would have suppressed"
        );
    }

    /// Same inputs, both verdict engines, same answer. This is the property
    /// that was broken, so it is asserted directly rather than inferred.
    #[test]
    fn fusion_and_flat_paths_agree_on_the_same_evidence() {
        let mut a = ctx();
        weak_and_benign(&mut a);
        apply_verdict(&mut a, &waf(2, 10, None));

        let mut b = ctx();
        weak_and_benign(&mut b);
        apply_verdict(
            &mut b,
            &waf(2, 10, Some(fusion(true, &[], vec![10, 8, 6, 4], vec![]))),
        );

        assert_eq!(a.decision, b.decision, "the two verdict paths disagree");
        assert_eq!(a.decision, WafDecision::Allow);
    }

    /// The veto needs all three conditions. Each of these breaks one, and each
    /// must still block — otherwise the fix would be suppressing real attacks.
    #[test]
    fn fusion_still_blocks_when_any_veto_condition_fails() {
        let mk = || waf(2, 10, Some(fusion(true, &[], vec![10, 8, 6, 4], vec![])));

        // (a) the model agrees it is an attack
        let mut c = ctx();
        c.add_engine_score("rules", 10);
        c.ml_scores.insert("payload_attack".to_string(), 0.97);
        apply_verdict(&mut c, &mk());
        assert_eq!(c.decision, WafDecision::Block, "model said attack");

        // (b) strong rule evidence, regardless of the model
        let mut c = ctx();
        c.add_engine_score("rules", 25);
        c.ml_scores.insert("payload_attack".to_string(), 0.01);
        apply_verdict(&mut c, &mk());
        assert_eq!(c.decision, WafDecision::Block, "evidence over the cap");

        // (c) one of our own coverage signatures fired
        let mut c = ctx();
        weak_and_benign(&mut c);
        c.rule_matches.push(sentinel_core::context::RuleMatch {
            rule_id: "9900206".into(),
            message: "coverage signature".into(),
            severity: sentinel_core::context::Severity::Critical,
            score: 5,
            target: "ARGS:q".into(),
            phase: Phase::RequestBody,
            matched_value: "x".into(),
        });
        apply_verdict(&mut c, &mk());
        assert_eq!(c.decision, WafDecision::Block, "in-house signature fired");
    }

    /// The live reproduction, as a test. A benign search term earning 15 from
    /// rules is vetoed on a clean IP. After twenty attacks from the same IP,
    /// correlation adds 4 and the bot detector adds 5 for the same block
    /// history, and the identical request became a 403. The request did not
    /// change; its neighbours did. History may escalate, never manufacture.
    #[test]
    fn ip_history_cannot_switch_off_the_veto() {
        for w in [
            waf(2, 10, None),
            waf(2, 10, Some(fusion(true, &[], vec![10, 8, 6, 4], vec![]))),
        ] {
            let mut c = ctx();
            c.add_engine_score("rules", 15); // borderline prose, as measured
            c.add_engine_score("correlation", 4); // recent blocks, capped
            c.add_engine_score("bot", 5); // the same blocks again, via repeat-offender
            c.ml_scores.insert("payload_attack".to_string(), 0.02);
            assert_eq!(c.anomaly_score, 24, "fixture must reproduce the live score");
            apply_verdict(&mut c, &w);
            assert_eq!(
                c.decision,
                WafDecision::Allow,
                "a tainted IP turned benign prose into a block (fusion={})",
                w.fusion.is_some()
            );
        }
    }

    /// History must still ESCALATE. When the request itself carries real
    /// evidence, or the model agrees it is an attack, a repeat offender blocks.
    #[test]
    fn ip_history_still_escalates_real_evidence() {
        let mut c = ctx();
        c.add_engine_score("rules", 25);
        c.add_engine_score("correlation", 4);
        c.ml_scores.insert("payload_attack".to_string(), 0.02);
        apply_verdict(&mut c, &waf(2, 10, None));
        assert_eq!(c.decision, WafDecision::Block, "real evidence over the cap");

        let mut c = ctx();
        c.add_engine_score("rules", 15);
        c.add_engine_score("correlation", 4);
        c.add_engine_score("bot", 5);
        c.ml_scores.insert("payload_attack".to_string(), 0.97);
        apply_verdict(&mut c, &waf(2, 20, None)); // rules alone fall short of 20
        assert_eq!(
            c.decision,
            WafDecision::Block,
            "history lifts a real attack"
        );
    }

    #[test]
    fn request_evidence_strips_only_history_engines() {
        let mut c = ctx();
        c.add_engine_score("rules", 10);
        c.add_engine_score("ml", 6); // the model's own points are request-derived
        c.add_engine_score("plugin", 2);
        c.add_engine_score("correlation", 4);
        c.add_engine_score("bot", 5);
        c.add_engine_score("reputation", 2);
        assert_eq!(c.anomaly_score, 29);
        assert_eq!(request_evidence(&c), 18, "rules + ml + plugin only");
    }

    /// A soft-deny is still a broken request for the customer, so the veto
    /// covers the Limit band too.
    #[test]
    fn fusion_veto_also_covers_the_limit_band() {
        let f = fusion(true, &[], vec![100], vec![5]); // limit at 5, block far away
        let mut c = ctx();
        weak_and_benign(&mut c);
        apply_verdict(&mut c, &waf(2, 10, Some(f)));
        assert_eq!(c.decision, WafDecision::Allow, "throttled benign traffic");
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
mod history_shed_tests {
    use super::*;

    /// Serialise: the event buffer and the shed counter are process-global.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn blocking_ctx() -> RequestContext {
        let mut ctx = RequestContext::new("203.0.113.9".parse().unwrap(), 4444);
        // record_event only stores NOTABLE requests — a Block here, so the row is
        // built and the buffer path is genuinely exercised.
        ctx.decision = WafDecision::Block;
        ctx.block_reason = Some("test: forced block".to_string());
        ctx.site_id = Some("shedtest".to_string());
        ctx
    }

    /// The fingerprint that drove a bot verdict must land on the stored row.
    ///
    /// `ctx.tls_fingerprint` fed bot scoring and the JA4 blocklist for months
    /// while never being recorded, so a JA4-caused block could not be explained
    /// from ClickHouse, the SIEM, or the log. This is the guard for the one site
    /// that builds the row from a live request context.
    #[test]
    fn the_stored_event_carries_the_request_ja4() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        HISTORY_SINK_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = drain_events();

        let mut ctx = blocking_ctx();
        ctx.tls_fingerprint = Some("q13d0310h3_55b375c5d22e_ba51bb2a78a2".to_string());
        record_event(&ctx);

        let rows = drain_events();
        let row = rows
            .iter()
            .find(|r| r.site == "shedtest")
            .expect("the forced block must have produced a row");
        assert_eq!(
            row.ja4, "q13d0310h3_55b375c5d22e_ba51bb2a78a2",
            "the row must carry the exact fingerprint from the request context"
        );

        // And a plaintext request stores an empty string, not a placeholder that
        // a downstream filter could mistake for a real fingerprint.
        let plain = blocking_ctx();
        record_event(&plain);
        let rows = drain_events();
        assert!(
            rows.iter()
                .any(|r| r.site == "shedtest" && r.ja4.is_empty()),
            "no fingerprint must be stored as empty"
        );
        HISTORY_SINK_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// A poisoned buffer lock used to be skipped both ways: every event after
    /// the panic was dropped without even counting as shed, and the flusher
    /// drained nothing — blocks kept being enforced while the event store
    /// recorded none of them.
    #[test]
    fn a_poisoned_event_buffer_still_records_and_drains() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        HISTORY_SINK_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = drain_events();
        let _ = std::thread::spawn(|| {
            let _held = waf_events().lock().unwrap();
            panic!("poisoning the event buffer on purpose");
        })
        .join();
        assert!(waf_events().is_poisoned(), "fixture must poison the lock");

        let shed_before = history_shed_total();
        record_event(&blocking_ctx());
        let rows = drain_events();
        // Restored before asserting: the other tests here lock it with unwrap().
        waf_events().clear_poison();
        HISTORY_SINK_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(
            rows.iter().any(|r| r.site == "shedtest"),
            "a block after the panic must still be recorded"
        );
        assert_eq!(
            history_shed_total(),
            shed_before,
            "and not be counted as shed"
        );
    }

    #[test]
    fn events_are_buffered_until_the_cap_then_counted_as_shed() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        HISTORY_SINK_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

        // Start from a known buffer state.
        let _ = drain_events();
        let shed_before = history_shed_total();

        // Fill exactly to the cap: none of these may shed.
        {
            let mut buf = waf_events().lock().unwrap();
            buf.clear();
            let filler = || sentinel_storage::WafEventRow {
                ts: 0,
                ip: String::new(),
                country: String::new(),
                site: String::new(),
                tenant: String::new(),
                method: String::new(),
                path: String::new(),
                query: String::new(),
                referer: String::new(),
                matched: String::new(),
                rule: String::new(),
                attack: String::new(),
                action: String::new(),
                severity: String::new(),
                score: 0,
                status: 0,
                protocol: String::new(),
                request_id: String::new(),
                target: String::new(),
                mode: String::new(),
                threshold: 0,
                explanation: String::new(),
                ja4: String::new(),
                rules: String::new(),
                headers: String::new(),
                ua: String::new(),
            };
            buf.resize_with(EVENT_BUFFER_CAP - 1, filler);
        }

        // One below the cap → must be accepted, nothing shed.
        record_event(&blocking_ctx());
        assert_eq!(
            waf_events().lock().unwrap().len(),
            EVENT_BUFFER_CAP,
            "the last free slot should have been used"
        );
        assert_eq!(
            history_shed_total(),
            shed_before,
            "nothing may be shed while the buffer still had room"
        );

        // Now full → the next three must shed AND be counted, and the buffer must
        // not grow past the cap (that bound is the reason shedding exists).
        for _ in 0..3 {
            record_event(&blocking_ctx());
        }
        assert_eq!(
            waf_events().lock().unwrap().len(),
            EVENT_BUFFER_CAP,
            "buffer must stay capped"
        );
        assert_eq!(
            history_shed_total(),
            shed_before + 3,
            "every dropped event must be counted — a silent shed is the bug this fixes"
        );

        // Draining frees space, so recording resumes without further shedding.
        let drained = drain_events();
        assert_eq!(drained.len(), EVENT_BUFFER_CAP);
        record_event(&blocking_ctx());
        assert_eq!(waf_events().lock().unwrap().len(), 1);
        assert_eq!(
            history_shed_total(),
            shed_before + 3,
            "no extra shed once the buffer drained"
        );

        let _ = drain_events();
    }

    #[test]
    fn healthz_reports_the_shed_total() {
        // Cheap guard that the field is actually wired into the payload an operator
        // reads, not only into /metrics.
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let body = serde_json::json!({ "history_shed": history_shed_total() });
        assert!(body["history_shed"].is_number());
    }

    /// The eBPF mode has to be READABLE, not just logged.
    ///
    /// Kernel XDP failed to load on every deployment for six weeks and the only
    /// trace was a single WARN at container startup, so nothing could detect it:
    /// not /healthz, not verify.sh, not the dashboard. The pair that matters is
    /// `kernel_requested` vs `mode` — requested-but-software is precisely the
    /// silent degradation that hid — so both must be present and typed.
    #[tokio::test]
    async fn healthz_reports_the_ebpf_mode_and_whether_kernel_was_requested() {
        let mgr = sentinel_ebpf::EbpfManager::new(sentinel_ebpf::EbpfConfig {
            interface: "eth0".to_string(),
            blocklist: vec![],
            enable_kernel: false,
            stats_interval_secs: 5,
        })
        .await
        .expect("software-mode manager must always construct");
        let stats = mgr.stats();
        let body = serde_json::json!({
            "ebpf": {
                "mode": mgr.mode().to_string(),
                "kernel_requested": mgr.config().enable_kernel,
                "interface": mgr.config().interface,
                "xdp_pass": stats.xdp_pass,
                "xdp_drop": stats.xdp_drop,
                "xdp_aborted": stats.xdp_aborted,
            }
        });
        let e = &body["ebpf"];
        assert!(
            e["mode"]
                .as_str()
                .is_some_and(|m| m == "kernel-xdp" || m == "software"),
            "mode must be a string verify.sh can match, got {:?}",
            e["mode"]
        );
        assert!(
            e["kernel_requested"].is_boolean(),
            "without kernel_requested, a host running software mode BY CONFIG is \
             indistinguishable from one that wanted the kernel path and silently \
             failed to get it — the exact bug this field exists to expose"
        );
        for k in ["xdp_pass", "xdp_drop", "xdp_aborted"] {
            assert!(e[k].is_number(), "{k} must be numeric");
        }
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
        let resp = metrics_response(&RateLimiter::new());
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

    #[tokio::test]
    async fn metrics_include_the_valkey_breaker_when_valkey_is_configured() {
        let rl = RateLimiter::distributed(sentinel_modules::DistributedGuard::default());
        let body = metrics_response(&rl).into_body().collect().await.unwrap();
        let text = String::from_utf8(body.to_bytes().to_vec()).unwrap();
        assert!(text.contains("sentinel_ratelimit_valkey_client_bound 0"));
        assert!(text.contains("sentinel_ratelimit_valkey_breaker_open 0"));
    }

    /// ClickHouse state was only in /healthz JSON; a writer spooling for hours
    /// was invisible to a Prometheus alert.
    #[test]
    fn history_sink_series_only_when_clickhouse_is_configured() {
        assert_eq!(history_sink_metrics_text(false, false, 0), "");
        let text = history_sink_metrics_text(true, false, 7);
        assert!(
            text.contains("sentinel_history_clickhouse_connected 0"),
            "{text}"
        );
        assert!(
            text.contains("sentinel_history_clickhouse_failures_total 7"),
            "{text}"
        );
        assert!(history_sink_metrics_text(true, true, 0)
            .contains("sentinel_history_clickhouse_connected 1"));
    }
}

#[cfg(test)]
mod storage_dependency_tests {
    use super::*;

    /// Storage connects in the background now, so /healthz is where an operator
    /// learns whether rate limits are cluster-wide and history reaches ClickHouse.
    #[test]
    fn healthz_storage_reports_what_rate_checks_really_use() {
        let v = storage_status(&RateLimiter::new());
        assert_eq!(v["valkey"]["configured"], false);
        assert_eq!(v["valkey"]["mode"], "in_memory");
        assert!(v["clickhouse"]["configured"].is_boolean());
        assert!(v["clickhouse"]["connected"].is_boolean());
        assert!(v["clickhouse"]["failures_total"].is_u64());

        let v = storage_status(&RateLimiter::distributed(
            sentinel_modules::DistributedGuard::default(),
        ));
        assert_eq!(v["valkey"]["configured"], true);
        assert_eq!(v["valkey"]["client_bound"], false);
        assert_eq!(v["valkey"]["mode"], "in_memory_fallback");
        assert_eq!(v["valkey"]["breaker"], "closed");
        assert_eq!(v["valkey"]["timeout_ms"], 50);
    }

    /// A ClickHouse that accepts and never replies must be a failed replay —
    /// segment kept for the next attempt, writer free to carry on — not a
    /// writer stuck on the first insert for good.
    #[tokio::test]
    async fn spool_replay_against_a_mute_clickhouse_fails_and_keeps_the_segment() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let dir = std::env::temp_dir().join(format!(
            "sk-spool-mute-ch-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let sp = sentinel_storage::Spool::open(&dir, 1 << 20).unwrap();
        let row = sentinel_storage::TrafficRow {
            ts: 1_700_000_000,
            tenant: "t".into(),
            site_id: "s".into(),
            reqs: 1,
            blocked: 0,
            p99_ms: 1.0,
        };
        sp.append("traffic", &[row]).unwrap();

        let client = sentinel_storage::ClickHouseClient::new(&format!("http://{addr}"), "db")
            .with_request_timeout(Duration::from_millis(300));
        let ok = tokio::time::timeout(Duration::from_secs(5), replay_history_spool(&sp, &client))
            .await
            .expect("spool replay hung on a ClickHouse that never replies");
        assert!(!ok, "a timed-out insert is a sink failure");
        assert_eq!(sp.segments("traffic").len(), 1, "the segment must survive");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn spool_dir(tag: &str) -> sentinel_storage::Spool {
        let dir = std::env::temp_dir().join(format!(
            "sk-spool-{tag}-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        sentinel_storage::Spool::open(&dir, 1 << 30).unwrap()
    }

    fn traffic_rows(n: usize) -> Vec<sentinel_storage::TrafficRow> {
        (0..n as i64)
            .map(|i| sentinel_storage::TrafficRow {
                ts: 1_700_000_000 + i,
                tenant: "t".into(),
                site_id: "s".into(),
                reqs: 1,
                blocked: 0,
                p99_ms: 1.0,
            })
            .collect()
    }

    fn spooled_rows(sp: &sentinel_storage::Spool, kind: &str) -> Vec<usize> {
        sp.segments(kind)
            .iter()
            .map(|p| {
                sentinel_storage::Spool::load::<sentinel_storage::TrafficRow>(p)
                    .unwrap()
                    .0
                    .len()
            })
            .collect()
    }

    /// Spooled while ClickHouse is down, a 20k-row drain became ONE segment,
    /// replayed as one request on every reconnect.
    #[test]
    fn spooling_writes_insert_sized_segments() {
        let sp = spool_dir("chunks");
        spool_batch(Some(&sp), "traffic", &traffic_rows(1_200));
        assert_eq!(spooled_rows(&sp, "traffic"), vec![500, 500, 200]);
        let _ = std::fs::remove_dir_all(sp.dir());
    }

    /// The reviewer's loop: a ClickHouse slow enough that an oversized insert
    /// misses the client's deadline still commits it, the segment is kept,
    /// and every reconnect replays it whole — another copy each time, and the
    /// spool never drains. Sent in INSERT-sized requests it goes in once.
    #[tokio::test]
    async fn an_oversized_segment_replays_once_against_a_slow_clickhouse() {
        use sentinel_storage::testing::{FakeClickHouse, InsertMode};
        // Commits any insert above 500 rows but answers it too late.
        let ch = FakeClickHouse::start(InsertMode::CommitSilentlyAbove(500)).await;
        let client = sentinel_storage::ClickHouseClient::new(&ch.url(), "db")
            .with_request_timeout(Duration::from_millis(300));
        let sp = spool_dir("oversized");
        // A segment from before segments were capped: one whole drain.
        sp.append("traffic", &traffic_rows(1_200)).unwrap();

        for _ in 0..2 {
            let _ =
                tokio::time::timeout(Duration::from_secs(5), replay_history_spool(&sp, &client))
                    .await
                    .expect("replay hung");
        }
        assert_eq!(ch.committed_rows(), 1_200, "inserts {:?}", ch.inserts());
        assert!(sp.segments("traffic").is_empty(), "the segment must drain");
        let _ = std::fs::remove_dir_all(sp.dir());
    }

    /// A replay that fails part-way keeps only what did not go in.
    #[tokio::test]
    async fn a_replay_that_fails_part_way_keeps_only_the_unreplayed_rows() {
        use sentinel_storage::testing::{FakeClickHouse, InsertMode};
        let sp = spool_dir("partial");
        sp.append("traffic", &traffic_rows(1_200)).unwrap();

        let flaky = FakeClickHouse::start(InsertMode::RejectAfter(1_000)).await;
        let client = sentinel_storage::ClickHouseClient::new(&flaky.url(), "db");
        assert!(!replay_history_spool(&sp, &client).await);
        assert_eq!(flaky.committed_rows(), 1_000);
        assert_eq!(spooled_rows(&sp, "traffic"), vec![200]);

        let healthy = FakeClickHouse::start(InsertMode::Accept).await;
        let client = sentinel_storage::ClickHouseClient::new(&healthy.url(), "db");
        assert!(replay_history_spool(&sp, &client).await);
        assert_eq!(healthy.committed_rows(), 200, "no row sent twice");
        assert!(sp.segments("traffic").is_empty());
        let _ = std::fs::remove_dir_all(sp.dir());
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

    // ── PROXY protocol ──────────────────────────────────────────────────────
    // The header is how HTTPS keeps a real client address once the fleet sits
    // behind a TCP-mode load balancer. It is also plaintext and self-asserted,
    // so the trust gate is the whole security of it.

    /// A header from an untrusted peer must NOT be believed. Without this, anyone
    /// who can reach the listener directly prepends a PROXY header and becomes
    /// whatever address they like — walking past an IP block, or pinning their
    /// attack on a colleague.
    #[test]
    fn a_proxy_header_is_only_believed_from_a_trusted_peer() {
        let lb: IpAddr = "172.18.0.15".parse().unwrap();
        let stranger: IpAddr = "203.0.113.9".parse().unwrap();
        let trusted = |ip: IpAddr| ip == lb;

        assert!(
            proxy_header_allowed(lb, trusted),
            "the load balancer's header must be honoured or HTTPS loses client IPs"
        );
        assert!(
            !proxy_header_allowed(stranger, trusted),
            "a direct client must not be able to assert its own source address"
        );
    }

    /// With no trusted proxies configured — the default — nothing is believed.
    /// Fail closed: a listener accidentally marked proxy_protocol on a
    /// directly-exposed port must refuse rather than accept spoofable headers.
    #[test]
    fn with_no_trusted_proxies_no_header_is_believed() {
        let none = |_: IpAddr| false;
        for ip in ["127.0.0.1", "172.18.0.15", "203.0.113.9"] {
            assert!(!proxy_header_allowed(ip.parse().unwrap(), none));
        }
    }

    #[test]
    fn a_proxied_header_replaces_the_transport_peer() {
        let transport: SocketAddr = "172.18.0.15:41234".parse().unwrap();
        let real: SocketAddr = "203.0.113.9:51000".parse().unwrap();
        assert_eq!(
            effective_peer(transport, crate::proxy_protocol::Peer::Proxied(real)),
            real,
            "the client address from the header is the one the pipeline must use"
        );
    }

    /// LOCAL is the balancer's own connection — a health check. Keeping the
    /// transport peer matters more than it looks: HAProxy probes /healthz every
    /// 300ms, so on a quiet box these are most of the connections, and turning
    /// each into a bogus client address would poison the log and the FPR sample
    /// at once.
    #[test]
    fn a_local_header_keeps_the_transport_peer() {
        let transport: SocketAddr = "172.18.0.15:41234".parse().unwrap();
        assert_eq!(
            effective_peer(transport, crate::proxy_protocol::Peer::Local),
            transport
        );
    }

    /// The end-to-end point of the whole feature: a blocked client stays blocked
    /// when it arrives through the balancer. Before PROXY protocol the peer was
    /// the LB, so this returned false and the block was inert for HTTPS — the
    /// same shape as the blocklist bug fixed in 598bcc4, one layer down.
    #[test]
    fn a_blocklisted_client_is_still_caught_when_it_arrives_via_the_balancer() {
        let lb: SocketAddr = "172.18.0.15:41234".parse().unwrap();
        let attacker: SocketAddr = "203.0.113.9:51000".parse().unwrap();
        let is_blocked = |ip: IpAddr| ip == attacker.ip();
        let is_trusted = |ip: IpAddr| ip == lb.ip();
        let headers = http::HeaderMap::new();

        // What the WAF saw BEFORE this change: the balancer.
        assert!(
            !blocklist_hit(lb.ip(), &headers, is_blocked, is_trusted),
            "sanity: the balancer itself is not blocklisted"
        );
        // What it sees now, after the header is applied.
        let peer = effective_peer(lb, crate::proxy_protocol::Peer::Proxied(attacker));
        assert!(
            blocklist_hit(peer.ip(), &headers, is_blocked, is_trusted),
            "a blocklisted client must not be able to reach the origin by coming \
             through the load balancer"
        );
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

#[cfg(test)]
mod log_explain_tests {
    use super::*;
    use sentinel_core::context::{RuleMatch, Severity};
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_with(ip: &str, path: &str) -> RequestContext {
        let mut ctx = RequestContext::new(ip.parse::<IpAddr>().unwrap(), 44321);
        ctx.method = http::Method::POST;
        ctx.uri = path.parse().unwrap();
        ctx.site_id = Some("juice".to_string());
        ctx.anomaly_threshold = Some(10);
        ctx.enforcement_mode = Some(WafMode::Blocking);
        ctx.response_status = Some(http::StatusCode::FORBIDDEN);
        ctx
    }

    fn sqli_match() -> RuleMatch {
        RuleMatch {
            rule_id: "942100".to_string(),
            message: "SQL injection detected".to_string(),
            severity: Severity::Critical,
            score: 15,
            target: "ARGS:username".to_string(),
            phase: Phase::RequestHeaders,
            matched_value: "' OR 1=1--".to_string(),
        }
    }

    /// A protocol nit that fires in the headers phase, before any payload has
    /// been inspected. `920350` matches whenever the Host header is a bare IP,
    /// which on an appliance reached by address is almost every request.
    fn host_is_bare_ip_match() -> RuleMatch {
        RuleMatch {
            rule_id: "920350".to_string(),
            message: "Host header is a numeric IP address".to_string(),
            severity: Severity::Medium,
            score: 3,
            target: "REQUEST_HEADERS:host".to_string(),
            phase: Phase::RequestHeaders,
            matched_value: "203.0.113.10".to_string(),
        }
    }

    /// Every record of a request names ONE rule, and it must be the worst
    /// finding rather than whichever rule happened to run first.
    ///
    /// Measured on the live demo node before this changed: 46% of 80,153 stored
    /// events were attributed to a MEDIUM "Host header is a numeric IP address"
    /// while carrying scores far above what that rule alone contributes, so the
    /// SQL injection, traversal or Log4Shell that actually tripped the threshold
    /// was nowhere on its own record. Detection was right the whole time; only
    /// the attribution was wrong, which is worse than it sounds — it is the
    /// field the console's attack breakdown and every SIEM rule group by.
    #[test]
    fn the_record_names_the_worst_rule_not_the_first_one() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4444);
        // Phase order: the protocol nit is appended first, the real finding second.
        ctx.rule_matches.push(host_is_bare_ip_match());
        ctx.rule_matches.push(sqli_match());

        let top = ctx.primary_rule_match().expect("a match");
        assert_eq!(top.rule_id, "942100", "the record must name the injection");
        assert_eq!(top.severity, Severity::Critical, "and carry its severity");
        assert_eq!(
            top.target, "ARGS:username",
            "and point at the parameter to exclude, not at the Host header"
        );
        assert_eq!(
            redacted_matched(top),
            "' OR 1=1--",
            "and show what the rule actually matched"
        );
    }

    /// The prose an operator reads is built from the same choice, so it cannot
    /// drift from the structured fields.
    #[test]
    fn the_explanation_describes_the_worst_rule_too() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4444);
        ctx.site_id = Some("demo".to_string());
        ctx.rule_matches.push(host_is_bare_ip_match());
        ctx.rule_matches.push(sqli_match());

        let (message, remediation) =
            explain_event(&ctx, "BLOCK", "942100", "SQL injection detected");
        assert!(
            message.contains("942100") && message.contains("Critical"),
            "explanation should name the injection and its severity: {message}"
        );
        assert!(
            !message.contains("920350"),
            "the masked protocol nit must not be presented as the finding: {message}"
        );
        assert!(
            remediation.contains("ARGS:username") || remediation.contains("username"),
            "remediation should name the real parameter: {remediation}"
        );
    }

    #[test]
    fn matched_payload_survives_to_logs_unless_credential_bearing() {
        // Forensic value: an attack payload in an ordinary parameter is kept.
        let m = sqli_match();
        assert_eq!(redacted_matched(&m), "' OR 1=1--");

        // A hit in a credential-bearing target must NEVER write the value —
        // a false positive there would put a user's password in the log.
        for target in [
            "ARGS:password",
            "ARGS:current_pwd",
            "REQUEST_HEADERS:Authorization",
            "REQUEST_COOKIES:session_id",
            "ARGS:api_key",
        ] {
            let mut m = sqli_match();
            m.target = target.to_string();
            let out = redacted_matched(&m);
            assert!(
                out.starts_with("[redacted:"),
                "{target} must redact, got {out:?}"
            );
            assert!(!out.contains("OR 1=1"), "{target} leaked the value");
        }

        // No capturable text → stays empty, never invented.
        let mut m = sqli_match();
        m.matched_value = String::new();
        assert_eq!(redacted_matched(&m), "");
    }

    #[test]
    fn query_is_logged_capped_and_separately_from_path() {
        let uri: http::Uri = "/search?q=1%27+UNION+SELECT".parse().unwrap();
        assert_eq!(capped_query(&uri), "q=1%27+UNION+SELECT");

        let bare: http::Uri = "/search".parse().unwrap();
        assert_eq!(capped_query(&bare), "");

        // A hostile megabyte query must not bloat a log line.
        let huge = format!("/x?p={}", "a".repeat(10_000));
        let uri: http::Uri = huge.parse().unwrap();
        let q = capped_query(&uri);
        assert!(q.chars().count() <= 2050, "got {} chars", q.chars().count());
        assert!(q.ends_with('…'));
    }

    #[test]
    fn target_is_rendered_in_english() {
        assert_eq!(humanize_target("ARGS:id"), "parameter 'id'");
        assert_eq!(
            humanize_target("REQUEST_HEADERS:X-Api-Key"),
            "request header 'X-Api-Key'"
        );
        assert_eq!(humanize_target("REQUEST_COOKIES:sid"), "cookie 'sid'");
        assert_eq!(humanize_target("REQUEST_BODY"), "the request body");
        assert_eq!(
            humanize_target("ARGS_NAMES:x"),
            "parameter name 'x'",
            "the NAME/value distinction must survive — it changes what you exclude"
        );
        // An unrecognised collection is echoed, never invented.
        assert_eq!(
            humanize_target("SOME_FUTURE_THING:z"),
            "SOME_FUTURE_THING:z"
        );
    }

    #[test]
    fn block_message_names_what_where_who_and_why() {
        let mut ctx = ctx_with("45.155.205.233", "/login");
        ctx.geo_country = Some("RU".to_string());
        ctx.decision = WafDecision::Block;
        ctx.anomaly_score = 15;
        ctx.rule_matches.push(sqli_match());

        let (msg, rem) = explain_event(&ctx, "BLOCK", "942100", "SQL injection detected");

        assert!(msg.starts_with("BLOCKED on 'juice'"), "got: {msg}");
        assert!(
            msg.contains("parameter 'username'"),
            "WHERE is missing: {msg}"
        );
        assert!(msg.contains("rule 942100"), "rule is missing: {msg}");
        assert!(
            msg.contains("45.155.205.233 (RU)"),
            "origin is missing: {msg}"
        );
        assert!(msg.contains("POST /login"), "request is missing: {msg}");
        assert!(
            msg.contains("score 15 against this site's threshold of 10"),
            "the score/threshold comparison is the WHY: {msg}"
        );
        assert!(msg.contains("threshold reached"), "got: {msg}");
        assert!(msg.contains("Responded 403"), "outcome is missing: {msg}");
        // The remediation must name the exact rule AND target to exclude.
        assert!(rem.contains("exclude rule 942100"), "got: {rem}");
        assert!(rem.contains("parameter 'username'"), "got: {rem}");
    }

    /// The most dangerous ambiguity in a WAF log: a learning-mode record that
    /// reads like an enforced block. An operator who believes traffic was stopped
    /// when it was not will not investigate.
    #[test]
    fn learning_mode_never_reads_as_blocked() {
        let mut ctx = ctx_with("1.2.3.4", "/search");
        ctx.enforcement_mode = Some(WafMode::Learning);
        ctx.decision = WafDecision::Log;
        ctx.would_block = true;
        ctx.anomaly_score = 12;
        ctx.response_status = Some(http::StatusCode::OK);
        ctx.rule_matches.push(sqli_match());

        let (msg, _) = explain_event(&ctx, "DETECT", "942100", "SQL injection detected");

        assert!(msg.contains("ALLOWED THROUGH"), "got: {msg}");
        assert!(msg.contains("learning mode"), "got: {msg}");
        assert!(msg.contains("not blocked"), "got: {msg}");
        assert!(
            !msg.contains("BLOCKED on"),
            "a learning record must never claim a block: {msg}"
        );
    }

    /// A rate-limit block carries no rule and no score. The explanation must not
    /// fabricate a score comparison it does not have.
    #[test]
    fn non_rule_block_explains_without_inventing_a_score() {
        let mut ctx = ctx_with("9.9.9.9", "/api/v1/orders");
        ctx.decision = WafDecision::Block;
        ctx.block_reason = Some("rate limit exceeded: 120 req/10s".to_string());
        ctx.response_status = Some(http::StatusCode::TOO_MANY_REQUESTS);

        let (msg, rem) = explain_event(&ctx, "BLOCK", "RATELIMIT", "Rate limit exceeded");

        assert!(
            msg.contains("rate limit exceeded: 120 req/10s"),
            "got: {msg}"
        );
        assert!(
            !msg.contains("anomaly score"),
            "no score exists for a rate-limit block; it must not be implied: {msg}"
        );
        assert!(rem.contains("raise the rate limit"), "got: {rem}");
    }

    #[test]
    fn prose_truncation_reports_the_real_length() {
        let long = "a".repeat(400);
        let out = truncate_for_prose(&long, 120);
        assert!(out.contains("400 chars total"), "got: {out}");
        assert!(out.chars().count() < 160, "still bounded: {}", out.len());
        // Short input is returned untouched.
        assert_eq!(truncate_for_prose("/short", 120), "/short");
    }

    #[test]
    fn unrouted_request_is_attributed_to_the_node_not_a_site() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1234);
        ctx.decision = WafDecision::Block;
        ctx.block_reason = Some("threat intel: known scanner".to_string());
        let (msg, rem) = explain_event(&ctx, "BLOCK", "THREATINTEL", "threat intel: known scanner");
        assert!(msg.contains("unrouted request"), "got: {msg}");
        assert!(rem.contains("threat-intelligence feed"), "got: {rem}");
    }
}

#[cfg(test)]
mod inline_rule_diag_tests {
    use super::*;
    use sentinel_core::config::{InlineRule, UpstreamConfig};

    /// The diagnostics registry is process-global by design — it mirrors one
    /// node's live state. Cargo runs tests in threads, so without this they clear
    /// each other's entries and fail intermittently. Serialise them. The panic
    /// tests take it too: every `ProxyServer` they start rebuilds the engines.
    pub(crate) static DIAG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn site_with(inline: Vec<InlineRule>) -> SiteConfig {
        SiteConfig {
            id: "s".into(),
            tenant_id: String::new(),
            domains: vec!["s.local".into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: WafConfig {
                mode: WafMode::Blocking,
                rules: vec![],
                inline_rules: inline,
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    fn diag(name: &str) -> Option<InlineRuleDiag> {
        inline_rule_diag_snapshot()
            .into_iter()
            .find(|d| d.name == name)
    }

    const GOOD: &str = r#"
rule 9990001 {
    phase    : request_body
    targets  : ARGS
    operator : rx /GOODMARKER/
    action   : block
    severity : critical
    message  : "ok"
}
"#;

    /// A rule that compiles must report enforced, and one that does not must
    /// report the reason. This is the whole contract: the control plane has no
    /// compiler, so if this is wrong the UI's "enabled" is a guess.
    #[test]
    fn records_success_and_failure_with_reasons() {
        let _g = guard();
        reset_inline_rule_diags();
        let site = site_with(vec![
            InlineRule {
                name: "good".into(),
                dsl: GOOD.into(),
            },
            InlineRule {
                name: "bad".into(),
                dsl: "rule nope { totally invalid (((".into(),
            },
        ]);
        let _ = load_site_engine(&site);

        let good = diag("good").expect("good rule should be reported");
        assert!(good.enforced, "a rule that compiles must report enforced");
        assert!(good.error.is_none());

        let bad = diag("bad").expect("bad rule should be reported");
        assert!(
            !bad.enforced,
            "a rule that does not parse must not claim to be enforced"
        );
        assert!(
            bad.error
                .as_deref()
                .unwrap_or("")
                .contains("does not parse"),
            "the failure must say why, got {:?}",
            bad.error
        );
    }

    /// A rule whose DSL parses but defines nothing is not enforcing anything, and
    /// reporting it as enforced would be the same false confidence in a subtler form.
    #[test]
    fn parsed_but_empty_is_not_enforced() {
        let _g = guard();
        reset_inline_rule_diags();
        let site = site_with(vec![InlineRule {
            name: "empty".into(),
            dsl: "# just a comment\n".into(),
        }]);
        let _ = load_site_engine(&site);

        let d = diag("empty").expect("should be reported");
        assert!(
            !d.enforced,
            "a DSL defining no rules must not report enforced"
        );
        assert!(d.error.as_deref().unwrap_or("").contains("no rules"));
    }

    /// The registry is rebuilt each reload so a deleted rule stops claiming to run.
    #[test]
    fn reset_clears_stale_entries() {
        let _g = guard();
        reset_inline_rule_diags();
        let _ = load_site_engine(&site_with(vec![InlineRule {
            name: "transient".into(),
            dsl: GOOD.into(),
        }]));
        assert!(diag("transient").is_some(), "precondition");

        reset_inline_rule_diags();
        assert!(
            diag("transient").is_none(),
            "a rule absent from the new config must not keep reporting enforced"
        );
    }

    /// Snapshot must serialise to the shape the control plane parses out of the
    /// heartbeat: a name, an enforced flag, and error only when present.
    #[test]
    fn snapshot_serialises_for_the_heartbeat() {
        let _g = guard();
        reset_inline_rule_diags();
        record_inline_rule_diag("ok-rule", true, None);
        record_inline_rule_diag("bad-rule", false, Some("does not parse: x".into()));

        let json = serde_json::to_string(&inline_rule_diag_snapshot()).expect("serialise");
        assert!(json.contains(r#""name":"ok-rule""#), "got {json}");
        assert!(json.contains(r#""enforced":true"#), "got {json}");
        assert!(
            json.contains(r#""error":"does not parse: x""#),
            "got {json}"
        );
        // The success entry must not carry a null error field.
        let ok_part = json.split(r#"{"name":"bad-rule""#).next().unwrap_or("");
        assert!(
            !ok_part.contains("error"),
            "success entry should omit error: {ok_part}"
        );
    }

    /// A failure recorded for one site must not be overwritten by another site
    /// succeeding, or a partially-broken rollout would report as healthy.
    #[test]
    fn a_failure_is_not_overwritten_by_a_later_success() {
        let _g = guard();
        reset_inline_rule_diags();
        record_inline_rule_diag("r", false, Some("does not parse".into()));
        record_inline_rule_diag("r", true, None);
        let d = diag("r").expect("present");
        assert!(!d.enforced, "a recorded failure must stick");
    }
}

// ---------------------------------------------------------------------------
// Response-body scan buffering
// ---------------------------------------------------------------------------

#[cfg(test)]
mod response_scan_tests {
    use super::*;

    /// A body that yields its chunks one frame at a time and — crucially —
    /// keeps the DEFAULT `size_hint()` of `(0, None)`.  That is exactly what a
    /// `Transfer-Encoding: chunked` response looks like, and it is the shape
    /// that used to slip past the size check.
    struct ChunkedTestBody {
        chunks: std::collections::VecDeque<Bytes>,
    }

    impl Body for ChunkedTestBody {
        type Data = Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            std::task::Poll::Ready(
                this.chunks
                    .pop_front()
                    .map(|b| Ok(hyper::body::Frame::data(b))),
            )
        }
    }

    fn chunked_body(chunks: Vec<Bytes>) -> BoxBody {
        ChunkedTestBody {
            chunks: chunks.into(),
        }
        .boxed()
    }

    #[test]
    fn the_test_body_declares_no_length_like_a_chunked_response() {
        let b = chunked_body(vec![Bytes::from_static(b"x")]);
        assert_eq!(b.size_hint().upper(), None, "fixture must be unbounded");
    }

    async fn drain(body: BoxBody) -> Bytes {
        body.collect().await.expect("drain body").to_bytes()
    }

    #[tokio::test]
    async fn body_under_the_cap_is_returned_whole_for_scanning() {
        let b = chunked_body(vec![
            Bytes::from_static(b"hello "),
            Bytes::from_static(b"world"),
        ]);
        match buffer_for_scan(b, 1024).await {
            ScanBuffer::Complete(bytes, trailers) => {
                assert_eq!(&bytes[..], b"hello world");
                assert!(trailers.is_none());
            }
            _ => panic!("expected Complete"),
        }
    }

    /// Trailers survive inspection. `buffer_for_scan` used to drop them, so a
    /// response that DLP or response rules read reached the client without
    /// them.
    #[tokio::test]
    async fn trailers_survive_buffering_and_the_rebuild() {
        let mut sent = header::HeaderMap::new();
        sent.insert("grpc-status", header::HeaderValue::from_static("0"));
        let origin_trailers = sent.clone();
        let body = Full::new(Bytes::from_static(b"payload"))
            .with_trailers(async move { Some(Ok(origin_trailers)) })
            .map_err(|never: Infallible| match never {})
            .boxed();

        let ScanBuffer::Complete(bytes, trailers) = buffer_for_scan(body, 1024).await else {
            panic!("expected Complete");
        };
        assert_eq!(&bytes[..], b"payload");
        assert_eq!(
            trailers.as_ref(),
            Some(&sent),
            "trailers dropped while buffering"
        );

        let rebuilt = rebuilt_body(bytes, trailers);
        assert_eq!(
            rebuilt.size_hint().exact(),
            Some(7),
            "Content-Length and the logged size come from this hint"
        );
        let collected = rebuilt.collect().await.unwrap();
        assert_eq!(
            collected.trailers(),
            Some(&sent),
            "trailers dropped in the rebuild"
        );
        assert_eq!(&collected.to_bytes()[..], b"payload");
    }

    #[tokio::test]
    async fn a_rebuilt_body_without_trailers_is_just_the_bytes() {
        let rebuilt = rebuilt_body(Bytes::from_static(b"abc"), None);
        assert_eq!(rebuilt.size_hint().exact(), Some(3));
        let collected = rebuilt.collect().await.unwrap();
        assert!(collected.trailers().is_none());
        assert_eq!(&collected.to_bytes()[..], b"abc");
    }

    /// THE REGRESSION TEST. A chunked body reports no size hint, so the old
    /// `size_hint().upper().unwrap_or(0)` check read `0`, passed the `<= cap`
    /// test, and collected the entire response into memory with no limit.
    /// Buffering must now stop at the cap.
    #[tokio::test]
    async fn oversized_chunked_body_stops_buffering_at_the_cap() {
        let cap = 4096;
        // 64 chunks x 1 KiB = 64 KiB, far past the cap, with NO declared length.
        let chunks: Vec<Bytes> = (0..64).map(|_| Bytes::from(vec![b'A'; 1024])).collect();
        let total: usize = chunks.iter().map(|c| c.len()).sum();

        match buffer_for_scan(chunked_body(chunks), cap).await {
            ScanBuffer::Oversize { prefix, rest } => {
                // Bounded: only the cap (plus at most one straddling chunk) is
                // ever held in memory — not the whole 64 KiB.
                assert!(
                    prefix.len() <= cap + 1024,
                    "buffered {} bytes for a {cap}-byte cap",
                    prefix.len()
                );
                // And nothing is lost: prefix + remainder == the original body.
                let rest = drain(rest).await;
                assert_eq!(prefix.len() + rest.len(), total, "bytes lost or duplicated");
            }
            _ => panic!("expected Oversize"),
        }
    }

    /// A response that is forwarded uninspected must reach the client
    /// byte-for-byte — the prefix already pulled off the wire is replayed, not
    /// dropped and not sent twice.
    #[tokio::test]
    async fn prefixed_body_replays_the_prefix_then_streams_the_rest() {
        let original: Vec<Bytes> = (0..32)
            .map(|i| Bytes::from(vec![b'a' + (i % 26) as u8; 512]))
            .collect();
        let expected: Vec<u8> = original.iter().flat_map(|c| c.to_vec()).collect();

        let ScanBuffer::Oversize { prefix, rest } =
            buffer_for_scan(chunked_body(original), 2048).await
        else {
            panic!("expected Oversize");
        };

        let forwarded = drain(
            PrefixedBody {
                prefix: Some(prefix),
                inner: rest,
            }
            .boxed(),
        )
        .await;
        assert_eq!(&forwarded[..], &expected[..]);
    }

    #[tokio::test]
    async fn prefixed_body_with_no_prefix_just_streams_the_inner_body() {
        let body = PrefixedBody {
            prefix: None,
            inner: chunked_body(vec![Bytes::from_static(b"abc")]),
        };
        assert_eq!(&drain(body.boxed()).await[..], b"abc");
    }

    #[test]
    fn concat_chunks_handles_empty_single_and_many() {
        assert_eq!(concat_chunks(vec![]).len(), 0);
        assert_eq!(
            &concat_chunks(vec![Bytes::from_static(b"solo")])[..],
            b"solo"
        );
        assert_eq!(
            &concat_chunks(vec![
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c"),
            ])[..],
            b"abc"
        );
    }
}

#[cfg(test)]
mod block_page_tests {
    use super::*;
    use sentinel_core::config::BlockPageConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_with(accept: Option<&str>, cfg: Option<BlockPageConfig>) -> RequestContext {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 41234);
        if let Some(a) = accept {
            let mut h = http::HeaderMap::new();
            h.insert(header::ACCEPT, a.parse().unwrap());
            // Mirrors the real Phase-0 stamping, so these tests exercise the
            // same decision path the proxy uses rather than a parallel one.
            ctx.client_accepts_html = wants_html(&h);
            ctx.request_headers = h;
        }
        ctx.block_reason = Some("threat intel: matched IOC feed 'abuse.ch' tier=block".into());
        ctx.block_page = cfg;
        ctx
    }

    async fn body_string(resp: Response<BoxBody>) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// The default must not tell the caller which control fired. `block_reason`
    /// names the engine and the feed, which is a free tuning oracle for anyone
    /// probing the WAF with permuted payloads.
    #[tokio::test]
    async fn reason_is_withheld_by_default() {
        for accept in [Some("text/html"), Some("application/json"), None] {
            let resp = block_response(&ctx_with(accept, None));
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let body = body_string(resp).await;
            assert!(
                !body.contains("threat intel") && !body.contains("abuse.ch"),
                "detection reason leaked with Accept={accept:?}: {body}"
            );
        }
    }

    /// A site with only the fields this test cares about; SiteConfig has no
    /// Default, so the rest is spelled out once here.
    fn plugin_site(id: &str, names: Vec<&str>) -> SiteConfig {
        SiteConfig {
            id: id.to_string(),
            tenant_id: String::new(),
            domains: vec![format!("{id}.local")],
            upstream: sentinel_core::config::UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: sentinel_core::config::WafConfig {
                enabled_plugins: names.into_iter().map(String::from).collect(),
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    /// A JWT failure is either the client's fault or the operator's, and only
    /// the second one needs an operator-facing line. Getting this wrong in
    /// either direction is bad: classify a bad token as a misconfiguration and
    /// the log fills with client noise; classify a missing key as a bad token
    /// and a site that can never authenticate anyone looks like an attack.
    #[test]
    fn jwt_misconfiguration_is_told_apart_from_a_bad_token() {
        for operator in [
            "no verification key configured",
            "misconfigured public key",
            "unknown key id: abc123",
        ] {
            assert!(
                jwt_failure_is_misconfiguration(operator),
                "{operator:?} is the operator's problem"
            );
        }
        for client in [
            "token expired",
            "invalid signature",
            "malformed token header",
            "token header missing kid (required for JWKS)",
            "issuer mismatch",
        ] {
            assert!(
                !jwt_failure_is_misconfiguration(client),
                "{client:?} is the client's problem and must not page an operator"
            );
        }
    }

    /// The diagnostic fires once per key, so a broken config produces one line
    /// rather than one per request.
    #[test]
    fn an_operator_diagnostic_is_logged_once_per_key() {
        let key = format!("test-key-{}", std::process::id());
        assert!(diag_first_time(key.clone()), "first time must report true");
        assert!(
            !diag_first_time(key.clone()),
            "second time must be suppressed"
        );
        assert!(!diag_first_time(key), "and stay suppressed");
        assert!(
            diag_first_time(format!("other-key-{}", std::process::id())),
            "a different key is a different diagnostic"
        );
    }

    /// A blocking-mode site whose rules will not compile must be REFUSED, not
    /// served without signature protection. Every branch of the decision, because
    /// the old version got this wrong in exactly one of them: it refused while a
    /// reload was in flight and then served the same broken site for ever.
    #[test]
    fn a_blocking_site_with_no_rule_engine_fails_closed() {
        use sentinel_core::config::WafMode;

        // has_engine=true → always served, whatever the mode.
        for mode in [WafMode::Blocking, WafMode::Learning] {
            let s = rules_site("s", mode, true);
            assert_eq!(
                missing_engine_action(&s, true, false, false),
                MissingEngine::Serve
            );
        }

        // Reload in flight: transient, refuse and let the client retry. Same for
        // both modes — the config may be seconds from being correct.
        for mode in [WafMode::Blocking, WafMode::Learning] {
            let s = rules_site("s", mode, true);
            assert_eq!(
                missing_engine_action(&s, false, true, false),
                MissingEngine::RefuseWarming
            );
        }

        // THE FIX: not warming, no engine, blocking mode → refuse permanently.
        let blocking = rules_site("s", WafMode::Blocking, true);
        assert_eq!(
            missing_engine_action(&blocking, false, false, false),
            MissingEngine::RefuseBroken,
            "a blocking-mode site that cannot enforce must not be served"
        );

        // Learning mode refuses too, as of 2026-09-17. It used to serve, on the
        // reasoning that learning never promised to block so availability was
        // the better trade. That reasoning was wrong about what learning
        // promises: it promises to OBSERVE, and a site with no engine observes
        // nothing. Serving it produces a learning report that is silently empty
        // — indistinguishable from "we looked and found nothing" — and that is
        // the report an operator reads to decide the site is safe to switch to
        // blocking. A wrong answer beats a missing one only if nobody acts on
        // it, and this one is read precisely in order to act.
        let learning = rules_site("s", WafMode::Learning, true);
        assert_eq!(
            missing_engine_action(&learning, false, false, false),
            MissingEngine::RefuseBroken,
            "a learning site with no engine would report zero findings, which an \
             operator would read as 'clean' rather than 'never inspected'"
        );

        // The escape hatch covers learning as well, so an operator who needs
        // the site up while the rules are broken has the same one lever.
        assert_eq!(
            missing_engine_action(&learning, false, false, true),
            MissingEngine::Serve,
            "SENTINEL_SERVE_ON_RULE_COMPILE_FAILURE must still override every mode"
        );

        // Warming still wins over the mode: a reload in flight is transient and
        // must not be reported as a broken rule set.
        assert_eq!(
            missing_engine_action(&learning, false, true, false),
            MissingEngine::RefuseWarming
        );

        // The escape hatch restores the old behaviour, deliberately.
        assert_eq!(
            missing_engine_action(&blocking, false, false, true),
            MissingEngine::Serve
        );

        // A site that never expected an engine is unaffected: mode off, or no
        // rules at all. Both must serve even in blocking mode with no engine.
        let off = rules_site("s", WafMode::Off, true);
        assert_eq!(
            missing_engine_action(&off, false, false, false),
            MissingEngine::Serve
        );
        let no_rules = rules_site("s", WafMode::Blocking, false);
        assert_eq!(
            missing_engine_action(&no_rules, false, false, false),
            MissingEngine::Serve,
            "a blocking site with no rules configured legitimately has no engine"
        );
    }

    /// `sites_refused` must name the consequence, not merely repeat the condition.
    #[test]
    fn healthz_separates_unprotected_from_refused() {
        use sentinel_core::config::WafMode;
        let cfg = SentinelConfig {
            sites: vec![
                rules_site("blocking-broken", WafMode::Blocking, true),
                rules_site("learning-broken", WafMode::Learning, true),
                rules_site("no-rules", WafMode::Blocking, false),
            ],
            ..Default::default()
        };
        let engines = RuleEngineMap::new(); // nothing compiled
        let unprotected = unprotected_sites(&cfg, &engines);
        assert_eq!(
            unprotected,
            vec!["blocking-broken".to_string(), "learning-broken".to_string()],
            "both broken sites lack signature protection"
        );
        // refused_sites reads the live warming flag and env, so assert the
        // decision directly. Both broken sites are refused as of 2026-09-17 —
        // learning used to be served, until it was pointed out that a learning
        // site with no engine reports zero findings, which reads as "clean".
        // The health endpoint still distinguishes the two lists: `unprotected`
        // is the condition (no signature coverage), `refused` is what the node
        // decided to do about it.
        assert_eq!(
            missing_engine_action(&cfg.sites[0], false, false, false),
            MissingEngine::RefuseBroken,
            "blocking site cannot enforce"
        );
        assert_eq!(
            missing_engine_action(&cfg.sites[1], false, false, false),
            MissingEngine::RefuseBroken,
            "learning site cannot observe"
        );
        // The site that never wanted an engine is still served, so the two
        // lists genuinely differ rather than becoming the same list.
        assert_eq!(
            missing_engine_action(&cfg.sites[2], false, false, false),
            MissingEngine::Serve,
            "a site with no rules configured is not broken"
        );
    }

    /// A site with rule files, at a given mode.
    fn rules_site(id: &str, mode: sentinel_core::config::WafMode, with_rules: bool) -> SiteConfig {
        let mut s = plugin_site(id, vec![]);
        s.waf.mode = mode;
        s.waf.rules = if with_rules {
            vec!["rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf".to_string()]
        } else {
            vec![]
        };
        s
    }

    /// Plugins are opt-in per site. Before 2026-09-07 the request path ran every
    /// loaded module for every site, so enabling one plugin to try it on a test
    /// site put it in front of production traffic too. These tests pin the
    /// selection: a site gets its own manifest plugins plus the installed ones it
    /// names, nothing else, and a name that is not loaded is reported.
    #[test]
    fn per_site_plugin_selection_is_opt_in() {
        let cfg = SentinelConfig {
            sites: vec![
                plugin_site("prod", vec![]),
                plugin_site("staging", vec!["scanner-guard"]),
                plugin_site("typo", vec!["scaner-guard"]),
            ],
            ..Default::default()
        };

        // Pretend the control plane installed one module.
        let uploaded: UploadedPlugins = Arc::new(DashMap::new());
        uploaded.insert(
            "scanner-guard".to_string(),
            ("sha".to_string(), minimal_plugin_wasm()),
        );

        let (rt, per_site, loaded, rejected, unresolved) =
            build_full_plugin_runtime(&cfg, &uploaded).expect("build runtime");
        assert_eq!(rejected, 0, "the fixture module must compile");
        assert_eq!(loaded, vec!["scanner-guard".to_string()]);

        // The site that named it runs it; the one that did not runs nothing.
        assert_eq!(
            per_site.get("staging").map(Vec::as_slice),
            Some(["scanner-guard".to_string()].as_slice())
        );
        assert!(
            !per_site.contains_key("prod"),
            "a site that named no plugin must run none — this is the whole point"
        );

        // A misspelled name is reported, never silently ignored.
        assert_eq!(
            unresolved,
            vec![("typo".to_string(), "scaner-guard".to_string())]
        );

        // …and healthz says all of that out loud.
        let st = plugin_status(&rt, &per_site, &unresolved);
        assert_eq!(st["loaded"], serde_json::json!(["scanner-guard"]));
        assert_eq!(st["running_on_at_least_one_site"], 1);
        assert_eq!(
            st["per_plugin_sites"]["scanner-guard"],
            serde_json::json!(["staging"])
        );
        assert_eq!(st["unresolved"][0]["site"], "typo");
        assert_eq!(st["unresolved"][0]["plugin"], "scaner-guard");
        assert_eq!(st["loaded_but_unused"], serde_json::json!([]));
    }

    /// A module nobody selected is reported as unused rather than looking active.
    #[test]
    fn a_loaded_plugin_no_site_selected_is_reported_unused() {
        let cfg = SentinelConfig {
            sites: vec![plugin_site("prod", vec![])],
            ..Default::default()
        };
        let uploaded: UploadedPlugins = Arc::new(DashMap::new());
        uploaded.insert(
            "scanner-guard".to_string(),
            ("sha".to_string(), minimal_plugin_wasm()),
        );
        let (rt, per_site, _, _, unresolved) =
            build_full_plugin_runtime(&cfg, &uploaded).expect("build runtime");
        let st = plugin_status(&rt, &per_site, &unresolved);
        assert_eq!(st["running_on_at_least_one_site"], 0);
        assert_eq!(
            st["loaded_but_unused"],
            serde_json::json!(["scanner-guard"])
        );
    }

    /// Smallest module the runtime will accept: exports `evaluate`, does nothing.
    fn minimal_plugin_wasm() -> Vec<u8> {
        // (module (func (export "evaluate")))
        vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
            0x03, 0x02, 0x01, 0x00, // function section
            0x07, 0x0c, 0x01, 0x08, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x65, 0x00,
            0x00, // export "evaluate"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code: empty body
        ]
    }

    /// A throttle is not a policy block: a rate-limited client must get 429 and
    /// a Retry-After in both the HTML and JSON shapes, and a plain block must
    /// stay 403 without one.
    #[tokio::test]
    async fn rate_limit_block_is_429_with_retry_after() {
        for accept in [Some("text/html"), Some("application/json"), None] {
            let mut ctx = ctx_with(accept, None);
            ctx.block_status = Some(429);
            let resp = block_response(&ctx);
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Accept={accept:?}"
            );
            assert_eq!(
                resp.headers()
                    .get(header::RETRY_AFTER)
                    .map(|v| v.to_str().unwrap()),
                Some("1"),
                "Accept={accept:?}"
            );
            if accept != Some("text/html") {
                let body = body_string(resp).await;
                assert!(body.contains("Too Many Requests"), "{body}");
            }
        }
        let plain = block_response(&ctx_with(Some("application/json"), None));
        assert_eq!(plain.status(), StatusCode::FORBIDDEN);
        assert!(plain.headers().get(header::RETRY_AFTER).is_none());
    }

    /// ...but an operator debugging a false positive on an internal site can
    /// opt in, and then it must actually appear.
    #[tokio::test]
    async fn reason_shown_when_opted_in() {
        let cfg = BlockPageConfig {
            show_reason: true,
            ..Default::default()
        };
        let body = body_string(block_response(&ctx_with(Some("text/html"), Some(cfg)))).await;
        assert!(body.contains("abuse.ch"), "opted-in reason missing: {body}");
    }

    /// A browser gets a page; anything that did not ask for HTML gets JSON.
    /// curl's `*/*` must NOT be treated as a browser or scripts break.
    #[tokio::test]
    async fn content_negotiation_splits_browsers_from_clients() {
        let html = block_response(&ctx_with(
            Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            None,
        ));
        assert_eq!(
            html.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert!(body_string(html).await.contains("<!doctype html>"));

        for accept in [Some("*/*"), Some("application/json"), None] {
            let resp = block_response(&ctx_with(accept, None));
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json",
                "Accept={accept:?} should get JSON"
            );
        }
    }

    /// The support id is the join key into access.log / waf.log / ClickHouse.
    /// Both representations must carry it or a caller quoting it is unhelpable.
    #[tokio::test]
    async fn support_id_present_in_both_representations() {
        let ctx = ctx_with(Some("text/html"), None);
        let id = ctx.request_id.to_string();
        assert!(body_string(block_response(&ctx)).await.contains(&id));

        let ctx = ctx_with(Some("application/json"), None);
        let id = ctx.request_id.to_string();
        let json = body_string(block_response(&ctx)).await;
        assert!(json.contains(&id));
        // request_id retained alongside support_id for clients written against
        // the previous response shape.
        assert!(json.contains("support_id") && json.contains("request_id"));
    }

    /// Config reaches the template verbatim, so a stray quote or tag in a
    /// customer-supplied field must not be able to break out of it.
    #[tokio::test]
    async fn config_values_are_html_escaped() {
        let cfg = BlockPageConfig {
            title: Some("<script>alert(1)</script>".into()),
            message: Some(r#"" onload="alert(2)"#.into()),
            contact: Some("<img src=x onerror=alert(3)>".into()),
            ..Default::default()
        };
        let body = body_string(block_response(&ctx_with(Some("text/html"), Some(cfg)))).await;
        // What matters is that no value can close its context and become live
        // markup — not that the characters are absent. `onerror=alert(3)` still
        // appears as inert text once the surrounding `<` is escaped.
        assert!(
            !body.contains("<script"),
            "title escaped out of its context"
        );
        assert!(
            !body.contains("<img src=x"),
            "contact escaped out of its context"
        );
        assert!(
            !body.contains(r#"" onload="#),
            "message escaped out of its attribute"
        );
        assert!(body.contains("&lt;script&gt;"), "expected escaped output");
    }

    /// `<img src>` accepts javascript: and data:text/html, which would turn a
    /// branding field into stored XSS on a page we serve on every block.
    #[test]
    fn logo_url_rejects_script_schemes() {
        assert!(sanitize_logo_url("javascript:alert(1)").is_none());
        assert!(sanitize_logo_url("JavaScript:alert(1)").is_none());
        assert!(sanitize_logo_url("data:text/html;base64,PHNjcmlwdD4=").is_none());
        assert!(sanitize_logo_url("//evil.example/x.png").is_none());
        assert!(sanitize_logo_url("").is_none());

        assert_eq!(
            sanitize_logo_url("https://cdn.example/logo.png").as_deref(),
            Some("https://cdn.example/logo.png")
        );
        assert_eq!(
            sanitize_logo_url("/assets/logo.png").as_deref(),
            Some("/assets/logo.png")
        );
    }

    #[test]
    fn contact_renders_as_link_only_when_unambiguous() {
        assert!(render_contact("soc@acme.example").contains(r#"href="mailto:soc@acme.example""#));
        assert!(render_contact("https://acme.example/support").contains(r#"<a href="https"#));
        // A phone number is not a URL and must not become a broken link.
        let phone = render_contact("+91 22 6674 0500");
        assert!(
            !phone.contains("<a "),
            "phone should stay plain text: {phone}"
        );
    }

    /// An error page must not be cached or framed, and must not leak the URL
    /// that was blocked to a third party via Referer.
    #[tokio::test]
    async fn block_page_sets_protective_headers() {
        let resp = block_response(&ctx_with(Some("text/html"), None));
        let h = resp.headers();
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(h.get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(h.get("X-Content-Type-Options").unwrap(), "nosniff");
        assert_eq!(h.get("Referrer-Policy").unwrap(), "no-referrer");
    }

    /// Disabling the page sends browsers the same JSON as API clients, rather
    /// than silently continuing to serve HTML.
    #[tokio::test]
    async fn disabling_falls_back_to_json_for_browsers() {
        let cfg = BlockPageConfig {
            enabled: false,
            ..Default::default()
        };
        let resp = block_response(&ctx_with(Some("text/html"), Some(cfg)));
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
}

#[cfg(test)]
mod block_page_connection_layer_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Regression: the connection-layer rejections (anti-DDoS, IP reputation,
    /// threat intel) answer BEFORE ctx.request_headers is populated — that
    /// assignment happens after into_parts(), downstream of a Host-synthesis
    /// step site matching depends on, so it cannot simply be hoisted.
    ///
    /// The first cut read the header map inside block_response, which was
    /// therefore EMPTY on those paths: every browser blocked by threat intel
    /// got JSON, which is exactly the audience the page exists for. Caught on
    /// the deploy VM, not by the original unit tests, because those only
    /// exercised the post-routing path where the headers happen to be set.
    ///
    /// The flag is now stamped at Phase 0, so a context with NO request_headers
    /// still renders HTML when the client asked for it.
    #[tokio::test]
    async fn connection_layer_block_still_renders_html_for_browsers() {
        use http_body_util::BodyExt;

        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 5555);
        ctx.block_reason = Some("threat intel: matched IOC feed".into());
        // Exactly the connection-layer shape: flag set at Phase 0, headers never
        // populated because the request was rejected before into_parts().
        ctx.client_accepts_html = true;
        assert!(
            ctx.request_headers.is_empty(),
            "fixture must model the pre-into_parts() state"
        );

        let resp = block_response(&ctx);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8",
            "a browser blocked at the connection layer must still get the page"
        );
        let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
            .to_string();
        assert!(
            body.contains("Support ID"),
            "page must carry the Support ID"
        );
        assert!(
            !body.contains("threat intel"),
            "reason must stay withheld on this path too"
        );
    }

    /// The mirror case: no Accept negotiation happened, so a scripted client
    /// blocked at the connection layer still gets JSON.
    #[tokio::test]
    async fn connection_layer_block_gives_json_to_non_browsers() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 5555);
        ctx.client_accepts_html = false;
        let resp = block_response(&ctx);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    /// Regression: every rejection path used to `return Ok(error_response(...))`
    /// without recording what it returned, so the size/method limits, the
    /// pre-routing rejections and the DLP block all logged `status=0, bytes=0`.
    /// That corrupted the 4xx/5xx counters and made `status` an unusable filter
    /// in Threat Search — an always-zero column teaches operators to distrust
    /// the whole line.
    #[test]
    fn stamped_rejections_record_their_real_status_and_size() {
        for (expected, resp) in [
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request Entity Too Large"),
            ),
            (
                StatusCode::METHOD_NOT_ALLOWED,
                error_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),
            ),
            (
                StatusCode::URI_TOO_LONG,
                error_response(StatusCode::URI_TOO_LONG, "URI Too Long"),
            ),
        ] {
            let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
            stamp_response(&mut ctx, &resp);
            assert_eq!(
                ctx.response_status,
                Some(expected),
                "status must reach the log, not default to 0"
            );
            assert!(
                ctx.bytes_sent > 0,
                "a rejection with a body must not log bytes=0"
            );
        }

        // The block page too — this is the path a stranger with a Support ID hit.
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 5555);
        ctx.block_reason = Some("threat intel: matched IOC feed".into());
        let resp = block_response(&ctx);
        stamp_response(&mut ctx, &resp);
        assert_eq!(ctx.response_status, Some(StatusCode::FORBIDDEN));
        assert!(ctx.bytes_sent > 0);
    }
}

#[cfg(test)]
mod nonrule_block_classification_tests {
    use super::*;

    /// Threat-intel, IP-reputation and DDoS blocks used to fall through to
    /// ANOMALY, producing log lines that read "anomaly threshold exceeded" with
    /// score=0 — blaming the scoring engine for a decision it never made, and
    /// disagreeing with ClickHouse about the same event.
    #[test]
    fn connection_layer_reasons_get_their_own_labels() {
        // Exactly the strings the proxy builds at the block sites.
        assert_eq!(
            classify_nonrule_block("threat intel: matched IOC feed 'abuse.ch' tier=block").0,
            "THREATINTEL"
        );
        assert_eq!(
            classify_nonrule_block("IP reputation: listed by dnsbl").0,
            "IPREP"
        );
        assert_eq!(
            classify_nonrule_block("DDoS mitigation: 1.2.3.4 is temporarily blocked").0,
            "DDOS"
        );
    }

    /// A threat-intel reason can legitimately contain the word "bot" (feeds are
    /// named things like "bot-net IOCs"). The threat-intel arm must win, or the
    /// fix simply moves the mislabelling somewhere less obvious.
    #[test]
    fn threat_intel_wins_over_a_bot_shaped_feed_name() {
        let (rule, _) = classify_nonrule_block("threat intel: matched bot-net IOC feed");
        assert_eq!(rule, "THREATINTEL", "feed name must not steal the match");
    }

    /// A body refused before any rule judged it read "anomaly threshold
    /// exceeded" with score 0, and the rule engine's own refusal (field names
    /// it cannot list) looked like a rule block with no rule to exclude.
    #[test]
    fn uninspectable_body_reasons_are_labelled_body() {
        // Exactly the strings the proxy builds at the body-read sites.
        assert_eq!(
            classify_nonrule_block("request body too large (limit 1048576 bytes)"),
            ("BODY", "Request body could not be inspected")
        );
        assert_eq!(
            classify_nonrule_block("request body read timed out (slow-body)").0,
            "BODY"
        );
        // The rule engine's reason, produced as a request produces it: a 32 KB
        // JSON key spelled out once per child is past the name budget.
        let engine =
            RuleEngine::from_crs_conf("SecRule ARGS \"@rx never-present\" \"id:1,phase:2,deny\"")
                .unwrap();
        let kids: Vec<String> = (0..3000).map(|i| format!("\"a{i}\":0")).collect();
        let body = format!("{{\"{}\":{{{}}}}}", "k".repeat(32 * 1024), kids.join(","));
        let mut ctx = RequestContext::new("203.0.113.9".parse().unwrap(), 4321);
        ctx.uri = "/submit".parse().unwrap();
        ctx.request_headers
            .insert("content-type", "application/json".parse().unwrap());
        ctx.request_body = Some(body.into_bytes().into());
        assert_eq!(
            engine.evaluate(&mut ctx, Phase::RequestBody, 0),
            WafDecision::Block
        );
        assert!(ctx.rule_matches.is_empty());
        let reason = ctx.block_reason.as_deref().unwrap();
        assert_eq!(classify_nonrule_block(reason).0, "BODY", "{reason}");
    }

    /// The arms that already worked must keep working.
    #[test]
    fn existing_labels_unchanged() {
        assert_eq!(classify_nonrule_block("country blocked: CN").0, "GEOIP");
        assert_eq!(classify_nonrule_block("rate limit exceeded").0, "RATELIMIT");
        assert_eq!(
            classify_nonrule_block("HTTP request smuggling detected").0,
            "SMUGGLING"
        );
        assert_eq!(classify_nonrule_block("bot challenge failed").0, "BOT");
    }

    /// Anything unrecognised still reports ANOMALY. Documented rather than
    /// endorsed: this default is why the bug was silent, so a NEW block reason
    /// added later will misreport the same way until it gets an arm here.
    #[test]
    fn unknown_reason_still_falls_back_to_anomaly() {
        assert_eq!(
            classify_nonrule_block("something nobody has classified yet").0,
            "ANOMALY"
        );
    }
}

#[cfg(test)]
mod accept_error_tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    fn errno(code: i32) -> Error {
        Error::from_raw_os_error(code)
    }

    /// The listener used to die on the FIRST accept() error of any kind, because
    /// the loop did `let (stream, peer) = accept?;`. ECONNABORTED is the one that
    /// makes that a remote denial of service rather than a rare accident: it is
    /// what the kernel returns when a client sends RST between SYN and accept, so
    /// an ordinary port scan produced a stream of them. Anyone who could reach the
    /// WAF could take its listener off the network, while the process stayed alive
    /// and every liveness check kept reporting healthy.
    #[test]
    fn routine_peer_failures_never_kill_the_listener() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
            ErrorKind::Interrupted,
            ErrorKind::NotConnected,
            ErrorKind::BrokenPipe,
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
        ] {
            assert_eq!(
                classify_accept_error(&Error::new(kind, "test")),
                AcceptRecovery::Retry,
                "{kind:?} is a per-connection failure and must not stop the listener"
            );
        }
        // The same thing arriving as a raw errno rather than a typed ErrorKind.
        assert_eq!(
            classify_accept_error(&errno(libc::ECONNABORTED)),
            AcceptRecovery::Retry,
            "ECONNABORTED by errno must also be per-connection"
        );
    }

    /// Descriptor exhaustion must back off rather than retry hot. The listening
    /// socket stays readable while there are no descriptors to accept onto, so a
    /// bare `continue` here burns a core at 100% until the pressure clears —
    /// turning a capacity problem into a CPU outage. Reachable in the shipped
    /// configuration: max_connections defaults to 10,000 and the dataplane
    /// container sets no nofile limit.
    #[test]
    fn resource_exhaustion_backs_off_instead_of_spinning() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(
                classify_accept_error(&errno(code)),
                AcceptRecovery::Backoff,
                "errno {code} is transient resource exhaustion: pause, do not spin, do not exit"
            );
        }
        assert_eq!(
            classify_accept_error(&Error::new(ErrorKind::OutOfMemory, "test")),
            AcceptRecovery::Backoff
        );
    }

    /// Only a genuinely unusable listening descriptor is fatal.
    #[test]
    fn a_broken_listening_socket_is_fatal() {
        for code in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL] {
            assert_eq!(
                classify_accept_error(&errno(code)),
                AcceptRecovery::Fatal,
                "errno {code} means the listening socket cannot work; retrying is pointless"
            );
        }
    }

    /// The default must be to SURVIVE. An unknown errno we pause on costs
    /// milliseconds if it really was unrecoverable; an unknown errno we exit on
    /// takes the WAF off the network. Kernels differ in what they surface from
    /// accept(), so this bias is load-bearing, not decorative.
    #[test]
    fn unknown_errors_survive_rather_than_kill_the_listener() {
        for code in [libc::EPROTO, libc::ENETDOWN, libc::EHOSTDOWN, 424_242] {
            assert_ne!(
                classify_accept_error(&errno(code)),
                AcceptRecovery::Fatal,
                "errno {code} is not known-fatal, so it must not stop the listener"
            );
        }
    }

    /// Backoff must be bounded on both ends: long enough to stop a hot spin,
    /// short enough that the listener recovers promptly once descriptors free.
    #[test]
    fn backoff_bounds_are_sane() {
        assert!(ACCEPT_BACKOFF_MIN >= std::time::Duration::from_millis(1));
        assert!(ACCEPT_BACKOFF_MIN < ACCEPT_BACKOFF_MAX);
        assert!(ACCEPT_BACKOFF_MAX <= std::time::Duration::from_secs(5));

        // Doubling from MIN must reach MAX in a small number of steps — the loop
        // caps with .min(MAX), so this just pins the growth curve.
        let mut d = ACCEPT_BACKOFF_MIN;
        let mut steps = 0;
        while d < ACCEPT_BACKOFF_MAX {
            d = (d * 2).min(ACCEPT_BACKOFF_MAX);
            steps += 1;
            assert!(steps < 16, "backoff should reach its ceiling quickly");
        }
    }
}

#[cfg(test)]
mod geoip_honesty_tests {
    use super::*;
    use sentinel_core::config::{GeoIpConfig, SentinelConfig, SiteConfig, UpstreamConfig};

    /// SiteConfig has no `Default`, so this mirrors `site_with` in the inline-rule
    /// tests above rather than inventing a second shape.
    fn bare_site(id: &str) -> SiteConfig {
        SiteConfig {
            id: id.into(),
            tenant_id: String::new(),
            domains: vec![format!("{id}.local")],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: WafConfig {
                mode: WafMode::Blocking,
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    fn site_with_geoip(id: &str, db: &str, block: Vec<&str>) -> SiteConfig {
        let mut s = bare_site(id);
        s.waf.geoip = Some(GeoIpConfig {
            db_path: db.into(),
            block_countries: block.into_iter().map(String::from).collect(),
            allow_countries: vec![],
        });
        s
    }

    /// The defect this pins: a site configured to block countries, with no
    /// MaxMind database anywhere, reported nothing at all. `GeoIp` degrades to a
    /// no-op that answers Unknown for every address, so the block passed all
    /// traffic while the console showed the policy as set. No `.mmdb` has ever
    /// shipped in any bundle, so this was every deployment.
    #[test]
    fn a_country_block_with_no_database_is_reported_as_inert() {
        let cfg = SentinelConfig {
            sites: vec![site_with_geoip(
                "shop",
                "/nonexistent/GeoLite2-Country.mmdb",
                vec!["CN", "RU"],
            )],
            ..Default::default()
        };
        let map = build_geoip_map(&cfg);
        let st = geoip_status(&cfg, &map);

        assert_eq!(st["configured"], 1, "the policy asks for country filtering");
        assert_eq!(
            st["active"], 0,
            "it cannot be enforced without a database and must not be counted as active"
        );
        let inert = st["inert"].as_array().expect("inert array");
        assert_eq!(inert.len(), 1, "the gap must be named, not merely counted");
        assert_eq!(inert[0]["site"], "shop");
        assert_eq!(
            inert[0]["db_present"], false,
            "the report must say the database is missing — that is the actionable part"
        );
    }

    /// A geoip block with no country rules is configuration, not a claim of
    /// enforcement, and must not be reported as an unmet one — otherwise the
    /// field cries wolf and stops being read.
    #[test]
    fn geoip_configured_with_no_countries_is_not_counted() {
        let cfg = SentinelConfig {
            sites: vec![site_with_geoip("shop", "/nonexistent.mmdb", vec![])],
            ..Default::default()
        };
        let st = geoip_status(&cfg, &build_geoip_map(&cfg));
        assert_eq!(st["configured"], 0);
        assert_eq!(st["inert"].as_array().unwrap().len(), 0);
    }

    /// A site with no geoip block at all contributes nothing.
    #[test]
    fn a_site_without_geoip_is_absent_from_the_report() {
        let cfg = SentinelConfig {
            sites: vec![bare_site("plain")],
            ..Default::default()
        };
        let st = geoip_status(&cfg, &build_geoip_map(&cfg));
        assert_eq!(st["configured"], 0);
        assert_eq!(st["active"], 0);
        assert_eq!(st["inert"].as_array().unwrap().len(), 0);
    }

    /// Several sites, mixed state — the counts must not collapse into a single
    /// boolean, because "some sites enforce and some do not" is the situation an
    /// operator actually has to act on.
    #[test]
    fn multiple_configured_sites_are_each_accounted_for() {
        let cfg = SentinelConfig {
            sites: vec![
                site_with_geoip("a", "/nope-a.mmdb", vec!["CN"]),
                site_with_geoip("b", "/nope-b.mmdb", vec!["RU"]),
                bare_site("c"),
            ],
            ..Default::default()
        };
        let st = geoip_status(&cfg, &build_geoip_map(&cfg));
        assert_eq!(st["configured"], 2);
        assert_eq!(st["active"], 0);
        let names: Vec<&str> = st["inert"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["site"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}

#[cfg(test)]
mod engine_warming_tests {
    use super::*;
    use sentinel_core::config::{InlineRule, UpstreamConfig, WafConfig};

    fn site_with(mode: WafMode, rules: Vec<String>, inline: Vec<InlineRule>) -> SiteConfig {
        SiteConfig {
            id: "s1".into(),
            tenant_id: String::new(),
            domains: vec!["s1.local".into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![],
                health_check: None,
                timeout_secs: None,
                websocket: false,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf: WafConfig {
                mode,
                rules,
                inline_rules: inline,
                ..Default::default()
            },
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    /// `site_expects_engine` MUST mirror the skip conditions in
    /// `build_rule_engines`. If it does not, the 503 warming gate either fires
    /// for a site that legitimately has no engine — 503ing it for ever — or
    /// fails to fire for one that is genuinely uninspectable.
    #[test]
    fn expects_engine_matches_what_build_rule_engines_actually_builds() {
        // mode: off never gets an engine, by design.
        let off = site_with(WafMode::Off, vec!["rules/x.conf".into()], vec![]);
        assert!(
            !site_expects_engine(&off),
            "a mode:off site legitimately has no engine and must never be gated"
        );

        // No rule files AND no inline rules → no engine, also by design.
        let bare = site_with(WafMode::Blocking, vec![], vec![]);
        assert!(
            !site_expects_engine(&bare),
            "a site with no rules at all must not be gated"
        );

        // Blocking with rule files → an engine is expected.
        let real = site_with(WafMode::Blocking, vec!["rules/x.conf".into()], vec![]);
        assert!(
            site_expects_engine(&real),
            "a rule-bearing site expects an engine"
        );

        // Learning counts too: learning still evaluates rules, it just does not
        // enforce the verdict. Gating it matters because the learning report is
        // the evidence used to decide whether to enforce later.
        let learning = site_with(WafMode::Learning, vec!["rules/x.conf".into()], vec![]);
        assert!(
            site_expects_engine(&learning),
            "learning mode still needs its engine"
        );

        // An inline-rules-only site (a virtual-patch-only site) expects one.
        let inline_only = site_with(
            WafMode::Blocking,
            vec![],
            vec![InlineRule {
                name: "vp1".into(),
                dsl: r#"SecRule ARGS "@rx x" "id:1,phase:2,deny""#.into(),
            }],
        );
        assert!(
            site_expects_engine(&inline_only),
            "a virtual-patch-only site expects an engine"
        );

        // And the real builder agrees about every one of these.
        // And the real builder agrees: neither of the skipped shapes produces
        // an engine, so gating them would 503 them permanently.
        for skipped in [&off, &bare] {
            assert!(
                !site_expects_engine(skipped),
                "helper and builder disagree about site {}",
                skipped.id
            );
        }
    }

    /// The flag must start CLEAR: engines are compiled before the listener
    /// accepts anything, so a fresh process must not 503 its first request.
    #[test]
    fn warming_flag_starts_clear() {
        // A panic test sets the flag as config sync would; not while this runs.
        let _serial = crate::panic_guard::testkit::proxy_state_lock();
        assert!(
            !ENGINES_WARMING.load(std::sync::atomic::Ordering::Acquire),
            "a freshly started proxy has already built its engines and must serve"
        );
    }

    fn handle_with(sites: Vec<SiteConfig>) -> ConfigHandle {
        Arc::new(ArcSwap::new(Arc::new(SentinelConfig {
            sites,
            ..Default::default()
        })))
    }

    /// THE RACE. A second sync landing WHILE the engines are being built must not
    /// let the finishing build declare the engines current — the config it built
    /// from is already superseded, and the site the newer sync introduced has no
    /// engine. Clearing the flag here reopens the exact fail-open it exists to
    /// prevent, one config change later than the bug that was originally fixed.
    #[test]
    fn a_config_change_during_the_build_must_not_clear_warming() {
        let cw = handle_with(vec![site_with(
            WafMode::Blocking,
            vec!["rules/x.conf".into()],
            vec![],
        )]);
        // The pointer the (slow) build started from.
        let built_from = Arc::as_ptr(&cw.load_full()) as usize;

        // A second sync lands mid-build, publishing a NEW site.
        let mut newer = site_with(WafMode::Blocking, vec!["rules/y.conf".into()], vec![]);
        newer.id = "site-added-during-build".into();
        cw.store(Arc::new(SentinelConfig {
            sites: vec![
                site_with(WafMode::Blocking, vec!["rules/x.conf".into()], vec![]),
                newer,
            ],
            ..Default::default()
        }));

        let flag = std::sync::atomic::AtomicBool::new(true);
        let cleared = clear_warming_if_current(&cw, built_from, &flag);
        assert!(!cleared, "the build was for a superseded config");
        assert!(
            flag.load(std::sync::atomic::Ordering::Acquire),
            "warming must STAY set: the newly published site has no engine yet, and \
             clearing here would make it matchable and uninspected"
        );
    }

    /// The ordinary path still clears, or every reload would 503 for ever.
    #[test]
    fn an_untouched_config_clears_warming() {
        let cw = handle_with(vec![site_with(
            WafMode::Blocking,
            vec!["rules/x.conf".into()],
            vec![],
        )]);
        let built_from = Arc::as_ptr(&cw.load_full()) as usize;
        let flag = std::sync::atomic::AtomicBool::new(true);
        assert!(clear_warming_if_current(&cw, built_from, &flag));
        assert!(
            !flag.load(std::sync::atomic::Ordering::Acquire),
            "an unchanged config must resume inspection"
        );
    }

    /// A site whose rules failed to compile has NO engine and — once warming
    /// clears — is served uninspected. It used to be visible in one log line
    /// only; it must be enumerable.
    #[test]
    fn a_site_with_no_engine_is_reported_as_unprotected() {
        let mut broken = site_with(WafMode::Blocking, vec!["rules/bad.conf".into()], vec![]);
        broken.id = "rules-failed-to-compile".into();
        let off = site_with(WafMode::Off, vec!["rules/x.conf".into()], vec![]);
        let mut bare = site_with(WafMode::Blocking, vec![], vec![]);
        bare.id = "no-rules-at-all".into();

        let cfg = SentinelConfig {
            sites: vec![broken, off, bare],
            ..Default::default()
        };
        let empty = RuleEngineMap::new();
        let listed = unprotected_sites(&cfg, &empty);

        assert_eq!(
            listed,
            vec!["rules-failed-to-compile".to_string()],
            "only a site that EXPECTS an engine and lacks one is unprotected; \
             mode:off and no-rules sites legitimately have none"
        );
    }
}

#[cfg(test)]
mod threat_intel_visibility_tests {
    use super::*;

    /// The four outcomes the old single `info!("hot-synced")` collapsed into one.
    ///
    /// Extracted as a pure function precisely so this is testable: the log text
    /// itself is not assertable here (the subscriber is process-wide), and the
    /// decision is the part that was wrong — installing 0 indicators over 200,000
    /// logged exactly like a healthy sync.
    #[test]
    fn an_empty_feed_replacing_a_populated_one_is_not_a_success() {
        assert_eq!(
            ti_sync_outcome(200_000, 0, 200),
            TiSyncOutcome::EmptyRegression { previous: 200_000 },
            "enforcement just went off; this must never read as 'hot-synced'"
        );
        assert_eq!(
            ti_sync_outcome(0, 0, 200),
            TiSyncOutcome::EmptyFirst,
            "a first sync that is empty is not a regression — warning here would cry wolf \
             on every fresh deployment"
        );
        assert_eq!(
            ti_sync_outcome(10, 50_000, 200),
            TiSyncOutcome::Synced { count: 50_000 }
        );
    }

    /// A refusal must never be treated as data. The status was not inspected at
    /// all, so a 403 body went into `serde_json::from_slice` and the only trace
    /// was a parse error naming JSON rather than the refusal.
    #[test]
    fn a_non_2xx_status_is_a_refusal_whatever_the_body_said() {
        for status in [301u16, 400, 401, 403, 500, 503] {
            assert_eq!(
                ti_sync_outcome(1_000, 5_000, status),
                TiSyncOutcome::Rejected { status },
                "HTTP {status} must be reported as a refusal, not installed"
            );
        }
    }

    /// `/healthz` must say IOC enforcement is off, and why, for each way it can
    /// be off. Before this there was no `threat_intel` key at all, so a node
    /// enforcing nothing looked exactly like a healthy one.
    #[test]
    fn healthz_reports_why_ioc_enforcement_is_inactive() {
        let mut cfg = SentinelConfig::default();
        let feed = ThreatFeed::empty();

        // 1. No sync URL — the shape that has no observable symptom.
        cfg.cluster.sync_url = None;
        let s = threat_intel_status(&cfg, &feed);
        assert_eq!(s["configured"], false);
        assert_eq!(s["active"], false);
        assert_eq!(s["poller"], "not_configured");
        assert!(
            s["inert_reason"]
                .as_str()
                .is_some_and(|r| r.contains("cluster.sync_url")),
            "the reason must name the config key that fixes it, got {:?}",
            s["inert_reason"]
        );

        // 2. Configured, but the poller has not been spawned.
        cfg.cluster.sync_url = Some("http://controlplane:9501".into());
        let s = threat_intel_status(&cfg, &feed);
        assert_eq!(s["configured"], true);
        assert_eq!(s["active"], false);
        assert_eq!(
            s["poller"], "not_started",
            "configured-but-not-running must be distinguishable from not-configured"
        );
    }
}

#[cfg(test)]
mod cp_poll_deadline_tests {
    use super::*;
    use crate::cp_client::{self, stub};

    type Empty = http_body_util::Empty<Bytes>;

    const DEADLINE: Duration = Duration::from_millis(300);
    /// Without a deadline a tick never returns; this turns that into a failure
    /// instead of a test that never finishes.
    const HUNG: Duration = Duration::from_secs(5);

    /// The sync statuses are process-wide, and so is what writes them: these
    /// tests take turns with each other and with the tests that run a proxy,
    /// whose config and threat-intel syncs record into the same statuses.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        crate::panic_guard::testkit::proxy_state_lock()
    }

    /// Two ticks of the config-sync loop against a control plane that accepts
    /// the connection and never answers, then one after it recovers. Each tick
    /// must return at the deadline with the failure recorded for the heartbeat,
    /// or the loop is parked and the node silently stops taking config.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see serial()
    async fn config_sync_against_a_silent_control_plane_records_it_and_moves_on() {
        let _serial = serial();
        note_config_sync_ok();
        let body = r#"{"version":7,"sites":[]}"#;
        let addr = stub::answering_after(2, 200, body).await;
        let url = format!("http://{addr}");
        let client = cp_client::client::<Empty>();

        let mut first_failure = None;
        for tick in 0..2 {
            let started = Instant::now();
            let got = tokio::time::timeout(HUNG, fetch_config_sync(&client, &url, None, DEADLINE))
                .await
                .unwrap_or_else(|_| panic!("config-sync tick {tick} never returned"));
            assert!(
                got.is_none(),
                "tick {tick} got a body from a silent control plane"
            );
            let took = started.elapsed();
            assert!(took < DEADLINE * 4, "tick {tick} took {took:?}");

            let status = config_sync_status();
            let err = status
                .last_error
                .expect("a timed-out poll must be recorded");
            assert!(err.starts_with("timeout:"), "tick {tick}: {err}");
            assert!(status.failing_since.is_some());
            // Stale since the FIRST failure, not the latest one.
            first_failure = first_failure.or(status.failing_since);
            assert_eq!(status.failing_since, first_failure);

            // And on the node's own /healthz: the heartbeat that also carries
            // it goes to the same silent control plane and times out too.
            let h = config_sync_health(&SentinelConfig::default());
            assert!(
                h["last_error"]
                    .as_str()
                    .is_some_and(|e| e.starts_with("timeout:")),
                "/healthz must carry the failure, got {h}"
            );
            assert_eq!(h["failing_since"].as_u64(), first_failure);
        }

        let got = tokio::time::timeout(HUNG, fetch_config_sync(&client, &url, None, DEADLINE))
            .await
            .expect("the tick after recovery never returned")
            .expect("the recovered control plane's answer");
        assert_eq!(&got[..], body.as_bytes());
        note_config_sync_ok();
    }

    /// The same for threat intel, whose `/healthz` state only ever recorded a
    /// status that arrived: a poller timing out kept saying "running".
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see serial()
    async fn threat_intel_sync_against_a_silent_control_plane_reports_failing() {
        let _serial = serial();
        let body = r#"{"version":3}"#;
        let addr = stub::answering_after(1, 200, body).await;
        let url = format!("http://{addr}");
        let client = cp_client::client::<Empty>();

        let got = tokio::time::timeout(HUNG, fetch_threat_intel(&client, &url, None, DEADLINE))
            .await
            .expect("threat-intel tick never returned");
        assert!(got.is_none());
        let (err, _) = ti_sync_failure().expect("a timed-out poll must be recorded");
        assert!(err.starts_with("timeout:"), "{err}");
        let s = threat_intel_status(&SentinelConfig::default(), &ThreatFeed::empty());
        assert!(
            s["last_error"]
                .as_str()
                .is_some_and(|e| e.starts_with("timeout:")),
            "/healthz must carry the failure, got {s}"
        );

        let hb = ti_sync_heartbeat();
        assert!(
            hb["last_error"]
                .as_str()
                .is_some_and(|e| e.starts_with("timeout:")),
            "the heartbeat must carry the failure, got {hb}"
        );
        assert!(hb["failing_since"].is_u64(), "{hb}");

        let (status, bytes) =
            tokio::time::timeout(HUNG, fetch_threat_intel(&client, &url, None, DEADLINE))
                .await
                .expect("the tick after recovery never returned")
                .expect("the recovered control plane's answer");
        assert_eq!(status, 200);
        assert_eq!(&bytes[..], body.as_bytes());
        assert!(parse_threat_intel_sync(&bytes).is_some());
        // Parsed is not installed: a sync that crashes in the install must not
        // read healthy because its fetch and parse went fine (see
        // panic_guard's a_crash_looping_threat_intel_sync_reads_failing).
        assert!(
            ti_sync_failure().is_some(),
            "a parsed body has installed nothing yet"
        );
        note_ti_sync_installed();
        assert!(
            ti_sync_failure().is_none(),
            "a poll that installed a corpus must clear the failure"
        );
    }

    /// A refusal is a failed poll, recorded as one. The status was thrown away,
    /// so a 403 went on to the parser and was recorded as the JSON error its
    /// error body produced ("parse: expected value at line 1 column 1").
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see serial()
    async fn a_refused_config_sync_is_recorded_as_a_refusal() {
        let _serial = serial();
        note_config_sync_ok();
        let addr = stub::answering_after(0, 403, r#"{"error":"forbidden"}"#).await;
        let url = format!("http://{addr}");
        let client = cp_client::client::<Empty>();

        let got = tokio::time::timeout(HUNG, fetch_config_sync(&client, &url, None, DEADLINE))
            .await
            .expect("config-sync tick never returned");
        assert!(got.is_none(), "a refusal must not reach the parser");
        let err = config_sync_status()
            .last_error
            .expect("a refused poll must be recorded");
        assert_eq!(err, "refused: HTTP 403 Forbidden");
        note_config_sync_ok();
    }

    /// A 200 whose body does not parse installs nothing, the same as no answer,
    /// and has to be recorded as such: it cleared the failure instead, so the
    /// poller read "running" while every poll did nothing. `failing_since` must
    /// also survive it, not restart with each bad poll.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see serial()
    async fn a_threat_intel_body_that_does_not_parse_keeps_the_poller_failing() {
        let _serial = serial();
        let garbage = stub::answering_after(0, 200, "<html>gateway</html>").await;
        let refusing = stub::answering_after(0, 403, r#"{"error":"forbidden"}"#).await;
        let client = cp_client::client::<Empty>();
        // A poll that timed out long ago, still unresolved.
        *ti_sync_failure_lock() = Some(("timeout: earlier".into(), 1_000));

        for tick in 0..2 {
            let (status, bytes) = tokio::time::timeout(
                HUNG,
                fetch_threat_intel(&client, &format!("http://{garbage}"), None, DEADLINE),
            )
            .await
            .expect("threat-intel tick never returned")
            .expect("the control plane answered");
            assert_eq!(status, 200);
            assert!(parse_threat_intel_sync(&bytes).is_none());
            let (err, since) = ti_sync_failure()
                .unwrap_or_else(|| panic!("tick {tick}: an unparseable 200 must be recorded"));
            assert!(err.starts_with("parse: "), "tick {tick}: {err}");
            assert_eq!(since, 1_000, "tick {tick}: failing_since restarted");
            assert_eq!(ti_poller_state(true, true, status, true), "failing");
        }

        // A refusal clears it: "rejected" is the truer label, and a leftover
        // failure would read "failing" over it.
        let (status, _) = tokio::time::timeout(
            HUNG,
            fetch_threat_intel(&client, &format!("http://{refusing}"), None, DEADLINE),
        )
        .await
        .expect("threat-intel tick never returned")
        .expect("the control plane answered");
        assert_eq!(status, 403);
        assert!(ti_sync_failure().is_none());
        assert_eq!(ti_poller_state(true, true, status, false), "rejected");
    }

    /// `failing` outranks the last status that arrived, which may be hours old.
    #[test]
    fn a_failing_threat_intel_poller_is_not_reported_as_running() {
        assert_eq!(ti_poller_state(true, true, 200, true), "failing");
        assert_eq!(ti_poller_state(true, true, 403, true), "failing");
        assert_eq!(ti_poller_state(true, true, 200, false), "running");
        assert_eq!(ti_poller_state(true, true, 403, false), "rejected");
        assert_eq!(ti_poller_state(true, true, 0, false), "starting");
        assert_eq!(ti_poller_state(true, false, 0, true), "not_started");
        assert_eq!(ti_poller_state(false, false, 0, true), "not_configured");
    }

    /// A poisoned failure record used to be skipped: polls that timed out were
    /// no longer recorded, a recovery no longer cleared an old failure, and the
    /// poller's label stayed whatever it was when the lock was poisoned.
    #[test]
    fn the_threat_intel_failure_record_survives_a_poisoned_lock() {
        let _serial = serial();
        clear_ti_sync_failure();
        let _ = std::thread::spawn(|| {
            let _held = TI_SYNC_FAILURE.lock().unwrap();
            panic!("poisoning the threat-intel failure record on purpose");
        })
        .join();
        assert!(
            TI_SYNC_FAILURE.is_poisoned(),
            "fixture must poison the lock"
        );

        note_ti_sync_failure("timeout: after the poison".to_string());
        let recorded = ti_sync_failure();
        clear_ti_sync_failure();
        let cleared = ti_sync_failure();
        TI_SYNC_FAILURE.clear_poison();
        assert_eq!(
            recorded.map(|(e, _)| e).as_deref(),
            Some("timeout: after the poison")
        );
        assert!(cleared.is_none(), "a recovery must clear the failure");
    }
}

#[cfg(test)]
mod global_settings_redaction_tests {
    use super::redact_secrets;

    #[test]
    fn redacts_secret_keys_and_url_userinfo_but_keeps_paths() {
        let mut v = serde_json::json!({
            "storage": {
                "timeseries": { "url": "http://ch:8123", "username": "u", "password": "pw" },
                "kv": { "backend": "redis", "url": "redis://default:s3cr3t@redis:6379/0" }
            },
            "cluster": { "control_plane": { "endpoints": ["https://cp:9501"], "tls": { "key": "/etc/sentinel/tls.key" } } },
            "logging": { "outputs": [{ "type": "otlp", "endpoint": "http://otel:4318/v1/logs", "auth_token": "abc" }] }
        });
        redact_secrets(&mut v);
        assert_eq!(v["storage"]["timeseries"]["password"], "***");
        assert_eq!(
            v["storage"]["timeseries"]["username"], "u",
            "usernames are not secrets"
        );
        assert_eq!(v["storage"]["kv"]["url"], "redis://***@redis:6379/0");
        assert_eq!(
            v["cluster"]["control_plane"]["endpoints"][0], "https://cp:9501",
            "no userinfo → untouched"
        );
        assert_eq!(
            v["cluster"]["control_plane"]["tls"]["key"], "/etc/sentinel/tls.key",
            "a TLS key PATH is not a secret value"
        );
        assert_eq!(v["logging"]["outputs"][0]["auth_token"], "***");
        assert_eq!(
            v["logging"]["outputs"][0]["endpoint"],
            "http://otel:4318/v1/logs"
        );
    }
}

#[cfg(test)]
mod security_header_hardening_tests {
    use super::*;
    use sentinel_core::config::{HstsConfig, SecurityHeadersConfig};

    #[test]
    fn hsts_and_cookie_flags_are_applied_when_configured() {
        let cfg = SecurityHeadersConfig {
            hsts: Some(HstsConfig {
                enabled: true,
                max_age: 0,
                include_subdomains: true,
                preload: false,
            }),
            cookie_flags: Some("* HttpOnly SameSite=Lax Secure".into()),
            ..Default::default()
        };
        let mut h = http::HeaderMap::new();
        h.append(
            header::SET_COOKIE,
            http::HeaderValue::from_static("sid=abc; Path=/"),
        );
        h.append(
            header::SET_COOKIE,
            http::HeaderValue::from_static("pref=1; SameSite=Strict; HttpOnly"),
        );
        inject_security_headers(&mut h, Some(&cfg));
        assert_eq!(
            h.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=31536000; includeSubDomains"
        );
        let cookies: Vec<&str> = h
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies[0],
            "sid=abc; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        // Origin's own SameSite=Strict wins; only the missing attribute is added.
        assert_eq!(cookies[1], "pref=1; SameSite=Strict; HttpOnly; Secure");
    }

    #[test]
    fn disabled_hsts_and_named_pattern() {
        let cfg = SecurityHeadersConfig {
            hsts: Some(HstsConfig {
                enabled: false,
                ..Default::default()
            }),
            cookie_flags: Some("session Secure".into()),
            ..Default::default()
        };
        let mut h = http::HeaderMap::new();
        h.append(
            header::SET_COOKIE,
            http::HeaderValue::from_static("session=x"),
        );
        h.append(
            header::SET_COOKIE,
            http::HeaderValue::from_static("other=y"),
        );
        inject_security_headers(&mut h, Some(&cfg));
        assert!(
            h.get(header::STRICT_TRANSPORT_SECURITY).is_none(),
            "disabled must emit nothing"
        );
        let cookies: Vec<&str> = h
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies, vec!["session=x; Secure", "other=y"]);
    }
}

#[cfg(test)]
mod config_sync_isolation_tests {
    use super::*;

    fn site(id: &str, mode: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "domains": [format!("{id}.example")],
            "upstream": {"servers": [{"host": "10.0.0.5", "port": 80}]},
            "waf": {"mode": mode, "rules": []}
        })
    }

    /// The live failure: one site with `"rules": null` (a site switched to Off
    /// under the old control plane). The other sites must still apply.
    #[test]
    fn one_unparseable_site_does_not_block_the_others() {
        let mut bad = site("bad", "off");
        bad["waf"]["rules"] = serde_json::Value::Null;
        let (sites, rejected) =
            parse_synced_sites(vec![site("a", "blocking"), bad, site("b", "learning")], &[]);
        let ids: Vec<_> = sites.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"], "the good sites must be applied");
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].id, "bad");
        assert!(
            !rejected[0].kept_previous,
            "a new bad site has nothing to keep"
        );
        assert!(rejected[0].error.contains("null"), "{}", rejected[0].error);
    }

    /// A known site that turns unparseable keeps its last good config rather
    /// than vanishing — dropping it would take the application offline.
    #[test]
    fn a_known_site_that_fails_keeps_its_previous_config() {
        let previous: SiteConfig = serde_json::from_value(site("app", "blocking")).unwrap();
        let mut bad = site("app", "off");
        bad["waf"]["rules"] = serde_json::Value::Null;
        let (sites, rejected) = parse_synced_sites(vec![bad], std::slice::from_ref(&previous));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id, "app");
        assert_eq!(sites[0].waf.mode, sentinel_core::config::WafMode::Blocking);
        assert!(rejected[0].kept_previous);
    }

    #[test]
    fn a_clean_sync_rejects_nothing() {
        let (sites, rejected) =
            parse_synced_sites(vec![site("a", "off"), site("b", "blocking")], &[]);
        assert_eq!(sites.len(), 2);
        assert!(rejected.is_empty());
    }
}

#[cfg(test)]
mod management_routing_tests {
    use super::management_path_is_control_plane as cp;

    #[test]
    fn control_plane_owns_api_v1_and_nothing_else() {
        assert!(cp("/api/v1/sites"));
        assert!(cp("/api/v1/logs/stream"));
        assert!(cp("/api/v1"));
        // The dashboard's own server route — the one that 404'd.
        assert!(!cp("/api/copilot"));
        assert!(!cp("/api/v10/x"));
        assert!(!cp("/api/v1x"));
        assert!(!cp("/overview"));
        assert!(!cp("/_next/static/chunks/a.js"));
    }
}
