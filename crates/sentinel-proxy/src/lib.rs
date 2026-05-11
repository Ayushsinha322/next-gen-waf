//! sentinel-proxy — async reverse proxy with WAF phase pipeline.
//!
//! Architecture:
//!   - One [`ProxyServer`] per listener (bind address).
//!   - Each accepted TCP connection is upgraded to TLS when the listener
//!     config includes a `tls` block.
//!   - hyper v1 serves HTTP/1.1 and HTTP/2 (HTTP/2 via ALPN on TLS).
//!   - A [`UpstreamPool`] holds a simple round-robin load balancer per site.
//!   - WAF phases 0–2 are wired to security modules and the rule engine.
//!
//! ## Phase pipeline
//! ```text
//! Phase 0: anti-DDoS (conn rate) → IP reputation → [future: eBPF XDP]
//! Phase 1: rate limit → bot detect → GeoIP → rule engine (CRS/SRL)
//! Phase 2: body inspection → anomaly threshold → ML (stub)
//! ```

pub mod upstream;

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{header, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use sentinel_core::{
    config::{
        ChallengeMode, ConfigHandle, IpReputationConfig, ListenerConfig, Protocol,
        SentinelConfig, SiteConfig, WafMode,
    },
    context::{Phase, RequestContext, WafDecision},
};
use sentinel_modules::{
    AntiDdos, BotDetector, BotVerdict, DdosVerdict, GeoIp, GeoVerdict, IpReputation, IpVerdict,
    RateLimiter,
};
use sentinel_rules::RuleEngine;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::upstream::UpstreamPool;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Maps `site_id` → compiled [`RuleEngine`].
type RuleEngineMap = HashMap<String, RuleEngine>;

/// Maps `site_id` → [`GeoIp`] filter (per-site country rules).
type GeoIpMap = HashMap<String, GeoIp>;

/// Cached suspect CIDRs fetched from external reputation feeds.
/// `(cidr_string, tags)` — stored in ArcSwap so the feed loader can swap
/// atomically without blocking request processing.
type FeedCache = Arc<ArcSwap<Vec<(String, Vec<String>)>>>;

// ---------------------------------------------------------------------------
// ModulesState — Phase 0/1 security module state shared across all handlers
// ---------------------------------------------------------------------------

/// Holds all Phase 2 security modules.
///
/// Fields marked "state preserved" are NOT rebuilt on SIGHUP so that
/// in-memory counters and block-lists survive config reloads.
struct ModulesState {
    /// Global IP reputation (merged across all sites, includes feed CIDRs).
    /// Rebuilt on config reload.
    ip_rep: ArcSwap<IpReputation>,

    /// Token-bucket rate limiter — state preserved across reloads.
    rate_limiter: RateLimiter,

    /// Bot / UA / JA4 classifier — rebuilt on reload (stateless).
    bot_detector: ArcSwap<BotDetector>,

    /// Per-site GeoIP country filters — rebuilt on reload.
    geoip_map: ArcSwap<GeoIpMap>,

    /// Connection-rate DDoS protector — state preserved across reloads.
    anti_ddos: AntiDdos,

    /// Suspect CIDRs fetched from external feeds; updated by the feed-loader
    /// background task and incorporated whenever ip_rep is rebuilt.
    feed_cache: FeedCache,
}

// ---------------------------------------------------------------------------
// ServerState — shared across all request handlers on a listener
// ---------------------------------------------------------------------------

struct ServerState {
    config: ConfigHandle,
    upstream_pool: Arc<UpstreamPool>,
    engines: Arc<ArcSwap<RuleEngineMap>>,
    modules: Arc<ModulesState>,
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

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

        let initial_engines = build_rule_engines(&cfg);
        let engines: Arc<ArcSwap<RuleEngineMap>> =
            Arc::new(ArcSwap::new(Arc::new(initial_engines)));

        let feed_cache: FeedCache = Arc::new(ArcSwap::new(Arc::new(Vec::new())));

        let modules = Arc::new(ModulesState {
            ip_rep: ArcSwap::new(Arc::new(build_ip_reputation(&cfg, &[]))),
            rate_limiter: RateLimiter::new(),
            bot_detector: ArcSwap::new(Arc::new(BotDetector::new())),
            geoip_map: ArcSwap::new(Arc::new(build_geoip_map(&cfg))),
            anti_ddos: build_anti_ddos(&cfg),
            feed_cache: Arc::clone(&feed_cache),
        });

        let state = Arc::new(ServerState {
            config: Arc::clone(&self.config),
            upstream_pool,
            engines: Arc::clone(&engines),
            modules: Arc::clone(&modules),
        });

        // --- Background task: config hot-reload watcher ---
        // Detects SIGHUP reloads by comparing the Arc pointer of the stored
        // config.  Rebuilds stateless modules (rule engines, ip_rep, geoip,
        // bot detector) on every change.  Stateful modules (rate_limiter,
        // anti_ddos) are intentionally NOT rebuilt.
        {
            let config_watch = Arc::clone(&self.config);
            let engines_swap = Arc::clone(&engines);
            let modules_ref = Arc::clone(&modules);
            tokio::spawn(async move {
                let mut last_ptr = Arc::as_ptr(&config_watch.load_full()) as usize;
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let current = config_watch.load_full();
                    let ptr = Arc::as_ptr(&current) as usize;
                    if ptr != last_ptr {
                        last_ptr = ptr;
                        let new_engines = build_rule_engines(&current);
                        let rule_count: usize =
                            new_engines.values().map(|e| e.rule_count()).sum();
                        engines_swap.store(Arc::new(new_engines));

                        let feed_cidrs = modules_ref.feed_cache.load_full();
                        modules_ref
                            .ip_rep
                            .store(Arc::new(build_ip_reputation(&current, &feed_cidrs)));
                        modules_ref
                            .bot_detector
                            .store(Arc::new(BotDetector::new()));
                        modules_ref
                            .geoip_map
                            .store(Arc::new(build_geoip_map(&current)));
                        info!(
                            rules = rule_count,
                            "rule engines and security modules hot-reloaded"
                        );
                    }
                }
            });
        }

        // --- Background task: RateLimiter GC (every 60 s) ---
        {
            let modules_ref = Arc::clone(&modules);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
                loop {
                    interval.tick().await;
                    modules_ref.rate_limiter.gc();
                    debug!(
                        ip_buckets = modules_ref.rate_limiter.per_ip_bucket_count(),
                        site_buckets = modules_ref.rate_limiter.per_site_bucket_count(),
                        "rate-limiter GC complete"
                    );
                }
            });
        }

        // --- Background task: AntiDdos GC (every 60 s) ---
        {
            let modules_ref = Arc::clone(&modules);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
                loop {
                    interval.tick().await;
                    modules_ref.anti_ddos.gc();
                    debug!(
                        blocked = modules_ref.anti_ddos.blocked_count(),
                        tracked = modules_ref.anti_ddos.tracked_count(),
                        "anti-DDoS GC complete"
                    );
                }
            });
        }

        // --- Background task: IP reputation feed loader (every 5 min) ---
        // Fetches CIDR lists from configured external feeds (AbuseIPDB,
        // Spamhaus, etc.) and rebuilds the in-memory IP reputation table.
        // HTTP-only in Phase 2; HTTPS support added in Phase 3 (hyper-rustls).
        {
            let config_watch = Arc::clone(&self.config);
            let modules_ref = Arc::clone(&modules);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
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
                                info!(
                                    url = %feed.url,
                                    count = cidrs.len(),
                                    "IP reputation feed loaded"
                                );
                                for cidr in cidrs {
                                    new_cidrs.push((cidr, vec!["feed".to_string()]));
                                }
                            }
                            Err(e) => {
                                warn!(url = %feed.url, "IP feed fetch failed: {e}");
                            }
                        }
                    }

                    let new_arc: Arc<Vec<(String, Vec<String>)>> = Arc::new(new_cidrs);
                    modules_ref.feed_cache.store(Arc::clone(&new_arc));
                    let new_ip_rep = build_ip_reputation(&cfg, &new_arc);
                    let entry_count = new_ip_rep.entry_count();
                    modules_ref.ip_rep.store(Arc::new(new_ip_rep));
                    info!(entries = entry_count, "IP reputation table rebuilt from feeds");
                }
            });
        }

        let mut handles = Vec::new();
        for listener_cfg in cfg.listeners.clone() {
            let state2 = Arc::clone(&state);
            let mut sd = shutdown.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_listener(listener_cfg, state2, &mut sd).await {
                    error!("listener error: {e}");
                }
            });
            handles.push(handle);
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
        Some(build_tls_acceptor(cfg.tls.as_ref().unwrap())?)
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
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, acceptor, protos, state).await {
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
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;

    if let Some(acceptor) = tls_acceptor {
        let tls = acceptor
            .accept(stream)
            .await
            .context("TLS handshake failed")?;

        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let io = TokioIo::new(tls);

        if negotiated.as_deref() == Some(b"h2") {
            serve_http2(io, peer, state).await
        } else {
            serve_http1(io, peer, state).await
        }
    } else {
        let io = TokioIo::new(stream);
        if protocols.contains(&Protocol::Http2) && !protocols.contains(&Protocol::Http1) {
            serve_http2(io, peer, state).await
        } else {
            serve_http1(io, peer, state).await
        }
    }
}

async fn serve_http1<T>(
    io: TokioIo<T>,
    peer: SocketAddr,
    state: Arc<ServerState>,
) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                async move { handle_request(s, peer, req).await }
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
) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let s = Arc::clone(&state);
                async move { handle_request(s, peer, req).await }
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
) -> Result<Response<BoxBody>, Infallible> {
    match proxy(state, peer, req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!("proxy error: {e:#}");
            Ok(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"))
        }
    }
}

async fn proxy(
    state: Arc<ServerState>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> anyhow::Result<Response<BoxBody>> {
    let cfg = state.config.load();
    let engine_map = state.engines.load_full();

    // --- Phase 0: Connection ---
    let mut ctx = RequestContext::new(peer.ip(), peer.port());

    // Anti-DDoS: connection-rate check (before any parsing — fastest possible
    // reject path for volumetric attacks).
    match state.modules.anti_ddos.check_connection(ctx.client_ip) {
        DdosVerdict::Block { reason } => {
            ctx.decision = WafDecision::Block;
            ctx.block_reason = Some(reason);
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

    ctx.advance_phase(Phase::RequestHeaders);

    // --- Phase 1: Request headers ---
    let (mut parts, body) = req.into_parts();

    ctx.http_version = parts.version;
    ctx.method = parts.method.clone();
    ctx.uri = parts.uri.clone();
    ctx.request_headers = parts.headers.clone();

    // Match site by Host header.
    let host = ctx.host().map(str::to_owned);
    let site = host
        .as_deref()
        .and_then(|h| cfg.sites.iter().find(|s| site_matches(s, h)));

    if let Some(s) = &site {
        ctx.site_id = Some(s.id.clone());
    }

    // WAF phase 1: rate limit → bot detect → GeoIP → rule engine.
    phase1_headers(&mut ctx, site, &engine_map, &state.modules)?;

    if ctx.decision == WafDecision::Block {
        let resp = block_response(&ctx);
        ctx.response_status = Some(resp.status());
        ctx.advance_phase(Phase::Logging);
        log_request(&ctx);
        return Ok(resp);
    }

    // --- Phase 2: Request body ---
    ctx.advance_phase(Phase::RequestBody);

    let should_inspect_body = site
        .map(|s| s.waf.mode != WafMode::Off)
        .unwrap_or(false);

    let boxed_body: BoxBody = if should_inspect_body {
        let collected = body
            .collect()
            .await
            .context("collecting request body")?;
        let bytes = collected.to_bytes();
        ctx.request_body = Some(bytes.clone());
        phase2_body(&mut ctx, site, &engine_map)?;
        if ctx.decision == WafDecision::Block {
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

    let upstream_addr = state
        .upstream_pool
        .next_server(&site_cfg.id)
        .ok_or_else(|| anyhow!("no healthy upstream for site '{}'", site_cfg.id))?;

    ctx.upstream_addr = Some(
        format!("{}:{}", upstream_addr.host, upstream_addr.port)
            .parse()
            .ok()
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
    );

    let upstream_uri = build_upstream_uri(&upstream_addr.host, upstream_addr.port, &parts.uri)?;

    strip_hop_by_hop(&mut parts.headers);
    inject_forwarding_headers(&mut parts.headers, peer.ip())?;

    parts.uri = upstream_uri;
    let upstream_req = Request::from_parts(parts, boxed_body);

    let upstream_start = std::time::Instant::now();
    let upstream_resp = state
        .upstream_pool
        .send_request(&site_cfg.id, upstream_req)
        .await
        .context("upstream request failed")?;
    ctx.upstream_latency_us = Some(upstream_start.elapsed().as_micros() as u64);

    // --- Phase 4: Response headers ---
    ctx.advance_phase(Phase::ResponseHeaders);
    let (mut resp_parts, resp_body) = upstream_resp.into_parts();
    ctx.response_status = Some(resp_parts.status);
    ctx.response_headers = Some(resp_parts.headers.clone());

    strip_hop_by_hop(&mut resp_parts.headers);
    inject_security_headers(&mut resp_parts.headers);

    // --- Phase 5: Response body (DLP stub) ---
    ctx.advance_phase(Phase::ResponseBody);

    // --- Phase 6: Logging ---
    ctx.advance_phase(Phase::Logging);
    log_request(&ctx);

    Ok(Response::from_parts(resp_parts, resp_body.boxed()))
}

// ---------------------------------------------------------------------------
// WAF phases
// ---------------------------------------------------------------------------

/// Phase 1: rate limit → bot detect → GeoIP → rule engine.
fn phase1_headers(
    ctx: &mut RequestContext,
    site: Option<&SiteConfig>,
    engines: &RuleEngineMap,
    modules: &ModulesState,
) -> anyhow::Result<()> {
    let Some(site) = site else { return Ok(()) };
    if site.waf.mode == WafMode::Off {
        return Ok(());
    }

    // Inject TX:DETECTION_PARANOIA_LEVEL so CRS skip-gate rules (@lt N) work.
    ctx.tx_vars.insert(
        "DETECTION_PARANOIA_LEVEL".to_owned(),
        site.waf.paranoia_level.to_string(),
    );

    // --- Rate limiting ---
    if ctx.decision == WafDecision::Allow {
        if let Some(ref rl_cfg) = site.waf.rate_limit {
            if modules.rate_limiter.check(&site.id, ctx.client_ip, rl_cfg) {
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
                    ctx.tx_vars
                        .insert("bot_suspicious".to_string(), "1".to_string());
                    ctx.anomaly_score = ctx.anomaly_score.saturating_add(2);
                    if bot_cfg.challenge != ChallengeMode::Off {
                        ctx.decision = WafDecision::Challenge;
                        ctx.block_reason = Some(
                            "suspicious bot UA — browser challenge required".to_string(),
                        );
                    }
                }
                BotVerdict::GoodBot(name) => {
                    ctx.tx_vars.insert("bot_good".to_string(), name.clone());
                }
                _ => {}
            }
        }
    }

    // --- GeoIP country filter ---
    if ctx.decision == WafDecision::Allow {
        if site.waf.geoip.is_some() {
            let geoip_map = modules.geoip_map.load();
            if let Some(geoip) = geoip_map.get(&site.id) {
                match geoip.check(ctx.client_ip) {
                    GeoVerdict::Block { country_code } => {
                        ctx.decision = WafDecision::Block;
                        ctx.block_reason =
                            Some(format!("country blocked: {country_code}"));
                    }
                    GeoVerdict::Allow | GeoVerdict::Unknown => {}
                }
            }
        }
    }

    // --- Rule engine (CRS / SRL) ---
    if ctx.decision == WafDecision::Allow {
        if let Some(engine) = engines.get(&site.id) {
            engine.evaluate(ctx, Phase::RequestHeaders);
        }
    }

    enforce_mode(ctx, &site.waf.mode);
    Ok(())
}

/// Phase 2: body inspection + anomaly threshold catch-all.
fn phase2_body(
    ctx: &mut RequestContext,
    site: Option<&SiteConfig>,
    engines: &RuleEngineMap,
) -> anyhow::Result<()> {
    let Some(site) = site else { return Ok(()) };
    if site.waf.mode == WafMode::Off {
        return Ok(());
    }

    if let Some(engine) = engines.get(&site.id) {
        engine.evaluate(ctx, Phase::RequestBody);
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

/// In `Learning` mode, downgrade `Block` / `Challenge` to `Log`.
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
                warn!(site = %site.id, "failed to load rule engine — site unprotected: {e:#}");
            }
        }
    }
    map
}

/// Build merged IP reputation from site configs + feed-loader cache.
///
/// Config-sourced allow/block CIDRs take priority (processed first by
/// `IpReputation::from_configs`).  Feed CIDRs are then added as suspect
/// entries, which only add anomaly score rather than outright blocking.
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

/// Build per-site GeoIP filters.
///
/// If a site has no `geoip` config, or the specified `.mmdb` file is missing,
/// that site's entry is omitted from the map (all IPs pass).
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

/// Build the global anti-DDoS protector from config.
///
/// Uses the first site with `anti_ddos.enabled = true`.  If no site has
/// anti-DDoS enabled, returns a disabled instance that always allows.
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

fn load_site_engine(site: &SiteConfig) -> anyhow::Result<RuleEngine> {
    use sentinel_rules::dsl::ast::{RuleFile, RuleItem};

    let mut merged = RuleFile::default();
    for path_str in &site.waf.rules {
        let path = std::path::Path::new(path_str);
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("reading rule file '{path_str}'"))?;

        let file: RuleFile = if path.extension().and_then(|e| e.to_str()) == Some("conf") {
            // Pass the .conf file's parent directory so @pmFromFile can be resolved.
            let data_dir = path.parent();
            sentinel_rules::import_secrule_conf_dir(&source, data_dir)
                .with_context(|| format!("importing CRS conf '{path_str}'"))?
        } else {
            sentinel_rules::parse_srl(&source)
                .map_err(|e| anyhow!("SRL parse error in '{path_str}': {e}"))?
        };

        merged.items.extend(file.items);
    }

    // Paranoia level gating: remove rules tagged paranoia-level/N where N > configured PL.
    // Untagged rules (no paranoia-level tag) are treated as PL 1 and always run.
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
            "rule engine: paranoia level gating removed rules"
        );
    }

    sentinel_rules::compile(merged)
        .map(RuleEngine::new)
        .with_context(|| format!("compiling rules for site '{}'", site.id))
}

// ---------------------------------------------------------------------------
// IP feed loader helpers
// ---------------------------------------------------------------------------

/// Fetch a CIDR block-list from an HTTP URL and return one CIDR per line.
///
/// Lines starting with `#` and blank lines are skipped.
/// HTTPS URLs are not yet supported (Phase 3+); a descriptive error is
/// returned so the caller can log and continue.
async fn fetch_feed_cidrs(url: &str) -> anyhow::Result<Vec<String>> {
    if url.starts_with("https://") {
        anyhow::bail!(
            "HTTPS feeds require rustls connector (Phase 3+): {url}. \
             Use an HTTP mirror or a file:// path for now."
        );
    }

    if let Some(path) = url.strip_prefix("file://") {
        let text = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("reading file feed: {path}"))?;
        return Ok(parse_cidr_text(&text));
    }

    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let uri: Uri = url.parse().with_context(|| format!("invalid feed URL: {url}"))?;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("User-Agent", "sentinel-waf/0.1 (ip-reputation-feed)")
        .body(Empty::<Bytes>::new())
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
    site.domains.iter().any(|d| {
        if d.starts_with("*.") {
            let suffix = &d[1..];
            host.ends_with(suffix) || host == &d[2..]
        } else {
            d == host
        }
    })
}

fn build_upstream_uri(host: &str, port: u16, original: &Uri) -> anyhow::Result<Uri> {
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let s = format!("http://{}:{}{}", host, port, path_and_query);
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

fn inject_forwarding_headers(
    headers: &mut http::HeaderMap,
    client_ip: std::net::IpAddr,
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
    insert(
        headers,
        "referrer-policy",
        "strict-origin-when-cross-origin",
    );
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
    let rule_ids_str = rule_ids.join(",");
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
        rule_ids = rule_ids_str,
        decision = ?ctx.decision,
        block_reason = ctx.block_reason.as_deref().unwrap_or(""),
        "request"
    );
}

// ---------------------------------------------------------------------------
// TLS acceptor builder
// ---------------------------------------------------------------------------

fn build_tls_acceptor(tls: &sentinel_core::config::TlsFileConfig) -> anyhow::Result<TlsAcceptor> {
    let cert_path = tls
        .cert
        .as_ref()
        .ok_or_else(|| anyhow!("listener TLS config missing 'cert' path"))?;
    let key_path = tls
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("listener TLS config missing 'key' path"))?;

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
