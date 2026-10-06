//! External IP-reputation feeds (`waf.ip_reputation.feeds` in a site policy).
//!
//! A feed URL is typed into the console by a site operator, synced to every
//! data-plane node and fetched from each of them on a timer. Console input
//! therefore drives an outbound fetcher on every node, and each fetch is
//! bounded on every axis this module controls:
//!
//! - **scheme** — http and https only. A `file://` branch used to read any path
//!   on the node, and every line of that file that was not a CIDR was then
//!   logged verbatim. Nothing in the repository (tests, docs, deploy files, the
//!   console, which labels the field "HTTP(S) URL") used it, so it is gone
//!   rather than gated; a local list can be served over HTTP.
//! - **time** — ONE deadline covers connect, TLS, headers and body. The old 30 s
//!   timeout ended when the headers arrived, so a feed that answered and then
//!   trickled its body held the loader forever.
//! - **size** — the body is read through [`Limited`]; a larger body fails the
//!   feed instead of being buffered without bound.
//! - **entries** — capped per feed and per node. `IpReputation::check` scans the
//!   suspect list linearly on every request, so this cap is also the bound on
//!   what feeds add to every request's latency.
//! - **count** — at most [`FeedLimits::max_feeds`] distinct URLs per node, and a
//!   URL listed by several sites is fetched once. The control plane allows 16
//!   per site; this is the node's own bound for configs that bypassed it.
//! - **pass** — feeds are fetched a few at a time under one deadline for the
//!   whole pass, so feeds that never answer cannot hold the others back for
//!   (count × timeout); what the budget does not reach is reported, not waited on.
//!
//! The node-wide cap is shared fairly between the sites that list feeds: before,
//! it went to whichever site came first in the config, and one site's large
//! feeds stopped every later site's from loading. A feed whose fetch fails keeps
//! the entries of its last good fetch for [`FeedLimits::max_stale`] instead of
//! dropping to nothing until the next good one. Every outcome — loaded, stale,
//! failed, skipped, truncated — is in `/healthz` (`ip_feeds`) and `/metrics`,
//! because each is a way for a feed to show as set in the console and enforce
//! nothing.
//!
//! Operator knobs (environment, clamped, WARN on a bad value):
//! `SENTINEL_IP_FEED_MAX_ENTRIES`, `SENTINEL_IP_FEED_MAX_TOTAL_ENTRIES`,
//! `SENTINEL_IP_FEED_TIMEOUT_SECS`, `SENTINEL_IP_FEED_MAX_BYTES`.
//!
//! Redirects are not followed (the legacy hyper client never does), so a 3xx
//! cannot move the fetch to another scheme or host; it fails as a non-2xx.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use sentinel_core::config::{IpFeedConfig, SentinelConfig};
use sentinel_core::redact::REDACTED;
use sentinel_modules::ip_reputation::parse_ip_or_cidr;
use tokio::time::Instant;
use tracing::{info, warn};

/// Largest feed body read into memory. A feed at the per-feed entry cap is
/// about 1-2 MiB of text; past this it is the wrong URL or a hostile server.
const FEED_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// One deadline for the whole fetch: connect, TLS, headers and body together.
const FEED_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Entries kept from one feed; the rest are dropped with a warning.
const FEED_MAX_ENTRIES: usize = 50_000;
/// Entries kept across every feed on the node. Every request pays for the whole
/// table: `IpReputation::check` on an IPv4 address in no feed measured ~3.7 µs
/// per 1,000 entries in the release profile (~0.38 ms at this cap, ~1 ms at
/// 200k, where it leaves the cache), ~13 µs per 1,000 at opt-level 1.
const FEED_MAX_TOTAL_ENTRIES: usize = 100_000;
/// Distinct feed URLs fetched per pass on one node.
const FEED_MAX_FEEDS: usize = 64;
/// Feeds fetched at once.
const FEED_CONCURRENCY: usize = 4;
/// Deadline for a whole pass. Under the loader's 300 s period, so one pass is
/// over before the next is due.
const FEED_PASS_BUDGET: Duration = Duration::from_secs(240);
/// How long a failing feed keeps the entries of its last good fetch.
const FEED_MAX_STALE: Duration = Duration::from_secs(24 * 3600);
/// Rejected lines quoted in the log, and how much of each.
const FEED_LOG_SAMPLES: usize = 3;
const FEED_SAMPLE_CHARS: usize = 64;
/// How much of a feed URL or error text is logged and reported.
const FEED_SHOWN_CHARS: usize = 160;
const FEED_ERROR_CHARS: usize = 300;

/// The bounds one loader applies. Production uses [`FeedLimits::from_env`];
/// tests shrink them so a cap can be hit without megabytes of fixture.
#[derive(Debug, Clone)]
pub(crate) struct FeedLimits {
    max_body_bytes: usize,
    timeout: Duration,
    max_entries: usize,
    max_total_entries: usize,
    max_feeds: usize,
    concurrency: usize,
    pass_budget: Duration,
    max_stale: Duration,
}

impl Default for FeedLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: FEED_MAX_BODY_BYTES,
            timeout: FEED_FETCH_TIMEOUT,
            max_entries: FEED_MAX_ENTRIES,
            max_total_entries: FEED_MAX_TOTAL_ENTRIES,
            max_feeds: FEED_MAX_FEEDS,
            concurrency: FEED_CONCURRENCY,
            pass_budget: FEED_PASS_BUDGET,
            max_stale: FEED_MAX_STALE,
        }
    }
}

impl FeedLimits {
    /// The defaults, with the operator's `SENTINEL_IP_FEED_*` overrides.
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let d = Self::default();
        // Ranges: the per-request scan cost above bounds the entry caps; the
        // timeout stays inside the pass budget; the body cap must hold a feed
        // at a useful entry cap and not exhaust the node.
        let total = knob(
            &get,
            "SENTINEL_IP_FEED_MAX_TOTAL_ENTRIES",
            d.max_total_entries,
            1,
            1_000_000,
        );
        Self {
            max_entries: knob(
                &get,
                "SENTINEL_IP_FEED_MAX_ENTRIES",
                d.max_entries,
                1,
                1_000_000,
            ),
            max_total_entries: total,
            timeout: Duration::from_secs(knob(
                &get,
                "SENTINEL_IP_FEED_TIMEOUT_SECS",
                d.timeout.as_secs() as usize,
                1,
                d.pass_budget.as_secs() as usize,
            ) as u64),
            max_body_bytes: knob(
                &get,
                "SENTINEL_IP_FEED_MAX_BYTES",
                d.max_body_bytes,
                64 * 1024,
                256 * 1024 * 1024,
            ),
            ..d
        }
    }
}

/// One whole-number setting: unset or blank keeps the default, out of range is
/// clamped, anything else keeps the default — the last two with a WARN.
fn knob(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> usize {
    let Some(raw) = get(name).filter(|v| !v.trim().is_empty()) else {
        return default;
    };
    match raw.trim().parse::<usize>() {
        Ok(v) if (min..=max).contains(&v) => v,
        Ok(v) => {
            let used = v.clamp(min, max);
            warn!(
                var = name,
                value = v,
                used,
                "IP feed setting is outside {min}-{max}; clamped"
            );
            used
        }
        Err(_) => {
            warn!(var = name, value = %raw, used = default, "IP feed setting is not a whole number; using the default");
            default
        }
    }
}

/// Every feed configured on the node, with the site that lists it, in config
/// order. The site is kept so the node-wide cap can be shared between sites and
/// the report can say whose feed failed.
pub(crate) fn configured_feeds(cfg: &SentinelConfig) -> Vec<(String, IpFeedConfig)> {
    let mut out = Vec::new();
    for site in &cfg.sites {
        if let Some(rep) = site.waf.ip_reputation.as_ref() {
            out.extend(rep.feeds.iter().map(|f| (site.id.clone(), f.clone())));
        }
    }
    out
}

/// What one feed body yielded.
#[derive(Debug, Default)]
struct ParsedFeed {
    /// Addresses / CIDR ranges `IpReputation` accepts, in feed order.
    entries: Vec<String>,
    /// Valid entries dropped because `max_entries` was reached.
    over_cap: usize,
    /// Lines that are neither blank, a `#` comment, nor an address / range.
    rejected: usize,
    /// The first few rejected lines, truncated — never the whole line, and
    /// never all of them: a feed URL pointed at the wrong document would
    /// otherwise copy that document into the log line by line.
    rejected_samples: Vec<String>,
}

/// The last successful fetch of one URL, reused while later fetches fail.
struct LastGood {
    entries: Arc<Vec<String>>,
    over_cap: usize,
    rejected: usize,
    at: Instant,
    at_unix: u64,
}

/// What happened to one distinct feed URL in a pass.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct FeedStatus {
    /// Sites listing this URL. The first owns it for the node-wide share.
    sites: Vec<String>,
    /// Userinfo and query withheld: either may carry the feed's credential.
    url: String,
    /// `loaded`, `stale` (this fetch failed; the last good one is in use),
    /// `failed` (nothing in use) or `skipped` (over the per-node feed limit).
    state: &'static str,
    /// Entries this feed put in the node table.
    entries: usize,
    /// Valid entries past the per-feed cap.
    dropped_over_feed_cap: usize,
    /// Entries cut because the owning site's share of the node cap ran out.
    dropped_over_node_cap: usize,
    /// Lines that were not an address or range.
    rejected_lines: usize,
    last_error: Option<String>,
    /// Unix seconds of the last successful fetch on this node, if any.
    last_success_at: Option<u64>,
    /// Age in seconds of the entries in use, when they are not from this pass.
    stale_secs: Option<u64>,
}

/// The outcome of one pass, for `/healthz` and `/metrics`.
#[derive(Debug, Clone, Default)]
pub(crate) struct FeedReport {
    feeds: Vec<FeedStatus>,
    /// Entries in the node table this pass built.
    entries: usize,
    finished_at: u64,
    pass_millis: u64,
    limits: FeedLimits,
}

/// A built table and the report that explains it.
pub(crate) struct FeedLoad {
    pub(crate) table: Vec<(String, Vec<String>)>,
    /// False only when this table and the previous pass's are both empty, so
    /// the node's table needs no rebuild. The loader used to skip every pass
    /// with no feed configured, which kept a removed feed enforced until restart.
    pub(crate) rebuild: bool,
    pub(crate) report: FeedReport,
}

/// Holds what must outlive one pass: the limits, each URL's last good fetch,
/// and whether the last table handed out was empty.
pub(crate) struct FeedLoader {
    limits: FeedLimits,
    last_good: HashMap<String, LastGood>,
    last_table_empty: bool,
}

/// One distinct URL and the sites that list it, in config order.
struct DistinctFeed {
    url: String,
    sites: Vec<String>,
}

/// A feed's contribution before the node cap is applied.
struct Outcome {
    state: &'static str,
    entries: Arc<Vec<String>>,
    over_cap: usize,
    rejected: usize,
    last_error: Option<String>,
    last_success_at: Option<u64>,
    stale_secs: Option<u64>,
}

impl FeedLoader {
    pub(crate) fn new(limits: FeedLimits) -> Self {
        Self {
            limits,
            last_good: HashMap::new(),
            // The node starts with an empty feed table.
            last_table_empty: true,
        }
    }

    /// Make the next pass rebuild the node's table, whatever table it builds.
    /// For a loader loop restarted after a panic: the run before may have built
    /// a table and died before the node's tables were rebuilt from it, so the
    /// last table handed out says nothing about what the node holds.
    pub(crate) fn rebuild_next_pass(&mut self) {
        self.last_table_empty = false;
    }

    /// Fetch every configured feed and build the node-wide suspect table.
    ///
    /// A feed that fails costs only itself; the others still load.
    pub(crate) async fn load(&mut self, feeds: &[(String, IpFeedConfig)]) -> FeedLoad {
        let started = Instant::now();
        let limits = self.limits.clone();

        // One entry per URL. Fetching a URL once per site that lists it spent
        // the node cap on copies and pushed out other sites' feeds.
        let mut distinct: Vec<DistinctFeed> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for (site, feed) in feeds {
            let url = feed.url.trim();
            match index.get(url) {
                Some(&i) => {
                    if !distinct[i].sites.contains(site) {
                        distinct[i].sites.push(site.clone());
                    }
                }
                None => {
                    index.insert(url, distinct.len());
                    distinct.push(DistinctFeed {
                        url: url.to_string(),
                        sites: vec![site.clone()],
                    });
                }
            }
        }
        let skipped = distinct.split_off(distinct.len().min(limits.max_feeds));
        if !skipped.is_empty() {
            warn!(
                configured = distinct.len() + skipped.len(),
                skipped = skipped.len(),
                "more than {} distinct IP feeds are configured on this node; the rest are not fetched",
                limits.max_feeds
            );
        }

        let results = fetch_all(
            distinct.iter().map(|d| d.url.clone()).collect(),
            &limits,
            started + limits.pass_budget,
        )
        .await;

        let outcomes: Vec<Outcome> = distinct
            .iter()
            .zip(results)
            .map(|(d, r)| self.outcome(&d.url, r))
            .collect();
        // Forget feeds that are no longer fetched, so a removed feed's entries
        // cannot come back as "stale".
        let fetched: HashSet<&str> = distinct.iter().map(|d| d.url.as_str()).collect();
        self.last_good.retain(|u, _| fetched.contains(u.as_str()));

        // The node cap, shared between owning sites in max-min fair shares.
        let mut site_order: Vec<&str> = Vec::new();
        let mut demand: HashMap<&str, usize> = HashMap::new();
        for (d, o) in distinct.iter().zip(&outcomes) {
            let owner = d.sites[0].as_str();
            if !demand.contains_key(owner) {
                site_order.push(owner);
            }
            *demand.entry(owner).or_default() += o.entries.len();
        }
        let shares = fair_shares(
            &site_order.iter().map(|s| demand[s]).collect::<Vec<_>>(),
            limits.max_total_entries,
        );
        let mut left: HashMap<&str, usize> = site_order.iter().copied().zip(shares).collect();

        let mut table: Vec<(String, Vec<String>)> = Vec::new();
        let mut report = FeedReport {
            limits: limits.clone(),
            ..FeedReport::default()
        };
        for (d, o) in distinct.iter().zip(outcomes) {
            let owner = d.sites[0].as_str();
            let room = left.get_mut(owner).expect("every owner has a share");
            let kept = o.entries.len().min(*room);
            *room -= kept;
            let shown = redact_url(&d.url);
            if kept < o.entries.len() {
                warn!(
                    url = %shown,
                    site = owner,
                    kept,
                    dropped = o.entries.len() - kept,
                    "IP feeds on this node reached the limit of {} entries, shared between the {} \
                     sites with feeds; the rest of this feed is not used",
                    limits.max_total_entries,
                    site_order.len()
                );
            }
            if o.state != "failed" {
                info!(url = %shown, count = kept, state = o.state, "IP feed loaded");
            }
            table.extend(
                o.entries
                    .iter()
                    .take(kept)
                    .map(|cidr| (cidr.clone(), vec!["feed".to_string()])),
            );
            report.feeds.push(FeedStatus {
                sites: d.sites.clone(),
                url: shown,
                state: o.state,
                entries: kept,
                dropped_over_feed_cap: o.over_cap,
                dropped_over_node_cap: o.entries.len() - kept,
                rejected_lines: o.rejected,
                last_error: o.last_error,
                last_success_at: o.last_success_at,
                stale_secs: o.stale_secs,
            });
        }
        for d in skipped {
            report.feeds.push(FeedStatus {
                sites: d.sites,
                url: redact_url(&d.url),
                state: "skipped",
                entries: 0,
                dropped_over_feed_cap: 0,
                dropped_over_node_cap: 0,
                rejected_lines: 0,
                last_error: Some(format!(
                    "not fetched: more than {} distinct feeds are configured on this node",
                    limits.max_feeds
                )),
                last_success_at: None,
                stale_secs: None,
            });
        }
        report.entries = table.len();
        report.finished_at = unix_now();
        report.pass_millis = started.elapsed().as_millis() as u64;
        let rebuild = !(table.is_empty() && self.last_table_empty);
        self.last_table_empty = table.is_empty();
        FeedLoad {
            table,
            rebuild,
            report,
        }
    }

    /// Turn one fetch result into what the feed contributes, falling back to
    /// its last good fetch while that is recent enough.
    fn outcome(&mut self, url: &str, result: anyhow::Result<ParsedFeed>) -> Outcome {
        let shown = redact_url(url);
        let parsed = match result {
            Ok(p) => p,
            Err(e) => {
                let err = cap_chars(&format!("{e:#}"), FEED_ERROR_CHARS);
                let now = Instant::now();
                if let Some(lg) = self.last_good.get(url) {
                    let age = now.duration_since(lg.at);
                    if age <= self.limits.max_stale {
                        warn!(
                            url = %shown,
                            kept = lg.entries.len(),
                            last_success_at = lg.at_unix,
                            "IP feed fetch failed: {err}; kept {} entries from the last successful \
                             fetch, {}s ago",
                            lg.entries.len(),
                            age.as_secs()
                        );
                        return Outcome {
                            state: "stale",
                            entries: Arc::clone(&lg.entries),
                            over_cap: lg.over_cap,
                            rejected: lg.rejected,
                            last_error: Some(err),
                            last_success_at: Some(lg.at_unix),
                            stale_secs: Some(age.as_secs()),
                        };
                    }
                    let at_unix = lg.at_unix;
                    self.last_good.remove(url);
                    warn!(
                        url = %shown,
                        last_success_at = at_unix,
                        "IP feed fetch failed: {err}; the last successful fetch is older than {}s, \
                         so its entries are no longer used",
                        self.limits.max_stale.as_secs()
                    );
                    return Outcome::failed(err, Some(at_unix));
                }
                warn!(url = %shown, "IP feed fetch failed: {err}");
                return Outcome::failed(err, None);
            }
        };
        if parsed.rejected > 0 {
            warn!(
                url = %shown,
                rejected = parsed.rejected,
                samples = ?parsed.rejected_samples,
                "IP feed: skipped lines that are not an IP address or CIDR range"
            );
        }
        if parsed.over_cap > 0 {
            warn!(
                url = %shown,
                kept = parsed.entries.len(),
                dropped = parsed.over_cap,
                "IP feed has more than {} entries; only the first {} are used",
                self.limits.max_entries,
                self.limits.max_entries
            );
        }
        let at_unix = unix_now();
        let entries = Arc::new(parsed.entries);
        self.last_good.insert(
            url.to_string(),
            LastGood {
                entries: Arc::clone(&entries),
                over_cap: parsed.over_cap,
                rejected: parsed.rejected,
                at: Instant::now(),
                at_unix,
            },
        );
        Outcome {
            state: "loaded",
            entries,
            over_cap: parsed.over_cap,
            rejected: parsed.rejected,
            last_error: None,
            last_success_at: Some(at_unix),
            stale_secs: None,
        }
    }
}

impl Outcome {
    fn failed(err: String, last_success_at: Option<u64>) -> Self {
        Self {
            state: "failed",
            entries: Arc::new(Vec::new()),
            over_cap: 0,
            rejected: 0,
            last_error: Some(err),
            last_success_at,
            stale_secs: None,
        }
    }
}

/// Max-min fair shares of `total` for the given demands: no one gets more than
/// they asked for, and what a small demand leaves is split among the rest.
fn fair_shares(demands: &[usize], total: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..demands.len()).collect();
    order.sort_by_key(|&i| demands[i]);
    let mut left = total;
    let mut out = vec![0; demands.len()];
    for (k, &i) in order.iter().enumerate() {
        out[i] = demands[i].min(left / (demands.len() - k));
        left -= out[i];
    }
    out
}

/// Fetch `urls`, at most `limits.concurrency` at a time, each within its own
/// timeout and all within `pass_deadline`. Results are in `urls` order.
async fn fetch_all(
    urls: Vec<String>,
    limits: &FeedLimits,
    pass_deadline: Instant,
) -> Vec<anyhow::Result<ParsedFeed>> {
    let urls = Arc::new(urls);
    let next = Arc::new(AtomicUsize::new(0));
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..limits.concurrency.clamp(1, urls.len().max(1)) {
        let (urls, next, limits) = (Arc::clone(&urls), Arc::clone(&next), limits.clone());
        workers.spawn(async move {
            let mut done = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(url) = urls.get(i) else { break };
                done.push((i, fetch_feed_until(url, &limits, pass_deadline).await));
            }
            done
        });
    }
    let mut out: Vec<Option<anyhow::Result<ParsedFeed>>> = urls.iter().map(|_| None).collect();
    while let Some(joined) = workers.join_next().await {
        // A panicking worker loses only its own feeds, reported below.
        if let Ok(done) = joined {
            for (i, r) in done {
                out[i] = Some(r);
            }
        }
    }
    out.into_iter()
        .map(|r| r.unwrap_or_else(|| Err(anyhow::anyhow!("feed fetch task ended unexpectedly"))))
        .collect()
}

/// Fetch one feed within `limits`, outside any pass (tests).
#[cfg(test)]
async fn fetch_feed(url: &str, limits: &FeedLimits) -> anyhow::Result<ParsedFeed> {
    fetch_feed_until(url, limits, Instant::now() + limits.pass_budget).await
}

/// Fetch one feed within its own timeout and the pass deadline, and parse it.
async fn fetch_feed_until(
    url: &str,
    limits: &FeedLimits,
    pass_deadline: Instant,
) -> anyhow::Result<ParsedFeed> {
    let uri = feed_uri(url)?;
    let now = Instant::now();
    if now >= pass_deadline {
        anyhow::bail!(
            "not fetched: this pass used its whole {}s budget before reaching it",
            limits.pass_budget.as_secs_f32()
        );
    }
    let own = now + limits.timeout;
    let body = tokio::time::timeout_at(
        own.min(pass_deadline),
        fetch_body(uri, limits.max_body_bytes),
    )
    .await
    .map_err(|_| {
        if own <= pass_deadline {
            anyhow::anyhow!(
                "feed did not finish within {:?} (connect, headers and body together)",
                limits.timeout
            )
        } else {
            anyhow::anyhow!(
                "feed did not finish before this pass's {}s budget ran out",
                limits.pass_budget.as_secs_f32()
            )
        }
    })??;
    let text = std::str::from_utf8(&body).context("feed body is not valid UTF-8")?;
    Ok(parse_feed_text(text, limits.max_entries))
}

/// Accept only an absolute http or https URL with a host.
fn feed_uri(url: &str) -> anyhow::Result<Uri> {
    const REFUSED: &str = "feed URL must start with http:// or https:// — no other scheme \
                           (file://, ftp://, …) is fetched";
    let url = url.trim();
    // Judged on the text first: `Uri` refuses `file:///x` as "invalid format",
    // which tells the operator nothing about why.
    let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        anyhow::bail!(REFUSED);
    }
    // The URL is not repeated in the error: it is logged and reported next to
    // it, redacted, and this text is not.
    let uri: Uri = url.parse().context("invalid feed URL")?;
    if !matches!(uri.scheme_str(), Some("http") | Some("https")) {
        anyhow::bail!(REFUSED);
    }
    if uri.host().is_none_or(str::is_empty) {
        anyhow::bail!("feed URL has no host");
    }
    Ok(uri)
}

async fn fetch_body(uri: Uri, max_body_bytes: usize) -> anyhow::Result<Bytes> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, http_body_util::combinators::BoxBody<Bytes, hyper::Error>> =
        Client::builder(TokioExecutor::new()).build(https);

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

    let resp = client
        .request(req)
        .await
        .context("feed HTTP request failed")?;
    if !resp.status().is_success() {
        anyhow::bail!("feed returned HTTP {}", resp.status());
    }

    let body = Limited::new(resp.into_body(), max_body_bytes)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<LengthLimitError>() {
                anyhow::anyhow!("feed body is larger than the {max_body_bytes}-byte limit")
            } else {
                anyhow::anyhow!("reading feed body: {e}")
            }
        })?
        .to_bytes();
    Ok(body)
}

/// One entry per line; blank lines and `#` comments are skipped. An entry is
/// kept only if `IpReputation` will accept it, so what is counted here is what
/// is enforced.
fn parse_feed_text(text: &str, max_entries: usize) -> ParsedFeed {
    let mut out = ParsedFeed::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if parse_ip_or_cidr(line).is_err() {
            out.rejected += 1;
            if out.rejected_samples.len() < FEED_LOG_SAMPLES {
                out.rejected_samples.push(log_sample(line));
            }
            continue;
        }
        if out.entries.len() < max_entries {
            out.entries.push(line.to_string());
        } else {
            out.over_cap += 1;
        }
    }
    out
}

fn log_sample(line: &str) -> String {
    cap_chars(line, FEED_SAMPLE_CHARS)
}

fn cap_chars(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if out.len() < s.len() {
        out.push('…');
    }
    out
}

/// A feed URL as logged and reported: userinfo and query withheld, because
/// either may carry the feed's credential, and this text reaches every node's
/// log every five minutes and `/healthz`.
fn redact_url(url: &str) -> String {
    let url = url.trim();
    let (base, had_query) = match url.find(['?', '#']) {
        Some(i) => (&url[..i], url[i..].starts_with('?')),
        None => (url, false),
    };
    let (scheme, rest) = match base.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, base),
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let mut out = String::with_capacity(url.len().min(FEED_SHOWN_CHARS) + 24);
    if let Some(scheme) = scheme {
        out.push_str(scheme);
        out.push_str("://");
    }
    match authority.rsplit_once('@') {
        Some((_, host)) => {
            out.push_str(REDACTED);
            out.push('@');
            out.push_str(host);
        }
        None => out.push_str(authority),
    }
    out.push_str(path);
    if had_query {
        out.push('?');
        out.push_str(REDACTED);
    }
    cap_chars(&out, FEED_SHOWN_CHARS)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// The last pass's report; `None` until the loader finishes its first pass.
static LAST_REPORT: ArcSwapOption<FeedReport> = ArcSwapOption::const_empty();

/// Make `report` what `/healthz` and `/metrics` show.
pub(crate) fn publish(report: FeedReport) {
    LAST_REPORT.store(Some(Arc::new(report)));
}

/// The `ip_feeds` block of `/healthz`.
pub(crate) fn status_json() -> serde_json::Value {
    report_json(LAST_REPORT.load().as_deref())
}

/// Feed gauges for `/metrics`; empty when no feed is configured, so a node
/// without feeds exports no permanently-zero series to alert on.
pub(crate) fn metrics_text() -> String {
    report_metrics(LAST_REPORT.load().as_deref())
}

fn report_json(report: Option<&FeedReport>) -> serde_json::Value {
    let Some(r) = report else {
        return serde_json::json!({ "state": "first pass not finished" });
    };
    let count = |state: &str| r.feeds.iter().filter(|f| f.state == state).count();
    serde_json::json!({
        "configured": r.feeds.len(),
        "loaded": count("loaded"),
        // A stale feed still enforces its last good fetch; failed and skipped
        // ones enforce nothing while the console shows them as set.
        "stale": count("stale"),
        "failed": count("failed"),
        "skipped": count("skipped"),
        "truncated": r.feeds.iter().filter(|f| f.dropped_over_feed_cap + f.dropped_over_node_cap > 0).count(),
        "entries": r.entries,
        "last_pass_at": r.finished_at,
        "last_pass_millis": r.pass_millis,
        "limits": {
            "max_feeds": r.limits.max_feeds,
            "max_entries_per_feed": r.limits.max_entries,
            "max_total_entries": r.limits.max_total_entries,
            "timeout_secs": r.limits.timeout.as_secs(),
            "max_body_bytes": r.limits.max_body_bytes,
            "pass_budget_secs": r.limits.pass_budget.as_secs(),
            "max_stale_secs": r.limits.max_stale.as_secs(),
        },
        "feeds": r.feeds,
    })
}

fn report_metrics(report: Option<&FeedReport>) -> String {
    let Some(r) = report.filter(|r| !r.feeds.is_empty()) else {
        return String::new();
    };
    let count = |state: &str| r.feeds.iter().filter(|f| f.state == state).count();
    let dropped: usize = r
        .feeds
        .iter()
        .map(|f| f.dropped_over_feed_cap + f.dropped_over_node_cap)
        .sum();
    format!(
        "# HELP sentinel_ip_feeds_configured Distinct IP-reputation feed URLs configured on this node\n\
         # TYPE sentinel_ip_feeds_configured gauge\n\
         sentinel_ip_feeds_configured {}\n\
         # HELP sentinel_ip_feeds_not_loaded Feeds enforcing nothing after the last pass (failed with no recent good fetch, or over the per-node feed limit)\n\
         # TYPE sentinel_ip_feeds_not_loaded gauge\n\
         sentinel_ip_feeds_not_loaded {}\n\
         # HELP sentinel_ip_feeds_stale Feeds whose last fetch failed, enforcing the entries of an earlier fetch\n\
         # TYPE sentinel_ip_feeds_stale gauge\n\
         sentinel_ip_feeds_stale {}\n\
         # HELP sentinel_ip_feed_entries Entries in the node's IP-feed table\n\
         # TYPE sentinel_ip_feed_entries gauge\n\
         sentinel_ip_feed_entries {}\n\
         # HELP sentinel_ip_feed_entries_dropped Valid feed entries left out by the per-feed or per-node entry cap in the last pass\n\
         # TYPE sentinel_ip_feed_entries_dropped gauge\n\
         sentinel_ip_feed_entries_dropped {}\n",
        r.feeds.len(),
        count("failed") + count("skipped"),
        count("stale"),
        r.entries,
        dropped,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A local origin. Each connection's request head is read, then the socket
    /// is handed to `respond`, which writes whatever the test needs — including
    /// a response that never ends.
    async fn stub<F, Fut>(respond: F) -> String
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // The binary installs this in main; the client's TLS config needs it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    respond(sock).await;
                });
            }
        });
        format!("http://{addr}/feed.netset")
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// A stub that answers 200 with `body`.
    async fn serving(body: String) -> String {
        counted(body).await.0
    }

    /// A stub that answers 200 with `body`, and counts the requests it gets.
    async fn counted(body: String) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        let url = stub(move |mut sock| {
            h.fetch_add(1, Ordering::SeqCst);
            let resp = ok_response(&body);
            async move {
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        })
        .await;
        (url, hits)
    }

    /// A stub that accepts, reads the request and never answers.
    async fn hanging() -> String {
        stub(|sock| async move {
            let _held = sock;
            std::future::pending::<()>().await
        })
        .await
    }

    /// `n` addresses under a /24 `prefix`, one per line.
    fn addresses(prefix: &str, n: u8) -> String {
        (1..=n)
            .map(|i| format!("{prefix}.{i}\n"))
            .collect::<Vec<_>>()
            .concat()
    }

    fn feed(site: &str, url: &str) -> (String, IpFeedConfig) {
        (
            site.to_string(),
            IpFeedConfig {
                url: url.to_string(),
                interval: "1h".to_string(),
                format: "cidr".to_string(),
            },
        )
    }

    fn with(f: impl FnOnce(&mut FeedLimits)) -> FeedLimits {
        let mut l = FeedLimits::default();
        f(&mut l);
        l
    }

    fn in_table(table: &[(String, Vec<String>)], prefix: &str) -> usize {
        table.iter().filter(|(c, _)| c.starts_with(prefix)).count()
    }

    /// Fails the test, rather than hanging it, when a fetch does not return.
    async fn bounded<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("feed fetch never returned — nothing bounds it")
    }

    // What the loader keeps from a well-formed feed must not change: the same
    // trimmed lines, in order, with comments and blanks skipped.
    #[tokio::test]
    async fn a_well_formed_feed_loads_as_before() {
        let url = serving(
            "# FireHOL-style header\n\n10.0.0.1\n  198.51.100.0/24  \n2001:db8::/32\n# trailing\n"
                .to_string(),
        )
        .await;
        let parsed = bounded(fetch_feed(&url, &FeedLimits::default()))
            .await
            .expect("well-formed feed");
        assert_eq!(
            parsed.entries,
            ["10.0.0.1", "198.51.100.0/24", "2001:db8::/32"]
        );
        assert_eq!((parsed.rejected, parsed.over_cap), (0, 0));

        // And through the loader: one site, one feed, every entry tagged "feed".
        let load = bounded(FeedLoader::new(FeedLimits::default()).load(&[feed("s", &url)])).await;
        let table: Vec<&str> = load.table.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(table, ["10.0.0.1", "198.51.100.0/24", "2001:db8::/32"]);
        assert!(load.table.iter().all(|(_, tags)| tags == &["feed"]));
        assert_eq!(load.report.feeds[0].state, "loaded");
    }

    // A file:// feed read any path on the node.
    #[tokio::test]
    async fn a_file_url_is_refused() {
        let path = std::env::temp_dir().join(format!("ip-feed-test-{}.txt", std::process::id()));
        std::fs::write(&path, "198.51.100.7\n").unwrap();
        let res = bounded(fetch_feed(
            &format!("file://{}", path.display()),
            &FeedLimits::default(),
        ))
        .await;
        let _ = std::fs::remove_file(&path);
        let err = res.expect_err("a file:// feed must not be read");
        assert!(
            format!("{err:#}").contains("http:// or https://"),
            "{err:#}"
        );
    }

    #[test]
    fn only_absolute_http_and_https_urls_are_accepted() {
        for bad in [
            "file:///etc/passwd",
            "FILE:///etc/passwd",
            "ftp://feeds.example/list",
            "gopher://feeds.example/",
            "//feeds.example/list",
            "feeds.example/list",
            "/etc/passwd",
            "http:///list",
            "",
        ] {
            assert!(feed_uri(bad).is_err(), "{bad} should be refused");
        }
        for ok in [
            "http://feeds.example/level1.netset",
            "https://feeds.example:8443/list?key=x",
            "HTTPS://FEEDS.EXAMPLE/list",
            "http://[2001:db8::1]/list",
            " https://feeds.example/list ",
        ] {
            assert!(feed_uri(ok).is_ok(), "{ok} should be accepted");
        }
    }

    // The console stores what the control plane accepts. A URL it accepts and
    // this parser refuses is saved, shown as set, and fails on every node at
    // every refresh — so the control plane's own list of accepted URLs must
    // all be accepted here. The Go side checks the same file.
    #[test]
    fn every_url_the_control_plane_accepts_is_fetchable() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../control-plane/cmd/controllerd/testdata/feed_urls_accepted.txt");
        let list = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let urls: Vec<&str> = list
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert!(urls.len() >= 10, "fixture has {} URLs", urls.len());
        for url in urls {
            if let Err(e) = feed_uri(url) {
                panic!("the control plane accepts {url} but the data plane refuses it: {e:#}");
            }
        }
    }

    // The production limit, against a body that never stops: the old reader
    // buffered it all.
    #[tokio::test]
    async fn a_body_over_the_size_cap_fails_the_feed() {
        let url = stub(|mut sock| async move {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await;
            let chunk = "10.0.0.1\n".repeat(64 * 1024 / 9);
            let mut sent = 0;
            while sent <= FEED_MAX_BODY_BYTES + chunk.len() {
                if sock.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
                sent += chunk.len();
            }
        })
        .await;
        let err = bounded(fetch_feed(&url, &FeedLimits::default()))
            .await
            .expect_err("an over-cap body must fail the feed");
        assert!(format!("{err:#}").contains("limit"), "{err:#}");
    }

    // Headers on time, then one byte every 50 ms: each read makes progress, so
    // only a deadline over the WHOLE fetch ends it.
    #[tokio::test]
    async fn a_slow_body_is_cut_off_by_the_single_deadline() {
        let url = stub(|mut sock| async move {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                .await;
            loop {
                if sock.write_all(b"1").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let limits = with(|l| l.timeout = Duration::from_millis(400));
        let started = Instant::now();
        let err = bounded(fetch_feed(&url, &limits))
            .await
            .expect_err("a trickled body must time out");
        assert!(format!("{err:#}").contains("did not finish"), "{err:#}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn entries_past_the_per_feed_cap_are_dropped() {
        let url = serving(addresses("10.0.0", 12)).await;
        let limits = with(|l| l.max_entries = 10);
        let parsed = bounded(fetch_feed(&url, &limits)).await.unwrap();
        assert_eq!(parsed.entries.len(), 10);
        assert_eq!(parsed.entries[0], "10.0.0.1");
        assert_eq!(parsed.over_cap, 2);
    }

    // The node cap went to whichever site came first in the config: one site's
    // two large feeds stopped every later site's from loading. It is now shared
    // between the sites that have feeds, and a failing feed costs only itself.
    #[tokio::test]
    async fn the_node_wide_cap_is_shared_fairly_between_sites() {
        let a1 = serving(addresses("10.0.1", 10)).await;
        let a2 = serving(addresses("10.0.2", 10)).await;
        let b = serving(addresses("10.0.3", 10)).await;
        let c = serving(addresses("10.0.4", 2)).await;
        let limits = with(|l| l.max_total_entries = 15);

        let feeds = [
            feed("a", &a1),
            feed("a", "file:///etc/hosts"),
            feed("a", &a2),
            feed("b", &b),
        ];
        let load = bounded(FeedLoader::new(limits.clone()).load(&feeds)).await;
        assert_eq!(load.table.len(), 15);
        // a wants 20, b wants 10: 7 and 8 of 15 (the remainder goes to the last).
        let (got_a, got_b) = (
            in_table(&load.table, "10.0.1.") + in_table(&load.table, "10.0.2."),
            in_table(&load.table, "10.0.3."),
        );
        assert_eq!((got_a, got_b), (8, 7), "{:?}", load.report.feeds);
        // Within a site, its feeds keep config order.
        assert_eq!(in_table(&load.table, "10.0.1."), 8);
        let st = |url: &str| {
            load.report
                .feeds
                .iter()
                .find(|f| f.url == redact_url(url))
                .unwrap()
                .clone()
        };
        assert_eq!(st(&a1).dropped_over_node_cap, 2);
        assert_eq!(st(&a2).dropped_over_node_cap, 10);
        assert_eq!(st("file:///etc/hosts").state, "failed");

        // A site that needs less than its share gets all of it; the rest goes
        // to the others.
        let feeds = [feed("a", &a1), feed("a", &a2), feed("c", &c)];
        let load = bounded(FeedLoader::new(limits).load(&feeds)).await;
        assert_eq!(in_table(&load.table, "10.0.4."), 2);
        assert_eq!(load.table.len(), 15);
    }

    // The same URL on several sites was fetched once per site and counted once
    // per site, so copies used up the node cap and a third site's different
    // feed was not loaded.
    #[tokio::test]
    async fn a_url_listed_by_several_sites_is_fetched_once() {
        let (a, a_hits) = counted(addresses("10.0.1", 10)).await;
        let b = serving(addresses("10.0.2", 10)).await;
        let limits = with(|l| l.max_total_entries = 11);
        let feeds = [feed("s1", &a), feed("s2", &a), feed("s3", &b)];
        let load = bounded(FeedLoader::new(limits).load(&feeds)).await;

        assert_eq!(a_hits.load(Ordering::SeqCst), 1, "a was fetched per site");
        assert!(
            in_table(&load.table, "10.0.2.") > 0,
            "s3's feed was pushed out"
        );
        let distinct: HashSet<&str> = load.table.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(
            distinct.len(),
            load.table.len(),
            "duplicate entries in the table"
        );
        assert_eq!(load.report.feeds.len(), 2);
        assert_eq!(load.report.feeds[0].sites, ["s1", "s2"]);
    }

    // Feeds were fetched one after another, each allowed the full timeout, so
    // N feeds that never answer held the loader for N × timeout.
    #[tokio::test]
    async fn hanging_feeds_are_fetched_concurrently() {
        let mut feeds = Vec::new();
        for i in 0..5 {
            feeds.push(feed(&format!("s{i}"), &hanging().await));
        }
        let limits = with(|l| l.timeout = Duration::from_millis(200));
        let started = Instant::now();
        let load = bounded(FeedLoader::new(limits).load(&feeds)).await;
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(900),
            "5 hanging feeds took {took:?}; one after another is 1 s"
        );
        assert!(load.report.feeds.iter().all(|f| f.state == "failed"));
    }

    // However many feeds, one pass ends at its budget; what it did not reach is
    // reported, not waited for.
    #[tokio::test]
    async fn a_pass_stops_at_its_budget() {
        let mut feeds = Vec::new();
        for i in 0..6 {
            feeds.push(feed(&format!("s{i}"), &hanging().await));
        }
        let limits = with(|l| {
            l.timeout = Duration::from_secs(5);
            l.pass_budget = Duration::from_millis(300);
        });
        let started = Instant::now();
        let load = bounded(FeedLoader::new(limits).load(&feeds)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(load.report.feeds.len(), 6);
        for f in &load.report.feeds {
            let err = f.last_error.as_deref().unwrap_or("");
            assert!(f.state == "failed" && err.contains("budget"), "{f:?}");
        }
    }

    // A node fetches at most max_feeds distinct URLs; the rest are reported as
    // skipped and never contacted.
    #[tokio::test]
    async fn feeds_past_the_per_node_feed_limit_are_not_fetched() {
        let a = serving(addresses("10.0.1", 3)).await;
        let b = serving(addresses("10.0.2", 3)).await;
        let (c, c_hits) = counted(addresses("10.0.3", 3)).await;
        let limits = with(|l| l.max_feeds = 2);
        let load =
            bounded(FeedLoader::new(limits).load(&[feed("s", &a), feed("s", &b), feed("t", &c)]))
                .await;
        assert_eq!(load.table.len(), 6);
        assert_eq!(c_hits.load(Ordering::SeqCst), 0);
        let skipped = &load.report.feeds[2];
        assert_eq!(
            (skipped.state, skipped.sites.as_slice()),
            ("skipped", &["t".to_string()][..])
        );
    }

    // The table is rebuilt every pass, so one failed fetch used to drop a
    // feed's entries until the next good one. They are kept, for a while.
    #[tokio::test]
    async fn a_failed_fetch_keeps_the_last_good_entries_for_a_while() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        let body = addresses("10.0.9", 4);
        let url = stub(move |mut sock| {
            let resp = if h.fetch_add(1, Ordering::SeqCst) == 0 {
                ok_response(&body)
            } else {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            async move {
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        })
        .await;
        let feeds = [feed("s", &url)];

        let mut loader = FeedLoader::new(FeedLimits::default());
        assert_eq!(bounded(loader.load(&feeds)).await.table.len(), 4);
        let second = bounded(loader.load(&feeds)).await;
        assert_eq!(second.table.len(), 4, "the last good entries were dropped");
        let st = &second.report.feeds[0];
        assert_eq!(st.state, "stale");
        assert!(st.last_error.as_deref().unwrap().contains("503"), "{st:?}");
        assert!(st.stale_secs.is_some() && st.last_success_at.is_some());

        // Past max_stale they are dropped.
        let mut loader = FeedLoader::new(with(|l| l.max_stale = Duration::ZERO));
        hits.store(0, Ordering::SeqCst);
        assert_eq!(bounded(loader.load(&feeds)).await.table.len(), 4);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let third = bounded(loader.load(&feeds)).await;
        assert!(third.table.is_empty());
        assert_eq!(third.report.feeds[0].state, "failed");

        // And a feed removed from the config does not come back as stale.
        let mut loader = FeedLoader::new(FeedLimits::default());
        hits.store(0, Ordering::SeqCst);
        bounded(loader.load(&feeds)).await;
        bounded(loader.load(&[])).await;
        assert!(bounded(loader.load(&feeds)).await.table.is_empty());
    }

    // hyper never sends userinfo, and a query often carries the feed's key; the
    // URL is logged on every node every five minutes and shown in /healthz.
    #[tokio::test]
    async fn credentials_in_a_feed_url_are_not_logged_or_reported() {
        assert_eq!(
            redact_url("https://user:s3cret@feeds.example/list?key=abc#x"),
            "https://[redacted]@feeds.example/list?[redacted]"
        );
        assert_eq!(
            redact_url(" http://feeds.example/l.netset "),
            "http://feeds.example/l.netset"
        );
        assert_eq!(redact_url("user:s3cret@host/x"), "[redacted]@host/x");
        assert_eq!(redact_url("http://h/a@b"), "http://h/a@b");

        let url = hanging().await.replace("http://", "http://user:s3cret@") + "?key=abc";
        let limits = with(|l| l.timeout = Duration::from_millis(100));
        let load = bounded(FeedLoader::new(limits).load(&[feed("s", &url)])).await;
        let shown = serde_json::to_string(&report_json(Some(&load.report))).unwrap();
        assert!(
            !shown.contains("s3cret") && !shown.contains("abc"),
            "{shown}"
        );
    }

    #[test]
    fn limits_come_from_the_environment_clamped() {
        let env = |pairs: &[(&str, &str)]| {
            let m: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            FeedLimits::from_lookup(move |k| m.get(k).cloned())
        };
        let d = env(&[]);
        assert_eq!(
            (
                d.max_entries,
                d.max_total_entries,
                d.timeout,
                d.max_body_bytes
            ),
            (
                FEED_MAX_ENTRIES,
                FEED_MAX_TOTAL_ENTRIES,
                FEED_FETCH_TIMEOUT,
                FEED_MAX_BODY_BYTES
            )
        );
        let l = env(&[
            ("SENTINEL_IP_FEED_MAX_ENTRIES", "20000"),
            ("SENTINEL_IP_FEED_MAX_TOTAL_ENTRIES", " 250000 "),
            ("SENTINEL_IP_FEED_TIMEOUT_SECS", "10"),
            ("SENTINEL_IP_FEED_MAX_BYTES", "1048576"),
        ]);
        assert_eq!(
            (
                l.max_entries,
                l.max_total_entries,
                l.timeout,
                l.max_body_bytes
            ),
            (20_000, 250_000, Duration::from_secs(10), 1 << 20)
        );
        // Out of range is clamped; garbage and blank keep the default.
        let l = env(&[
            ("SENTINEL_IP_FEED_MAX_TOTAL_ENTRIES", "50000000"),
            ("SENTINEL_IP_FEED_TIMEOUT_SECS", "0"),
            ("SENTINEL_IP_FEED_MAX_ENTRIES", "lots"),
            ("SENTINEL_IP_FEED_MAX_BYTES", ""),
        ]);
        assert_eq!(l.max_total_entries, 1_000_000);
        assert_eq!(l.timeout, Duration::from_secs(1));
        assert_eq!(l.max_entries, FEED_MAX_ENTRIES);
        assert_eq!(l.max_body_bytes, FEED_MAX_BODY_BYTES);
    }

    #[test]
    fn fair_shares_never_exceed_the_total_or_a_demand() {
        assert_eq!(fair_shares(&[20, 10], 15), [8, 7]);
        assert_eq!(fair_shares(&[20, 2], 15), [13, 2]);
        assert_eq!(fair_shares(&[5, 5], 100), [5, 5]);
        assert_eq!(fair_shares(&[0, 30, 30], 11), [0, 5, 6]);
        assert_eq!(fair_shares(&[], 10), Vec::<usize>::new());
    }

    // /healthz and /metrics carry the report: a feed that failed, was skipped
    // or truncated must be visible somewhere other than a log line.
    #[tokio::test]
    async fn the_report_shows_what_each_feed_enforces() {
        assert_eq!(report_metrics(None), "");
        assert_eq!(report_json(None)["state"], "first pass not finished");

        let a = serving(addresses("10.0.1", 10)).await;
        let limits = with(|l| {
            l.max_feeds = 2;
            l.max_total_entries = 6;
        });
        let load = bounded(FeedLoader::new(limits).load(&[
            feed("s", &a),
            feed("s", "ftp://feeds.example/x"),
            feed("t", "http://127.0.0.1:9/never"),
        ]))
        .await;
        let j = report_json(Some(&load.report));
        assert_eq!(
            (
                &j["configured"],
                &j["loaded"],
                &j["failed"],
                &j["skipped"],
                &j["truncated"]
            ),
            (&3.into(), &1.into(), &1.into(), &1.into(), &1.into()),
            "{j:#}"
        );
        assert_eq!(j["entries"], 6);
        assert_eq!(j["feeds"][0]["dropped_over_node_cap"], 4);
        assert_eq!(j["feeds"][2]["state"], "skipped");

        let m = report_metrics(Some(&load.report));
        for line in [
            "sentinel_ip_feeds_configured 3\n",
            "sentinel_ip_feeds_not_loaded 2\n",
            "sentinel_ip_feeds_stale 0\n",
            "sentinel_ip_feed_entries 6\n",
            "sentinel_ip_feed_entries_dropped 4\n",
        ] {
            assert!(m.contains(line), "missing {line:?} in\n{m}");
        }
        // No feed configured: no series.
        let empty = bounded(FeedLoader::new(FeedLimits::default()).load(&[])).await;
        assert_eq!(report_metrics(Some(&empty.report)), "");
    }

    // Removing every feed used to leave the last table enforced until restart:
    // the loader skipped any pass with no feed configured.
    #[tokio::test]
    async fn removing_every_feed_empties_the_table() {
        let a = serving(addresses("10.0.1", 3)).await;
        let mut loader = FeedLoader::new(FeedLimits::default());
        assert!(
            !bounded(loader.load(&[])).await.rebuild,
            "nothing before, nothing now"
        );
        let first = bounded(loader.load(&[feed("s", &a)])).await;
        assert!(first.rebuild && first.table.len() == 3);
        let removed = bounded(loader.load(&[])).await;
        assert!(removed.rebuild, "the removed feed's entries stay enforced");
        assert!(removed.table.is_empty());
        assert!(!bounded(loader.load(&[])).await.rebuild);
    }

    // A loader loop restarted after a panic cannot tell whether the run before
    // it stored the last table it built, so its first pass rebuilds even when
    // that table and this one are both empty; later passes are back to normal.
    #[tokio::test]
    async fn a_resumed_loader_rebuilds_on_its_next_pass() {
        let mut loader = FeedLoader::new(FeedLimits::default());
        assert!(!bounded(loader.load(&[])).await.rebuild);
        loader.rebuild_next_pass();
        let resumed = bounded(loader.load(&[])).await;
        assert!(
            resumed.rebuild,
            "a table the dead run built may still be enforced"
        );
        assert!(resumed.table.is_empty());
        assert!(!bounded(loader.load(&[])).await.rebuild);
    }

    // A URL pointed at the wrong document: its lines are counted, a few are
    // quoted short, and none of them become entries.
    #[test]
    fn rejected_lines_are_counted_and_sampled_not_kept() {
        let junk = "x".repeat(10_000);
        let text = format!("{}10.0.0.1\n", format!("{junk}\n").repeat(50));
        let parsed = parse_feed_text(&text, FEED_MAX_ENTRIES);
        assert_eq!(parsed.entries, ["10.0.0.1"]);
        assert_eq!(parsed.rejected, 50);
        assert_eq!(parsed.rejected_samples.len(), FEED_LOG_SAMPLES);
        assert!(parsed
            .rejected_samples
            .iter()
            .all(|s| s.chars().count() <= FEED_SAMPLE_CHARS + 1));
    }
}
