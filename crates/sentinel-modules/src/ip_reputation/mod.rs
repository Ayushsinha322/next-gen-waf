//! IP reputation module — CIDR-based allowlists / blocklists with HTTP(S) feed support.
//!
//! Checked at Phase 0 (connection), before any HTTP parsing.  An explicit
//! allowlist entry always wins over a blocklist entry for the same IP.

use std::net::IpAddr;
use std::str::FromStr;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ipnet::IpNet;
use sentinel_core::config::{IpFeedConfig, IpReputationConfig};
use tracing::warn;

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    http_body_util::combinators::BoxBody<Bytes, hyper::Error>,
>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of an IP reputation lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVerdict {
    /// IP is on the allowlist or has no reputation entry — forward to Phase 1.
    Allow,
    /// IP is explicitly blocked — return 403 immediately.
    Block { reason: String },
    /// IP has suspicious tags (feed-sourced) — continue but add anomaly score.
    Suspect { tags: Vec<String> },
}

// ---------------------------------------------------------------------------
// IpReputation
// ---------------------------------------------------------------------------

/// Holds compiled CIDR allowlists and blocklists.
///
/// Built from one or more [`IpReputationConfig`] blocks and stored inside an
/// `ArcSwap` so it can be hot-swapped on SIGHUP without locking request
/// processing.
pub struct IpReputation {
    /// CIDR ranges that bypass all blocking (e.g. internal monitoring, CDN).
    allowlist: Vec<IpNet>,
    /// CIDR ranges that are unconditionally blocked, with an explanatory reason.
    blocklist: Vec<(IpNet, String)>,
    /// CIDR ranges from reputation feeds tagged with category labels.
    suspect_list: Vec<(IpNet, Vec<String>)>,
}

impl Default for IpReputation {
    fn default() -> Self {
        Self::new()
    }
}

impl IpReputation {
    /// Create an empty reputation table (allows everything).
    pub fn new() -> Self {
        Self {
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            suspect_list: Vec::new(),
        }
    }

    /// Build a merged reputation table from all site configs.
    ///
    /// All sites' allow/block lists are unioned together so that the global
    /// check at Phase 0 covers every protected application.
    pub fn from_configs(configs: &[&IpReputationConfig]) -> Self {
        let mut rep = Self::new();
        for cfg in configs {
            for cidr in &cfg.allow {
                if let Err(e) = rep.add_allowed_cidr(cidr) {
                    warn!(cidr = %cidr, "ip_reputation: invalid allow CIDR — skipping: {e}");
                }
            }
            for cidr in &cfg.block {
                if let Err(e) = rep.add_blocked_cidr(cidr, "config blocklist") {
                    warn!(cidr = %cidr, "ip_reputation: invalid block CIDR — skipping: {e}");
                }
            }
        }
        rep
    }

    /// Add a CIDR range to the allowlist.
    pub fn add_allowed_cidr(&mut self, cidr: &str) -> anyhow::Result<()> {
        let net =
            IpNet::from_str(cidr).map_err(|e| anyhow::anyhow!("invalid CIDR '{cidr}': {e}"))?;
        self.allowlist.push(net);
        Ok(())
    }

    /// Add a CIDR range to the blocklist with a human-readable reason.
    pub fn add_blocked_cidr(&mut self, cidr: &str, reason: &str) -> anyhow::Result<()> {
        let net =
            IpNet::from_str(cidr).map_err(|e| anyhow::anyhow!("invalid CIDR '{cidr}': {e}"))?;
        self.blocklist.push((net, reason.to_string()));
        Ok(())
    }

    /// Add a CIDR range to the suspect list with category tags.
    pub fn add_suspect_cidr(&mut self, cidr: &str, tags: Vec<String>) -> anyhow::Result<()> {
        let net =
            IpNet::from_str(cidr).map_err(|e| anyhow::anyhow!("invalid CIDR '{cidr}': {e}"))?;
        self.suspect_list.push((net, tags));
        Ok(())
    }

    /// Look up an IP address.
    ///
    /// Precedence: allowlist > blocklist > suspect list > allow.
    pub fn check(&self, ip: IpAddr) -> IpVerdict {
        let ip = normalize_ip(ip);

        // 1. Allowlist wins over everything.
        for net in &self.allowlist {
            if net_contains(net, ip) {
                return IpVerdict::Allow;
            }
        }

        // 2. Blocklist.
        for (net, reason) in &self.blocklist {
            if net_contains(net, ip) {
                return IpVerdict::Block {
                    reason: reason.clone(),
                };
            }
        }

        // 3. Suspect list — accumulate all matching tags.
        let mut tags: Vec<String> = Vec::new();
        for (net, t) in &self.suspect_list {
            if net_contains(net, ip) {
                tags.extend_from_slice(t);
            }
        }
        if !tags.is_empty() {
            return IpVerdict::Suspect { tags };
        }

        IpVerdict::Allow
    }

    /// `true` when `ip` is on this table's allowlist (used so a site's own
    /// allow entry also bypasses the node-wide feed check).
    pub fn is_allowlisted(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.allowlist.iter().any(|net| net_contains(net, ip))
    }

    /// Number of entries across all lists (useful for logging).
    pub fn entry_count(&self) -> usize {
        self.allowlist.len() + self.blocklist.len() + self.suspect_list.len()
    }

    /// Fetch all configured feed URLs and ingest their CIDR lists.
    ///
    /// Supports both HTTP and HTTPS.  Feeds are fetched sequentially; any feed
    /// that fails is logged and skipped.  Returns the total number of new
    /// entries added to the suspect list.
    pub async fn load_feeds(&mut self, feeds: &[IpFeedConfig]) -> usize {
        if feeds.is_empty() {
            return 0;
        }
        let client = build_https_client();
        let mut total = 0usize;
        for feed in feeds {
            match fetch_text(&client, &feed.url).await {
                Ok(body) => {
                    let count = self.ingest_cidr_feed(&body, &feed.url);
                    tracing::info!(url = %feed.url, count, "ip_reputation: feed loaded");
                    total += count;
                }
                Err(e) => {
                    warn!(url = %feed.url, error = %e, "ip_reputation: feed fetch failed — skipping");
                }
            }
        }
        total
    }

    /// Parse a text feed body (one CIDR or IP per line) and add entries to the
    /// suspect list tagged with `feed:<url>`.  Returns the count added.
    fn ingest_cidr_feed(&mut self, body: &str, source_url: &str) -> usize {
        let tag = format!("feed:{}", source_url);
        let mut count = 0usize;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            // Some feeds use "IP|category" or "IP category" format — take just the IP/CIDR.
            let cidr_str = line.split_whitespace().next().unwrap_or(line);
            let cidr_str = cidr_str.split('|').next().unwrap_or(cidr_str);

            let cidr = if cidr_str.contains('/') {
                cidr_str.to_owned()
            } else {
                match cidr_str.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => format!("{}/32", cidr_str),
                    Ok(IpAddr::V6(_)) => format!("{}/128", cidr_str),
                    Err(_) => {
                        tracing::debug!(entry = %cidr_str, "ip_reputation: skipping non-CIDR feed line");
                        continue;
                    }
                }
            };

            match self.add_suspect_cidr(&cidr, vec![tag.clone()]) {
                Ok(()) => count += 1,
                Err(e) => tracing::debug!(cidr, error = %e, "ip_reputation: invalid CIDR in feed"),
            }
        }
        count
    }
}

// ---------------------------------------------------------------------------
// HTTP(S) feed helpers
// ---------------------------------------------------------------------------

fn build_https_client() -> HttpsClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

async fn fetch_text(client: &HttpsClient, url: &str) -> anyhow::Result<String> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid feed URL '{}': {}", url, e))?;

    let req = Request::builder()
        .uri(uri)
        .header("User-Agent", "sentinel-waf/1.0 ip-reputation-feed-fetcher")
        .body(
            Empty::<Bytes>::new()
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed(),
        )?;

    let resp = tokio::time::timeout(std::time::Duration::from_secs(30), client.request(req))
        .await
        .map_err(|_| anyhow::anyhow!("feed '{}' timed out after 30s", url))??;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("feed '{}' returned HTTP {}", url, status);
    }

    let bytes = resp.collect().await?.to_bytes();
    String::from_utf8(bytes.to_vec())
        .map_err(|e| anyhow::anyhow!("feed '{}' body is not valid UTF-8: {}", url, e))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to plain IPv4 so
/// that IPv4 CIDR rules match connections on dual-stack sockets.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// Check whether an `IpNet` contains an `IpAddr`, handling v4/v6 mismatch
/// gracefully (returns false rather than panicking).
fn net_contains(net: &IpNet, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpNet::V4(net4), IpAddr::V4(ip4)) => net4.contains(&ip4),
        (IpNet::V6(net6), IpAddr::V6(ip6)) => net6.contains(&ip6),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn empty_reputation_allows_everything() {
        let rep = IpReputation::new();
        assert_eq!(rep.check(ipv4(1, 2, 3, 4)), IpVerdict::Allow);
    }

    #[test]
    fn blocklist_match() {
        let mut rep = IpReputation::new();
        rep.add_blocked_cidr("10.0.0.0/8", "private network")
            .unwrap();
        assert!(matches!(
            rep.check(ipv4(10, 1, 2, 3)),
            IpVerdict::Block { .. }
        ));
        assert_eq!(rep.check(ipv4(192, 168, 1, 1)), IpVerdict::Allow);
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let mut rep = IpReputation::new();
        rep.add_blocked_cidr("10.0.0.0/8", "private").unwrap();
        rep.add_allowed_cidr("10.0.0.5/32").unwrap();
        // Blocked range
        assert!(matches!(
            rep.check(ipv4(10, 0, 0, 1)),
            IpVerdict::Block { .. }
        ));
        // Exact allowlist entry wins
        assert_eq!(rep.check(ipv4(10, 0, 0, 5)), IpVerdict::Allow);
    }

    #[test]
    fn suspect_tags_returned() {
        let mut rep = IpReputation::new();
        rep.add_suspect_cidr("203.0.113.0/24", vec!["tor".to_string(), "vpn".to_string()])
            .unwrap();
        match rep.check(ipv4(203, 0, 113, 55)) {
            IpVerdict::Suspect { tags } => {
                assert!(tags.contains(&"tor".to_string()));
            }
            other => panic!("expected Suspect, got {other:?}"),
        }
        assert_eq!(rep.check(ipv4(203, 0, 114, 1)), IpVerdict::Allow);
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_cidr() {
        let mut rep = IpReputation::new();
        rep.add_blocked_cidr("1.2.3.0/24", "test").unwrap();
        // ::ffff:1.2.3.4 is IPv4-mapped IPv6 — should hit the IPv4 CIDR
        let mapped: IpAddr = IpAddr::V6(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4,
        ]));
        assert!(matches!(rep.check(mapped), IpVerdict::Block { .. }));
    }

    #[test]
    fn from_configs_merges() {
        let cfg1 = IpReputationConfig {
            block: vec!["192.0.2.0/24".to_string()],
            allow: vec![],
            feeds: vec![],
            xdp_mirror: false,
        };
        let cfg2 = IpReputationConfig {
            block: vec!["198.51.100.0/24".to_string()],
            allow: vec!["198.51.100.1/32".to_string()],
            feeds: vec![],
            xdp_mirror: false,
        };
        let rep = IpReputation::from_configs(&[&cfg1, &cfg2]);
        assert!(matches!(
            rep.check(ipv4(192, 0, 2, 1)),
            IpVerdict::Block { .. }
        ));
        assert!(matches!(
            rep.check(ipv4(198, 51, 100, 5)),
            IpVerdict::Block { .. }
        ));
        // Allowlist override within cfg2
        assert_eq!(rep.check(ipv4(198, 51, 100, 1)), IpVerdict::Allow);
    }
}
