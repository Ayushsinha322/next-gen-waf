//! Threat Intelligence enforcement — the data-plane side of the CTI pipeline.
//!
//! The control plane aggregates global IOCs (malicious IPs/CIDRs, botnet C2,
//! Tor exits, bad user-agents, malicious domains/URL patterns) and serves them,
//! split into two enforcement tiers by confidence:
//!   * **block** — high-confidence IOCs → the request is rejected (403) at Phase 0.
//!   * **watch** — lower-confidence IOCs → the request continues but gains an
//!     anomaly score, so the rule engine / ML decides.
//!
//! [`ThreatFeed`] is built from a snapshot and swapped atomically ([`arc_swap`])
//! into the running proxy — hundreds of thousands of indicators update without
//! dropping a single live request.
//!
//! # Lookup performance
//! IP matching is the hot path. Exact IPs live in a `HashSet` (O(1)); CIDRs are
//! bucketed by prefix length, so a lookup masks the query address once per
//! *distinct* prefix length present (≤ 33 for IPv4) and hits a `HashSet` each
//! time — effectively constant-time, no per-CIDR scan, no external radix crate.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// The outcome of a threat-intel lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatVerdict {
    /// No IOC matched.
    None,
    /// A watch-tier IOC matched: continue, but add `score` to the anomaly score.
    Score { score: u32, tag: String },
    /// A block-tier (high-confidence) IOC matched: reject the request.
    Block { reason: String },
}

/// Raw, per-tier indicator lists as delivered by the control plane. Kept
/// serde-free so this crate stays independent of the wire format — the proxy
/// deserializes the endpoint JSON and hands the string vectors here.
#[derive(Default, Debug, Clone)]
pub struct RawTier {
    pub ips: Vec<String>,
    pub cidrs: Vec<String>,
    pub user_agents: Vec<String>,
    pub domains: Vec<String>,
    pub url_substrings: Vec<String>,
}

/// Fast IP set: exact addresses plus CIDRs bucketed by prefix length.
#[derive(Default)]
struct IpMatcher {
    exact_v4: HashSet<u32>,
    exact_v6: HashSet<u128>,
    cidr_v4: HashMap<u8, HashSet<u32>>,
    cidr_v6: HashMap<u8, HashSet<u128>>,
    v4_lens: Vec<u8>,
    v6_lens: Vec<u8>,
    count: usize,
}

impl IpMatcher {
    fn add_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(a) => {
                self.exact_v4.insert(u32::from(a));
            }
            IpAddr::V6(a) => {
                self.exact_v6.insert(u128::from(a));
            }
        }
        self.count += 1;
    }

    fn add_cidr(&mut self, net: IpNet) {
        match net {
            IpNet::V4(n) => {
                let plen = n.prefix_len();
                let key = u32::from(n.network()) & v4_mask(plen);
                if self.cidr_v4.entry(plen).or_default().insert(key) && !self.v4_lens.contains(&plen) {
                    self.v4_lens.push(plen);
                    self.v4_lens.sort_unstable();
                }
            }
            IpNet::V6(n) => {
                let plen = n.prefix_len();
                let key = u128::from(n.network()) & v6_mask(plen);
                if self.cidr_v6.entry(plen).or_default().insert(key) && !self.v6_lens.contains(&plen) {
                    self.v6_lens.push(plen);
                    self.v6_lens.sort_unstable();
                }
            }
        }
        self.count += 1;
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                let bits = u32::from(a);
                if self.exact_v4.contains(&bits) {
                    return true;
                }
                for &plen in &self.v4_lens {
                    let net = bits & v4_mask(plen);
                    if self.cidr_v4.get(&plen).is_some_and(|s| s.contains(&net)) {
                        return true;
                    }
                }
                false
            }
            IpAddr::V6(a) => {
                let bits = u128::from(a);
                if self.exact_v6.contains(&bits) {
                    return true;
                }
                for &plen in &self.v6_lens {
                    let net = bits & v6_mask(plen);
                    if self.cidr_v6.get(&plen).is_some_and(|s| s.contains(&net)) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

fn v4_mask(plen: u8) -> u32 {
    match plen {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

fn v6_mask(plen: u8) -> u128 {
    match plen {
        0 => 0,
        p if p >= 128 => u128::MAX,
        p => u128::MAX << (128 - p),
    }
}

/// One enforcement tier's compiled indicators.
#[derive(Default)]
struct Tier {
    ips: IpMatcher,
    user_agents: Vec<String>, // lowercased substring tokens
    domains: HashSet<String>, // lowercased exact hostnames
    url_substrings: Vec<String>, // lowercased URI substrings
}

impl Tier {
    fn from_raw(raw: RawTier) -> Self {
        let mut ips = IpMatcher::default();
        for s in &raw.ips {
            if let Ok(ip) = IpAddr::from_str(s.trim()) {
                ips.add_ip(ip);
            }
        }
        for s in &raw.cidrs {
            if let Ok(net) = IpNet::from_str(s.trim()) {
                ips.add_cidr(net);
            }
        }
        let lower_nonempty = |v: &[String]| -> Vec<String> {
            v.iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Tier {
            ips,
            user_agents: lower_nonempty(&raw.user_agents),
            domains: lower_nonempty(&raw.domains).into_iter().collect(),
            url_substrings: lower_nonempty(&raw.url_substrings),
        }
    }

    fn is_empty(&self) -> bool {
        self.ips.count == 0
            && self.user_agents.is_empty()
            && self.domains.is_empty()
            && self.url_substrings.is_empty()
    }

    fn entry_count(&self) -> usize {
        self.ips.count + self.user_agents.len() + self.domains.len() + self.url_substrings.len()
    }

    /// Returns a human-readable reason for the first matching indicator, if any.
    /// `ua_low`/`host_low`/`uri_low` are already normalized (lowercased, host
    /// port-stripped) by the caller so both tiers reuse the same work.
    fn match_reason(
        &self,
        ip: IpAddr,
        ua_low: Option<&str>,
        host_low: Option<&str>,
        uri_low: Option<&str>,
    ) -> Option<String> {
        if self.ips.contains(ip) {
            return Some(format!("malicious IP {ip}"));
        }
        if let Some(ua) = ua_low {
            if let Some(bad) = self.user_agents.iter().find(|b| ua.contains(b.as_str())) {
                return Some(format!("bad user-agent (~{bad})"));
            }
        }
        if let Some(host) = host_low {
            if self.domains.contains(host) {
                return Some(format!("malicious domain {host}"));
            }
        }
        if let Some(uri) = uri_low {
            if let Some(s) = self.url_substrings.iter().find(|s| uri.contains(s.as_str())) {
                return Some(format!("malicious URL pattern (~{s})"));
            }
        }
        None
    }
}

/// Immutable, hot-swappable set of threat-intel indicators split into a
/// high-confidence *block* tier and a lower-confidence *watch* tier.
pub struct ThreatFeed {
    version: i64,
    block: Tier,
    watch: Tier,
    watch_score: u32,
    // Precomputed so the hot path only lowercases header/URI strings that some
    // indicator can actually match against.
    needs_ua: bool,
    needs_domain: bool,
    needs_url: bool,
    empty: bool,
}

impl Default for ThreatFeed {
    fn default() -> Self {
        Self::empty()
    }
}

impl ThreatFeed {
    /// An empty feed — matches nothing. Used before the first sync.
    pub fn empty() -> Self {
        Self::from_parts(0, 0, RawTier::default(), RawTier::default())
    }

    /// Compile a feed from the two tiers. `watch_score` is the anomaly score
    /// added when a watch-tier indicator matches.
    pub fn from_parts(version: i64, watch_score: u32, block: RawTier, watch: RawTier) -> Self {
        let block = Tier::from_raw(block);
        let watch = Tier::from_raw(watch);
        let needs_ua = !block.user_agents.is_empty() || !watch.user_agents.is_empty();
        let needs_domain = !block.domains.is_empty() || !watch.domains.is_empty();
        let needs_url = !block.url_substrings.is_empty() || !watch.url_substrings.is_empty();
        let empty = block.is_empty() && watch.is_empty();
        Self {
            version,
            block,
            watch,
            watch_score,
            needs_ua,
            needs_domain,
            needs_url,
            empty,
        }
    }

    pub fn version(&self) -> i64 {
        self.version
    }

    pub fn is_empty(&self) -> bool {
        self.empty
    }

    pub fn entry_count(&self) -> usize {
        self.block.entry_count() + self.watch.entry_count()
    }

    /// Evaluate a request against the feed. Block tier wins over watch tier.
    /// `ua`, `host`, and `uri` are the raw request values (host may include a
    /// port; casing is irrelevant — normalization happens here).
    pub fn check(&self, ip: IpAddr, ua: Option<&str>, host: Option<&str>, uri: &str) -> ThreatVerdict {
        if self.empty {
            return ThreatVerdict::None;
        }
        let ua_low = if self.needs_ua {
            ua.map(|s| s.to_lowercase())
        } else {
            None
        };
        let host_low = if self.needs_domain {
            host.map(|s| strip_port(s).to_lowercase())
        } else {
            None
        };
        let uri_low = if self.needs_url {
            Some(uri.to_lowercase())
        } else {
            None
        };

        if let Some(reason) =
            self.block
                .match_reason(ip, ua_low.as_deref(), host_low.as_deref(), uri_low.as_deref())
        {
            return ThreatVerdict::Block { reason };
        }
        if let Some(tag) =
            self.watch
                .match_reason(ip, ua_low.as_deref(), host_low.as_deref(), uri_low.as_deref())
        {
            return ThreatVerdict::Score {
                score: self.watch_score,
                tag,
            };
        }
        ThreatVerdict::None
    }
}

/// Strip a trailing `:port` from a Host header value, handling bracketed IPv6
/// literals (`[::1]:80` → `::1`). Bare hostnames/IPv4 are returned unchanged
/// when no numeric port suffix is present.
fn strip_port(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match host.rfind(':') {
        Some(i) if !host[i + 1..].is_empty() && host[i + 1..].bytes().all(|b| b.is_ascii_digit()) => {
            &host[..i]
        }
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn ip_matcher_exact_and_cidr() {
        let mut m = IpMatcher::default();
        m.add_ip(ip("1.2.3.4"));
        m.add_cidr(IpNet::from_str("10.0.0.0/8").unwrap());
        m.add_cidr(IpNet::from_str("192.168.1.0/24").unwrap());
        assert!(m.contains(ip("1.2.3.4")));
        assert!(!m.contains(ip("1.2.3.5")));
        assert!(m.contains(ip("10.255.255.255"))); // inside /8
        assert!(m.contains(ip("192.168.1.200"))); // inside /24
        assert!(!m.contains(ip("192.168.2.1"))); // outside /24
    }

    #[test]
    fn ip_matcher_v6() {
        let mut m = IpMatcher::default();
        m.add_ip(ip("2001:db8::1"));
        m.add_cidr(IpNet::from_str("2001:db8:abcd::/48").unwrap());
        assert!(m.contains(ip("2001:db8::1")));
        assert!(m.contains(ip("2001:db8:abcd::9999")));
        assert!(!m.contains(ip("2001:db8:ffff::1")));
    }

    fn feed() -> ThreatFeed {
        let block = RawTier {
            ips: vec!["9.9.9.9".into()],
            cidrs: vec!["203.0.113.0/24".into()],
            user_agents: vec!["sqlmap".into()],
            domains: vec!["Evil.example".into()],
            url_substrings: vec!["/wp-admin/evil".into()],
        };
        let watch = RawTier {
            ips: vec!["8.8.8.8".into()],
            ..Default::default()
        };
        ThreatFeed::from_parts(42, 3, block, watch)
    }

    #[test]
    fn block_tier_blocks() {
        let f = feed();
        assert!(matches!(
            f.check(ip("9.9.9.9"), None, None, "/"),
            ThreatVerdict::Block { .. }
        ));
        assert!(matches!(
            f.check(ip("203.0.113.55"), None, None, "/"),
            ThreatVerdict::Block { .. }
        ));
    }

    #[test]
    fn ua_substring_and_domain_port_strip() {
        let f = feed();
        // UA substring match, case-insensitive.
        assert!(matches!(
            f.check(ip("1.1.1.1"), Some("Mozilla sqlMAP/1.7"), None, "/"),
            ThreatVerdict::Block { .. }
        ));
        // Domain match with a port + different case.
        assert!(matches!(
            f.check(ip("1.1.1.1"), None, Some("evil.example:8443"), "/"),
            ThreatVerdict::Block { .. }
        ));
        // URL substring match.
        assert!(matches!(
            f.check(ip("1.1.1.1"), None, None, "/WP-Admin/Evil?x=1"),
            ThreatVerdict::Block { .. }
        ));
    }

    #[test]
    fn watch_tier_scores_not_blocks() {
        let f = feed();
        match f.check(ip("8.8.8.8"), None, None, "/") {
            ThreatVerdict::Score { score, .. } => assert_eq!(score, 3),
            other => panic!("expected Score, got {other:?}"),
        }
    }

    #[test]
    fn clean_request_passes() {
        let f = feed();
        assert_eq!(
            f.check(ip("1.1.1.1"), Some("Mozilla/5.0"), Some("good.example"), "/index.html"),
            ThreatVerdict::None
        );
    }

    #[test]
    fn empty_feed_matches_nothing() {
        let f = ThreatFeed::empty();
        assert!(f.is_empty());
        assert_eq!(f.check(ip("9.9.9.9"), Some("sqlmap"), None, "/"), ThreatVerdict::None);
    }
}
