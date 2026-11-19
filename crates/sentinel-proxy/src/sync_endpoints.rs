//! The control-plane endpoints a data-plane node talks to, and which one it is
//! using right now.
//!
//! WHY A LIST
//!
//! Every WAF node took its configuration, threat intelligence, plugins and
//! heartbeat from ONE address, `http://controlplane:9501` — control-plane node
//! 1 — and the admin console's API went to the same place. In the three-node
//! layout the other two control-plane nodes take over leadership when node 1
//! dies, but nothing could reach them: no site change, certificate or indicator
//! reached any WAF node, and the console was down, until node 1 came back. The
//! cluster was highly available on paper only.
//!
//! A load balancer in front of the control plane would also fix it, but the
//! WAF nodes are rolled BEFORE the control plane and the balancer is never
//! rolled, so a node pointed at a new balancer endpoint during an upgrade would
//! find nothing there and stop syncing. A list of the nodes' own names needs
//! nothing new to exist: every name in it already resolves today.
//!
//! HOW IT FAILS OVER
//!
//! Sticky: the current endpoint stays current while it works. When a poll fails
//! the next one becomes current; the order wraps. Every control-plane node
//! serves the same database, so any of them is as good as the first and there
//! is no fail-back. With one endpoint configured nothing changes from before.

use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::{info, warn};

#[derive(Debug)]
pub struct SyncEndpoints {
    urls: Vec<String>,
    current: AtomicUsize,
}

impl SyncEndpoints {
    /// Parse a comma-separated list of `http(s)://host:port` bases. Entries
    /// without a scheme are dropped with a warning; `None` when none remain.
    pub fn parse(spec: &str) -> Option<Self> {
        let mut urls = Vec::new();
        for raw in spec.split(',') {
            let u = raw.trim().trim_end_matches('/');
            if u.is_empty() {
                continue;
            }
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                warn!(endpoint = %u, "control-plane endpoint is not an http(s) URL — skipped");
                continue;
            }
            if !urls.iter().any(|x| x == u) {
                urls.push(u.to_string());
            }
        }
        (!urls.is_empty()).then(|| Self {
            urls,
            current: AtomicUsize::new(0),
        })
    }

    /// The endpoint to use now.
    pub fn current(&self) -> String {
        self.urls[self.current.load(Ordering::Acquire) % self.urls.len()].clone()
    }

    /// `base` just failed. If it is still the current endpoint, move to the
    /// next; if another caller already moved on, leave it. Returns the
    /// endpoint now current.
    pub fn failed(&self, base: &str) -> String {
        let n = self.urls.len();
        if n > 1 {
            let i = self.current.load(Ordering::Acquire);
            if self.urls[i % n] == base {
                let next = (i + 1) % n;
                if self
                    .current
                    .compare_exchange(i, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    info!(
                        from = %base,
                        to = %self.urls[next],
                        "control plane unreachable or not ready — switching endpoint"
                    );
                }
            }
        }
        self.current()
    }

    /// Every endpoint, in preference order.
    pub fn all(&self) -> &[String] {
        &self.urls
    }

    /// How many endpoints there are to fail over between.
    pub fn len(&self) -> usize {
        self.urls.len()
    }

    /// Never true: `parse` refuses an empty list. Here for clippy's sake.
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }
}

/// The list as configured: `a,b,c`.
impl std::fmt::Display for SyncEndpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.urls.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_endpoint_behaves_as_before() {
        let e = SyncEndpoints::parse("http://controlplane:9501").unwrap();
        assert_eq!(e.current(), "http://controlplane:9501");
        assert_eq!(
            e.failed("http://controlplane:9501"),
            "http://controlplane:9501"
        );
    }

    #[test]
    fn a_list_is_normalised_and_bad_entries_dropped() {
        let e = SyncEndpoints::parse(
            " http://controlplane:9501/ , cp2:9501, http://cp3:9501,,http://cp3:9501",
        )
        .unwrap();
        assert_eq!(e.all(), ["http://controlplane:9501", "http://cp3:9501"]);
        assert!(SyncEndpoints::parse(" , ").is_none());
        assert!(SyncEndpoints::parse("cp2:9501").is_none());
    }

    #[test]
    fn a_failure_moves_on_and_wraps() {
        let e = SyncEndpoints::parse("http://a:1,http://b:1,http://c:1").unwrap();
        assert_eq!(e.failed("http://a:1"), "http://b:1");
        // It stays on b while b works: sticky.
        assert_eq!(e.current(), "http://b:1");
        assert_eq!(e.failed("http://b:1"), "http://c:1");
        assert_eq!(e.failed("http://c:1"), "http://a:1");
    }

    #[test]
    fn a_stale_failure_report_does_not_skip_a_working_endpoint() {
        // Two loops saw `a` fail; the first moved to `b`. The second report is
        // about `a`, not `b`, and must not move `b` on.
        let e = SyncEndpoints::parse("http://a:1,http://b:1,http://c:1").unwrap();
        e.failed("http://a:1");
        assert_eq!(e.failed("http://a:1"), "http://b:1");
    }
}
