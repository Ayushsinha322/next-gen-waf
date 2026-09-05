//! Verifying a "good bot" User-Agent claim before it earns the allowlist.
//!
//! `bot_detect::score` used to return `score: 0, tier: Allow` for any request
//! whose User-Agent matched one of fourteen crawler patterns. That is an
//! unauthenticated allowlist: `curl -A Googlebot` opted out of bot scoring with
//! one header, and the `good_bot_allowed_unverified` counter exists to show how
//! often that trust was granted.
//!
//! The crawler operators themselves document how to verify a claim (Google's
//! "Verifying Googlebot", Bing's equivalent): reverse-resolve the client IP, check
//! the PTR name ends in the operator's published domain, then FORWARD-resolve
//! that name and require the client IP to be among its addresses. The forward
//! step is what defeats a spoofed PTR — anyone controls the PTR for their own
//! address space; nobody but Google controls what `googlebot.com` names resolve
//! to.
//!
//! # Never on the request path
//!
//! DNS is a network round-trip with attacker-controlled timing: an adversary who
//! sends thousands of "Googlebot" requests from addresses whose PTR lookups hang
//! would otherwise turn a WAF check into a latency amplifier. So `check` NEVER
//! awaits. It answers from a per-IP cache, and on a miss it records `Pending`,
//! spawns a bounded background verification, and returns "unknown" — which the
//! scorer treats as "no bypass, no penalty". The first request from a genuine
//! crawler IP is scored like any other client (it is not a scanner, so it
//! passes); the second earns the allowlist. That is the correct fail-closed
//! default.
//!
//! In-flight lookups are capped by a semaphore; over the cap we simply do not
//! verify, which costs a crawler its allowlist for one request and costs an
//! attacker nothing to exploit. The cache has three TTLs, because the three
//! outcomes decay differently: a verified address stays verified for hours; a
//! contradicted PTR is a fact worth remembering for a while; a lookup that merely
//! failed should be retried soon.
//!
//! # Why the OS resolver
//!
//! `getnameinfo(3)` for PTR and `tokio::net::lookup_host` for A/AAAA — the same
//! glibc resolver the proxy already uses for upstreams, so it works inside the
//! distroless image and honours the container's `resolv.conf`. A resolver crate
//! was tried first: `hickory-resolver` requires `url >= 2.5`, which pulls the
//! `icu_*` crates and Rust 1.86 (toolchain and CI are 1.85), plus 44 packages.
//! `getnameinfo` is blocking, so it runs in `spawn_blocking`, which is fine off
//! the request path and behind the permit cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tracing::debug;

/// Positive results are stable: crawler addresses do not change owner by the hour.
const TTL_VERIFIED: Duration = Duration::from_secs(6 * 3600);
/// A PTR that contradicted the claim is evidence; keep it, but not forever.
const TTL_REJECTED: Duration = Duration::from_secs(3600);
/// A lookup that failed (no PTR, timeout, resolver error) says nothing about the
/// client; retry soon rather than penalise or trust.
const TTL_UNKNOWN: Duration = Duration::from_secs(5 * 60);
/// A `Pending` older than this means the verification task died; allow another.
const PENDING_STALE: Duration = Duration::from_secs(30);
/// Hard cap on concurrent lookups. Over it, claims simply go unverified.
const MAX_INFLIGHT: usize = 32;
/// Cache cap. A flood of distinct addresses must not grow memory without bound.
const MAX_CACHE: usize = 50_000;
/// Per-lookup budget. Resolver defaults can wait tens of seconds; we will not.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Verified,
    Rejected,
    Unknown,
    Pending,
}

impl Verdict {
    fn ttl(self) -> Duration {
        match self {
            Verdict::Verified => TTL_VERIFIED,
            Verdict::Rejected => TTL_REJECTED,
            Verdict::Unknown => TTL_UNKNOWN,
            Verdict::Pending => PENDING_STALE,
        }
    }
    /// What the scorer is told. `Pending` and `Unknown` are both "not known".
    fn for_scorer(self) -> Option<bool> {
        match self {
            Verdict::Verified => Some(true),
            Verdict::Rejected => Some(false),
            Verdict::Unknown | Verdict::Pending => None,
        }
    }
}

/// DNS primitives, abstracted so the verifier's logic is testable without a
/// network and so the OS-resolver choice is confined to one impl.
#[async_trait::async_trait]
pub(crate) trait Resolve: Send + Sync + 'static {
    /// PTR names for `ip`, lowercased, without trailing dot. Empty or `Err` when
    /// there is none.
    async fn ptr(&self, ip: IpAddr) -> std::io::Result<Vec<String>>;
    /// A/AAAA addresses for `host`.
    async fn addrs(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The system resolver — glibc via `getnameinfo(3)` and `getaddrinfo(3)`.
pub(crate) struct OsResolver;

#[async_trait::async_trait]
impl Resolve for OsResolver {
    async fn ptr(&self, ip: IpAddr) -> std::io::Result<Vec<String>> {
        tokio::task::spawn_blocking(move || ptr_blocking(ip))
            .await
            .map_err(|e| std::io::Error::other(format!("ptr task: {e}")))?
    }
    async fn addrs(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let addrs = tokio::net::lookup_host((host, 0)).await?;
        Ok(addrs.map(|sa| sa.ip()).collect())
    }
}

#[cfg(unix)]
fn ptr_blocking(ip: IpAddr) -> std::io::Result<Vec<String>> {
    use std::ffi::CStr;
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;

    // NI_MAXHOST is 1025 on glibc.
    let mut host = [0 as libc::c_char; 1025];
    let rc = unsafe {
        match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        // EAI_NONAME under NI_NAMEREQD is simply "no PTR"; any other code is a
        // resolver problem. Both are "unknown" to the caller.
        return Err(std::io::Error::other(format!("getnameinfo rc={rc}")));
    }
    // SAFETY: getnameinfo returned 0, so `host` holds a NUL-terminated string.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if name.is_empty() {
        return Ok(vec![]);
    }
    Ok(vec![name])
}

#[cfg(not(unix))]
fn ptr_blocking(_ip: IpAddr) -> std::io::Result<Vec<String>> {
    Err(std::io::Error::other(
        "reverse DNS not implemented on this platform",
    ))
}

/// Does `host` sit inside one of the operator's published domains?
/// Exact match or a dot-separated subdomain; `evilgooglebot.com` is neither.
fn in_domain(host: &str, domains: &[&str]) -> bool {
    domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Per-process verifier. One instance lives in `ModulesState`.
pub(crate) struct GoodBotVerifier {
    resolver: Arc<dyn Resolve>,
    cache: Mutex<HashMap<IpAddr, (Verdict, Instant)>>,
    inflight: Arc<Semaphore>,
    // Counters, read by /healthz. Relaxed: they are statistics, not sync.
    lookups: AtomicU64,
    verified: AtomicU64,
    rejected: AtomicU64,
    unverifiable: AtomicU64,
}

impl GoodBotVerifier {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_resolver(Arc::new(OsResolver))
    }

    pub(crate) fn with_resolver(resolver: Arc<dyn Resolve>) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            cache: Mutex::new(HashMap::new()),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            lookups: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            unverifiable: AtomicU64::new(0),
        })
    }

    /// The request-path entry point. NEVER awaits.
    ///
    /// Returns what is known about `ip`'s claim to be `crawler` right now, and
    /// if nothing is known, starts finding out for next time.
    pub(crate) fn check(self: &Arc<Self>, ip: IpAddr, crawler: &'static str) -> Option<bool> {
        let domains = sentinel_modules::good_bot_verify_domains(crawler);
        if domains.is_empty() {
            // Operator publishes no PTR domain: can never be verified. Counted,
            // not looked up — there is nothing a lookup could establish.
            self.unverifiable.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let now = Instant::now();
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((v, at)) = cache.get(&ip).copied() {
                if now.duration_since(at) < v.ttl() {
                    return v.for_scorer();
                }
            }
            // Miss or expired. Bound memory before growing.
            if cache.len() >= MAX_CACHE {
                cache.retain(|_, (v, at)| now.duration_since(*at) < v.ttl());
                if cache.len() >= MAX_CACHE {
                    // Still full of live entries: refuse to grow. No verification
                    // for this address right now — fail closed, not open.
                    return None;
                }
            }
            cache.insert(ip, (Verdict::Pending, now));
        }
        // Spawn only if a permit is free; otherwise the Pending entry expires in
        // PENDING_STALE and a later request tries again.
        let Ok(permit) = Arc::clone(&self.inflight).try_acquire_owned() else {
            return None;
        };
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let v = me.verify(ip, domains).await;
            me.record(ip, v);
            drop(permit);
        });
        None
    }

    /// The actual verification. Public to the crate so tests can await it.
    pub(crate) async fn verify(&self, ip: IpAddr, domains: &[&str]) -> Verdict {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let names = match tokio::time::timeout(LOOKUP_TIMEOUT, self.resolver.ptr(ip)).await {
            Ok(Ok(n)) => n,
            // No PTR, resolver error, or timeout: says nothing about the client.
            Ok(Err(_)) | Err(_) => return Verdict::Unknown,
        };
        if names.is_empty() {
            return Verdict::Unknown;
        }
        let mut saw_in_domain = false;
        for name in &names {
            if !in_domain(name, domains) {
                continue;
            }
            saw_in_domain = true;
            // Forward-confirm: the operator-owned name must resolve back to the
            // client. This is the step that defeats a spoofed PTR.
            match tokio::time::timeout(LOOKUP_TIMEOUT, self.resolver.addrs(name)).await {
                Ok(Ok(addrs)) if addrs.contains(&ip) => return Verdict::Verified,
                Ok(Ok(_)) => {} // in-domain name that does not point back: spoof
                Ok(Err(_)) | Err(_) => return Verdict::Unknown,
            }
        }
        // A PTR exists and either lies outside the domain or failed to confirm.
        // Both are a claim contradicted by the evidence.
        debug!(%ip, ?names, in_domain = saw_in_domain, "good-bot claim rejected by reverse DNS");
        Verdict::Rejected
    }

    fn record(&self, ip: IpAddr, v: Verdict) {
        match v {
            Verdict::Verified => self.verified.fetch_add(1, Ordering::Relaxed),
            Verdict::Rejected => self.rejected.fetch_add(1, Ordering::Relaxed),
            Verdict::Unknown => self.unverifiable.fetch_add(1, Ordering::Relaxed),
            Verdict::Pending => 0,
        };
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(ip, (v, Instant::now()));
    }

    /// For /healthz.
    pub(crate) fn status(&self) -> serde_json::Value {
        let cache_entries = self.cache.lock().map(|c| c.len()).unwrap_or(0);
        serde_json::json!({
            "lookups": self.lookups.load(Ordering::Relaxed),
            "verified": self.verified.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "unverifiable": self.unverifiable.load(Ordering::Relaxed),
            "cache_entries": cache_entries,
            "max_inflight": MAX_INFLIGHT,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Scripted resolver: PTR answers per IP, forward answers per host, plus a
    /// call counter so caching can be asserted.
    struct Mock {
        ptr: HashMap<IpAddr, Vec<String>>,
        fwd: HashMap<String, Vec<IpAddr>>,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Resolve for Mock {
        async fn ptr(&self, ip: IpAddr) -> std::io::Result<Vec<String>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.ptr
                .get(&ip)
                .cloned()
                .ok_or_else(|| std::io::Error::other("no ptr"))
        }
        async fn addrs(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.fwd
                .get(host)
                .cloned()
                .ok_or_else(|| std::io::Error::other("nxdomain"))
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    const G: &[&str] = &["googlebot.com", "google.com"];

    fn verifier(
        ptr: &[(&str, &str)],
        fwd: &[(&str, &[&str])],
    ) -> (Arc<GoodBotVerifier>, Arc<Mock>) {
        let m = Arc::new(Mock {
            ptr: ptr
                .iter()
                .map(|(i, n)| (ip(i), vec![n.to_string()]))
                .collect(),
            fwd: fwd
                .iter()
                .map(|(h, ips)| (h.to_string(), ips.iter().map(|i| ip(i)).collect()))
                .collect(),
            calls: AtomicUsize::new(0),
        });
        (GoodBotVerifier::with_resolver(m.clone()), m)
    }

    /// The real thing: PTR in googlebot.com AND it resolves back to the client.
    #[tokio::test]
    async fn a_genuine_crawler_verifies() {
        let (v, _) = verifier(
            &[("66.249.66.1", "crawl-66-249-66-1.googlebot.com")],
            &[("crawl-66-249-66-1.googlebot.com", &["66.249.66.1"])],
        );
        assert_eq!(v.verify(ip("66.249.66.1"), G).await, Verdict::Verified);
    }

    /// THE attack the forward step exists for: anyone can make THEIR OWN
    /// address's PTR say "googlebot.com". Only Google can make a googlebot.com
    /// name resolve to that address — and here it does not.
    #[tokio::test]
    async fn a_spoofed_ptr_is_rejected_by_forward_confirmation() {
        let (v, _) = verifier(
            &[("203.0.113.9", "crawl-1-2-3-4.googlebot.com")],
            &[("crawl-1-2-3-4.googlebot.com", &["66.249.66.1"])], // points elsewhere
        );
        assert_eq!(v.verify(ip("203.0.113.9"), G).await, Verdict::Rejected);
    }

    #[tokio::test]
    async fn a_ptr_outside_the_operators_domain_is_rejected() {
        let (v, _) = verifier(&[("203.0.113.9", "vps-9.evil-hosting.example")], &[]);
        assert_eq!(v.verify(ip("203.0.113.9"), G).await, Verdict::Rejected);
        // Lookalike domains are not subdomains.
        let (v2, _) = verifier(&[("203.0.113.10", "crawl.evilgooglebot.com")], &[]);
        assert_eq!(v2.verify(ip("203.0.113.10"), G).await, Verdict::Rejected);
    }

    /// No PTR is not a lie — it is an absence. Unknown, no penalty, retried soon.
    #[tokio::test]
    async fn no_ptr_is_unknown_not_rejected() {
        let (v, _) = verifier(&[], &[]);
        assert_eq!(v.verify(ip("198.51.100.7"), G).await, Verdict::Unknown);
    }

    /// `check` never awaits and answers from the cache on the second call
    /// without touching the resolver again.
    #[tokio::test]
    async fn check_is_non_blocking_and_cached() {
        let (v, m) = verifier(
            &[("66.249.66.1", "crawl-66-249-66-1.googlebot.com")],
            &[("crawl-66-249-66-1.googlebot.com", &["66.249.66.1"])],
        );
        let client = ip("66.249.66.1");
        // First sight: nothing known yet, lookup kicked off in the background.
        assert_eq!(v.check(client, "Googlebot"), None);
        // Let the spawned verification finish.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let calls_after_first = m.calls.load(Ordering::Relaxed);
        assert!(calls_after_first >= 2, "ptr + forward should have run");
        // Now known, and served from cache: no new resolver calls.
        assert_eq!(v.check(client, "Googlebot"), Some(true));
        assert_eq!(v.check(client, "Googlebot"), Some(true));
        assert_eq!(m.calls.load(Ordering::Relaxed), calls_after_first);
        let s = v.status();
        assert_eq!(s["verified"], 1);
        assert_eq!(s["lookups"], 1);
    }

    /// A crawler whose operator publishes no PTR domain is never looked up and
    /// never verified — fail closed, and cheaply.
    #[tokio::test]
    async fn an_unverifiable_crawler_costs_no_lookup_and_earns_nothing() {
        let (v, m) = verifier(&[("1.2.3.4", "whatever.example")], &[]);
        assert_eq!(v.check(ip("1.2.3.4"), "DuckDuckBot"), None);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            m.calls.load(Ordering::Relaxed),
            0,
            "no lookup for an unverifiable crawler"
        );
        assert_eq!(v.status()["unverifiable"], 1);
    }

    #[test]
    fn domain_matching_is_exact_or_subdomain() {
        assert!(in_domain("googlebot.com", G));
        assert!(in_domain("crawl-1-2-3-4.googlebot.com", G));
        assert!(in_domain("rate-limited-proxy-66-249-66-1.google.com", G));
        assert!(!in_domain("evilgooglebot.com", G));
        assert!(!in_domain("googlebot.com.attacker.example", G));
        assert!(!in_domain("", G));
    }
}
