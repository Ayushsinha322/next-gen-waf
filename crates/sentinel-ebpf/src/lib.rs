//! sentinel-ebpf — eBPF/XDP integration layer for Sentinel WAF
//!
//! # Overview
//!
//! This crate provides kernel-level packet dropping via XDP as well as a
//! transparent userspace fallback for development environments that lack
//! `CAP_BPF` / `CAP_NET_ADMIN` (e.g. containers, CI, macOS).
//!
//! ## Modes
//!
//! | Mode | How to enable | Notes |
//! |------|---------------|-------|
//! | **Software** (default) | `EbpfConfig { enable_kernel: false, .. }` | Pure userspace; the proxy calls `is_blocked()` before forwarding each request. |
//! | **Kernel XDP** | `enable_kernel: true` + `kernel` Cargo feature + CAP_BPF | Attaches a compiled XDP ELF to a NIC; truly drops packets in the kernel. |
//!
//! The kernel path is gated behind `#[cfg(feature = "kernel")]` so the crate
//! always compiles cleanly on any platform.
//!
//! ## Enabling kernel XDP
//!
//! 1. Compile the BPF program (e.g. with `aya-build` or `clang -target bpf`)
//!    and embed the ELF bytes in `XDP_PROGRAM_BYTES`.
//! 2. Build with `--features kernel`.
//! 3. Run with `CAP_BPF` / `CAP_NET_ADMIN` (or as root).
//!
//! ## IP-blocking pipeline (userspace mode)
//!
//! ```text
//!  Incoming request
//!       │
//!  proxy ──► EbpfManager::is_blocked(src_ip)
//!                  │ true  ──► 403 / drop
//!                  │ false ──► forward
//! ```
//!
//! In kernel mode this check happens in the NIC driver interrupt path and
//! packets are dropped before they ever reach userspace.

#![deny(clippy::unwrap_used)]

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the sentinel-ebpf crate.
#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("XDP program load failed: {0}")]
    LoadFailed(String),

    #[error("XDP attach failed on interface {iface}: {msg}")]
    AttachFailed { iface: String, msg: String },

    #[error("BPF map operation failed: {0}")]
    MapError(String),

    #[error("Permission denied — CAP_BPF / CAP_NET_ADMIN required for kernel XDP")]
    PermissionDenied,

    #[error("Kernel XDP not supported on this platform")]
    UnsupportedPlatform,

    #[error("Manager is not running")]
    NotRunning,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, EbpfError>;

// ---------------------------------------------------------------------------
// IpNet — CIDR representation
// ---------------------------------------------------------------------------

/// An IP network (address + prefix length).
///
/// Supports both IPv4 (e.g. `192.168.1.0/24`) and IPv6 (e.g. `::1/128`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpNet {
    /// Network address (host bits zeroed is conventional but not enforced).
    pub addr: IpAddr,
    /// Prefix length in bits (0–32 for IPv4, 0–128 for IPv6).
    pub prefix_len: u8,
}

impl IpNet {
    /// Create a new `IpNet`.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }

    /// Returns `true` if `ip` falls within this network.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let bits = self.prefix_len.min(32);
                if bits == 0 {
                    return true;
                }
                let mask: u32 = !0u32 << (32 - bits);
                (u32::from_be_bytes(net.octets()) & mask)
                    == (u32::from_be_bytes(candidate.octets()) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let bits = self.prefix_len.min(128);
                if bits == 0 {
                    return true;
                }
                let net_n = u128::from_be_bytes(net.octets());
                let cand_n = u128::from_be_bytes(candidate.octets());
                let mask: u128 = !0u128 << (128 - bits);
                (net_n & mask) == (cand_n & mask)
            }
            // IPv4/IPv6 mismatch — never contained
            _ => false,
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

// Convenience: parse "1.2.3.0/24" strings via ipnet crate
impl TryFrom<&str> for IpNet {
    type Error = String;

    fn try_from(s: &str) -> std::result::Result<Self, String> {
        // Delegate to the ipnet workspace crate for parsing
        let parsed: ipnet::IpNet = s
            .parse()
            .map_err(|e: ipnet::AddrParseError| e.to_string())?;
        Ok(Self {
            addr: parsed.network(),
            prefix_len: parsed.prefix_len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`EbpfManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    /// Network interface to attach XDP to (e.g. `"eth0"`).
    pub interface: String,

    /// Initial CIDR blocklist loaded into the BPF map (or userspace set).
    pub blocklist: Vec<IpNet>,

    /// Attempt to load a real XDP program (requires the `kernel` Cargo
    /// feature, Linux, and `CAP_BPF`/`CAP_NET_ADMIN`).  If loading fails
    /// the manager silently falls back to the software implementation.
    pub enable_kernel: bool,

    /// How often (in seconds) the background stats-polling task wakes up.
    /// In software mode this has no effect on accuracy since counters are
    /// updated inline.
    pub stats_interval_secs: u64,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            blocklist: Vec::new(),
            enable_kernel: false,
            stats_interval_secs: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Snapshot of XDP/eBPF counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EbpfStats {
    /// Packets allowed through (XDP_PASS).
    pub xdp_pass: u64,
    /// Packets dropped by XDP (XDP_DROP).
    pub xdp_drop: u64,
    /// Packets that caused an eBPF program error (XDP_ABORTED).
    pub xdp_aborted: u64,
    /// Alias for `xdp_drop` — used by the proxy to read "how many packets
    /// were dropped at the kernel level".
    pub ebpf_drops: u64,
}

/// Thread-safe atomic counter set used internally.
struct AtomicStats {
    xdp_pass: AtomicU64,
    xdp_drop: AtomicU64,
    xdp_aborted: AtomicU64,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            xdp_pass: AtomicU64::new(0),
            xdp_drop: AtomicU64::new(0),
            xdp_aborted: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> EbpfStats {
        let drop = self.xdp_drop.load(Ordering::Relaxed);
        EbpfStats {
            xdp_pass: self.xdp_pass.load(Ordering::Relaxed),
            xdp_drop: drop,
            xdp_aborted: self.xdp_aborted.load(Ordering::Relaxed),
            ebpf_drops: drop,
        }
    }
}

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

/// Whether the manager is using the kernel XDP path or pure-userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EbpfMode {
    /// XDP program loaded in the kernel; packets are dropped before reaching
    /// userspace.  Requires the `kernel` feature + `CAP_BPF`.
    Kernel,
    /// Pure-userspace accounting.  The WAF proxy calls [`EbpfManager::is_blocked`]
    /// on each incoming connection and returns 403 / drops the request.
    Software,
}

impl fmt::Display for EbpfMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EbpfMode::Kernel => write!(f, "kernel-xdp"),
            EbpfMode::Software => write!(f, "software"),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal blocklist — supports both exact IPs and CIDR ranges
// ---------------------------------------------------------------------------

struct Blocklist {
    /// Exact-IP fast-path (covers the 99 % case of single-IP bans).
    exact: HashSet<IpAddr>,
    /// CIDR ranges (used for subnet bans).
    ranges: Vec<IpNet>,
}

impl Blocklist {
    fn new() -> Self {
        Self {
            exact: HashSet::new(),
            ranges: Vec::new(),
        }
    }

    fn from_nets(nets: &[IpNet]) -> Self {
        let mut bl = Self::new();
        for net in nets {
            if net.prefix_len == 32 && net.addr.is_ipv4()
                || net.prefix_len == 128 && net.addr.is_ipv6()
            {
                bl.exact.insert(net.addr);
            } else {
                bl.ranges.push(net.clone());
            }
        }
        bl
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        if self.exact.contains(ip) {
            return true;
        }
        self.ranges.iter().any(|net| net.contains(ip))
    }

    fn add_ip(&mut self, ip: IpAddr) {
        self.exact.insert(ip);
    }

    fn remove_ip(&mut self, ip: &IpAddr) {
        self.exact.remove(ip);
        // Also remove any /32 or /128 range entry that matches exactly
        self.ranges.retain(|net| {
            !(net.addr == *ip
                && ((ip.is_ipv4() && net.prefix_len == 32)
                    || (ip.is_ipv6() && net.prefix_len == 128)))
        });
    }

    fn len(&self) -> usize {
        self.exact.len() + self.ranges.len()
    }
}

// ---------------------------------------------------------------------------
// XDP kernel backend (feature-gated)
// ---------------------------------------------------------------------------

// When the "kernel" feature is present we expose a thin aya wrapper.
// The XDP ELF binary should be embedded here (e.g. via include_bytes!) or
// loaded from a path supplied in config.  For now the slot is reserved and
// the software fallback is used even with the feature enabled unless a real
// ELF is provided.
//
// To plug in a real program:
//   1. Compile `xdp_blocklist.bpf.c` with clang -target bpf -O2
//   2. Replace the None below with Some(include_bytes!("../bpf/xdp_blocklist.bpf.o"))
//   3. Implement XdpKernel::attach() with aya calls

#[cfg(feature = "kernel")]
mod kernel_xdp {
    use super::*;

    /// Placeholder ELF bytes.  Replace with `include_bytes!("path/to/prog.o")`.
    const XDP_PROGRAM_BYTES: Option<&[u8]> = None;

    pub struct XdpKernel {
        _iface: String,
    }

    impl XdpKernel {
        /// Try to load and attach the XDP program.  Returns `None` if no ELF
        /// is embedded or if loading fails (caller falls back to software).
        pub fn try_attach(iface: &str) -> Option<Self> {
            let _bytes = XDP_PROGRAM_BYTES?;

            // Real implementation would be:
            //   let mut ebpf = aya::Ebpf::load(bytes).ok()?;
            //   aya_log::EbpfLogger::init(&mut ebpf).ok();
            //   let prog: &mut aya::programs::Xdp =
            //       ebpf.program_mut("xdp_blocklist")?.try_into().ok()?;
            //   prog.load().ok()?;
            //   prog.attach(iface, aya::programs::XdpFlags::default()).ok()?;
            //   Some(Self { _iface: iface.to_string() })

            warn!("kernel XDP: no ELF embedded — falling back to software mode");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// EbpfManager
// ---------------------------------------------------------------------------

/// Central handle for eBPF/XDP management.
///
/// Create with [`EbpfManager::new`], then call [`EbpfManager::start`] to
/// spawn the background task.  The proxy should call [`EbpfManager::is_blocked`]
/// on each new connection in software mode.
pub struct EbpfManager {
    config: Arc<EbpfConfig>,
    blocklist: Arc<RwLock<Blocklist>>,
    stats: Arc<AtomicStats>,
    running: Arc<AtomicBool>,
    mode: EbpfMode,
}

impl EbpfManager {
    /// Create a new manager.  Does NOT start the background task; call
    /// [`start`][Self::start] afterwards.
    pub async fn new(cfg: EbpfConfig) -> Result<Self> {
        let mode = if cfg.enable_kernel {
            #[cfg(feature = "kernel")]
            {
                if kernel_xdp::XdpKernel::try_attach(&cfg.interface).is_some() {
                    EbpfMode::Kernel
                } else {
                    info!(
                        interface = %cfg.interface,
                        "XDP kernel attach unavailable — using software mode"
                    );
                    EbpfMode::Software
                }
            }
            #[cfg(not(feature = "kernel"))]
            {
                info!(
                    "sentinel-ebpf: 'kernel' feature not enabled — using software mode \
                     (rebuild with --features kernel for XDP)"
                );
                EbpfMode::Software
            }
        } else {
            EbpfMode::Software
        };

        let blocklist = Blocklist::from_nets(&cfg.blocklist);
        info!(
            mode = %mode,
            interface = %cfg.interface,
            initial_entries = blocklist.len(),
            "EbpfManager initialised"
        );

        Ok(Self {
            blocklist: Arc::new(RwLock::new(blocklist)),
            stats: Arc::new(AtomicStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            mode,
            config: Arc::new(cfg),
        })
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Start the background statistics / housekeeping task.
    ///
    /// In software mode this is a lightweight periodic log; in kernel mode
    /// (when fully implemented) it would also poll BPF map counters.
    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            // Already running — idempotent
            return Ok(());
        }

        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let blocklist = Arc::clone(&self.blocklist);
        let interval_secs = self.config.stats_interval_secs.max(1);
        let mode = self.mode;
        let iface = self.config.interface.clone();

        tokio::spawn(async move {
            info!(mode = %mode, interface = %iface, "eBPF background task started");
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            ticker.tick().await; // skip the immediate first tick

            while running.load(Ordering::Relaxed) {
                ticker.tick().await;

                let snap = stats.snapshot();
                let bl_len = blocklist.read().expect("blocklist RwLock poisoned").len();

                debug!(
                    mode = %mode,
                    xdp_pass  = snap.xdp_pass,
                    xdp_drop  = snap.xdp_drop,
                    xdp_abort = snap.xdp_aborted,
                    blocklist_entries = bl_len,
                    "eBPF stats"
                );

                // In kernel mode: here we would re-read BPF map counters via
                // aya and merge them into `stats`.
            }

            info!("eBPF background task stopped");
        });

        Ok(())
    }

    /// Gracefully stop the background task.
    pub async fn shutdown(&self) {
        if self.running.swap(false, Ordering::SeqCst) {
            info!("EbpfManager: shutdown requested");
            // Give the background task one tick to notice the flag.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // -----------------------------------------------------------------------
    // Blocklist management
    // -----------------------------------------------------------------------

    /// Add a single IP to the blocklist.
    ///
    /// In kernel mode this would also update the BPF LPM-trie map so that
    /// the XDP program starts dropping packets immediately.
    pub fn block_ip(&self, ip: IpAddr) {
        let mut bl = self.blocklist.write().expect("blocklist RwLock poisoned");
        bl.add_ip(ip);
        self.stats.xdp_drop.fetch_add(0, Ordering::Relaxed); // no-op; update on match
        debug!(%ip, "blocked IP added");
    }

    /// Add a CIDR range to the blocklist.
    pub fn block_net(&self, net: IpNet) {
        let mut bl = self.blocklist.write().expect("blocklist RwLock poisoned");
        bl.ranges.push(net.clone());
        debug!(%net, "blocked CIDR range added");
    }

    /// Remove a single IP from the blocklist.
    pub fn unblock_ip(&self, ip: IpAddr) {
        let mut bl = self.blocklist.write().expect("blocklist RwLock poisoned");
        bl.remove_ip(&ip);
        debug!(%ip, "unblocked IP removed");
    }

    /// Check whether `ip` is covered by the current blocklist.
    ///
    /// This is the hot path: the proxy calls it on **every** incoming
    /// connection in software mode.  The implementation acquires a read-lock
    /// (no contention with background writer) and does an O(1) hash-set
    /// lookup plus an O(n) scan over CIDR ranges.  Typical deployments have
    /// O(10³) exact-IP entries and O(10) CIDR ranges, so this is fast enough.
    ///
    /// When a match is found the `xdp_drop` counter is incremented.
    #[inline]
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let bl = self.blocklist.read().expect("blocklist RwLock poisoned");
        if bl.contains(&ip) {
            self.stats.xdp_drop.fetch_add(1, Ordering::Relaxed);
            self.stats
                .xdp_aborted // reuse as "software_drop" — field renamed in snapshot
                .fetch_add(0, Ordering::Relaxed);
            true
        } else {
            self.stats.xdp_pass.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------

    /// Return a point-in-time snapshot of XDP counters.
    pub fn stats(&self) -> EbpfStats {
        self.stats.snapshot()
    }

    /// Convenience: total number of packets dropped (alias for `stats().ebpf_drops`).
    pub fn ebpf_drops(&self) -> u64 {
        self.stats.xdp_drop.load(Ordering::Relaxed)
    }

    // -----------------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------------

    /// Current operating mode.
    pub fn mode(&self) -> EbpfMode {
        self.mode
    }

    /// Immutable view of the current configuration.
    pub fn config(&self) -> &EbpfConfig {
        &self.config
    }
}

// EbpfManager is safe to send/sync across threads: all interior state is
// wrapped in Arc + RwLock/Atomic — the compiler derives this automatically.

impl fmt::Debug for EbpfManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EbpfManager")
            .field("mode", &self.mode)
            .field("interface", &self.config.interface)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // ------------------------------------------------------------------
    // IpNet::contains
    // ------------------------------------------------------------------

    #[test]
    fn ipnet_contains_exact_ipv4() {
        let net = IpNet::new("192.168.1.1".parse().unwrap(), 32);
        assert!(net.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!net.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn ipnet_contains_subnet_ipv4() {
        let net = IpNet::new("10.0.0.0".parse().unwrap(), 8);
        assert!(net.contains(&"10.0.0.1".parse().unwrap()));
        assert!(net.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!net.contains(&"11.0.0.1".parse().unwrap()));
        assert!(!net.contains(&"9.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ipnet_contains_slash24_ipv4() {
        let net = IpNet::new("192.168.1.0".parse().unwrap(), 24);
        assert!(net.contains(&"192.168.1.0".parse().unwrap()));
        assert!(net.contains(&"192.168.1.254".parse().unwrap()));
        assert!(!net.contains(&"192.168.2.0".parse().unwrap()));
        assert!(!net.contains(&"192.168.0.255".parse().unwrap()));
    }

    #[test]
    fn ipnet_contains_slash0_matches_all_ipv4() {
        let net = IpNet::new("0.0.0.0".parse().unwrap(), 0);
        assert!(net.contains(&"1.2.3.4".parse().unwrap()));
        assert!(net.contains(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ipnet_contains_exact_ipv6() {
        let net = IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128);
        assert!(net.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!net.contains(&"::2".parse().unwrap()));
    }

    #[test]
    fn ipnet_contains_subnet_ipv6() {
        // fd00::/8
        let net = IpNet::new("fd00::".parse().unwrap(), 8);
        assert!(net.contains(&"fd00::1".parse().unwrap()));
        assert!(net.contains(&"fdff::ffff".parse().unwrap()));
        assert!(!net.contains(&"fe00::".parse().unwrap()));
    }

    #[test]
    fn ipnet_ipv4_does_not_match_ipv6() {
        let net = IpNet::new("10.0.0.0".parse().unwrap(), 8);
        let ipv6: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(!net.contains(&ipv6));
    }

    #[test]
    fn ipnet_display() {
        let net = IpNet::new("192.168.0.0".parse().unwrap(), 24);
        assert_eq!(net.to_string(), "192.168.0.0/24");
    }

    #[test]
    fn ipnet_try_from_str() {
        let net = IpNet::try_from("10.0.0.0/8").expect("parse");
        assert_eq!(net.prefix_len, 8);
        assert_eq!(net.addr, "10.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipnet_try_from_str_invalid() {
        assert!(IpNet::try_from("not_a_cidr").is_err());
    }

    // ------------------------------------------------------------------
    // Blocklist internal struct
    // ------------------------------------------------------------------

    #[test]
    fn blocklist_exact_ip_add_remove() {
        let mut bl = Blocklist::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!bl.contains(&ip));
        bl.add_ip(ip);
        assert!(bl.contains(&ip));
        bl.remove_ip(&ip);
        assert!(!bl.contains(&ip));
    }

    #[test]
    fn blocklist_cidr_range() {
        let net = IpNet::new("172.16.0.0".parse().unwrap(), 12);
        let mut bl = Blocklist::new();
        bl.ranges.push(net);
        assert!(bl.contains(&"172.16.0.1".parse().unwrap()));
        assert!(bl.contains(&"172.31.255.255".parse().unwrap()));
        assert!(!bl.contains(&"172.32.0.0".parse().unwrap()));
    }

    #[test]
    fn blocklist_len() {
        let nets = vec![
            IpNet::new("10.0.0.0".parse().unwrap(), 8),
            IpNet::new("192.168.1.1".parse().unwrap(), 32),
        ];
        let bl = Blocklist::from_nets(&nets);
        // /32 goes to exact set; /8 goes to ranges
        assert_eq!(bl.len(), 2);
    }

    // ------------------------------------------------------------------
    // EbpfManager: construction, block/unblock, stats
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn manager_new_default_config() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        assert_eq!(mgr.mode(), EbpfMode::Software);
    }

    #[tokio::test]
    async fn manager_block_unblock_ip() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();

        assert!(!mgr.is_blocked(ip));
        mgr.block_ip(ip);
        assert!(mgr.is_blocked(ip));
        mgr.unblock_ip(ip);
        assert!(!mgr.is_blocked(ip));
    }

    #[tokio::test]
    async fn manager_block_net() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let net = IpNet::new("203.0.113.0".parse().unwrap(), 24);

        mgr.block_net(net);
        assert!(mgr.is_blocked("203.0.113.42".parse().unwrap()));
        assert!(!mgr.is_blocked("203.0.112.42".parse().unwrap()));
    }

    #[tokio::test]
    async fn manager_stats_tracking() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let blocked: IpAddr = "198.18.0.1".parse().unwrap();
        let allowed: IpAddr = "198.18.0.2".parse().unwrap();

        mgr.block_ip(blocked);

        // 3 blocked hits
        for _ in 0..3 {
            assert!(mgr.is_blocked(blocked));
        }
        // 2 pass-through hits
        for _ in 0..2 {
            assert!(!mgr.is_blocked(allowed));
        }

        let stats = mgr.stats();
        assert_eq!(stats.xdp_drop, 3);
        assert_eq!(stats.ebpf_drops, 3, "ebpf_drops must alias xdp_drop");
        assert_eq!(stats.xdp_pass, 2);
    }

    #[tokio::test]
    async fn manager_ebpf_drops_convenience() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        mgr.block_ip(ip);
        mgr.is_blocked(ip);
        mgr.is_blocked(ip);
        assert_eq!(mgr.ebpf_drops(), 2);
    }

    #[tokio::test]
    async fn manager_initial_blocklist_from_config() {
        let cfg = EbpfConfig {
            blocklist: vec![IpNet::new("192.0.2.0".parse().unwrap(), 24)],
            ..Default::default()
        };
        let mgr = EbpfManager::new(cfg).await.unwrap();
        assert!(mgr.is_blocked("192.0.2.100".parse().unwrap()));
        assert!(!mgr.is_blocked("192.0.3.100".parse().unwrap()));
    }

    #[tokio::test]
    async fn manager_start_and_shutdown() {
        let mgr = EbpfManager::new(EbpfConfig {
            stats_interval_secs: 1,
            ..Default::default()
        })
        .await
        .unwrap();

        mgr.start().await.unwrap();
        assert!(mgr.running.load(Ordering::Relaxed));

        // Idempotent second start
        mgr.start().await.unwrap();

        mgr.shutdown().await;
        assert!(!mgr.running.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn manager_debug_impl() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let s = format!("{mgr:?}");
        assert!(s.contains("EbpfManager"), "missing struct name: {s}");
        // EbpfMode::Software's Debug representation is "Software"
        assert!(
            s.contains("Software") || s.contains("software"),
            "missing mode in debug output: {s}"
        );
    }

    #[tokio::test]
    async fn manager_config_accessor() {
        let cfg = EbpfConfig {
            interface: "lo".to_string(),
            ..Default::default()
        };
        let mgr = EbpfManager::new(cfg).await.unwrap();
        assert_eq!(mgr.config().interface, "lo");
    }

    // ------------------------------------------------------------------
    // IPv6 blocking
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn manager_block_ipv6() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        mgr.block_ip(ip);
        assert!(mgr.is_blocked(ip));
        assert!(!mgr.is_blocked(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))));
    }

    // ------------------------------------------------------------------
    // EbpfMode display
    // ------------------------------------------------------------------

    #[test]
    fn mode_display() {
        assert_eq!(EbpfMode::Software.to_string(), "software");
        assert_eq!(EbpfMode::Kernel.to_string(), "kernel-xdp");
    }
}
