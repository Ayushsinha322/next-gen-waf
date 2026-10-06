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
use std::sync::{Arc, PoisonError, RwLock};
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
// LPM-trie key encoding (byte order) — shared, panic-free, endianness-safe
// ---------------------------------------------------------------------------

/// Encode an IPv4 address into the `u32` that an LPM-trie key's `data` field
/// must hold.
///
/// BYTE-ORDER CONTRACT (locked, do not "simplify"):
/// The kernel LPM trie matches the key `data` **MSB-first over its raw
/// in-memory bytes**, and the C program stores `ip->saddr` verbatim — i.e. the
/// IPv4 octets `a.b.c.d` in network (big-endian) byte order. So the userspace
/// key `data` must be the `u32` whose **native in-memory bytes are exactly the
/// octets `[a, b, c, d]`**. `u32::from_ne_bytes(octets)` produces precisely
/// that value on any host endianness (unlike `from_be_bytes`, which yields a
/// host-numeric value whose memory layout differs on little-endian). This is
/// verified by `lpm_v4_key_data_is_network_order_octets`.
#[cfg(any(test, feature = "kernel"))]
fn lpm_v4_key_data(ip: std::net::Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

// ---------------------------------------------------------------------------
// XDP kernel backend (feature-gated)
// ---------------------------------------------------------------------------

// When the "kernel" feature is enabled we expose a thin aya 0.13 wrapper around
// the committed XDP ELF (`bpf/sentinel_xdp.o`). It loads + attaches the program
// and mirrors the blocklist into the kernel LPM-trie maps. Every operation is
// panic-free: any error degrades to the userspace software path.

/// Test-only accessor for the embedded XDP object, so the integration test can
/// assert the alignment the loader depends on. Not part of the public API.
#[cfg(feature = "kernel")]
#[doc(hidden)]
pub fn xdp_object_bytes_for_test() -> &'static [u8] {
    kernel_xdp::xdp_program_bytes()
}

#[cfg(feature = "kernel")]
mod kernel_xdp {
    use super::{lpm_v4_key_data, EbpfError, IpNet, Result};
    use std::net::IpAddr;
    use std::sync::Mutex;

    use aya::maps::lpm_trie::{Key, LpmTrie};
    use aya::maps::PerCpuArray;
    use aya::programs::{Xdp, XdpFlags};
    use aya::Ebpf;
    use tracing::{info, warn};

    /// Wrapper that forces 8-byte alignment on the embedded object.
    ///
    /// THIS ALIGNMENT IS LOAD-BEARING. `include_bytes!` expands to a plain byte
    /// array and carries **no alignment guarantee**, so the linker may place it
    /// at any address. aya parses the ELF via the `object` crate, whose ELF64
    /// header is read as a `Pod` requiring 8-byte alignment; on an odd address
    /// it returns `Invalid ELF header size or alignment`, which aya then
    /// flattens into the opaque `error parsing ELF data`.
    ///
    /// Because the outcome is decided by the final link layout, the *same* .o
    /// parses in one binary and fails in another — which is exactly what made
    /// this so misleading. The object was always structurally valid (correct
    /// magic, machine 0xf7, relocatable, BTF present) and rebuilding it changed
    /// nothing; in the shipped data-plane binary the bytes simply landed
    /// unaligned, so kernel XDP had never once loaded on any deployment and
    /// every install silently ran the DDoS path in software mode.
    ///
    /// Do not replace this with a bare `include_bytes!`.
    #[repr(align(8))]
    struct Aligned<T: ?Sized>(T);

    /// The compiled XDP object file, committed to the repo and embedded at
    /// build time so no BPF toolchain is required at runtime.
    ///
    /// The length comes from the macro itself so the two can never drift.
    static XDP_OBJECT: Aligned<[u8; include_bytes!("bpf/sentinel_xdp.o").len()]> =
        Aligned(*include_bytes!("bpf/sentinel_xdp.o"));

    /// Alignment-guaranteed view of the embedded object.
    pub(crate) fn xdp_program_bytes() -> &'static [u8] {
        &XDP_OBJECT.0
    }

    /// The program/function name (matches `SEC("xdp") int sentinel_xdp(...)`).
    const PROGRAM_NAME: &str = "sentinel_xdp";
    const MAP_V4: &str = "blocked_v4";
    const MAP_V6: &str = "blocked_v6";
    const MAP_COUNTERS: &str = "counters";
    const COUNTER_PASS: u32 = 0;
    const COUNTER_DROP: u32 = 1;

    /// Owns the loaded aya `Ebpf` for the lifetime of the attachment. Dropping
    /// this detaches the XDP program from the interface.
    pub struct XdpKernel {
        // `Mutex` so that `&self` methods can mutate the maps (aya map handles
        // require `&mut MapData`).
        ebpf: Mutex<Ebpf>,
        iface: String,
    }

    impl XdpKernel {
        /// Load and attach the XDP program on `iface`.
        ///
        /// Returns `None` (never panics / propagates) on ANY error so the
        /// caller falls back to software mode. Tries native (driver) XDP first,
        /// then retries in generic/SKB mode which is required on veth / Docker.
        pub fn try_attach(iface: &str) -> Option<Self> {
            let mut ebpf = match Ebpf::load(xdp_program_bytes()) {
                Ok(e) => e,
                Err(e) => {
                    warn!(iface, error = %e, "kernel XDP: failed to load ELF");
                    return None;
                }
            };

            // Best-effort log relay; the program emits no logs, so ignore errors.
            let _ = aya_log::EbpfLogger::init(&mut ebpf);

            let program: &mut Xdp = match ebpf.program_mut(PROGRAM_NAME) {
                Some(p) => match p.try_into() {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(iface, error = %e, "kernel XDP: program is not an Xdp program");
                        return None;
                    }
                },
                None => {
                    warn!(
                        iface,
                        program = PROGRAM_NAME,
                        "kernel XDP: program not found in ELF"
                    );
                    return None;
                }
            };

            if let Err(e) = program.load() {
                warn!(iface, error = %e, "kernel XDP: program load() failed");
                return None;
            }

            // Native XDP first, then generic (SKB) mode for veth/Docker.
            match program.attach(iface, XdpFlags::default()) {
                Ok(_) => {
                    info!(iface, mode = "native", "kernel XDP attached");
                }
                Err(native_err) => {
                    debug_attach_fallback(iface, &native_err);
                    match program.attach(iface, XdpFlags::SKB_MODE) {
                        Ok(_) => {
                            info!(iface, mode = "skb", "kernel XDP attached (generic)");
                        }
                        Err(skb_err) => {
                            warn!(
                                iface,
                                native_error = %native_err,
                                skb_error = %skb_err,
                                "kernel XDP: attach failed in both native and SKB mode"
                            );
                            return None;
                        }
                    }
                }
            }

            Some(Self {
                ebpf: Mutex::new(ebpf),
                iface: iface.to_string(),
            })
        }

        /// Interface the program is attached to.
        #[allow(dead_code)]
        pub fn iface(&self) -> &str {
            &self.iface
        }

        /// Block a single address (host-length prefix: /32 v4, /128 v6).
        pub fn block_ip(&self, ip: IpAddr) -> Result<()> {
            match ip {
                IpAddr::V4(v4) => self.insert_v4(lpm_v4_key_data(v4), 32),
                IpAddr::V6(v6) => self.insert_v6(v6.octets(), 128),
            }
        }

        /// Block a CIDR network, inserting with its prefix length.
        pub fn block_net(&self, net: &IpNet) -> Result<()> {
            match net.addr {
                IpAddr::V4(v4) => self.insert_v4(lpm_v4_key_data(v4), net.prefix_len as u32),
                IpAddr::V6(v6) => self.insert_v6(v6.octets(), net.prefix_len as u32),
            }
        }

        /// Remove a single address (host-length prefix) from the trie.
        pub fn unblock_ip(&self, ip: IpAddr) -> Result<()> {
            let mut ebpf = self.lock()?;
            match ip {
                IpAddr::V4(v4) => {
                    let map = ebpf
                        .map_mut(MAP_V4)
                        .ok_or_else(|| EbpfError::MapError(format!("map {MAP_V4} not found")))?;
                    let mut trie: LpmTrie<_, u32, u32> =
                        LpmTrie::try_from(map).map_err(|e| EbpfError::MapError(e.to_string()))?;
                    let key = Key::new(32, lpm_v4_key_data(v4));
                    trie.remove(&key)
                        .map_err(|e| EbpfError::MapError(e.to_string()))
                }
                IpAddr::V6(v6) => {
                    let map = ebpf
                        .map_mut(MAP_V6)
                        .ok_or_else(|| EbpfError::MapError(format!("map {MAP_V6} not found")))?;
                    let mut trie: LpmTrie<_, [u8; 16], u32> =
                        LpmTrie::try_from(map).map_err(|e| EbpfError::MapError(e.to_string()))?;
                    let key = Key::new(128, v6.octets());
                    trie.remove(&key)
                        .map_err(|e| EbpfError::MapError(e.to_string()))
                }
            }
        }

        /// Read the per-CPU [pass, drop] counters, summed across all CPUs.
        /// Panic-free: returns `(0, 0)` if the map cannot be read.
        pub fn read_counters(&self) -> (u64, u64) {
            let ebpf = match self.lock() {
                Ok(g) => g,
                Err(e) => {
                    warn!(error = %e, "kernel XDP: cannot lock ebpf to read counters");
                    return (0, 0);
                }
            };
            let map = match ebpf.map(MAP_COUNTERS) {
                Some(m) => m,
                None => return (0, 0),
            };
            let array: PerCpuArray<_, u64> = match PerCpuArray::try_from(map) {
                Ok(a) => a,
                Err(e) => {
                    warn!(error = %e, "kernel XDP: counters map has unexpected type");
                    return (0, 0);
                }
            };
            let sum = |idx: u32| -> u64 {
                match array.get(&idx, 0) {
                    Ok(vals) => vals.iter().copied().sum(),
                    Err(_) => 0,
                }
            };
            (sum(COUNTER_PASS), sum(COUNTER_DROP))
        }

        // -- internals ------------------------------------------------------

        /// Poisoning is recovered rather than reported: every map update is a
        /// single syscall, so a panic elsewhere cannot leave the maps half
        /// written, and refusing the lock would freeze the kernel blocklist for
        /// the rest of the process.
        fn lock(&self) -> Result<std::sync::MutexGuard<'_, Ebpf>> {
            Ok(self
                .ebpf
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner))
        }

        fn insert_v4(&self, data: u32, prefix_len: u32) -> Result<()> {
            let mut ebpf = self.lock()?;
            let map = ebpf
                .map_mut(MAP_V4)
                .ok_or_else(|| EbpfError::MapError(format!("map {MAP_V4} not found")))?;
            let mut trie: LpmTrie<_, u32, u32> =
                LpmTrie::try_from(map).map_err(|e| EbpfError::MapError(e.to_string()))?;
            let key = Key::new(prefix_len, data);
            trie.insert(&key, 1u32, 0)
                .map_err(|e| EbpfError::MapError(e.to_string()))
        }

        fn insert_v6(&self, octets: [u8; 16], prefix_len: u32) -> Result<()> {
            let mut ebpf = self.lock()?;
            let map = ebpf
                .map_mut(MAP_V6)
                .ok_or_else(|| EbpfError::MapError(format!("map {MAP_V6} not found")))?;
            let mut trie: LpmTrie<_, [u8; 16], u32> =
                LpmTrie::try_from(map).map_err(|e| EbpfError::MapError(e.to_string()))?;
            let key = Key::new(prefix_len, octets);
            trie.insert(&key, 1u32, 0)
                .map_err(|e| EbpfError::MapError(e.to_string()))
        }
    }

    fn debug_attach_fallback(iface: &str, err: &aya::programs::ProgramError) {
        tracing::debug!(
            iface,
            error = %err,
            "kernel XDP: native attach failed, retrying in SKB (generic) mode"
        );
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
    /// Every lock site recovers a poisoned lock. Each critical section is one
    /// set or vec operation, so the list stays usable after a panic, and
    /// `is_blocked` runs on every connection: a lock that panicked once poisoned
    /// would turn one panic into a node that panics on every request.
    blocklist: Arc<RwLock<Blocklist>>,
    stats: Arc<AtomicStats>,
    running: Arc<AtomicBool>,
    mode: EbpfMode,
    /// Live XDP attachment when running in kernel mode. Kept alive for the
    /// lifetime of the manager (dropping it detaches the program). Wrapped in
    /// `Arc` so the background stats task can poll kernel counters.
    #[cfg(feature = "kernel")]
    kernel: Option<Arc<kernel_xdp::XdpKernel>>,
}

/// What the stats task reads and updates, apart from the manager, so
/// [`EbpfManager::start`] can move it into its task.
struct StatsTask {
    running: Arc<AtomicBool>,
    stats: Arc<AtomicStats>,
    blocklist: Arc<RwLock<Blocklist>>,
    mode: EbpfMode,
    #[cfg(feature = "kernel")]
    kernel: Option<Arc<kernel_xdp::XdpKernel>>,
}

impl StatsTask {
    fn refresh(&self) {
        // In kernel mode, refresh our counters from the live BPF per-CPU
        // array so stats()/ebpf_drops() reflect real kernel drops (packets
        // dropped in the NIC driver never touch userspace, so is_blocked()
        // cannot account for them).
        #[cfg(feature = "kernel")]
        if let Some(k) = self.kernel.as_ref() {
            let (pass, drop) = k.read_counters();
            self.stats.xdp_pass.store(pass, Ordering::Relaxed);
            self.stats.xdp_drop.store(drop, Ordering::Relaxed);
        }

        let snap = self.stats.snapshot();
        let bl_len = self
            .blocklist
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len();

        debug!(
            mode = %self.mode,
            xdp_pass  = snap.xdp_pass,
            xdp_drop  = snap.xdp_drop,
            xdp_abort = snap.xdp_aborted,
            blocklist_entries = bl_len,
            "eBPF stats"
        );
    }
}

impl EbpfManager {
    /// Create a new manager.  Does NOT start the background task; call
    /// [`start`][Self::start] afterwards.
    pub async fn new(cfg: EbpfConfig) -> Result<Self> {
        // Try to bring up the kernel XDP path; on any failure fall back to
        // software mode. The attached handle (if any) must be stored so the
        // program stays attached and its maps stay live.
        #[cfg(feature = "kernel")]
        let (mode, kernel) = if cfg.enable_kernel {
            match kernel_xdp::XdpKernel::try_attach(&cfg.interface) {
                Some(k) => {
                    // Seed the kernel maps from the configured blocklist so the
                    // XDP program drops these immediately.
                    for net in &cfg.blocklist {
                        if let Err(e) = k.block_net(net) {
                            debug!(%net, error = %e, "kernel XDP: failed to seed blocklist entry");
                        }
                    }
                    (EbpfMode::Kernel, Some(Arc::new(k)))
                }
                None => {
                    info!(
                        interface = %cfg.interface,
                        "XDP kernel attach unavailable — using software mode"
                    );
                    (EbpfMode::Software, None)
                }
            }
        } else {
            (EbpfMode::Software, None)
        };

        #[cfg(not(feature = "kernel"))]
        let mode = if cfg.enable_kernel {
            info!(
                "sentinel-ebpf: 'kernel' feature not enabled — using software mode \
                 (rebuild with --features kernel for XDP)"
            );
            EbpfMode::Software
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
            #[cfg(feature = "kernel")]
            kernel,
        })
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Start the background statistics / housekeeping task.
    ///
    /// In software mode this is a lightweight periodic log; in kernel mode
    /// (when fully implemented) it would also poll BPF map counters.
    ///
    /// The task is a bare `tokio::spawn`: a panic in it ends it, with the
    /// kernel counters frozen. A caller that supervises its background loops
    /// runs it itself instead ([`claim_stats_task`][Self::claim_stats_task]).
    pub async fn start(&self) -> Result<()> {
        if !self.claim_stats_task() {
            // Already running — idempotent
            return Ok(());
        }

        let stats = self.stats_task();
        let interval = self.stats_interval();
        let iface = self.config.interface.clone();
        let mode = self.mode;

        tokio::spawn(async move {
            info!(mode = %mode, interface = %iface, "eBPF background task started");
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the immediate first tick

            while stats.running.load(Ordering::Relaxed) {
                ticker.tick().await;
                stats.refresh();
            }

            info!("eBPF background task stopped");
        });

        Ok(())
    }

    /// Mark the stats task as running, for a caller that runs its loop itself
    /// (every [`stats_interval`][Self::stats_interval], call
    /// [`refresh_stats`][Self::refresh_stats] while
    /// [`stats_running`][Self::stats_running]) instead of [`start`][Self::start]'s
    /// bare spawn — the proxy, which restarts the loop after a panic. False
    /// when it is already running, and then the caller must not run another.
    pub fn claim_stats_task(&self) -> bool {
        !self.running.swap(true, Ordering::SeqCst)
    }

    /// Whether the stats task should keep running; [`shutdown`][Self::shutdown]
    /// clears it.
    pub fn stats_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// How often the stats task runs.
    pub fn stats_interval(&self) -> Duration {
        Duration::from_secs(self.config.stats_interval_secs.max(1))
    }

    fn stats_task(&self) -> StatsTask {
        StatsTask {
            running: Arc::clone(&self.running),
            stats: Arc::clone(&self.stats),
            blocklist: Arc::clone(&self.blocklist),
            mode: self.mode,
            #[cfg(feature = "kernel")]
            kernel: self.kernel.clone(),
        }
    }

    /// One pass of the stats task: in kernel mode, read the live BPF per-CPU
    /// counters into [`stats`][Self::stats] (packets dropped in the NIC driver
    /// never reach userspace, so nothing else can count them), then log a
    /// snapshot.
    pub fn refresh_stats(&self) {
        self.stats_task().refresh();
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
        let mut bl = self
            .blocklist
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        bl.add_ip(ip);
        self.stats.xdp_drop.fetch_add(0, Ordering::Relaxed); // no-op; update on match
        debug!(%ip, "blocked IP added");
        drop(bl);
        // Mirror into the kernel LPM trie so XDP drops it immediately.
        #[cfg(feature = "kernel")]
        if let Some(k) = &self.kernel {
            if let Err(e) = k.block_ip(ip) {
                debug!(%ip, error = %e, "kernel XDP: block_ip mirror failed");
            }
        }
    }

    /// Add a CIDR range to the blocklist.
    pub fn block_net(&self, net: IpNet) {
        let mut bl = self
            .blocklist
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        bl.ranges.push(net.clone());
        debug!(%net, "blocked CIDR range added");
        drop(bl);
        #[cfg(feature = "kernel")]
        if let Some(k) = &self.kernel {
            if let Err(e) = k.block_net(&net) {
                debug!(%net, error = %e, "kernel XDP: block_net mirror failed");
            }
        }
    }

    /// Remove a single IP from the blocklist.
    pub fn unblock_ip(&self, ip: IpAddr) {
        let mut bl = self
            .blocklist
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        bl.remove_ip(&ip);
        debug!(%ip, "unblocked IP removed");
        drop(bl);
        #[cfg(feature = "kernel")]
        if let Some(k) = &self.kernel {
            if let Err(e) = k.unblock_ip(ip) {
                debug!(%ip, error = %e, "kernel XDP: unblock_ip mirror failed");
            }
        }
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
    /// Everything currently in the blocklist: exact IPs (sorted) and CIDR ranges.
    /// For the console's Blocked Sources page; the set is small (bans are
    /// low-volume) so a copy under the read lock is fine.
    pub fn blocked_entries(&self) -> (Vec<IpAddr>, Vec<IpNet>) {
        let bl = self
            .blocklist
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let mut ips: Vec<IpAddr> = bl.exact.iter().copied().collect();
        ips.sort();
        (ips, bl.ranges.clone())
    }

    #[inline]
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let bl = self
            .blocklist
            .read()
            .unwrap_or_else(PoisonError::into_inner);
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ------------------------------------------------------------------
    // LPM-trie key byte order (must match the C program's network-order key)
    // ------------------------------------------------------------------

    #[test]
    fn lpm_v4_key_data_is_network_order_octets() {
        // The C side keys the trie on `ip->saddr` (network byte order), and
        // the trie matches MSB-first over the key's raw bytes. So the u32 we
        // hand aya MUST have in-memory bytes equal to the octets a.b.c.d.
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        assert_eq!(
            lpm_v4_key_data(ip).to_ne_bytes(),
            [1u8, 2, 3, 4],
            "key data bytes must equal the octets in network (MSB-first) order"
        );

        // Asymmetric high/low octets catch any accidental byte-swap.
        let ip2: Ipv4Addr = "255.0.0.1".parse().unwrap();
        assert_eq!(lpm_v4_key_data(ip2).to_ne_bytes(), [255u8, 0, 0, 1]);

        let ip3: Ipv4Addr = "10.20.30.40".parse().unwrap();
        assert_eq!(lpm_v4_key_data(ip3).to_ne_bytes(), ip3.octets());
    }

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

    /// A panic while the blocklist was locked used to make every later
    /// `is_blocked` panic too, and `is_blocked` runs on every connection — one
    /// panic became a node that could serve nothing. Now the list is recovered.
    #[tokio::test]
    async fn a_poisoned_blocklist_keeps_enforcing() {
        let mgr = EbpfManager::new(EbpfConfig::default()).await.unwrap();
        let before: IpAddr = "203.0.113.7".parse().unwrap();
        mgr.block_ip(before);

        let bl = Arc::clone(&mgr.blocklist);
        let _ = std::thread::spawn(move || {
            let _held = bl.write().unwrap();
            panic!("poisoning the blocklist on purpose");
        })
        .join();
        assert!(mgr.blocklist.is_poisoned(), "fixture must poison the lock");

        assert!(
            mgr.is_blocked(before),
            "entries from before the panic still apply"
        );
        let after: IpAddr = "203.0.113.8".parse().unwrap();
        mgr.block_ip(after);
        mgr.block_net(IpNet::new("198.51.100.0".parse().unwrap(), 24));
        assert!(mgr.is_blocked(after));
        assert!(mgr.is_blocked("198.51.100.9".parse().unwrap()));
        mgr.unblock_ip(after);
        assert!(!mgr.is_blocked(after));
        assert_eq!(mgr.blocked_entries().0, vec![before]);
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
