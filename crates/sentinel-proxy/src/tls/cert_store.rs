/// Hot-swappable certificate store with disk persistence.
///
/// Holds live TLS certs per domain (from ACME or manual upload), a self-signed
/// cert for each configured site that has neither, and one default cert for
/// every other name. The `SentinelCertResolver` wraps this and plugs straight
/// into rustls. It only looks certs up: everything that generates or writes one
/// runs at startup, on config sync, or in an admin call — never in a handshake,
/// where any client could pick the name.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use sentinel_core::config::{ConfigHandle, SentinelConfig, SiteConfig};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Cert metadata (persisted alongside PEM files)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertMeta {
    pub domain: String,
    /// Operator-assigned friendly name / profile label (empty = use domain).
    #[serde(default)]
    pub name: String,
    pub san: Vec<String>,
    /// UNIX timestamp of issuance.
    pub issued_at: u64,
    /// UNIX timestamp of expiry (0 = unknown).
    pub expires_at: u64,
    /// SHA-256 fingerprint of the leaf cert (hex, lower-case).
    pub fingerprint: String,
    pub source: CertSource,
    /// Issuer common name (filled by the validating uploader; empty = unknown).
    #[serde(default)]
    pub issuer: String,
    /// Key type label, e.g. "ECDSA P-256" / "RSA 2048" (empty = unknown).
    #[serde(default)]
    pub key_type: String,
}

/// Reserved cert key for the management-console certificate. Kept out of the
/// customer-facing cert repository listing so it can't be renamed/deleted there.
pub const MANAGEMENT_CERT_KEY: &str = "__management__";

/// Cert store keys beginning with this prefix are internal (e.g. the management
/// cert) and are hidden from the customer cert repository listing.
const RESERVED_PREFIX: &str = "__";

/// Key of the one certificate served for every name no site is configured for,
/// and to clients that send no SNI (bare-IP access). It is the name the no-SNI
/// path has always used, so a fleet upgrading keeps serving the certificate its
/// clients already accepted.
pub const DEFAULT_CERT_KEY: &str = "default";

/// How often the site cert sync looks for a changed site list. Until it has run
/// for a new site, that site is served the default certificate — self-signed
/// either way.
const SITE_SYNC_INTERVAL: Duration = Duration::from_secs(2);

impl CertMeta {
    pub fn days_until_expiry(&self) -> i64 {
        if self.expires_at == 0 {
            return i64::MAX;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ((self.expires_at as i64) - (now as i64)) / 86_400
    }

    pub fn needs_renewal(&self, renew_before_days: u32) -> bool {
        self.days_until_expiry() < renew_before_days as i64
    }

    pub fn is_expired(&self) -> bool {
        self.days_until_expiry() <= 0
    }

    pub fn status_label(&self) -> &'static str {
        let d = self.days_until_expiry();
        if d <= 0 {
            "expired"
        } else if d <= 14 {
            "critical"
        } else if d <= 30 {
            "expiring"
        } else {
            "valid"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertSource {
    SelfSigned,
    Acme { provider: String, email: String },
    Manual,
}

// ---------------------------------------------------------------------------
// CertStore — DashMap-based, hot-swappable
// ---------------------------------------------------------------------------

struct CertEntry {
    key: Arc<CertifiedKey>,
    meta: CertMeta,
    /// The SNI names this cert is served for: every DNS name in its leaf's
    /// subjectAltName (wildcards included) plus the key it is stored under,
    /// normalised like an SNI. Empty for reserved keys and site fallbacks,
    /// which are looked up by key only.
    names: Vec<String>,
}

pub struct CertStore {
    /// Operator certificates: ACME, manual uploads and the management cert,
    /// by store key. `get_meta` answers from here alone, so a self-signed cert
    /// can never look like an issued one to the ACME issuance and renewal
    /// checks. Changed only through `insert_live` / `remove_live`, which keep
    /// `by_name` in step.
    live: DashMap<String, Arc<CertEntry>>,
    /// SNI name → keys in `live` of the certs whose `names` hold it. A cert
    /// used to be found by its store key alone — the first name of an ACME
    /// order — so every other name it carried got the self-signed fallback.
    by_name: DashMap<String, Vec<String>>,
    /// Serialises `live` + `by_name` updates so two installs cannot interleave
    /// their index edits. Handshakes never take it.
    index_write: Mutex<()>,
    /// TLS-ALPN-01 challenge certs: domain → special cert served during challenge.
    alpn_challenge: DashMap<String, Arc<CertifiedKey>>,
    /// Self-signed certs for configured site names that have no live cert.
    /// Bounded by the configuration: rebuilt on every sync, never grown by a
    /// handshake.
    fallback: RwLock<SiteFallbacks>,
    /// Served for every name that is not a configured site, and when the client
    /// sends no SNI. Set once at startup by `ensure_default_cert`.
    default_cert: ArcSwapOption<CertifiedKey>,
    /// Set by the first `start_site_cert_sync`, so a node runs one sync task
    /// however many SNI listeners it has.
    site_sync_started: AtomicBool,
    cert_dir: PathBuf,
}

/// The configured names and their self-signed certs, under ONE lock so that a
/// cert minted for a site removed meanwhile is never inserted after the sync
/// that dropped it.
#[derive(Default)]
struct SiteFallbacks {
    /// Lower-cased site names; rustls lower-cases the SNI it hands the resolver.
    configured: HashSet<String>,
    certs: HashMap<String, Arc<CertEntry>>,
}

/// The names a configured site can be reached by over SNI, normalised the way
/// rustls normalises the SNI it hands the resolver.
pub fn site_cert_names(sites: &[SiteConfig]) -> HashSet<String> {
    sites
        .iter()
        .flat_map(|s| s.domains.iter())
        .filter_map(|d| {
            let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
            sni_matchable(&d).then_some(d)
        })
        .collect()
}

/// Whether a handshake could ever ask for `name` (or, for `*.x`, a name one
/// label below it). rustls hands the resolver only a valid DNS name: never an IP
/// literal (RFC 6066), and never a byte outside ASCII letters, digits, `-` and
/// `_` — an IDN arrives as its `xn--` A-label. A cert for any other name could
/// never be served, and minting one is worse than useless: rcgen asserts that
/// SAN names are ASCII, so `bücher.example` panicked the sync, and with the
/// release profile's `panic = "abort"` of the time, the node. Reserved keys are
/// internal.
fn sni_matchable(name: &str) -> bool {
    let host = name.strip_prefix("*.").unwrap_or(name);
    !name.starts_with(RESERVED_PREFIX) && DnsName::try_from(host).is_ok()
}

/// Start the background sync that keeps the per-site self-signed certs in step
/// with the configured sites; once per store, however often it is called.
///
/// Each listener that serves certs through the SNI resolver calls this. A node
/// with none (HTTP only, TLS offloaded, explicit cert/key) never serves those
/// certs, so it mints none: no private keys on its volume, and no self-signed
/// rows in its cert listing for certificates nobody is shown.
pub fn start_site_cert_sync(store: &Arc<CertStore>, config: ConfigHandle) {
    if !store.site_sync_started.swap(true, Ordering::AcqRel) {
        spawn_site_cert_sync_every(Arc::clone(store), config, SITE_SYNC_INTERVAL);
    }
}

/// Watches the config handle, so a site arriving by any route (control-plane
/// sync, file reload, cached-config restore) gets its cert, and a removed site
/// drops out of the fallback map. The minting runs on a blocking thread.
///
/// Supervised like the data plane's other background loops: a panic restarts
/// the sync, whose first round then syncs every name again, instead of ending
/// it and leaving every site configured afterwards on the default cert.
fn spawn_site_cert_sync_every(
    store: Arc<CertStore>,
    config: ConfigHandle,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    crate::panic_guard::supervised!("site certificate sync", {
        per_run!(store, config);
        let mut sync = SiteSync::default();
        loop {
            #[cfg(test)]
            inject_site_sync_panic(&config.load());
            if let Some(names) = sync.due(config.load_full()) {
                let report = store.sync_site_fallbacks(names.clone()).await;
                for name in sync.record(names, report.failed) {
                    tracing::warn!(
                        domain = %name,
                        "could not create a self-signed certificate for this site; \
                         serving the default one and retrying"
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// A site name that panics the site cert sync once per process, in test builds
/// only.
#[cfg(test)]
const INJECT_SITE_SYNC_PANIC_NAME: &str = "panic-guard-site-sync.example";

#[cfg(test)]
static SITE_SYNC_PANICKED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn inject_site_sync_panic(cfg: &SentinelConfig) {
    let named = cfg
        .sites
        .iter()
        .any(|s| s.domains.iter().any(|d| d == INJECT_SITE_SYNC_PANIC_NAME));
    if named && !SITE_SYNC_PANICKED.swap(true, Ordering::SeqCst) {
        panic!("injected site certificate sync panic");
    }
}

/// A site name whose self-signed cert panics the mint, every time, in test
/// builds only.
#[cfg(test)]
const INJECT_MINT_PANIC_NAME: &str = "panic-guard-mint.example";

/// How many times the injected mint panic fired.
#[cfg(test)]
static MINT_PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn inject_mint_panic(names: &[String]) {
    if names.iter().any(|n| n == INJECT_MINT_PANIC_NAME) {
        MINT_PANICS.fetch_add(1, Ordering::SeqCst);
        panic!("injected site certificate mint panic");
    }
}

/// When the site cert sync has to run, and which failures it has reported.
#[derive(Default)]
struct SiteSync {
    /// The config last examined. Held, not its address: a freed address can be
    /// reused by the next config and the change would be missed.
    seen: Option<Arc<SentinelConfig>>,
    /// The site names of the last sync.
    synced: Option<HashSet<String>>,
    /// Names whose cert could not be minted at the last sync. While any remain
    /// every tick retries them — otherwise they would wait for the next change
    /// to the site list — but each is reported once.
    failing: HashSet<String>,
}

impl SiteSync {
    /// The site names to sync now: the site list changed, or a mint is owed.
    fn due(&mut self, cfg: Arc<SentinelConfig>) -> Option<HashSet<String>> {
        let changed = !self.seen.as_ref().is_some_and(|s| Arc::ptr_eq(s, &cfg));
        if !changed && self.failing.is_empty() {
            return None;
        }
        let names = site_cert_names(&cfg.sites);
        self.seen = Some(cfg);
        (self.synced.as_ref() != Some(&names) || !self.failing.is_empty()).then_some(names)
    }

    /// Record a sync of `names`; returns the failures not reported before.
    fn record(&mut self, names: HashSet<String>, failed: Vec<String>) -> Vec<String> {
        let new = failed
            .iter()
            .filter(|n| !self.failing.contains(*n))
            .cloned()
            .collect();
        self.failing = failed.into_iter().collect();
        self.synced = Some(names);
        new
    }
}

/// What one round of minting site certs did.
#[derive(Debug, Default)]
pub struct MintReport {
    pub added: usize,
    /// Names whose cert could not be created; they stay on the default cert.
    pub failed: Vec<String>,
}

/// Whether a cert served for `cert_name` is served for the SNI `site`: the
/// same name, or a wildcard one label above it — the match `resolve_live` makes.
pub(crate) fn cert_covers(cert_name: &str, site: &str) -> bool {
    cert_name == site
        || cert_name
            .strip_prefix("*.")
            .is_some_and(|base| site.split_once('.').is_some_and(|(_, rest)| rest == base))
}

/// Whether a cert stored under `name` would be served for a configured site.
fn serves_configured_name(name: &str, site_names: &HashSet<String>) -> bool {
    site_names.iter().any(|site| cert_covers(name, site))
}

/// How `serving_entry` orders the certs that carry one name: valid, the name
/// itself (not via a wildcard), stored under it, expiry, then the lowest key.
type ServeRank = (bool, bool, bool, u64, std::cmp::Reverse<String>);

/// A name as rustls hands it to the resolver: no surrounding space, no
/// trailing dot, lower case.
pub(crate) fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The DNS names in the leaf's subjectAltName, wildcards included, normalised.
/// IP-address entries are not names: rustls never hands the resolver one.
pub(crate) fn leaf_dns_names(leaf: &CertificateDer<'_>) -> Result<Vec<String>> {
    let cert = webpki::EndEntityCert::try_from(leaf)
        .map_err(|e| anyhow::anyhow!("the certificate could not be parsed: {e}"))?;
    let mut names: Vec<String> = Vec::new();
    for name in cert.valid_dns_names().map(normalize_name) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

/// Whether a certificate carrying `names` is valid for `host`, as a client
/// checks it: the name itself, or a wildcard one label above it.
pub(crate) fn names_cover(names: &[String], host: &str) -> bool {
    let host = normalize_name(host);
    names.iter().any(|n| cert_covers(n, &host))
}

/// A live entry for `ck` stored under `key`, served for every DNS name in its
/// leaf and for `key` itself — the name it has always been found by, and the
/// only one for a leaf that names none (the bare-IP `default` cert) or cannot
/// be parsed. Reserved keys are internal: found by key, never by SNI.
fn live_entry(key: &str, ck: Arc<CertifiedKey>, meta: CertMeta) -> Arc<CertEntry> {
    let names = if key.starts_with(RESERVED_PREFIX) {
        Vec::new()
    } else {
        let mut names = ck
            .end_entity_cert()
            .ok()
            .and_then(|leaf| leaf_dns_names(leaf).ok())
            .unwrap_or_default();
        let own = normalize_name(key);
        if !own.is_empty() && !names.contains(&own) {
            names.push(own);
        }
        names
    };
    Arc::new(CertEntry {
        key: ck,
        meta,
        names,
    })
}

/// Fill what the metadata lacks from the leaf: names its subjectAltName
/// carries that `san` does not list (an upload's meta used to hold only the
/// name it was uploaded for), and an unknown expiry.
fn complete_meta(meta: &mut CertMeta, ck: &CertifiedKey) {
    let Ok(leaf) = ck.end_entity_cert() else {
        return;
    };
    for name in leaf_dns_names(leaf).unwrap_or_default() {
        if !meta.san.iter().any(|s| s.eq_ignore_ascii_case(&name)) {
            meta.san.push(name);
        }
    }
    if meta.expires_at == 0 {
        meta.expires_at = super::acme::der_not_after(leaf.as_ref()).unwrap_or(0);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Outcome of loading one directory of the cert volume.
enum DirLoad {
    Loaded,
    /// A self-signed cert for a name no site is configured for, left in place.
    Skipped,
    /// No cert in it, or the default cert, which `ensure_default_cert` adopts.
    Nothing,
}

impl CertStore {
    pub fn new(cert_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            live: DashMap::new(),
            by_name: DashMap::new(),
            index_write: Mutex::new(()),
            alpn_challenge: DashMap::new(),
            fallback: RwLock::new(SiteFallbacks::default()),
            default_cert: ArcSwapOption::empty(),
            site_sync_started: AtomicBool::new(false),
            cert_dir,
        })
    }

    // A panic elsewhere must not take TLS down with it: the guarded data is a
    // plain map that is never left half-updated, so a poisoned lock is usable.
    fn fallback_read(&self) -> RwLockReadGuard<'_, SiteFallbacks> {
        self.fallback.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn fallback_write(&self) -> RwLockWriteGuard<'_, SiteFallbacks> {
        self.fallback
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    // ── live certs and the names they are served for ────────────────────────

    /// Put `entry` in `live` under `key`, replacing what was there, and point
    /// each of its names at it. A name only the replaced cert carried stops
    /// resolving to this key.
    fn insert_live(&self, key: String, entry: Arc<CertEntry>) {
        let _w = self
            .index_write
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let old = self.live.insert(key.clone(), Arc::clone(&entry));
        for name in old.iter().flat_map(|o| o.names.iter()) {
            if !entry.names.contains(name) {
                self.unindex(name, &key);
            }
        }
        for name in &entry.names {
            let mut keys = self.by_name.entry(name.clone()).or_default();
            if !keys.contains(&key) {
                keys.push(key.clone());
            }
        }
    }

    /// Take `key` out of `live`, and every name it was served for with it.
    fn remove_live(&self, key: &str) -> Option<Arc<CertEntry>> {
        let _w = self
            .index_write
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (_, old) = self.live.remove(key)?;
        for name in &old.names {
            self.unindex(name, key);
        }
        Some(old)
    }

    fn unindex(&self, name: &str, key: &str) {
        if let Some(mut keys) = self.by_name.get_mut(name) {
            keys.retain(|k| k != key);
        }
        self.by_name.remove_if(name, |_, keys| keys.is_empty());
    }

    /// The live cert a handshake for `sni` is served, if any: one whose names
    /// hold `sni` itself, else its wildcard one label up.
    ///
    /// Several certs can carry one name (an ACME cert for `example.com` +
    /// `www.example.com`, and an upload for `www.example.com` alone). The pick
    /// is the same on every node and every restart: an unexpired cert over an
    /// expired one, the name itself over a wildcard, the cert stored under that
    /// very name over one that merely lists it, then the later expiry, then
    /// the lowest key.
    fn serving_entry(&self, sni: &str) -> Option<Arc<CertEntry>> {
        let sni = normalize_name(sni);
        let wildcard = sni.split_once('.').map(|(_, rest)| format!("*.{rest}"));
        let now = unix_now();
        let mut best: Option<(ServeRank, Arc<CertEntry>)> = None;
        let lookups =
            std::iter::once((sni.as_str(), true)).chain(wildcard.as_deref().map(|w| (w, false)));
        for (name, literal) in lookups {
            // Cloned so no index guard is held while `live` is read.
            let Some(keys) = self.by_name.get(name).map(|k| k.clone()) else {
                continue;
            };
            for key in keys {
                let Some(entry) = self.live.get(&key).map(|e| Arc::clone(e.value())) else {
                    continue;
                };
                // The index can trail a concurrent install by an instant; only
                // the entry's own names are trusted.
                if !entry.names.iter().any(|n| n == name) {
                    continue;
                }
                let expires = entry.meta.expires_at;
                let rank = (
                    expires == 0 || expires > now,
                    literal,
                    key.eq_ignore_ascii_case(name),
                    expires,
                    std::cmp::Reverse(key),
                );
                if best.as_ref().is_none_or(|(b, _)| rank > *b) {
                    best = Some((rank, entry));
                }
            }
        }
        best.map(|(_, e)| e)
    }

    /// Load all persisted certs from `cert_dir/{domain}/` on startup.
    ///
    /// `site_names` are the configured site names (see `site_cert_names`). A
    /// self-signed cert for one of them becomes that site's fallback; one for any
    /// other name is skipped and counted, never deleted — also when its
    /// meta.json is missing. Those directories are what the old resolver minted
    /// for whatever SNI a client sent, and loading them would rebuild the
    /// unbounded map at every boot. A directory that cannot be read is counted
    /// as failed and the rest still load.
    pub fn load_from_disk(&self, site_names: &HashSet<String>) -> Result<usize> {
        // Recorded first, so a load that fails part-way still leaves the sync
        // task knowing which names to mint.
        {
            let mut fb = self.fallback_write();
            fb.configured = site_names.clone();
            fb.certs.retain(|name, _| site_names.contains(name));
        }
        std::fs::create_dir_all(&self.cert_dir)
            .with_context(|| format!("creating cert dir: {}", self.cert_dir.display()))?;

        // One bad directory costs only itself. The old resolver wrote meta.json
        // best-effort for every probed name, so a crash or a full disk mid-flood
        // leaves truncated files; aborting on the first would leave every
        // operator cert after it in readdir order unloaded.
        let (mut count, mut skipped, mut failed) = (0usize, 0usize, 0usize);
        for entry in std::fs::read_dir(&self.cert_dir)
            .with_context(|| format!("reading cert dir: {}", self.cert_dir.display()))?
        {
            let dir = match entry.and_then(|e| Ok((e.path(), e.file_type()?.is_dir()))) {
                Ok((dir, true)) => dir,
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!("unreadable entry in the cert dir: {e}");
                    failed += 1;
                    continue;
                }
            };
            match self.load_cert_dir(&dir, site_names) {
                Ok(DirLoad::Loaded) => count += 1,
                Ok(DirLoad::Skipped) => skipped += 1,
                Ok(DirLoad::Nothing) => {}
                Err(e) => {
                    tracing::warn!(?dir, "failed to load cert: {e:#}");
                    failed += 1;
                }
            }
        }
        if skipped > 0 {
            tracing::info!(
                skipped,
                "left self-signed certificates for names no site is configured for \
                 on disk, unloaded"
            );
        }
        if failed > 0 {
            tracing::warn!(
                failed,
                "cert directories that could not be loaded were skipped; the rest loaded"
            );
        }
        Ok(count)
    }

    /// Load the cert in one directory of the volume (see `load_from_disk`).
    fn load_cert_dir(&self, dir: &Path, site_names: &HashSet<String>) -> Result<DirLoad> {
        let cert_file = dir.join("cert.pem");
        let key_file = dir.join("key.pem");
        if !cert_file.exists() || !key_file.exists() {
            return Ok(DirLoad::Nothing);
        }
        let cert_pem = std::fs::read(&cert_file).context("reading cert.pem")?;

        let meta_file = dir.join("meta.json");
        let meta: CertMeta = if meta_file.exists() {
            let raw = std::fs::read_to_string(&meta_file).context("reading meta.json")?;
            serde_json::from_str(&raw).context("parsing meta.json")?
        } else {
            let domain = dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .replace("_wildcard_", "*");
            let name = domain.to_ascii_lowercase();
            if name == DEFAULT_CERT_KEY {
                return Ok(DirLoad::Nothing);
            }
            // No metadata: an operator's hand-placed PEM pair, or what the old
            // resolver left when its meta.json write failed. A cert for a
            // configured site, an internal key, or one someone else issued is
            // the operator's; a self-issued cert for any other name is a
            // leftover and must not reach `live` as "Manual" past the skip.
            let operator_cert = name.starts_with(RESERVED_PREFIX)
                || serves_configured_name(&name, site_names)
                || !pem_is_self_issued(&cert_pem);
            if !operator_cert {
                return Ok(DirLoad::Skipped);
            }
            CertMeta {
                domain: domain.clone(),
                name: String::new(),
                san: vec![domain],
                issued_at: 0,
                expires_at: 0,
                fingerprint: String::new(),
                source: CertSource::Manual,
                issuer: String::new(),
                key_type: String::new(),
            }
        };

        // A site's self-signed cert goes to the fallback map; operator certs
        // and reserved keys (the management cert, even self-signed) to `live`.
        let fallback_name = (meta.source == CertSource::SelfSigned
            && !meta.domain.starts_with(RESERVED_PREFIX))
        .then(|| meta.domain.to_ascii_lowercase());
        if let Some(name) = &fallback_name {
            // Adopted by `ensure_default_cert`, and not a site's cert.
            if name == DEFAULT_CERT_KEY {
                return Ok(DirLoad::Nothing);
            }
            if !site_names.contains(name) {
                return Ok(DirLoad::Skipped);
            }
        }

        let key_pem = std::fs::read(&key_file).context("reading key.pem")?;
        let ck = load_pem_bytes(&cert_pem, &key_pem)?;
        match fallback_name {
            Some(name) => {
                let entry = Arc::new(CertEntry {
                    key: ck,
                    meta,
                    names: Vec::new(),
                });
                self.fallback_write().certs.insert(name, entry);
            }
            None => {
                // Served for every name its leaf carries, whatever the meta
                // written when it was installed says.
                let mut meta = meta;
                complete_meta(&mut meta, &ck);
                let key = meta.domain.clone();
                self.insert_live(key.clone(), live_entry(&key, ck, meta));
            }
        }
        Ok(DirLoad::Loaded)
    }

    /// The certificate served for every name no site is configured for, and to
    /// clients that send no SNI. One for the whole fleet, persisted like the
    /// others so every node and every restart serve the same bytes. Created at
    /// startup (resolver construction), so no handshake ever has to.
    pub fn ensure_default_cert(&self) -> Option<Arc<CertifiedKey>> {
        if let Some(ck) = self.default_cert.load_full() {
            return Some(ck);
        }
        let ck = self.adopt_or_create_self_signed(DEFAULT_CERT_KEY)?;
        self.default_cert.store(Some(Arc::clone(&ck)));
        Some(ck)
    }

    /// Point the fallback map at the configured `names`: certs for names no
    /// longer configured are dropped, and the names still lacking any cert are
    /// returned for `ensure_site_fallbacks`. Cheap — no keygen, no disk.
    ///
    /// "Any cert" is what a handshake would find: a live wildcard covering a
    /// site counts, so no key is minted for a site the wildcard serves.
    pub fn set_site_names(&self, names: HashSet<String>) -> Vec<String> {
        let mut fb = self.fallback_write();
        fb.certs.retain(|name, _| names.contains(name));
        fb.configured = names;
        fb.configured
            .iter()
            .filter(|n| !fb.certs.contains_key(*n) && self.resolve_live(n).is_none())
            .cloned()
            .collect()
    }

    /// Adopt or create the shared self-signed cert for each of `names` that is
    /// still configured and still has no cert. Blocking (keygen and disk), so the
    /// sync task runs it on a blocking thread.
    pub fn ensure_site_fallbacks(&self, names: &[String]) -> MintReport {
        let mut report = MintReport::default();
        for name in names {
            // The site may have been removed, or given a real cert, mid-batch.
            if !self.needs_site_fallback(name) {
                continue;
            }
            let Some(ck) = self.adopt_or_create_self_signed(name) else {
                report.failed.push(name.clone());
                continue;
            };
            let entry = Arc::new(CertEntry {
                key: ck,
                meta: self_signed_meta(name),
                names: Vec::new(),
            });
            let mut fb = self.fallback_write();
            // Checked again under the lock: an entry for a name a concurrent sync
            // just dropped is exactly the growth this map exists to prevent.
            if fb.configured.contains(name) && self.resolve_live(name).is_none() {
                fb.certs.insert(name.clone(), entry);
                report.added += 1;
            }
        }
        report
    }

    /// `set_site_names`, then mint what is missing on a blocking thread.
    ///
    /// A panic while minting is raised again here, in the caller (the site
    /// cert sync, which is supervised). It used to come back as a JoinError
    /// taken for "all failed": one WARN, and since a failure is retried every
    /// `SITE_SYNC_INTERVAL`, a mint that panics every time logged a fresh
    /// panic (and backtrace) every 2 s for ever, never backing off and never
    /// recorded as a restart.
    pub async fn sync_site_fallbacks(self: &Arc<Self>, names: HashSet<String>) -> MintReport {
        let missing = self.set_site_names(names);
        if missing.is_empty() {
            return MintReport::default();
        }
        let store = Arc::clone(self);
        let batch = missing.clone();
        let minted = tokio::task::spawn_blocking(move || {
            crate::panic_guard::catch_for_elsewhere(|| {
                #[cfg(test)]
                inject_mint_panic(&batch);
                store.ensure_site_fallbacks(&batch)
            })
        })
        .await;
        match minted {
            Ok(Ok(report)) => {
                if report.added > 0 {
                    tracing::info!(
                        certs = report.added,
                        "self-signed certificates ready for new sites"
                    );
                }
                report
            }
            Ok(Err(panicked)) => panicked.resume(),
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => {
                tracing::warn!("minting self-signed site certificates failed: {e}");
                MintReport {
                    added: 0,
                    failed: missing,
                }
            }
        }
    }

    fn needs_site_fallback(&self, name: &str) -> bool {
        let fb = self.fallback_read();
        fb.configured.contains(name)
            && !fb.certs.contains_key(name)
            && self.resolve_live(name).is_none()
    }

    /// Return the shared self-signed cert for `domain`, creating it once if no
    /// node has yet, and record it in `live`.
    ///
    /// This is how a reserved key (the management listener's cert) gets its
    /// self-signed default. Site names go through `ensure_site_fallbacks`
    /// instead, into the bounded fallback map that ACME decisions do not see.
    pub fn self_signed_shared(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // Someone — possibly this process, at boot — already has it.
        if let Some(e) = self.live.get(domain) {
            return Some(Arc::clone(&e.key));
        }
        let ck = self.adopt_or_create_self_signed(domain)?;
        self.remember_self_signed(domain, Arc::clone(&ck));
        Some(ck)
    }

    /// The fleet's shared self-signed cert for `domain`: adopted from the cert
    /// volume, or created there if no node has yet. Touches no in-memory map.
    ///
    /// The point is convergence across a fleet. `cert_dir` is a volume shared by
    /// every node, so the FIRST node to need a name writes the cert and the
    /// others adopt it. Without this each node generated its own in memory and a
    /// client got a different certificate per request — harmless-looking on a
    /// single node, and a fresh browser warning on every other request once
    /// HAProxy started spreading :443 across three.
    ///
    /// Create-if-absent, never overwrite. Overwriting would mean every restart
    /// replaced the cert and the fleet would flap between them — the same bug in
    /// slow motion. `create_new` makes the claim atomic at the filesystem level,
    /// so a race has exactly one winner and the losers adopt the winner's cert
    /// rather than keeping their own.
    ///
    /// Returns `None` only if the name cannot be served at all; a store that
    /// cannot be written (read-only volume, no permissions) still yields a
    /// working in-memory cert, because refusing TLS would be worse than an
    /// inconsistent cert.
    fn adopt_or_create_self_signed(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let dir = self.cert_dir.join(domain_to_dirname(domain));
        let cert_file = dir.join("cert.pem");
        let key_file = dir.join("key.pem");

        // Another node may have written it since this process started.
        if cert_file.exists() && key_file.exists() {
            if let Ok(ck) = load_pem_files(&cert_file, &key_file) {
                tracing::debug!(domain, "adopted the fleet's shared self-signed cert");
                return Some(ck);
            }
        }

        let (cert_pem, key_pem) = generate_self_signed_pem(domain).ok()?;

        // Try to claim the name. Losing the race is the normal case on a busy
        // fleet and is not an error.
        match self.claim_self_signed(&dir, &cert_file, &key_file, domain, &cert_pem, &key_pem) {
            Ok(()) => tracing::info!(domain, "generated the fleet's shared self-signed cert"),
            Err(e) => tracing::debug!(domain, "did not claim the self-signed cert: {e}"),
        }

        // Re-read regardless of who won, so every node ends up serving the same
        // bytes. Only fall back to our own copy if the store is unusable.
        load_pem_files(&cert_file, &key_file)
            .or_else(|_| load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes()))
            .ok()
    }

    /// Write the cert files only if absent, atomically claiming the name.
    fn claim_self_signed(
        &self,
        dir: &Path,
        cert_file: &Path,
        key_file: &Path,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        // create_new is the whole mechanism: it fails if the file exists, so the
        // first writer wins and nobody clobbers a cert already in use.
        write_new(key_file, key_pem.as_bytes(), 0o600)?;
        write_new(cert_file, cert_pem.as_bytes(), 0o644)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let meta = CertMeta {
            domain: domain.to_string(),
            name: String::new(),
            san: vec![domain.to_string(), format!("*.{domain}")],
            issued_at: now,
            expires_at: 0,
            fingerprint: String::new(),
            source: CertSource::SelfSigned,
            issuer: String::new(),
            key_type: String::new(),
        };
        // Best-effort: the cert is usable without metadata, and the loader
        // synthesises a default when meta.json is missing.
        let _ = write_new(
            &dir.join("meta.json"),
            serde_json::to_string_pretty(&meta)?.as_bytes(),
            0o644,
        );
        Ok(())
    }

    fn remember_self_signed(&self, domain: &str, ck: Arc<CertifiedKey>) {
        let meta = self_signed_meta(domain);
        self.insert_live(domain.to_string(), live_entry(domain, ck, meta));
    }

    /// Install a cert from PEM strings (from ACME or manual upload), stored
    /// under `domain` and served for every DNS name its leaf carries.
    /// Hot-swaps immediately — no restart required. A cert it replaces stops
    /// being served for the names only that cert carried.
    pub fn install(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        mut meta: CertMeta,
    ) -> Result<()> {
        // Loaded before anything is written: a PEM pair that does not load
        // must not replace the files of the cert being served.
        let ck = load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
            .context("loading installed cert into rustls")?;
        complete_meta(&mut meta, &ck);

        let dir = self.cert_dir.join(domain_to_dirname(domain));
        std::fs::create_dir_all(&dir)?;
        // The directory (and thus the private key it holds) must not be
        // world-readable. Lock it to 0700, then write every file atomically at
        // 0600 — same hardening the management-cert path already uses. A bare
        // `std::fs::write` here previously left customer private keys at the
        // process umask (typically 0644, world-readable).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        write_atomic(&dir.join("cert.pem"), cert_pem.as_bytes())?;
        write_atomic(&dir.join("key.pem"), key_pem.as_bytes())?;
        write_atomic(
            &dir.join("meta.json"),
            serde_json::to_string_pretty(&meta)?.as_bytes(),
        )?;

        let entry = live_entry(domain, ck, meta);
        let names = entry.names.clone();
        self.insert_live(domain.to_string(), entry);
        // The self-signed cert this replaces would only be listed beside it; its
        // files were just overwritten anyway.
        self.fallback_write().certs.remove(&normalize_name(domain));
        tracing::info!(domain, ?names, "TLS cert installed and hot-swapped");
        Ok(())
    }

    pub fn remove(&self, domain: &str) -> Result<()> {
        let removed = self.remove_live(domain);
        let dir = self.cert_dir.join(domain_to_dirname(domain));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        // A site's self-signed cert lived in that directory too. The configured
        // sites this cert answered for — any name it carried, or every name one
        // of its wildcards covered — get a self-signed one now, in this admin
        // call, rather than the default cert until the next config change. One
        // another live cert still serves keeps that cert.
        let own = normalize_name(domain);
        self.fallback_write().certs.remove(&own);
        let served = removed.map_or_else(|| vec![own], |e| e.names.clone());
        let uncovered: Vec<String> = self
            .fallback_read()
            .configured
            .iter()
            .filter(|site| served.iter().any(|n| cert_covers(n, site)))
            .cloned()
            .collect();
        for failed in self.ensure_site_fallbacks(&uncovered).failed {
            tracing::warn!(
                domain = %failed,
                "could not create a self-signed certificate; serving the default one"
            );
        }
        Ok(())
    }

    /// Set the operator-assigned friendly name (profile label) for a cert.
    /// Updates the persisted meta.json and hot-swaps the live entry's metadata
    /// (reloads the existing PEM so the served key is unchanged).
    pub fn set_name(&self, domain: &str, name: &str) -> Result<()> {
        let dir = self.cert_dir.join(domain_to_dirname(domain));
        let meta_file = dir.join("meta.json");
        let mut meta: CertMeta = serde_json::from_str(
            &std::fs::read_to_string(&meta_file)
                .with_context(|| format!("no metadata for cert '{domain}'"))?,
        )?;
        meta.name = name.to_string();
        std::fs::write(&meta_file, serde_json::to_string_pretty(&meta)?)?;

        let cert_pem = std::fs::read_to_string(dir.join("cert.pem"))?;
        let key_pem = std::fs::read_to_string(dir.join("key.pem"))?;
        let ck = load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
            .context("reloading cert after rename")?;
        // Renaming a site's self-signed cert must not promote it into `live`,
        // where `get_meta` would report it as issued and hold off ACME.
        if meta.source == CertSource::SelfSigned && !domain.starts_with(RESERVED_PREFIX) {
            let name = normalize_name(domain);
            let mut fb = self.fallback_write();
            if fb.configured.contains(&name) {
                let names = Vec::new();
                fb.certs.insert(
                    name,
                    Arc::new(CertEntry {
                        key: ck,
                        meta,
                        names,
                    }),
                );
            }
        } else {
            complete_meta(&mut meta, &ck);
            self.insert_live(domain.to_string(), live_entry(domain, ck, meta));
        }
        Ok(())
    }

    /// All cert metadata for the customer cert repository (the dashboard API).
    /// Internal/reserved certs (e.g. the management cert) are hidden so they
    /// can't be listed, renamed, or deleted from the customer cert page.
    /// Configured sites still on their self-signed cert are listed too — only
    /// while a handshake would serve it, not under a live cert or wildcard.
    pub fn all_meta(&self) -> Vec<CertMeta> {
        let mut all: Vec<CertMeta> = self
            .live
            .iter()
            .filter(|e| !e.key().starts_with(RESERVED_PREFIX))
            .map(|e| e.value().meta.clone())
            .collect();
        let fb = self.fallback_read();
        all.extend(
            fb.certs
                .iter()
                .filter(|(name, _)| self.resolve_live(name).is_none())
                .map(|(_, e)| e.meta.clone()),
        );
        all
    }

    /// Metadata of the operator cert a handshake for `domain` is served — the
    /// pick `serving_entry` makes among every cert whose leaf carries the name
    /// or a wildcard over it — or, for a reserved key, the cert stored under
    /// it. Self-signed fallbacks are deliberately not reported — ACME issuance
    /// and renewal read this, and a self-signed cert (which never expires by
    /// its metadata) would hold them off for ever.
    pub fn get_meta(&self, domain: &str) -> Option<CertMeta> {
        if domain.starts_with(RESERVED_PREFIX) {
            return self.live.get(domain).map(|e| e.value().meta.clone());
        }
        if let Some(e) = self.serving_entry(domain) {
            return Some(e.meta.clone());
        }
        // The names recorded at issuance count too: the renewal loop asks
        // whether an issued cert covers a site, and must not re-order one every
        // hour because the serving index was built from the leaf alone.
        let want = normalize_name(domain);
        self.live
            .iter()
            .find(|e| e.value().meta.san.iter().any(|s| normalize_name(s) == want))
            .map(|e| e.value().meta.clone())
    }

    /// Install (or replace) the management-console certificate, hot-swapped with
    /// zero downtime. Unlike `install`, this writes the PEM files **atomically**
    /// (temp file + rename) and only swaps the live key after the new PEM has
    /// successfully parsed — so a bad upload can never leave a half-written or
    /// mismatched cert on disk or in memory. Returns the previous fingerprint
    /// (if any) so the caller can record an audit old→new transition.
    pub fn install_management(
        &self,
        cert_pem: &str,
        key_pem: &str,
        meta: CertMeta,
    ) -> Result<Option<String>> {
        // 1. Parse + build the signing key FIRST, and verify the private key
        //    actually matches the leaf cert (defense-in-depth: the control plane
        //    validates this too, but a direct internal-API call must not be able
        //    to install a mismatched pair). Bail before touching disk/live store.
        let ck = load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
            .context("management cert PEM failed to load")?;
        ck.keys_match()
            .map_err(|e| anyhow::anyhow!("private key does not match certificate: {e}"))?;

        let prev_fp = self
            .live
            .get(MANAGEMENT_CERT_KEY)
            .map(|e| e.value().meta.fingerprint.clone());

        // 2. Atomic disk write with restore-on-failure. Snapshot the existing
        //    files first; if any write fails, restore the snapshot so disk never
        //    ends up with a mismatched new-cert/old-key pair.
        let dir = self.cert_dir.join(domain_to_dirname(MANAGEMENT_CERT_KEY));
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let meta_path = dir.join("meta.json");
        let snapshot: Vec<(PathBuf, Option<Vec<u8>>)> = [&cert_path, &key_path, &meta_path]
            .iter()
            .map(|p| ((*p).clone(), std::fs::read(p).ok()))
            .collect();

        let meta_json = serde_json::to_string_pretty(&meta)?;
        let write_res = (|| -> Result<()> {
            write_atomic(&cert_path, cert_pem.as_bytes())?;
            write_atomic(&key_path, key_pem.as_bytes())?;
            write_atomic(&meta_path, meta_json.as_bytes())?;
            Ok(())
        })();
        if let Err(e) = write_res {
            // Restore the previous on-disk state (or remove if there was none).
            for (p, prev) in &snapshot {
                match prev {
                    Some(bytes) => {
                        let _ = write_atomic(p, bytes);
                    }
                    None => {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
            return Err(e).context("installing management cert (restored previous on-disk state)");
        }

        // 3. Hot-swap the live entry — picked up on the next TLS handshake.
        self.insert_live(
            MANAGEMENT_CERT_KEY.to_string(),
            live_entry(MANAGEMENT_CERT_KEY, ck, meta),
        );
        tracing::info!("management TLS cert installed and hot-swapped");
        Ok(prev_fp)
    }

    /// Revert the management cert to the built-in self-signed default (removes
    /// the uploaded management cert from disk + the live store).
    pub fn revert_management(&self) -> Result<()> {
        self.remove(MANAGEMENT_CERT_KEY)?;
        // The console listener only looks its cert up, so its shared self-signed
        // cert is restored here; otherwise it would serve the default cert.
        let _ = self.self_signed_shared(MANAGEMENT_CERT_KEY);
        Ok(())
    }

    // ── TLS-ALPN-01 challenge helpers ─────────────────────────────────────────

    pub fn set_alpn_challenge(&self, domain: &str, ck: Arc<CertifiedKey>) {
        self.alpn_challenge.insert(domain.to_string(), ck);
    }

    pub fn clear_alpn_challenge(&self, domain: &str) {
        self.alpn_challenge.remove(domain);
    }

    // ── internal resolvers ────────────────────────────────────────────────────

    /// The live cert served for `sni`: one carrying the name, or a wildcard
    /// over it (see `serving_entry`).
    fn resolve_live(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.serving_entry(sni).map(|e| Arc::clone(&e.key))
    }

    /// The live cert stored under `key`, whatever its names: how the
    /// management listener finds the one cert it serves.
    fn resolve_key(&self, key: &str) -> Option<Arc<CertifiedKey>> {
        self.live.get(key).map(|e| Arc::clone(&e.value().key))
    }

    /// The self-signed cert of a configured site, matched like `resolve_live`.
    fn resolve_site_fallback(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let fb = self.fallback_read();
        if let Some(e) = fb.certs.get(sni) {
            return Some(Arc::clone(&e.key));
        }
        let parent = sni.split_once('.').map(|(_, rest)| format!("*.{rest}"))?;
        fb.certs.get(&parent).map(|e| Arc::clone(&e.key))
    }

    fn default_cert(&self) -> Option<Arc<CertifiedKey>> {
        self.default_cert.load_full()
    }
}

// ---------------------------------------------------------------------------
// SentinelCertResolver — plugs into rustls ServerConfig::with_cert_resolver
// ---------------------------------------------------------------------------

pub struct SentinelCertResolver {
    store: Arc<CertStore>,
    /// When set, every handshake resolves THIS store key regardless of SNI.
    /// Used by the management listener to always serve the management cert.
    fixed_key: Option<String>,
}

impl std::fmt::Debug for SentinelCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SentinelCertResolver")
            .finish_non_exhaustive()
    }
}

impl SentinelCertResolver {
    /// Resolver for the SNI listeners. The default certificate is made sure of
    /// here, at listener startup, so `resolve` never has to create one.
    pub fn new(store: Arc<CertStore>) -> Arc<Self> {
        store.ensure_default_cert();
        Arc::new(Self {
            store,
            fixed_key: None,
        })
    }

    /// Resolver that always serves the cert stored under `key` (ignoring SNI),
    /// falling back to a self-signed cert for `key` until one is uploaded. This
    /// backs the management listener: it's a single-purpose HTTPS endpoint, so
    /// there's no SNI multiplexing — one cert, hot-swappable.
    ///
    /// The self-signed cert is persisted and shared: the first node to need it
    /// writes it to the cert volume and every node — and every restart — serves
    /// the same bytes until an operator uploads a real one. A per-process cert
    /// put the browser's certificate warning back on the console at every roll.
    /// It is minted here, at listener startup, not in the first handshake.
    pub fn new_fixed(store: Arc<CertStore>, key: &str) -> Arc<Self> {
        store.ensure_default_cert();
        if store.resolve_key(key).is_none() {
            let _ = store.self_signed_shared(key);
        }
        Arc::new(Self {
            store,
            fixed_key: Some(key.to_string()),
        })
    }

    /// Pick the certificate for one handshake.
    ///
    /// Lookups only. This used to mint and persist a self-signed cert for any
    /// SNI it had not seen, so every name a scanner tried cost a key generation,
    /// a directory on the shared cert volume and an entry in two maps that were
    /// never pruned — at the client's choosing, before any WAF check ran. A name
    /// with no cert of its own now gets the default certificate.
    fn select(&self, sni: Option<&str>, acme_alpn: bool) -> Option<Arc<CertifiedKey>> {
        // Fixed-key mode (management listener): always the one configured cert,
        // regardless of SNI.
        if let Some(key) = &self.fixed_key {
            return self
                .store
                .resolve_key(key)
                .or_else(|| self.store.default_cert());
        }

        // Clients connecting by bare IP (and some older clients) send no SNI.
        // They get the default cert so the handshake still completes — Host-header
        // routing then selects the site. Returning None would abort the handshake
        // and break IP access.
        let sni = sni.unwrap_or(DEFAULT_CERT_KEY);

        // 1. TLS-ALPN-01 challenge takes highest priority
        if acme_alpn {
            if let Some(ck) = self.store.alpn_challenge.get(sni) {
                return Some(Arc::clone(ck.value()));
            }
        }

        // 2. Live ACME / manual cert, 3. a configured site's self-signed cert,
        // 4. the default cert for everything else.
        self.store
            .resolve_live(sni)
            .or_else(|| self.store.resolve_site_fallback(sni))
            .or_else(|| self.store.default_cert())
    }
}

/// An SNI that panics the resolver inside the TLS handshake, in test builds
/// only: rustls calls it while quinn holds its locks on an HTTP/3 handshake.
#[cfg(test)]
pub(crate) const INJECT_RESOLVER_PANIC_SNI: &str = "panic-guard-resolver.local";

impl ResolvesServerCert for SentinelCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        #[cfg(test)]
        if client_hello.server_name() == Some(INJECT_RESOLVER_PANIC_SNI) {
            panic!("injected certificate resolver panic");
        }
        let acme_alpn = client_hello
            .alpn()
            .map(|mut it| it.any(|p| p == b"acme-tls/1"))
            .unwrap_or(false);
        self.select(client_hello.server_name(), acme_alpn)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Metadata for a self-signed cert held in memory.
fn self_signed_meta(domain: &str) -> CertMeta {
    CertMeta {
        domain: domain.to_string(),
        name: String::new(),
        san: vec![domain.to_string(), format!("*.{domain}")],
        issued_at: 0,
        expires_at: 0,
        fingerprint: String::new(),
        source: CertSource::SelfSigned,
        issuer: String::new(),
        key_type: String::new(),
    }
}

/// Generate a self-signed cert for `domain` and return it as PEM.
///
/// Exists so the fallback cert can be PERSISTED. Before this, the fallback was
/// generated per process and held only in memory, which is invisible on one node
/// and wrong on three: each node invented its own certificate for the same name,
/// so a client was served a different cert depending on which node the load
/// balancer picked. Measured on .71 the moment HTTPS moved behind the LB — 12
/// handshakes returned exactly 3 distinct certificates, 4 each.
pub fn generate_self_signed_pem(domain: &str) -> Result<(String, String)> {
    ensure_ascii_name(domain)?;
    let names = vec![domain.to_string(), format!("*.{domain}")];
    let cert =
        rcgen::generate_simple_self_signed(names).context("rcgen generate_simple_self_signed")?;
    Ok((
        cert.serialize_pem().context("serialize cert PEM")?,
        cert.serialize_private_key_pem(),
    ))
}

pub fn generate_self_signed(domain: &str) -> Result<Arc<CertifiedKey>> {
    ensure_ascii_name(domain)?;
    let names = vec![domain.to_string(), format!("*.{domain}")];
    let cert =
        rcgen::generate_simple_self_signed(names).context("rcgen generate_simple_self_signed")?;
    let cert_der = cert.serialize_der().context("serialize cert DER")?;
    let key_der = cert.serialize_private_key_der();

    let pkcs8 = PrivatePkcs8KeyDer::from(key_der);
    let any_key = PrivateKeyDer::Pkcs8(pkcs8.clone_key());
    let signing = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&any_key)
        .or_else(|_| rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&pkcs8))
        .context("building rustls signing key for self-signed cert")?;

    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(cert_der)],
        signing,
    )))
}

/// rcgen encodes SAN names as IA5String and asserts they are ASCII, so a
/// non-ASCII name is a panic: a dead process while release builds aborted on
/// panic, and still a restarted sync and a site on the default cert now that
/// they unwind. Refuse it as an error instead.
fn ensure_ascii_name(domain: &str) -> Result<()> {
    anyhow::ensure!(
        domain.is_ascii(),
        "certificate name {domain:?} is not ASCII; use its xn-- form"
    );
    Ok(())
}

/// Whether the first cert in `cert_pem` names itself as its issuer. Unknown
/// (unparseable) counts as no, so an operator's cert is never dropped on a guess.
fn pem_is_self_issued(cert_pem: &[u8]) -> bool {
    rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem))
        .next()
        .and_then(|c| c.ok())
        .and_then(|der| super::acme::der_self_issued(der.as_ref()))
        .unwrap_or(false)
}

fn load_pem_files(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    load_pem_bytes(&cert_pem, &key_pem)
}

pub fn load_pem_bytes(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem))
            .collect::<std::result::Result<_, _>>()
            .context("parsing cert PEM")?;

    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem))
        .context("parsing key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))?;

    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .context("building rustls signing key")?;

    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// Map a hostname to a single, traversal-safe filesystem directory component.
///
/// Wildcards become a literal token; every character outside a strict allow-list
/// (letters, digits, `.`, `-`, `_`) — including path separators and NULs — is
/// replaced with `_`. Finally, a component made up only of dots (`""`, `"."`,
/// `".."`, …) is neutralized, because otherwise a crafted `:domain` such as
/// `DELETE /certs/..` would resolve to `cert_dir/..` via `Path::join` and let
/// `remove_dir_all` escape the certificate directory.
///
/// For all legitimate hostnames (and the reserved `__management__` key) this is
/// identical to the previous mapping, so existing on-disk cert dirs are stable.
fn domain_to_dirname(domain: &str) -> String {
    let mut sanitized: String = domain
        .replace('*', "_wildcard_")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() || sanitized.chars().all(|c| c == '.') {
        // e.g. "" -> "_", "." -> "_.", ".." -> "_.." — never a traversal.
        sanitized.insert(0, '_');
    }
    sanitized
}

/// Write `bytes` to `path` atomically and owner-only (0600): write to a sibling
/// temp file created with mode 0600, fsync, then rename over the target (atomic
/// on the same filesystem). Prevents a crash/partial write from leaving a
/// truncated cert or key, and never leaves a private key world-readable. The
/// temp file is removed on any failure.
/// Write `bytes` to `path` ONLY if it does not exist, at `mode`.
///
/// The failure is the feature: on a shared cert volume this is how a fleet of
/// nodes agrees on one self-signed certificate without coordinating. `create_new`
/// is atomic in the kernel, so exactly one node succeeds and the rest read what
/// it wrote instead of overwriting each other on every restart.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(path)
        .with_context(|| format!("claiming {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");

    let res = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::from(e).context(format!(
            "renaming {} -> {}",
            tmp.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn tmp_store() -> Arc<CertStore> {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sentinel-certtest-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        CertStore::new(dir)
    }

    /// A fresh directory two stores can share — i.e. two containers with the
    /// same volume mounted. Uses the same scheme as `tmp_store` above rather
    /// than adding a `tempfile` dev-dependency this crate does not have.
    fn tmp_dir() -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sentinel-certshare-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create shared cert dir");
        dir
    }

    fn self_signed_pem(cn: &str) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec![cn.to_string()]).unwrap();
        (
            cert.serialize_pem().unwrap(),
            cert.serialize_private_key_pem(),
        )
    }

    fn meta(fp: &str) -> CertMeta {
        CertMeta {
            domain: MANAGEMENT_CERT_KEY.to_string(),
            name: "Mgmt".into(),
            san: vec!["mgmt.test".into()],
            issued_at: 1,
            expires_at: 2,
            fingerprint: fp.into(),
            source: CertSource::Manual,
            issuer: "Test CA".into(),
            key_type: "ECDSA P-256".into(),
        }
    }

    #[test]
    fn management_cert_install_get_hidden_and_revert() {
        let store = tmp_store();
        let (cert, key) = self_signed_pem("mgmt.test");

        // First install: no previous fingerprint.
        let prev = store.install_management(&cert, &key, meta("fp1")).unwrap();
        assert_eq!(prev, None);

        // Readable via the dedicated getter, with the extended metadata.
        let got = store.get_meta(MANAGEMENT_CERT_KEY).unwrap();
        assert_eq!(got.issuer, "Test CA");
        assert_eq!(got.key_type, "ECDSA P-256");
        assert_eq!(got.fingerprint, "fp1");

        // Hidden from the customer cert repository listing.
        assert!(store
            .all_meta()
            .iter()
            .all(|m| m.domain != MANAGEMENT_CERT_KEY));

        // Re-install returns the previous fingerprint (for audit old→new).
        let (cert2, key2) = self_signed_pem("mgmt.test");
        let prev2 = store
            .install_management(&cert2, &key2, meta("fp2"))
            .unwrap();
        assert_eq!(prev2, Some("fp1".to_string()));

        // Revert removes it → back on the shared self-signed management cert,
        // which the Management TLS page reports as self-signed.
        store.revert_management().unwrap();
        assert_eq!(
            store.get_meta(MANAGEMENT_CERT_KEY).map(|m| m.source),
            Some(CertSource::SelfSigned)
        );
    }

    #[test]
    fn install_management_rejects_malformed_pem() {
        let store = tmp_store();
        assert!(store
            .install_management("not a cert", "not a key", meta("x"))
            .is_err());
        // Nothing installed on failure.
        assert!(store.get_meta(MANAGEMENT_CERT_KEY).is_none());
    }

    /// The management cert must survive a restart and be shared by the fleet,
    /// or every roll re-triggers the browser warning on the console.
    #[test]
    fn management_self_signed_cert_is_persisted_and_shared() {
        let dir = tmp_dir();
        let a = CertStore::new(dir.clone());
        let first = a
            .self_signed_shared(MANAGEMENT_CERT_KEY)
            .expect("node a mints the management cert");
        // A second process over the same volume — a restart, or another node.
        let b = CertStore::new(dir.clone());
        let second = b
            .self_signed_shared(MANAGEMENT_CERT_KEY)
            .expect("node b adopts it");
        assert_eq!(
            first.cert[0].as_ref(),
            second.cert[0].as_ref(),
            "restart/other node must serve the SAME management cert bytes"
        );
        // It is on disk under the reserved key, and still hidden from the
        // customer cert repository listing.
        assert!(dir
            .join(domain_to_dirname(MANAGEMENT_CERT_KEY))
            .join("cert.pem")
            .exists());
        assert!(a.all_meta().iter().all(|m| m.domain != MANAGEMENT_CERT_KEY));
        // And it reports itself as self-signed, so the Management TLS page does
        // not claim an operator certificate is installed.
        assert!(matches!(
            a.get_meta(MANAGEMENT_CERT_KEY).map(|m| m.source),
            Some(CertSource::SelfSigned)
        ));
    }

    /// Two nodes sharing a cert volume must serve the SAME self-signed cert.
    ///
    /// This is the whole point. Before it, the fallback lived in a per-process
    /// HashMap: on .71, once HAProxy spread :443 across three nodes, 12
    /// handshakes returned 3 distinct certificates — a fresh browser warning on
    /// every other request.
    #[test]
    fn two_nodes_sharing_a_volume_converge_on_one_self_signed_cert() {
        let dir = tmp_dir();
        // Two independent stores over ONE directory — exactly two containers
        // with the same volume mounted.
        let a = CertStore::new(dir.clone());
        let b = CertStore::new(dir.clone());

        let ka = a
            .self_signed_shared("shop.example.com")
            .expect("node A cert");
        let kb = b
            .self_signed_shared("shop.example.com")
            .expect("node B cert");

        assert_eq!(
            ka.end_entity_cert().unwrap().as_ref(),
            kb.end_entity_cert().unwrap().as_ref(),
            "two nodes served different certificates for the same name"
        );
        assert!(
            dir.join("shop.example.com").join("cert.pem").exists(),
            "the cert was not persisted, so a third node would invent its own"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restart must not replace a cert already in use. Overwriting would make
    /// the fleet flap between certificates on every recreate — the same defect,
    /// just slower.
    #[test]
    fn a_second_call_does_not_overwrite_the_persisted_cert() {
        let dir = tmp_dir();
        let first = CertStore::new(dir.clone())
            .self_signed_shared("api.example.com")
            .expect("first");
        let pem_before = std::fs::read(dir.join("api.example.com").join("cert.pem")).unwrap();

        // A fresh process over the same volume.
        let second = CertStore::new(dir.clone())
            .self_signed_shared("api.example.com")
            .expect("second");
        let pem_after = std::fs::read(dir.join("api.example.com").join("cert.pem")).unwrap();

        assert_eq!(pem_before, pem_after, "the on-disk cert was rewritten");
        assert_eq!(
            first.end_entity_cert().unwrap().as_ref(),
            second.end_entity_cert().unwrap().as_ref(),
            "a restart changed the served certificate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Distinct names still get distinct certs — the sharing must be per-name,
    /// not one cert for everything.
    #[test]
    fn different_names_get_different_certs() {
        let dir = tmp_dir();
        let st = CertStore::new(dir.clone());
        let one = st.self_signed_shared("a.example.com").unwrap();
        let two = st.self_signed_shared("b.example.com").unwrap();
        assert_ne!(
            one.end_entity_cert().unwrap().as_ref(),
            two.end_entity_cert().unwrap().as_ref()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A panic while the site-fallback map was locked must not end TLS. Every
    /// handshake for a configured site reads it and the site sync writes it; the
    /// fallback cache it replaced `expect`ed its lock, so one panic there failed
    /// every later handshake on the listener.
    #[test]
    fn a_poisoned_fallback_map_keeps_serving() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let poisoner = Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.fallback.write().unwrap();
            panic!("poisoning the fallback map on purpose");
        })
        .join();
        assert!(store.fallback.is_poisoned(), "fixture must poison the lock");

        // The sync still records the site and mints its cert...
        let missing = store.set_site_names(names(&["after-poison.example"]));
        assert_eq!(missing, vec!["after-poison.example".to_string()]);
        assert_eq!(store.ensure_site_fallbacks(&missing).added, 1);
        // ...and a handshake for it is served that cert, not the default one.
        let served = leaf(
            &resolver
                .select(Some("after-poison.example"), false)
                .unwrap(),
        );
        assert_ne!(served, leaf(&store.default_cert().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unwritable store must still yield a working cert. Refusing TLS because
    /// a volume is read-only would be a worse failure than an inconsistent cert.
    #[test]
    fn an_unwritable_store_still_serves_tls() {
        let s = CertStore::new(std::path::PathBuf::from("/proc/nonexistent-cert-dir"));
        assert!(
            s.self_signed_shared("x.example.com").is_some(),
            "a read-only or missing cert dir must not take HTTPS down"
        );
    }

    // ── resolver: lookups only ───────────────────────────────────────────────

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// The client side of a test handshake trusts anything: what is under test
    /// is WHICH certificate the server picks, not whether it chains.
    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// A full in-memory TLS handshake against `resolver`; returns the leaf
    /// certificate the server presented. `None` sends no SNI — what a browser
    /// does for `https://<ip>/`.
    fn handshake(resolver: &Arc<SentinelCertResolver>, sni: Option<&str>) -> Vec<u8> {
        use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
        // Explicit provider: both aws-lc-rs and ring are compiled in, so the
        // process-default builder would panic.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(resolver) as Arc<dyn ResolvesServerCert>);
        let client_cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        // rustls never sends an IP address as SNI.
        let name = match sni {
            Some(n) => ServerName::try_from(n.to_string()).expect("valid DNS name"),
            None => ServerName::IpAddress(std::net::Ipv4Addr::new(192, 0, 2, 1).into()),
        };
        let mut client = ClientConnection::new(Arc::new(client_cfg), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        for _ in 0..10 {
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
            let mut wire = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut wire).unwrap();
            }
            let mut rd = wire.as_slice();
            while !rd.is_empty() {
                server.read_tls(&mut rd).unwrap();
                server.process_new_packets().expect("server handshake");
            }
            let mut wire = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut wire).unwrap();
            }
            let mut rd = wire.as_slice();
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
                client.process_new_packets().expect("client handshake");
            }
        }
        client
            .peer_certificates()
            .expect("the server presented a certificate")[0]
            .as_ref()
            .to_vec()
    }

    /// Every file and directory under `dir`, recursively.
    fn count_entries(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| {
                        1 + if e.path().is_dir() {
                            count_entries(&e.path())
                        } else {
                            0
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    }

    fn names(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn site(id: &str, domains: &[&str]) -> SiteConfig {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "domains": domains,
            "upstream": { "servers": [] },
        }))
        .expect("site config")
    }

    fn config_with(sites: Vec<SiteConfig>) -> ConfigHandle {
        Arc::new(arc_swap::ArcSwap::from_pointee(SentinelConfig {
            sites,
            ..Default::default()
        }))
    }

    fn leaf(ck: &Arc<CertifiedKey>) -> Vec<u8> {
        ck.cert[0].as_ref().to_vec()
    }

    fn pem_leaf(path: &Path) -> Vec<u8> {
        let pem = std::fs::read(path).expect("cert.pem");
        let der = rustls_pemfile::certs(&mut pem.as_slice())
            .next()
            .expect("one cert")
            .expect("parse");
        der.as_ref().to_vec()
    }

    /// The defect: the resolver minted and persisted a certificate for any SNI
    /// it had not seen. Every name a scanner sent cost a key generation, a
    /// directory on the shared cert volume, and an entry in two maps nothing
    /// ever pruned — at the client's choosing, before any WAF check ran.
    #[test]
    fn resolving_many_unconfigured_names_writes_nothing_and_grows_nothing() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        store.load_from_disk(&names(&["shop.example.com"])).unwrap();
        store.ensure_site_fallbacks(&["shop.example.com".to_string()]);
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let default_cert = handshake(&resolver, None);
        let shop = handshake(&resolver, Some("shop.example.com"));

        let entries_before = count_entries(&dir);
        let live_before = store.live.len();
        let fallback_before = store.fallback_read().certs.len();

        let served: Vec<Vec<u8>> = (0..200)
            .map(|i| handshake(&resolver, Some(&format!("probe-{i}.scanner.example"))))
            .collect();

        assert_eq!(
            count_entries(&dir),
            entries_before,
            "a handshake for an unconfigured name wrote to the cert volume"
        );
        assert_eq!(store.live.len(), live_before, "the live map grew");
        assert_eq!(
            store.fallback_read().certs.len(),
            fallback_before,
            "the fallback map grew"
        );
        assert!(
            served.iter().all(|c| *c == default_cert),
            "an unconfigured name must be served the default certificate"
        );
        // The configured site still has its own.
        assert_ne!(shop, default_cert);
        assert_eq!(handshake(&resolver, Some("shop.example.com")), shop);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Wait (bounded) for the background sync to produce `f`'s answer.
    async fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        for _ in 0..500 {
            if let Some(v) = f() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// A configured site with no certificate gets its own self-signed one from
    /// the background sync — at startup, and when a later sync adds a site —
    /// and a removed site drops out of the fallback map.
    #[tokio::test]
    async fn a_configured_site_without_a_cert_gets_one_after_sync() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let config = config_with(vec![site("shop", &["shop.example.com"])]);
        store
            .load_from_disk(&site_cert_names(&config.load().sites))
            .unwrap();
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let default_cert = handshake(&resolver, None);

        // Before the sync has run the site is on the default cert, and asking
        // for it did not make the handshake mint one.
        assert_eq!(handshake(&resolver, Some("shop.example.com")), default_cert);
        assert!(!dir.join("shop.example.com").exists());

        let task = spawn_site_cert_sync_every(
            Arc::clone(&store),
            Arc::clone(&config),
            Duration::from_millis(10),
        );
        let shop = eventually("the configured site's own cert", || {
            let c = handshake(&resolver, Some("shop.example.com"));
            (c != default_cert).then_some(c)
        })
        .await;
        assert_eq!(
            pem_leaf(&dir.join("shop.example.com").join("cert.pem")),
            shop,
            "the site cert must be the one on the shared volume, or nodes diverge"
        );

        // A later sync adds a site: it gets its own as well.
        config.store(Arc::new(SentinelConfig {
            sites: vec![
                site("shop", &["shop.example.com"]),
                site("api", &["API.Example.com"]),
            ],
            ..Default::default()
        }));
        let api = eventually("the added site's cert", || {
            let c = handshake(&resolver, Some("api.example.com"));
            (c != default_cert).then_some(c)
        })
        .await;
        assert_ne!(api, shop);

        // A sync that removes a site prunes the map; the name falls to the
        // default cert. Nothing is deleted from the volume.
        config.store(Arc::new(SentinelConfig {
            sites: vec![site("api", &["api.example.com"])],
            ..Default::default()
        }));
        eventually("the removed site to fall back to the default cert", || {
            (handshake(&resolver, Some("shop.example.com")) == default_cert).then_some(())
        })
        .await;
        assert_eq!(store.fallback_read().certs.len(), 1);
        assert!(dir.join("shop.example.com").join("cert.pem").exists());
        task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A panic in the sync restarts it. A bare spawn ended it for good: the
    /// sites configured then, and every site added later, stayed on the default
    /// certificate until the node restarted.
    #[tokio::test]
    async fn a_panic_in_the_site_sync_restarts_it() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let config = config_with(vec![site("p", &[INJECT_SITE_SYNC_PANIC_NAME])]);
        let task = spawn_site_cert_sync_every(
            Arc::clone(&store),
            Arc::clone(&config),
            Duration::from_millis(10),
        );
        // The first round panics; the restarted run mints the cert.
        eventually("the restarted sync to mint the site's cert", || {
            store.resolve_site_fallback(INJECT_SITE_SYNC_PANIC_NAME)
        })
        .await;
        assert!(
            SITE_SYNC_PANICKED.load(Ordering::SeqCst),
            "the injected panic fired"
        );
        task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mint that panics, on the blocking pool, came back as a JoinError the
    /// sync took for "all failed", and a failure is retried every tick: a
    /// fresh panic, ERROR line and backtrace each time, for ever, with no
    /// backoff and no restart recorded. It reaches the supervisor now, which
    /// records it under the mint's own location and backs off.
    #[tokio::test]
    async fn a_panicking_mint_reaches_the_supervisor() {
        crate::panic_guard::install_panic_hook();
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let config = config_with(vec![site("m", &[INJECT_MINT_PANIC_NAME])]);
        let task = spawn_site_cert_sync_every(
            Arc::clone(&store),
            Arc::clone(&config),
            Duration::from_millis(10),
        );
        let (location, _) = eventually("the mint's panic to restart the sync", || {
            crate::panic_guard::task_last_panic("site certificate sync")
                .filter(|(_, panic)| panic == "injected site certificate mint panic")
        })
        .await;
        assert!(location.contains("cert_store.rs"), "{location}");

        // Backed off: the old sync retried every 10 ms here.
        let mints = MINT_PANICS.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let more = MINT_PANICS.load(Ordering::SeqCst) - mints;
        assert!(more <= 2, "{more} mints in 1.5 s");
        task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No SNI (bare-IP access) still completes the handshake, with the one
    /// persisted default cert — the same bytes on every node and restart.
    #[test]
    fn no_sni_gets_the_shared_default_cert() {
        let dir = tmp_dir();
        let a = CertStore::new(dir.clone());
        a.load_from_disk(&names(&["shop.example.com"])).unwrap();
        let ra = SentinelCertResolver::new(Arc::clone(&a));
        let served = handshake(&ra, None);
        assert_eq!(
            served,
            pem_leaf(&dir.join(DEFAULT_CERT_KEY).join("cert.pem"))
        );

        // Another node over the same volume serves the same default cert, for no
        // SNI and for a name it has no cert for.
        let b = CertStore::new(dir.clone());
        b.load_from_disk(&names(&["shop.example.com"])).unwrap();
        let rb = SentinelCertResolver::new(Arc::clone(&b));
        assert_eq!(handshake(&rb, None), served);
        assert_eq!(handshake(&rb, Some("unknown.example.net")), served);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TLS-ALPN-01 keeps priority over every other cert, and live certs over the
    /// self-signed fallback.
    #[test]
    fn acme_challenge_then_live_then_fallback_then_default() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        store.load_from_disk(&names(&["shop.example.com"])).unwrap();
        store.ensure_site_fallbacks(&["shop.example.com".to_string()]);
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let fallback = leaf(&resolver.select(Some("shop.example.com"), false).unwrap());

        let (cert, key) = self_signed_pem("shop.example.com");
        let mut m = meta("fp");
        m.domain = "shop.example.com".into();
        store.install("shop.example.com", &cert, &key, m).unwrap();
        let live = leaf(&resolver.select(Some("shop.example.com"), false).unwrap());
        assert_ne!(live, fallback, "a manual cert must win over the fallback");

        let challenge = generate_self_signed("shop.example.com").unwrap();
        store.set_alpn_challenge("shop.example.com", Arc::clone(&challenge));
        assert_eq!(
            leaf(&resolver.select(Some("shop.example.com"), true).unwrap()),
            leaf(&challenge),
            "the acme-tls/1 challenge cert must win"
        );
        // Only for a challenge handshake.
        assert_eq!(
            leaf(&resolver.select(Some("shop.example.com"), false).unwrap()),
            live
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A configured wildcard site covers one label below it, as a live wildcard
    /// cert does.
    #[test]
    fn a_wildcard_site_cert_covers_its_subdomains() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        store.load_from_disk(&names(&["*.example.com"])).unwrap();
        assert_eq!(
            store
                .ensure_site_fallbacks(&["*.example.com".to_string()])
                .added,
            1
        );
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let default_cert = leaf(&store.default_cert().unwrap());
        let sub = leaf(&resolver.select(Some("shop.example.com"), false).unwrap());
        assert_ne!(sub, default_cert);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// At startup, self-signed dirs for names no site is configured for — what
    /// the old resolver left on the volume for every probed SNI — are skipped,
    /// counted and left in place. Everything else loads as before.
    #[test]
    fn startup_skips_self_signed_dirs_for_unconfigured_names() {
        let dir = tmp_dir();
        {
            // What a fleet running the old resolver left on the volume.
            let old = CertStore::new(dir.clone());
            for n in ["junk-1.example", "junk-2.example", "shop.example.com"] {
                old.self_signed_shared(n).unwrap();
            }
            old.self_signed_shared(MANAGEMENT_CERT_KEY).unwrap();
            old.self_signed_shared(DEFAULT_CERT_KEY).unwrap();
            let (cert, key) = self_signed_pem("manual.example.com");
            let mut m = meta("fp");
            m.domain = "manual.example.com".into();
            old.install("manual.example.com", &cert, &key, m).unwrap();
        }

        let store = CertStore::new(dir.clone());
        let loaded = store
            .load_from_disk(&names(&["shop.example.com", "manual.example.com"]))
            .unwrap();
        assert_eq!(loaded, 3, "shop (fallback), manual and management");
        assert!(store.live.contains_key("manual.example.com"));
        assert!(store.live.contains_key(MANAGEMENT_CERT_KEY));
        assert!(!store.live.contains_key("junk-1.example"));
        assert!(!store.live.contains_key("shop.example.com"));
        assert!(store.fallback_read().certs.contains_key("shop.example.com"));
        assert_eq!(store.fallback_read().certs.len(), 1);
        // Delete nothing.
        assert!(dir.join("junk-1.example").join("cert.pem").exists());
        assert!(dir.join("junk-2.example").join("cert.pem").exists());

        // A self-signed cert is never reported as issued: ACME would wait for
        // ever behind it. It is still listed for the console.
        assert!(store.get_meta("shop.example.com").is_none());
        let listed: Vec<String> = store.all_meta().into_iter().map(|m| m.domain).collect();
        assert!(listed.contains(&"shop.example.com".to_string()));
        assert!(listed.contains(&"manual.example.com".to_string()));
        assert!(!listed.iter().any(|d| d.starts_with("junk")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Installing a real cert supersedes the fallback (one listing row);
    /// removing it gives the still-configured site a fresh self-signed cert in
    /// that admin call, not the default cert.
    #[test]
    fn install_replaces_the_fallback_and_remove_restores_one() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        store.load_from_disk(&names(&["shop.example.com"])).unwrap();
        store.ensure_site_fallbacks(&["shop.example.com".to_string()]);
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let default_cert = leaf(&store.default_cert().unwrap());

        let (cert, key) = self_signed_pem("shop.example.com");
        let mut m = meta("fp");
        m.domain = "shop.example.com".into();
        store.install("shop.example.com", &cert, &key, m).unwrap();
        let manual = leaf(&resolver.select(Some("shop.example.com"), false).unwrap());
        let rows: Vec<CertMeta> = store
            .all_meta()
            .into_iter()
            .filter(|m| m.domain == "shop.example.com")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, CertSource::Manual);

        store.remove("shop.example.com").unwrap();
        let after = leaf(&resolver.select(Some("shop.example.com"), false).unwrap());
        assert_ne!(after, manual);
        assert_ne!(after, default_cert);
        assert_eq!(
            pem_leaf(&dir.join("shop.example.com").join("cert.pem")),
            after
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cert minted for a site that a sync removed meanwhile is not kept.
    #[test]
    fn a_site_removed_mid_batch_is_not_added() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let missing = store.set_site_names(names(&["gone.example.com"]));
        assert_eq!(missing, vec!["gone.example.com".to_string()]);
        store.set_site_names(HashSet::new());
        let report = store.ensure_site_fallbacks(&missing);
        assert_eq!((report.added, report.failed.len()), (0, 0));
        assert!(store.fallback_read().certs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An ACME order is stored under its first name. Its other names must read
    /// as covered, or the renewal loop re-orders the site every hour.
    #[test]
    fn get_meta_answers_for_a_name_in_an_issued_certs_san() {
        let store = tmp_store();
        let (cert, key) = self_signed_pem("example.org");
        let m = CertMeta {
            domain: "example.org".into(),
            name: String::new(),
            san: vec!["example.org".into(), "www.example.org".into()],
            issued_at: 1,
            expires_at: 2,
            fingerprint: "fp".into(),
            source: CertSource::Acme {
                provider: "LetsEncrypt".into(),
                email: "ops@example.org".into(),
            },
            issuer: String::new(),
            key_type: String::new(),
        };
        store.install("example.org", &cert, &key, m).unwrap();
        assert_eq!(
            store.get_meta("www.example.org").map(|m| m.domain),
            Some("example.org".to_string())
        );
        assert!(store.get_meta("other.example.org").is_none());
    }

    /// The management listener's self-signed cert is minted when the listener
    /// is built; a handshake only looks it up, whatever SNI it carries.
    #[test]
    fn management_cert_is_minted_at_startup_not_in_the_handshake() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let resolver = SentinelCertResolver::new_fixed(Arc::clone(&store), MANAGEMENT_CERT_KEY);
        let mgmt_file = dir
            .join(domain_to_dirname(MANAGEMENT_CERT_KEY))
            .join("cert.pem");
        assert!(mgmt_file.exists(), "not minted at listener construction");
        let entries = count_entries(&dir);
        for sni in [None, Some("console.example.com"), Some("x.example.net")] {
            assert_eq!(handshake(&resolver, sni), pem_leaf(&mgmt_file));
        }
        assert_eq!(count_entries(&dir), entries);

        // An uploaded cert is served at once. A revert restores the console's
        // own persisted self-signed cert in the store call itself — not the
        // default cert, and not minted later in a handshake.
        let minted = pem_leaf(&mgmt_file);
        let (cert, key) = self_signed_pem("console.example.com");
        store.install_management(&cert, &key, meta("fp")).unwrap();
        let uploaded = handshake(&resolver, None);
        assert_ne!(uploaded, minted);
        store.revert_management().unwrap();
        let reverted = pem_leaf(&mgmt_file);
        let entries = count_entries(&dir);
        assert_ne!(reverted, uploaded);
        assert_ne!(
            reverted,
            pem_leaf(&dir.join(DEFAULT_CERT_KEY).join("cert.pem"))
        );
        assert_eq!(handshake(&resolver, Some("x.example.net")), reverted);
        assert_eq!(count_entries(&dir), entries);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── follow-up: names, wildcards, startup robustness, retries ────────────

    /// A site domain with a non-ASCII character (a console typo, a pasted IDN
    /// U-label, a zero-width space) is accepted by the control plane. rcgen
    /// asserts SAN names are ASCII, so the sync panicked minting it — under the
    /// release profile's `panic = "abort"` of the time, every node within
    /// seconds of the config push and again at each boot. No handshake can ever
    /// carry such a name, so it is simply not a cert name.
    #[tokio::test]
    async fn a_non_ascii_site_name_is_skipped_not_a_crash() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        let sites = vec![
            site("books", &["bücher.example", "shop\u{200b}.example.com"]),
            site("shop", &["shop.example.com"]),
        ];
        let wanted = site_cert_names(&sites);
        assert_eq!(wanted, names(&["shop.example.com"]));

        let report = store.sync_site_fallbacks(wanted).await;
        assert_eq!(
            report.added, 1,
            "the other sites must still get their certs"
        );
        assert!(report.failed.is_empty());
        assert!(dir.join("shop.example.com").join("cert.pem").exists());
        assert!(!dir.join(domain_to_dirname("bücher.example")).exists());

        // No caller can reach the rcgen assert any more.
        assert!(generate_self_signed_pem("bücher.example").is_err());
        assert!(generate_self_signed("bücher.example").is_err());
        store.remove("bücher.example").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only names a handshake can carry are cert names: rustls hands the
    /// resolver a valid DNS name or nothing.
    #[test]
    fn site_cert_names_keeps_only_names_sni_can_carry() {
        let got = site_cert_names(&[site(
            "s",
            &[
                "Shop.Example.com.",
                "*.example.org",
                "under_score.example.net",
                "juice",
                "xn--bcher-kva.example",
                "10.0.0.5",
                "::1",
                "",
                "__management__",
                "*.*.example.com",
                "bad host.example",
                "bücher.example",
                "app.example.com:8443",
            ],
        )]);
        assert_eq!(
            got,
            names(&[
                "shop.example.com",
                "*.example.org",
                "under_score.example.net",
                "juice",
                "xn--bcher-kva.example",
            ])
        );
    }

    /// One ACME order covers every name of a site, but the cert was stored and
    /// found under the first name only: www.example.com got the self-signed
    /// fallback while example.com got the real certificate.
    #[test]
    fn a_cert_is_served_for_every_name_in_its_subject_alt_name() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        store
            .load_from_disk(&names(&["example.com", "www.example.com"]))
            .unwrap();
        let cert = rcgen::generate_simple_self_signed(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .unwrap();
        let (pem, key) = (
            cert.serialize_pem().unwrap(),
            cert.serialize_private_key_pem(),
        );
        let mut m = meta("fp-multi");
        m.domain = "example.com".into();
        m.san = vec!["example.com".into()];
        store.install("example.com", &pem, &key, m).unwrap();

        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let apex = leaf(&resolver.select(Some("example.com"), false).unwrap());
        let www = leaf(&resolver.select(Some("WWW.Example.com."), false).unwrap());
        assert_eq!(apex, www, "www.example.com must get the same issued cert");

        // Survives a restart: the names come from the leaf, not the stored key.
        let reloaded = CertStore::new(dir.clone());
        reloaded
            .load_from_disk(&names(&["example.com", "www.example.com"]))
            .unwrap();
        let resolver = SentinelCertResolver::new(Arc::clone(&reloaded));
        assert_eq!(
            leaf(&resolver.select(Some("www.example.com"), false).unwrap()),
            apex
        );

        // Removing the cert stops serving it for every name it carried.
        reloaded.remove("example.com").unwrap();
        let resolver = SentinelCertResolver::new(Arc::clone(&reloaded));
        let after = resolver
            .select(Some("www.example.com"), false)
            .map(|ck| leaf(&ck));
        assert_ne!(after.as_deref(), Some(apex.as_slice()));
    }

    #[test]
    fn an_upload_with_the_wrong_key_or_for_another_name_is_refused() {
        let (pem, key) = self_signed_pem("shop.example.in");
        let (_, other_key) = self_signed_pem("shop.example.in");
        assert!(super::super::acme::check_upload("shop.example.in", &pem, &key).is_ok());
        let wrong_key = super::super::acme::check_upload("shop.example.in", &pem, &other_key);
        assert!(
            wrong_key
                .unwrap_err()
                .to_string()
                .contains("does not belong"),
            "a mismatched key must be refused"
        );
        let wrong_name = super::super::acme::check_upload("pay.example.in", &pem, &key);
        assert!(
            wrong_name
                .unwrap_err()
                .to_string()
                .contains("does not cover pay.example.in"),
            "a cert for another name must be refused"
        );
    }

    fn install_manual(store: &CertStore, domain: &str) {
        let (cert, key) = self_signed_pem(domain);
        let mut m = meta("fp");
        m.domain = domain.into();
        m.san = vec![domain.into()];
        store.install(domain, &cert, &key, m).unwrap();
    }

    /// A configured site served by a live wildcard cert: a handshake gets the
    /// wildcard, so no self-signed key is minted for it and the console lists
    /// no self-signed row claiming otherwise. Removing the wildcard gives the
    /// site its self-signed cert in that call.
    #[test]
    fn a_site_under_a_live_wildcard_gets_no_self_signed_cert_or_row() {
        let dir = tmp_dir();
        let store = CertStore::new(dir.clone());
        store
            .load_from_disk(&names(&["shop.example.com", "api.example.com"]))
            .unwrap();
        // shop already has its self-signed cert when the wildcard arrives.
        store.ensure_site_fallbacks(&["shop.example.com".to_string()]);
        install_manual(&store, "*.example.com");
        let resolver = SentinelCertResolver::new(Arc::clone(&store));
        let wildcard = leaf(&resolver.select(Some("api.example.com"), false).unwrap());

        let missing = store.set_site_names(names(&["shop.example.com", "api.example.com"]));
        assert!(
            missing.is_empty(),
            "minting for wildcard-served sites: {missing:?}"
        );
        assert_eq!(
            store
                .ensure_site_fallbacks(&["api.example.com".to_string()])
                .added,
            0
        );
        assert!(!dir.join("api.example.com").exists());
        let rows: Vec<(String, CertSource)> = store
            .all_meta()
            .into_iter()
            .map(|m| (m.domain, m.source))
            .collect();
        assert_eq!(
            rows,
            vec![("*.example.com".to_string(), CertSource::Manual)],
            "the listing must show what a handshake serves"
        );
        assert_eq!(
            leaf(&resolver.select(Some("shop.example.com"), false).unwrap()),
            wildcard
        );

        store.remove("*.example.com").unwrap();
        let default_cert = leaf(&store.default_cert().unwrap());
        for site in ["shop.example.com", "api.example.com"] {
            let served = leaf(&resolver.select(Some(site), false).unwrap());
            assert_ne!(served, wildcard);
            assert_ne!(served, default_cert, "{site} fell to the default cert");
        }
        assert!(dir.join("api.example.com").join("cert.pem").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_dir(dir: &Path, name: &str, cert: &str, key: &str, meta_json: Option<&str>) {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cert.pem"), cert).unwrap();
        std::fs::write(d.join("key.pem"), key).unwrap();
        if let Some(m) = meta_json {
            std::fs::write(d.join("meta.json"), m).unwrap();
        }
    }

    fn ca_issued_pem(cn: &str) -> (String, String) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new());
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        let ca = rcgen::Certificate::from_params(ca_params).unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec![cn.to_string()]).unwrap();
        (
            leaf.serialize_pem_with_signer(&ca).unwrap(),
            leaf.serialize_private_key_pem(),
        )
    }

    #[test]
    fn self_issued_is_told_apart_from_ca_issued() {
        let (own, _) = self_signed_pem("a.example.com");
        let (issued, _) = ca_issued_pem("b.example.com");
        assert!(pem_is_self_issued(own.as_bytes()));
        assert!(!pem_is_self_issued(issued.as_bytes()));
        assert!(!pem_is_self_issued(b"not a cert"));
    }

    /// What a flood against the old resolver can leave on the volume: a
    /// truncated meta.json (crash or full disk mid-write) and self-issued
    /// certs with no meta.json at all. The first aborted the whole load, so
    /// every operator cert after it in readdir order went unloaded; the second
    /// loaded as a "Manual" operator cert, past the skip.
    #[test]
    fn startup_survives_bad_dirs_and_skips_metaless_leftovers() {
        let dir = tmp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let (junk_c, junk_k) = self_signed_pem("junk.example");
        write_dir(
            &dir,
            "truncated.example",
            &junk_c,
            &junk_k,
            Some("{\"domain\": \"trun"),
        );
        write_dir(&dir, "metaless-junk.example", &junk_c, &junk_k, None);
        let (ca_c, ca_k) = ca_issued_pem("metaless-ca.example.com");
        write_dir(&dir, "metaless-ca.example.com", &ca_c, &ca_k, None);
        let (own_c, own_k) = self_signed_pem("hand.example.com");
        write_dir(&dir, "hand.example.com", &own_c, &own_k, None);
        let (wc_c, wc_k) = self_signed_pem("*.corp.example.com");
        write_dir(&dir, "_wildcard_.corp.example.com", &wc_c, &wc_k, None);
        let (mgmt_c, mgmt_k) = self_signed_pem("console");
        write_dir(&dir, MANAGEMENT_CERT_KEY, &mgmt_c, &mgmt_k, None);
        {
            let old = CertStore::new(dir.clone());
            install_manual(&old, "manual.example.com");
        }

        let store = CertStore::new(dir.clone());
        let loaded = store
            .load_from_disk(&names(&["hand.example.com", "app.corp.example.com"]))
            .expect("one bad directory must not fail the whole load");
        let mut live: Vec<String> = store.live.iter().map(|e| e.key().clone()).collect();
        live.sort();
        assert_eq!(
            live,
            vec![
                "*.corp.example.com",
                MANAGEMENT_CERT_KEY,
                "hand.example.com",
                "manual.example.com",
                "metaless-ca.example.com",
            ]
        );
        assert_eq!(loaded, 5);
        // Skipped, not deleted.
        assert!(dir.join("metaless-junk.example").join("cert.pem").exists());
        assert!(dir.join("truncated.example").join("cert.pem").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mint that fails is retried on the next tick rather than waiting for
    /// the next change to the site list, and reported once, not every tick.
    #[test]
    fn a_failed_mint_is_retried_and_reported_once() {
        let cfg = Arc::new(SentinelConfig {
            sites: vec![site("a", &["a.example.com"]), site("b", &["b.example.com"])],
            ..Default::default()
        });
        let mut sync = SiteSync::default();
        let n = sync.due(Arc::clone(&cfg)).expect("the first look syncs");
        assert_eq!(
            sync.record(n, vec!["a.example.com".into()]),
            vec!["a.example.com".to_string()]
        );

        let n = sync
            .due(Arc::clone(&cfg))
            .expect("same config, but a mint is owed");
        assert!(
            sync.record(n, vec!["a.example.com".into()]).is_empty(),
            "a repeat failure is not reported again"
        );

        let n = sync.due(Arc::clone(&cfg)).expect("still owed");
        assert!(sync.record(n, Vec::new()).is_empty());
        assert!(
            sync.due(Arc::clone(&cfg)).is_none(),
            "nothing owed and nothing changed: quiet"
        );

        // A new config with the same names needs no work either.
        let same = Arc::new(SentinelConfig {
            sites: cfg.sites.clone(),
            ..Default::default()
        });
        assert!(sync.due(same).is_none());
    }
}
