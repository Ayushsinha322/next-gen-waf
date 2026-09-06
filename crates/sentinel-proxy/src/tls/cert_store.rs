/// Hot-swappable certificate store with disk persistence.
///
/// Holds live TLS certs per domain (from ACME or manual upload) plus a fallback
/// self-signed generator for domains that have no configured cert.  The
/// `SentinelCertResolver` wraps this and plugs straight into rustls.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
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
}

pub struct CertStore {
    live: DashMap<String, Arc<CertEntry>>,
    /// TLS-ALPN-01 challenge certs: domain → special cert served during challenge.
    alpn_challenge: DashMap<String, Arc<CertifiedKey>>,
    cert_dir: PathBuf,
}

impl CertStore {
    pub fn new(cert_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            live: DashMap::new(),
            alpn_challenge: DashMap::new(),
            cert_dir,
        })
    }

    /// Load all persisted certs from `cert_dir/{domain}/` on startup.
    pub fn load_from_disk(&self) -> Result<usize> {
        std::fs::create_dir_all(&self.cert_dir)
            .with_context(|| format!("creating cert dir: {}", self.cert_dir.display()))?;

        let mut count = 0;
        for entry in std::fs::read_dir(&self.cert_dir)
            .with_context(|| format!("reading cert dir: {}", self.cert_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let dir = entry.path();
            let cert_file = dir.join("cert.pem");
            let key_file = dir.join("key.pem");
            if !cert_file.exists() || !key_file.exists() {
                continue;
            }

            let meta_file = dir.join("meta.json");
            let meta: CertMeta = if meta_file.exists() {
                serde_json::from_str(&std::fs::read_to_string(&meta_file)?)?
            } else {
                let domain = entry
                    .file_name()
                    .to_string_lossy()
                    .replace("_wildcard_", "*");
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

            match load_pem_files(&cert_file, &key_file) {
                Ok(ck) => {
                    self.live
                        .insert(meta.domain.clone(), Arc::new(CertEntry { key: ck, meta }));
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(?dir, "failed to load cert: {e}");
                }
            }
        }
        Ok(count)
    }

    /// Return the shared self-signed cert for `domain`, creating it once if no
    /// node has yet.
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
    pub fn self_signed_shared(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // Someone — possibly this process, at boot — already has it.
        if let Some(e) = self.live.get(domain) {
            return Some(Arc::clone(&e.key));
        }

        let dir = self.cert_dir.join(domain_to_dirname(domain));
        let cert_file = dir.join("cert.pem");
        let key_file = dir.join("key.pem");

        // Another node may have written it since this process started.
        if cert_file.exists() && key_file.exists() {
            if let Ok(ck) = load_pem_files(&cert_file, &key_file) {
                self.remember_self_signed(domain, Arc::clone(&ck));
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
        let ck = load_pem_files(&cert_file, &key_file)
            .or_else(|_| load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes()))
            .ok()?;
        self.remember_self_signed(domain, Arc::clone(&ck));
        Some(ck)
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
        let meta = CertMeta {
            domain: domain.to_string(),
            name: String::new(),
            san: vec![domain.to_string(), format!("*.{domain}")],
            issued_at: 0,
            expires_at: 0,
            fingerprint: String::new(),
            source: CertSource::SelfSigned,
            issuer: String::new(),
            key_type: String::new(),
        };
        self.live
            .insert(domain.to_string(), Arc::new(CertEntry { key: ck, meta }));
    }

    /// Install a cert from PEM strings (from ACME or manual upload).
    /// Hot-swaps immediately — no restart required.
    pub fn install(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        meta: CertMeta,
    ) -> Result<()> {
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

        let ck = load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
            .context("loading installed cert into rustls")?;

        self.live
            .insert(domain.to_string(), Arc::new(CertEntry { key: ck, meta }));
        tracing::info!(domain, "TLS cert installed and hot-swapped");
        Ok(())
    }

    pub fn remove(&self, domain: &str) -> Result<()> {
        self.live.remove(domain);
        let dir = self.cert_dir.join(domain_to_dirname(domain));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
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
        self.live
            .insert(domain.to_string(), Arc::new(CertEntry { key: ck, meta }));
        Ok(())
    }

    /// All cert metadata for the customer cert repository (the dashboard API).
    /// Internal/reserved certs (e.g. the management cert) are hidden so they
    /// can't be listed, renamed, or deleted from the customer cert page.
    pub fn all_meta(&self) -> Vec<CertMeta> {
        self.live
            .iter()
            .filter(|e| !e.key().starts_with(RESERVED_PREFIX))
            .map(|e| e.value().meta.clone())
            .collect()
    }

    pub fn get_meta(&self, domain: &str) -> Option<CertMeta> {
        self.live.get(domain).map(|e| e.value().meta.clone())
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
        self.live.insert(
            MANAGEMENT_CERT_KEY.to_string(),
            Arc::new(CertEntry { key: ck, meta }),
        );
        tracing::info!("management TLS cert installed and hot-swapped");
        Ok(prev_fp)
    }

    /// Revert the management cert to the built-in self-signed default (removes
    /// the uploaded management cert from disk + the live store).
    pub fn revert_management(&self) -> Result<()> {
        self.remove(MANAGEMENT_CERT_KEY)
    }

    // ── TLS-ALPN-01 challenge helpers ─────────────────────────────────────────

    pub fn set_alpn_challenge(&self, domain: &str, ck: Arc<CertifiedKey>) {
        self.alpn_challenge.insert(domain.to_string(), ck);
    }

    pub fn clear_alpn_challenge(&self, domain: &str) {
        self.alpn_challenge.remove(domain);
    }

    // ── internal resolvers ────────────────────────────────────────────────────

    fn resolve_live(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        // Exact match
        if let Some(e) = self.live.get(sni) {
            return Some(Arc::clone(&e.value().key));
        }
        // Wildcard: *.example.com covers sub.example.com
        if let Some(parent) = sni.split_once('.').map(|(_, rest)| format!("*.{rest}")) {
            if let Some(e) = self.live.get(&parent) {
                return Some(Arc::clone(&e.value().key));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// SentinelCertResolver — plugs into rustls ServerConfig::with_cert_resolver
// ---------------------------------------------------------------------------

pub struct SentinelCertResolver {
    store: Arc<CertStore>,
    /// Self-signed fallback (generated once per domain, cached).
    fallback: Mutex<HashMap<String, Arc<CertifiedKey>>>,
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
    pub fn new(store: Arc<CertStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            fallback: Mutex::new(HashMap::new()),
            fixed_key: None,
        })
    }

    /// Resolver that always serves the cert stored under `key` (ignoring SNI),
    /// falling back to a self-signed cert for `key` until one is uploaded. This
    /// backs the management listener: it's a single-purpose HTTPS endpoint, so
    /// there's no SNI multiplexing — one cert, hot-swappable.
    pub fn new_fixed(store: Arc<CertStore>, key: &str) -> Arc<Self> {
        Arc::new(Self {
            store,
            fallback: Mutex::new(HashMap::new()),
            fixed_key: Some(key.to_string()),
        })
    }

    /// Pre-warm the self-signed fallback cache for known domains.
    pub fn pre_warm(&self, domains: &[String]) {
        let mut fb = self.fallback.lock().expect("fallback lock");
        for d in domains {
            if self.store.resolve_live(d).is_none() {
                if let Ok(ck) = generate_self_signed(d) {
                    fb.insert(d.clone(), ck);
                }
            }
        }
    }
}

impl ResolvesServerCert for SentinelCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Fixed-key mode (management listener): always serve the one configured
        // cert, regardless of SNI, with a self-signed fallback until uploaded.
        if let Some(key) = &self.fixed_key {
            if let Some(ck) = self.store.resolve_live(key) {
                return Some(ck);
            }
            {
                let fb = self.fallback.lock().expect("fallback lock");
                if let Some(ck) = fb.get(key) {
                    return Some(Arc::clone(ck));
                }
            }
            // Persisted and shared, like the site fallback below. This used to be
            // a per-process in-memory cert, so every data-plane restart minted a
            // new management cert and every roll put the browser's certificate
            // warning back on the console. Now the first node to need it writes
            // it to the cert volume and every node — and every restart — serves
            // the same bytes until an operator uploads a real one.
            let ck = self.store.self_signed_shared(key)?;
            self.fallback
                .lock()
                .expect("fallback lock")
                .insert(key.clone(), Arc::clone(&ck));
            return Some(ck);
        }

        // Clients connecting by bare IP (and some older clients) send no SNI.
        // Serve a stable default self-signed cert so the handshake still
        // completes — Host-header routing then selects the site. Without this,
        // returning None here would abort the handshake and break IP access.
        let sni = client_hello.server_name().unwrap_or("default");

        // 1. TLS-ALPN-01 challenge takes highest priority
        let is_acme_alpn = client_hello
            .alpn()
            .map(|mut it| it.any(|p| p == b"acme-tls/1"))
            .unwrap_or(false);
        if is_acme_alpn {
            if let Some(ck) = self.store.alpn_challenge.get(sni) {
                return Some(Arc::clone(ck.value()));
            }
        }

        // 2. Live ACME / manual cert
        if let Some(ck) = self.store.resolve_live(sni) {
            return Some(ck);
        }

        // 3. Self-signed fallback, SHARED across the fleet.
        //
        // Was a per-process in-memory cache, which meant three nodes served
        // three different certificates for the same name — invisible while one
        // node owned :443, and a browser warning on every other request once the
        // load balancer began spreading it. Now the first node to need a name
        // persists the cert to the shared volume and the others adopt it.
        {
            let fb = self.fallback.lock().expect("fallback lock");
            if let Some(ck) = fb.get(sni) {
                return Some(Arc::clone(ck));
            }
        }
        let ck = self.store.self_signed_shared(sni)?;
        self.fallback
            .lock()
            .expect("fallback lock")
            .insert(sni.to_string(), Arc::clone(&ck));
        Some(ck)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed cert for `domain` and return it as PEM.
///
/// Exists so the fallback cert can be PERSISTED. Before this, the fallback was
/// generated per process and held only in memory, which is invisible on one node
/// and wrong on three: each node invented its own certificate for the same name,
/// so a client was served a different cert depending on which node the load
/// balancer picked. Measured on .71 the moment HTTPS moved behind the LB — 12
/// handshakes returned exactly 3 distinct certificates, 4 each.
pub fn generate_self_signed_pem(domain: &str) -> Result<(String, String)> {
    let names = vec![domain.to_string(), format!("*.{domain}")];
    let cert =
        rcgen::generate_simple_self_signed(names).context("rcgen generate_simple_self_signed")?;
    Ok((
        cert.serialize_pem().context("serialize cert PEM")?,
        cert.serialize_private_key_pem(),
    ))
}

pub fn generate_self_signed(domain: &str) -> Result<Arc<CertifiedKey>> {
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

        // Revert removes it → resolver falls back to self-signed.
        store.revert_management().unwrap();
        assert!(store.get_meta(MANAGEMENT_CERT_KEY).is_none());
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
}
