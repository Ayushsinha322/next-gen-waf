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
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, PrivateKeyDer};
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
}

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
        if d <= 0 { "expired" } else if d <= 14 { "critical" } else if d <= 30 { "expiring" } else { "valid" }
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
                let domain = entry.file_name().to_string_lossy().replace("_wildcard_", "*");
                CertMeta {
                    domain: domain.clone(),
                    name: String::new(),
                    san: vec![domain],
                    issued_at: 0,
                    expires_at: 0,
                    fingerprint: String::new(),
                    source: CertSource::Manual,
                }
            };

            match load_pem_files(&cert_file, &key_file) {
                Ok(ck) => {
                    self.live.insert(
                        meta.domain.clone(),
                        Arc::new(CertEntry { key: ck, meta }),
                    );
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(?dir, "failed to load cert: {e}");
                }
            }
        }
        Ok(count)
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
        std::fs::write(dir.join("cert.pem"), cert_pem)?;
        std::fs::write(dir.join("key.pem"), key_pem)?;
        std::fs::write(
            dir.join("meta.json"),
            serde_json::to_string_pretty(&meta)?,
        )?;

        let ck = load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
            .context("loading installed cert into rustls")?;

        self.live.insert(domain.to_string(), Arc::new(CertEntry { key: ck, meta }));
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
        self.live.insert(domain.to_string(), Arc::new(CertEntry { key: ck, meta }));
        Ok(())
    }

    /// All cert metadata (for the dashboard API).
    pub fn all_meta(&self) -> Vec<CertMeta> {
        self.live.iter().map(|e| e.value().meta.clone()).collect()
    }

    pub fn get_meta(&self, domain: &str) -> Option<CertMeta> {
        self.live.get(domain).map(|e| e.value().meta.clone())
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
}

impl std::fmt::Debug for SentinelCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SentinelCertResolver").finish_non_exhaustive()
    }
}

impl SentinelCertResolver {
    pub fn new(store: Arc<CertStore>) -> Arc<Self> {
        Arc::new(Self {
            store,
            fallback: Mutex::new(HashMap::new()),
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
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
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

        // 3. Cached self-signed fallback
        let mut fb = self.fallback.lock().expect("fallback lock");
        if let Some(ck) = fb.get(sni) {
            return Some(Arc::clone(ck));
        }
        let ck = generate_self_signed(sni).ok()?;
        fb.insert(sni.to_string(), Arc::clone(&ck));
        Some(ck)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn generate_self_signed(domain: &str) -> Result<Arc<CertifiedKey>> {
    let names = vec![domain.to_string(), format!("*.{domain}")];
    let cert = rcgen::generate_simple_self_signed(names)
        .context("rcgen generate_simple_self_signed")?;
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

fn domain_to_dirname(domain: &str) -> String {
    domain.replace('*', "_wildcard_").replace(['/', '\\'], "_")
}
