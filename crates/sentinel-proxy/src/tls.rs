//! Auto-generated TLS certificates for per-site SNI.
//!
//! When a site doesn't have an explicit TLS cert configured, a self-signed
//! certificate is generated on-demand for its domains.  Certificates are
//! cached for the lifetime of the process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;

/// Generate a self-signed certificate for a domain (+ wildcard).
fn generate_certified_key(domain: &str) -> anyhow::Result<Arc<CertifiedKey>> {
    let alt_names = vec![domain.to_string(), format!("*.{}", domain)];

    let cert = rcgen::generate_simple_self_signed(alt_names)
        .context("generating self-signed cert")?;

    let cert_der = cert.serialize_der().context("serializing cert")?;
    let key_der = cert.serialize_private_key_der();

    let pkcs8 = PrivatePkcs8KeyDer::from(key_der);
    let any_der = PrivateKeyDer::Pkcs8(pkcs8.clone_key());

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&any_der)
        .or_else(|_| rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&pkcs8))
        .context("building rustls signing key")?;

    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(cert_der)],
        signing_key,
    )))
}

/// Thread-safe per-domain certificate store.
struct CertStore {
    explicit: HashMap<String, Arc<CertifiedKey>>,
    generated: HashMap<String, Arc<CertifiedKey>>,
}

impl CertStore {
    fn get_or_generate(&mut self, domain: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(ck) = self.explicit.get(domain) {
            return Some(Arc::clone(ck));
        }
        if let Some(ck) = self.generated.get(domain) {
            return Some(Arc::clone(ck));
        }
        let ck = generate_certified_key(domain).ok()?;
        self.generated
            .insert(domain.to_string(), Arc::clone(&ck));
        Some(ck)
    }
}

/// SNI-aware cert resolver that auto-generates certs for unknown domains.
pub struct AutoCertResolver {
    store: Mutex<CertStore>,
}

impl std::fmt::Debug for AutoCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoCertResolver").finish_non_exhaustive()
    }
}

impl AutoCertResolver {
    pub fn new(explicit: HashMap<String, Arc<CertifiedKey>>) -> Self {
        Self {
            store: Mutex::new(CertStore {
                explicit,
                generated: HashMap::new(),
            }),
        }
    }

    /// Pre-warm the cache so the first TLS handshake is fast.
    pub fn pre_warm(&self, domains: &[String]) {
        let mut store = self.store.lock().unwrap();
        for d in domains {
            let _ = store.get_or_generate(d);
        }
    }
}

impl ResolvesServerCert for AutoCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let mut store = self.store.lock().unwrap();
        store.get_or_generate(sni)
    }
}