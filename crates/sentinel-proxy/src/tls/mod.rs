//! TLS certificate management for Sentinel.
//!
//! Three cert sources, in priority order:
//!   1. **ACME** (Let's Encrypt / ZeroSSL) — auto-issued and auto-renewed
//!   2. **Manual** — operator-uploaded PEM files
//!   3. **Self-signed fallback** — generated on demand for any unknown domain
//!
//! The `SentinelCertResolver` plugs into rustls `ServerConfig::with_cert_resolver`
//! and hot-swaps certs without restarting any listener.

pub mod acme;
pub mod cert_store;
pub mod renewal;

pub use acme::CertManager;
pub use cert_store::{
    CertMeta, CertSource, CertStore, SentinelCertResolver, generate_self_signed, load_pem_bytes,
};

// Keep AutoCertResolver name so the remaining build_tls_acceptor path in lib.rs compiles.
pub use SentinelCertResolver as AutoCertResolver;