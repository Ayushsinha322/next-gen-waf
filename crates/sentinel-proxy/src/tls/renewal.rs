/// Background cert renewal task.
///
/// Checks every hour; renews any cert whose expiry is within `renew_before_days`
/// (default 30) days.  Runs as a detached tokio task started once at proxy boot.
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::config::{ConfigHandle, SiteAcmeConfig, TlsCertMode};

use super::acme::CertManager;

const CHECK_INTERVAL: Duration = Duration::from_secs(3_600); // 1 hour

pub async fn renewal_loop(
    cert_manager: Arc<CertManager>,
    config_handle: ConfigHandle,
) {
    loop {
        tokio::time::sleep(CHECK_INTERVAL).await;
        let cfg = config_handle.load();

        for site in &cfg.sites {
            let acme_cfg = match &site.tls.acme {
                Some(a) if site.tls.mode == TlsCertMode::Acme => a,
                _ => continue,
            };

            for domain in &site.domains {
                let meta = match cert_manager.store.get_meta(domain) {
                    Some(m) => m,
                    None => {
                        // No cert at all — issue one
                        tracing::info!(domain, "no cert found — triggering initial issuance");
                        trigger_issuance(&cert_manager, site.domains.clone(), acme_cfg).await;
                        break; // domains share one order; break inner loop
                    }
                };

                if meta.needs_renewal(acme_cfg.renew_before_days) {
                    tracing::info!(
                        domain,
                        days_remaining = meta.days_until_expiry(),
                        "cert nearing expiry — renewing"
                    );
                    trigger_issuance(&cert_manager, site.domains.clone(), acme_cfg).await;
                    break;
                }
            }
        }
    }
}

async fn trigger_issuance(
    cert_manager: &Arc<CertManager>,
    domains: Vec<String>,
    config: &SiteAcmeConfig,
) {
    match cert_manager.issue_acme(domains.clone(), config).await {
        Ok(()) => {}
        Err(e) => {
            tracing::error!(
                ?domains,
                "ACME renewal failed: {e:#}"
            );
        }
    }
}
