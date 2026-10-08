/// Background cert renewal task.
///
/// Checks every hour; renews any cert whose expiry is within `renew_before_days`
/// (default 30) days.  Runs as a detached tokio task started once at proxy boot.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sentinel_core::config::{ConfigHandle, SiteAcmeConfig, SiteConfig, TlsCertMode};

use super::acme::CertManager;
use super::cert_store::CertStore;

/// How often the loop looks at every ACME site. Cheap: a lookup per name.
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// When to try again after `failures` failed orders in a row: 2, 5 and 15
/// minutes, then hourly. A failed first order (DNS not moved yet, port 80 not
/// forwarded) used to wait for the next hourly pass — up to an hour of the
/// self-signed certificate on a just-cut-over public domain — and every retry
/// after that waited an hour too.
pub(crate) fn retry_delay(failures: u32) -> Duration {
    const STEPS: [u64; 3] = [120, 300, 900];
    Duration::from_secs(
        STEPS
            .get(failures.saturating_sub(1) as usize)
            .copied()
            .unwrap_or(3_600),
    )
}

/// Whether every name already has an issued certificate (ACME or uploaded)
/// that is not due for renewal. Ordering again would only spend the CA's
/// duplicate-certificate allowance (Let's Encrypt: 5 per name set per week).
pub(crate) fn names_already_covered(
    store: &CertStore,
    names: &[String],
    renew_before_days: u32,
) -> bool {
    !names.is_empty()
        && names.iter().all(|d| {
            store
                .get_meta(d)
                .is_some_and(|m| !m.needs_renewal(renew_before_days))
        })
}

/// Reserved / private-use suffixes that no public CA will ever issue for.
///
/// RFC 6761 and RFC 8375 special-use names, plus `.internal` which is now
/// reserved for private use. A site legitimately carries these as internal
/// aliases; they simply are not ACME material.
const NON_PUBLIC_SUFFIXES: [&str; 7] = [
    ".local",
    ".localhost",
    ".internal",
    ".home.arpa",
    ".test",
    ".invalid",
    ".example",
];

/// Whether a public CA could plausibly issue for this name.
///
/// A site's `domains` list is its routing table, not its certificate order: it
/// legitimately holds an IP address, a short internal alias like `juice`, and
/// `localhost` alongside the real hostname. Let's Encrypt rejects the ENTIRE
/// order if any identifier is invalid, so passing the list through unfiltered
/// meant one internal alias silently cost the site its certificate — and the
/// failure repeated every hour, at ERROR, for ever.
///
/// Observed on .71: `["172.16.21.71", "juice", "localhost", "wafdemo.esds.local"]`
/// failed with *Cannot issue for "172.16.21.71": Identifier type is DNS but
/// value is an IP address (and 3 more problems)*.
fn is_acme_eligible(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    // An IP literal is never a DNS identifier. v6 has no dots, so it would also
    // be caught by the single-label test below, but be explicit about both.
    if d.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // Wildcards require a DNS-01 challenge; this issuer does HTTP-01, so an
    // order containing one fails for a different reason but fails just as hard.
    if d.starts_with("*.") {
        return false;
    }
    // Single-label names (`juice`, `localhost`) are not FQDNs.
    if !d.contains('.') {
        return false;
    }
    if NON_PUBLIC_SUFFIXES.iter().any(|s| d.ends_with(s)) {
        return false;
    }
    true
}

/// The subset of a site's domains worth sending to a CA.
pub(crate) fn acme_domains(domains: &[String]) -> Vec<String> {
    domains
        .iter()
        .filter(|d| is_acme_eligible(d))
        .cloned()
        .collect()
}

/// The ACME orders to place at startup: for each ACME site, its orderable names
/// (see `acme_domains`), when any of them has no issued certificate yet. A site
/// with none is left to the renewal loop, which reports it.
///
/// Filtered like renewal, for the same reason: one alias in the order makes the
/// CA reject all of it. Unfiltered, an alias with no cert (`juice`, `localhost`)
/// sent a doomed order at every boot on every node — once a self-signed cert
/// stopped counting as issued, nothing could ever cover it.
pub(crate) fn initial_orders(
    sites: &[SiteConfig],
    store: &CertStore,
) -> Vec<(Vec<String>, SiteAcmeConfig)> {
    sites
        .iter()
        .filter_map(|site| {
            let acme = site
                .tls
                .acme
                .as_ref()
                .filter(|_| site.tls.mode == TlsCertMode::Acme)?;
            let orderable = acme_domains(&site.domains);
            orderable
                .iter()
                .any(|d| store.get_meta(d).is_none())
                .then(|| (orderable, acme.clone()))
        })
        .collect()
}

/// ACME orders whose last attempt failed, keyed by the names ordered together.
///
/// A failing renewal was a log line every retry and nothing else: nothing told
/// anyone until the certificate expired and every client got a TLS error. This
/// is what the heartbeat carries to the control plane, which alerts on it.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct AcmeFailure {
    pub domains: Vec<String>,
    /// Failed orders in a row.
    pub failures: u32,
    /// The last error, shortened.
    pub error: String,
    /// Unix seconds of the first failure in this run.
    pub since: u64,
}

fn acme_failures() -> &'static Mutex<HashMap<String, AcmeFailure>> {
    static F: OnceLock<Mutex<HashMap<String, AcmeFailure>>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record how an order for `domains` went. Every issuance path calls this:
/// the first order at boot and the renewal loop.
pub(crate) fn record_acme_outcome(domains: &[String], outcome: Result<(), &anyhow::Error>) {
    let key = domains.join(",");
    let mut map = acme_failures().lock().unwrap_or_else(|p| p.into_inner());
    match outcome {
        Ok(()) => {
            map.remove(&key);
        }
        Err(e) => {
            let mut error = format!("{e:#}");
            if error.len() > 300 {
                let mut cut = 300;
                while !error.is_char_boundary(cut) {
                    cut -= 1;
                }
                error.truncate(cut);
                error.push('…');
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let entry = map.entry(key).or_insert_with(|| AcmeFailure {
                domains: domains.to_vec(),
                failures: 0,
                error: String::new(),
                since: now,
            });
            entry.failures += 1;
            entry.error = error;
        }
    }
}

/// The failing orders, for the heartbeat and `/healthz`. Empty when every
/// order's last attempt succeeded (or none was made).
pub(crate) fn acme_failures_json() -> serde_json::Value {
    let map = acme_failures().lock().unwrap_or_else(|p| p.into_inner());
    let mut list: Vec<&AcmeFailure> = map.values().collect();
    list.sort_by(|a, b| a.domains.cmp(&b.domains));
    serde_json::to_value(list).unwrap_or_else(|_| serde_json::json!([]))
}

pub async fn renewal_loop(cert_manager: Arc<CertManager>, config_handle: ConfigHandle) {
    // Sites already reported as having nothing issuable. Without this the
    // "skipping" line would repeat hourly and become the same noise it replaces.
    let mut reported_ineligible: HashSet<String> = HashSet::new();
    // Site id → (failed orders in a row, not before). Cleared on success.
    let mut backoff: HashMap<String, (u32, tokio::time::Instant)> = HashMap::new();

    loop {
        tokio::time::sleep(CHECK_INTERVAL).await;
        let cfg = config_handle.load();
        let now = tokio::time::Instant::now();

        for site in &cfg.sites {
            let acme_cfg = match &site.tls.acme {
                Some(a) if site.tls.mode == TlsCertMode::Acme => a,
                _ => continue,
            };

            // Order only the names a CA could actually issue for. The rest of
            // the site's domains keep working over the self-signed fallback.
            let orderable = acme_domains(&site.domains);
            if orderable.is_empty() {
                if reported_ineligible.insert(site.id.clone()) {
                    tracing::warn!(
                        site = %site.id,
                        domains = ?site.domains,
                        "ACME is enabled for this site but none of its domains can be \
                         issued for (IP address, single-label name, or reserved suffix). \
                         Skipping issuance; TLS continues on the self-signed certificate."
                    );
                }
                continue;
            }
            reported_ineligible.remove(&site.id);

            if orderable.len() != site.domains.len() {
                tracing::debug!(
                    site = %site.id,
                    ordering = ?orderable,
                    skipped = site.domains.len() - orderable.len(),
                    "some domains are not ACME-eligible and were left out of the order"
                );
            }

            // Renewal is decided per certificate, but the whole set is ordered
            // together, so only the orderable names are examined.
            for domain in &orderable {
                let meta = match cert_manager.store.get_meta(domain) {
                    Some(m) => m,
                    None => {
                        tracing::info!(domain, "no cert found — triggering initial issuance");
                        order_with_backoff(
                            &cert_manager,
                            &mut backoff,
                            &site.id,
                            now,
                            orderable.clone(),
                            acme_cfg,
                        )
                        .await;
                        break; // domains share one order; break inner loop
                    }
                };

                if meta.needs_renewal(acme_cfg.renew_before_days) {
                    tracing::info!(
                        domain,
                        days_remaining = meta.days_until_expiry(),
                        "cert nearing expiry — renewing"
                    );
                    order_with_backoff(
                        &cert_manager,
                        &mut backoff,
                        &site.id,
                        now,
                        orderable.clone(),
                        acme_cfg,
                    )
                    .await;
                    break;
                }
            }
        }
    }
}

/// Order `domains` unless the site is still backing off from a failure; record
/// the outcome so the next attempt follows `retry_delay`.
async fn order_with_backoff(
    cert_manager: &Arc<CertManager>,
    backoff: &mut HashMap<String, (u32, tokio::time::Instant)>,
    site: &str,
    now: tokio::time::Instant,
    domains: Vec<String>,
    config: &SiteAcmeConfig,
) {
    if backoff
        .get(site)
        .is_some_and(|(_, not_before)| now < *not_before)
    {
        return;
    }
    let result = cert_manager.issue_acme(domains.clone(), config).await;
    record_acme_outcome(&domains, result.as_ref().map(|_| ()));
    match result {
        Ok(()) => {
            backoff.remove(site);
        }
        Err(e) => {
            let failures = backoff.get(site).map_or(0, |(n, _)| *n) + 1;
            let wait = retry_delay(failures);
            tracing::error!(
                ?domains,
                failures,
                retry_in_secs = wait.as_secs(),
                "ACME order failed: {e:#}"
            );
            backoff.insert(site.to_string(), (failures, now + wait));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_order_is_reported_until_it_succeeds() {
        let names = vec!["acme-report-test.example".to_string()];
        let find = || {
            acme_failures_json()
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["domains"] == serde_json::json!(names))
                .cloned()
        };
        let err = anyhow::anyhow!("urn:ietf:params:acme:error:dns: NXDOMAIN looking up A");
        record_acme_outcome(&names, Err(&err));
        record_acme_outcome(&names, Err(&err));
        let f = find().expect("a failing order is in the report");
        assert_eq!(f["failures"], 2);
        assert!(f["error"].as_str().unwrap().contains("NXDOMAIN"));

        let long = anyhow::anyhow!("é".repeat(400));
        record_acme_outcome(&names, Err(&long));
        assert!(find().unwrap()["error"].as_str().unwrap().len() <= 304);

        record_acme_outcome(&names, Ok(()));
        assert!(find().is_none(), "a success clears it");
    }

    #[test]
    fn a_failed_order_is_retried_within_minutes_then_hourly() {
        let secs: Vec<u64> = (1..=5).map(|n| retry_delay(n).as_secs()).collect();
        assert_eq!(secs, vec![120, 300, 900, 3_600, 3_600]);
    }

    #[test]
    fn a_site_whose_names_all_hold_a_valid_issued_cert_is_not_ordered_again() {
        use super::super::cert_store::{CertMeta, CertSource};
        let dir = std::env::temp_dir().join(format!("sk-acme-cover-{}", std::process::id()));
        let store = CertStore::new(dir);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let install = |name: &str, days_left: u64| {
            let c = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
            let meta = CertMeta {
                domain: name.into(),
                name: String::new(),
                san: vec![name.into()],
                issued_at: now,
                expires_at: now + days_left * 86_400,
                fingerprint: format!("fp-{name}"),
                source: CertSource::Acme {
                    provider: "LetsEncrypt".into(),
                    email: "ops@example.in".into(),
                },
                issuer: String::new(),
                key_type: String::new(),
            };
            store
                .install(
                    name,
                    &c.serialize_pem().unwrap(),
                    &c.serialize_private_key_pem(),
                    meta,
                )
                .unwrap();
        };
        install("shop.example.in", 60);
        install("old.example.in", 10);
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(names_already_covered(
            &store,
            &names(&["shop.example.in"]),
            30
        ));
        assert!(!names_already_covered(
            &store,
            &names(&["shop.example.in", "new.example.in"]),
            30
        ));
        assert!(
            !names_already_covered(&store, &names(&["old.example.in"]), 30),
            "due for renewal"
        );
        assert!(!names_already_covered(&store, &[], 30));
    }

    #[test]
    fn ip_addresses_and_internal_aliases_are_not_ordered() {
        // The exact list from .71, which failed the whole order every hour.
        for d in [
            "172.16.21.71",
            "juice",
            "localhost",
            "wafdemo.esds.local",
            "::1",
            "2001:db8::1",
            "box.internal",
            "dev.test",
            "*.example.com",
            "",
            "   ",
        ] {
            assert!(!is_acme_eligible(d), "{d} must not be sent to a CA");
        }
    }

    #[test]
    fn real_public_hostnames_are_ordered() {
        for d in [
            "www.example.com",
            "api.shop.co.uk",
            "a.b.c.d.example.org",
            "EXAMPLE.COM",
            "trailing-dot.example.com.",
        ] {
            assert!(is_acme_eligible(d), "{d} should be orderable");
        }
    }

    #[test]
    fn a_mixed_list_keeps_only_the_issuable_names() {
        let domains: Vec<String> = [
            "172.16.21.71",
            "juice",
            "localhost",
            "shop.example.com",
            "www.example.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            acme_domains(&domains),
            vec![
                "shop.example.com".to_string(),
                "www.example.com".to_string()
            ]
        );
    }

    #[test]
    fn a_site_with_nothing_issuable_yields_an_empty_order() {
        // This is the case that must SKIP rather than fail: previously it sent
        // the whole list, Let's Encrypt rejected it, and the site got no
        // certificate at all — including for names that were perfectly valid.
        let domains: Vec<String> = ["10.0.0.5", "intranet", "box.local"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(acme_domains(&domains).is_empty());
    }

    fn acme_site(id: &str, domains: &[&str]) -> SiteConfig {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "domains": domains,
            "upstream": { "servers": [] },
            "tls": {
                "mode": "acme",
                "acme": { "email": "ops@example.org" },
            },
        }))
        .expect("site config")
    }

    /// The startup order is filtered like renewal. Unfiltered, a site whose
    /// real name was already issued still ordered at every boot because an alias
    /// (`juice`, `localhost`) had no cert — and the CA rejected the whole order.
    #[test]
    fn startup_orders_only_issuable_names_and_only_when_one_is_missing() {
        let dir =
            std::env::temp_dir().join(format!("sentinel-renewal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CertStore::new(dir.clone());
        let cert = rcgen::generate_simple_self_signed(vec!["shop.example.org".into()]).unwrap();
        let meta = super::super::CertMeta {
            domain: "shop.example.org".into(),
            name: String::new(),
            san: vec!["shop.example.org".into()],
            issued_at: 1,
            expires_at: u64::MAX / 2,
            fingerprint: "fp".into(),
            source: super::super::CertSource::Acme {
                provider: "LetsEncrypt".into(),
                email: "ops@example.org".into(),
            },
            issuer: String::new(),
            key_type: String::new(),
        };
        store
            .install(
                "shop.example.org",
                &cert.serialize_pem().unwrap(),
                &cert.serialize_private_key_pem(),
                meta,
            )
            .unwrap();

        // ACME settings present, but the site is not in ACME mode.
        let mut plain = acme_site("plain", &["plain.example.org"]);
        plain.tls.mode = TlsCertMode::SelfSigned;
        let sites = vec![
            acme_site("issued", &["shop.example.org", "juice", "localhost"]),
            acme_site("aliases", &["intranet", "10.0.0.5", "box.local"]),
            acme_site("new", &["new.example.org", "juice"]),
            plain,
        ];
        let orders: Vec<Vec<String>> = initial_orders(&sites, &store)
            .into_iter()
            .map(|(domains, _)| domains)
            .collect();
        assert_eq!(orders, vec![vec!["new.example.org".to_string()]]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
