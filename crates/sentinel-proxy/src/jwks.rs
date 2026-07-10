//! JWKS cache — fetches and caches an identity provider's JSON Web Key Set
//! (JWKS) over HTTPS and rotates keys by `kid`.
//!
//! Used by the edge-JWT gate ([`crate::phase1_headers`]) to verify tokens
//! signed with keys the operator does not pin statically (the common
//! OAuth2/OIDC case — Auth0, Keycloak, Entra ID, Okta, …). Keys are cached per
//! endpoint URL with a TTL; a request for a `kid` the cache does not know
//! forces a re-fetch so key rotation is picked up immediately. On a fetch
//! failure the last-known-good key set is reused (fail to last-known-good)
//! rather than locking every request out on a transient blip.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::DecodingKey;
use sentinel_modules::decoding_keys_from_jwks;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// How long a fetched key set is treated as fresh before a re-fetch.
const JWKS_TTL: Duration = Duration::from_secs(300);
/// Hard cap on the JWKS document we will read into memory (defensive).
const JWKS_MAX_BYTES: usize = 512 * 1024;
/// Per-fetch network timeout.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Decoding keys for one endpoint, keyed by JWK `kid`. Shared by `Arc` so a
/// live request never blocks a refresh (and vice versa).
type KeyMap = Arc<HashMap<String, DecodingKey>>;

struct CachedJwks {
    keys: KeyMap,
    fetched: Instant,
}

/// Thread-safe, per-URL JWKS cache with stale-while-error fallback.
pub(crate) struct JwksCache {
    entries: RwLock<HashMap<String, CachedJwks>>,
}

impl JwksCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Return the decoding keys for `url`, keyed by `kid`. The cached copy is
    /// used when it is fresh **and** already contains `wanted_kid` (if given);
    /// otherwise the endpoint is re-fetched. On a fetch failure a stale copy is
    /// returned when one exists, else an empty map (the caller then fails
    /// closed by rejecting the token).
    pub(crate) async fn keys(&self, url: &str, wanted_kid: Option<&str>) -> KeyMap {
        // Fast path: fresh entry that already has the key we need.
        {
            let guard = self.entries.read().await;
            if let Some(entry) = guard.get(url) {
                let fresh = entry.fetched.elapsed() < JWKS_TTL;
                let has_kid = wanted_kid.is_none_or(|k| entry.keys.contains_key(k));
                if fresh && has_kid {
                    return Arc::clone(&entry.keys);
                }
            }
        }
        // Slow path: (re)fetch. Concurrent requests may race here; that is fine
        // — each observes a valid map and the last writer wins the cache slot.
        match Self::fetch(url).await {
            Ok(fetched) => {
                let keys: KeyMap = Arc::new(fetched);
                let mut guard = self.entries.write().await;
                guard.insert(
                    url.to_string(),
                    CachedJwks {
                        keys: Arc::clone(&keys),
                        fetched: Instant::now(),
                    },
                );
                keys
            }
            Err(e) => {
                warn!(jwks_url = url, error = %format!("{e:#}"), "JWKS fetch failed; using stale keys if any");
                let guard = self.entries.read().await;
                guard
                    .get(url)
                    .map(|entry| Arc::clone(&entry.keys))
                    .unwrap_or_default()
            }
        }
    }

    /// GET the JWKS document over HTTPS and parse it into decoding keys.
    async fn fetch(url: &str) -> anyhow::Result<HashMap<String, DecodingKey>> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client: Client<_, http_body_util::combinators::BoxBody<Bytes, hyper::Error>> =
            Client::builder(TokioExecutor::new()).build(https);

        let uri: Uri = url
            .parse()
            .with_context(|| format!("invalid JWKS URL: {url}"))?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("User-Agent", "sentinel-waf/1.0 jwks-fetcher")
            .header("Accept", "application/json")
            .body(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never: std::convert::Infallible| match never {})
                    .boxed(),
            )
            .context("building JWKS request")?;

        let resp = tokio::time::timeout(JWKS_FETCH_TIMEOUT, client.request(req))
            .await
            .context("JWKS request timed out")?
            .context("JWKS HTTP request failed")?;

        if !resp.status().is_success() {
            anyhow::bail!("JWKS endpoint returned HTTP {}", resp.status());
        }

        // Read with a hard size cap so a hostile/broken endpoint cannot OOM us.
        let body = Limited::new(resp.into_body(), JWKS_MAX_BYTES)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("reading JWKS body (>{JWKS_MAX_BYTES} bytes?): {e}"))?
            .to_bytes();

        let keys = decoding_keys_from_jwks(&body);
        debug!(jwks_url = url, keys = keys.len(), "fetched JWKS");
        Ok(keys)
    }
}
