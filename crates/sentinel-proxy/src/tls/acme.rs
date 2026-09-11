/// ACME (RFC 8555) certificate manager — zero new dependencies.
///
/// Uses ring (ES256/P-256), hyper-rustls (HTTPS), rcgen 0.12 (CSR), sha2.
/// Supports HTTP-01 and TLS-ALPN-01 challenges.
/// Providers: Let's Encrypt production/staging, ZeroSSL.
///
/// All resource fetches use POST-as-GET (signed POST with an empty payload), as
/// required by RFC 8555 §6.3 — plain GET is rejected by Let's Encrypt v2.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use sentinel_core::config::{AcmeChallengeType, AcmeProvider, SiteAcmeConfig};

use super::cert_store::{CertMeta, CertSource, CertStore};

/// HTTPS client used for all ACME traffic (single body type keeps signatures simple).
type AcmeHttp = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

fn build_https_client() -> AcmeHttp {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

// ---------------------------------------------------------------------------
// CertManager
// ---------------------------------------------------------------------------

pub struct CertManager {
    pub store: Arc<CertStore>,
    /// HTTP-01 challenge tokens shared with the proxy request handler.
    pub http01_tokens: Arc<DashMap<String, String>>,
    cert_dir: PathBuf,
}

impl CertManager {
    pub fn new(cert_dir: PathBuf) -> Arc<Self> {
        let store = CertStore::new(cert_dir.clone());
        Arc::new(Self {
            store,
            http01_tokens: Arc::new(DashMap::new()),
            cert_dir,
        })
    }

    pub fn load_from_disk(&self) -> Result<usize> {
        self.store.load_from_disk()
    }

    /// Issue (or renew) a certificate for `domains` via ACME.
    pub async fn issue_acme(
        self: &Arc<Self>,
        domains: Vec<String>,
        config: &SiteAcmeConfig,
    ) -> Result<()> {
        let mut client = AcmeClient::new_or_load(&self.cert_dir, config).await?;
        let (cert_pem, key_pem, expires_at) = client
            .issue(
                &domains,
                &config.challenge,
                &self.http01_tokens,
                &self.store,
            )
            .await?;

        let primary = domains.first().cloned().unwrap_or_default();
        let meta = CertMeta {
            domain: primary.clone(),
            name: String::new(),
            san: domains,
            issued_at: unix_now(),
            expires_at,
            fingerprint: fingerprint(&cert_pem),
            source: CertSource::Acme {
                provider: format!("{:?}", config.provider),
                email: config.email.clone(),
            },
            issuer: String::new(),
            key_type: String::new(),
        };
        self.store.install(&primary, &cert_pem, &key_pem, meta)
    }

    /// Upload a PEM cert + key that the operator provides manually.
    /// `name` is an optional friendly profile label (empty = use domain).
    pub fn install_manual(
        &self,
        domain: &str,
        name: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<()> {
        let expires_at = parse_expiry(cert_pem).unwrap_or(unix_now() + 90 * 86_400);
        let meta = CertMeta {
            domain: domain.to_string(),
            name: name.to_string(),
            san: vec![domain.to_string()],
            issued_at: unix_now(),
            expires_at,
            fingerprint: fingerprint(cert_pem),
            source: CertSource::Manual,
            issuer: String::new(),
            key_type: String::new(),
        };
        self.store.install(domain, cert_pem, key_pem, meta)
    }
}

// ---------------------------------------------------------------------------
// ACME account key (ring P-256), persisted as PKCS#8 DER
// ---------------------------------------------------------------------------

struct AcmeKey {
    pair: EcdsaKeyPair,
    pkcs8_der: Vec<u8>,
}

impl AcmeKey {
    fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("ACME key generation failed"))?;
        let pkcs8_der = pkcs8.as_ref().to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_der, &rng)
            .map_err(|_| anyhow!("failed to parse generated ACME key"))?;
        Ok(Self { pair, pkcs8_der })
    }

    fn from_der(der: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|_| anyhow!("invalid PKCS#8 ACME key"))?;
        Ok(Self {
            pair,
            pkcs8_der: der.to_vec(),
        })
    }

    /// JWK (public key) for the JWS `jwk` protected header.
    fn jwk(&self) -> serde_json::Value {
        let pk = self.pair.public_key().as_ref();
        // Uncompressed point: 0x04 || X(32) || Y(32)
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(&pk[1..33]),
            "y": b64url(&pk[33..65]),
        })
    }

    /// RFC 7638 JWK thumbprint (SHA-256 of canonical JWK).
    fn thumbprint(&self) -> String {
        let pk = self.pair.public_key().as_ref();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            b64url(&pk[1..33]),
            b64url(&pk[33..65]),
        );
        b64url(Sha256::digest(canonical.as_bytes()))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, message)
            .map_err(|_| anyhow!("ES256 signing failed"))?;
        Ok(sig.as_ref().to_vec())
    }
}

// ---------------------------------------------------------------------------
// ACME HTTP client (JWS + nonce management)
// ---------------------------------------------------------------------------

struct AcmeClient {
    key: AcmeKey,
    kid: Option<String>, // account URL, set after newAccount
    nonce: Option<String>,
    directory: AcmeDirectory,
    http: AcmeHttp,
}

#[derive(Deserialize)]
struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

impl AcmeClient {
    async fn new_or_load(cert_dir: &PathBuf, config: &SiteAcmeConfig) -> Result<Self> {
        std::fs::create_dir_all(cert_dir)?;
        let http = build_https_client();

        // Fetch the ACME directory (plain GET is allowed for the directory).
        let dir_url = directory_url(config)?;
        let dir_json = http_get_json(&http, dir_url).await?;
        let directory: AcmeDirectory =
            serde_json::from_value(dir_json).context("parsing ACME directory")?;

        // Load or create the account key (persisted as PKCS#8 DER).
        let account_file = cert_dir.join(format!(
            "acme_account_{}.key",
            slug(&format!("{:?}_{}", config.provider, config.email))
        ));
        let key = if account_file.exists() {
            AcmeKey::from_der(&std::fs::read(&account_file)?)?
        } else {
            let k = AcmeKey::generate()?;
            // The ACME account key is private key material — write it 0600
            // (atomic), not at the world-readable process umask default.
            super::cert_store::write_atomic(&account_file, &k.pkcs8_der)?;
            k
        };

        let mut client = Self {
            key,
            kid: None,
            nonce: None,
            directory,
            http,
        };

        // Register (or look up) the account — newAccount is idempotent.
        let new_account_url = client.directory.new_account.clone();
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", config.email)],
        });
        let resp = client.post_jws_jwk(&new_account_url, &payload).await?;
        client.kid = Some(
            resp.location
                .ok_or_else(|| anyhow!("newAccount returned no Location header"))?,
        );
        tracing::debug!(email = %config.email, "ACME account ready");

        Ok(client)
    }

    /// Full issuance flow: order → challenges → finalize → download.
    async fn issue(
        &mut self,
        domains: &[String],
        challenge_type: &AcmeChallengeType,
        http01_tokens: &Arc<DashMap<String, String>>,
        store: &Arc<CertStore>,
    ) -> Result<(String, String, u64)> {
        // 1. New order
        let identifiers: Vec<serde_json::Value> = domains
            .iter()
            .map(|d| serde_json::json!({"type": "dns", "value": d}))
            .collect();
        let new_order_url = self.directory.new_order.clone();
        let order_resp = self
            .post_jws_kid(
                &new_order_url,
                Some(&serde_json::json!({"identifiers": identifiers})),
            )
            .await?;
        let order_url = order_resp
            .location
            .clone()
            .ok_or_else(|| anyhow!("newOrder returned no Location header"))?;
        let order: OrderResp = order_resp.json().context("parsing order")?;

        // 2. Satisfy each authorization
        let acme_chtype = match challenge_type {
            AcmeChallengeType::Http01 => "http-01",
            AcmeChallengeType::TlsAlpn01 => "tls-alpn-01",
        };
        let mut challenge_urls = Vec::new();
        let mut cleanup: Vec<CleanupAction> = Vec::new();

        for authz_url in &order.authorizations {
            let authz: AuthzResp = self
                .post_as_get(authz_url)
                .await?
                .json()
                .context("parsing authz")?;
            if authz.identifier.kind != "dns" {
                return Err(anyhow!(
                    "unsupported identifier type: {}",
                    authz.identifier.kind
                ));
            }
            let domain = authz.identifier.value.clone();

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.kind == acme_chtype)
                .ok_or_else(|| anyhow!("CA did not offer {acme_chtype} for {domain}"))?;

            let token = challenge
                .token
                .clone()
                .ok_or_else(|| anyhow!("{acme_chtype} challenge for {domain} carries no token"))?;
            let key_auth = format!("{}.{}", token, self.key.thumbprint());

            match challenge_type {
                AcmeChallengeType::Http01 => {
                    http01_tokens.insert(token.clone(), key_auth);
                    cleanup.push(CleanupAction::Http01(token.clone()));
                    tracing::debug!(domain, token = %token, "HTTP-01 token armed");
                }
                AcmeChallengeType::TlsAlpn01 => {
                    let digest: [u8; 32] = Sha256::digest(key_auth.as_bytes()).into();
                    let alpn = build_alpn_cert(&domain, &digest)?;
                    store.set_alpn_challenge(&domain, alpn);
                    cleanup.push(CleanupAction::Alpn(domain.clone()));
                    tracing::debug!(domain, "TLS-ALPN-01 challenge cert armed");
                }
            }
            challenge_urls.push(challenge.url.clone());
        }

        // 3. Tell the CA each challenge is ready (signed POST with empty object `{}`).
        for url in &challenge_urls {
            self.post_jws_kid(url, Some(&serde_json::json!({}))).await?;
        }

        // 4. Poll the order until `ready` (120s budget).
        let finalize_url = {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let o: OrderResp = self.post_as_get(&order_url).await?.json()?;
                match o.status.as_str() {
                    "ready" | "valid" => {
                        break o
                            .finalize
                            .ok_or_else(|| anyhow!("order missing finalize URL"))?
                    }
                    "invalid" => {
                        self.run_cleanup(&cleanup, http01_tokens, store);
                        return Err(anyhow!("ACME order marked invalid"));
                    }
                    _ => {}
                }
                if tokio::time::Instant::now() > deadline {
                    self.run_cleanup(&cleanup, http01_tokens, store);
                    return Err(anyhow!("ACME challenge validation timed out (120s)"));
                }
            }
        };
        self.run_cleanup(&cleanup, http01_tokens, store);

        // 5. Generate the cert key + CSR (rcgen 0.12).
        let mut params = rcgen::CertificateParams::new(domains.to_vec());
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params).context("building CSR cert")?;
        let csr_der = cert.serialize_request_der().context("serializing CSR")?;
        let key_pem = cert.serialize_private_key_pem();

        // 6. Finalize the order with the CSR.
        self.post_jws_kid(
            &finalize_url,
            Some(&serde_json::json!({"csr": b64url(&csr_der)})),
        )
        .await?;

        // 7. Poll the order for the issued certificate URL (60s budget).
        let cert_url = {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let o: OrderResp = self.post_as_get(&order_url).await?.json()?;
                if let Some(c) = o.certificate {
                    break c;
                }
                if o.status == "invalid" {
                    return Err(anyhow!("order became invalid during finalization"));
                }
                if tokio::time::Instant::now() > deadline {
                    return Err(anyhow!("timed out waiting for certificate issuance"));
                }
            }
        };

        // 8. Download the full chain (PEM) via POST-as-GET.
        let cert_chain = self.post_as_get(&cert_url).await?.text;
        let expires_at = parse_expiry(&cert_chain).unwrap_or(unix_now() + 90 * 86_400);
        Ok((cert_chain, key_pem, expires_at))
    }

    // ── JWS request helpers ───────────────────────────────────────────────────

    /// POST a JWS with a `jwk` protected header (used only for newAccount).
    async fn post_jws_jwk(&mut self, url: &str, payload: &serde_json::Value) -> Result<AcmeResp> {
        let nonce = self.fresh_nonce().await?;
        let header = serde_json::json!({
            "alg": "ES256",
            "jwk": self.key.jwk(),
            "nonce": nonce,
            "url": url,
        });
        self.post_jws(url, &header, Some(payload)).await
    }

    /// POST a JWS with a `kid` protected header. `payload: None` is a POST-as-GET.
    async fn post_jws_kid(
        &mut self,
        url: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<AcmeResp> {
        let kid = self
            .kid
            .clone()
            .ok_or_else(|| anyhow!("no ACME account KID"))?;
        let nonce = self.fresh_nonce().await?;
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": kid,
            "nonce": nonce,
            "url": url,
        });
        self.post_jws(url, &header, payload).await
    }

    /// POST-as-GET: signed POST with an empty payload string (RFC 8555 §6.3).
    async fn post_as_get(&mut self, url: &str) -> Result<AcmeResp> {
        self.post_jws_kid(url, None).await
    }

    async fn post_jws(
        &mut self,
        url: &str,
        header: &serde_json::Value,
        payload: Option<&serde_json::Value>,
    ) -> Result<AcmeResp> {
        let protected = b64url(header.to_string().as_bytes());
        // POST-as-GET (payload = None) uses an empty payload string.
        let payload_b64 = match payload {
            Some(p) => b64url(p.to_string().as_bytes()),
            None => String::new(),
        };
        let signing_input = format!("{protected}.{payload_b64}");
        let sig = self.key.sign(signing_input.as_bytes())?;
        let jws = serde_json::json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": b64url(&sig),
        });

        let req = http::Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", "application/jose+json")
            .body(Full::new(Bytes::from(jws.to_string())))
            .context("building ACME JWS request")?;

        let resp = self.http.request(req).await.context("ACME POST failed")?;

        if let Some(n) = header_str(&resp, "replay-nonce") {
            self.nonce = Some(n);
        }
        let location = header_str(&resp, "location");
        let status = resp.status();
        let body_bytes = resp.collect().await?.to_bytes();
        let text = String::from_utf8_lossy(&body_bytes).into_owned();

        if !status.is_success() {
            let detail = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                .ok()
                .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(String::from))
                .unwrap_or_else(|| text.clone());
            return Err(anyhow!("ACME error {}: {detail}", status.as_u16()));
        }

        Ok(AcmeResp { text, location })
    }

    async fn fresh_nonce(&mut self) -> Result<String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let req = http::Request::builder()
            .method("HEAD")
            .uri(&self.directory.new_nonce)
            .body(Full::new(Bytes::new()))
            .context("building newNonce request")?;
        let resp = self.http.request(req).await.context("newNonce failed")?;
        header_str(&resp, "replay-nonce")
            .ok_or_else(|| anyhow!("no Replay-Nonce header in newNonce response"))
    }

    fn run_cleanup(
        &self,
        actions: &[CleanupAction],
        http01_tokens: &Arc<DashMap<String, String>>,
        store: &Arc<CertStore>,
    ) {
        for a in actions {
            match a {
                CleanupAction::Http01(token) => {
                    http01_tokens.remove(token);
                }
                CleanupAction::Alpn(domain) => store.clear_alpn_challenge(domain),
            }
        }
    }
}

enum CleanupAction {
    Http01(String),
    Alpn(String),
}

struct AcmeResp {
    text: String,
    /// Location header (order URL / account URL).
    location: Option<String>,
}

impl AcmeResp {
    fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.text).context("parsing ACME JSON response")
    }
}

#[derive(Deserialize)]
struct OrderResp {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: Option<String>,
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct AuthzResp {
    identifier: AcmeIdentifier,
    challenges: Vec<AcmeChallenge>,
}

#[derive(Deserialize)]
struct AcmeIdentifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    kind: String,
    /// Optional: newer challenge types (e.g. `dns-persist-01`) carry no token.
    /// Always present for http-01 / dns-01 / tls-alpn-01.
    #[serde(default)]
    token: Option<String>,
    url: String,
}

// ---------------------------------------------------------------------------
// TLS-ALPN-01 challenge cert (RFC 8737, id-pe-acmeIdentifier OID)
// ---------------------------------------------------------------------------

fn build_alpn_cert(
    domain: &str,
    key_auth_digest: &[u8; 32],
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    // Extension value = DER OCTET STRING { 32-byte SHA-256(keyAuthorization) }
    let mut ext_value = Vec::with_capacity(34);
    ext_value.push(0x04); // OCTET STRING tag
    ext_value.push(0x20); // length = 32
    ext_value.extend_from_slice(key_auth_digest);

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let mut ext =
        rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 31], ext_value);
    ext.set_criticality(true);
    params.custom_extensions = vec![ext];

    let cert = rcgen::Certificate::from_params(params).context("ALPN challenge cert")?;
    let cert_pem = cert.serialize_pem().context("serializing ALPN cert")?;
    let key_pem = cert.serialize_private_key_pem();

    super::cert_store::load_pem_bytes(cert_pem.as_bytes(), key_pem.as_bytes())
        .context("loading ALPN challenge cert into rustls")
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async fn http_get_json(client: &AcmeHttp, url: &str) -> Result<serde_json::Value> {
    let req = http::Request::builder()
        .method("GET")
        .uri(url)
        .header("Accept", "application/json")
        .body(Full::new(Bytes::new()))
        .context("building GET request")?;
    let resp = client.request(req).await.context("ACME GET failed")?;
    let body = resp.collect().await?.to_bytes();
    serde_json::from_slice(&body).context("parsing ACME JSON response")
}

fn header_str<B>(resp: &http::Response<B>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// The ACME directory URL to use: an explicit `ca_server` wins over the
/// `provider` enum.
///
/// Pure and separate from the client so it can be tested — the selection used to
/// be one line inside an async fn that immediately fetched the URL, which meant
/// the only way to check it was to make a network request.
///
/// Only an authenticated administrator of this deployment can set `ca_server`,
/// and choosing a CA is their decision. But it is an outbound URL this node will
/// fetch and whose certificates it will then serve, so the scheme is verified
/// instead of trusted.
///
/// **https only.** `build_https_client` is built with `.https_only()`, so an
/// `http://` directory would be accepted here and then refused by the connector
/// — which is the same store-it-and-ignore-it failure this field was fixed for.
/// Rejecting it here makes the refusal say why.
fn directory_url(config: &SiteAcmeConfig) -> anyhow::Result<&str> {
    let u = config.ca_server.trim();
    if u.is_empty() {
        return Ok(provider_url(&config.provider));
    }
    if !u.starts_with("https://") {
        anyhow::bail!(
            "acme ca_server must be an https:// URL (the ACME HTTP client is https-only), \
             got {u:?} — refusing to use it"
        );
    }
    Ok(u)
}

fn provider_url(provider: &AcmeProvider) -> &'static str {
    match provider {
        AcmeProvider::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
        AcmeProvider::LetsEncryptStaging => {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        }
        AcmeProvider::ZeroSsl => "https://acme.zerossl.com/v2/DV90",
    }
}

/// Base64url without padding, as required by JOSE/ACME.
fn b64url(data: impl AsRef<[u8]>) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let data = data.as_ref();
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let v = ((c[0] as usize) << 16) | ((c[1] as usize) << 8) | (c[2] as usize);
        out.push(TABLE[(v >> 18) & 63] as char);
        out.push(TABLE[(v >> 12) & 63] as char);
        out.push(TABLE[(v >> 6) & 63] as char);
        out.push(TABLE[v & 63] as char);
    }
    match chunks.remainder() {
        [a, b] => {
            let v = ((*a as usize) << 16) | ((*b as usize) << 8);
            out.push(TABLE[(v >> 18) & 63] as char);
            out.push(TABLE[(v >> 12) & 63] as char);
            out.push(TABLE[(v >> 6) & 63] as char);
        }
        [a] => {
            let v = (*a as usize) << 16;
            out.push(TABLE[(v >> 18) & 63] as char);
            out.push(TABLE[(v >> 12) & 63] as char);
        }
        _ => {}
    }
    out
}

/// Best-effort certificate expiry parse. Walks the leaf cert's DER to find the
/// notAfter time; falls back to a 90-day estimate if the structure can't be parsed.
fn parse_expiry(cert_pem: &str) -> Option<u64> {
    use rustls::pki_types::CertificateDer;
    let der: CertificateDer<'_> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
            .next()?
            .ok()?;
    der_not_after(der.as_ref())
}

/// Minimal ASN.1 DER walk to extract the certificate's notAfter time.
/// Returns a UNIX timestamp; conservative — returns None on anything unexpected.
fn der_not_after(der: &[u8]) -> Option<u64> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... validity SEQUENCE {..} } }
    let cert_inner = der_seq_content(der, 0)?;
    let tbs_inner = der_seq_content(cert_inner, 0)?;
    // Scan tbsCertificate's top-level elements for the first SEQUENCE whose content
    // is exactly two time values — that's `validity`.
    let mut pos = 0usize;
    while pos < tbs_inner.len() {
        let tag = tbs_inner[pos];
        let (len, hdr) = der_len(tbs_inner, pos + 1)?;
        let cs = pos + 1 + hdr;
        let ce = cs + len;
        if ce > tbs_inner.len() {
            return None;
        }
        if tag == 0x30 {
            if let Some(ts) = validity_not_after(&tbs_inner[cs..ce]) {
                return Some(ts);
            }
        }
        pos = ce;
    }
    None
}

/// Given the content of a candidate `validity` SEQUENCE (two time values), return notAfter.
fn validity_not_after(buf: &[u8]) -> Option<u64> {
    let mut pos = 0usize;
    let mut times = Vec::new();
    while pos < buf.len() && times.len() < 2 {
        let tag = buf[pos];
        let (len, hdr) = der_len(buf, pos + 1)?;
        let cs = pos + 1 + hdr;
        let ce = cs + len;
        if ce > buf.len() {
            return None;
        }
        // 0x17 = UTCTime, 0x18 = GeneralizedTime
        if tag == 0x17 || tag == 0x18 {
            times.push((tag, &buf[cs..ce]));
        } else {
            return None; // not a validity sequence
        }
        pos = ce;
    }
    if times.len() != 2 {
        return None;
    }
    let (tag, bytes) = times[1];
    parse_asn1_time(tag, bytes)
}

fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(bytes).ok()?;
    // UTCTime: YYMMDDHHMMSSZ ; GeneralizedTime: YYYYMMDDHHMMSSZ
    let (year, rest) = if tag == 0x17 {
        let yy: i64 = s.get(0..2)?.parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &s[2..])
    } else {
        let yyyy: i64 = s.get(0..4)?.parse().ok()?;
        (yyyy, &s[4..])
    };
    let month: i64 = rest.get(0..2)?.parse().ok()?;
    let day: i64 = rest.get(2..4)?.parse().ok()?;
    let hour: i64 = rest.get(4..6)?.parse().ok()?;
    let min: i64 = rest.get(6..8)?.parse().ok()?;
    let sec: i64 = rest.get(8..10)?.parse().ok()?;
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    Some(secs.max(0) as u64)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Return the content slice of a DER SEQUENCE located at `pos`.
fn der_seq_content(buf: &[u8], pos: usize) -> Option<&[u8]> {
    if pos >= buf.len() || buf[pos] != 0x30 {
        return None;
    }
    let (len, hdr) = der_len(buf, pos + 1)?;
    let cs = pos + 1 + hdr;
    let ce = cs + len;
    if ce > buf.len() {
        return None;
    }
    Some(&buf[cs..ce])
}

/// Decode a DER length at `pos`, returning (length, header_byte_count).
fn der_len(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let first = buf[pos];
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || pos + n >= buf.len() {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | buf[pos + 1 + i] as usize;
    }
    Some((len, 1 + n))
}

pub fn fingerprint(cert_pem: &str) -> String {
    hex::encode(Sha256::digest(cert_pem.as_bytes()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_rfc4648_vectors() {
        // RFC 4648 §10 test vectors, base64url without padding.
        assert_eq!(b64url(""), "");
        assert_eq!(b64url("f"), "Zg");
        assert_eq!(b64url("fo"), "Zm8");
        assert_eq!(b64url("foo"), "Zm9v");
        assert_eq!(b64url("foob"), "Zm9vYg");
        assert_eq!(b64url("fooba"), "Zm9vYmE");
        assert_eq!(b64url("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn b64url_is_url_safe() {
        // 0xFB 0xFF would be "+/" in standard base64; must be "-_" here, no padding.
        assert_eq!(b64url([0xfb, 0xff]), "-_8");
    }

    #[test]
    fn jwk_thumbprint_is_stable_and_url_safe() {
        let k = AcmeKey::generate().unwrap();
        let tp = k.thumbprint();
        assert_eq!(tp, k.thumbprint(), "thumbprint must be deterministic");
        assert!(!tp.contains('='), "thumbprint must be unpadded");
        assert!(
            !tp.contains('+') && !tp.contains('/'),
            "thumbprint must be url-safe"
        );
    }

    #[test]
    fn parse_asn1_utctime() {
        // 2025-12-31 23:59:59Z as UTCTime "251231235959Z"
        let ts = parse_asn1_time(0x17, b"251231235959Z").unwrap();
        // sanity: this is in 2025, well after 2020 epoch offset
        assert!(ts > 1_767_000_000 && ts < 1_768_000_000, "got {ts}");
    }

    /// Live network test against the Let's Encrypt **staging** CA.
    ///
    /// Exercises the full ACME protocol/crypto subset that does NOT require
    /// owning the domain or inbound connectivity:
    ///   directory → newNonce → newAccount (ES256/JWS + JWK) →
    ///   newOrder (kid-signed JWS) → POST-as-GET authz (empty-payload JWS).
    ///
    /// This proves the hand-rolled JWS signing, JWK, nonce handling and
    /// base64url are all wire-correct — a bad signature is rejected by LE
    /// immediately with a `malformed`/`JWS verification` error.
    ///
    /// The challenge-validation step is intentionally skipped (it needs a
    /// public domain pointed at this host). Run explicitly:
    ///   cargo test -p sentinel-proxy --lib tls::acme -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "hits the Let's Encrypt staging CA over the network"]
    async fn live_le_staging_account_order_authz() {
        // The production binary installs this at startup (sentinel-bin/main.rs);
        // the test harness must do the same before building any rustls config.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_dir = std::env::temp_dir().join("sentinel-acme-livetest");
        // Fresh account each run so we test creation, not the load-from-disk path.
        let _ = std::fs::remove_dir_all(&cert_dir);

        let config = SiteAcmeConfig {
            // LE rejects example.com as a contact domain; use a real-domain address.
            email: "ayush.sinha@esds.co.in".to_string(),
            provider: AcmeProvider::LetsEncryptStaging,
            // No override: this test must reach the real staging CA.
            ca_server: String::new(),
            challenge: AcmeChallengeType::Http01,
            renew_before_days: 30,
        };

        // 1. Account creation — directory + nonce + jwk-header ES256 JWS.
        let mut client = AcmeClient::new_or_load(&cert_dir, &config)
            .await
            .expect("ACME account creation against LE staging failed");
        let kid = client.kid.clone().expect("account KID must be set");
        assert!(
            kid.contains("acme-staging-v02.api.letsencrypt.org"),
            "KID should be a staging account URL, got: {kid}"
        );
        eprintln!("✅ account created: {kid}");

        // 2. newOrder — kid-header ES256 JWS + nonce chaining.
        // Ownership is only checked at challenge time, so a test domain is fine.
        let domain = "sentinel-waf-acme-smoketest.com";
        let new_order_url = client.directory.new_order.clone();
        let order_resp = client
            .post_jws_kid(
                &new_order_url,
                Some(&serde_json::json!({
                    "identifiers": [{"type": "dns", "value": domain}]
                })),
            )
            .await
            .expect("newOrder failed (would indicate a JWS/kid signing bug)");
        let order_url = order_resp.location.clone().expect("order Location header");
        let order: OrderResp = order_resp.json().expect("parse order");
        assert!(
            !order.authorizations.is_empty(),
            "order must contain authorizations"
        );
        eprintln!("✅ order created: {order_url} (status={})", order.status);

        // 3. POST-as-GET the authorization — empty-payload JWS.
        let authz: AuthzResp = client
            .post_as_get(&order.authorizations[0])
            .await
            .expect("fetch authz failed (would indicate a POST-as-GET signing bug)")
            .json()
            .expect("parse authz");
        assert_eq!(authz.identifier.value, domain);
        assert!(
            authz.challenges.iter().any(|c| c.kind == "http-01"),
            "CA must offer an http-01 challenge"
        );
        assert!(
            authz.challenges.iter().any(|c| c.kind == "tls-alpn-01"),
            "CA must offer a tls-alpn-01 challenge"
        );
        eprintln!(
            "✅ authz fetched: {} challenges offered ({})",
            authz.challenges.len(),
            authz
                .challenges
                .iter()
                .map(|c| c.kind.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        eprintln!("✅ LE staging protocol+crypto path verified end-to-end (pre-validation)");
    }
}

#[cfg(test)]
mod ca_server_tests {
    use super::*;

    fn cfg(ca: &str, provider: AcmeProvider) -> SiteAcmeConfig {
        SiteAcmeConfig {
            email: "ops@example.com".into(),
            provider,
            ca_server: ca.into(),
            challenge: AcmeChallengeType::Http01,
            renew_before_days: 30,
        }
    }

    /// Empty means "use the provider", which is the behaviour every existing
    /// deployment relies on.
    #[test]
    fn empty_ca_server_falls_back_to_the_provider() {
        let c = cfg("", AcmeProvider::LetsEncryptStaging);
        assert_eq!(
            directory_url(&c).unwrap(),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    /// The whole point of the fix: this value used to be stored, echoed back to
    /// the operator, and then ignored while issuance went to Let's Encrypt.
    #[test]
    fn explicit_ca_server_overrides_the_provider() {
        let c = cfg("https://pebble:14000/dir", AcmeProvider::LetsEncrypt);
        assert_eq!(directory_url(&c).unwrap(), "https://pebble:14000/dir");
    }

    /// Whitespace is an operator typing into a form field, not an intent to
    /// override.
    #[test]
    fn whitespace_only_is_treated_as_unset() {
        let c = cfg("   ", AcmeProvider::LetsEncrypt);
        assert_eq!(
            directory_url(&c).unwrap(),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    /// Refused rather than passed to the HTTP client to interpret.
    #[test]
    fn non_http_schemes_are_refused() {
        // http:// is in this list deliberately: the ACME HTTP client is
        // https-only, so accepting it would re-create the exact bug this field
        // was fixed for — a value stored, echoed back, and silently unusable.
        for bad in [
            "http://ca.example/dir",
            "file:///etc/passwd",
            "ftp://ca.example/dir",
            "pebble:14000/dir",
            "//ca/dir",
        ] {
            let c = cfg(bad, AcmeProvider::LetsEncrypt);
            assert!(directory_url(&c).is_err(), "{bad} should be refused");
        }
    }
}
