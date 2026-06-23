//! OCI Distribution Spec client for pulling WASM plugin artifacts from OCI registries.
//!
//! # Supported URI format
//! ```text
//! oci://registry.example.com/namespace/image:tag
//! oci://registry.example.com:5000/namespace/image@sha256:abc123
//! ```
//!
//! # Artifact layout
//! Sentinel expects OCI images where the single layer contains the raw WASM binary
//! with media type `application/wasm` or the standard OCI tar+gzip layer type.
//! Tools like `wasm-to-oci` and `oras` produce compatible artifacts.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    http_body_util::combinators::BoxBody<Bytes, hyper::Error>,
>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Pull a WASM binary from an OCI registry.
///
/// `oci_ref` must follow the format `oci://registry/name:tag` or
/// `oci://registry/name@sha256:digest`.
///
/// Returns the raw WASM bytes ready to pass to [`PluginRuntime::load_plugin`].
pub async fn pull_wasm(oci_ref: &str) -> Result<Vec<u8>> {
    let parsed = parse_oci_ref(oci_ref)?;
    let client = build_https_client();
    pull_wasm_from_registry(&client, &parsed).await
}

/// Download a WASM binary from a plain HTTP or HTTPS URL.
///
/// Use this for direct `.wasm` file URLs; use [`pull_wasm`] for OCI refs.
pub async fn download_wasm(url: &str) -> Result<Vec<u8>> {
    let client = build_https_client();
    fetch_bytes(&client, url).await
}

// ---------------------------------------------------------------------------
// OCI reference parsing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct OciRef {
    registry: String,
    name: String,
    /// Tag or `@sha256:...` digest reference.
    reference: String,
}

fn parse_oci_ref(raw: &str) -> Result<OciRef> {
    let rest = raw
        .strip_prefix("oci://")
        .with_context(|| format!("OCI ref must start with oci:// — got '{raw}'"))?;

    // Split registry from the rest: first '/' separates registry from path.
    let (registry, path) = rest
        .split_once('/')
        .with_context(|| format!("OCI ref missing image path: '{raw}'"))?;

    // Split name from tag/digest.
    let (name, reference) = if let Some(idx) = path.rfind('@') {
        // digest reference: name@sha256:...
        (path[..idx].to_owned(), path[idx..].to_owned())
    } else if let Some(idx) = path.rfind(':') {
        // tag reference: name:tag
        (path[..idx].to_owned(), path[idx + 1..].to_owned())
    } else {
        // No tag — default to latest.
        (path.to_owned(), "latest".to_owned())
    };

    if name.is_empty() {
        bail!("OCI ref has empty image name: '{raw}'");
    }

    Ok(OciRef {
        registry: registry.to_owned(),
        name,
        reference,
    })
}

// ---------------------------------------------------------------------------
// OCI Distribution Spec implementation
// ---------------------------------------------------------------------------

/// OCI manifest (v2 schema2 or OCI image manifest).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    layers: Vec<OciDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciDescriptor {
    media_type: String,
    digest: String,
}

async fn pull_wasm_from_registry(client: &HttpsClient, r: &OciRef) -> Result<Vec<u8>> {
    // Step 1 — fetch the manifest to discover the WASM blob digest.
    let manifest_url = format!(
        "https://{}/v2/{}/manifests/{}",
        r.registry, r.name, r.reference
    );

    let manifest_bytes = fetch_with_accept(
        client,
        &manifest_url,
        "application/vnd.oci.image.manifest.v1+json, \
         application/vnd.docker.distribution.manifest.v2+json",
    )
    .await
    .with_context(|| format!("failed to fetch OCI manifest for {}/{}", r.registry, r.name))?;

    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| "OCI manifest is not valid JSON")?;

    if manifest.layers.is_empty() {
        bail!("OCI manifest for {}/{} has no layers", r.registry, r.name);
    }

    // Prefer the first application/wasm layer; fall back to the first layer overall.
    let layer = manifest
        .layers
        .iter()
        .find(|l| l.media_type == "application/wasm")
        .or_else(|| manifest.layers.first())
        .expect("OCI manifest has no layers");

    tracing::debug!(
        registry = %r.registry,
        image = %r.name,
        digest = %layer.digest,
        media_type = %layer.media_type,
        "pulling OCI layer"
    );

    // Step 2 — download the blob.
    let blob_url = format!(
        "https://{}/v2/{}/blobs/{}",
        r.registry, r.name, layer.digest
    );

    let blob = fetch_bytes(client, &blob_url)
        .await
        .with_context(|| format!("failed to fetch OCI blob {}", layer.digest))?;

    Ok(blob)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn build_https_client() -> HttpsClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

async fn fetch_bytes(client: &HttpsClient, url: &str) -> Result<Vec<u8>> {
    let body = fetch_with_accept(client, url, "*/*").await?;
    Ok(body.to_vec())
}

async fn fetch_with_accept(client: &HttpsClient, url: &str, accept: &str) -> Result<Bytes> {
    let uri: hyper::Uri = url
        .parse()
        .with_context(|| format!("invalid URL: '{url}'"))?;

    let req = Request::builder()
        .uri(uri)
        .header("Accept", accept)
        .header("User-Agent", "sentinel-waf/1.0 plugin-installer")
        .body(
            Full::<Bytes>::new(Bytes::new())
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed(),
        )?;

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.request(req),
    )
    .await
    .map_err(|_| anyhow::anyhow!("request to '{}' timed out after 60s", url))??;

    let status = resp.status();
    if !status.is_success() {
        bail!("server returned HTTP {} for '{}'", status, url);
    }

    Ok(resp.collect().await?.to_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_oci_ref_tag() {
        let r = parse_oci_ref("oci://registry.example.com/sentinel-plugins/my-plugin:v1.2.3").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.name, "sentinel-plugins/my-plugin");
        assert_eq!(r.reference, "v1.2.3");
    }

    #[test]
    fn parse_oci_ref_digest() {
        let r = parse_oci_ref("oci://ghcr.io/myorg/plugin@sha256:deadbeef").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "myorg/plugin");
        assert_eq!(r.reference, "@sha256:deadbeef");
    }

    #[test]
    fn parse_oci_ref_default_tag() {
        let r = parse_oci_ref("oci://registry.local:5000/myplugin").unwrap();
        assert_eq!(r.registry, "registry.local:5000");
        assert_eq!(r.name, "myplugin");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_oci_ref_missing_scheme_fails() {
        assert!(parse_oci_ref("registry.example.com/plugin:v1").is_err());
    }
}
