//! Plugin runtime — host-side engine that loads, stores, and executes WASM
//! guest plugins.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use sentinel_core::{RequestContext, WafDecision};
use tracing;
use wasmtime::{Engine, Linker, Module, Store};

use crate::abi::{self, HttpCalloutResult, PluginContext};
use crate::manifest::PluginManifest;

/// Thread-local storage for outbound HTTP callout results.
/// Populated by [`PluginRuntime::execute_pending_callouts`] after a plugin
/// evaluation completes, and read by `host_http_callout_status` /
/// `host_http_callout_body` during a subsequent evaluation pass.
static CALLOUT_RESULTS: std::sync::LazyLock<Arc<DashMap<i32, HttpCalloutResult>>> =
    std::sync::LazyLock::new(|| Arc::new(DashMap::new()));

/// Return a reference to the global callout results map (used by ABI functions).
pub(crate) fn get_callout_results() -> Arc<DashMap<i32, HttpCalloutResult>> {
    Arc::clone(&CALLOUT_RESULTS)
}

// ---------------------------------------------------------------------------
// PluginEvalResult
// ---------------------------------------------------------------------------

/// Result of a plugin evaluation — returned to the caller (e.g. the proxy)
/// so it can apply side-effects to the `RequestContext`.
#[derive(Debug, Clone)]
pub struct PluginEvalResult {
    /// WAF decision set by the plugin.  Defaults to `Allow` if the plugin
    /// didn't call `host_set_decision`.
    pub decision: WafDecision,
    /// Anomaly score delta accumulated by the plugin via `host_add_score`.
    /// The proxy adds this to `RequestContext::anomaly_score`.
    pub anomaly_score_delta: u32,
    /// Response headers queued by the plugin via `host_set_header`.  The proxy
    /// injects these after the upstream response is received.
    pub response_headers: Vec<(String, String)>,
    /// Outbound HTTP callouts queued by the plugin via `host_http_callout`.
    /// If non-empty, the proxy executes them via
    /// [`PluginRuntime::execute_pending_callouts`] and re-evaluates the plugin
    /// so it can read the results.
    pub pending_callouts: Option<Vec<crate::abi::HttpCalloutRequest>>,
    /// True when the evaluation FAILED rather than completing: the module was
    /// not loaded, would not instantiate, exports no `evaluate`, or trapped
    /// (including fuel exhaustion and the epoch deadline).
    ///
    /// Every one of those paths returns an Allow, so a plugin that fails on
    /// every request is indistinguishable from one that never blocks anything.
    /// The caller counts this — see `sentinel_plugin_traps_total` — so "the
    /// control looks enabled and is judging nothing" is measurable instead of
    /// being buried in ERROR lines.
    pub failed: bool,
}

// ---------------------------------------------------------------------------
// PluginRuntime
// ---------------------------------------------------------------------------

/// The WASM plugin host runtime.
///
/// Holds a shared [`Engine`], a map of pre-compiled [`Module`]s keyed by
/// plugin name, and a shared KV store accessible by all plugins.
/// Thread-safe — can be shared across tokio tasks.
pub struct PluginRuntime {
    engine: Engine,
    modules: HashMap<String, Module>,
    /// Per-plugin memory limits in bytes (key = plugin name).
    memory_limits: HashMap<String, usize>,
    /// Shared key-value store across all plugins.  Plugins access this via
    /// `host_kv_get` / `host_kv_set`.  Keys should be scoped to avoid
    /// collisions (e.g. `my_plugin:rate_limit_count`).
    pub kv_store: Arc<DashMap<String, String>>,
    /// Fuel (instructions) limit per plugin invocation.  `None` means no
    /// limit.  When set, the engine will trap if a plugin exceeds this budget.
    fuel_limit: Option<u64>,
    /// Epoch deadline in engine ticks.  Each plugin invocation interrupts
    /// after this many ticks have elapsed (1 tick ≈ 1 μs of CPU).
    epoch_deadline: Option<u64>,
    /// HTTP client for outbound callouts from plugins.
    http_client: Client<HttpConnector, http_body_util::combinators::BoxBody<Bytes, hyper::Error>>,
}

impl PluginRuntime {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new runtime with a default wasmtime engine.
    ///
    /// Plugins are limited to 16 MiB of linear memory with a 2 MiB guard page.
    /// Epoch interruption is enabled with a 1ms deadline.
    pub fn new() -> anyhow::Result<Self> {
        let mut config = wasmtime::Config::default();
        config.static_memory_maximum_size(16 * 1024 * 1024);
        config.static_memory_guard_size(2 * 1024 * 1024);
        // Enable fuel metering for CPU budget enforcement.
        config.consume_fuel(true);
        // Enable epoch interruption for preempting runaway plugins.
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;
        Ok(Self {
            engine,
            modules: HashMap::new(),
            memory_limits: HashMap::new(),
            kv_store: Arc::new(DashMap::new()),
            fuel_limit: Some(100_000), // default: 100k instructions per invocation
            epoch_deadline: Some(1_000_000), // default: 1M ticks ≈ 1ms
            http_client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
        })
    }

    /// Set the fuel (instruction) limit per plugin invocation.
    ///
    /// Set to `None` to disable fuel metering entirely.
    pub fn set_fuel_limit(&mut self, limit: Option<u64>) {
        self.fuel_limit = limit;
    }

    /// Set the epoch deadline (in engine ticks, ~1 μs each) for plugin
    /// interruption.
    pub fn set_epoch_deadline(&mut self, deadline: Option<u64>) {
        self.epoch_deadline = deadline;
    }

    /// Get the current epoch deadline.
    pub fn epoch_deadline(&self) -> Option<u64> {
        self.epoch_deadline
    }

    /// Set a per-plugin memory limit hint (in bytes).  The engine-level
    /// cap (16 MiB) applies to all plugins; this field is advisory and
    /// reserved for future engine-per-plugin support.
    pub fn set_memory_limit(&mut self, plugin_name: &str, limit_bytes: Option<usize>) {
        match limit_bytes {
            Some(bytes) => {
                self.memory_limits.insert(plugin_name.to_string(), bytes);
            }
            None => {
                self.memory_limits.remove(plugin_name);
            }
        }
    }

    /// Get the per-plugin memory limit hint (in bytes). Returns `None` if no
    /// limit has been set for this plugin.
    pub fn memory_limit(&self, plugin_name: &str) -> Option<usize> {
        self.memory_limits.get(plugin_name).copied()
    }

    // -----------------------------------------------------------------------
    // Plugin lifecycle
    // -----------------------------------------------------------------------

    /// Compile a WASM binary and register it under `name`.
    ///
    /// The module **must** export `evaluate() -> ()` — the runtime calls this
    /// function every time the plugin is invoked for a request.
    pub fn load_plugin(&mut self, name: &str, wasm_bytes: &[u8]) -> anyhow::Result<()> {
        let module = Module::from_binary(&self.engine, wasm_bytes)
            .map_err(|e| anyhow::anyhow!("failed to compile plugin '{}': {}", name, e))?;
        self.modules.insert(name.to_string(), module);
        tracing::info!(%name, "plugin module loaded");
        Ok(())
    }

    /// Remove a previously loaded plugin.
    pub fn unload_plugin(&mut self, name: &str) {
        if self.modules.remove(name).is_some() {
            tracing::info!(%name, "plugin module unloaded");
        }
    }

    /// Replace a loaded plugin with a new WASM binary without restarting.
    ///
    /// If no plugin with `name` is currently loaded this behaves identically
    /// to [`load_plugin`].  The swap is performed while holding `&mut self`,
    /// so it is atomic from the caller's perspective.  For zero-downtime
    /// hot-reload in production, clone the runtime, call this method on the
    /// clone, then swap it in via the proxy's `ArcSwap<PluginRuntime>`.
    pub fn hot_reload(&mut self, name: &str, wasm_bytes: &[u8]) -> anyhow::Result<()> {
        let module = Module::from_binary(&self.engine, wasm_bytes)
            .map_err(|e| anyhow::anyhow!("failed to recompile plugin '{}': {}", name, e))?;
        let replaced = self.modules.insert(name.to_string(), module).is_some();
        if replaced {
            tracing::info!(%name, "plugin module hot-reloaded");
        } else {
            tracing::info!(%name, "plugin module loaded (new via hot_reload)");
        }
        Ok(())
    }

    /// Download a WASM binary from `url` and load it as plugin `name`.
    ///
    /// Supports plain HTTP and HTTPS.  For OCI registry URLs use
    /// [`install_from_oci`] instead.
    pub async fn install_from_url(&mut self, name: &str, url: &str) -> anyhow::Result<()> {
        let bytes = crate::registry::download_wasm(url)
            .await
            .map_err(|e| anyhow::anyhow!("install_from_url '{}': {}", url, e))?;
        self.load_plugin(name, &bytes)
    }

    /// Pull a WASM binary from an OCI registry and load it as plugin `name`.
    ///
    /// `oci_ref` format: `oci://registry/image:tag` or `oci://registry/image@sha256:digest`.
    pub async fn install_from_oci(&mut self, name: &str, oci_ref: &str) -> anyhow::Result<()> {
        let bytes = crate::registry::pull_wasm(oci_ref)
            .await
            .map_err(|e| anyhow::anyhow!("install_from_oci '{}': {}", oci_ref, e))?;
        self.load_plugin(name, &bytes)
    }

    /// Load a plugin from a `sentinel-plugin.toml` manifest file.
    ///
    /// Reads the manifest, resolves the `.wasm` path relative to the manifest
    /// directory, and compiles the WASM binary.
    /// Load a plugin described by a manifest file and return its declared name,
    /// so the caller can record which site asked for it (per-site selection
    /// needs the name, and the manifest is the only place it is written).
    pub fn load_from_manifest(&mut self, manifest_path: &Path) -> anyhow::Result<String> {
        let manifest_bytes = std::fs::read(manifest_path)
            .map_err(|e| anyhow::anyhow!("failed to read manifest {:?}: {}", manifest_path, e))?;
        let manifest = PluginManifest::from_slice(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse manifest {:?}: {}", manifest_path, e))?;

        let dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        let wasm_path = dir.join(&manifest.plugin.wasm);
        let wasm_bytes = std::fs::read(&wasm_path)
            .map_err(|e| anyhow::anyhow!("failed to read wasm {:?}: {}", wasm_path, e))?;

        self.load_plugin(&manifest.plugin.name, &wasm_bytes)?;

        tracing::info!(
            name = %manifest.plugin.name,
            version = %manifest.plugin.version,
            hooks.req_headers = manifest.plugin.hooks.request_headers,
            hooks.req_body = manifest.plugin.hooks.request_body,
            hooks.resp_headers = manifest.plugin.hooks.response_headers,
            hooks.resp_body = manifest.plugin.hooks.response_body,
            "plugin loaded from manifest"
        );

        Ok(manifest.plugin.name)
    }

    /// Return the number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.modules.len()
    }

    /// Return the names of all loaded plugins.
    pub fn plugin_names(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }

    // -----------------------------------------------------------------------
    // Evaluation — called once per request per site
    // -----------------------------------------------------------------------

    /// Execute a plugin against the given request context.
    ///
    /// Returns a [`PluginEvalResult`] containing the WAF decision, anomaly
    /// score delta, and any queued response headers.
    ///
    /// If the plugin is not found, panics during evaluation, does not export
    /// `evaluate`, or exceeds its fuel budget, this method logs the error and
    /// returns a safe default (Allow, zero delta, no headers).
    pub async fn evaluate_plugin(
        &self,
        plugin_name: &str,
        ctx: &RequestContext,
    ) -> PluginEvalResult {
        // --- resolve module ---
        let module = match self.modules.get(plugin_name) {
            Some(m) => m,
            None => {
                tracing::warn!(%plugin_name, "plugin not loaded — returning Allow");
                return PluginEvalResult {
                    decision: WafDecision::Allow,
                    anomaly_score_delta: 0,
                    response_headers: Vec::new(),
                    pending_callouts: None,
                    failed: true,
                };
            }
        };

        // --- build per-invocation state ---
        let plugin_ctx = PluginContext {
            headers: extract_headers(ctx),
            decision: WafDecision::Allow,
            anomaly_score_delta: 0,
            response_headers: Vec::new(),
            plugin_name: plugin_name.to_string(),
            kv_store: self.kv_store.clone(),
            callouts: Vec::new(),
        };

        let mut store = Store::new(&self.engine, plugin_ctx);

        // Apply fuel limit if configured.
        if let Some(limit) = self.fuel_limit {
            store.set_fuel(limit).unwrap_or_else(|e| {
                tracing::warn!(%plugin_name, error = %e, "failed to set fuel limit");
            });
        }

        // Apply epoch deadline for interruption of runaway plugins.
        if let Some(deadline) = self.epoch_deadline {
            self.engine.increment_epoch();
            store.set_epoch_deadline(deadline);
        }

        let mut linker = Linker::new(&self.engine);

        if let Err(e) = abi::add_host_functions(&mut linker) {
            tracing::error!(%plugin_name, error = %e, "failed to add host functions");
            return PluginEvalResult {
                decision: WafDecision::Allow,
                anomaly_score_delta: 0,
                response_headers: Vec::new(),
                pending_callouts: None,
                failed: true,
            };
        }

        // --- instantiate ---
        let instance = match linker.instantiate(&mut store, module) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(%plugin_name, error = %e, "instantiation failed");
                return PluginEvalResult {
                    decision: WafDecision::Allow,
                    anomaly_score_delta: 0,
                    response_headers: Vec::new(),
                    pending_callouts: None,
                    failed: true,
                };
            }
        };

        // --- resolve the `evaluate` export ---
        let evaluate = match instance.get_typed_func::<(), ()>(&mut store, "evaluate") {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(%plugin_name, error = %e, "plugin missing 'evaluate' export");
                return PluginEvalResult {
                    decision: WafDecision::Allow,
                    anomaly_score_delta: 0,
                    response_headers: Vec::new(),
                    pending_callouts: None,
                    failed: true,
                };
            }
        };

        // --- call ---
        if let Err(e) = evaluate.call(&mut store, ()) {
            tracing::error!(%plugin_name, error = %e, "plugin evaluation trapped");
            return PluginEvalResult {
                decision: WafDecision::Allow,
                anomaly_score_delta: 0,
                response_headers: Vec::new(),
                pending_callouts: None,
                failed: true,
            };
        }

        let data = store.into_data();
        let pending_callouts = if data.callouts.is_empty() {
            None
        } else {
            Some(data.callouts.clone())
        };
        PluginEvalResult {
            decision: data.decision,
            anomaly_score_delta: data.anomaly_score_delta,
            response_headers: data.response_headers,
            pending_callouts,
            failed: false,
        }
    }

    /// Execute any pending HTTP callouts queued by the plugin during its last
    /// `evaluate()` invocation.  Results are stored in the global
    /// `CALLOUT_RESULTS` map so the plugin can read them on its next
    /// evaluation pass.
    ///
    /// Call this after `evaluate_plugin()` if the plugin may have queued
    /// callouts.  If there are pending callouts, call `evaluate_plugin()`
    /// again so the plugin can read the results.
    pub async fn execute_pending_callouts(&self, callouts: Vec<crate::abi::HttpCalloutRequest>) {
        CALLOUT_RESULTS.clear();
        for callout in &callouts {
            tracing::debug!(
                callout_id = callout.id,
                url = %callout.url,
                method = %callout.method,
                "executing plugin HTTP callout"
            );

            let method: Method = match callout.method.as_str() {
                "POST" => Method::POST,
                "PUT" => Method::PUT,
                "DELETE" => Method::DELETE,
                "PATCH" => Method::PATCH,
                "HEAD" => Method::HEAD,
                _ => Method::GET,
            };

            let uri: Uri = match callout.url.parse() {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(
                        callout_id = callout.id,
                        url = %callout.url,
                        error = %e,
                        "invalid callout URL"
                    );
                    CALLOUT_RESULTS.insert(callout.id, HttpCalloutResult::default());
                    continue;
                }
            };

            let mut req_builder = Request::builder().method(&method).uri(&uri);

            // Parse and apply headers from JSON.
            if let Ok(headers_map) =
                serde_json::from_str::<HashMap<String, String>>(&callout.headers)
            {
                for (k, v) in &headers_map {
                    req_builder = req_builder.header(k.as_str(), v.as_str());
                }
            }

            // Set User-Agent if not already set.
            if !callout.headers.contains("\"user-agent\"")
                && !callout.headers.contains("\"User-Agent\"")
            {
                req_builder = req_builder.header("User-Agent", "sentinel-waf-plugin/0.1");
            }

            let body_bytes = if callout.body.is_empty() {
                Empty::<Bytes>::new()
                    .map_err(|never: std::convert::Infallible| match never {})
                    .boxed()
            } else {
                http_body_util::Full::new(Bytes::from(callout.body.clone()))
                    .map_err(|never: std::convert::Infallible| match never {})
                    .boxed()
            };

            let req = match req_builder.body(body_bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(callout_id = callout.id, error = %e, "callout request build failed");
                    CALLOUT_RESULTS.insert(callout.id, HttpCalloutResult::default());
                    continue;
                }
            };

            let result = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.http_client.request(req),
            )
            .await
            {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16() as i32;
                    let body = match resp.collect().await {
                        Ok(collected) => {
                            let bytes = collected.to_bytes();
                            String::from_utf8_lossy(&bytes).to_string()
                        }
                        Err(e) => {
                            tracing::warn!(callout_id = callout.id, error = %e, "callout body read failed");
                            String::new()
                        }
                    };
                    HttpCalloutResult { status, body }
                }
                Ok(Err(e)) => {
                    tracing::warn!(callout_id = callout.id, error = %e, "callout request failed");
                    HttpCalloutResult::default()
                }
                Err(_timeout) => {
                    tracing::warn!(callout_id = callout.id, "callout timed out after 10s");
                    HttpCalloutResult::default()
                }
            };

            CALLOUT_RESULTS.insert(callout.id, result);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract request headers into a `Vec<(String, String)>`.
///
/// Headers whose name or value cannot be represented as a UTF-8 string are
/// silently skipped (they are extremely rare in practice and are usually
/// malicious).
fn extract_headers(ctx: &RequestContext) -> Vec<(String, String)> {
    ctx.request_headers
        .iter()
        .filter_map(|(name, value)| {
            let name_str = name.to_string();
            let value_str = value.to_str().ok()?;
            Some((name_str, value_str.to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn runtime_create() {
        let rt = PluginRuntime::new().expect("create runtime");
        assert_eq!(rt.plugin_count(), 0);
        assert!(rt.kv_store.is_empty());
        assert_eq!(rt.fuel_limit, Some(100_000));
        assert_eq!(rt.epoch_deadline, Some(1_000_000));
    }

    #[test]
    fn runtime_fuel_limit_configurable() {
        let mut rt = PluginRuntime::new().unwrap();
        rt.set_fuel_limit(Some(50_000));
        assert_eq!(rt.fuel_limit, Some(50_000));
        rt.set_fuel_limit(None);
        assert_eq!(rt.fuel_limit, None);
    }

    #[test]
    fn runtime_epoch_deadline_configurable() {
        let mut rt = PluginRuntime::new().unwrap();
        rt.set_epoch_deadline(Some(5_000_000));
        assert_eq!(rt.epoch_deadline, Some(5_000_000));
        rt.set_epoch_deadline(None);
        assert_eq!(rt.epoch_deadline, None);
    }

    #[test]
    fn runtime_memory_limit_configurable() {
        let mut rt = PluginRuntime::new().unwrap();
        rt.set_memory_limit("my-plugin", Some(8 * 1024 * 1024));
        assert_eq!(rt.memory_limits.get("my-plugin"), Some(&(8 * 1024 * 1024)));
        rt.set_memory_limit("my-plugin", None);
        assert!(!rt.memory_limits.contains_key("my-plugin"));
    }

    #[tokio::test]
    async fn evaluate_missing_plugin_returns_allow() {
        let rt = PluginRuntime::new().unwrap();
        let ctx = RequestContext::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let result = rt.evaluate_plugin("nonexistent", &ctx).await;
        assert_eq!(result.decision, WafDecision::Allow);
        assert_eq!(result.anomaly_score_delta, 0);
        assert!(result.response_headers.is_empty());
        assert!(result.pending_callouts.is_none());
    }

    #[test]
    fn kv_store_shared_across_plugins() {
        let rt = PluginRuntime::new().unwrap();
        rt.kv_store
            .insert("global_key".into(), "shared_value".into());

        let another_ref = rt.kv_store.clone();
        assert_eq!(
            another_ref.get("global_key").unwrap().value().as_str(),
            "shared_value"
        );
    }

    #[test]
    fn load_from_manifest_works() {
        let dir = tempfile::tempdir().expect("create temp dir");

        // Write a minimal manifest.
        let manifest_toml = r#"
[plugin]
name = "test-plugin"
version = "0.1.0"
"#;
        let manifest_path = dir.path().join("sentinel-plugin.toml");
        std::fs::write(&manifest_path, manifest_toml).expect("write manifest");

        // Write a minimal WASM module (just exports evaluate).
        // Build a minimal wasm module with wat if available, or use a pre-built one.
        // For now, we test the error path for a missing/non-wasm file.
        let wasm_path = dir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, b"not a wasm binary").expect("write fake wasm");

        let mut rt = PluginRuntime::new().unwrap();
        let result = rt.load_from_manifest(&manifest_path);
        // Should fail because the "wasm" is not valid.
        assert!(result.is_err());
    }
}
