//! Host ABI — functions that the host exposes to WASM guest plugins.
//!
//! Every guest module imports the following from the `"env"` module:
//!   - `host_log(ptr, len)`             — write a message to the Sentinel log.
//!   - `host_get_req_header(name_ptr, name_len, out_ptr, out_max_len) -> i32`
//!       — read a request header; returns bytes written or -1.
//!   - `host_set_decision(code)`        — set the WAF decision (0=Allow, 1=Block,
//!       2=Challenge, 3=Log).
//!   - `host_add_score(delta)`          — increment the anomaly score.
//!   - `host_set_header(name_ptr, name_len, val_ptr, val_len)` — queue a
//!       response header to be injected.
//!   - `host_kv_get(key_ptr, key_len, out_ptr, out_max_len) -> i32`
//!       — read from the shared plugin KV store.
//!   - `host_kv_set(key_ptr, key_len, val_ptr, val_len)` — write to the
//!       shared plugin KV store.
//!   - `host_http_callout(ptr, len) -> i32` — queue an outbound HTTP request;
//!       returns a request id (≥0) or -1 on error.
//!   - `host_http_callout_status(id) -> i32` — read response status code
//!       of a completed callout; 0 if pending/failed.
//!   - `host_http_callout_body(id, out_ptr, out_max_len) -> i32` — read
//!       response body of a completed callout; returns bytes written or -1.

use std::sync::Arc;

use dashmap::DashMap;
use sentinel_core::WafDecision;
use wasmtime::{AsContext, AsContextMut, Caller, Linker};

// ---------------------------------------------------------------------------
// PluginContext — per-invocation state held in the WASM store
// ---------------------------------------------------------------------------

/// Per-invocation state held inside the `wasmtime::Store`.
///
/// Must implement `Send` (wasmtime requirement).  Request headers are extracted
/// into a plain `Vec<(String, String)>` rather than holding an
/// `http::HeaderMap` which is `!Send`.
#[derive(Debug, Clone)]
pub(crate) struct PluginContext {
    /// Request headers extracted from the `RequestContext` (name, value).
    /// Duplicate header names produce multiple entries.
    pub(crate) headers: Vec<(String, String)>,
    /// The WAF decision set by the guest.  Defaults to `Allow`.
    pub(crate) decision: WafDecision,
    /// Anomaly score delta accumulated by the guest via `host_add_score`.
    pub(crate) anomaly_score_delta: u32,
    /// Response headers queued by the guest via `host_set_header`.
    pub(crate) response_headers: Vec<(String, String)>,
    /// Plugin name for log attribution.
    pub(crate) plugin_name: String,
    /// Shared KV store across all plugins (plugin-scoped keys).
    pub(crate) kv_store: Arc<DashMap<String, String>>,
    /// Outbound HTTP callouts queued by the guest via `host_http_callout`.
    /// Processed asynchronously by the host after evaluate() returns.
    pub(crate) callouts: Vec<HttpCalloutRequest>,
}

/// An outbound HTTP request queued by a plugin.
#[derive(Debug, Clone)]
pub struct HttpCalloutRequest {
    /// Sequential request id assigned by the host.
    pub(crate) id: i32,
    /// Full URL to fetch (e.g. `https://auth.example.com/verify`).
    pub(crate) url: String,
    /// HTTP method (GET, POST, etc.).
    pub(crate) method: String,
    /// Request headers as JSON (e.g. `{"Authorization": "Bearer ..."}`).
    pub(crate) headers: String,
    /// Request body (may be empty).
    pub(crate) body: String,
}

/// Result of an outbound HTTP callout.
#[derive(Debug, Clone, Default)]
pub struct HttpCalloutResult {
    /// HTTP status code (0 if the request failed).
    pub(crate) status: i32,
    /// Response body.
    pub(crate) body: String,
}

// ---------------------------------------------------------------------------
// Public helper
// ---------------------------------------------------------------------------

/// Register every host ABI function on the given linker.
pub(crate) fn add_host_functions(linker: &mut Linker<PluginContext>) -> anyhow::Result<()> {
    linker.func_wrap("env", "host_log", host_log)?;
    linker.func_wrap("env", "host_get_req_header", host_get_req_header)?;
    linker.func_wrap("env", "host_set_decision", host_set_decision)?;
    linker.func_wrap("env", "host_add_score", host_add_score)?;
    linker.func_wrap("env", "host_set_header", host_set_header)?;
    linker.func_wrap("env", "host_kv_get", host_kv_get)?;
    linker.func_wrap("env", "host_kv_set", host_kv_set)?;
    linker.func_wrap("env", "host_http_callout", host_http_callout)?;
    linker.func_wrap("env", "host_http_callout_status", host_http_callout_status)?;
    linker.func_wrap("env", "host_http_callout_body", host_http_callout_body)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Host ABI implementations
// ---------------------------------------------------------------------------

/// `host_log(ptr: i32, len: i32)`
///
/// Read a message from the guest and emit it as a Sentinel tracing event.
fn host_log(mut caller: Caller<'_, PluginContext>, ptr: i32, len: i32) {
    let msg = read_guest_string(&mut caller, ptr, len);
    if let Some(msg) = msg {
        let plugin = &caller.data().plugin_name;
        tracing::info!(plugin = %plugin, "{}", msg);
    }
}

/// `host_get_req_header(name_ptr, name_len, out_ptr, out_max_len) -> i32`
///
/// Look up a request header by name (case-insensitive) and write its value
/// into the guest buffer.  Returns the number of bytes written (or would be
/// written if the buffer were large enough), or `-1` if the header is absent.
fn host_get_req_header(
    mut caller: Caller<'_, PluginContext>,
    name_ptr: i32,
    name_len: i32,
    out_ptr: i32,
    out_max_len: i32,
) -> i32 {
    // Step 1 — read the header name from guest memory.
    let header_name = match read_guest_string(&mut caller, name_ptr, name_len) {
        Some(n) => n.to_ascii_lowercase(),
        None => return -1,
    };

    // Step 2 — look up the matching value in PluginContext.
    let found_value = {
        let ctx = caller.data();
        ctx.headers
            .iter()
            .find(|(name, _)| name.to_ascii_lowercase() == header_name)
            .map(|(_, val)| val.clone())
    };

    // Step 3 — write the value back into guest memory.
    match found_value {
        Some(v) => write_guest_string(&mut caller, out_ptr, out_max_len, &v),
        None => -1,
    }
}

/// `host_set_decision(code: i32)`
///
/// Set the WAF decision for this request.
///   `0` = Allow, `1` = Block, `2` = Challenge, `3` = Log.
fn host_set_decision(mut caller: Caller<'_, PluginContext>, code: i32) {
    let decision = match code {
        1 => WafDecision::Block,
        2 => WafDecision::Challenge,
        3 => WafDecision::Log,
        _ => WafDecision::Allow,
    };

    let ctx = caller.data_mut();
    ctx.decision = decision;
    tracing::debug!(
        plugin = %ctx.plugin_name,
        decision = ?ctx.decision,
        "plugin set decision"
    );
}

/// `host_add_score(delta: i32)`
///
/// Increment the anomaly score by `delta`.  Negative deltas are clamped to
/// zero (guest cannot reduce the score below zero).
fn host_add_score(mut caller: Caller<'_, PluginContext>, delta: i32) {
    let ctx = caller.data_mut();
    if delta > 0 {
        ctx.anomaly_score_delta = ctx.anomaly_score_delta.saturating_add(delta as u32);
    }
    tracing::debug!(
        plugin = %ctx.plugin_name,
        delta,
        total_delta = ctx.anomaly_score_delta,
        "plugin added anomaly score"
    );
}

/// `host_set_header(name_ptr, name_len, val_ptr, val_len)`
///
/// Queue a response header to be injected by the proxy after the upstream
/// response is received.  Multiple calls with the same name append entries.
fn host_set_header(
    mut caller: Caller<'_, PluginContext>,
    name_ptr: i32,
    name_len: i32,
    val_ptr: i32,
    val_len: i32,
) {
    let name = match read_guest_string(&mut caller, name_ptr, name_len) {
        Some(n) => n,
        None => return,
    };
    let value = match read_guest_string(&mut caller, val_ptr, val_len) {
        Some(v) => v,
        None => return,
    };

    let ctx = caller.data_mut();
    ctx.response_headers.push((name.clone(), value));
    tracing::debug!(
        plugin = %ctx.plugin_name,
        header = %name,
        "plugin queued response header"
    );
}

/// `host_kv_get(key_ptr, key_len, out_ptr, out_max_len) -> i32`
///
/// Look up a key in the shared plugin KV store and write its value into the
/// guest buffer.  Returns bytes written or `-1` if the key is absent.
fn host_kv_get(
    mut caller: Caller<'_, PluginContext>,
    key_ptr: i32,
    key_len: i32,
    out_ptr: i32,
    out_max_len: i32,
) -> i32 {
    let key = match read_guest_string(&mut caller, key_ptr, key_len) {
        Some(k) => k,
        None => return -1,
    };

    let val_opt = {
        let kv = caller.data().kv_store.clone();
        kv.get(&key).map(|entry| entry.value().clone())
    };

    match val_opt {
        Some(val) => write_guest_string(&mut caller, out_ptr, out_max_len, &val),
        None => -1,
    }
}

/// `host_kv_set(key_ptr, key_len, val_ptr, val_len)`
///
/// Store a key-value pair in the shared plugin KV store.  Overwrites any
/// existing value.
fn host_kv_set(
    mut caller: Caller<'_, PluginContext>,
    key_ptr: i32,
    key_len: i32,
    val_ptr: i32,
    val_len: i32,
) {
    let key = match read_guest_string(&mut caller, key_ptr, key_len) {
        Some(k) => k,
        None => return,
    };
    let value = match read_guest_string(&mut caller, val_ptr, val_len) {
        Some(v) => v,
        None => return,
    };

    let kv = caller.data().kv_store.clone();
    kv.insert(key.clone(), value);
}

// ---------------------------------------------------------------------------
// Host ABI — outbound HTTP callout
// ---------------------------------------------------------------------------

/// `host_http_callout(ptr: i32, len: i32) -> i32`
///
/// Queue an outbound HTTP request.  The guest passes a JSON string with keys
/// `url`, `method` (optional, defaults to GET), `headers` (optional JSON
/// object), and `body` (optional string).
///
/// Returns a sequentially-increasing request id (≥0) on success, or -1 on
/// parse error.
fn host_http_callout(mut caller: Caller<'_, PluginContext>, ptr: i32, len: i32) -> i32 {
    let json = match read_guest_string(&mut caller, ptr, len) {
        Some(s) => s,
        None => return -1,
    };

    let parsed: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let url = parsed
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if url.is_empty() {
        return -1;
    }

    let method = parsed
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();

    let headers = parsed
        .get("headers")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "{}".to_string());

    let body = parsed
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let ctx = caller.data_mut();
    let id = ctx.callouts.len() as i32;
    ctx.callouts.push(HttpCalloutRequest {
        id,
        url,
        method,
        headers,
        body,
    });

    tracing::debug!(
        plugin = %ctx.plugin_name,
        callout_id = id,
        "plugin queued HTTP callout"
    );
    id
}

/// `host_http_callout_status(id: i32) -> i32`
///
/// Read the HTTP status code of a completed callout.  Returns the status code
/// (e.g. 200), or 0 if the callout hasn't completed or failed.
fn host_http_callout_status(mut _caller: Caller<'_, PluginContext>, id: i32) -> i32 {
    let results = crate::runtime::get_callout_results();
    results.get(&id).map(|r| r.value().status).unwrap_or(0)
}

/// `host_http_callout_body(id: i32, out_ptr: i32, out_max_len: i32) -> i32`
///
/// Read the response body of a completed callout.  Writes the body bytes into
/// the guest buffer.  Returns bytes written, or -1 if the callout hasn't
/// completed or the body is absent.
fn host_http_callout_body(
    mut caller: Caller<'_, PluginContext>,
    id: i32,
    out_ptr: i32,
    out_max_len: i32,
) -> i32 {
    let results = crate::runtime::get_callout_results();
    let body = results.get(&id).map(|r| r.value().body.clone()).unwrap_or_default();
    if body.is_empty() {
        -1
    } else {
        write_guest_string(&mut caller, out_ptr, out_max_len, &body)
    }
}

// ---------------------------------------------------------------------------
// Helpers — guest memory read / write
// ---------------------------------------------------------------------------

/// Read a UTF-8 string from the guest's linear memory at `ptr..ptr+len`.
fn read_guest_string(caller: &mut Caller<'_, PluginContext>, ptr: i32, len: i32) -> Option<String> {
    if ptr < 0 || len <= 0 {
        return None;
    }
    let mem = caller.get_export("memory")?.into_memory()?;
    let data = mem.data(caller.as_context());
    let start = ptr as usize;
    let end = start.saturating_add(len as usize);
    let slice = data.get(start..end)?;
    let mut bytes = slice.to_vec();
    // Strip trailing null bytes — some WASM toolchains (Go, C) null-terminate
    // strings, and wat data segments may include them.
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes).ok()
}

/// Write a string into the guest's linear memory.  Returns the number of bytes
/// actually written.  If the buffer is too small the value is truncated.
fn write_guest_string(
    caller: &mut Caller<'_, PluginContext>,
    ptr: i32,
    max_len: i32,
    s: &str,
) -> i32 {
    if ptr < 0 || max_len <= 0 {
        return -1;
    }
    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(m) => m,
        None => return -1,
    };
    let start = ptr as usize;
    let end = start.saturating_add(max_len as usize);
    let all = mem.data_mut(caller.as_context_mut());
    let bytes = s.as_bytes();
    let to_write = bytes.len().min(max_len as usize);
    match all.get_mut(start..end) {
        Some(dest) => {
            dest[..to_write].copy_from_slice(&bytes[..to_write]);
            to_write as i32
        }
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_context_defaults() {
        let ctx = PluginContext {
            headers: vec![("host".into(), "example.com".into())],
            decision: WafDecision::Allow,
            anomaly_score_delta: 0,
            response_headers: Vec::new(),
            plugin_name: "test".into(),
            kv_store: Arc::new(DashMap::new()),
            callouts: Vec::new(),
        };
        assert_eq!(ctx.decision, WafDecision::Allow);
        assert_eq!(ctx.headers.len(), 1);
        assert_eq!(ctx.anomaly_score_delta, 0);
        assert!(ctx.response_headers.is_empty());
    }

    #[test]
    fn decision_codes() {
        let codes = [
            (0, WafDecision::Allow),
            (1, WafDecision::Block),
            (2, WafDecision::Challenge),
            (3, WafDecision::Log),
            (99, WafDecision::Allow), // unknown → Allow
        ];
        for (code, expected) in codes {
            assert_eq!(
                match code {
                    1 => WafDecision::Block,
                    2 => WafDecision::Challenge,
                    3 => WafDecision::Log,
                    _ => WafDecision::Allow,
                },
                expected,
            );
        }
    }

    #[test]
    fn kv_store_basic_operations() {
        let kv: Arc<DashMap<String, String>> = Arc::new(DashMap::new());
        kv.insert("rate_limit_key".into(), "42".into());
        assert_eq!(kv.get("rate_limit_key").unwrap().value().as_str(), "42");

        kv.insert("rate_limit_key".into(), "99".into());
        assert_eq!(kv.get("rate_limit_key").unwrap().value().as_str(), "99");

        assert!(kv.get("nonexistent").is_none());
    }
}
