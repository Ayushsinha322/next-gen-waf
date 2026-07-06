//! Sentinel WAF — Rust plugin SDK.
//!
//! This module contains the host-side type definitions and documentation for
//! authors writing Sentinel WAF plugins in Rust.  Copy the contents of this
//! file into your WASM crate to get type-safe access to all host ABI functions.
//!
//! # Quick start
//!
//! ```toml
//! # Cargo.toml
//! [lib]
//! crate-type = ["cdylib"]   # required for WASM
//! ```
//!
//! ```rust,ignore
//! // lib.rs — minimal Sentinel WAF plugin
//! use sentinel_plugin_sdk::*;
//!
//! #[no_mangle]
//! pub extern "C" fn evaluate() {
//!     let ua = get_header("user-agent").unwrap_or_default();
//!     if ua.contains("sqlmap") {
//!         set_decision(Decision::Block);
//!         add_score(50);
//!     }
//! }
//! ```
//!
//! # Host ABI
//!
//! The host imports the following functions into each plugin's WASM module.
//! See [`crate::abi`] for the host-side implementations.

// ---------------------------------------------------------------------------
// Decision type (mirrors WafDecision in sentinel-core)
// ---------------------------------------------------------------------------

/// WAF decision codes, as returned by `host_get_decision` / set by `host_set_decision`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow = 0,
    Block = 1,
    Challenge = 2,
}

impl Decision {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Decision::Block,
            2 => Decision::Challenge,
            _ => Decision::Allow,
        }
    }
}

// ---------------------------------------------------------------------------
// Host function imports (use these inside a WASM plugin)
// ---------------------------------------------------------------------------
//
// Paste the block below into your WASM crate's lib.rs.  The `#[link]` attribute
// tells the WASM linker to resolve these from the "env" namespace that
// sentinel-plugins provides via `abi::add_host_functions`.

/// Include this in your WASM plugin crate to import all host functions.
///
/// ```rust,ignore
/// sentinel_plugin_sdk::import_host_functions!();
/// ```
#[macro_export]
macro_rules! import_host_functions {
    () => {
        #[link(wasm_import_module = "env")]
        extern "C" {
            /// Write `len` bytes from `ptr` to the host's structured log at WARN level.
            pub fn host_log(ptr: i32, len: i32);

            /// Get the value of request header `name` (ptr+len).
            /// Writes the value into `out_ptr` (max `out_cap` bytes) and returns actual length.
            /// Returns -1 if the header is absent.
            pub fn host_get_header(name_ptr: i32, name_len: i32, out_ptr: i32, out_cap: i32)
                -> i32;

            /// Overwrite or add a response header.
            pub fn host_set_header(name_ptr: i32, name_len: i32, val_ptr: i32, val_len: i32);

            /// Read the current WAF decision (0=Allow, 1=Block, 2=Challenge).
            pub fn host_get_decision() -> i32;

            /// Override the WAF decision (0=Allow, 1=Block, 2=Challenge).
            pub fn host_set_decision(decision: i32);

            /// Add `delta` to the anomaly score for this request.
            pub fn host_add_score(delta: i32);

            /// Read a string value from the plugin KV store (shared across plugins).
            /// Returns actual length; -1 if key absent.
            pub fn host_kv_get(key_ptr: i32, key_len: i32, out_ptr: i32, out_cap: i32) -> i32;

            /// Write a string value to the plugin KV store.
            pub fn host_kv_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32);

            /// Queue an outbound HTTP callout.  `headers_json` is a JSON object
            /// of request headers.  Returns a callout ID to pass to
            /// `host_http_callout_status` / `host_http_callout_body`.
            pub fn host_http_callout(
                id: i32,
                url_ptr: i32,
                url_len: i32,
                method_ptr: i32,
                method_len: i32,
                headers_ptr: i32,
                headers_len: i32,
                body_ptr: i32,
                body_len: i32,
            );

            /// Get the HTTP status of a completed callout (-1 = pending/failed).
            pub fn host_http_callout_status(id: i32) -> i32;

            /// Read the body of a completed callout.  Returns actual byte count.
            pub fn host_http_callout_body(id: i32, out_ptr: i32, out_cap: i32) -> i32;
        }
    };
}

// ---------------------------------------------------------------------------
// Safe helper wrappers — only available when compiling for WASM targets.
// Copy these into your plugin crate (they call the host ABI imports above).
// ---------------------------------------------------------------------------

/// Log a message to the host's structured log.
#[cfg(target_arch = "wasm32")]
pub fn log_msg(msg: &str) {
    unsafe { host_log(msg.as_ptr() as i32, msg.len() as i32) }
}

/// Get the value of a request header by name (case-insensitive on the host).
#[cfg(target_arch = "wasm32")]
pub fn get_header(name: &str) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let len = unsafe {
        host_get_header(
            name.as_ptr() as i32,
            name.len() as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if len < 0 {
        return None;
    }
    buf.truncate(len as usize);
    String::from_utf8(buf).ok()
}

/// Set the WAF decision for this request.
#[cfg(target_arch = "wasm32")]
pub fn set_decision(d: Decision) {
    unsafe { host_set_decision(d as i32) }
}

/// Add `delta` to the request anomaly score.
#[cfg(target_arch = "wasm32")]
pub fn add_score(delta: i32) {
    unsafe { host_add_score(delta) }
}

/// Read a value from the shared plugin KV store.
#[cfg(target_arch = "wasm32")]
pub fn kv_get(key: &str) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let len = unsafe {
        host_kv_get(
            key.as_ptr() as i32,
            key.len() as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if len < 0 {
        return None;
    }
    buf.truncate(len as usize);
    String::from_utf8(buf).ok()
}

/// Write a value to the shared plugin KV store.
#[cfg(target_arch = "wasm32")]
pub fn kv_set(key: &str, value: &str) {
    unsafe {
        host_kv_set(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        )
    }
}

// ---------------------------------------------------------------------------
// Plugin SDK metadata
// ---------------------------------------------------------------------------

/// Current Sentinel plugin ABI version.
pub const SENTINEL_PLUGIN_ABI_VERSION: u32 = 1;
