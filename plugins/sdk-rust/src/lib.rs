//! Sentinel WAF — Rust guest SDK for WASM plugins.
//!
//! This crate provides safe wrappers over the raw ABI imports that the
//! Sentinel host exposes to WASM guests.  Plugin authors depend on this
//! crate and call the safe functions; the user code **must** export
//! `evaluate() -> ()` as the entry point.
//!
//! # Quick start
//!
//! Add to `Cargo.toml`:
//! ```toml
//! [lib]
//! crate-type = ["cdylib"]
//!
//! [dependencies]
//! sentinel-plugin-sdk = { path = "../../sdk-rust" }
//! ```
//!
//! Then write your plugin:
//! ```no_run
//! use sentinel_plugin_sdk::*;
//!
//! #[no_mangle]
//! pub extern "C" fn evaluate() {
//!     log("Hello from Rust plugin!");
//!     if let Some(ua) = get_req_header("user-agent") {
//!         if ua.contains("curl") {
//!             add_score(3);
//!         }
//!     }
//! }
//! ```

#![no_std]

extern crate alloc;
use alloc::string::String;

// ---------------------------------------------------------------------------
// Host ABI imports (raw `extern "C"` declarations)
// ---------------------------------------------------------------------------

extern "C" {
    fn host_log(ptr: *const u8, len: i32);
    fn host_get_req_header(name_ptr: *const u8, name_len: i32, out_ptr: *mut u8, out_max_len: i32) -> i32;
    fn host_set_decision(code: i32);
    fn host_add_score(delta: i32);
    fn host_set_header(name_ptr: *const u8, name_len: i32, val_ptr: *const u8, val_len: i32);
    fn host_kv_get(key_ptr: *const u8, key_len: i32, out_ptr: *mut u8, out_max_len: i32) -> i32;
    fn host_kv_set(key_ptr: *const u8, key_len: i32, val_ptr: *const u8, val_len: i32);
    fn host_http_callout(ptr: *const u8, len: i32) -> i32;
    fn host_http_callout_status(id: i32) -> i32;
    fn host_http_callout_body(id: i32, out_ptr: *mut u8, out_max_len: i32) -> i32;
}

// ---------------------------------------------------------------------------
// Safe wrappers — logging
// ---------------------------------------------------------------------------

/// Write a message to the Sentinel log (INFO level, attributed to the plugin
/// name).
pub fn log(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe { host_log(bytes.as_ptr(), bytes.len() as i32) };
}

// ---------------------------------------------------------------------------
// Safe wrappers — request inspection
// ---------------------------------------------------------------------------

/// Look up a request header by name (case-insensitive).
///
/// Returns `None` if the header is absent or the ABI call fails.
pub fn get_req_header(name: &str) -> Option<String> {
    let name_bytes = name.as_bytes();
    let mut buf = [0u8; 4096];
    let written = unsafe {
        host_get_req_header(
            name_bytes.as_ptr(),
            name_bytes.len() as i32,
            buf.as_mut_ptr(),
            buf.len() as i32,
        )
    };
    if written <= 0 {
        None
    } else {
        let len = (written as usize).min(buf.len());
        alloc::str::from_utf8(&buf[..len]).ok().map(|s| s.into())
    }
}

// ---------------------------------------------------------------------------
// Safe wrappers — decision
// ---------------------------------------------------------------------------

/// Set the WAF decision for this request.
pub fn set_decision(code: Decision) {
    unsafe { host_set_decision(code as i32) };
}

/// WAF decision codes that a plugin can set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Decision {
    Allow = 0,
    Block = 1,
    Challenge = 2,
    Log = 3,
}

// ---------------------------------------------------------------------------
// Safe wrappers — anomaly score
// ---------------------------------------------------------------------------

/// Increment the anomaly score by `delta`.
///
/// Negative deltas are ignored by the host (clamped to zero).
/// Call this when the plugin detects suspicious activity that isn't severe
/// enough to block outright.
pub fn add_score(delta: u32) {
    unsafe { host_add_score(delta as i32) };
}

// ---------------------------------------------------------------------------
// Safe wrappers — response header injection
// ---------------------------------------------------------------------------

/// Queue a response header to be injected after the upstream response is
/// received.  Multiple calls with the same name append entries.
pub fn set_response_header(name: &str, value: &str) {
    let n = name.as_bytes();
    let v = value.as_bytes();
    unsafe {
        host_set_header(
            n.as_ptr(),
            n.len() as i32,
            v.as_ptr(),
            v.len() as i32,
        );
    }
}

// ---------------------------------------------------------------------------
// Safe wrappers — shared KV store
// ---------------------------------------------------------------------------

/// Read a value from the shared plugin key-value store.
///
/// Returns `None` if the key is absent.  Keys should be scoped to avoid
/// collisions (e.g. `"my_plugin:rate_limit_count"`).
pub fn kv_get(key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    let mut buf = [0u8; 4096];
    let written = unsafe {
        host_kv_get(
            key_bytes.as_ptr(),
            key_bytes.len() as i32,
            buf.as_mut_ptr(),
            buf.len() as i32,
        )
    };
    if written <= 0 {
        None
    } else {
        let len = (written as usize).min(buf.len());
        alloc::str::from_utf8(&buf[..len]).ok().map(|s| s.into())
    }
}

/// Store a key-value pair in the shared plugin KV store.
///
/// Overwrites any existing value for the same key.
pub fn kv_set(key: &str, value: &str) {
    let k = key.as_bytes();
    let v = value.as_bytes();
    unsafe {
        host_kv_set(
            k.as_ptr(),
            k.len() as i32,
            v.as_ptr(),
            v.len() as i32,
        );
    }
}

// ---------------------------------------------------------------------------
// Utility — URL decoding
// ---------------------------------------------------------------------------

/// Decode a URL-encoded string (e.g. query parameter values).
///
/// This is a minimal implementation; for production use, depend on
/// `percent-encoding` in your plugin.
pub fn url_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(byte) = hex_byte(bytes[i + 1], bytes[i + 2]) {
                out.push(byte as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

fn hex_byte(a: u8, b: u8) -> Option<u8> {
    let hi = hex_digit(a)?;
    let lo = hex_digit(b)?;
    Some((hi << 4) | lo)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Safe wrappers — outbound HTTP callout
// ---------------------------------------------------------------------------

/// Queue an outbound HTTP request and return a callout ID (≥0), or -1 on
/// error.
///
/// The request is specified as a JSON string with keys:
/// `url` (required), `method` (optional, defaults to GET),
/// `headers` (optional JSON object), `body` (optional string).
///
/// After `evaluate()` returns, the host executes the callout asynchronously
/// and calls `evaluate()` again so the plugin can read the result via
/// [`http_callout_status`] and [`http_callout_body`].
pub fn http_callout(json_req: &str) -> i32 {
    let bytes = json_req.as_bytes();
    if bytes.is_empty() {
        return -1;
    }
    unsafe { host_http_callout(bytes.as_ptr(), bytes.len() as i32) }
}

/// Return the HTTP status code of a completed callout, or 0 if the callout
/// hasn't completed or failed.
pub fn http_callout_status(id: i32) -> i32 {
    unsafe { host_http_callout_status(id) }
}

/// Return the response body of a completed callout.
///
/// Returns `None` if the callout hasn't completed, failed, or the body is
/// absent.
pub fn http_callout_body(id: i32) -> Option<String> {
    let mut buf = [0u8; 65536];
    let written = unsafe {
        host_http_callout_body(id, buf.as_mut_ptr(), buf.len() as i32)
    };
    if written <= 0 {
        None
    } else {
        let len = (written as usize).min(buf.len());
        alloc::str::from_utf8(&buf[..len]).ok().map(|s| s.into())
    }
}
