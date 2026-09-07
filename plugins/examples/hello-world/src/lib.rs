//! Hello-world example WASM plugin for Sentinel WAF.
//!
//! This plugin logs a message and checks for suspicious user-agents.
//! Build with: cargo build --target wasm32-unknown-unknown --release

#![no_std]

extern crate alloc;
use alloc::string::ToString;

use sentinel_plugin_sdk::*;

// ---------------------------------------------------------------------------
// Global allocator (required for alloc)
// ---------------------------------------------------------------------------

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// ---------------------------------------------------------------------------
// Plugin entry point
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn evaluate() {
    log("Hello from Sentinel WASM plugin!");

    // Check the User-Agent header.
    match get_req_header("user-agent") {
        Some(ua) if ua.is_empty() => {
            log("Empty User-Agent — suspicious");
            add_score(2);
        }
        Some(ua) if ua.contains("sqlmap") => {
            log("SQLMap detected in User-Agent");
            set_decision(Decision::Block);
        }
        Some(_) => {
            // Normal UA — nothing to do.
        }
        None => {
            log("No User-Agent header");
            add_score(1);
        }
    }

    // Use the shared KV store as a simple request counter.
    let count_key = "hello_world:request_count";
    let prev = kv_get(count_key)
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let next = prev.saturating_add(1);
    kv_set(count_key, &next.to_string());

    // Set a custom response header.
    set_response_header("X-Sentinel-Plugin", "hello-world/v0.1.0");
}
