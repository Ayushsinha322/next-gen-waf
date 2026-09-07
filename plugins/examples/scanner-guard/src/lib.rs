//! scanner-guard — blocks well-known vulnerability scanners and brute-force
//! tools by their User-Agent signature.
//!
//! This is the first plugin in the bundled catalogue. It is deliberately small:
//! one header read, one decision. Its job as a catalogue entry is to show what
//! a sandboxed plugin can do (and, through its manifest, what it is ALLOWED to
//! do) on real traffic — the WASM sandbox has been a differentiator nobody could
//! see because nothing shipped to run in it.
//!
//! Build: cargo build --target wasm32-unknown-unknown --release

#![no_std]

extern crate alloc;

use alloc::string::String;
use sentinel_plugin_sdk::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

/// Lower-cased substrings that identify scanners and attack tooling. Kept to
/// tools whose default UA is unambiguous — a match here has essentially no
/// false-positive cost, which is why the action is Block rather than a score.
const SCANNERS: &[&str] = &[
    "sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab", "nuclei",
    "wpscan", "dirbuster", "gobuster", "feroxbuster", "ffuf", "dirb",
    "acunetix", "nessus", "openvas", "netsparker", "qualys", "appscan",
    "whatweb", "arachni", "w3af", "skipfish", "jaeles", "havij",
    "hydra", "medusa", "brutus", "commix", "xsser", "wfuzz",
];

fn to_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[no_mangle]
pub extern "C" fn evaluate() {
    match get_req_header("user-agent") {
        None => {
            // No UA at all: unusual for browsers, normal for some SDKs. Score, don't block.
            add_score(2);
        }
        Some(ua) if ua.trim().is_empty() => {
            add_score(2);
        }
        Some(ua) => {
            let lower = to_lower(&ua);
            for sig in SCANNERS {
                if lower.contains(sig) {
                    log("scanner-guard: blocked scanner user-agent");
                    set_decision(Decision::Block);
                    return;
                }
            }
        }
    }
}
