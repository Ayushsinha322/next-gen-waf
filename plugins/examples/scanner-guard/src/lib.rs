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

/// Lower-cased substrings that identify scanner and exploitation tooling.
///
/// This list follows the SAME policy as the control plane's built-in
/// bad-user-agent indicators (`builtinBadUserAgents` in
/// internal/threatintel/sources.go), and it must not drift from it:
///
///  1. The string is meaningless outside the tool. No generic words, and no
///     names that collide with legitimate software.
///  2. The tool is hostile in UNSOLICITED traffic. An enterprise scanner a
///     customer points at their own site under a maintenance window is not.
///
/// Removed 2026-09-07 for violating those rules: `qualys` and `appscan` are
/// authorised scans, `medusa` collides with a widely used media manager whose
/// UA is "Medusa/x.y", and `brutus` is a word. They were the ONLY entries here
/// that the control plane's policy deliberately refuses — so the plugin was
/// blocking traffic the product had decided not to block, which is the worst
/// kind of divergence: invisible, and only in one direction.
///
/// The remaining names overlap the node-wide indicator corpus by design. That
/// corpus normally matches first, so this plugin's block path is usually
/// unreachable on a deployment with threat intel enabled; it still matters
/// where threat intel is off, its feed is stale, or an operator wants the check
/// on one site only. The scoring branch below (no User-Agent at all) is this
/// plugin's own contribution either way.
const SCANNERS: &[&str] = &[
    // exploitation
    "sqlmap", "sqlninja", "commix", "havij", "xsser", "xsstrike", "dalfox",
    "fimap", "hydra",
    // scanners
    "nikto", "nmap scripting engine", "masscan", "zgrab", "nuclei", "wpscan",
    "whatweb", "arachni", "w3af", "skipfish", "jaeles", "openvas", "netsparker",
    "nessus", "acunetix",
    // content discovery / fuzzing
    "dirb", "gobuster", "feroxbuster", "ffuf", "wfuzz", "dirsearch",
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
