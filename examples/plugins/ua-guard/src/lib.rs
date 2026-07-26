//! Sentinel WAF example plugin — scanner User-Agent guard.
//!
//! Demonstrates the whole plugin contract in something you would actually run:
//! read a request header, decide, influence the verdict, and explain yourself in
//! the host log.
//!
//! The module exports `evaluate()`, which the host calls once per request for
//! each phase the manifest opts into (`request_headers` here). Host functions are
//! imported from the `env` namespace — see `crates/sentinel-plugins/src/abi.rs`
//! for the host side and `src/sdk.rs` for the documented ABI.
//!
//! Build: `rustup target add wasm32-unknown-unknown && ./build.sh`

// Host ABI. Declared directly rather than via the SDK macro because the SDK is a
// module inside the host crate meant to be copied into plugin crates, and a
// plugin must not depend on the host.
#[link(wasm_import_module = "env")]
extern "C" {
    /// Write `len` bytes at `ptr` to the host's structured log.
    fn host_log(ptr: i32, len: i32);
    /// Read a request header into `out_ptr`; returns the true length, or -1 if absent.
    fn host_get_header(name_ptr: i32, name_len: i32, out_ptr: i32, out_cap: i32) -> i32;
    /// Override the WAF decision: 0=Allow, 1=Block, 2=Challenge.
    fn host_set_decision(decision: i32);
    /// Add to this request's anomaly score.
    fn host_add_score(delta: i32);
}

const DECISION_BLOCK: i32 = 1;

/// User-Agent substrings that identify a scanner or exploitation tool. Matched
/// case-insensitively. These are tools, not browsers — a request advertising one
/// is not a user to be protected.
const BLOCK_AGENTS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nessus",
    "masscan",
    "nmap",
    "metasploit",
    "havij",
    "acunetix",
    "wpscan",
    "dirbuster",
    "gobuster",
];

/// Agents that are merely suspicious: generic scripting clients which are often
/// legitimate automation. Scored rather than blocked, so the site's threshold and
/// the rest of the pipeline decide — a plugin should not unilaterally block
/// traffic it is only unsure about.
const SUSPICIOUS_AGENTS: &[&str] = &["python-requests", "curl/", "wget/", "libwww-perl", "go-http-client"];

/// ASCII-case-insensitive substring search.
///
/// Hand-rolled to avoid allocating: `to_lowercase()` would need `alloc`, and this
/// runs on every request. Header values are ASCII by specification, so ASCII
/// folding is the correct comparison here, not Unicode folding.
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let last = haystack.len() - needle.len();
    for start in 0..=last {
        let mut hit = true;
        for i in 0..needle.len() {
            if !haystack[start + i].eq_ignore_ascii_case(&needle[i]) {
                hit = false;
                break;
            }
        }
        if hit {
            return true;
        }
    }
    false
}

fn log(msg: &str) {
    // Safety: the host reads exactly `len` bytes from `ptr` inside this module's
    // linear memory, and `msg` is live for the duration of the call.
    unsafe { host_log(msg.as_ptr() as i32, msg.len() as i32) }
}

#[no_mangle]
pub extern "C" fn evaluate() {
    // 512 bytes holds any sane User-Agent. A longer one is truncated for the
    // comparison, which is safe: a scanner name appears at the start in practice,
    // and an over-long UA is itself handled by the header-size limits.
    let mut buf = [0u8; 512];
    let name = b"user-agent";

    // Safety: both pointers are into this module's own linear memory and the
    // capacity passed matches the buffer.
    let n = unsafe {
        host_get_header(
            name.as_ptr() as i32,
            name.len() as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if n <= 0 {
        return; // header absent — nothing to judge
    }
    let ua = &buf[..(n as usize).min(buf.len())];

    for bad in BLOCK_AGENTS {
        if contains_ignore_ascii_case(ua, bad.as_bytes()) {
            log("ua-guard: blocking a known scanner User-Agent");
            unsafe {
                host_set_decision(DECISION_BLOCK);
                // Scored as well as blocked so the event carries a score
                // consistent with the verdict for anyone reading the logs.
                host_add_score(50);
            }
            return;
        }
    }

    for sus in SUSPICIOUS_AGENTS {
        if contains_ignore_ascii_case(ua, sus.as_bytes()) {
            log("ua-guard: scoring a generic scripted client");
            unsafe { host_add_score(5) };
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::contains_ignore_ascii_case;

    #[test]
    fn matches_regardless_of_case() {
        assert!(contains_ignore_ascii_case(b"Mozilla sqlMAP/1.0", b"sqlmap"));
        assert!(contains_ignore_ascii_case(b"SQLMAP", b"sqlmap"));
        assert!(contains_ignore_ascii_case(b"curl/8.5.0", b"curl/"));
    }

    #[test]
    fn does_not_match_absent_or_partial() {
        assert!(!contains_ignore_ascii_case(b"Mozilla/5.0", b"sqlmap"));
        assert!(!contains_ignore_ascii_case(b"sqlma", b"sqlmap"));
        assert!(!contains_ignore_ascii_case(b"", b"sqlmap"));
        assert!(!contains_ignore_ascii_case(b"anything", b""));
    }

    #[test]
    fn matches_at_the_very_end() {
        assert!(contains_ignore_ascii_case(b"scanner: nikto", b"nikto"));
    }
}
