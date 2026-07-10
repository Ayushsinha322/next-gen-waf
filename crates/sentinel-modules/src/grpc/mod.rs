//! gRPC firewall.
//!
//! A guard for gRPC endpoints fronted by the reverse-proxy data plane. gRPC
//! rides on HTTP/2 with a `content-type` of `application/grpc` (and flavors)
//! and a body of **length-prefixed message frames**. Each frame on the wire is:
//!
//! ```text
//!   [1 byte: compressed flag] [4 bytes: big-endian uint32 length] [<length> bytes: message]
//! ```
//!
//! The firewall runs in two cheap, panic-free phases:
//!
//!   - **Request phase** ([`check_request`]) — a path/method-level check that
//!     runs before the body is buffered. It can block server reflection
//!     (schema disclosure) and enforce method allow/block lists.
//!   - **Body phase** ([`check_body`]) — walks the length-prefixed frames and
//!     enforces a per-message size cap and a per-body frame-count cap (both
//!     anti-DoS controls).
//!
//! **Leniency.** A WAF may observe only a partial body (a streaming call or a
//! chunk boundary), so a truncated *tail* frame is never treated as an attack —
//! only explicit size/count violations block. An *early* frame whose declared
//! length is absurd (larger than the cap) is blocked even when the buffered
//! body is short, because that oversized length prefix is itself the DoS signal.
//!
//! **grpc-web-text** bodies are base64-encoded rather than raw frames.
//! [`check_body`] parses bytes as raw frames and errs toward leniency: a body
//! that is not well-formed raw frames simply stops parsing rather than
//! false-positiving (documented behavior — callers that want frame-level
//! inspection of grpc-web-text should base64-decode first).
//!
//! Dependency-free (std only) and safe on any input (all arithmetic is
//! checked/saturating; no indexing can go out of bounds).

/// Limits enforced by the gRPC firewall.
#[derive(Debug, Clone)]
pub struct GrpcLimits {
    /// Per-frame message-size cap, in bytes (anti-DoS).
    pub max_message_bytes: usize,
    /// Maximum number of frames permitted in one body.
    pub max_frames: usize,
    /// When `true`, server-reflection services are blocked.
    pub block_reflection: bool,
    /// If non-empty, ONLY these `/svc/Method` entries (or `/svc/`-prefix
    /// entries ending in `/`) are allowed to pass.
    pub allowed_methods: Vec<String>,
    /// These `/svc/Method` entries (or `/svc/`-prefix entries ending in `/`)
    /// are always blocked.
    pub blocked_methods: Vec<String>,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 4 * 1024 * 1024,
            max_frames: 512,
            block_reflection: true,
            allowed_methods: Vec::new(),
            blocked_methods: Vec::new(),
        }
    }
}

/// Return `true` if `content_type` is any gRPC flavor.
///
/// Recognizes `application/grpc`, `application/grpc+proto`,
/// `application/grpc+json`, `application/grpc-web`,
/// `application/grpc-web+proto`, and `application/grpc-web-text`. The match is
/// case-insensitive and ignores any `;`-delimited parameters.
pub fn is_grpc(content_type: &str) -> bool {
    // Drop any parameters (`; charset=...`) and normalize.
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime == "application/grpc"
        || mime.starts_with("application/grpc+")
        || mime.starts_with("application/grpc-web")
}

/// Path/method-level checks, run in the request-header phase before the body
/// is buffered.
///
/// Returns `Some(reason)` to **block** and `None` to allow. Enforcement order:
///
///   1. If `block_reflection` and the method is a server-reflection service
///      (path contains `grpc.reflection.` or the method segment is
///      `ServerReflectionInfo`) → blocked.
///   2. If `blocked_methods` is non-empty and the path matches an entry → blocked.
///   3. If `allowed_methods` is non-empty and the path matches no entry → blocked.
///   4. Otherwise allowed.
///
/// A method entry ending in `/` (e.g. `/pkg.Svc/`) matches by prefix (the whole
/// service); any other entry matches the exact `/pkg.Svc/Method` path.
pub fn check_request(path: &str, limits: &GrpcLimits) -> Option<String> {
    // Strip any query/fragment; gRPC method lives in the :path only.
    let path = path.split(['?', '#']).next().unwrap_or(path);

    if limits.block_reflection {
        let method_seg = path.rsplit('/').next().unwrap_or("");
        if path.contains("grpc.reflection.") || method_seg == "ServerReflectionInfo" {
            return Some("server reflection blocked".to_string());
        }
    }

    if !limits.blocked_methods.is_empty()
        && limits
            .blocked_methods
            .iter()
            .any(|entry| method_matches(path, entry))
    {
        return Some(format!("method blocked: {path}"));
    }

    if !limits.allowed_methods.is_empty()
        && !limits
            .allowed_methods
            .iter()
            .any(|entry| method_matches(path, entry))
    {
        return Some(format!("method not allowed: {path}"));
    }

    None
}

/// Return `true` if `path` matches a method-list `entry`.
///
/// An entry ending in `/` matches by prefix (an entire service); otherwise the
/// match is exact.
fn method_matches(path: &str, entry: &str) -> bool {
    if entry.ends_with('/') {
        path.starts_with(entry)
    } else {
        path == entry
    }
}

/// Body-level checks, run after the body is buffered.
///
/// Walks the length-prefixed frames and enforces `max_message_bytes` (per frame)
/// and `max_frames` (per body). Returns `Some(reason)` to **block** and `None`
/// to allow.
///
/// Parsing stops leniently at any partial/truncated tail frame (fewer than 5
/// header bytes remaining, or a declared length that runs past the buffered
/// bytes) — a partial body is expected mid-stream and is not an attack. An
/// early frame whose declared length exceeds `max_message_bytes` blocks even
/// when the body is short, because the oversized prefix is the DoS signal.
pub fn check_body(body: &[u8], limits: &GrpcLimits) -> Option<String> {
    let mut offset: usize = 0;
    let mut frame_count: usize = 0;

    loop {
        // Need at least the 5-byte frame header. Fewer bytes is a partial
        // tail frame, not an error — stop leniently.
        let remaining = body.len().saturating_sub(offset);
        if remaining < 5 {
            return None;
        }

        // Byte at `offset` is the compressed flag (ignored here). The next
        // four bytes are the big-endian message length.
        let len = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]) as usize;

        // Oversized message: block even if the body is truncated (DoS signal).
        if len > limits.max_message_bytes {
            return Some(format!(
                "message size {} exceeds max {}",
                len, limits.max_message_bytes
            ));
        }

        // Count the frame; an excess frame count is a DoS signal.
        frame_count += 1;
        if frame_count > limits.max_frames {
            return Some(format!("frame count exceeds max {}", limits.max_frames));
        }

        // Advance past this frame. Overflow or running past the end of the
        // buffer means the tail frame is incomplete — stop leniently.
        let next = offset.checked_add(5).and_then(|o| o.checked_add(len))?;
        if next > body.len() {
            return None;
        }
        offset = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> GrpcLimits {
        GrpcLimits::default()
    }

    /// Build a raw gRPC frame: `[flag][BE len][payload]`.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + payload.len());
        v.push(0u8); // uncompressed
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    // ---- is_grpc -------------------------------------------------------

    #[test]
    fn is_grpc_recognizes_every_flavor() {
        assert!(is_grpc("application/grpc"));
        assert!(is_grpc("application/grpc+proto"));
        assert!(is_grpc("application/grpc+json"));
        assert!(is_grpc("application/grpc-web"));
        assert!(is_grpc("application/grpc-web+proto"));
        assert!(is_grpc("application/grpc-web-text"));
    }

    #[test]
    fn is_grpc_is_case_insensitive_and_ignores_params() {
        assert!(is_grpc("Application/GRPC"));
        assert!(is_grpc("APPLICATION/GRPC-WEB+PROTO"));
        assert!(is_grpc("application/grpc; charset=utf-8"));
        assert!(is_grpc("  application/grpc+proto  "));
    }

    #[test]
    fn is_grpc_rejects_non_grpc() {
        assert!(!is_grpc("application/json"));
        assert!(!is_grpc("text/plain"));
        assert!(!is_grpc("application/grpcfoo")); // no delimiter after grpc
        assert!(!is_grpc(""));
    }

    // ---- check_request: reflection ------------------------------------

    #[test]
    fn reflection_v1alpha_blocked() {
        let path = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";
        assert_eq!(
            check_request(path, &limits()).as_deref(),
            Some("server reflection blocked")
        );
    }

    #[test]
    fn reflection_v1_blocked() {
        let path = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
        assert_eq!(
            check_request(path, &limits()).as_deref(),
            Some("server reflection blocked")
        );
    }

    #[test]
    fn reflection_method_segment_blocked() {
        // Even a non-standard service path is caught by the method segment.
        let path = "/some.custom.Service/ServerReflectionInfo";
        assert_eq!(
            check_request(path, &limits()).as_deref(),
            Some("server reflection blocked")
        );
    }

    #[test]
    fn reflection_allowed_when_disabled() {
        let l = GrpcLimits {
            block_reflection: false,
            ..GrpcLimits::default()
        };
        let path = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
        assert_eq!(check_request(path, &l), None);
    }

    // ---- check_request: blocked_methods -------------------------------

    #[test]
    fn blocked_method_exact() {
        let l = GrpcLimits {
            blocked_methods: vec!["/helloworld.Greeter/SayHello".to_string()],
            ..GrpcLimits::default()
        };
        assert_eq!(
            check_request("/helloworld.Greeter/SayHello", &l).as_deref(),
            Some("method blocked: /helloworld.Greeter/SayHello")
        );
        // A different method on the same service is not blocked by an exact entry.
        assert_eq!(check_request("/helloworld.Greeter/SayBye", &l), None);
    }

    #[test]
    fn blocked_method_service_prefix() {
        let l = GrpcLimits {
            blocked_methods: vec!["/admin.Admin/".to_string()],
            ..GrpcLimits::default()
        };
        assert_eq!(
            check_request("/admin.Admin/DeleteEverything", &l).as_deref(),
            Some("method blocked: /admin.Admin/DeleteEverything")
        );
        assert_eq!(check_request("/public.Api/Get", &l), None);
    }

    // ---- check_request: allowed_methods -------------------------------

    #[test]
    fn allowed_list_passes_and_rejects() {
        let l = GrpcLimits {
            block_reflection: false,
            allowed_methods: vec![
                "/helloworld.Greeter/SayHello".to_string(),
                "/public.Api/".to_string(),
            ],
            ..GrpcLimits::default()
        };
        // Exact allow entry passes.
        assert_eq!(check_request("/helloworld.Greeter/SayHello", &l), None);
        // Prefix allow entry passes for any method on the service.
        assert_eq!(check_request("/public.Api/Anything", &l), None);
        // Anything else is rejected.
        assert_eq!(
            check_request("/secret.Svc/Method", &l).as_deref(),
            Some("method not allowed: /secret.Svc/Method")
        );
    }

    #[test]
    fn empty_limits_allow_all() {
        let l = GrpcLimits {
            block_reflection: false,
            ..GrpcLimits::default()
        };
        assert_eq!(check_request("/any.Service/AnyMethod", &l), None);
    }

    // ---- check_body ---------------------------------------------------

    #[test]
    fn body_valid_single_frame() {
        let body = frame(b"hello");
        assert_eq!(check_body(&body, &limits()), None);
    }

    #[test]
    fn body_valid_multi_frame() {
        let mut body = frame(b"one");
        body.extend_from_slice(&frame(b"two"));
        body.extend_from_slice(&frame(b"three"));
        assert_eq!(check_body(&body, &limits()), None);
    }

    #[test]
    fn body_message_over_max_blocks_even_when_short() {
        let l = GrpcLimits {
            max_message_bytes: 16,
            ..GrpcLimits::default()
        };
        // Declared length 1000, but only a few payload bytes present.
        let mut body = vec![0u8];
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(b"short");
        assert_eq!(
            check_body(&body, &l).as_deref(),
            Some("message size 1000 exceeds max 16")
        );
    }

    #[test]
    fn body_frame_count_over_max_blocks() {
        let l = GrpcLimits {
            max_frames: 2,
            ..GrpcLimits::default()
        };
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend_from_slice(&frame(b"x"));
        }
        assert_eq!(
            check_body(&body, &l).as_deref(),
            Some("frame count exceeds max 2")
        );
    }

    #[test]
    fn body_empty_allowed() {
        assert_eq!(check_body(b"", &limits()), None);
    }

    #[test]
    fn body_truncated_tail_frame_allowed() {
        // A complete frame followed by a partial header (< 5 bytes) and a frame
        // whose declared length runs past the buffered bytes — both lenient.
        let mut body = frame(b"complete");
        body.extend_from_slice(&[0u8, 0, 0]); // 3 dangling bytes: partial header
        assert_eq!(check_body(&body, &limits()), None);

        let mut body2 = vec![0u8];
        body2.extend_from_slice(&50u32.to_be_bytes()); // declares 50 bytes
        body2.extend_from_slice(b"only-ten!!"); // but only 10 present
        assert_eq!(check_body(&body2, &limits()), None);
    }

    #[test]
    fn body_overflow_length_does_not_panic() {
        // Maximum uint32 length with a large cap so the size check passes and
        // the offset advance must not overflow / index out of bounds.
        let l = GrpcLimits {
            max_message_bytes: usize::MAX,
            ..GrpcLimits::default()
        };
        let mut body = vec![0u8];
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        body.extend_from_slice(b"tiny");
        // Declared length dwarfs the buffer → stop leniently, no panic.
        assert_eq!(check_body(&body, &l), None);
    }

    // ---- adversarial hardening ----------------------------------------

    #[test]
    fn allowed_list_prefix_and_substring_do_not_bypass() {
        let l = GrpcLimits {
            block_reflection: false,
            allowed_methods: vec!["/svc.S/SayHello".to_string(), "/public.Api/".to_string()],
            ..GrpcLimits::default()
        };
        // A method that extends an allowed exact entry must NOT pass (exact match).
        assert!(check_request("/svc.S/SayHelloWorld", &l).is_some());
        // A method that is a prefix of an allowed exact entry must NOT pass.
        assert!(check_request("/svc.S/SayHel", &l).is_some());
        // A sibling service that only shares a textual prefix with an allowed
        // service-prefix entry must NOT pass — the trailing '/' anchors it.
        assert!(check_request("/public.ApiEvil/Get", &l).is_some());
        // The genuine allowed service prefix still passes.
        assert_eq!(check_request("/public.Api/Get", &l), None);
    }

    #[test]
    fn blocked_service_prefix_is_boundary_anchored() {
        let l = GrpcLimits {
            blocked_methods: vec!["/admin.Admin/".to_string()],
            ..GrpcLimits::default()
        };
        // A sibling service sharing a textual prefix is not caught by the block.
        assert_eq!(check_request("/admin.AdminExtra/Op", &l), None);
        // The real service is blocked.
        assert!(check_request("/admin.Admin/Op", &l).is_some());
    }

    #[test]
    fn reflection_substring_is_blocked_not_evaded() {
        // Embedding the reflection service name as a substring still trips it.
        assert!(check_request("/x.grpc.reflection.evil.Svc/Call", &limits()).is_some());
        // The query string is stripped before matching a reflection method.
        assert_eq!(
            check_request("/pkg.Svc/ServerReflectionInfo?x=1", &limits()).as_deref(),
            Some("server reflection blocked")
        );
    }

    #[test]
    fn is_grpc_rejects_grpc_prefixed_impostors() {
        // "grpc" followed by a non-delimiter must not match.
        assert!(!is_grpc("application/grpc-evil"));
        assert!(!is_grpc("application/grpcx"));
        assert!(!is_grpc("application/x-grpc"));
        // Real grpc-web flavors (prefix match) are still recognized.
        assert!(is_grpc("application/grpc-web-text"));
    }

    #[test]
    fn oversize_later_frame_blocks_not_partial() {
        let l = GrpcLimits {
            max_message_bytes: 16,
            ..GrpcLimits::default()
        };
        // A small valid frame, then a frame whose full 5-byte header is present
        // and declares an oversize length. The oversize check must fire even
        // though the second frame's payload is truncated (not "partial-lenient").
        let mut body = frame(b"ok");
        body.push(0u8);
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(b"partialtail");
        assert_eq!(
            check_body(&body, &l).as_deref(),
            Some("message size 1000 exceeds max 16")
        );
    }

    #[test]
    fn tiny_bodies_are_lenient_no_panic() {
        // 0..=4 byte bodies never reach a full header → lenient, never panic.
        for n in 0..5usize {
            let body = vec![0u8; n];
            assert_eq!(check_body(&body, &limits()), None);
        }
        // A 4-byte all-ones fragment is still < 5 bytes → lenient.
        assert_eq!(check_body(&[1u8, 0xff, 0xff, 0xff], &limits()), None);
    }

    #[test]
    fn zero_length_frames_are_counted() {
        let l = GrpcLimits {
            max_frames: 3,
            ..GrpcLimits::default()
        };
        // Four empty frames (5-byte header, declared length 0) still count, so a
        // flood of zero-length frames cannot evade the frame-count cap.
        let mut body = Vec::new();
        for _ in 0..4 {
            body.push(0u8);
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        assert_eq!(
            check_body(&body, &l).as_deref(),
            Some("frame count exceeds max 3")
        );
    }
}
