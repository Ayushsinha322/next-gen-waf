//! The committed BPF object must PARSE, in the binary that actually ships it.
//!
//! The failure this guards against shipped for six weeks:
//!
//!   WARN kernel XDP: failed to load ELF
//!        error: "error parsing BPF object: error parsing ELF data"
//!   INFO EbpfManager initialised mode: "software"
//!
//! The cause was NOT the object file, which was always structurally valid, and
//! rebuilding it changed nothing. `include_bytes!` carries no alignment
//! guarantee, and the `object` crate reads the ELF64 header as a `Pod` needing
//! 8-byte alignment — so the outcome was decided by link layout. The same .o
//! parsed in one binary and failed in another, and in the data-plane binary it
//! landed unaligned, so kernel XDP never loaded on any deployment.
//!
//! Parsing is pure userspace, so this runs unprivileged in CI. Creating maps and
//! attaching afterwards does need privileges, so a post-parse error is accepted
//! and only a PARSE error fails: a parse error means the object we ship is
//! unusable on every machine, privileged or not.
#![cfg(feature = "kernel")]

use aya::{Ebpf, EbpfError};

#[test]
fn committed_object_is_not_rejected_at_parse_time() {
    let bytes = sentinel_ebpf::xdp_object_bytes_for_test();

    // Assert the precondition directly, so a regression names its own cause
    // instead of surfacing as aya's opaque "error parsing ELF data".
    assert_eq!(
        bytes.as_ptr() as usize % 8,
        0,
        "the embedded XDP object is not 8-byte aligned; the `object` crate will \
         reject its ELF header and aya will report the opaque \"error parsing \
         ELF data\". Keep the #[repr(align(8))] wrapper in \
         sentinel-ebpf/src/lib.rs."
    );

    match Ebpf::load(bytes) {
        Ok(bpf) => {
            let progs: Vec<_> = bpf.programs().map(|(n, _)| n.to_string()).collect();
            println!("loaded; programs = {progs:?}");
            assert!(
                progs.iter().any(|p| p == "sentinel_xdp"),
                "object loaded but exposes no `sentinel_xdp` program; the runtime \
                 looks it up by that exact name. Found: {progs:?}"
            );
        }
        Err(EbpfError::ParseError(e)) => panic!(
            "the committed sentinel_xdp.o FAILED TO PARSE: {e}\n\
             Every deployment silently falls back to software mode."
        ),
        Err(other) => {
            println!("parsed OK; post-parse error (expected unprivileged): {other}");
        }
    }
}
