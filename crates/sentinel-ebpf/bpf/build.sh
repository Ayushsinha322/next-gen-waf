#!/usr/bin/env bash
# Recompile the XDP program to a committed BPF ELF. Run this only when
# sentinel_xdp.bpf.c changes; the runtime build embeds the committed .o via
# include_bytes! and needs no BPF toolchain. Requires clang (-target bpf).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
arch_inc="/usr/include/$(uname -m)-linux-gnu"
clang -O2 -g -Wall -target bpf \
  -I "$here" -I "$arch_inc" \
  -c "$here/sentinel_xdp.bpf.c" \
  -o "$here/../src/bpf/sentinel_xdp.o"
echo "built $here/../src/bpf/sentinel_xdp.o"
