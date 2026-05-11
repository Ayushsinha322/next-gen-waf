#!/usr/bin/env bash
# Run the Rust data plane natively (against Dockerized infra + control plane).
set -euo pipefail
cd "$(dirname "$0")/../.."

export SENTINEL_CONFIG="${SENTINEL_CONFIG:-configs/dev/sentinel.yaml}"
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}"
export RUST_LOG="${RUST_LOG:-info,sentinel=debug}"
export RUST_BACKTRACE=1

# Use `cargo watch` for hot reload if installed.
if command -v cargo-watch >/dev/null 2>&1; then
  exec cargo watch -x 'run --bin sentinel-bin'
else
  exec cargo run --bin sentinel-bin
fi
