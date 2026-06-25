#!/usr/bin/env bash
# Run the Rust data plane natively (against Dockerized infra + control plane).
# Proxies:
#   dvwa.local   → 127.0.0.1:9095  (DVWA)
#   juice.local  → 127.0.0.1:3000  (OWASP Juice Shop)
# Logs → $HOME/.local/share/sentinel/logs/*.log  (picked up by control-plane SSE hub)
set -euo pipefail
cd "$(dirname "$0")/../.."

export SENTINEL_CONFIG="${SENTINEL_CONFIG:-configs/dev/sentinel.yaml}"
export SENTINEL_LOG_DIR="${SENTINEL_LOG_DIR:-$HOME/.local/share/sentinel/logs}"  # real disk, NOT tmpfs
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}"
export RUST_LOG="${RUST_LOG:-info,sentinel=debug}"
export RUST_BACKTRACE=1

mkdir -p "$SENTINEL_LOG_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Sentinel WAF — Data Plane"
echo "  Proxy listen : http://0.0.0.0:9080"
echo "  DVWA         : http://127.0.0.1:9095  (Host: dvwa.local)"
echo "  Juice Shop   : http://127.0.0.1:3000  (Host: juice.local)"
echo "  Logs         : $SENTINEL_LOG_DIR"
echo ""
echo "  /etc/hosts entries required:"
echo "    127.0.0.1  dvwa.local"
echo "    127.0.0.1  juice.local"
echo ""
echo "  OWASP attack test:"
echo "    sentinelctl test --site dvwa"
echo "    sentinelctl test --site juice"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Use cargo watch for hot reload if installed.
if command -v cargo-watch >/dev/null 2>&1; then
  exec cargo watch -x 'run --bin sentinel-bin'
else
  exec cargo run --bin sentinel-bin
fi
