#!/usr/bin/env bash
# Run the Sentinel control plane.
# The control plane automatically starts the WAF proxy (data plane) as a
# managed child process — you do NOT need to run run-dataplane.sh separately.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT/control-plane"

export SENTINEL_DB_URL="${SENTINEL_DB_URL:-postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable}"
# Native dev connects as the Postgres superuser (RLS bypassed) — opt out of the
# multi-tenant boot assertion. Single-tenant dev only; never set in prod.
export SENTINEL_ALLOW_SUPERUSER_DB="${SENTINEL_ALLOW_SUPERUSER_DB:-1}"
export SENTINEL_REDIS_URL="${SENTINEL_REDIS_URL:-redis://localhost:6379}"
export SENTINEL_CLICKHOUSE_URL="${SENTINEL_CLICKHOUSE_URL:-http://sentinel:sentinel_dev@localhost:8123/sentinel_logs}"
export SENTINEL_S3_ENDPOINT="${SENTINEL_S3_ENDPOINT:-http://localhost:9002}"
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}"
export SENTINEL_LOG_LEVEL="${SENTINEL_LOG_LEVEL:-debug}"
export SENTINEL_LOG_DIR="${SENTINEL_LOG_DIR:-$HOME/.local/share/sentinel/logs}"  # real disk, NOT tmpfs
export SENTINEL_CONFIG="${SENTINEL_CONFIG:-$REPO_ROOT/configs/dev/sentinel.yaml}"

# Point autoStartDataPlane at the correct binary path.
export SENTINEL_PROXY_BIN="${SENTINEL_PROXY_BIN:-$REPO_ROOT/target/debug/sentinel-bin}"

mkdir -p "$SENTINEL_LOG_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Sentinel WAF — Control Plane + WAF Proxy"
echo "  REST API         : http://localhost:9501"
echo "  WAF shared port  : http://localhost:9080  (Host header routing)"
echo "  DVWA via WAF     : http://localhost:9095  (transparent, no Host needed)"
echo "  Juice Shop via WAF: http://localhost:3000 (transparent, no Host needed)"
echo "  Dashboard        : http://localhost:2222"
echo "  Log files        : $SENTINEL_LOG_DIR"
echo ""
echo "  Lab targets must run on shifted ports:"
echo "    DVWA:       docker run -p 9096:80  vulnerables/web-dvwa"
echo "    JuiceShop:  docker run -p 3001:3000 bkimminich/juice-shop"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Use air for hot reload if installed, else plain go run.
if command -v air >/dev/null 2>&1; then
  exec air -c .air.toml
else
  exec go run ./cmd/controllerd
fi
