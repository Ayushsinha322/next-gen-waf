#!/usr/bin/env bash
# Run the Go control plane natively (against Dockerized infra).
set -euo pipefail
cd "$(dirname "$0")/../../control-plane"

export SENTINEL_DB_URL="${SENTINEL_DB_URL:-postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable}"
export SENTINEL_REDIS_URL="${SENTINEL_REDIS_URL:-redis://localhost:6379}"
export SENTINEL_CLICKHOUSE_URL="${SENTINEL_CLICKHOUSE_URL:-http://sentinel:sentinel_dev@localhost:8123/sentinel_logs}"
export SENTINEL_S3_ENDPOINT="${SENTINEL_S3_ENDPOINT:-http://localhost:9002}"
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}"
export SENTINEL_LOG_LEVEL="${SENTINEL_LOG_LEVEL:-debug}"

# Use `air` for hot reload if installed, else plain go run.
if command -v air >/dev/null 2>&1; then
  exec air -c .air.toml
else
  exec go run ./cmd/controllerd
fi
