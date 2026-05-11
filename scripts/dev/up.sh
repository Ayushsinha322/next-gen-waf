#!/usr/bin/env bash
# Bring up local development infra (Postgres, Redis, ClickHouse, MinIO, OTel, Jaeger).
# Rust + Go + Node code runs natively on the host for fastest iteration.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "→ Starting infra containers (compose.dev.yml)…"
docker compose -f deploy/docker/compose.dev.yml up -d

echo "→ Waiting for Postgres…"
until docker exec sentinel-postgres pg_isready -U sentinel >/dev/null 2>&1; do sleep 1; done
echo "  ✓ Postgres ready on localhost:5432"

echo "→ Waiting for Redis…"
until docker exec sentinel-redis redis-cli ping >/dev/null 2>&1; do sleep 1; done
echo "  ✓ Redis ready on localhost:6379"

cat <<EOF

╔════════════════════════════════════════════════════════════════════╗
║  Sentinel WAF dev infra is UP                                      ║
╠════════════════════════════════════════════════════════════════════╣
║  Postgres   localhost:5432   user=sentinel  pass=sentinel_dev      ║
║  Redis      localhost:6379                                         ║
║  ClickHouse localhost:8123 (HTTP) / 9000 (native)                  ║
║  MinIO      localhost:9001 (console) / 9002 (S3)                   ║
║  Jaeger UI  http://localhost:16686                                 ║
║  Demo upstream  http://localhost:8080                              ║
╚════════════════════════════════════════════════════════════════════╝

Next:
  ./scripts/dev/run-controlplane.sh      # Go control plane (native)
  ./scripts/dev/run-dataplane.sh         # Rust data plane (native)
  ./scripts/dev/run-dashboard.sh         # Next.js dashboard  (native)

To tear down:
  docker compose -f deploy/docker/compose.dev.yml down          # keep data
  docker compose -f deploy/docker/compose.dev.yml down -v       # wipe data
EOF
