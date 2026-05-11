#!/usr/bin/env bash
# Stop dev infra. Pass -v to wipe data volumes.
set -euo pipefail
cd "$(dirname "$0")/../.."
docker compose -f deploy/docker/compose.dev.yml down "$@"
