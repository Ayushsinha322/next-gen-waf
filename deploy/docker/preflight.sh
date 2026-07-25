#!/usr/bin/env bash
# Deploy preflight for the Next-Gen ESDS WAF control-plane cluster.
#
# Catches the failure mode that crash-looped the cluster once: an image rebuilt
# to newer code whose boot-fatal env the .env / compose didn't supply. Run this
# BEFORE `docker compose ... up` on any rebuild or config change. Exit non-zero
# blocks the deploy.
#
#   ./preflight.sh                       # uses the default 3-file cluster overlay
#   COMPOSE="-f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml" ./preflight.sh
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="${COMPOSE:--f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml}"
ENV_FILE=".env"
fail=0
red(){ printf '\033[31m✗ %s\033[0m\n' "$*"; fail=1; }
ok(){ printf '\033[32m✓ %s\033[0m\n' "$*"; }

[ -f "$ENV_FILE" ] || { red ".env missing (copy .env.example)"; exit 1; }

# 1) boot-fatal keys present + long enough
check_len(){ # name minlen
  local v; v="$(grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-)"
  if [ -z "$v" ]; then red "$1 is unset"; return; fi
  if [ "${#v}" -lt "$2" ]; then red "$1 is ${#v} chars (need >=$2)"; return; fi
  ok "$1 present (${#v} chars)"
}
check_len SENTINEL_JWT_SECRET 32
check_len SENTINEL_AUDIT_HMAC_KEY 32
check_len SENTINEL_INTERNAL_SECRET 32
# Database TLS: a DSN that says disable/require is a silent downgrade. `require`
# encrypts but accepts ANY certificate, so it does not stop an interception.
if grep -qE '^SENTINEL_DB_URL=.*sslmode=(disable|allow|prefer)' "$ENV_FILE"; then
  red "SENTINEL_DB_URL uses sslmode=disable/allow/prefer — database traffic would be cleartext. Run deploy/docker/issue-postgres-cert.sh and set sslmode=verify-full"
fi
if grep -qE '^SENTINEL_DB_URL=.*sslmode=require' "$ENV_FILE"; then
  red "SENTINEL_DB_URL uses sslmode=require, which encrypts but accepts ANY server certificate. Use sslmode=verify-full with sslrootcert"
fi
if grep -qE '^SENTINEL_DB_URL=.*sslmode=verify-full' "$ENV_FILE" && ! grep -qE '^SENTINEL_DB_URL=.*sslrootcert=' "$ENV_FILE"; then
  red "SENTINEL_DB_URL uses verify-full but sets no sslrootcert — verification will fail unless the CA is in the system trust store"
fi
if grep -qE '^SENTINEL_RAFT_SECRET=' "$ENV_FILE"; then
  red "SENTINEL_RAFT_SECRET is set but no longer used — leadership is a Postgres advisory lock. Remove it from .env"
fi

# 2) compose renders (this alone fails if a :? var is unset) — the authoritative
#    view of what containers actually get (env comes from compose AND .env).
if docker compose $COMPOSE config >/tmp/_pf_cfg.yml 2>/tmp/_pf_cfg.err; then
  ok "docker compose config renders"
else
  red "docker compose config failed:"; sed 's/^/    /' /tmp/_pf_cfg.err
  rm -f /tmp/_pf_cfg.yml
fi

# 2b) superuser opt-in must be present in the RENDERED config (it's set by the
#     compose anchor, not necessarily .env) whenever a superuser DSN is used.
if [ -s /tmp/_pf_cfg.yml ]; then
  if grep -qE 'SENTINEL_ALLOW_SUPERUSER_DB: *"?1"?' /tmp/_pf_cfg.yml; then
    ok "SENTINEL_ALLOW_SUPERUSER_DB=1 present in rendered config"
  elif grep -qE 'SENTINEL_DB_URL:.*postgres://sentinel:' /tmp/_pf_cfg.yml; then
    red "superuser DSN without SENTINEL_ALLOW_SUPERUSER_DB=1 in rendered config (boot-fatal)"
  fi
fi

# 3) env PARITY across the three CP nodes (only node id / raft addr / peers may differ)
if [ -s /tmp/_pf_cfg.yml ]; then
  extract(){ awk "/^  $1:/{f=1} f&&/^  [a-z]/&&!/^  $1:/{f=0} f" /tmp/_pf_cfg.yml \
    | grep -oE 'SENTINEL_[A-Z_]+|CLICKHOUSE_[A-Z_]+' \
    | grep -vE 'SENTINEL_NODE_ID|SENTINEL_ADVERTISE_ADDR' | sort -u; }
  if diff <(extract controlplane) <(extract cp2) >/dev/null && diff <(extract cp2) <(extract cp3) >/dev/null; then
    ok "control-plane env keys identical across controlplane/cp2/cp3"
  else
    red "control-plane env key drift across nodes:"; diff <(extract controlplane) <(extract cp2) | sed 's/^/    /' || true
  fi
fi

[ "$fail" -eq 0 ] && { echo; ok "preflight PASSED — safe to deploy"; } || { echo; echo "preflight FAILED — fix the above before 'up'"; exit 1; }
