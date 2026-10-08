#!/usr/bin/env bash
#
# least-privilege-db.sh — move an existing installation's control plane off the
# Postgres superuser.
#
# Installations made before 1.1.18 connect the control plane to Postgres as the
# superuser the database was created with, so any SQL-level compromise of the
# control plane is a superuser one (server files, COPY ... PROGRAM). A fresh
# 1.1.18 install already uses sentinel_cp: not a superuser, data privileges
# only. This converts an older one, once:
#
#   1. backs up .env next to it
#   2. adds SENTINEL_CP_DB_PASSWORD and SENTINEL_MIGRATE_DB_URL (the current,
#      owner DSN — migrations keep running as the owner) and points
#      SENTINEL_DB_URL at sentinel_cp
#   3. re-runs the migrate job, which creates sentinel_cp's login
#   4. restarts the control plane and waits for /readyz
#
# If the control plane is not ready again within two minutes, .env is put back
# and the control plane restarted on the old login. Run as root on the WAF host:
#
#   sudo ./least-privilege-db.sh
#
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'
die()  { printf '%s✗%s %s\n' "$RED" "$R" "$1" >&2; exit 1; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$1"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$1"; }

INSTALL_DIR="${INSTALL_DIR:-/opt/sentinel/current}"
ENV_FILE="$INSTALL_DIR/.env"
[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ -r "$ENV_FILE" ]] || die "cannot read $ENV_FILE"

if grep -qE '^SENTINEL_CP_DB_PASSWORD=.+' "$ENV_FILE"; then
  ok "already converted: the control plane connects as sentinel_cp"
  exit 0
fi
OWNER_URL="$(sed -n 's/^SENTINEL_DB_URL=//p' "$ENV_FILE" | head -1)"
[[ "$OWNER_URL" =~ ^postgres://sentinel:[^@]+@ ]] \
  || die "SENTINEL_DB_URL is not the installer's owner login (postgres://sentinel:…@…) — convert by hand"

C=(docker compose -p sentinel -f "$INSTALL_DIR/compose.prod.yml" --env-file "$ENV_FILE")
BACKUP="$ENV_FILE.pre-least-privilege.$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$ENV_FILE" "$BACKUP" || die "could not back up $ENV_FILE"
ok "backed up .env to $BACKUP"

PW="$(openssl rand -hex 32)"
CP_URL="postgres://sentinel_cp:${PW}@${OWNER_URL#postgres://sentinel:*@}"
TMP="$(mktemp "$ENV_FILE.XXXXXX")" || die "mktemp failed"
chmod 600 "$TMP"
{
  grep -v -E '^(SENTINEL_DB_URL|SENTINEL_MIGRATE_DB_URL|SENTINEL_CP_DB_PASSWORD)=' "$ENV_FILE"
  printf '\n# Control plane on a non-superuser login (least-privilege-db.sh, %s).\n' "$(date -u +%F)"
  printf 'SENTINEL_CP_DB_PASSWORD=%s\n' "$PW"
  printf 'SENTINEL_DB_URL=%s\n' "$CP_URL"
  printf 'SENTINEL_MIGRATE_DB_URL=%s\n' "$OWNER_URL"
} > "$TMP" && mv "$TMP" "$ENV_FILE" || die "could not write $ENV_FILE"
ok ".env updated"

restore() {
  warn "$1 — putting the old login back"
  cp -p "$BACKUP" "$ENV_FILE"
  ( cd "$INSTALL_DIR" && "${C[@]}" up -d controlplane >/dev/null 2>&1 )
  die "not converted; .env restored from $BACKUP"
}

( cd "$INSTALL_DIR" && "${C[@]}" up -d --force-recreate migrate >/dev/null 2>&1 ) || restore "the migrate job did not start"
for _ in $(seq 1 60); do
  st="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' sentinel-migrate-1 2>/dev/null)"
  [[ "$st" == exited* ]] && break
  sleep 2
done
[[ "$st" == "exited 0" ]] || restore "the migrate job did not finish cleanly ($st)"
# Captured first: `docker logs | grep -q` under pipefail reads a present line
# as absent once grep exits early and docker logs takes a SIGPIPE.
mlog="$(docker logs sentinel-migrate-1 2>&1 || true)"
grep -q 'sentinel_cp) ready' <<<"$mlog" || restore "the migrate job did not create the login"
ok "sentinel_cp login created"

( cd "$INSTALL_DIR" && "${C[@]}" up -d controlplane >/dev/null 2>&1 ) || restore "the control plane did not restart"
for _ in $(seq 1 40); do
  if docker exec sentinel-clickhouse-1 wget -qO- --timeout=5 http://controlplane:9501/readyz 2>/dev/null | grep -q '"ready":true'; then
    role="$(docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \
      "select count(*) from pg_stat_activity where usename = 'sentinel_cp'" 2>/dev/null | tr -dc 0-9)"
    ok "control plane ready on sentinel_cp (${role:-?} connections)"
    printf '\n  %sDone.%s Keep %s until you are satisfied; it holds the old login.\n\n' "$B" "$R" "$BACKUP"
    exit 0
  fi
  sleep 3
done
restore "the control plane was not ready within two minutes"
