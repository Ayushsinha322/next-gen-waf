#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — restore PostgreSQL + ClickHouse from a backup produced by
# backup.sh. DESTRUCTIVE: it overwrites the current databases.
#
# Usage:
#   ./restore.sh <backup-dir>          # e.g. /var/backups/sentinel/20260714T090000Z
#   ./restore.sh latest                # newest dir under $BACKUP_ROOT
#   ./restore.sh <dir> --force         # skip the confirmation prompt (automation)
#
# An encrypted backup (1.1.18 on; see _crypto.sh) needs the key it was taken
# with: $BACKUP_KEY_FILE, or the private key of BACKUP_GPG_RECIPIENT in root's
# keyring. That is checked before anything is stopped. The .env, PKI and
# certificates in the backup are not restored here: extract-secrets.sh.
#
# Without --force it asks for a typed YES, on a terminal only: with no terminal
# to ask on (a script, a pipe, output sent to a log) it refuses rather than wait
# on a question nobody can see. Callers confirm first and pass --force.
#
# Whichever of the control plane, data plane and dashboard are running are
# stopped for the restore, so nothing writes mid-restore, and started again
# afterwards, also when the restore fails. Traffic through the WAF stops until
# then. PostgreSQL and ClickHouse keep running: the restore goes through them.
# =============================================================================
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

SRC="${1:-}"; FORCE="${2:-}"
[ -n "$SRC" ] || die "usage: restore.sh <backup-dir|latest> [--force]"
if [ "$SRC" = "latest" ]; then
  SRC="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
  [ -n "$SRC" ] || die "no backups under $BACKUP_ROOT"
fi
[ -d "$SRC" ] || die "backup dir not found: $SRC"
# A caller may hand us the BACKUP_ROOT rather than one backup inside it —
# upgrade.sh did exactly that for every release, so --restore-db could never
# succeed. Descend when the answer is unambiguous, and when it is not, say what
# is actually there instead of only what is missing.
if [ ! -f "$SRC/postgres.dump" ]; then
  n=$(find "$SRC" -mindepth 2 -maxdepth 2 -name postgres.dump -type f 2>/dev/null | wc -l)
  if [ "$n" -eq 1 ]; then
    SRC="$(dirname "$(find "$SRC" -mindepth 2 -maxdepth 2 -name postgres.dump -type f)")"
    log "descended into the single backup found there: $SRC"
  elif [ "$n" -gt 1 ]; then
    die "$SRC holds $n backups — name the one you want:
$(find "$SRC" -mindepth 2 -maxdepth 2 -name postgres.dump -type f -exec dirname {} \; | sort | sed 's/^/    /')"
  else
    die "not a Swaraj Kavach backup (no postgres.dump): $SRC"
  fi
fi
log "restore source: $SRC"

# ── Integrity ────────────────────────────────────────────────────────────────
if [ -f "$SRC/SHA256SUMS" ]; then
  log "verifying checksums…"
  ( cd "$SRC" && sha256sum -c SHA256SUMS >/dev/null ) || die "checksum verification FAILED — backup is corrupt"
  log "  checksums OK"
fi

# ── Decryption ───────────────────────────────────────────────────────────────
# Proven here, before the prompt and before anything is stopped: a wrong or
# missing key must not be found out with the WAF already down.
trap gpg_cleanup EXIT
open_backup "$SRC"

# ── Confirm ──────────────────────────────────────────────────────────────────
# Only where someone can see the question and answer it. rollback.sh and
# upgrade.sh ran this without --force and with all its output in their log: the
# question went into the log while `read` waited on a terminal nobody was
# watching, and with no terminal at all `read` hit end-of-input and the restore
# failed. The prompt goes to stderr, so `| tee` still shows it.
if [ "$FORCE" != "--force" ]; then
  if [ ! -t 0 ] || [ ! -t 2 ]; then
    die "a restore needs a typed YES, and there is no terminal to ask on. Nothing was changed.
       Run it from a terminal, or confirm some other way and pass --force."
  fi
  printf 'This will OVERWRITE the live PostgreSQL and ClickHouse databases from\n  %s\nType YES to proceed: ' "$SRC" >&2
  ans=""; read -r ans || true
  [ "$ans" = "YES" ] || die "aborted — nothing was changed"
fi

# ── Writers ──────────────────────────────────────────────────────────────────
# The control plane, data plane and dashboard write to these databases, and keep
# state read out of them. Whichever are running are stopped before anything is
# overwritten and started again on the way out — on failure too, so that a
# failed restore does not also take the WAF down. PostgreSQL and ClickHouse stay
# up: the restore goes through them. Only what was running is restarted, so a
# rebuilt host with just the datastores up is left for the operator to start.
# The drill restores into throwaway containers (PG_CONTAINER/CH_CONTAINER) and
# must never stop the live stack, so it skips this.
STOPPED=(); WAS_RUNNING=0; RESTORING=no
start_writers() {
  [ "${#STOPPED[@]}" -gt 0 ] || return 0
  local svcs=("${STOPPED[@]}"); STOPPED=()
  log "starting ${svcs[*]} again…"
  if dc start "${svcs[@]}" </dev/null; then log "  started"; return 0; fi
  printf 'ERROR: could not start %s again — the WAF may not be serving traffic. Start it with:\n         docker compose -f %s up -d\n' \
    "${svcs[*]}" "$COMPOSE_FILE" >&2
  return 1
}
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$RESTORING" = yes ]; then
    printf 'ERROR: the restore did not finish, so the databases may be partly restored.\n       The backup itself is unchanged: run the restore again.\n' >&2
  fi
  start_writers || rc=1
  gpg_cleanup
  exit "$rc"
}
trap on_exit EXIT

COMPOSE_STACK=no
if [ -z "$PG_CONTAINER" ] || [ -z "$CH_CONTAINER" ]; then
  COMPOSE_STACK=yes
  running="$(dc ps --services </dev/null)" \
    || die "could not ask docker compose which services are running. Nothing was changed."
  for w in controlplane dataplane dashboard; do
    if grep -qx "$w" <<<"$running"; then STOPPED+=("$w"); fi
  done
  WAS_RUNNING=${#STOPPED[@]}
  if [ "$WAS_RUNNING" -gt 0 ]; then
    log "stopping ${STOPPED[*]} for the restore — traffic stops until it is done…"
    dc stop "${STOPPED[@]}" </dev/null || die "could not stop ${STOPPED[*]}. Nothing was restored."
  fi
fi

# ── PostgreSQL ───────────────────────────────────────────────────────────────
RESTORING=yes
log "pg_restore (--clean --if-exists)…"
dec < "$SRC/postgres.dump" \
  | pg_sh 'exec pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
log "  postgres restored"

# ── ClickHouse ───────────────────────────────────────────────────────────────
if [ -f "$SRC/clickhouse/TABLES.txt" ]; then
  log "clickhouse: restoring tables…"
  ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"CREATE DATABASE IF NOT EXISTS \$CLICKHOUSE_DB\"" </dev/null
  # The table list is read on fd 3, and nothing in the loop reads stdin it was
  # not given. `docker exec -i` and `docker compose exec` forward their stdin
  # into the container, so with the list on stdin the first DROP swallowed the
  # rest of it: only the first table was ever restored (traffic_buckets — never
  # waf_events), and the drill, with one table, could not show it.
  while IFS= read -r t <&3; do
    [ -n "$t" ] || continue
    log "  table $t"
    ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"DROP TABLE IF EXISTS \$CLICKHOUSE_DB.\\\`$t\\\`\"" </dev/null
    # recreate from the saved DDL (which carries the db-qualified name)
    dec < "$SRC/clickhouse/$t.schema.sql" \
      | ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" --multiquery"
    # reload data
    dec < "$SRC/clickhouse/$t.native.gz" | gzip -dc \
      | ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"INSERT INTO \$CLICKHOUSE_DB.\\\`$t\\\` FORMAT Native\""
  done 3< "$SRC/clickhouse/TABLES.txt"
  log "  clickhouse restored"
else
  log "no ClickHouse tables in this backup — skipping CH restore"
fi
RESTORING=no

start_writers || exit 1
if [ "$COMPOSE_STACK" = yes ] && [ "$WAS_RUNNING" -eq 0 ]; then
  log "DONE. The control plane, data plane and dashboard were not running; start them when ready:"
  log "  docker compose -f $COMPOSE_FILE up -d"
else
  log "DONE."
fi
