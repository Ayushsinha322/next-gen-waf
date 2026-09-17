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
# Recommended: stop the control plane + data plane first so nothing writes mid-restore:
#   docker compose -f deploy/docker/compose.prod.yml stop controlplane dataplane
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
    die "not a Sentinel backup (no postgres.dump): $SRC"
  fi
fi
log "restore source: $SRC"

# ── Integrity ────────────────────────────────────────────────────────────────
if [ -f "$SRC/SHA256SUMS" ]; then
  log "verifying checksums…"
  ( cd "$SRC" && sha256sum -c SHA256SUMS >/dev/null ) || die "checksum verification FAILED — backup is corrupt"
  log "  checksums OK"
fi

# ── Confirm ──────────────────────────────────────────────────────────────────
if [ "$FORCE" != "--force" ]; then
  printf 'This will OVERWRITE the live PostgreSQL and ClickHouse databases from\n  %s\nType YES to proceed: ' "$SRC"
  read -r ans; [ "$ans" = "YES" ] || die "aborted"
fi

# ── PostgreSQL ───────────────────────────────────────────────────────────────
log "pg_restore (--clean --if-exists)…"
pg_sh 'exec pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < "$SRC/postgres.dump"
log "  postgres restored"

# ── ClickHouse ───────────────────────────────────────────────────────────────
if [ -f "$SRC/clickhouse/TABLES.txt" ]; then
  log "clickhouse: restoring tables…"
  ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"CREATE DATABASE IF NOT EXISTS \$CLICKHOUSE_DB\""
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    log "  table $t"
    ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"DROP TABLE IF EXISTS \$CLICKHOUSE_DB.\\\`$t\\\`\""
    # recreate from the saved DDL (which carries the db-qualified name)
    ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" --multiquery" < "$SRC/clickhouse/$t.schema.sql"
    # reload data
    gzip -dc "$SRC/clickhouse/$t.native.gz" \
      | ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"INSERT INTO \$CLICKHOUSE_DB.\\\`$t\\\` FORMAT Native\""
  done < "$SRC/clickhouse/TABLES.txt"
  log "  clickhouse restored"
else
  log "no ClickHouse tables in this backup — skipping CH restore"
fi

log "DONE. Restart the planes:  docker compose -f deploy/docker/compose.prod.yml up -d controlplane dataplane"
