#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — full backup: PostgreSQL (control-plane state) + ClickHouse
# (traffic/event log store) → timestamped local dir → offsite.
#
#   PostgreSQL : pg_dump custom format (-Fc, compressed, restorable with pg_restore)
#   ClickHouse : per-table schema (SHOW CREATE) + data (FORMAT Native, gzipped)
#
# Writes $BACKUP_ROOT/<UTC-timestamp>/ with a manifest + SHA-256 checksums, prunes
# local backups older than $RETENTION_DAYS, then pushes offsite (rclone/rsync).
#
# Usage:  ./backup.sh
# Config: see _common.sh (BACKUP_ROOT, RETENTION_DAYS, offsite target, creds).
# =============================================================================
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_ROOT/$STAMP"
mkdir -p "$DEST"
log "backup → $DEST"

# ── PostgreSQL ───────────────────────────────────────────────────────────────
log "pg_dump (custom format)…"
pg_sh 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > "$DEST/postgres.dump"
[ -s "$DEST/postgres.dump" ] || die "postgres dump is empty"
log "  postgres.dump $(du -h "$DEST/postgres.dump" | cut -f1)"

# ── ClickHouse ───────────────────────────────────────────────────────────────
log "clickhouse: enumerating data-bearing tables…"
mkdir -p "$DEST/clickhouse"
# Base (non-view) tables in the configured DB. Views/MVs are recreated by schema,
# so we back up their definition but not a data snapshot.
mapfile -t CH_TABLES < <(ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" --param_db=\"\$CLICKHOUSE_DB\" -q \"SELECT name FROM system.tables WHERE database={db:String} AND engine NOT LIKE '%View%' AND engine NOT LIKE '%Dictionary%' ORDER BY name FORMAT TabSeparated\"" 2>/dev/null || true)

if [ "${#CH_TABLES[@]}" -eq 0 ]; then
  log "  WARNING: no ClickHouse tables found (empty DB or CH unreachable) — recording empty CH set"
fi
for t in "${CH_TABLES[@]}"; do
  [ -n "$t" ] || continue
  log "  table $t → schema + data"
  ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"SHOW CREATE TABLE \$CLICKHOUSE_DB.\\\`$t\\\`\"" \
    | sed 's/\\n/\n/g' > "$DEST/clickhouse/$t.schema.sql"
  ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"SELECT * FROM \$CLICKHOUSE_DB.\\\`$t\\\` FORMAT Native\"" \
    | gzip > "$DEST/clickhouse/$t.native.gz"
done
printf '%s\n' "${CH_TABLES[@]}" > "$DEST/clickhouse/TABLES.txt"

# ── Manifest + checksums ─────────────────────────────────────────────────────
{
  echo "sentinel-backup"
  echo "timestamp_utc=$STAMP"
  echo "postgres_db=$(pg_sh 'printf %s "$POSTGRES_DB"' 2>/dev/null || echo '?')"
  echo "clickhouse_db=$(ch_sh 'printf %s "$CLICKHOUSE_DB"' 2>/dev/null || echo '?')"
  echo "clickhouse_tables=${#CH_TABLES[@]}"
} > "$DEST/MANIFEST.txt"
( cd "$DEST" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + > SHA256SUMS )
log "manifest + checksums written"

# ── Retention (local) ────────────────────────────────────────────────────────
log "pruning local backups older than ${RETENTION_DAYS}d…"
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime "+$RETENTION_DAYS" -exec rm -rf {} + 2>/dev/null || true

# ── Offsite ──────────────────────────────────────────────────────────────────
offsite_push "$DEST" || die "offsite push FAILED — backup exists locally at $DEST but is NOT offsite"

log "DONE: $DEST"
