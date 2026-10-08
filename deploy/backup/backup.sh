#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — full backup: PostgreSQL (control-plane state) + ClickHouse
# (traffic/event log store) + the host's secrets and certificates → timestamped
# local dir → offsite.
#
#   PostgreSQL : pg_dump custom format (-Fc, compressed, restorable with pg_restore)
#   ClickHouse : per-table schema (SHOW CREATE) + data (FORMAT Native, gzipped)
#   secrets    : .env, the internal PKI (root CA key included) and the certificate
#                store (ACME and uploaded keys — the only copy of them), one tar
#
# Every one of those is encrypted as it is written (see _crypto.sh): nothing
# readable reaches the disk or the offsite target. The directory is root-only.
# MANIFEST.txt, clickhouse/TABLES.txt and SHA256SUMS stay readable so a backup
# can be checked and listed without the key.
#
# Writes $BACKUP_ROOT/<UTC-timestamp>/ with a manifest + SHA-256 checksums, prunes
# local backups older than $RETENTION_DAYS, then pushes offsite (rclone/rsync).
#
# Usage:  ./backup.sh
# Config: see _common.sh and _crypto.sh (BACKUP_ROOT, RETENTION_DAYS, the offsite
#         target, BACKUP_KEY_FILE / BACKUP_GPG_RECIPIENT, BACKUP_SECRETS=no for a
#         database-only backup).
# =============================================================================
set -euo pipefail
# Backups were written with the default umask: world-readable dumps of every
# user, API key hash and certificate, under a world-readable directory.
umask 077
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"
trap gpg_cleanup EXIT

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_ROOT" || die "cannot create $BACKUP_ROOT"
# Also closes off backups an older version left readable inside it.
chmod 700 "$BACKUP_ROOT" || die "cannot restrict $BACKUP_ROOT to its owner"
DEST="$BACKUP_ROOT/$STAMP"
mkdir -p "$DEST"
log "backup → $DEST"
choose_encryption
log "encryption: $ENCRYPTION$([ "$ENCRYPTION" = gpg-symmetric ] && printf ' (key %s)' "$(key_id)")"

# ── PostgreSQL ───────────────────────────────────────────────────────────────
log "pg_dump (custom format)…"
pg_sh 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"' | enc > "$DEST/postgres.dump"
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
    | sed 's/\\n/\n/g' | enc > "$DEST/clickhouse/$t.schema.sql"
  ch_sh "clickhouse-client -u \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -q \"SELECT * FROM \$CLICKHOUSE_DB.\\\`$t\\\` FORMAT Native\"" \
    | gzip | enc > "$DEST/clickhouse/$t.native.gz"
done
printf '%s\n' "${CH_TABLES[@]}" > "$DEST/clickhouse/TABLES.txt"

# ── Secrets and certificates ─────────────────────────────────────────────────
# A restored database is no use without the keys that sign and authenticate
# against it, and the certificate store held the only copy of every customer's
# private keys: none of the three was in any backup. Paths are kept as they are
# on the host, so extract-secrets.sh gives back a tree that says where each file
# goes. Overridable for the drill and for non-default layouts.
SECRETS=()
if [ "${BACKUP_SECRETS:-yes}" != no ]; then
  PKI_DIR="${PKI_DIR:-/opt/sentinel-pki}"
  if [ -z "${CERTS_DIR:-}" ]; then
    CERTS_DIR="$(docker volume inspect -f '{{.Mountpoint}}' "${COMPOSE_PROJECT:-sentinel}_sentinel-certs" 2>/dev/null || true)"
  fi
  for p in "$ENV_FILE" "$PKI_DIR" "$CERTS_DIR"; do
    if [ -n "$p" ] && [ -e "$p" ]; then SECRETS+=("${p#/}")
    else log "  secrets: ${p:-the certificate store volume} not found — not in this backup"; fi
  done
  if [ "${#SECRETS[@]}" -gt 0 ]; then
    log "secrets: ${SECRETS[*]/#//}"
    tar -cf - -C / "${SECRETS[@]}" | enc > "$DEST/secrets.tar" \
      || die "could not archive the secrets (they are root-only: run as root, or BACKUP_SECRETS=no)"
  fi
fi

# ── Manifest + checksums ─────────────────────────────────────────────────────
{
  echo "sentinel-backup"
  echo "format=2"
  echo "timestamp_utc=$STAMP"
  echo "encryption=$ENCRYPTION"
  [ "$ENCRYPTION" != gpg-symmetric ] || echo "key_id=$(key_id)"
  [ "$ENCRYPTION" != gpg-pubkey ] || echo "recipient=$BACKUP_GPG_RECIPIENT"
  echo "postgres_db=$(pg_sh 'printf %s "$POSTGRES_DB"' 2>/dev/null || echo '?')"
  echo "clickhouse_db=$(ch_sh 'printf %s "$CLICKHOUSE_DB"' 2>/dev/null || echo '?')"
  echo "clickhouse_tables=${#CH_TABLES[@]}"
  echo "secrets=$(IFS=,; printf '%s' "${SECRETS[*]/#//}")"
} > "$DEST/MANIFEST.txt"
( cd "$DEST" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + > SHA256SUMS )
log "manifest + checksums written"

# ── Retention (local) ────────────────────────────────────────────────────────
log "pruning local backups older than ${RETENTION_DAYS}d…"
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime "+$RETENTION_DAYS" -exec rm -rf {} + 2>/dev/null || true

# ── Offsite ──────────────────────────────────────────────────────────────────
offsite_push "$DEST" || die "offsite push FAILED — backup exists locally at $DEST but is NOT offsite"

log "DONE: $DEST"
