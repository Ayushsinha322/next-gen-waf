# shellcheck shell=bash
# =============================================================================
# Shared config + helpers for Sentinel backup / restore (Docker Compose deploy).
# Sourced by backup.sh, restore.sh, and drill.sh — not run directly.
# =============================================================================

# --- Locations ---------------------------------------------------------------
BK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve compose.prod.yml across the three trees these scripts actually run from.
#
# This was hardcoded to "$BK_DIR/../docker" — the REPO layout. In the customer
# bundle the backup scripts live at scripts/backup/, so that resolved to
# scripts/docker, which does not exist; the `cd` failed, the command substitution
# produced an empty string, and COMPOSE_FILE became the literal "/compose.prod.yml".
# Every backup, restore and drill on a customer install was therefore broken —
# including the pre-upgrade backup that upgrade.sh takes before touching anything.
if [[ -z "${COMPOSE_FILE:-}" ]]; then
  for _cand in \
      "$BK_DIR/../docker/compose.prod.yml" \
      "$BK_DIR/../../compose/compose.prod.yml" \
      "/opt/sentinel/current/compose.prod.yml"; do
    if [[ -f "$_cand" ]]; then
      COMPOSE_FILE="$(cd "$(dirname "$_cand")" && pwd)/compose.prod.yml"
      break
    fi
  done
fi
if [[ -z "${COMPOSE_FILE:-}" || ! -f "$COMPOSE_FILE" ]]; then
  printf 'ERROR: cannot locate compose.prod.yml (looked beside %s, in ../../compose, and /opt/sentinel/current).\n' "$BK_DIR" >&2
  printf '       Set COMPOSE_FILE=/path/to/compose.prod.yml and re-run.\n' >&2
  exit 1
fi
ENV_FILE="${ENV_FILE:-$(dirname "$COMPOSE_FILE")/.env}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/sentinel}"   # where dumps land locally
RETENTION_DAYS="${RETENTION_DAYS:-14}"                 # local prune horizon

# --- Offsite (choose ONE; leave all blank = local-only, which is NOT DR-safe) -
#   rclone (recommended — S3/GCS/Azure/B2/SFTP): set BACKUP_RCLONE_REMOTE, e.g. s3prod:sentinel-backups
#   rsync over SSH:                              set BACKUP_RSYNC_DEST,   e.g. backup@nas:/vol/sentinel
BACKUP_RCLONE_REMOTE="${BACKUP_RCLONE_REMOTE:-}"
BACKUP_RSYNC_DEST="${BACKUP_RSYNC_DEST:-}"

# --- Container access --------------------------------------------------------
# By default we exec the DB tools inside the running compose containers (no extra
# images, no secrets on the host process list — creds come from container env).
# The drill overrides PG_CONTAINER/CH_CONTAINER to reuse this exact code path
# against throwaway containers.
PG_CONTAINER="${PG_CONTAINER:-}"
CH_CONTAINER="${CH_CONTAINER:-}"

log()  { printf '%s  %s\n' "$(date -u +%FT%TZ)" "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# shellcheck source=_crypto.sh
. "$BK_DIR/_crypto.sh"

dc() { docker compose -f "$COMPOSE_FILE" ${ENV_FILE:+--env-file "$ENV_FILE"} "$@"; }

# Run a shell snippet inside the postgres / clickhouse container. Creds are read
# from the container's OWN environment, so nothing sensitive hits argv on the host.
pg_sh() {
  if [ -n "$PG_CONTAINER" ]; then docker exec -i "$PG_CONTAINER" sh -c "$1"
  else dc exec -T postgres sh -c "$1"; fi
}
ch_sh() {
  if [ -n "$CH_CONTAINER" ]; then docker exec -i "$CH_CONTAINER" sh -c "$1"
  else dc exec -T clickhouse sh -c "$1"; fi
}

# Push a finished backup directory offsite. Returns non-zero if an offsite target
# is configured but the transfer fails (so cron/systemd surfaces it).
offsite_push() {
  local src="$1" name; name="$(basename "$src")"
  if [ "$ENCRYPTION" = none ] && [ -n "$BACKUP_RCLONE_REMOTE$BACKUP_RSYNC_DEST" ]; then
    log "refusing to send an unencrypted backup offsite — install gpg (apt-get install gnupg)"
    return 1
  fi
  if [ -n "$BACKUP_RCLONE_REMOTE" ]; then
    command -v rclone >/dev/null || die "BACKUP_RCLONE_REMOTE set but rclone not installed"
    log "offsite → rclone $BACKUP_RCLONE_REMOTE/$name"
    rclone copy --checksum "$src" "$BACKUP_RCLONE_REMOTE/$name" || return 1
  elif [ -n "$BACKUP_RSYNC_DEST" ]; then
    command -v rsync >/dev/null || die "BACKUP_RSYNC_DEST set but rsync not installed"
    log "offsite → rsync $BACKUP_RSYNC_DEST/$name"
    rsync -a --mkpath "$src/" "$BACKUP_RSYNC_DEST/$name/" || return 1
  else
    log "WARNING: no offsite target configured (BACKUP_RCLONE_REMOTE / BACKUP_RSYNC_DEST empty)."
    log "         Local-only backups do NOT protect against disk/host loss. Configure offsite for DR."
    return 0
  fi
  log "offsite copy OK"
}
