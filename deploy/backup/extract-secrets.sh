#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — unpack the .env, internal PKI and certificate store from a
# backup taken by backup.sh (1.1.18 on).
#
#   ./extract-secrets.sh <backup-dir|latest> <out-dir>
#
# <out-dir> gets a root-only tree that mirrors where each file lived on the host
# it was taken from, for example:
#
#   <out-dir>/opt/sentinel/current/.env
#   <out-dir>/opt/sentinel-pki/root.key …
#   <out-dir>/var/lib/docker/volumes/sentinel_sentinel-certs/_data/…
#
# Nothing is put in place: copy back what you need (RUNBOOK.md, "Rebuilding on a
# new host"). Needs the backup's key, as restore.sh does.
# =============================================================================
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log()  { printf '%s  %s\n' "$(date -u +%FT%TZ)" "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# shellcheck source=_crypto.sh
. "$HERE/_crypto.sh"
trap gpg_cleanup EXIT

SRC="${1:-}"; OUT="${2:-}"
[ -n "$SRC" ] && [ -n "$OUT" ] || die "usage: extract-secrets.sh <backup-dir|latest> <out-dir>"
if [ "$SRC" = latest ]; then
  SRC="$(find "${BACKUP_ROOT:-/var/backups/sentinel}" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
  [ -n "$SRC" ] || die "no backups under ${BACKUP_ROOT:-/var/backups/sentinel}"
fi
[ -f "$SRC/secrets.tar" ] || die "no secrets.tar in $SRC (taken before 1.1.18, or with BACKUP_SECRETS=no)"
if [ -f "$SRC/SHA256SUMS" ]; then
  ( cd "$SRC" && sha256sum -c --ignore-missing SHA256SUMS >/dev/null ) || die "checksum verification FAILED — backup is corrupt"
fi
open_backup "$SRC"

mkdir -p "$OUT" && chmod 700 "$OUT" || die "cannot create $OUT"
dec < "$SRC/secrets.tar" | tar -xf - -C "$OUT" || die "could not unpack $SRC/secrets.tar"
log "unpacked into $OUT:"
sed -n 's/^secrets=//p' "$SRC/MANIFEST.txt" | tr ',' '\n' | sed 's/^/    /'
