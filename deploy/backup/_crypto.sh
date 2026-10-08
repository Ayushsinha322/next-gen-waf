# shellcheck shell=bash
# =============================================================================
# Backup encryption. Sourced by _common.sh and extract-secrets.sh — not run
# directly. Callers provide log() and die().
#
# Every file in a backup that holds data or secrets goes through enc() as it is
# written, so nothing readable ever reaches the disk or the offsite target:
#
#   gpg-symmetric  AES-256 under the passphrase in $BACKUP_KEY_FILE — created on
#                  the first backup. It is NOT inside any backup: keep a copy off
#                  this host, or no backup can be restored after losing it.
#   gpg-pubkey     to BACKUP_GPG_RECIPIENT, a public key in root's keyring; the
#                  private key can stay off this host entirely.
#   none           gpg is not installed. The backup is still root-only on disk,
#                  but it is never pushed offsite in this state.
#
# MANIFEST.txt records which, so restore.sh reads backups taken before 1.1.18
# (always "none") as well.
# =============================================================================

# The nightly service gets these from /etc/sentinel/backup.env. So does anything
# else that runs backup.sh, restore.sh or extract-secrets.sh — upgrade.sh,
# rollback.sh, an operator — or it would encrypt under, or look for, a key other
# than the one configured there. Read, not sourced: it is only two values.
if [ -z "${BACKUP_KEY_FILE+x}${BACKUP_GPG_RECIPIENT+x}" ] && [ -r "${BACKUP_ENV_FILE:-/etc/sentinel/backup.env}" ]; then
  _bk_val() { sed -n "s/^$1=//p" "${BACKUP_ENV_FILE:-/etc/sentinel/backup.env}" | tail -1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"; }
  BACKUP_KEY_FILE="$(_bk_val BACKUP_KEY_FILE)"
  BACKUP_GPG_RECIPIENT="$(_bk_val BACKUP_GPG_RECIPIENT)"
fi
BACKUP_KEY_FILE="${BACKUP_KEY_FILE:-/etc/sentinel/backup.key}"
BACKUP_GPG_RECIPIENT="${BACKUP_GPG_RECIPIENT:-}"
ENCRYPTION=""

# A private, throwaway gpg home for the symmetric mode: the passphrase never
# meets root's keyring or a long-lived agent. Made in the calling shell, before
# any pipeline — a subshell's assignment would be lost and its directory leak.
GPG_HOME=""
gpg_init() {
  [ -z "$GPG_HOME" ] || return 0
  GPG_HOME="$(mktemp -d)" || die "mktemp failed"
  chmod 700 "$GPG_HOME"
}
gpg_cleanup() {
  [ -n "$GPG_HOME" ] || return 0
  gpgconf --homedir "$GPG_HOME" --kill all >/dev/null 2>&1 || true
  rm -rf "$GPG_HOME"; GPG_HOME=""
}

# A short, public identifier for the key a backup needs, so "which key?" has an
# answer after a rotation. A hash prefix of a 256-bit random key reveals nothing.
key_id() { sha256sum "$BACKUP_KEY_FILE" 2>/dev/null | cut -c1-16; }

ensure_backup_key() {
  if [ -s "$BACKUP_KEY_FILE" ]; then
    chmod 600 "$BACKUP_KEY_FILE" 2>/dev/null || true
    return 0
  fi
  mkdir -p "$(dirname "$BACKUP_KEY_FILE")" || die "cannot create $(dirname "$BACKUP_KEY_FILE")"
  ( umask 077
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$BACKUP_KEY_FILE.tmp" && echo >> "$BACKUP_KEY_FILE.tmp" ) \
    && mv "$BACKUP_KEY_FILE.tmp" "$BACKUP_KEY_FILE" || die "cannot write $BACKUP_KEY_FILE"
  log "WARNING: created a new backup key at $BACKUP_KEY_FILE (key id $(key_id))."
  log "         Copy it OFF this host now. It is not inside any backup, and without it"
  log "         no backup taken from now on can be restored."
}

# Decide how this backup is encrypted. Sets ENCRYPTION.
choose_encryption() {
  if [ -n "$BACKUP_GPG_RECIPIENT" ]; then
    command -v gpg >/dev/null || die "BACKUP_GPG_RECIPIENT is set but gpg is not installed (apt-get install gnupg)"
    gpg --batch --list-keys "$BACKUP_GPG_RECIPIENT" >/dev/null 2>&1 \
      || die "BACKUP_GPG_RECIPIENT '$BACKUP_GPG_RECIPIENT' is not in root's keyring — gpg --import the public key first"
    ENCRYPTION=gpg-pubkey
  elif command -v gpg >/dev/null; then
    ensure_backup_key
    gpg_init
    ENCRYPTION=gpg-symmetric
  else
    ENCRYPTION=none
    log "WARNING: gpg is not installed, so this backup is NOT encrypted (root-only on disk)."
    log "         It will not be pushed offsite. Install it: apt-get install gnupg"
  fi
}

# stdin → stdout
enc() {
  case "$ENCRYPTION" in
    gpg-symmetric)
      gpg --homedir "$GPG_HOME" --batch --quiet --no-symkey-cache --pinentry-mode loopback \
        --passphrase-file "$BACKUP_KEY_FILE" --symmetric --cipher-algo AES256 \
        --s2k-digest-algo SHA512 --compress-algo none --output - ;;
    gpg-pubkey)
      gpg --batch --quiet --trust-model always --recipient "$BACKUP_GPG_RECIPIENT" \
        --compress-algo none --encrypt --output - ;;
    none) cat ;;
    *) die "enc: encryption not chosen" ;;
  esac
}
dec() {
  case "$ENCRYPTION" in
    gpg-symmetric)
      gpg --homedir "$GPG_HOME" --batch --quiet --no-symkey-cache --pinentry-mode loopback \
        --passphrase-file "$BACKUP_KEY_FILE" --decrypt ;;
    gpg-pubkey) gpg --batch --quiet --decrypt ;;
    none) cat ;;
    *) die "dec: unknown encryption '$ENCRYPTION'" ;;
  esac
}

# Read a backup's encryption from its manifest and make sure it can be
# decrypted here, before anything is changed. Sets ENCRYPTION.
open_backup() {
  local src="$1" want
  ENCRYPTION="$(sed -n 's/^encryption=//p' "$src/MANIFEST.txt" 2>/dev/null | head -1)"
  ENCRYPTION="${ENCRYPTION:-none}"   # before 1.1.18, and upgrade.sh's plain pg_dump
  case "$ENCRYPTION" in
    none) return 0 ;;
    gpg-symmetric|gpg-pubkey) ;;
    *) die "unknown encryption '$ENCRYPTION' in $src/MANIFEST.txt. Nothing was changed." ;;
  esac
  command -v gpg >/dev/null || die "this backup is encrypted and gpg is not installed (apt-get install gnupg). Nothing was changed."
  if [ "$ENCRYPTION" = gpg-symmetric ]; then
    want="$(sed -n 's/^key_id=//p' "$src/MANIFEST.txt" | head -1)"
    [ -r "$BACKUP_KEY_FILE" ] || die "this backup is encrypted with backup key ${want:-?} and $BACKUP_KEY_FILE is missing.
       Put that key there (or set BACKUP_KEY_FILE) and run again. Nothing was changed."
    gpg_init
  fi
  log "checking that this host can decrypt the backup…"
  if ! dec < "$src/postgres.dump" > /dev/null 2>&1; then
    if [ "$ENCRYPTION" = gpg-symmetric ]; then
      die "$BACKUP_KEY_FILE (key $(key_id)) does not decrypt this backup, which needs key ${want:-?}. Nothing was changed."
    fi
    die "root's keyring here has no private key that decrypts this backup. Nothing was changed."
  fi
  log "  decrypts OK"
}
