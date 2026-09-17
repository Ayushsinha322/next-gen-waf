#!/usr/bin/env bash
# =============================================================================
#  Swaraj Kavach — rollback to the previous version
#
#      sudo ./rollback.sh                 # back to the recorded previous version
#      sudo ./rollback.sh --to 1.0.0      # back to a specific version
#      sudo ./rollback.sh --list          # what can be rolled back to
#      sudo ./rollback.sh --restore-db    # also restore the pre-upgrade database
#
#  upgrade.sh already rolls back automatically when its health checks fail. This
#  script is for the other case: the upgrade passed its checks, was committed, and
#  a problem appeared later — a regression under real traffic, a behaviour change
#  you do not want, a detection rule that misfires on your workload.
#
#  WHAT A ROLLBACK CAN AND CANNOT UNDO
#
#  Container images: fully. They are still on disk, so switching back is a restart.
#
#  Database schema: NOT by itself. Migrations are forward-only. If the upgrade you
#  are undoing applied migrations, older code will be running against a newer
#  schema — not a supported state. Restoring the pre-upgrade database backup is
#  then part of the rollback, and that discards everything written since the
#  upgrade: sites added, rules edited, users created, and all attack history in
#  between. That is a real cost, so this script never does it silently.
# =============================================================================
set -uo pipefail

STATE_DIR=/opt/sentinel
INSTALL_DIR="$STATE_DIR/current"
ENV_FILE="$INSTALL_DIR/.env"
LOG_DIR=/var/log/sentinel
LOG="$LOG_DIR/upgrade.log"

TARGET=""; DO_LIST=no; RESTORE_DB=no; ASSUME_YES=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --to) TARGET="${2:-}"; shift ;;
    --list) DO_LIST=yes ;;
    --restore-db) RESTORE_DB=yes ;;
    --yes|-y) ASSUME_YES=yes ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi

LOG_OK=no
if mkdir -p "$LOG_DIR" 2>/dev/null && : >>"$LOG" 2>/dev/null; then LOG_OK=yes; fi
log()  { [[ "$LOG_OK" == "yes" ]] || return 0
         printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG" 2>/dev/null || true; }
say()  { printf '%s\n' "$*"; log "$*"; }
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; log "STEP $*"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; log "OK $*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; log "WARN $*"; }
die()  { printf '\n  %s✗ ROLLBACK ABORTED%s\n    %s\n\n' "$RED" "$R" "$*" >&2; log "ABORT $*"; exit 1; }

SERVICES=(dataplane controlplane dashboard migrate)

# See upgrade.sh: images are not always called sentinel/*. A registry install
# names them after the customer's registry, so a hard-coded prefix listed no
# rollback targets at all and the script reported there was nothing to roll
# back to on a perfectly healthy installation.
IMG_PREFIX="$(sed -n 's/^SENTINEL_IMAGE_PREFIX=//p' "$ENV_FILE" 2>/dev/null | head -1)"
IMG_PREFIX="${IMG_PREFIX:-sentinel}"

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -f "$ENV_FILE" ]] || die "no installation found at $INSTALL_DIR"

CURRENT=$(cat "$STATE_DIR/version" 2>/dev/null \
          || grep -oP '^SENTINEL_VERSION=\K.*' "$ENV_FILE" 2>/dev/null || echo unknown)

# Rollback targets are decided by what is ON DISK, not by history: a version we
# no longer have images for cannot be rolled back to, whatever the log says.
available=()
while read -r v; do [[ -n "$v" ]] && available+=("$v"); done < <(
  docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
    | grep -E "^${IMG_PREFIX}/dataplane:" | cut -d: -f2 | grep -vx latest | sort -Vr
)

if [[ "$DO_LIST" == "yes" ]]; then
  printf '\n  %sCurrently running:%s %s\n\n' "$B" "$R" "$CURRENT"
  printf '  %sVersions available to roll back to%s %s(all four images present)%s\n' "$B" "$R" "$DIM" "$R"
  found=0
  for v in "${available[@]}"; do
    [[ "$v" == "$CURRENT" ]] && continue
    complete=yes
    for svc in "${SERVICES[@]}"; do
      docker image inspect "${IMG_PREFIX}/${svc}:${v}" >/dev/null 2>&1 || complete=no
    done
    [[ "$complete" == "yes" ]] && { printf '    %s\n' "$v"; found=1; }
  done
  [[ $found -eq 0 ]] && printf '    %s(none — no other complete image set on disk)%s\n' "$DIM" "$R"
  prev=$(cat "$STATE_DIR/previous-version" 2>/dev/null || echo "")
  [[ -n "$prev" ]] && printf '\n  Recorded previous version: %s\n' "$prev"
  bk=$(cat "$STATE_DIR/last-pre-upgrade-backup" 2>/dev/null || echo "")
  [[ -n "$bk" ]] && printf '  Last pre-upgrade backup:   %s\n' "$bk"
  printf '\n'
  exit 0
fi

printf '\n  %sSwaraj Kavach — rollback%s\n' "$B" "$R"

step "Step 1 of 5 — target"
if [[ -z "$TARGET" ]]; then
  TARGET=$(cat "$STATE_DIR/previous-version" 2>/dev/null || echo "")
  [[ -n "$TARGET" ]] || die "no previous version recorded.

    List what is available and choose explicitly:
      sudo ./rollback.sh --list
      sudo ./rollback.sh --to <version>"
fi
[[ "$TARGET" != "$CURRENT" ]] || die "already running $CURRENT — nothing to roll back to"
say "  running: $CURRENT"
say "  target:  $TARGET"

for svc in "${SERVICES[@]}"; do
  docker image inspect "${IMG_PREFIX}/${svc}:${TARGET}" >/dev/null 2>&1 \
    || die "image ${IMG_PREFIX}/${svc}:${TARGET} is not on this host.

    Rollback needs all four images for the target version. Check what is
    available with:  sudo ./rollback.sh --list"
done
ok "all four $TARGET images present"

# ── 2. did the version being undone apply migrations? ────────────────────────
step "Step 2 of 5 — schema check"
BK=$(cat "$STATE_DIR/last-pre-upgrade-backup" 2>/dev/null || echo "")
applied=$(docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \
            "select count(*) from goose_db_version;" 2>/dev/null | tr -dc '0-9' || echo "")
[[ -n "$applied" ]] && say "  applied migrations in the database: $applied"
if [[ -n "$BK" && -d "$BK" ]]; then
  ok "pre-upgrade backup available: $BK"
else
  warn "no pre-upgrade backup recorded — a schema restore would not be possible"
fi
printf '\n  %sImages roll back cleanly. The SCHEMA does not — migrations are%s\n' "$YEL" "$R"
printf '  %sforward-only. If %s applied any, %s will be running against a%s\n' "$YEL" "$CURRENT" "$TARGET" "$R"
printf '  %snewer schema until the database is restored too.%s\n' "$YEL" "$R"

if [[ "$ASSUME_YES" != "yes" ]]; then
  printf '\n  This restarts the data plane; traffic is briefly interrupted.\n'
  read -r -p "  Roll back $CURRENT -> $TARGET? Type YES: " c || true
  [[ "$c" == "YES" ]] || die "aborted by operator"
fi

# ── 3. safety backup of the CURRENT state ────────────────────────────────────
step "Step 3 of 5 — backup of current state"
# Rolling back is itself a change, and someone will want to undo it. Capture the
# secrets at minimum, cheaply.
SAFE="$STATE_DIR/pre-rollback-$CURRENT-to-$TARGET-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SAFE"
cp "$ENV_FILE" "$SAFE/.env" && chmod 600 "$SAFE/.env"
ok "current configuration -> $SAFE/.env"

# ── 4. switch ────────────────────────────────────────────────────────────────
step "Step 4 of 5 — applying $TARGET"
# Pure shell, not python3: minimal Ubuntu images ship without it, and this is
# the ROLLBACK path — the one thing that must still work when an upgrade has
# already gone wrong. install.sh removed the same dependency for the same
# reason and left this copy behind.
#
# `cat >` rather than `sed -i` keeps the inode and the 0600 mode. The version is
# validated rather than escaped: a tag is [A-Za-z0-9._-].
[[ "$TARGET" =~ ^[A-Za-z0-9._-]+$ ]] \
  || die "refusing to write a version containing unexpected characters: $TARGET"
_tmp="$(mktemp)"
if grep -q '^SENTINEL_VERSION=' "$ENV_FILE"; then
  sed "s|^SENTINEL_VERSION=.*|SENTINEL_VERSION=${TARGET}|" "$ENV_FILE" > "$_tmp"
else
  { printf 'SENTINEL_VERSION=%s\n' "$TARGET"; cat "$ENV_FILE"; } > "$_tmp"
fi
[[ -s "$_tmp" ]] || { rm -f "$_tmp"; die "refusing to write an empty .env"; }
cat "$_tmp" > "$ENV_FILE"
rm -f "$_tmp"
ok ".env pinned to $TARGET"

C=(docker compose -p sentinel -f "$INSTALL_DIR/compose.prod.yml" --env-file "$ENV_FILE")
( cd "$INSTALL_DIR" && "${C[@]}" config >/dev/null 2>>"$LOG" ) \
  || die "compose configuration invalid at $TARGET — see $LOG"
( cd "$INSTALL_DIR" && "${C[@]}" up -d >>"$LOG" 2>&1 ) \
  || warn "compose up reported an error — see $LOG"
ok "services recreated at $TARGET"

# ── 5. verify ────────────────────────────────────────────────────────────────
step "Step 5 of 5 — health"
health_ok=yes
hc() { local label="$1"; shift
  for _ in $(seq 1 40); do "$@" >/dev/null 2>&1 && { ok "$label"; return 0; }; sleep 3; done
  printf '  %s✗%s %s\n' "$RED" "$R" "$label"; health_ok=no; return 1; }
hc "Postgres"   docker exec sentinel-postgres-1 pg_isready -U sentinel -d sentinel
hc "ClickHouse" bash -c "docker exec sentinel-clickhouse-1 wget -qO- http://127.0.0.1:8123/ping | grep -q Ok"
hc "Data plane" bash -c "curl -fsS --max-time 3 http://127.0.0.1:80/healthz >/dev/null"
running=$(docker inspect sentinel-dataplane-1 --format '{{.Config.Image}}' 2>/dev/null || echo "")
if [[ "$running" == *":${TARGET}" ]]; then ok "data plane is running $TARGET"
else printf '  %s✗%s data plane is running "%s", expected %s\n' "$RED" "$R" "$running" "$TARGET"; health_ok=no; fi

if [[ "$RESTORE_DB" == "yes" ]]; then
  step "Database restore (--restore-db)"
  [[ -n "$BK" && -d "$BK" ]] || die "no pre-upgrade backup to restore from"
  if [[ "$ASSUME_YES" != "yes" ]]; then
    printf '  %s%sThis DISCARDS every change made since the upgrade%s — sites, rules,\n' "$B" "$RED" "$R"
    printf '  users, and all attack history recorded in between.\n\n'
    read -r -p "  Type RESTORE to confirm: " c || true
    [[ "$c" == "RESTORE" ]] || die "database restore declined — images are on $TARGET, schema unchanged"
  fi
  if [[ -x "$INSTALL_DIR/scripts/backup/restore.sh" ]]; then
    ( cd "$INSTALL_DIR/scripts/backup" && ./restore.sh "$BK" >>"$LOG" 2>&1 ) \
      && ok "database restored from $BK" || die "restore.sh failed — see $LOG"
  else
    die "restore.sh not available — restore manually from $BK"
  fi
fi

printf '%s\n' "$TARGET" > "$STATE_DIR/version"
printf '%s\n' "$CURRENT" > "$STATE_DIR/previous-version"
printf '%s %s -> %s ROLLBACK %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CURRENT" "$TARGET" \
  "$([[ "$health_ok" == "yes" ]] && echo OK || echo UNHEALTHY)" \
  >> "$STATE_DIR/upgrade-history.log" 2>/dev/null || true

if [[ "$health_ok" == "yes" ]]; then
  cat <<DONE

  ${GRN}${B}Rolled back — now running $TARGET${R}

    Previous            $CURRENT   ${DIM}(images kept; you can go forward again)${R}
    Config backup       $SAFE/.env
    Database restored   $([[ "$RESTORE_DB" == "yes" ]] && echo "YES" || echo "no — schema is unchanged")

  Verify:  sudo ./verify.sh
$([[ "$RESTORE_DB" != "yes" && -n "$BK" ]] && printf '\n  %sIf %s applied migrations, the schema is still the newer one. To\n  complete the rollback:  sudo ./rollback.sh --to %s --restore-db%s\n' "$YEL" "$CURRENT" "$TARGET" "$R")

DONE
  exit 0
fi

printf '\n  %s✗ Rolled back to %s but health checks are FAILING%s\n' "$RED" "$TARGET" "$R"
printf '    docker compose -p sentinel ps\n    docker compose -p sentinel logs --tail 100\n'
printf '    Log: %s\n' "$LOG"
[[ -n "$BK" ]] && printf '    Full recovery from backup: %s\n' "$BK"
printf '\n'
exit 1
