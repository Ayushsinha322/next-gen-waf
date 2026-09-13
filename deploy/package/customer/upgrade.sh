#!/usr/bin/env bash
# =============================================================================
#  Next-Gen ESDSWAF — in-place upgrade
#
#      sudo ./upgrade.sh                # upgrade to this package's version
#      sudo ./upgrade.sh --dry-run      # run every check, change nothing
#      sudo ./upgrade.sh --force        # allow same-version or downgrade
#      sudo ./upgrade.sh --yes          # no prompts (for automation)
#
#  Run it from the NEW package directory. It reads the installed version from
#  /opt/sentinel/version and upgrades that installation in place.
#
#  Sequence: verify package -> confirm rollback is possible -> back up database
#  and secrets -> load new images -> start (migrations run as a dependency) ->
#  health checks -> AUTOMATIC ROLLBACK if those fail.
#
#  HONEST LIMIT OF "AUTOMATIC ROLLBACK" — read this before relying on it.
#
#  Database migrations are FORWARD-ONLY. Once they have applied, restoring the
#  previous container images does not un-migrate the schema, and older code may
#  not understand a newer schema. So rollback has two different characters:
#
#    - Upgrade carried NO migrations  -> image rollback is complete and clean.
#    - Upgrade DID apply migrations   -> image rollback alone can leave old code
#      against a new schema. Restoring the pre-upgrade database backup is then
#      part of the rollback, and that discards anything written since the backup
#      (usually seconds).
#
#  This script detects which case it is in and says so, rather than reporting a
#  clean rollback it did not perform. Database restore is NOT silent: it needs
#  --restore-db, or a typed confirmation.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/opt/sentinel
INSTALL_DIR="$STATE_DIR/current"
ENV_FILE="$INSTALL_DIR/.env"
LOG_DIR=/var/log/sentinel
LOG="$LOG_DIR/upgrade.log"

DRY_RUN=no; FORCE=no; ASSUME_YES=no; RESTORE_DB=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=yes ;;
    --force) FORCE=yes ;;
    --yes|-y) ASSUME_YES=yes ;;
    --restore-db) RESTORE_DB=yes ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
die()  { printf '\n  %s✗ UPGRADE ABORTED%s\n    %s\n\n' "$RED" "$R" "$*" >&2; log "ABORT $*"
         [[ "$LOG_OK" == "yes" ]] && printf '  %sThe running deployment was not modified. Log: %s%s\n\n' "$DIM" "$LOG" "$R" >&2
         exit 1; }

SERVICES=(dataplane controlplane dashboard migrate)

printf '\n  %sNext-Gen ESDSWAF — upgrade%s\n' "$B" "$R"
log "upgrade started"

# ── 1. what is installed, what are we installing ─────────────────────────────
step "Step 1 of 8 — versions"
[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -f "$ENV_FILE" ]] || die "no installation found at $INSTALL_DIR — use install.sh for a first install"
[[ -f "$HERE/bundle/manifest.json" ]] || die "bundle/manifest.json missing — run this from the NEW package directory"

CURRENT=$(cat "$STATE_DIR/version" 2>/dev/null \
          || grep -oP '^SENTINEL_VERSION=\K.*' "$ENV_FILE" 2>/dev/null || echo unknown)
NEW=$(python3 -c "import json;print(json.load(open('$HERE/bundle/manifest.json'))['version'])" 2>/dev/null || echo unknown)
[[ "$NEW" != "unknown" ]] || die "cannot read the new version from bundle/manifest.json"

say "  installed: $CURRENT"
say "  package:   $NEW"

if [[ "$CURRENT" == "$NEW" ]]; then
  [[ "$FORCE" == "yes" ]] || die "already running $NEW. Use --force to re-apply the same version."
  warn "re-applying the same version ($NEW) because --force was given"
elif [[ "$CURRENT" != "unknown" ]]; then
  # sort -V puts the lower version first; if that is the NEW one, this is a downgrade.
  older=$(printf '%s\n%s\n' "$CURRENT" "$NEW" | sort -V | head -1)
  if [[ "$older" == "$NEW" ]]; then
    [[ "$FORCE" == "yes" ]] || die "refusing to DOWNGRADE $CURRENT -> $NEW.

    Downgrading cannot undo database migrations already applied by $CURRENT, so
    the older code may not understand the current schema. If you really mean it,
    re-run with --force and be ready to restore a backup taken before $CURRENT."
    warn "DOWNGRADING $CURRENT -> $NEW because --force was given"
  else
    ok "upgrade path $CURRENT -> $NEW"
  fi
fi

# ── 2. package integrity ─────────────────────────────────────────────────────
step "Step 2 of 8 — package integrity"
[[ -f "$HERE/SHA256SUMS" ]] || die "SHA256SUMS missing — cannot verify this package"
if ( cd "$HERE" && sha256sum -c --quiet SHA256SUMS >>"$LOG" 2>&1 ); then
  ok "verified ($(wc -l < "$HERE/SHA256SUMS") files)"
else
  die "CHECKSUM MISMATCH — this package is corrupted or altered. Re-download it."
fi

# ── 3. can we actually roll back? check BEFORE changing anything ─────────────
step "Step 3 of 8 — rollback readiness"
# Promising automatic rollback is worthless if the current images have been
# pruned, so establish it up front rather than discovering it mid-failure.
rollback_possible=yes
if [[ "$CURRENT" == "unknown" ]]; then
  rollback_possible=no
  warn "installed version is unknown — automatic rollback will not be available"
else
  for svc in "${SERVICES[@]}"; do
    docker image inspect "sentinel/${svc}:${CURRENT}" >/dev/null 2>&1 || {
      warn "image sentinel/${svc}:${CURRENT} is not present locally"
      rollback_possible=no
    }
  done
  [[ "$rollback_possible" == "yes" ]] && ok "current images present — automatic rollback available"
fi
if [[ "$rollback_possible" != "yes" ]]; then
  warn "WITHOUT rollback images, a failed upgrade must be recovered from backup"
  if [[ "$ASSUME_YES" != "yes" && "$DRY_RUN" != "yes" ]]; then
    read -r -p "  Continue without automatic rollback? Type YES: " c || true
    [[ "$c" == "YES" ]] || die "aborted at rollback-readiness check"
  fi
fi

# Will this upgrade apply migrations? Knowing in advance decides how honest the
# rollback message has to be. Compare the migration files the package ships with
# the ones already applied, if the schema records them.
NEW_MIGRATIONS=unknown
applied=$(docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \
            "select count(*) from goose_db_version;" 2>/dev/null | tr -dc '0-9' || echo "")
if [[ -n "$applied" ]]; then
  ok "database currently has $applied applied migration(s)"
  NEW_MIGRATIONS="$applied"
fi

[[ "$DRY_RUN" == "yes" ]] && { say ""; ok "--dry-run: checks passed, nothing changed"; exit 0; }

if [[ "$ASSUME_YES" != "yes" ]]; then
  printf '\n  %sThis will upgrade the running deployment from %s to %s.%s\n' "$B" "$CURRENT" "$NEW" "$R"
  printf '  A backup is taken first. Traffic is briefly interrupted while the\n'
  printf '  data plane is recreated.\n\n'
  read -r -p "  Proceed? Type YES: " c || true
  [[ "$c" == "YES" ]] || die "aborted by operator"
fi

# ── 4. back up before touching anything ──────────────────────────────────────
step "Step 4 of 8 — backup"
BK_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK_DIR="$STATE_DIR/pre-upgrade-$CURRENT-to-$NEW-$BK_STAMP"
mkdir -p "$BK_DIR"
# The .env FIRST and unconditionally. A restored database is useless without the
# keys that authenticate and sign against it, and it is one small file.
cp "$ENV_FILE" "$BK_DIR/.env" && chmod 600 "$BK_DIR/.env"
ok "secrets and configuration -> $BK_DIR/.env"

if [[ -x "$INSTALL_DIR/scripts/backup/backup.sh" ]]; then
  say "  running the full database backup (Postgres + ClickHouse)…"
  if ( cd "$INSTALL_DIR/scripts/backup" && BACKUP_ROOT="$BK_DIR" ./backup.sh >>"$LOG" 2>&1 ); then
    ok "database backup complete -> $BK_DIR"
  else
    warn "backup.sh reported an error — see $LOG"
    if [[ "$ASSUME_YES" != "yes" ]]; then
      read -r -p "  Continue WITHOUT a verified database backup? Type YES: " c || true
      [[ "$c" == "YES" ]] || die "aborted — fix the backup first"
    fi
  fi
else
  # Minimum viable safety net rather than proceeding with nothing.
  warn "backup.sh not available — taking a plain pg_dump instead"
  docker exec sentinel-postgres-1 pg_dump -U sentinel -Fc sentinel > "$BK_DIR/postgres.dump" 2>>"$LOG" \
    && ok "pg_dump -> $BK_DIR/postgres.dump" \
    || die "could not back up the database — refusing to upgrade blind"
fi
printf '%s\n' "$BK_DIR" > "$STATE_DIR/last-pre-upgrade-backup"

# ── 5. load the new images ───────────────────────────────────────────────────
step "Step 5 of 8 — loading images"
docker load -i "$HERE/bundle/images.tar.gz" >>"$LOG" 2>&1 || die "docker load failed — see $LOG"
for svc in "${SERVICES[@]}"; do
  docker image inspect "sentinel/${svc}:${NEW}" >/dev/null 2>&1 \
    || die "sentinel/${svc}:${NEW} missing after load — package is incomplete"
done
ok "four images loaded at version $NEW"

# ── 6. switch version and start ──────────────────────────────────────────────
step "Step 6 of 8 — applying $NEW"
printf '%s\n' "$CURRENT" > "$STATE_DIR/previous-version"

# Refresh compose files and scripts from the new package — a new version may
# need new compose settings, and shipping new images against old compose is how
# an upgrade half-applies.
cp -r "$HERE/compose/." "$INSTALL_DIR/" 2>>"$LOG" || warn "could not refresh compose files"
rm -rf "$INSTALL_DIR/scripts.bak" 2>/dev/null || true
[[ -d "$INSTALL_DIR/scripts" ]] && mv "$INSTALL_DIR/scripts" "$INSTALL_DIR/scripts.bak"
cp -r "$HERE/scripts" "$INSTALL_DIR/scripts" 2>>"$LOG" || warn "could not refresh scripts"
chmod +x "$INSTALL_DIR"/scripts/*.sh "$INSTALL_DIR"/scripts/2vm/*.sh 2>/dev/null || true

set_version() { # set_version VERSION — rewrite SENTINEL_VERSION in .env
  python3 - "$ENV_FILE" "$1" <<'PY'
import sys, re
p, v = sys.argv[1], sys.argv[2]
s = open(p).read()
if re.search(r'^SENTINEL_VERSION=', s, flags=re.M):
    s = re.sub(r'^SENTINEL_VERSION=.*$', 'SENTINEL_VERSION=' + v, s, count=1, flags=re.M)
else:
    s = 'SENTINEL_VERSION=' + v + '\n' + s
open(p, 'w').write(s)
PY
}
set_version "$NEW"
ok ".env pinned to $NEW"

C=(docker compose -p sentinel -f "$INSTALL_DIR/compose.prod.yml" --env-file "$ENV_FILE")
( cd "$INSTALL_DIR" && "${C[@]}" config >/dev/null 2>>"$LOG" ) || {
  set_version "$CURRENT"
  die "the new compose configuration is invalid — see $LOG. Version reverted; nothing was restarted."
}
# `up -d` recreates only services whose image or config changed — postgres, redis
# and clickhouse are pinned third-party images and are left running.
say "  recreating changed services (migrations run first, as a dependency)…"
( cd "$INSTALL_DIR" && "${C[@]}" up -d >>"$LOG" 2>&1 ) || {
  warn "compose up failed — rolling back"
  ROLLBACK_REASON="compose up failed"
}

# Did migrations actually apply anything?
MIGRATED=no
# `docker logs` output is unbounded, so it must NOT be piped into `grep -q`
# under `set -o pipefail`. `grep -q` exits the moment it matches, `docker logs`
# then dies on SIGPIPE with 141, and pipefail makes the PIPELINE non-zero — so a
# pattern that IS present reads as absent. Verified: a 200k-line producer piped
# into `grep -q` on a pattern it contains returns 141 and takes the else branch
# (a small producer finishes first and happens to work, which is why this hides).
# Capturing first and matching the variable removes the pipeline entirely.
# A `tail` in the middle does not help: tail is then the one killed by SIGPIPE.
miglog=$(docker logs sentinel-migrate-1 2>&1 || true)
if grep -qE "OK\s+[0-9]+_" <<<"$(tail -40 <<<"$miglog")"; then
  MIGRATED=yes
  warn "database migrations were APPLIED by this upgrade"
else
  ok "no new database migrations (schema unchanged)"
fi
after=$(docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \
          "select count(*) from goose_db_version;" 2>/dev/null | tr -dc '0-9' || echo "")
[[ -n "$after" && -n "$NEW_MIGRATIONS" && "$after" != "$NEW_MIGRATIONS" ]] && MIGRATED=yes

# ── 7. health checks ─────────────────────────────────────────────────────────
step "Step 7 of 8 — health checks"
health_ok=yes
hc() { local label="$1"; shift
  for _ in $(seq 1 40); do "$@" >/dev/null 2>&1 && { ok "$label"; return 0; }; sleep 3; done
  printf '  %s✗%s %s\n' "$RED" "$R" "$label"; log "FAIL $label"; health_ok=no; return 1; }
hc "Postgres"   docker exec sentinel-postgres-1 pg_isready -U sentinel -d sentinel
hc "Redis"      docker exec sentinel-redis-1 valkey-cli ping
hc "ClickHouse" bash -c "docker exec sentinel-clickhouse-1 wget -qO- http://127.0.0.1:8123/ping | grep -q Ok"
hc "Data plane" bash -c "curl -fsS --max-time 3 http://127.0.0.1:80/healthz >/dev/null"
# Version actually in service, not merely loaded.
running=$(docker inspect sentinel-dataplane-1 --format '{{.Config.Image}}' 2>/dev/null || echo "")
if [[ "$running" == *":${NEW}" ]]; then ok "data plane is running $NEW"
else printf '  %s✗%s data plane is running "%s", expected %s\n' "$RED" "$R" "$running" "$NEW"; health_ok=no; fi

# ── 8. commit or roll back ───────────────────────────────────────────────────
if [[ "$health_ok" == "yes" && -z "${ROLLBACK_REASON:-}" ]]; then
  step "Step 8 of 8 — done"
  printf '%s\n' "$NEW" > "$STATE_DIR/version"
  rm -rf "$INSTALL_DIR/scripts.bak" 2>/dev/null || true
  log "upgrade $CURRENT -> $NEW succeeded"
  printf '%s %s -> %s SUCCESS\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CURRENT" "$NEW" \
    >> "$STATE_DIR/upgrade-history.log" 2>/dev/null || true
  cat <<DONE

  ${GRN}${B}Upgrade successful — now running $NEW${R}

    Previous version   $CURRENT   ${DIM}(images kept, so rollback stays possible)${R}
    Pre-upgrade backup $BK_DIR
    Migrations applied $([[ "$MIGRATED" == "yes" ]] && echo "YES" || echo "no")

  Verify independently:   sudo ./verify.sh
  Roll back if needed:    sudo ./rollback.sh
$([[ "$MIGRATED" == "yes" ]] && printf '\n  %sNote: this upgrade applied database migrations. A rollback to %s\n  will also need the database restored from the backup above.%s\n' "$YEL" "$CURRENT" "$R")

DONE
  exit 0
fi

# ---- automatic rollback -----------------------------------------------------
step "Step 8 of 8 — AUTOMATIC ROLLBACK"
printf '  %sHealth checks failed%s%s — restoring %s\n' \
  "$RED" "$R" "${ROLLBACK_REASON:+ ($ROLLBACK_REASON)}" "$CURRENT"
log "ROLLBACK triggered: health_ok=$health_ok reason=${ROLLBACK_REASON:-health}"

if [[ "$rollback_possible" != "yes" ]]; then
  printf '\n  %s✗ CANNOT ROLL BACK AUTOMATICALLY%s — the %s images are not present.\n' "$RED" "$R" "$CURRENT"
  printf '    Recover from the backup:\n      %s\n\n' "$BK_DIR"
  exit 1
fi

set_version "$CURRENT"
[[ -d "$INSTALL_DIR/scripts.bak" ]] && { rm -rf "$INSTALL_DIR/scripts"; mv "$INSTALL_DIR/scripts.bak" "$INSTALL_DIR/scripts"; }
( cd "$INSTALL_DIR" && "${C[@]}" up -d >>"$LOG" 2>&1 ) \
  || printf '  %s!%s compose up during rollback reported an error — see %s\n' "$YEL" "$R" "$LOG"

rb_ok=yes
for chk in "docker exec sentinel-postgres-1 pg_isready -U sentinel -d sentinel" \
           "curl -fsS --max-time 3 http://127.0.0.1:80/healthz"; do
  ok_this=no
  for _ in $(seq 1 30); do bash -c "$chk" >/dev/null 2>&1 && { ok_this=yes; break; }; sleep 3; done
  [[ "$ok_this" == "yes" ]] || rb_ok=no
done

if [[ "$rb_ok" == "yes" ]]; then
  ok "rolled back to $CURRENT and healthy"
else
  warn "rolled back to $CURRENT but health checks are STILL failing"
fi

if [[ "$MIGRATED" == "yes" ]]; then
  printf '\n  %s%sDATABASE SCHEMA WAS ALREADY MIGRATED FORWARD%s\n' "$B" "$YEL" "$R"
  printf '  Images are back on %s, but the schema is the %s one. Older code\n' "$CURRENT" "$NEW"
  printf '  against a newer schema is not a supported state, so the rollback is\n'
  printf '  NOT complete until the database is restored:\n\n'
  printf '      sudo %s/scripts/backup/restore.sh %s\n\n' "$INSTALL_DIR" "$BK_DIR"
  printf '  %sThat discards anything written since the backup (usually seconds).%s\n' "$DIM" "$R"
  if [[ "$RESTORE_DB" == "yes" ]]; then
    printf '\n  --restore-db given: restoring now…\n'
    if [[ -x "$INSTALL_DIR/scripts/backup/restore.sh" ]]; then
      ( cd "$INSTALL_DIR/scripts/backup" && ./restore.sh "$BK_DIR" >>"$LOG" 2>&1 ) \
        && ok "database restored from $BK_DIR" \
        || warn "restore.sh failed — see $LOG"
    else
      warn "restore.sh not available — restore manually"
    fi
  fi
else
  printf '\n  %sNo migrations were applied, so this rollback is complete.%s\n' "$GRN" "$R"
fi

printf '\n  Backup:  %s\n  Log:     %s\n\n' "$BK_DIR" "$LOG"
printf '%s %s -> %s FAILED (rolled back)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CURRENT" "$NEW" \
  >> "$STATE_DIR/upgrade-history.log" 2>/dev/null || true
exit 1
