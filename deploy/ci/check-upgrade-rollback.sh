#!/usr/bin/env bash
# =============================================================================
#  The upgrade and rollback path must actually work on a customer's host.
#
#  These scripts run at the worst possible moment — mid-upgrade, or after one has
#  already gone wrong — so a defect here is not "a feature is broken", it is "the
#  customer cannot get back". Three separate ones shipped:
#
#    * `--restore-db` could NEVER succeed. backup.sh writes
#      $BACKUP_ROOT/<timestamp>/postgres.dump, restore.sh requires postgres.dump
#      directly inside the directory it is given, and upgrade.sh recorded the
#      PARENT. It only appeared to work in the fallback path, where a plain
#      pg_dump writes straight into the parent — so it failed precisely when
#      backup.sh was present, which is the normal case.
#
#    * python3 was required by both scripts. install.sh removed exactly that
#      dependency, for exactly the documented reason that Ubuntu cloud and
#      minimal images ship without it, and left these two copies behind. One of
#      them was the same `python3 … || echo unknown` idiom whose removal the
#      installer's own comment describes.
#
#    * a registry install could never be upgraded or rolled back. Images are
#      named by SENTINEL_IMAGE_PREFIX, which for those installs is the
#      customer's registry; both scripts hard-coded `sentinel/`, so the
#      present-image check found nothing and `docker load` died on a bundle that
#      ships no images on purpose.
#
#  This runs in the alpine CI image: no python, no docker daemon.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
fail=0

pass() { printf '  %s✓%s %s\n' "$GRN" "$R" "$1"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$R" "$1"; fail=$((fail + 1)); }

CUSTOMER=deploy/package/customer

printf '\n%s%s==> the recovery path does not need tools the installer says are absent%s\n\n' "$B" "$YEL" "$R"

# Comments may DISCUSS python3 — they explain why it is gone. Only a real
# invocation counts.
for f in "$CUSTOMER"/install.sh "$CUSTOMER"/upgrade.sh "$CUSTOMER"/rollback.sh; do
  hits=$(grep -nE '(^|[^#[:alnum:]_])python3?[[:space:]]' "$f" 2>/dev/null \
         | grep -vE '^[0-9]+:[[:space:]]*#' | head -3)
  if [[ -z "$hits" ]]; then
    pass "$(basename "$f") invokes no python"
  else
    bad "$(basename "$f") still invokes python:"
    printf '      %s%s%s\n' "$DIM" "$hits" "$R"
  fi
done

printf '\n%s%s==> image names come from the installation, not a hard-coded prefix%s\n\n' "$B" "$YEL" "$R"

for f in "$CUSTOMER"/upgrade.sh "$CUSTOMER"/rollback.sh; do
  hits=$(grep -nE '"sentinel/\$\{svc\}|\^sentinel/dataplane' "$f" 2>/dev/null | head -3)
  if [[ -z "$hits" ]]; then
    pass "$(basename "$f") uses SENTINEL_IMAGE_PREFIX"
  else
    bad "$(basename "$f") hard-codes the sentinel/ prefix — registry installs cannot upgrade:"
    printf '      %s%s%s\n' "$DIM" "$hits" "$R"
  fi
done

if grep -q 'IMG_PREFIX=' "$CUSTOMER/upgrade.sh" && grep -q 'IMG_PREFIX=' "$CUSTOMER/rollback.sh"; then
  pass "both read SENTINEL_IMAGE_PREFIX from the installed .env"
else
  bad "one of upgrade.sh / rollback.sh does not read SENTINEL_IMAGE_PREFIX"
fi

printf '\n%s%s==> the recorded backup is one restore.sh can actually read%s\n\n' "$B" "$YEL" "$R"

# upgrade.sh must record the directory that CONTAINS postgres.dump.
if grep -q 'printf .*"\$DUMP_DIR" > "\$STATE_DIR/last-pre-upgrade-backup"' "$CUSTOMER/upgrade.sh"; then
  pass "upgrade.sh records the directory holding the dump, not the backup root"
else
  bad "upgrade.sh does not record DUMP_DIR — --restore-db will fail on every upgrade"
fi

# And restore.sh must cope with being handed the root anyway, because old
# installations already have the parent path written into their state file.
tmp="$(mktemp -d)"
mkdir -p "$tmp/root/20260101T000000Z"
: > "$tmp/root/20260101T000000Z/postgres.dump"

# Drive only the directory-resolution logic: everything after it needs docker.
out=$(
  SRC="$tmp/root"
  if [ ! -f "$SRC/postgres.dump" ]; then
    n=$(find "$SRC" -mindepth 2 -maxdepth 2 -name postgres.dump -type f 2>/dev/null | wc -l)
    if [ "$n" -eq 1 ]; then
      SRC="$(dirname "$(find "$SRC" -mindepth 2 -maxdepth 2 -name postgres.dump -type f)")"
      printf 'descended:%s' "$SRC"
    else
      printf 'ambiguous:%s' "$n"
    fi
  fi
)
if [[ "$out" == "descended:$tmp/root/20260101T000000Z" ]]; then
  pass "a backup root with one backup inside resolves to that backup"
else
  bad "directory resolution did not descend correctly: $out"
fi

# Two backups must NOT be guessed between.
mkdir -p "$tmp/root/20260102T000000Z"; : > "$tmp/root/20260102T000000Z/postgres.dump"
n=$(find "$tmp/root" -mindepth 2 -maxdepth 2 -name postgres.dump -type f | wc -l)
if [[ "$n" -eq 2 ]] && grep -q 'holds \$n backups' deploy/backup/restore.sh; then
  pass "two backups are reported rather than silently guessed between"
else
  bad "restore.sh does not refuse an ambiguous backup root"
fi
rm -rf "$tmp"

# The scripts that actually consume the recorded path must use it.
if grep -q './restore.sh "\$DUMP_DIR"' "$CUSTOMER/upgrade.sh"; then
  pass "upgrade.sh --restore-db restores from the recorded dump directory"
else
  bad "upgrade.sh --restore-db does not use DUMP_DIR"
fi

printf '\n'
if (( fail == 0 )); then
  printf '  %s✓%s the recovery path holds\n\n' "$GRN" "$R"
  exit 0
fi
printf '  %s✗%s %d problem(s) — a customer may not be able to get back\n\n' "$RED" "$R" "$fail"
exit 1
