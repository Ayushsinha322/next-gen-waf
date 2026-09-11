#!/usr/bin/env bash
# =============================================================================
#  Bundle contract check  —  runs in CI, needs no Docker and no image build
#
#      STAGE_ONLY=1 ./deploy/package/build-bundle.sh
#      ./deploy/ci/check-bundle-contract.sh dist/ESDSWAF-v<version>
#
#  Asserts that every path the shipped scripts and compose files reference is
#  actually present in the staged customer tree.
#
#  WHY THIS EXISTS
#
#  On 2026-08-08 an audit of the install path found 54 confirmed defects, 9 of
#  them fatal. The pipeline was green throughout. It was green because ~5,200
#  lines of deploy shell were never linted, never executed and never validated by
#  anything — the entire operational surface had zero CI coverage.
#
#  Every one of the fatal packaging bugs was a CONTRACT VIOLATION visible in the
#  staged tree alone, with no image and no VM required:
#
#    * install-2vm.sh resolved "$SCRIPT_DIR/../docker", a repo-only path. In the
#      bundle it lands in scripts/2vm/, so that resolved to scripts/docker, which
#      the builder never creates. The shipped active/passive installer aborted on
#      its first check.
#    * The 2vm compose overlays bind-mount ./pg-init-replication.sh and
#      ./pg-standby-entrypoint.sh RELATIVE TO THE COMPOSE FILE, but both were
#      staged only into scripts/. Docker creates a missing bind source as a
#      DIRECTORY, so replication silently never initialised.
#    * install.sh's closing message told the operator to run fpr-report.sh, which
#      the builder never staged.
#    * backup/_common.sh hardcoded ../docker, so COMPOSE_FILE resolved to the
#      literal "/compose.prod.yml" and every backup and restore was broken.
#
#  Each check below is named after the bug it prevents. A check that cannot fail
#  is worse than no check, so every assertion here has been confirmed to fail
#  when its guard is removed.
# =============================================================================
set -uo pipefail

STAGE="${1:-}"
if [[ -z "$STAGE" ]]; then
  # NEWEST staged tree, not alphabetically first. `ls | head -1` picked the OLDEST
  # once dist/ held more than one version, so this validated a tree from a previous
  # release and reported it as stale — a confusing failure that looked like a bug in
  # the staging step rather than in this selection.
  STAGE=$(ls -dt dist/ESDSWAF-v*/ 2>/dev/null | head -1)
  STAGE="${STAGE%/}"
fi
[[ -n "$STAGE" && -d "$STAGE" ]] || {
  echo "usage: $0 <staged-tree>   (run STAGE_ONLY=1 ./deploy/package/build-bundle.sh first)" >&2
  exit 2
}

if [[ -t 1 ]]; then R=$'\e[0m'; RED=$'\e[91m'; GRN=$'\e[92m'; B=$'\e[1m'
else R=''; RED=''; GRN=''; B=''; fi

FAIL=0
pass() { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
fail() { printf '  %s✗%s %s\n' "$RED" "$R" "$*"; FAIL=1; }
sect() { printf '\n%s== %s%s\n' "$B" "$*" "$R"; }

printf '\n%sBundle contract check%s — %s\n' "$B" "$R" "$STAGE"

# Refuse to validate a STALE tree.
#
# Found the hard way: a STAGE_ONLY run failed (it could not delete a root-owned
# dist/ left behind by a container), and this script then happily validated the
# PREVIOUS staging output and reported "contract holds". The tree it checked was
# real, its checksums verified, every assertion passed — and none of it described
# the code being tested.
#
# In CI this cannot cause a false pass, because the job runs staging and checking
# as separate steps and fails on the first non-zero exit. But a checker that can
# silently describe output nobody just produced is the same defect class this file
# exists to catch, so it refuses rather than relying on the caller.
# deploy/ci/ is excluded: it is the CHECKER, not bundle content. Including it made
# the guard flag itself the moment this file was edited — a guard whose own
# maintenance trips it gets deleted by the next person, which is worse than having
# none. Compare only against what build-bundle.sh actually stages.
STALE=$(find deploy -path deploy/ci -prune -o \
          \( -name '*.sh' -o -name '*.yml' -o -name '*.yaml' -o -name '*.conf' -o -name '*.md' \) \
          -newer "$STAGE/SHA256SUMS" -print 2>/dev/null | head -3)
if [[ -n "$STALE" ]]; then
  printf '  %s✗ STALE: bundle sources are newer than the staged tree:%s\n' "$RED" "$R" >&2
  printf '%s\n' "$STALE" | sed 's/^/      /' >&2
  printf '    Re-run: STAGE_ONLY=1 ./deploy/package/build-bundle.sh\n\n' >&2
  exit 2
fi

# ── 1. layout ────────────────────────────────────────────────────────────────
sect "Tree layout"
for d in bundle compose configs scripts docs scripts/2vm; do
  [[ -d "$STAGE/$d" ]] && pass "$d/" || fail "$d/ missing"
done
for f in install.sh uninstall.sh verify.sh first-site.sh add-operator.sh upgrade.sh rollback.sh README.md SHA256SUMS; do
  [[ -f "$STAGE/$f" ]] && pass "$f" || fail "$f missing"
done

# ── 2. compose bind mounts ───────────────────────────────────────────────────
# Regression: pg-init-replication.sh / pg-standby-entrypoint.sh staged in
# scripts/ while the overlay mounts them as ./ next to the compose file.
sect "Compose bind-mount sources resolve (relative to the compose file)"
# NOTE ON SHELL MECHANICS, because this bit already bit this very script:
# `... | while read` runs the loop body in a SUBSHELL, so a FAIL=1 set inside it
# is lost when the pipe closes. The first version of this check printed four red
# failures and then reported "contract holds" — a check that cannot fail, which
# is precisely the defect class this file exists to prevent. Process substitution
# keeps the loop in the current shell so assignments stick.
for cf in "$STAGE"/compose/*.yml; do
  while read -r src; do
    [[ -n "$src" ]] || continue
    if [[ -e "$STAGE/compose/$src" ]]; then
      pass "$(basename "$cf") mounts ./$src"
    else
      fail "$(basename "$cf") mounts ./$src — NOT STAGED (Docker would silently create a directory here)"
    fi
  done < <(grep -oE '^\s*-\s+\./[A-Za-z0-9._/-]+:' "$cf" 2>/dev/null \
             | sed -E 's/^\s*-\s+\.\///; s/:$//' | sort -u)
done

# ── 3. the 2VM layout resolver ───────────────────────────────────────────────
# Regression: install-2vm.sh died on "$SCRIPT_DIR/../docker" inside the bundle.
sect "install-2vm.sh resolves its paths from the bundle layout"
RESOLVER=$(mktemp)
sed -n '/# ── where things live/,/^\[\[ -n "\$HELPER_DIR" \]\]/p' \
  "$STAGE/scripts/2vm/install-2vm.sh" > "$RESOLVER" 2>/dev/null
if [[ ! -s "$RESOLVER" ]]; then
  fail "could not extract the layout resolver from install-2vm.sh (did it change shape?)"
else
  OUT=$(SCRIPT_DIR="$(cd "$STAGE/scripts/2vm" && pwd)" bash -c '
    SCRIPT_DIR="'"$(cd "$STAGE/scripts/2vm" && pwd)"'"
    source "'"$RESOLVER"'"
    printf "%s|%s|%s|%s|%s\n" "$LAYOUT" "$COMPOSE_DIR" "$HELPER_DIR" "$ENV_EXAMPLE" "$BUNDLE_IMAGES"
  ' 2>/dev/null)
  IFS='|' read -r L CD HD EE BI <<< "$OUT"
  [[ "$L" == "bundle" ]] && pass "detects layout=bundle" || fail "layout detected as '${L:-<none>}', expected 'bundle'"
  [[ -f "$CD/compose.prod.yml"          ]] && pass "COMPOSE_DIR has compose.prod.yml"        || fail "COMPOSE_DIR ($CD) has no compose.prod.yml"
  [[ -f "$CD/compose.2vm-active.yml"    ]] && pass "COMPOSE_DIR has the 2vm overlays"        || fail "COMPOSE_DIR ($CD) has no 2vm overlay"
  [[ -f "$HD/issue-postgres-cert.sh"    ]] && pass "HELPER_DIR has issue-postgres-cert.sh"   || fail "HELPER_DIR ($HD) has no issue-postgres-cert.sh"
  [[ -f "$HD/promote-standby.sh"        ]] && pass "HELPER_DIR has promote-standby.sh"       || fail "HELPER_DIR ($HD) has no promote-standby.sh"
  [[ -f "$EE"                           ]] && pass "ENV_EXAMPLE resolves"                    || fail "ENV_EXAMPLE ($EE) missing"
  [[ -n "$BI" && -e "$BI"               ]] && pass "BUNDLE_IMAGES resolves"                  || fail "BUNDLE_IMAGES ($BI) missing"
fi
rm -f "$RESOLVER"

# ── 4. scripts the installers tell operators to run ──────────────────────────
# Regression: fpr-report.sh referenced by install.sh but never staged.
sect "Scripts referenced by the installer are shipped"
for s in fpr-report.sh backup/backup.sh backup/drill.sh issue-ip-cert.sh \
         issue-postgres-cert.sh issue-clickhouse-cert.sh promote-standby.sh preflight.sh; do
  [[ -f "$STAGE/scripts/$s" ]] && pass "scripts/$s" || fail "scripts/$s missing (an installer or doc points at it)"
done

# ── 5. backup scripts resolve compose.prod.yml from the bundle ───────────────
# Regression: _common.sh hardcoded ../docker → COMPOSE_FILE="/compose.prod.yml".
sect "backup/_common.sh finds compose.prod.yml in the bundle layout"
if [[ -f "$STAGE/scripts/backup/_common.sh" ]]; then
  BK="$(cd "$STAGE/scripts/backup" && pwd)"
  RESOLVED=$(bash -c '
    BK_DIR="'"$BK"'"
    for c in "$BK_DIR/../docker/compose.prod.yml" "$BK_DIR/../../compose/compose.prod.yml" /opt/sentinel/current/compose.prod.yml; do
      [ -f "$c" ] && { echo "$c"; exit 0; }
    done' 2>/dev/null)
  [[ -n "$RESOLVED" ]] && pass "resolves to ${RESOLVED#"$PWD"/}" \
    || fail "backup scripts cannot locate compose.prod.yml from scripts/backup/"
else
  fail "scripts/backup/_common.sh not staged"
fi

# ── 6. docs ──────────────────────────────────────────────────────────────────
sect "Operator documentation ships with the bundle"
for d in STANDALONE.md ACTIVE-PASSIVE.md TOPOLOGY.md; do
  [[ -f "$STAGE/docs/$d" ]] && pass "docs/$d" || fail "docs/$d missing"
done
# The pages an operator actually runs the product from. Checked by name because
# these are the ones referenced from install.sh's closing message, from each
# other, and from the walkthrough — a missing one is a dead link in a document
# someone is reading at 2am, not a cosmetic gap.
for d in README.md USER-MANUAL.md NOC-RUNBOOK.md ADMIN-GUIDE.md SITE-ONBOARDING.md TROUBLESHOOTING.md ROLLBACK.md; do
  [[ -f "$STAGE/docs/manual/$d" ]] && pass "docs/manual/$d" || fail "docs/manual/$d missing"
done
# The one document a first-time operator reads end to end.
# Attribution is a shipping requirement, not a nicety: without these the archive
# redistributes Apache-2.0 code with no licence text and no attribution.
[[ -f "$STAGE/THIRD-PARTY-NOTICES.md" ]] \
  && pass "THIRD-PARTY-NOTICES.md" \
  || fail "THIRD-PARTY-NOTICES.md missing"
[[ -f "$STAGE/licenses/Apache-2.0.txt" ]] \
  && pass "licenses/Apache-2.0.txt" \
  || fail "licenses/Apache-2.0.txt missing"

[[ -f "$STAGE/docs/vm-deploy/INSTALL-WALKTHROUGH.md" ]] \
  && pass "docs/vm-deploy/INSTALL-WALKTHROUGH.md" \
  || fail "docs/vm-deploy/INSTALL-WALKTHROUGH.md missing"

# ── 7. manifest is parseable by install.sh's own sed parser ──────────────────
# install.sh deliberately does not use python3; if the manifest shape drifts the
# installer reads an empty version and dies five steps later on a missing image.
sect "manifest.json is readable by the installer's parser"
MF="$STAGE/bundle/manifest.json"
if [[ -f "$MF" ]]; then
  V=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MF" | head -1)
  RI=$(sed -n 's/.*"requires_internet"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$MF" | head -1)
  [[ -n "$V"  ]] && pass "version parses as '$V'"                 || fail "version does not parse — install.sh would abort"
  [[ -n "$RI" ]] && pass "requires_internet parses as '$RI'"      || fail "requires_internet does not parse — offline detection breaks"
else
  fail "bundle/manifest.json missing"
fi

# ── 8. SHA256SUMS covers every shipped file ─────────────────────────────────
# install.sh verifies the whole package against SHA256SUMS and refuses to run on a
# mismatch. If the manifest misses files, that gate silently checks less than it
# claims — and the operator is told "package integrity verified".
#
# (A grep for repo-only paths used to live here. It was removed as a bad check:
# install-2vm.sh legitimately probes "$SCRIPT_DIR/../docker" as ONE branch of its
# multi-layout resolver, so the grep flagged correct code, and other hits were
# advice text inside echo statements. Check 3 above tests the same property
# properly, by EXECUTING the resolver against the real staged tree.)
sect "SHA256SUMS covers every shipped file"
if [[ -f "$STAGE/SHA256SUMS" ]]; then
  listed=$(wc -l < "$STAGE/SHA256SUMS")
  actual=$(cd "$STAGE" && find . -type f ! -name SHA256SUMS | wc -l)
  if [[ "$listed" -eq "$actual" ]]; then
    pass "$listed files listed, $actual files present"
  else
    fail "SHA256SUMS lists $listed files but $actual are shipped — the integrity gate covers less than the bundle"
  fi
  if ( cd "$STAGE" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1 ); then
    pass "every checksum verifies"
  else
    fail "checksums do not verify against the staged tree"
  fi
else
  fail "SHA256SUMS missing"
fi

printf '\n'
if [[ $FAIL -eq 0 ]]; then
  printf '  %s%s✓ bundle contract holds%s\n\n' "$GRN" "$B" "$R"
  exit 0
fi
printf '  %s%s✗ bundle contract VIOLATED — the shipped bundle would be broken%s\n\n' "$RED" "$B" "$R"
exit 1
