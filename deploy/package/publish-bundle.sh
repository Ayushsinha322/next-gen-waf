#!/usr/bin/env bash
# =============================================================================
#  Publish a built bundle to the GitLab generic package registry.
#
#      GITLAB_TOKEN=glpat-xxxx ./deploy/package/publish-bundle.sh 1.0.1
#
#  This was a paragraph of copy-pasteable commands in deploy/vm-deploy/README.md.
#  It is a script because three of its steps are easy to get wrong by hand and
#  each failure lands on the customer rather than on us:
#
#    * The .sha256 files MUST be generated from INSIDE dist/, so they record a
#      bare filename. Generated from the repo root they record `dist/ESDSWAF-...`
#      and `sha256sum -c` then fails on the customer's machine looking for a
#      dist/ directory that does not exist there.
#
#    * The offline archive exceeds this GitLab's ~250 MB upload limit and must be
#      split. The part COUNT follows the archive size, so hardcoding it (the
#      README said four; at v1.0.1 it is three) publishes a set that cannot be
#      reassembled.
#
#    * Uploading the same version twice leaves BOTH copies in the registry under
#      one package. GitLab serves the newest consistently, but "which 1.0.0 did
#      they download" is not a question anyone should have to answer on an
#      install day. This refuses to publish over an existing version unless
#      --replace is passed.
#
#      --dry-run    show exactly what would be uploaded, upload nothing
#      --replace    publish over a version that already exists
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT/dist" 2>/dev/null || { echo "no dist/ directory — build first" >&2; exit 1; }

PROJECT_ID=1301
GITLAB=https://git.enlight.dev
SPLIT_SIZE=240M

DRY_RUN=no
REPLACE=no
VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=yes ;;
    --replace) REPLACE=yes ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *)  VERSION="$1" ;;
  esac
  shift
done

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }

[[ -n "$VERSION" ]] || VERSION="$(cat "$REPO_ROOT/VERSION" 2>/dev/null)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be MAJOR.MINOR.PATCH, got '${VERSION:-<empty>}'"
[[ -n "${GITLAB_TOKEN:-}" ]] || die "set GITLAB_TOKEN (a token with api scope — read_api is not enough to upload)"

BASE="$GITLAB/api/v4/projects/$PROJECT_ID/packages/generic/esdswaf/$VERSION"
ONLINE="ESDSWAF-v${VERSION}-online.tar.gz"
OFFLINE="ESDSWAF-v${VERSION}-offline.tar.gz"

step "Bundles for v$VERSION"
[[ -f "$ONLINE"  ]] || die "$ONLINE not found in dist/ — run build-bundle.sh $VERSION"
[[ -f "$OFFLINE" ]] || warn "$OFFLINE not found — publishing the online bundle only"
for f in "$ONLINE" "$OFFLINE"; do
  [[ -f "$f" ]] && ok "$f ($(du -h "$f" | cut -f1))"
done

# ── the bundles must agree with the source they claim to come from ───────────
# A bundle built before the last commit to the installer is the failure this
# catches: it looks fine, installs fine, and ships yesterday's fixes.
step "Provenance"
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
for f in "$ONLINE" "$OFFLINE"; do
  [[ -f "$f" ]] || continue
  built="$(tar -xzOf "$f" --wildcards '*/bundle/manifest.json' 2>/dev/null \
           | sed -n 's/.*"built_from_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [[ "$built" == "$HEAD_SHA" ]]; then
    ok "$f built from $built (= HEAD)"
  else
    warn "$f built from ${built:-unknown}, HEAD is $HEAD_SHA"
    printf '      %sthis bundle does not contain your latest commits%s\n' "$DIM" "$R"
  fi
done

# ── does this version already exist? ─────────────────────────────────────────
step "Checking the registry"
existing="$(curl -sS -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "$GITLAB/api/v4/projects/$PROJECT_ID/packages?package_name=esdswaf" 2>/dev/null \
  | grep -o "\"version\":\"$VERSION\"" | head -1)"
if [[ -n "$existing" ]]; then
  if [[ "$REPLACE" == "yes" ]]; then
    warn "v$VERSION already published — uploading anyway (--replace)"
    printf '      %sboth copies will exist; GitLab serves the newest%s\n' "$DIM" "$R"
  else
    die "v$VERSION is already in the registry.
    Publishing again leaves two copies under one package. Either bump the
    version, or pass --replace if you really mean to supersede it."
  fi
else
  ok "v$VERSION is not yet published"
fi

# ── checksums, generated HERE so they record bare filenames ──────────────────
step "Checksums"
for f in "$ONLINE" "$OFFLINE"; do
  [[ -f "$f" ]] || continue
  sha256sum "$f" > "$f.sha256"
  ok "$f.sha256 — $(cut -c1-16 < "$f.sha256")…"
done
# Prove they verify from this directory, which is where the customer runs them.
for f in "$ONLINE" "$OFFLINE"; do
  [[ -f "$f" ]] || continue
  sha256sum -c "$f.sha256" >/dev/null 2>&1 || die "$f.sha256 does not verify against $f"
done
ok "both checksums verify"

# ── split the offline archive ────────────────────────────────────────────────
UPLOADS=("$ONLINE" "$ONLINE.sha256")
if [[ -f "$OFFLINE" ]]; then
  step "Splitting the offline archive (GitLab rejects uploads over ~250 MB)"
  rm -f "$OFFLINE.part-"*
  split -b "$SPLIT_SIZE" -d -a 2 "$OFFLINE" "$OFFLINE.part-"
  n=0
  for p in "$OFFLINE.part-"*; do
    ok "$p ($(du -h "$p" | cut -f1))"
    UPLOADS+=("$p"); n=$((n+1))
  done
  UPLOADS+=("$OFFLINE.sha256")
  # Reassemble and check, here, rather than letting the customer discover a bad
  # split. The whole point of the parts is that joining them is lossless.
  cat "$OFFLINE.part-"* > "$OFFLINE.rejoined"
  if cmp -s "$OFFLINE" "$OFFLINE.rejoined"; then
    ok "$n parts rejoin byte-identically"
  else
    rm -f "$OFFLINE.rejoined"; die "the parts do not rejoin to the original — do not publish"
  fi
  rm -f "$OFFLINE.rejoined"
fi

# ── upload ───────────────────────────────────────────────────────────────────
step "Uploading to $BASE"
if [[ "$DRY_RUN" == "yes" ]]; then
  for f in "${UPLOADS[@]}"; do printf '  %s(dry-run)%s %s\n' "$DIM" "$R" "$f"; done
  printf '\n  %s--dry-run: nothing was uploaded.%s\n\n' "$YEL" "$R"
  exit 0
fi

fail=0
for f in "${UPLOADS[@]}"; do
  printf '  %-52s ' "$f"
  code=$(curl -sS -o /dev/null -w '%{http_code}' \
           --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
           --upload-file "$f" "$BASE/$f" 2>/dev/null)
  case "$code" in
    201|200) printf '%s✓ %s%s\n' "$GRN" "$code" "$R" ;;
    413)     printf '%s✗ 413 too large%s\n' "$RED" "$R"; fail=1 ;;
    *)       printf '%s✗ %s%s\n' "$RED" "$code" "$R"; fail=1 ;;
  esac
done

(( fail == 0 )) || die "one or more uploads failed — the published set is INCOMPLETE"

step "Verifying what the registry actually serves"
served=$(curl -sS -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "$BASE/$ONLINE.sha256" 2>/dev/null)
local_sum=$(cat "$ONLINE.sha256")
if [[ "$served" == "$local_sum" ]]; then
  ok "the registry serves the checksum we just built"
else
  warn "served checksum differs from the local one:"
  printf '      served: %s\n      local : %s\n' "${served:0:20}…" "${local_sum:0:20}…"
fi

printf '\n  %s%sPublished v%s%s\n\n' "$GRN" "$B" "$VERSION" "$R"
printf '    %s\n\n' "$GITLAB/research-lab/SIG-CyberSec/sentinel-waf/-/packages"
