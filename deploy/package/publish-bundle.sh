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
REGISTRY="ESDSWAF-v${VERSION}-registry.tar.gz"
ONLINE="ESDSWAF-v${VERSION}-online.tar.gz"
OFFLINE="ESDSWAF-v${VERSION}-offline.tar.gz"

step "Bundles for v$VERSION"
# The registry variant is the one to prefer where the target can reach Harbor, so
# it is listed first and its absence is worth a word — but none of the three is
# mandatory: publishing only what was built beats refusing to publish anything.
found=0
for f in "$REGISTRY" "$ONLINE" "$OFFLINE"; do
  if [[ -f "$f" ]]; then ok "$f ($(du -h "$f" | cut -f1))"; found=$((found+1))
  else warn "$f not built — it will not be published"; fi
done
(( found > 0 )) || die "no bundles found in dist/ for v$VERSION — run build-bundle.sh $VERSION"

# ── the bundles must agree with the source they claim to come from ───────────
# A bundle built before the last commit to the installer is the failure this
# catches: it looks fine, installs fine, and ships yesterday's fixes.
step "Provenance"
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
for f in "$REGISTRY" "$ONLINE" "$OFFLINE"; do
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
# An UNREACHABLE registry must not read as an EMPTY one. Curl returning nothing
# because the VPN dropped looks identical to "this version is not published" if
# you only inspect the body, and the consequence is publishing a duplicate over a
# version that already exists — which is exactly how 1.0.0 ended up with three
# overlapping uploads. Gate on the HTTP status, not on the text.
reg_body="$(mktemp)"
reg_code="$(curl -sS -o "$reg_body" -w '%{http_code}' --connect-timeout 15 --max-time 60 \
  -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "$GITLAB/api/v4/projects/$PROJECT_ID/packages?package_name=esdswaf" 2>/dev/null)"
case "$reg_code" in
  200) ;;
  000) rm -f "$reg_body"; die "cannot reach $GITLAB — check the VPN.
    Refusing to publish without knowing what is already in the registry." ;;
  401|403) rm -f "$reg_body"; die "GitLab rejected the token ($reg_code).
    Uploading needs a token with the 'api' scope; 'read_api' is not enough." ;;
  *) rm -f "$reg_body"; die "unexpected response from the registry: HTTP $reg_code" ;;
esac
existing="$(grep -o "\"version\":\"$VERSION\"" "$reg_body" | head -1)"
rm -f "$reg_body"
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
for f in "$REGISTRY" "$ONLINE" "$OFFLINE"; do
  [[ -f "$f" ]] || continue
  sha256sum "$f" > "$f.sha256"
  ok "$f.sha256 — $(cut -c1-16 < "$f.sha256")…"
done
# Prove they verify from this directory, which is where the customer runs them.
for f in "$REGISTRY" "$ONLINE" "$OFFLINE"; do
  [[ -f "$f" ]] || continue
  sha256sum -c "$f.sha256" >/dev/null 2>&1 || die "$f.sha256 does not verify against $f"
done
ok "every checksum verifies"

# ── split the offline archive ────────────────────────────────────────────────
UPLOADS=()
for f in "$REGISTRY" "$ONLINE"; do
  # Neither needs splitting: the registry bundle is ~316 KB and the online one
  # ~99 MB, both comfortably under this GitLab's ~250 MB cap. Only the offline
  # bundle does, and that is handled below.
  [[ -f "$f" ]] && UPLOADS+=("$f" "$f.sha256")
done
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
# Every uploaded file, against the SHA-256 GitLab itself computed on receipt.
# This used to check back ONE file — the registry or online bundle — so a publish
# of only the offline bundle "verified" a file it never uploaded, got a 404 page
# back, warned, and then printed "Published" anyway. A mismatch is now fatal.
api="$GITLAB/api/v4/projects/$PROJECT_ID/packages"
pkg_id=$(curl -sS -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
           "$api?package_type=generic&package_name=esdswaf&package_version=$VERSION" 2>/dev/null |
         python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null)
[[ -n "$pkg_id" ]] || die "the registry lists no esdswaf $VERSION package after the upload"
files_json=$(curl -sS -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "$api/$pkg_id/package_files?per_page=100" 2>/dev/null)
bad=0
for f in "${UPLOADS[@]}"; do
  want=$(sha256sum "$f" | cut -d' ' -f1)
  # Re-uploading a name adds a new entry; the newest one is what is served.
  got=$(printf '%s' "$files_json" | python3 -c '
import sys,json
name=sys.argv[1]
m=[x for x in json.load(sys.stdin) if x.get("file_name")==name]
print(max(m,key=lambda x:x["id"]).get("file_sha256") or "" if m else "")' "$f" 2>/dev/null)
  if [[ "$got" == "$want" ]]; then
    ok "$f"
  else
    warn "$f: registry has ${got:-nothing}, local is $want"; bad=1
  fi
done
(( bad == 0 )) || die "the registry does not hold what was built — do NOT announce this release"

printf '\n  %s%sPublished v%s%s\n\n' "$GRN" "$B" "$VERSION" "$R"
printf '    %s\n\n' "$GITLAB/research-lab/SIG-CyberSec/sentinel-waf/-/packages"
