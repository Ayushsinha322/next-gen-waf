#!/usr/bin/env bash
# =============================================================================
#  Swaraj Kavach — download helper
#
#  Fetches the installation bundle from the ESDS GitLab Package Registry,
#  reassembles it if it was split, verifies its checksum, and extracts it.
#
#      export GITLAB_TOKEN=<your GitLab personal access token>
#      ./get-esdswaf.sh                 # offline bundle (default, always works)
#      ./get-esdswaf.sh --online        # smaller, needs Docker Hub at install time
#      ./get-esdswaf.sh --version 1.1.0
#
#  Then:  cd ESDSWAF-v<version> && sudo ./install.sh
#
#  This script does NOT install anything and does not need root. It only
#  downloads into the current directory.
# =============================================================================
set -uo pipefail

GITLAB_HOST="${GITLAB_HOST:-git.enlight.dev}"
PROJECT_ID="${PROJECT_ID:-1301}"
PKG_NAME="esdswaf"
VERSION="${ESDSWAF_VERSION:-1.1.0}"
VARIANT="offline"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --offline) VARIANT=offline ;;
    --online)  VARIANT=online ;;
    --version) VERSION="${2:-}"; shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; CYN=''; fi
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
[[ -n "${GITLAB_TOKEN:-}" ]] || die \
"GITLAB_TOKEN is not set.

  The project is private, so downloading needs a GitLab token.
  Create one at: https://${GITLAB_HOST}/-/user_settings/personal_access_tokens
  with the 'read_api' scope, then:

      export GITLAB_TOKEN=glpat-xxxxxxxxxxxx
      $0 ${VARIANT:+--$VARIANT}

  Or download in a browser instead — no token needed when you are logged in:
      https://${GITLAB_HOST}/research-lab/SIG-CyberSec/sentinel-waf/-/packages"

BASE="https://${GITLAB_HOST}/api/v4/projects/${PROJECT_ID}/packages/generic/${PKG_NAME}/${VERSION}"
ARCHIVE="ESDSWAF-v${VERSION}-${VARIANT}.tar.gz"

fetch() { # fetch REMOTE_NAME
  curl -fsSL --max-time 3600 --retry 3 --retry-delay 5 \
    --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" -o "$1" "${BASE}/$1"
}

step "Swaraj Kavach v${VERSION} — ${VARIANT} bundle"

# The checksum is fetched first and always: it is the only way to tell a truncated
# multi-hundred-MB download from a good one, and a truncated archive fails later
# in ways that look like a broken product rather than a broken transfer.
step "Downloading checksum"
fetch "${ARCHIVE}.sha256" || die "could not download ${ARCHIVE}.sha256 — check the token and the version"
ok "${ARCHIVE}.sha256"

step "Downloading bundle"
# The offline bundle exceeds this GitLab's upload size limit, so it is published as
# 240 MB parts. Try the whole file first; fall back to parts. Both end up byte
# identical — the checksum below proves it either way.
if fetch "$ARCHIVE" 2>/dev/null; then
  ok "$ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
else
  printf '  %spublished in parts — fetching them%s\n' "$DIM" "$R"
  rm -f "${ARCHIVE}.part-"*
  i=0
  while :; do
    part="$(printf '%s.part-%02d' "$ARCHIVE" "$i")"
    fetch "$part" 2>/dev/null || break
    printf '  %s✓%s %s (%s)\n' "$GRN" "$R" "$part" "$(du -h "$part" | cut -f1)"
    i=$((i+1))
  done
  [[ $i -gt 0 ]] || die "no bundle found at ${BASE} — is the version '${VERSION}' correct?"
  printf '  %sreassembling %d parts%s\n' "$DIM" "$i" "$R"
  cat "${ARCHIVE}.part-"* > "$ARCHIVE" || die "could not reassemble the parts"
  rm -f "${ARCHIVE}.part-"*
  ok "$ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
fi

step "Verifying"
sha256sum -c "${ARCHIVE}.sha256" >/dev/null 2>&1 \
  || die "CHECKSUM MISMATCH — the download is incomplete or corrupted.
    Delete ${ARCHIVE} and run this script again. Do not install it."
ok "checksum verified"

step "Extracting"
tar -xzf "$ARCHIVE" || die "could not extract $ARCHIVE"
ok "ESDSWAF-v${VERSION}/"

cat <<NEXT

  ${GRN}${B}Ready.${R}

    cd ESDSWAF-v${VERSION}
    sudo ./install.sh --dry-run     ${DIM}# checks this host, changes nothing${R}
    sudo ./install.sh

  ${B}Before you start${R}
    · 16 GB RAM is a hard requirement — the installer refuses below ~15 GB
    · Ubuntu 22.04 or 24.04 only
    · Ports 80, 443 and 9443 must be free
$([[ "$VARIANT" == "online" ]] && printf '    · This is the ONLINE bundle: the VM must reach Docker Hub during install\n' \
                                || printf '    · This is the OFFLINE bundle: no internet needed on the VM\n')

  Full guide: ESDSWAF-v${VERSION}/docs/STANDALONE.md
  Two-VM HA:  ESDSWAF-v${VERSION}/docs/ACTIVE-PASSIVE.md

NEXT
