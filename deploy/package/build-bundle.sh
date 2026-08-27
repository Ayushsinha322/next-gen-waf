#!/usr/bin/env bash
# =============================================================================
# Next-Gen ESDSWAF — release bundle builder  (INTERNAL — release engineer only)
#
# Produces the single archive a customer receives:
#
#     dist/ESDSWAF-v1.0.0.tar.gz
#
# The customer extracts it, runs ./install.sh, and never sees Rust or Go source,
# never runs `docker build`, and never waits ~15 minutes for a compile. Images
# arrive pre-built and are loaded with `docker load` in about a minute.
#
#   ./build-bundle.sh                 # version from the repo's VERSION file
#   ./build-bundle.sh 1.0.1           # explicit version
#   SKIP_BUILD=1 ./build-bundle.sh    # reuse images already built locally
#
# WHAT IS AND IS NOT IN THE BUNDLE
#
# Bundled: the four ESDSWAF images (dataplane, controlplane, dashboard, migrate).
# NOT bundled: postgres, redis, clickhouse, prometheus, grafana — the customer's
# Docker pulls those from Docker Hub (or a mirror). That is a deliberate choice:
# it keeps the archive at a few hundred MB instead of ~2 GB, and those images are
# public and stable.
#
# The consequence must be stated wherever the bundle is described: THE INSTALL IS
# NOT AIR-GAPPED. install.sh therefore checks Docker Hub reachability in preflight
# and aborts early with a clear message rather than dying halfway through. For a
# genuinely offline site, run with BUNDLE_THIRD_PARTY=1 to include all ten.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
PRODUCT="ESDSWAF"
BUNDLE_THIRD_PARTY="${BUNDLE_THIRD_PARTY:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
# STAGE_ONLY=1 lays out the customer tree and stops — no image build, no
# `docker save`, no archive. It exists so CI can validate the BUNDLE CONTRACT
# (that every path the installers, compose overlays and helper scripts reference
# is actually staged) on a runner with no Docker and no 15-minute Rust build.
#
# Every fatal packaging bug found on 2026-08-08 — install-2vm.sh resolving a
# repo-only ../docker path, pg-init-replication.sh staged where the compose
# overlay could not bind-mount it, fpr-report.sh referenced but never shipped —
# was a contract violation visible in the staged tree alone. None needed an image.
STAGE_ONLY="${STAGE_ONLY:-0}"

# The extracted DIRECTORY keeps the plain name, so `cd ESDSWAF-v<version>` is the
# same instruction for both variants. Only the ARCHIVE carries the suffix.
#
# Both variants used to be written to the identical filename, so building one
# silently overwrote the other — and since they have different checksums, an
# operator holding the older .sha256 would get a mismatch that reads as tampering.
# Name them apart at the point of creation instead of relying on whoever runs this
# to remember to rename the output.
STAGE="dist/${PRODUCT}-v${VERSION}"

# The four images we build and ship.
OWN_IMAGES=(dataplane controlplane dashboard migrate)
# Third-party images, pinned to the exact tags compose requests. Listed even when
# not bundled: the customer needs them to pre-seed a registry mirror.
THIRD_PARTY=(
  "postgres:16-alpine"
  "redis:7-alpine"
  "clickhouse/clickhouse-server:24-alpine"
  "prom/prometheus:v2.54.1"
  "grafana/grafana:11.2.0"
  # Used only by compose.ha.yml, which is shipped — so it belongs in the list a
  # customer pre-seeds a registry mirror from, and in the offline bundle.
  "haproxy:2.9-alpine"
)

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; G=$'\e[92m'; Y=$'\e[93m'; C=$'\e[96m'
else B=''; R=''; G=''; Y=''; C=''; fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s==> %s%s\n' "$B" "$C" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' $'\e[91m' "$*" "$R" >&2; exit 1; }

# THREE VARIANTS, and the difference is only where the container images come from.
#
#   registry  ~400 KB   ships NO images. The installer pulls all ten from Harbor.
#                       For any VM that can reach hub.enlight.dev — which is every
#                       ESDS-internal deployment. This is the one to prefer.
#   online     ~99 MB   ships our four images; the other six come from Docker Hub.
#   offline   ~584 MB   ships all ten. The only variant that travels to a customer
#                       site, because Harbor is on an unroutable private address.
#
# Registry mode is not merely "online without the images": it also pins the
# third-party prefix at Harbor, so the install needs ONE reachable host instead
# of Harbor plus the internet.
BUNDLE_IMAGES="${BUNDLE_IMAGES:-bundled}"
REGISTRY_PREFIX="${REGISTRY_PREFIX:-hub.enlight.dev/swaraj-kavach}"
case "$BUNDLE_IMAGES" in
  registry)
    [[ "$BUNDLE_THIRD_PARTY" == "1" ]] \
      && die "BUNDLE_IMAGES=registry and BUNDLE_THIRD_PARTY=1 contradict each other:
    one ships no images, the other ships all ten. Pick one."
    ARCHIVE="dist/${PRODUCT}-v${VERSION}-registry.tar.gz" ;;
  bundled)
    if [[ "$BUNDLE_THIRD_PARTY" == "1" ]]; then
      ARCHIVE="dist/${PRODUCT}-v${VERSION}-offline.tar.gz"
    else
      ARCHIVE="dist/${PRODUCT}-v${VERSION}-online.tar.gz"
    fi ;;
  *) die "BUNDLE_IMAGES must be 'bundled' or 'registry', got '$BUNDLE_IMAGES'" ;;
esac

if [[ "$STAGE_ONLY" != "1" ]]; then
  command -v docker >/dev/null 2>&1 || die "docker is required"
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is required"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be MAJOR.MINOR.PATCH, got '$VERSION'"

step "Building ${PRODUCT} v${VERSION}"

# ── 1. build the four images at the version tag ──────────────────────────────
if [[ "$STAGE_ONLY" == "1" ]]; then
  warn "STAGE_ONLY=1 — laying out the tree only; no images, no archive"
elif [[ "$SKIP_BUILD" == "1" ]]; then
  warn "SKIP_BUILD=1 — reusing local images (only for iterating on this script)"
else
  step "Step 1 of 6 — building images (this is the slow part: Rust release + LTO)"
  # Compose interpolates .env even for a build, so supply placeholders. The real
  # values come from the .env install.sh generates on the customer's host; nothing
  # here is baked into an image.
  ( cd deploy/docker && \
    SENTINEL_VERSION="$VERSION" \
    POSTGRES_USER=build POSTGRES_PASSWORD=build POSTGRES_DB=build \
    CLICKHOUSE_USER=build CLICKHOUSE_PASSWORD=build CLICKHOUSE_DB=build \
    SENTINEL_JWT_SECRET=x SENTINEL_INTERNAL_SECRET=x SENTINEL_AUDIT_HMAC_KEY=x \
    GRAFANA_ADMIN_PASSWORD=x SENTINEL_DB_URL=x SENTINEL_DB_URL_PRIMARY=x \
    SENTINEL_REPL_USER=x SENTINEL_REPL_PASSWORD=x SENTINEL_STANDBY_CIDR=0.0.0.0/32 \
    docker compose -f compose.prod.yml build controlplane migrate dashboard dataplane ) \
    || die "image build failed"
  ok "four images built at tag $VERSION"
fi

# Fail loudly rather than shipping a bundle with a missing or stale image.
if [[ "$STAGE_ONLY" != "1" ]]; then
  for svc in "${OWN_IMAGES[@]}"; do
    docker image inspect "sentinel/${svc}:${VERSION}" >/dev/null 2>&1 \
      || die "sentinel/${svc}:${VERSION} not present — build did not produce it"
  done
fi

# ── 2. stage the tree ────────────────────────────────────────────────────────
step "Step 2 of 6 — staging the customer tree"
rm -rf "$STAGE"
mkdir -p "$STAGE"/{bundle,compose,configs/tls,scripts,docs}

# Compose files: the topologies a customer may deploy.
cp deploy/docker/compose.prod.yml          "$STAGE/compose/"
cp deploy/docker/compose.2vm-active.yml    "$STAGE/compose/"
cp deploy/docker/compose.2vm-passive.yml   "$STAGE/compose/"
cp deploy/docker/compose.ha.yml            "$STAGE/compose/"
cp deploy/docker/compose.cluster.yml       "$STAGE/compose/"
# Supporting files the compose files bind-mount. Miss one and Docker silently
# creates a DIRECTORY in its place, which is the single most confusing failure
# mode in this stack (a directory satisfies -s, so an absent file reports present).
cp deploy/docker/pg_hba.conf               "$STAGE/compose/"
cp deploy/docker/sentinel.proxy.yaml       "$STAGE/compose/" 2>/dev/null || true
cp deploy/docker/clickhouse-tls.xml        "$STAGE/compose/"
# These two are bind-mounted by the 2vm overlays as ./pg-init-replication.sh and
# ./pg-standby-entrypoint.sh — RELATIVE TO THE COMPOSE FILE. They were staged only
# into scripts/, so in the bundle Docker found nothing at those paths and created
# DIRECTORIES in their place: the primary's replication role/slot/pg_hba entry were
# never created, and the standby's entrypoint was a directory. Both failures are
# silent at `up` time and surface later as "replication just isn't running".
cp deploy/docker/pg-init-replication.sh    "$STAGE/compose/"
cp deploy/docker/pg-standby-entrypoint.sh  "$STAGE/compose/"
chmod +x "$STAGE/compose/pg-init-replication.sh" "$STAGE/compose/pg-standby-entrypoint.sh"
cp deploy/docker/prometheus.yml            "$STAGE/compose/" 2>/dev/null || true
# compose.ha.yml is shipped and bind-mounts ./haproxy.cfg; without it Docker would
# create a directory there and HAProxy would fail to start. (haproxy:2.9-alpine is
# listed in THIRD_PARTY below for the same reason.)
cp deploy/docker/haproxy.cfg               "$STAGE/compose/" 2>/dev/null \
  || warn "missing haproxy.cfg — compose.ha.yml would fail to start"
cp -r deploy/docker/grafana                "$STAGE/compose/" 2>/dev/null || true

# Operational scripts the customer legitimately needs.
#
# verify-deploy.sh is NOT one of them and was removed from this list. It is an
# internal check for the ESDS 3-node HA cluster: it `cd`s to /opt/sentinel-src
# (install.sh creates /opt/sentinel/current and never that path) under `set -uo
# pipefail` with no `-e`, so the failed cd does not stop it; it then expects the
# services cp2/cp3/waf1/waf2/waf3/lb/juiceshop, none of which exist in a
# standalone install, and probes with a hardcoded `Host: 172.16.21.71`. Run on a
# perfectly healthy customer install it printed roughly fourteen red FAILs,
# including "benign GET / -> 502" and "SQLi -> 502 (expected 403)".
#
# It shipped beside preflight.sh and the cert issuers, under a header reading
# "Post-deploy verification", so an operator troubleshooting an install would
# reasonably run it — and then either believe their install was broken or stop
# trusting verification output altogether. verify.sh is the customer tool.
for s in preflight.sh promote-standby.sh \
         issue-ip-cert.sh issue-postgres-cert.sh issue-clickhouse-cert.sh \
         pg-init-replication.sh pg-standby-entrypoint.sh; do
  cp "deploy/docker/$s" "$STAGE/scripts/" 2>/dev/null || warn "missing script: $s"
done
cp -r deploy/backup "$STAGE/scripts/backup" 2>/dev/null || warn "no backup scripts"
# install.sh's closing message tells the operator to run this before enabling
# blocking mode, so it has to be IN the bundle. It lives under deploy/load-test/
# rather than deploy/docker/, so the fixed list above never picked it up and the
# instruction pointed at a file the customer did not have.
cp deploy/load-test/fpr-report.sh "$STAGE/scripts/" 2>/dev/null \
  || warn "missing script: fpr-report.sh (install.sh references it after install)"
mkdir -p "$STAGE/scripts/2vm"
cp deploy/2vm/install-2vm.sh deploy/2vm/keepalived.conf.tmpl \
   deploy/2vm/sentinel-vrrp-check.sh deploy/2vm/sentinel-vrrp-notify.sh \
   "$STAGE/scripts/2vm/" 2>/dev/null || warn "2vm assets incomplete"

cp deploy/docker/.env.example "$STAGE/configs/env.example"
# The two installation guides ship WITH the bundle. An operator who has the archive
# but not the repo otherwise has no written procedure — and the active/passive one
# in particular is a two-machine sequence that cannot be guessed from --help.
for d in STANDALONE.md ACTIVE-PASSIVE.md; do
  cp "deploy/$d" "$STAGE/docs/" 2>/dev/null || warn "missing guide: deploy/$d"
done
# The operator manual. The two guides above are installation procedures; these are
# the documents someone RUNS the product from — and the audience is explicitly not
# the developer. They live in their own subdirectory with their filenames intact:
# the five pages cross-link each other by relative name, so flattening or renaming
# them into docs/ would ship a manual whose every internal link is broken.
# Copied by name, not by glob, so a renamed or deleted page warns here rather than
# going missing silently.
mkdir -p "$STAGE/docs/manual"
for d in README.md USER-MANUAL.md NOC-RUNBOOK.md ADMIN-GUIDE.md SITE-ONBOARDING.md TROUBLESHOOTING.md ROLLBACK.md; do
  cp "deploy/manual/$d" "$STAGE/docs/manual/$d" 2>/dev/null \
    || warn "missing manual page: deploy/manual/$d"
done
# The install walkthrough — the ONE document a first-time operator reads, and the
# only one that covers download-to-dashboard without cross-referencing anything.
# It goes to docs/vm-deploy/ rather than docs/ because the manual pages link to it
# as ../vm-deploy/INSTALL-WALKTHROUGH.md: that relative path then resolves
# identically in the repo (deploy/manual → deploy/vm-deploy) and in the bundle
# (docs/manual → docs/vm-deploy), so the same link works in both places instead of
# being right in one and broken in the other.
mkdir -p "$STAGE/docs/vm-deploy"
cp deploy/vm-deploy/INSTALL-WALKTHROUGH.md "$STAGE/docs/vm-deploy/" 2>/dev/null \
  || warn "missing guide: deploy/vm-deploy/INSTALL-WALKTHROUGH.md"
[[ -f docs/WAFDocuments/Next-Gen-ESDSWAF-Deployment-Guide.pdf ]] \
  && cp docs/WAFDocuments/Next-Gen-ESDSWAF-Deployment-Guide.pdf "$STAGE/docs/" \
  || warn "deployment guide PDF not found — bundle ships without docs"
ok "tree staged"

# ── 3. export images ─────────────────────────────────────────────────────────
step "Step 3 of 6 — exporting images"
EXPORT=()
for svc in "${OWN_IMAGES[@]}"; do EXPORT+=("sentinel/${svc}:${VERSION}"); done
if [[ "$BUNDLE_THIRD_PARTY" == "1" ]]; then
  say "  BUNDLE_THIRD_PARTY=1 — including third-party images (fully offline)"
  for img in "${THIRD_PARTY[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img" >/dev/null
    EXPORT+=("$img")
  done
fi
if [[ "$BUNDLE_IMAGES" == "registry" ]]; then
  # No images.tar.gz AT ALL — not an empty one. An empty archive would be handed
  # to `docker load`, which fails obscurely; its absence is what tells install.sh
  # unambiguously that this is a registry bundle, alongside the manifest field.
  rm -f "$STAGE/bundle/images.tar.gz"
  ok "no images shipped — the installer pulls from $REGISTRY_PREFIX"
elif [[ "$STAGE_ONLY" == "1" ]]; then
  # A placeholder keeps the tree SHAPE identical so the contract check sees the
  # same layout a real bundle has. It is never shipped: STAGE_ONLY stops before
  # the archive is built.
  : > "$STAGE/bundle/images.tar.gz"
  ok "images.tar.gz — placeholder (STAGE_ONLY)"
else
  docker save "${EXPORT[@]}" | gzip -6 > "$STAGE/bundle/images.tar.gz"
  ok "images.tar.gz — $(du -h "$STAGE/bundle/images.tar.gz" | cut -f1) ($(printf '%s\n' "${EXPORT[@]}" | wc -l) images)"
fi

# ── 4. manifest ──────────────────────────────────────────────────────────────
step "Step 4 of 6 — manifest"
{
  printf '{\n'
  printf '  "product": "Next-Gen ESDSWAF",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "built_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "built_from_commit": "%s",\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  printf '  "air_gapped": %s,\n' "$([[ "$BUNDLE_THIRD_PARTY" == "1" ]] && echo true || echo false)"
  # image_source is what install.sh branches on. Named rather than inferred from
  # the presence of a file, so a truncated download cannot silently look like a
  # registry bundle and skip loading images it was supposed to contain.
  printf '  "image_source": "%s",\n' "$BUNDLE_IMAGES"
  if [[ "$BUNDLE_IMAGES" == "registry" ]]; then
    printf '  "registry_prefix": "%s",\n' "$REGISTRY_PREFIX"
    printf '  "thirdparty_prefix": "%s/",\n' "$REGISTRY_PREFIX"
  fi
  # In registry mode nothing is bundled, so this list is EMPTY rather than
  # describing four images the archive does not contain. The expected tags are
  # already implied by registry_prefix + version; a manifest that itemises
  # payload it does not carry is the same defect class as a doc describing a
  # feature that was never built.
  printf '  "bundled_images": [\n'
  local_first=1
  for svc in $([[ "$BUNDLE_IMAGES" == "registry" ]] || printf '%s ' "${OWN_IMAGES[@]}"); do
    if [[ "$STAGE_ONLY" == "1" ]]; then id="stage-only"; sz=0; else
      id=$(docker image inspect "sentinel/${svc}:${VERSION}" --format '{{.Id}}' 2>/dev/null || echo unknown)
      sz=$(docker image inspect "sentinel/${svc}:${VERSION}" --format '{{.Size}}' 2>/dev/null || echo 0)
    fi
    [[ $local_first -eq 1 ]] && local_first=0 || printf ',\n'
    printf '    { "repository": "sentinel/%s", "tag": "%s", "id": "%s", "size_bytes": %s }' \
      "$svc" "$VERSION" "$id" "$sz"
  done
  printf '\n  ],\n'
  printf '  "pulled_from_registry": [\n'
  tp_first=1
  for img in "${THIRD_PARTY[@]}"; do
    [[ $tp_first -eq 1 ]] && tp_first=0 || printf ',\n'
    printf '    "%s"' "$img"
  done
  printf '\n  ],\n'
  printf '  "requires_internet": %s,\n' "$([[ "$BUNDLE_THIRD_PARTY" == "1" ]] && echo false || echo true)"
  printf '  "supported_os": ["Ubuntu 22.04", "Ubuntu 24.04"],\n'
  printf '  "minimum_hardware": { "vcpu": 4, "ram_gb": 16, "disk_gb": 100 }\n'
  printf '}\n'
} > "$STAGE/bundle/manifest.json"
# Validate with the SAME line-oriented parser install.sh uses, not python3.
#
# Two reasons. First, python3 is absent from minimal images — this line failed the
# CI job on alpine, and it is the identical dependency that made install.sh read a
# literal "unknown" version on Ubuntu images without python3. Second, and more
# usefully: `json.load` proves the file is valid JSON, which is NOT the property
# that matters here. What matters is that install.sh's sed parser can read the
# keys it needs. A manifest can be perfectly valid JSON and still be unreadable by
# the installer if it is reformatted onto one line. Validate the real contract.
_mv=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STAGE/bundle/manifest.json" | head -1)
_mi=$(sed -n 's/.*"requires_internet"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$STAGE/bundle/manifest.json" | head -1)
[[ "$_mv" == "$VERSION" ]] \
  || die "manifest.json: install.sh's parser reads version '$_mv', expected '$VERSION'"
[[ -n "$_mi" ]] \
  || die "manifest.json: install.sh's parser cannot read requires_internet — offline detection would break"
ok "manifest.json (readable by the installer's own parser)"

# ── 5. checksums over EVERYTHING, not just the image tarball ─────────────────
step "Step 5 of 6 — checksums"
# Cover every shipped file. A corrupted or tampered compose file or script is as
# damaging as a corrupted image, and checksumming only images.tar.gz would leave
# the executable parts unverified.
( cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )
ok "SHA256SUMS — $(wc -l < "$STAGE/SHA256SUMS") files"

# ── 6. installer entry points + archive ──────────────────────────────────────
step "Step 6 of 6 — installer and archive"
for f in install.sh uninstall.sh verify.sh first-site.sh add-operator.sh upgrade.sh rollback.sh README.md; do
  if [[ -f "deploy/package/customer/$f" ]]; then
    cp "deploy/package/customer/$f" "$STAGE/$f"
    [[ "$f" == *.sh ]] && chmod +x "$STAGE/$f"
  else
    warn "deploy/package/customer/$f not found — bundle incomplete"
  fi
done
# Re-checksum: the installer files were added after the first pass.
( cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

if [[ "$STAGE_ONLY" == "1" ]]; then
  ok "staged tree ready at $STAGE (STAGE_ONLY — no archive built)"
  exit 0
fi

mkdir -p dist
tar -czf "$ARCHIVE" -C dist "$(basename "$STAGE")"
# Generate the checksum from INSIDE dist/, so the file records a bare filename.
#
# `sha256sum "$ARCHIVE"` recorded the path as "dist/ESDSWAF-v<v>.tar.gz". The
# customer receives only the two files and, per the README, runs
#     sha256sum -c ESDSWAF-v<v>.tar.gz.sha256
# in whatever directory they landed in — where there is no dist/ subdirectory. So
# the FIRST command of the install procedure failed on a perfectly good bundle,
# reporting "FAILED open or read". For a security product that reads as tampering,
# which is the worst possible false alarm.
( cd dist && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256" )
ok "$ARCHIVE — $(du -h "$ARCHIVE" | cut -f1)"

cat <<SUMMARY

  ${B}Bundle ready${R}

    archive   $ARCHIVE
    sha256    $(cut -d' ' -f1 < "$ARCHIVE.sha256")
    version   $VERSION
    commit    $(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    images    $(case "$BUNDLE_IMAGES:$BUNDLE_THIRD_PARTY" in
                  registry:*) echo "pulled from $REGISTRY_PREFIX — one host, no internet needed" ;;
                  *:1)        echo "all $(( ${#OWN_IMAGES[@]} + ${#THIRD_PARTY[@]} )) inside the archive — air-gapped" ;;
                  *)          echo "${#OWN_IMAGES[@]} inside; ${#THIRD_PARTY[@]} pulled from Docker Hub (needs internet)" ;;
                esac)

  Send the customer BOTH files. They verify before extracting:

      sha256sum -c $(basename "$ARCHIVE").sha256
      tar -xzf $(basename "$ARCHIVE")
      cd ${PRODUCT}-v${VERSION} && sudo ./install.sh

SUMMARY
