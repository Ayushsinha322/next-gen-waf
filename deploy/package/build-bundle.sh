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
# genuinely offline site, run with BUNDLE_THIRD_PARTY=1 to include all nine.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-$(cat VERSION 2>/dev/null || echo 0.0.0)}"
PRODUCT="ESDSWAF"
STAGE="dist/${PRODUCT}-v${VERSION}"
ARCHIVE="dist/${PRODUCT}-v${VERSION}.tar.gz"
BUNDLE_THIRD_PARTY="${BUNDLE_THIRD_PARTY:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"

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
)

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; G=$'\e[92m'; Y=$'\e[93m'; C=$'\e[96m'
else B=''; R=''; G=''; Y=''; C=''; fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s==> %s%s\n' "$B" "$C" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' $'\e[91m' "$*" "$R" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is required"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be MAJOR.MINOR.PATCH, got '$VERSION'"

step "Building ${PRODUCT} v${VERSION}"

# ── 1. build the four images at the version tag ──────────────────────────────
if [[ "$SKIP_BUILD" == "1" ]]; then
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
for svc in "${OWN_IMAGES[@]}"; do
  docker image inspect "sentinel/${svc}:${VERSION}" >/dev/null 2>&1 \
    || die "sentinel/${svc}:${VERSION} not present — build did not produce it"
done

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
cp deploy/docker/prometheus.yml            "$STAGE/compose/" 2>/dev/null || true
cp -r deploy/docker/grafana                "$STAGE/compose/" 2>/dev/null || true

# Operational scripts the customer legitimately needs.
for s in preflight.sh verify-deploy.sh promote-standby.sh \
         issue-ip-cert.sh issue-postgres-cert.sh issue-clickhouse-cert.sh \
         pg-init-replication.sh pg-standby-entrypoint.sh; do
  cp "deploy/docker/$s" "$STAGE/scripts/" 2>/dev/null || warn "missing script: $s"
done
cp -r deploy/backup "$STAGE/scripts/backup" 2>/dev/null || warn "no backup scripts"
mkdir -p "$STAGE/scripts/2vm"
cp deploy/2vm/install-2vm.sh deploy/2vm/keepalived.conf.tmpl \
   deploy/2vm/sentinel-vrrp-check.sh deploy/2vm/sentinel-vrrp-notify.sh \
   "$STAGE/scripts/2vm/" 2>/dev/null || warn "2vm assets incomplete"

cp deploy/docker/.env.example "$STAGE/configs/env.example"
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
docker save "${EXPORT[@]}" | gzip -6 > "$STAGE/bundle/images.tar.gz"
ok "images.tar.gz — $(du -h "$STAGE/bundle/images.tar.gz" | cut -f1) ($(printf '%s\n' "${EXPORT[@]}" | wc -l) images)"

# ── 4. manifest ──────────────────────────────────────────────────────────────
step "Step 4 of 6 — manifest"
{
  printf '{\n'
  printf '  "product": "Next-Gen ESDSWAF",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "built_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "built_from_commit": "%s",\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  printf '  "air_gapped": %s,\n' "$([[ "$BUNDLE_THIRD_PARTY" == "1" ]] && echo true || echo false)"
  printf '  "bundled_images": [\n'
  local_first=1
  for svc in "${OWN_IMAGES[@]}"; do
    id=$(docker image inspect "sentinel/${svc}:${VERSION}" --format '{{.Id}}' 2>/dev/null || echo unknown)
    sz=$(docker image inspect "sentinel/${svc}:${VERSION}" --format '{{.Size}}' 2>/dev/null || echo 0)
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
python3 -c "import json,sys; json.load(open('$STAGE/bundle/manifest.json'))" \
  || die "manifest.json is not valid JSON"
ok "manifest.json"

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
for f in install.sh uninstall.sh verify.sh upgrade.sh README.md; do
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

mkdir -p dist
tar -czf "$ARCHIVE" -C dist "$(basename "$STAGE")"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
ok "$ARCHIVE — $(du -h "$ARCHIVE" | cut -f1)"

cat <<SUMMARY

  ${B}Bundle ready${R}

    archive   $ARCHIVE
    sha256    $(cut -d' ' -f1 < "$ARCHIVE.sha256")
    version   $VERSION
    commit    $(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    offline   $([[ "$BUNDLE_THIRD_PARTY" == "1" ]] && echo "yes (all images bundled)" \
                 || echo "NO — customer needs Docker Hub for 5 third-party images")

  Send the customer BOTH files. They verify before extracting:

      sha256sum -c ${PRODUCT}-v${VERSION}.tar.gz.sha256
      tar -xzf ${PRODUCT}-v${VERSION}.tar.gz
      cd ${PRODUCT}-v${VERSION} && sudo ./install.sh

SUMMARY
