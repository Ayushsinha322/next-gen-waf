#!/usr/bin/env bash
# =============================================================================
#  Mirror the third-party images into Harbor  (INTERNAL — release engineer only)
#
#      GITLAB_TOKEN=… HARBOR_USER=… HARBOR_TOKEN=… ./mirror-thirdparty.sh
#
#  Copies Postgres, Redis, ClickHouse, Prometheus, Grafana and HAProxy from Docker
#  Hub into hub.enlight.dev/swaraj-kavach, under the SAME repository names compose
#  asks for, so a registry-mode install reaches exactly one host.
#
#  WHY THIS IS NECESSARY
#
#  Registry mode pulls our four images from Harbor. Without this, the other six
#  would still come from Docker Hub — so an ESDS management-network VM, which can
#  reach 172.16.23.2 but not the internet, would get four images and then hang.
#  "Online" has to mean one reachable host, not two.
#
#  Harbor repository names may contain slashes (this Harbor already hosts
#  base-images/anilrevgade/centos-apache-php), so clickhouse/clickhouse-server and
#  prom/prometheus mirror without being renamed — which is what lets compose use a
#  single ${SENTINEL_THIRDPARTY_PREFIX} rather than a per-image mapping table.
#
#  Idempotent: an image already present at the same digest is skipped.
#
#      --dry-run   show what would be copied
# =============================================================================
set -uo pipefail

HARBOR="${HARBOR:-hub.enlight.dev}"
PROJECT="${HARBOR_PROJECT:-swaraj-kavach}"
DRY_RUN=no
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=yes

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }

# Exactly the tags compose requests. Kept in step with the THIRD_PARTY list in
# build-bundle.sh and the image: lines in compose.prod.yml / compose.ha.yml — a
# mirror of the wrong tag is worse than no mirror, because the pull succeeds and
# runs software nobody tested.
IMAGES=(
  "postgres:16-alpine"
  "valkey/valkey:8-alpine"
  "clickhouse/clickhouse-server:24-alpine"
  "prom/prometheus:v2.54.1"
  "haproxy:2.9-alpine"
)

step "Checking the tags match what compose actually asks for"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drift=0
for img in "${IMAGES[@]}"; do
  if grep -qF "}$img" "$ROOT/deploy/docker/compose.prod.yml" "$ROOT/deploy/docker/compose.ha.yml" 2>/dev/null; then
    ok "$img"
  else
    warn "$img is not referenced by any shipped compose file"
    drift=1
  fi
done
(( drift == 0 )) || warn "the list above has drifted from compose — check before relying on this"

command -v docker >/dev/null || die "docker is required"
if [[ "$DRY_RUN" != "yes" ]]; then
  [[ -n "${HARBOR_USER:-}" && -n "${HARBOR_TOKEN:-}" ]] \
    || die "set HARBOR_USER and HARBOR_TOKEN (a robot account with push on $PROJECT)"
  echo "$HARBOR_TOKEN" | docker login "$HARBOR" --username "$HARBOR_USER" --password-stdin >/dev/null \
    || die "docker login to $HARBOR failed"
  ok "authenticated to $HARBOR as $HARBOR_USER"
fi

step "Mirroring ${#IMAGES[@]} images into $HARBOR/$PROJECT"
fail=0
for img in "${IMAGES[@]}"; do
  dest="$HARBOR/$PROJECT/$img"
  printf '  %-46s ' "$img"
  if [[ "$DRY_RUN" == "yes" ]]; then printf '%s(dry-run)%s -> %s\n' "$DIM" "$R" "$dest"; continue; fi

  # Pull the source first so the digest is knowable, then compare: re-pushing an
  # identical image wastes minutes of upload on a link that has dropped repeatedly.
  docker pull -q "$img" >/dev/null 2>&1 || { printf '%s✗ pull failed%s\n' "$RED" "$R"; fail=1; continue; }
  src_id="$(docker image inspect "$img" --format '{{.Id}}' 2>/dev/null)"
  if docker manifest inspect "$dest" >/dev/null 2>&1 \
     && docker pull -q "$dest" >/dev/null 2>&1 \
     && [[ "$(docker image inspect "$dest" --format '{{.Id}}' 2>/dev/null)" == "$src_id" ]]; then
    printf '%salready mirrored%s\n' "$DIM" "$R"; continue
  fi
  docker tag "$img" "$dest" \
    && docker push -q "$dest" >/dev/null 2>&1 \
    && printf '%s✓%s pushed\n' "$GRN" "$R" \
    || { printf '%s✗ push failed%s\n' "$RED" "$R"; fail=1; }
done

[[ "$DRY_RUN" == "yes" ]] && { printf '\n  %s--dry-run: nothing was pushed.%s\n\n' "$YEL" "$R"; exit 0; }
docker logout "$HARBOR" >/dev/null 2>&1 || true
(( fail == 0 )) || die "one or more images did not mirror — a registry install would hang on the missing one"
printf '\n  %s%sAll %d third-party images mirrored.%s\n' "$GRN" "$B" "${#IMAGES[@]}" "$R"
printf '  %sA registry-mode install now needs only %s.%s\n\n' "$DIM" "$HARBOR" "$R"
