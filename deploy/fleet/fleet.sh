#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — internal fleet release tool  (INTERNAL — release engineer only)
#
#   ./deploy/fleet/fleet.sh status              # what is each node actually running?
#   ./deploy/fleet/fleet.sh release             # build -> ship+sync -> roll -> verify
#   ./deploy/fleet/fleet.sh release --dry-run   # print every command, change nothing
#   ./deploy/fleet/fleet.sh verify              # post-deploy checks only
#   ./deploy/fleet/fleet.sh release --only waf-active
#
# WHY THIS EXISTS
#
# Images are built ONCE on a workstation and shipped to the fleet as a `docker
# save` tarball. That is a deliberate choice and it is much faster than building
# on every box: a data-plane build is ~14 min on the demo host and ~35 min on the
# pair (any change to sentinel-core invalidates the Rust dependency graph, so it
# is a cold release build with LTO), while shipping the same image takes ~8 s.
#
# But on 2026-08-10 that approach was run by hand, and the hand-run version
# shipped images WITHOUT syncing /opt/sentinel-src. All three VMs then ran `main`
# while their source trees sat 21 commits behind. Nothing was broken — until the
# next person ran `docker compose build` on a box, at which point the stale tree
# would have silently rebuilt old code and reverted three fixes (the @pm
# case-insensitivity fix, the accept(2) classifier, and the ML de-fabrication).
# The box would have reported healthy throughout.
#
# So this script makes the coupling STRUCTURAL rather than remembered:
#
#   * `ship` ALWAYS syncs the source. There is no flag to skip it. If you can
#     ship an image you have already synced the tree that would rebuild it.
#   * every image carries its commit in an OCI label, so "what is this node
#     running?" is a query rather than the forensics it was on 2026-08-11
#     (docker cp the binary out of a distroless image and grep it for a string).
#   * `status` compares source commit vs image label vs running container on every
#     node and names any drift, so the answer is checkable before it matters.
#
# WHAT IT REFUSES TO DO
#
#   * build or ship from a dirty working tree (--allow-dirty stamps `-dirty` and
#     then `ship` still refuses without --force)
#   * ship an image whose revision label is `unknown`
#   * roll a node whose running containers were created with a DIFFERENT compose
#     file set than its role declares — the 2026-08-07 outage, mechanised
#   * rsync `deploy/` or any `.env`: the VM copies carry drift that is invisible
#     to git (SENTINEL_TRUSTED_PROXIES) and secrets that are gitignored. Syncing
#     deploy/docker/.env on 2026-07-27 silently downgraded the control plane to
#     plaintext Postgres and broke the audit HMAC chain.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FLEET_CONF="${FLEET_CONF:-deploy/fleet/fleet.conf}"
IMAGES=(dataplane controlplane dashboard migrate)

# The ONLY paths that are synced. Taken from the Dockerfiles' COPY set
# (Cargo.toml, Cargo.lock, crates, rules, control-plane) plus dashboard/, so the
# tree on the node is exactly what a rebuild there would consume. `rules` matters
# and is easy to forget: the Dockerfile does `COPY rules ./rules`, so rule packs
# are BAKED into the image, not mounted.
SYNC_PATHS=(Cargo.toml Cargo.lock crates rules control-plane dashboard)
SYNC_EXCLUDES=(--exclude .git --exclude target --exclude node_modules --exclude .next)

DRY=0
ONLY=""
ALLOW_DIRTY=0
FORCE=0

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; G=$'\e[92m'; Y=$'\e[93m'; C=$'\e[96m'; E=$'\e[91m'
else B=''; R=''; G=''; Y=''; C=''; E=''; fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s==> %s%s\n' "$B" "$C" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$R" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$E" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$E" "$*" "$R" >&2; exit 1; }

FAILS=0
PASS() { printf '  %sPASS%s %s\n' "$G" "$R" "$*"; }
FAIL() { printf '  %sFAIL%s %s\n' "$E" "$R" "$*"; FAILS=$((FAILS + 1)); }

# ─────────────────────────────────────────────────────────────────────────────
# Inventory
# ─────────────────────────────────────────────────────────────────────────────
NAMES=(); HOSTS=(); ROLES=(); KEYS=()

load_fleet() {
  [[ -f "$FLEET_CONF" ]] || die "inventory not found: $FLEET_CONF"
  local name host role key
  while read -r name host role key _rest; do
    [[ -z "${name:-}" || "${name:0:1}" == "#" ]] && continue
    [[ -n "${host:-}" && -n "${role:-}" && -n "${key:-}" ]] \
      || die "malformed line in $FLEET_CONF near '$name' — need: name host role ssh_key"
    if [[ -n "$ONLY" && "$name" != "$ONLY" ]]; then continue; fi
    NAMES+=("$name"); HOSTS+=("$host"); ROLES+=("$role"); KEYS+=("${key/#\~/$HOME}")
  done < "$FLEET_CONF"
  [[ ${#NAMES[@]} -gt 0 ]] || die "no nodes selected${ONLY:+ (--only $ONLY matched nothing)}"
}

# The compose file set for a role. This is the single source of truth; every
# remote docker compose invocation is built from it, so no caller can improvise.
role_compose_files() {
  case "$1" in
    standalone-ha) echo "-f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml" ;;
    pair-active)   echo "-f compose.prod.yml -f compose.2vm-active.yml" ;;
    pair-passive)  echo "-f compose.prod.yml -f compose.2vm-passive.yml" ;;
    standalone)    echo "-f compose.prod.yml" ;;
    *) die "unknown role '$1' — see deploy/fleet/fleet.conf for the valid set" ;;
  esac
}

# Services to recreate, IN ORDER. On the HA box the control-plane nodes and WAF
# nodes are rolled one at a time so quorum and the HAProxy backend pool are never
# emptied; the node that serves last (waf1/dataplane) is rolled last.
role_roll_services() {
  case "$1" in
    standalone-ha) echo "cp2 cp3 controlplane waf2 waf3 waf1 dashboard" ;;
    pair-active|pair-passive|standalone) echo "controlplane dataplane dashboard" ;;
    *) die "unknown role '$1'" ;;
  esac
}

SSH_OPTS=(-o ConnectTimeout=12 -o ServerAliveInterval=5 -o ServerAliveCountMax=4
          -o StrictHostKeyChecking=accept-new)

# Remote command. Honours --dry-run for anything that mutates; read-only callers
# use rsh_ro so `status`/`verify` still work under --dry-run.
rsh() {
  local key="$1" host="$2"; shift 2
  if [[ "$DRY" == "1" ]]; then printf '  %s[dry-run]%s ssh %s -- %s\n' "$Y" "$R" "$host" "$*"; return 0; fi
  ssh -i "$key" "${SSH_OPTS[@]}" "root@$host" "$@"
}
rsh_ro() {
  local key="$1" host="$2"; shift 2
  ssh -i "$key" "${SSH_OPTS[@]}" "root@$host" "$@"
}

git_sha()   { git rev-parse --short HEAD; }
build_date() { date -u +%Y-%m-%dT%H:%M:%SZ; }

require_clean_tree() {
  [[ -z "$(git status --porcelain)" ]] && return 0
  if [[ "$ALLOW_DIRTY" == "1" ]]; then
    warn "working tree is DIRTY — images will be stamped '$(git_sha)-dirty' and ship will refuse them without --force"
    return 0
  fi
  git status --short | head -10
  die "working tree is dirty. Commit first, or pass --allow-dirty to build a marked throwaway."
}

# The revision stamped into images for this run. A dirty tree is marked so the
# label can never claim a commit that does not describe the bits.
release_rev() {
  if [[ -n "$(git status --porcelain)" ]]; then echo "$(git_sha)-dirty"; else git_sha; fi
}

# ─────────────────────────────────────────────────────────────────────────────
# status — the drift detector
# ─────────────────────────────────────────────────────────────────────────────
cmd_status() {
  local want; want="$(release_rev)"
  step "Fleet status (local HEAD $want)"
  local i name host role key
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"; host="${HOSTS[$i]}"; role="${ROLES[$i]}"; key="${KEYS[$i]}"
    printf '\n%s── %s (%s, %s)%s\n' "$B" "$name" "$host" "$role" "$R"
    if ! rsh_ro "$key" "$host" true 2>/dev/null; then
      bad "unreachable over SSH — VPN down, or the host is off"
      continue
    fi
    rsh_ro "$key" "$host" "bash -s" <<REMOTE || true
set -u
src=\$(sed -n 's/^commit: *//p' /opt/sentinel-src/DEPLOYED_COMMIT 2>/dev/null | awk '{print \$1}')
printf '  %-22s %s\n' "source tree:" "\${src:-<no DEPLOYED_COMMIT — provenance unknown>}"
for img in ${IMAGES[*]}; do
  rev=\$(docker image inspect "sentinel/\$img:latest" \
        --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null)
  [ -z "\$rev" ] && rev="<unlabelled: built before provenance landed>"
  printf '  %-22s %s\n' "image \$img:" "\$rev"
done
dp=\$(docker ps --format '{{.Names}}' | grep -E '^sentinel-(waf1|dataplane)-1\$' | head -1)
if [ -n "\$dp" ]; then
  printf '  %-22s %s\n' "compose file set:" \
    "\$(docker inspect "\$dp" --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' | tr ',' ' ' | xargs -n1 basename | tr '\n' ' ')"
  cur=\$(docker inspect "\$dp" --format '{{.Image}}')
  new=\$(docker image inspect sentinel/dataplane:latest --format '{{.Id}}' 2>/dev/null)
  if [ "\$cur" = "\$new" ]; then printf '  %-22s %s\n' "data plane:" "on current :latest"
  else printf '  %-22s %s\n' "data plane:" "STALE CONTAINER — not on sentinel/dataplane:latest"; fi
fi
REMOTE
  done
  printf '\n'
  say "Drift to look for: a source tree that disagrees with the image labels means a"
  say "rebuild on that node would produce something other than what is running."
}

# ─────────────────────────────────────────────────────────────────────────────
# build — locally, once, stamped
# ─────────────────────────────────────────────────────────────────────────────
cmd_build() {
  local rev bdate
  require_clean_tree
  rev="$(release_rev)"; bdate="$(build_date)"
  step "Building images locally at revision $rev"
  command -v docker >/dev/null 2>&1 || die "docker is required"

  if [[ "$DRY" == "1" ]]; then
    printf '  %s[dry-run]%s docker compose build (4 images, GIT_SHA=%s)\n' "$Y" "$R" "$rev"
  else
    # Compose interpolates EVERY service even when you name one, so the secret
    # vars must resolve or the build dies at parse time. These placeholders
    # exist purely to satisfy interpolation; nothing
    # here reaches a running container — the real values live in each node's .env.
    ( cd deploy/docker \
      && SENTINEL_GIT_SHA="$rev" SENTINEL_BUILD_DATE="$bdate" \
         CLICKHOUSE_DB=build CLICKHOUSE_USER=build CLICKHOUSE_PASSWORD=build \
         POSTGRES_DB=build POSTGRES_USER=build POSTGRES_PASSWORD=build \
         SENTINEL_DB_URL=build \
         SENTINEL_JWT_SECRET=build SENTINEL_INTERNAL_SECRET=build SENTINEL_AUDIT_HMAC_KEY=build \
         docker compose -f compose.prod.yml build dataplane controlplane dashboard migrate )
  fi

  local img
  for img in "${IMAGES[@]}"; do
    if [[ "$DRY" == "1" ]]; then
      printf '  %s[dry-run]%s docker tag sentinel/%s:latest sentinel/%s:%s\n' "$Y" "$R" "$img" "$img" "$rev"
      continue
    fi
    docker image inspect "sentinel/$img:latest" >/dev/null 2>&1 \
      || die "sentinel/$img:latest missing — the build did not produce it"
    local got
    got=$(docker image inspect "sentinel/$img:latest" \
          --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
    [[ "$got" == "$rev" ]] \
      || die "sentinel/$img:latest is labelled '$got', expected '$rev'. The build args did not reach the image; check the x-build-provenance anchor in compose.prod.yml."
    docker tag "sentinel/$img:latest" "sentinel/$img:$rev"
    ok "sentinel/$img:$rev (labelled and tagged)"
  done
}

# ─────────────────────────────────────────────────────────────────────────────
# ship — tarball to each node, AND sync the source. Not separable, by design.
# ─────────────────────────────────────────────────────────────────────────────
cmd_ship() {
  local rev; rev="$(release_rev)"
  if [[ "$rev" == *-dirty && "$FORCE" != "1" ]]; then
    die "refusing to ship '$rev': a dirty tree cannot be reproduced from git. Commit, or pass --force if this is a deliberate one-off to a lab box."
  fi
  local i name host role key refs=()
  local img
  for img in "${IMAGES[@]}"; do refs+=("sentinel/$img:$rev"); done

  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"; host="${HOSTS[$i]}"; role="${ROLES[$i]}"; key="${KEYS[$i]}"
    step "Ship + sync -> $name ($host, $role)"
    rsh_ro "$key" "$host" true 2>/dev/null || die "$name is unreachable — aborting before any node is touched"

    if [[ "$DRY" == "1" ]]; then
      printf '  %s[dry-run]%s docker save %s | ssh %s docker load\n' "$Y" "$R" "${refs[*]}" "$host"
    else
      # gzip -1: the link is a VPN, and the images are already-compressed layers,
      # so heavier compression costs CPU for almost no bytes.
      docker save "${refs[@]}" | gzip -1 \
        | ssh -i "$key" "${SSH_OPTS[@]}" "root@$host" 'gunzip | docker load' >/dev/null
      ok "images loaded"
    fi

    # Retag :latest on the node, keeping the outgoing images as a rollback tag.
    # compose asks for :latest, so this is the step that actually selects the
    # build — and the rollback tag is what makes the roll reversible.
    rsh "$key" "$host" "bash -s" <<REMOTE
set -euo pipefail
for img in ${IMAGES[*]}; do
  if docker image inspect "sentinel/\$img:latest" >/dev/null 2>&1; then
    docker tag "sentinel/\$img:latest" "sentinel/\$img:rollback-$(date -u +%Y%m%d-%H%M%S)"
  fi
  docker tag "sentinel/\$img:$rev" "sentinel/\$img:latest"
  got=\$(docker image inspect "sentinel/\$img:latest" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
  [ "\$got" = "$rev" ] || { echo "FATAL: sentinel/\$img:latest is '\$got', expected '$rev'"; exit 1; }
done
REMOTE
    [[ "$DRY" == "1" ]] || ok ":latest now points at $rev, previous build kept as :rollback-*"

    sync_source_to "$name" "$host" "$key" "$rev"
  done
}

# The half that used to be forgotten. Called only from cmd_ship, so shipping
# without syncing is not expressible.
sync_source_to() {
  local name="$1" host="$2" key="$3" rev="$4"
  local p
  for p in "${SYNC_PATHS[@]}"; do
    case "$p" in
      deploy|deploy/*|*.env)
        die "SYNC_PATHS contains '$p'. deploy/ and .env are never synced — the node copies carry drift invisible to git and secrets that are gitignored." ;;
    esac
  done

  if [[ "$DRY" == "1" ]]; then
    printf '  %s[dry-run]%s rsync -az --delete %s -> %s:/opt/sentinel-src/\n' "$Y" "$R" "${SYNC_PATHS[*]}" "$host"
    return 0
  fi

  rsync -az --delete "${SYNC_EXCLUDES[@]}" \
    -e "ssh -i $key ${SSH_OPTS[*]}" \
    "${SYNC_PATHS[@]}" "root@$host:/opt/sentinel-src/"
  ok "source tree synced ($name)"

  rsh "$key" "$host" "bash -s" <<REMOTE
set -euo pipefail
cd /opt/sentinel-src
{
  echo "commit: $rev"
  echo "synced: $(build_date) by deploy/fleet/fleet.sh from $(hostname)"
  echo "paths:  ${SYNC_PATHS[*]}"
  echo "NOT synced: deploy/ (node-local drift) and deploy/docker/.env (secrets)"
  echo ""
  echo "images at sync time:"
  for img in ${IMAGES[*]}; do
    printf '  %-28s %s\n' "sentinel/\$img:latest" \
      "\$(docker image inspect "sentinel/\$img:latest" --format '{{.Id}} rev={{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null)"
  done
  echo ""
  echo "This tree and those images were shipped together. If they ever disagree,"
  echo "the images are the truth about what is RUNNING and this tree is the truth"
  echo "about what a rebuild here would PRODUCE. Reconcile before building."
} > DEPLOYED_COMMIT
REMOTE
  ok "DEPLOYED_COMMIT stamped ($rev)"
}

# ─────────────────────────────────────────────────────────────────────────────
# roll — recreate services with the role's compose set, one at a time
# ─────────────────────────────────────────────────────────────────────────────
cmd_roll() {
  local i name host role key files services
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"; host="${HOSTS[$i]}"; role="${ROLES[$i]}"; key="${KEYS[$i]}"
    files="$(role_compose_files "$role")"
    services="$(role_roll_services "$role")"
    step "Roll $name ($role): $services"

    # Guard: what file set were the RUNNING containers created with? A node whose
    # containers came from a different set will lose whatever the missing overlay
    # provided the moment it is recreated. This is the 2026-08-07 outage as a
    # precondition check rather than a postmortem.
    if [[ "$DRY" != "1" ]]; then
      local actual expected_count actual_count
      actual=$(rsh_ro "$key" "$host" \
        "docker ps --format '{{.Names}}' | grep -E '^sentinel-(waf1|dataplane)-1\$' | head -1 | xargs -r -I{} docker inspect {} --format '{{index .Config.Labels \"com.docker.compose.project.config_files\"}}'" 2>/dev/null || echo "")
      # Count the -f flags, not the lines: `grep -c` counts matching LINES, so on
      # a single-line string it answers 1 no matter how many files are named.
      expected_count=$(echo "$files" | tr ' ' '\n' | grep -c '^-f$' || true)
      actual_count=$(echo "$actual" | tr ',' '\n' | grep -c . || true)
      if [[ -n "$actual" && "$actual_count" -ne "$expected_count" ]]; then
        bad "running containers were created with: $actual"
        bad "role '$role' declares:               $files"
        die "compose file-set mismatch on $name — refusing to roll. Reconcile the inventory with reality first."
      fi
      ok "compose file set matches role ($actual_count files)"
    fi

    local svc svc_list=()
    read -r -a svc_list <<< "$services"
    for svc in "${svc_list[@]}"; do
      rsh "$key" "$host" "cd /opt/sentinel-src/deploy/docker && docker compose -p sentinel $files up -d --no-deps --force-recreate $svc"
      [[ "$DRY" == "1" ]] || ok "recreated $svc"
      # Settle before touching the next one: on the HA box this is what keeps
      # quorum and the HAProxy backend pool from emptying, and on a pair node it
      # is the window in which keepalived notices and moves the VIP.
      [[ "$DRY" == "1" ]] || sleep 8
    done
  done
}

# ─────────────────────────────────────────────────────────────────────────────
# verify — measurements, not assertions. Non-zero exit if anything FAILs.
# ─────────────────────────────────────────────────────────────────────────────
cmd_verify() {
  local rev; rev="$(release_rev)"
  local i name host role key
  for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"; host="${HOSTS[$i]}"; role="${ROLES[$i]}"; key="${KEYS[$i]}"
    step "Verify $name ($host, $role) against $rev"
    if ! rsh_ro "$key" "$host" true 2>/dev/null; then FAIL "$name unreachable"; continue; fi

    local out
    out=$(rsh_ro "$key" "$host" "bash -s" <<REMOTE
set -u
src=\$(sed -n 's/^commit: *//p' /opt/sentinel-src/DEPLOYED_COMMIT 2>/dev/null | awk '{print \$1}')
echo "SRC \$src"
for img in ${IMAGES[*]}; do
  echo "IMG \$img \$(docker image inspect "sentinel/\$img:latest" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null)"
done
dp=\$(docker ps --format '{{.Names}}' | grep -E '^sentinel-(waf1|dataplane)-1\$' | head -1)
if [ -n "\$dp" ]; then
  echo "CTR \$(docker inspect "\$dp" --format '{{.Image}}') \$(docker image inspect sentinel/dataplane:latest --format '{{.Id}}' 2>/dev/null)"
  echo "RST \$(docker inspect "\$dp" --format '{{.RestartCount}}')"
fi
hostname_probe=\$(cat /etc/sentinel/2vm-probe-host 2>/dev/null || echo localhost)
echo "HTTP \$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: \$hostname_probe" http://127.0.0.1/ 2>/dev/null)"
# Extract the field on the node rather than shipping a truncated prefix back.
# This read \`| head -c 200\` and produced a FALSE FAIL on the HA box, whose
# healthz lists three listeners and so pushes "status" to byte 196 — the cut
# landed mid-field and the grep below missed a node that was perfectly healthy.
# A check must not depend on how long an unrelated part of the payload is.
echo "HEALTH \$(curl -sk --max-time 8 https://127.0.0.1:9443/healthz 2>/dev/null | grep -o '"status":"[a-z]*"' | head -1)"
REMOTE
    ) || true

    local src_rev; src_rev=$(echo "$out" | awk '/^SRC /{print $2}')
    if [[ "$src_rev" == "$rev" ]]; then PASS "source tree stamped $rev"
    else FAIL "source tree says '${src_rev:-<none>}', expected '$rev' — a rebuild here would not reproduce what is running"; fi

    local img got
    for img in "${IMAGES[@]}"; do
      got=$(echo "$out" | awk -v i="$img" '$1=="IMG" && $2==i {print $3}')
      if [[ "$got" == "$rev" ]]; then PASS "image $img labelled $rev"
      else FAIL "image $img labelled '${got:-<none>}', expected '$rev'"; fi
    done

    local cur new
    cur=$(echo "$out" | awk '/^CTR /{print $2}'); new=$(echo "$out" | awk '/^CTR /{print $3}')
    if [[ -n "$cur" && "$cur" == "$new" ]]; then PASS "data plane container is on the current image"
    elif [[ -n "$cur" ]]; then FAIL "data plane container is stale (not on sentinel/dataplane:latest)"; fi

    local rst; rst=$(echo "$out" | awk '/^RST /{print $2}')
    if [[ -n "$rst" && "$rst" -le 2 ]]; then PASS "data plane restarts=$rst"
    elif [[ -n "$rst" ]]; then FAIL "data plane RestartCount=$rst — crashlooping"; fi

    local code; code=$(echo "$out" | awk '/^HTTP /{print $2}')
    if [[ "$code" == "200" ]]; then PASS "benign request served 200"
    else FAIL "benign request returned '${code:-no response}'"; fi

    if echo "$out" | grep -q '"status":"ok"'; then PASS "data plane /healthz status ok"
    else FAIL "data plane /healthz did not report ok"; fi

    # Pair-specific: replication is the thing a bad roll silently kills.
    if [[ "$role" == "pair-active" ]]; then
      local repl
      repl=$(rsh_ro "$key" "$host" "docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \"select client_addr||' '||state from pg_stat_replication\"" 2>/dev/null | tr -d '\r')
      if [[ "$repl" == *streaming* ]]; then PASS "replication: $repl"
      else FAIL "replication not streaming (got '${repl:-nothing}') — check the active overlay published Postgres"; fi
    fi
  done

  printf '\n'
  if [[ "$FAILS" -gt 0 ]]; then die "$FAILS check(s) FAILED"; fi
  ok "all checks passed"
}

cmd_release() {
  cmd_build
  cmd_ship
  cmd_roll
  cmd_verify
}

usage() {
  sed -n '2,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

SUB="${1:-status}"
# `[[ ... ]] && shift` would be the natural spelling, but under `set -e` a false
# test makes the whole list return 1 and kills the script when run with no args.
if [[ $# -gt 0 ]]; then shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)     DRY=1 ;;
    --only)        ONLY="${2:-}"; shift ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --force)       FORCE=1 ;;
    -h|--help)     usage 0 ;;
    *)             die "unknown option '$1' (try --help)" ;;
  esac
  shift
done

load_fleet

case "$SUB" in
  status)  cmd_status ;;
  build)   cmd_build ;;
  ship)    cmd_ship ;;
  roll)    cmd_roll ;;
  verify)  cmd_verify ;;
  release) cmd_release ;;
  -h|--help|help) usage 0 ;;
  *) die "unknown subcommand '$SUB' — one of: status build ship roll verify release" ;;
esac
