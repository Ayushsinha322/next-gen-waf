#!/usr/bin/env bash
# =============================================================================
#  Does compose.prod.yml parse with EXACTLY the environment install.sh generates?
#
#  THE BUG THIS EXISTS TO PREVENT
#
#  compose.prod.yml gained a Ghost blog as a practice origin, behind
#  `profiles: [ghost]`, guarded by `${GHOST_DB_PASSWORD:?...}`. The profile was
#  believed to keep it out of customer installs. It does not: Compose
#  interpolates the ENTIRE file before it filters by profile, so a variable
#  referenced by a service that never starts still hard-fails every command
#  against that file.
#
#  install.sh generates seven secrets and none of them are GHOST_*. So install.sh
#  on a fresh VM died at its final step —
#
#      required variable GHOST_DB_PASSWORD is missing a value
#
#  — after images were loaded and /opt/sentinel was written, leaving a
#  half-installed host and an operator staring at an error about a blog's
#  database during a WAF install. build-bundle.sh broke the same way: it supplies
#  build placeholders for every other variable, but not for the GHOST_* three.
#
#  Nothing caught it because nothing ever ran these files with anything other
#  than a developer's shell, which happened to have the variables exported.
#
#  WHAT THIS CHECKS
#
#  Not "does it parse bare" — several variables SHOULD be mandatory. The real
#  invariant is narrower and is the one that broke:
#
#      every ${VAR:?} in a compose file must be supplied by whoever deploys it
#
#  So: read the variable names install.sh actually writes into its generated
#  .env, synthesise exactly that environment, and parse the file with it. If
#  Compose still demands a variable, the installer cannot deploy this file — and
#  that is the ghost bug, whatever it is called next time.
#
#  The 2VM overlays are checked against their own documented sources
#  (install-2vm.sh plus deploy/docker/2VM-ACTIVE-PASSIVE.md), because those are
#  deliberately operator-supplied for an HA pair rather than generated.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; fi

INSTALLER=deploy/package/customer/install.sh
BUILDER=deploy/package/build-bundle.sh
TWOVM=deploy/2vm/install-2vm.sh
TWOVM_DOC=deploy/docker/2VM-ACTIVE-PASSIVE.md

fail=0

# ── the gate must be able to run ─────────────────────────────────────────────
# A check that cannot run has to FAIL, not pass. `docker compose config` only
# parses and interpolates, so this needs no daemon and no privileged runner —
# but if the CLI is absent (the apk package renamed, the before_script edited)
# every check below would report a clean parse for files it never opened.
if ! docker compose version >/dev/null 2>&1; then
  printf '\n  %s✗%s docker compose CLI is not available — this gate cannot run\n' "$RED" "$R"
  printf '      %sinstall docker-cli-compose (no daemon needed: `config` never contacts one)%s\n\n' "$DIM" "$R"
  exit 1
fi

# ── what does install.sh actually put in the generated .env? ─────────────────
# The heredoc between `cat > "$ENV_FILE" <<ENVEOF` and `ENVEOF`. Taking the names
# from the installer rather than restating them here is the point: if someone
# removes a variable from the installer, this check starts failing, which is
# exactly the signal wanted.
installer_vars() {
  awk '/cat > "\$ENV_FILE" <<ENVEOF/{inside=1; next} inside && /^ENVEOF$/{inside=0} inside' \
    "$INSTALLER" | grep -oE '^[A-Z_][A-Z0-9_]*=' | tr -d '='
}

# Variables build-bundle.sh exports for the image build. A `:?` variable covered
# only by these is fine for BUILDING but would still break a real install, so
# they are tracked separately and reported differently.
builder_vars() {
  sed -n '/Step 1 of 6/,/docker compose -f compose.prod.yml build/p' "$BUILDER" \
    | grep -oE '\b[A-Z_][A-Z0-9_]*=' | tr -d '='
}

# Operator-supplied HA variables: named in the install script or its guide.
twovm_vars() {
  { [[ -f "$TWOVM" ]] && grep -oE '\b[A-Z_][A-Z0-9_]*=' "$TWOVM" | tr -d '='
    [[ -f "$TWOVM_DOC" ]] && grep -oE '\b[A-Z_][A-Z0-9_]*=' "$TWOVM_DOC" | tr -d '='
  } 2>/dev/null
}

# ── build a synthetic env file from a list of variable names ────────────────
# Values are placeholders; only presence is under test. A few need a shape that
# survives Compose's own validation rather than any string.
synth_env() {
  local out="$1"; shift
  : > "$out"
  local v
  for v in "$@"; do
    case "$v" in
      *CIDR*)                printf '%s=0.0.0.0/32\n'         "$v" ;;
      *_URL|*_URL_PRIMARY)   printf '%s=http://placeholder\n' "$v" ;;
      # Compose validates these against a schema after interpolation, so a bare
      # word fails on shape rather than on absence and would be misread as the
      # very bug this script hunts for.
      *MEM_LIMIT*|*_LIMIT)   printf '%s=1g\n'                 "$v" ;;
      # Two bind shapes exist in the compose files and they are not the same.
      # SENTINEL_MGMT_BIND carries its own trailing colon
      # ("${SENTINEL_MGMT_BIND:-127.0.0.1:}9443:9443"), while SENTINEL_PG_BIND
      # and SENTINEL_CH_BIND do not ("${SENTINEL_PG_BIND:-0.0.0.0}:5432:5432").
      # One placeholder for both produced "127.0.0.1::5432" and failed the file
      # on the harness's own value rather than on anything in the file.
      *MGMT_BIND*)           printf '%s=127.0.0.1:\n'         "$v" ;;
      *BIND*)                printf '%s=127.0.0.1\n'          "$v" ;;
      *PORT*|*_DAYS|*_BYTES) printf '%s=1\n'                  "$v" ;;
      *)                     printf '%s=placeholder\n'        "$v" ;;
    esac >> "$out"
  done
}

# ── the check ────────────────────────────────────────────────────────────────
# $1 comma-separated compose files, base first  $2 human label
# $3.. variable names considered "supplied"
#
# The file list matters. compose.ha.yml, compose.cluster.yml and the two 2VM
# files are OVERLAYS — each one's own header documents the invocation as
# `-f compose.prod.yml -f <overlay>`. Parsed alone they fail for reasons that
# say nothing about the deployment ("service waf2 refers to undefined network
# sentinel", "controlplane has neither an image nor a build context"), because
# the base declares those. Checking an overlay by itself tests a command nobody
# runs, so the stack under test is spelled out at each call site.
check_file() {
  local spec="$1" label="$2"; shift 2
  local -a files=() fargs=()
  IFS=',' read -r -a files <<< "$spec"
  local f
  for f in "${files[@]}"; do fargs+=(-f "$f"); done
  # Name the file under test — the last one — not the base it layers on.
  local file="${files[${#files[@]} - 1]}"
  local envf; envf="$(mktemp)"
  synth_env "$envf" "$@"

  # Gate on the EXIT STATUS, never on the wording of the message.
  #
  # This used to pipe compose's output through `grep -iE '^error|error while'`
  # and treat an empty match as success. That matches only INTERPOLATION
  # failures. Probed directly, all three of these produced no match and were
  # reported as a clean parse:
  #
  #   yaml: line 1: did not find expected key            (syntax error)
  #   validating ...: Additional property prots is not allowed  (schema error)
  #   env: 'docker': No such file or directory           (tool missing)
  #
  # So a malformed compose file passed this gate and failed at the customer's
  # first `docker compose up`. `config -q` already exits non-zero on every one
  # of them; the exit code is the whole answer and needs no pattern.
  local out rc=0
  out=$(env -i PATH="$PATH" HOME="$HOME" \
          docker compose --env-file "$envf" "${fargs[@]}" config -q 2>&1) || rc=$?

  if (( rc == 0 )); then
    printf '  %s✓%s %-26s parses with the environment %s provides\n' \
      "$GRN" "$R" "$(basename "$file")" "$label"
  else
    printf '  %s✗%s %-26s %sunsatisfied by %s%s\n' \
      "$RED" "$R" "$(basename "$file")" "$RED" "$label" "$R"
    printf '      %s%s%s\n' "$DIM" "$(printf '%s\n' "$out" | head -1)" "$R"
    printf '      %s→ if a variable is missing: generate it in %s, or move the\n' "$DIM" "$label"
    printf '        service into an overlay only its users pass (see compose.ghost.yml).\n'
    printf '        Any other error means the file itself does not parse.%s\n' "$R"
    fail=$((fail + 1))
  fi
  rm -f "$envf"
}

printf '\n%s%s==> compose files must parse with the environment their installer generates%s\n\n' \
  "$B" "$YEL" "$R"

mapfile -t IVARS < <(installer_vars)
mapfile -t BVARS < <(builder_vars)
mapfile -t HVARS < <(twovm_vars)

if (( ${#IVARS[@]} == 0 )); then
  printf '  %s✗%s could not read the generated-.env block from %s\n' "$RED" "$R" "$INSTALLER"
  printf '      %sthe heredoc marker moved — fix installer_vars() in this script%s\n\n' "$DIM" "$R"
  exit 1
fi
printf '  %sinstall.sh generates %d variables; build-bundle.sh exports %d for the build%s\n\n' \
  "$DIM" "${#IVARS[@]}" "${#BVARS[@]}" "$R"

# What a customer install actually runs.
check_file deploy/docker/compose.prod.yml    "install.sh"   "${IVARS[@]}"
check_file deploy/docker/compose.prod.yml,deploy/docker/compose.ha.yml \
           "install.sh"   "${IVARS[@]}"
check_file deploy/docker/compose.prod.yml,deploy/docker/compose.cluster.yml \
           "install.sh"   "${IVARS[@]}"

# What the release build runs, before any customer is involved.
check_file deploy/docker/compose.prod.yml    "build-bundle.sh" "${BVARS[@]}"

# Deliberate HA overlays: operator-supplied, per the 2VM guide.
check_file deploy/docker/compose.prod.yml,deploy/docker/compose.2vm-active.yml \
           "install-2vm.sh + its guide" "${IVARS[@]}" "${HVARS[@]}"
check_file deploy/docker/compose.prod.yml,deploy/docker/compose.2vm-passive.yml \
           "install-2vm.sh + its guide" "${IVARS[@]}" "${HVARS[@]}"

# ── overlays that are allowed to be strict ──────────────────────────────────
# compose.ghost.yml keeps its `:?` guards on purpose: for a public-edge practice
# run those values must be set deliberately, and a default password on an
# internet-facing origin is worse than a failed command. Isolation is what makes
# strictness affordable — it can only fail the people who ask for it. Assert it
# stays isolated, i.e. that nothing in the default deployment path pulls it in.
printf '\n%s%s==> the strict overlay stays opt-in%s\n\n' "$B" "$YEL" "$R"

if grep -qE 'compose\.ghost\.yml' "$INSTALLER" 2>/dev/null; then
  printf '  %s✗%s install.sh references compose.ghost.yml — a customer install must never load it\n' "$RED" "$R"
  fail=$((fail + 1))
else
  printf '  %s✓%s install.sh does not load compose.ghost.yml\n' "$GRN" "$R"
fi

if grep -qE '^\s*(ghost|ghost-db):' deploy/docker/compose.prod.yml 2>/dev/null; then
  printf '  %s✗%s ghost services are back in compose.prod.yml\n' "$RED" "$R"
  fail=$((fail + 1))
else
  printf '  %s✓%s compose.prod.yml declares no practice-origin services\n' "$GRN" "$R"
fi

# ── the passive node must have somewhere to put its events ───────────────────
# Measured on 2026-07-29: the passive VM held the VIP, blocked nine attacks with
# 403, and ClickHouse held ZERO of them. That VM runs no ClickHouse, so with the
# inherited `clickhouse:8123` the writer resolved nothing and the history was
# simply never recorded — the SOC console goes blind after a failover, and the
# FPR pilot gets a silent hole in exactly the window it is measuring.
#
# Four properties make it safe, and all four are invisible in a diff of one
# file, so assert them against the RENDERED config rather than by reading YAML:
#   1. the sink points at the primary's REAL address — never localhost, never
#      the VIP (the VIP follows traffic, so during a failover it resolves to
#      THIS node and the writer would be chasing itself),
#   2. the internal CA is trusted, or every HTTPS write fails verification,
#   3. a spool directory is set, so a primary outage DELAYS the audit trail
#      instead of punching a hole in it,
#   4. the spool lands on a PERSISTED volume, or a container restart discards
#      whatever was waiting to be replayed.
printf '\n%s%s==> the passive node has a durable event sink%s\n\n' "$B" "$YEL" "$R"

check_passive_sink() {
  local envf; envf="$(mktemp)"
  synth_env "$envf" "${IVARS[@]}" "${HVARS[@]}"
  # Give the sink URL a concrete host: the generic placeholder would pass the
  # "not localhost" assertion for the wrong reason.
  sed -i 's#^SENTINEL_CLICKHOUSE_URL_PRIMARY=.*#SENTINEL_CLICKHOUSE_URL_PRIMARY=https://10.9.9.9:8443#' "$envf"

  local rendered
  if ! rendered=$(env -i PATH="$PATH" HOME="$HOME" docker compose --env-file "$envf" \
        -f deploy/docker/compose.prod.yml -f deploy/docker/compose.2vm-passive.yml \
        config 2>/dev/null); then
    printf '  %s✗%s could not render the passive overlay\n' "$RED" "$R"
    fail=$((fail + 1)); rm -f "$envf"; return
  fi
  rm -f "$envf"

  # Extract just the `dataplane:` service block from the rendered config.
  #
  # Deliberately awk + grep, with no python and no yaml library: this runs in the
  # deploy-shell job, an alpine image carrying only bash/shellcheck/git/
  # coreutils/findutils/grep/sed/docker-cli-compose. An earlier version of this
  # check shelled out to python3 and turned the whole job red with
  # "python3: command not found" — a guard that cannot run where it is supposed
  # to run is worse than no guard, and making it skip when its interpreter is
  # missing would have been worse still (silently green).
  #
  # Services sit at two-space indent in `docker compose config` output and their
  # keys at four, so the block ends at the next two-space key.
  local dp
  dp=$(printf '%s\n' "$rendered" | awk '
    /^  dataplane:[[:space:]]*$/ { inblk = 1; next }
    inblk && /^  [^ ]/          { inblk = 0 }
    inblk                        { print }
  ')

  if [[ -z "$dp" ]]; then
    printf '  %s✗%s no dataplane service in the rendered passive overlay\n' "$RED" "$R"
    fail=$((fail + 1)); return
  fi

  # value_of <KEY> — the rendered value of one environment key, unquoted.
  value_of() {
    printf '%s\n' "$dp" \
      | grep -E "^      $1:" \
      | head -1 \
      | sed -e "s/^      $1:[[:space:]]*//" -e 's/^"//' -e 's/"$//'
  }

  local problems=()
  local url ca spool
  url=$(value_of SENTINEL_CLICKHOUSE_URL)
  ca=$(value_of SENTINEL_CLICKHOUSE_CA_FILE)
  spool=$(value_of SENTINEL_SPOOL_DIR)

  if [[ -z "$url" ]]; then
    problems+=("SENTINEL_CLICKHOUSE_URL is unset — events go nowhere")
  elif printf '%s' "$url" | grep -qE 'localhost|127\.0\.0\.1|//clickhouse:|@clickhouse:'; then
    problems+=("sink points at a LOCAL ClickHouse this VM does not run: $url")
  fi
  [[ -n "$ca" ]] || problems+=("no SENTINEL_CLICKHOUSE_CA_FILE — an internal cert cannot verify")

  if [[ -z "$spool" ]]; then
    problems+=("no SENTINEL_SPOOL_DIR — a primary outage loses events instead of delaying them")
  else
    # The spool must land on a mounted volume, or a container restart discards
    # whatever was waiting to be replayed. Compose renders each mount as a
    # `target:` line inside the service's `volumes:` list.
    local mounted=0 tgt
    while IFS= read -r tgt; do
      [[ -n "$tgt" ]] || continue
      case "$spool" in
        "$tgt"|"$tgt"/*) mounted=1; break;;
      esac
    done < <(printf '%s\n' "$dp" | grep -E '^[[:space:]]+target:' | sed -e 's/^[[:space:]]*target:[[:space:]]*//' -e 's/^"//' -e 's/"$//')
    (( mounted )) || problems+=("spool $spool is not on a mounted volume — a restart discards it")
  fi

  if (( ${#problems[@]} == 0 )); then
    printf '  %s✓%s passive dataplane writes to the primary, over the internal CA, with a persisted spool\n' "$GRN" "$R"
  else
    local msg
    for msg in "${problems[@]}"; do
      printf '  %s✗%s %s\n' "$RED" "$R" "$msg"
      fail=$((fail + 1))
    done
  fi
}
check_passive_sink

# ── HTTPS must be highly available, not single-homed ─────────────────────────
#
# The defect this pins: waf1 published :443 directly, so HTTPS ran on ONE node
# while compose.ha.yml's header promised "kill any node → zero downtime". True
# for :80 only. Killing waf1, or merely rolling it during an upgrade, took HTTPS
# down — and nothing checked, which is why it survived for months. Rolling
# restarts appeared clean because they curled ~12s after each roll, well after
# the window had closed.
#
# Three properties, each of which independently breaks HTTPS HA if lost:
#   1. exactly ONE service binds host 443/tcp, and it is the load balancer
#   2. every waf node mounts the SHARED cert volume — otherwise a node serves
#      its own self-signed cert and clients see a different certificate
#      depending on which node they land on
#   3. every waf node expects PROXY protocol on its https listener — otherwise
#      every HTTPS client looks like the balancer and the IP blocklist,
#      per-source rate limits, correlation and auto-ban all collapse silently
check_https_is_ha() {
  printf '\n%s==> HTTPS survives losing a node%s\n\n' "$B" "$R"
  local envf; envf="$(mktemp)"
  synth_env "$envf" "${IVARS[@]}" "${HVARS[@]}"
  local rendered problems=()
  if ! rendered=$(env -i PATH="$PATH" HOME="$HOME" docker compose --env-file "$envf" \
        -f deploy/docker/compose.prod.yml -f deploy/docker/compose.cluster.yml \
        -f deploy/docker/compose.ha.yml config 2>/dev/null); then
    printf '  %s✗%s could not render the HA topology\n' "$RED" "$R"
    fail=$((fail + 1)); rm -f "$envf"; return
  fi
  rm -f "$envf"

  # awk + grep ONLY — no python, no yaml library. This job runs in an alpine
  # image with bash/shellcheck/git/coreutils/findutils/grep/sed/docker-cli-compose
  # and nothing else. The note on check_passive_sink above records this exact
  # lesson, and the first version of THIS check ignored it and turned the job red
  # with "python3: command not found". Twice is a pattern, so it is written here
  # too, next to the code that would repeat it.
  #
  # Rendered shapes being matched (verified against real output, not assumed):
  #     ports:                       volumes:                environment:
  #       - mode: ingress              - type: volume          KEY: value
  #         target: 443                  source: sentinel-certs
  #         published: "443"             target: /var/lib/sentinel/certs
  #         protocol: tcp

  # 1. Exactly one service may publish host 443/tcp, and it must be the balancer.
  #    A port entry spans several lines, so published+protocol are paired per
  #    entry rather than grepped independently — otherwise 443/udp on waf1 would
  #    satisfy a naive "published 443 and protocol tcp somewhere in this service".
  local owners
  #    Evaluated at the END of each port entry, not on the `published:` line.
  #    `protocol:` is rendered AFTER `published:`, so testing early sees the
  #    default "tcp" and mistakes waf1's 443/UDP for a TCP binding — which is
  #    exactly what the first version of this awk did.
  owners=$(printf '%s\n' "$rendered" | awk '
    function flush() {
      if (have && pub == "443" && proto == "tcp") print svc
      have = 0; pub = ""; proto = "tcp"
    }
    /^  [^ ]+:[[:space:]]*$/          { flush(); svc = $1; sub(/:$/, "", svc); inports = 0 }
    /^    ports:[[:space:]]*$/        { flush(); inports = 1; next }
    inports && /^    [^ ]/            { flush(); inports = 0 }
    inports && /^      - /            { flush(); have = 1 }
    inports && /published:/           { pub = $2; gsub(/"/, "", pub) }
    inports && /protocol:/            { proto = $2 }
    END                               { flush() }
  ' | sort -u | tr '\n' ' ' | sed 's/ $//')
  if [[ "$owners" != "lb" ]]; then
    problems+=("host 443/tcp is bound by [${owners:-nothing}], want exactly [lb] — HTTPS is single-homed unless the balancer owns it")
  fi

  # 2. + 3. Every waf node needs the shared cert volume and the PROXY-protocol
  #    listener name. Without the first it serves its own self-signed cert;
  #    without the second every HTTPS client looks like the balancer.
  local svc missing_certs="" missing_pp="" blk
  for svc in $(printf '%s\n' "$rendered" | grep -oE '^  waf[0-9]+:' | tr -d ' :'); do
    blk=$(printf '%s\n' "$rendered" | awk -v s="  $svc:" '
      $0 == s        { inblk = 1; next }
      inblk && /^  [^ ]/ { inblk = 0 }
      inblk          { print }
    ')
    printf '%s\n' "$blk" | grep -qE '^        target: /var/lib/sentinel/certs[[:space:]]*$' \
      || missing_certs="$missing_certs $svc"
    printf '%s\n' "$blk" | grep -qE '^      SENTINEL_PROXY_PROTOCOL_LISTENERS:.*https' \
      || missing_pp="$missing_pp $svc"
  done
  missing_certs="${missing_certs# }"; missing_pp="${missing_pp# }"
  [[ -n "$missing_certs" ]] && problems+=("[$missing_certs] do not mount the shared cert volume — they would serve their own self-signed cert")
  [[ -n "$missing_pp" ]] && problems+=("[$missing_pp] do not expect PROXY protocol on https — every HTTPS client would look like the load balancer")

  if (( ${#problems[@]} == 0 )); then
    printf '  %s✓%s only the balancer owns 443/tcp; every node has the shared certs and expects PROXY protocol\n' "$GRN" "$R"
  else
    local msg
    for msg in "${problems[@]}"; do
      printf '  %s✗%s %s\n' "$RED" "$R" "$msg"
      fail=$((fail + 1))
    done
  fi
}
check_https_is_ha

# ── RUST_LOG must not carry a `sentinel=` directive ──────────────────────────
#
# `RUST_LOG=info,sentinel=info` silently disabled EVERY log line from the
# sentinel-modules crate: geoip, bot_detect, dlp, jwt_auth, anti_ddos,
# rate_limit, ip_reputation, threat_intel, smuggling, tls_fingerprint, graphql,
# grpc. Twelve subsystems, invisible on every deployment. `sentinel` is not a
# module-path prefix of `sentinel_modules`, so the targeted directive never
# matched it and its presence stopped the bare `info` applying as the default.
#
# Proven on .71 by toggling only this value and restarting one node: with the
# directive, zero sentinel_modules lines in the container's whole lifetime;
# without it, the GeoIP lines appear immediately. It is also why GeoIP's
# "database not found" warning went unnoticed for months — emitted and filtered.
#
# grep, not compose rendering: this must also catch the Dockerfile ENV and the
# k8s manifests, which are the copies a fix is most easily missed in.
check_rust_log_directives() {
  printf '\n%s==> RUST_LOG does not silence a crate%s\n\n' "$B" "$R"
  local hits
  # --exclude-dir=ci, and the directive must appear AFTER RUST_LOG on the line.
  # Without both, this check matched ITS OWN message text and reported the guard
  # as the violation — the same self-match that made `pkill -f` kill its own SSH
  # session and `pgrep -cf` report a process that was not running.
  hits=$(grep -rn --exclude-dir=ci "RUST_LOG" deploy/ 2>/dev/null \
         | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' \
         | grep -E "RUST_LOG.*sentinel[a-z_]*=" || true)
  if [[ -z "$hits" ]]; then
    printf '  %s✓%s no per-crate sentinel=* directive in any RUST_LOG\n' "$GRN" "$R"
  else
    printf '  %s✗%s RUST_LOG carries a sentinel=* directive — this silences sentinel-modules entirely:\n' "$RED" "$R"
    printf '      %s\n' "$hits"
    fail=$((fail + 1))
  fi
}
check_rust_log_directives

# ── Node services must have a pinned identity ────────────────────────────────
#
# A node reports itself to the cluster view under its hostname. Docker's default
# hostname is the container id, which changes on every recreate, so an unpinned
# controlplane/dataplane left a permanent "down" ghost behind after every
# upgrade or rollback — seen on the first customer install. Render the standalone
# compose file with the installer's environment and assert both services carry a
# hostname. The cluster/HA overlays pin their own (cp2/cp3, waf1/2/3).
check_node_identity() {
  printf '\n%s==> node services carry a stable identity%s\n\n' "$B" "$R"
  local envf rendered
  # Without jq the lookup below returns nothing, and "nothing" used to read as
  # "has no hostname" — a false product defect that failed every pipeline for
  # three days while the compose file was correct. A missing tool is a missing
  # tool: say so, and still fail, because an unrun check is not a pass.
  if ! command -v jq >/dev/null 2>&1; then
    printf '  %s✗%s jq is not installed — cannot inspect node hostnames (install jq; the compose file was NOT checked)\n' "$RED" "$R"
    fail=$((fail + 1)); return
  fi
  envf=$(mktemp); synth_env "$envf" "${IVARS[@]}"
  rendered=$(cd deploy/docker && docker compose --env-file "$envf" -f compose.prod.yml config --format json 2>/dev/null) || rendered=""
  rm -f "$envf"
  if [[ -z "$rendered" ]]; then
    printf '  %s✗%s could not render compose.prod.yml to inspect hostnames\n' "$RED" "$R"; fail=$((fail + 1)); return
  fi
  local svc h
  for svc in controlplane dataplane; do
    h=$(jq -r --arg s "$svc" '.services[$s].hostname // empty' <<<"$rendered")
    if [[ -n "$h" ]]; then
      printf '  %s✓%s %s: hostname %s\n' "$GRN" "$R" "$svc" "$h"
    else
      printf '  %s✗%s %s has no hostname — every recreate mints a new node id and leaves a permanent "down" ghost\n' "$RED" "$R" "$svc"
      fail=$((fail + 1))
    fi
  done
}
check_node_identity

printf '\n'
if (( fail )); then
  printf '  %s✗ %d compose problem(s) — an install or a release build would abort%s\n\n' "$RED" "$fail" "$R"
  exit 1
fi
printf '  %s✓ every compose file parses with the environment its installer provides%s\n\n' "$GRN" "$R"
