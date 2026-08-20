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
      *BIND*)                printf '%s=127.0.0.1:\n'         "$v" ;;
      *PORT*|*_DAYS|*_BYTES) printf '%s=1\n'                  "$v" ;;
      *)                     printf '%s=placeholder\n'        "$v" ;;
    esac >> "$out"
  done
}

# ── the check ────────────────────────────────────────────────────────────────
# $1 compose file  $2 human label  $3.. variable names considered "supplied"
check_file() {
  local file="$1" label="$2"; shift 2
  local envf; envf="$(mktemp)"
  synth_env "$envf" "$@"

  local err
  if err=$(env -i PATH="$PATH" HOME="$HOME" \
             docker compose --env-file "$envf" -f "$file" config -q 2>&1 \
             | grep -iE '^error|error while' | head -1); [[ -z "$err" ]]; then
    printf '  %s✓%s %-26s parses with the environment %s provides\n' \
      "$GRN" "$R" "$(basename "$file")" "$label"
  else
    printf '  %s✗%s %-26s %sunsatisfied by %s%s\n' \
      "$RED" "$R" "$(basename "$file")" "$RED" "$label" "$R"
    printf '      %s%s%s\n' "$DIM" "$err" "$R"
    printf '      %s→ either generate the variable in %s, or move the service\n' "$DIM" "$label"
    printf '        into an overlay file only its users pass (see compose.ghost.yml)%s\n' "$R"
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
check_file deploy/docker/compose.ha.yml      "install.sh"   "${IVARS[@]}"
check_file deploy/docker/compose.cluster.yml "install.sh"   "${IVARS[@]}"

# What the release build runs, before any customer is involved.
check_file deploy/docker/compose.prod.yml    "build-bundle.sh" "${BVARS[@]}"

# Deliberate HA overlays: operator-supplied, per the 2VM guide.
check_file deploy/docker/compose.2vm-active.yml  "install-2vm.sh + its guide" "${IVARS[@]}" "${HVARS[@]}"
check_file deploy/docker/compose.2vm-passive.yml "install-2vm.sh + its guide" "${IVARS[@]}" "${HVARS[@]}"

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

printf '\n'
if (( fail )); then
  printf '  %s✗ %d compose problem(s) — an install or a release build would abort%s\n\n' "$RED" "$fail" "$R"
  exit 1
fi
printf '  %s✓ every compose file parses with the environment its installer provides%s\n\n' "$GRN" "$R"
