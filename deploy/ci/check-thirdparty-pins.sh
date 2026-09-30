#!/usr/bin/env bash
# =============================================================================
#  Every place a supporting image is named must name the tag the bundle ships.
#
#  The ClickHouse pin is a literal in a dozen files — compose prod/dev, both
#  k8s manifests, the k8s backup job, the backup drill, the bundle's
#  THIRD_PARTY list, the mirror script, the customer README — and moving it
#  24.10 -> 26.8 -> 26.3 meant editing all of them by hand. One missed file
#  fails silently: the drill ("same versions as prod") tests a different
#  server, the k8s backup job's clickhouse-client drifts from the server, or the
#  offline bundle ships an image compose never runs, so an air-gapped upgrade
#  stops at its image-presence check. (Code review finding.)
#
#  The source of truth is build-bundle.sh's THIRD_PARTY list. For each
#  `repo:tag` there, every `repo:<tag>` in the tracked deployment files must use
#  that tag. Plus a denylist: images the product deliberately replaced.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/../.."

if [[ -t 1 ]]; then GRN=$'\e[92m'; RED=$'\e[91m'; R=$'\e[0m'; else GRN=''; RED=''; R=''; fi
fail=0
pass() { printf '  %s✓%s %s\n' "$GRN" "$R" "$1"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$R" "$1"; fail=$((fail + 1)); }

# The pinned list, straight out of the bundle builder.
mapfile -t PINS < <(awk '/^THIRD_PARTY=\(/{on=1; next} on && /^\)/{exit} on' deploy/package/build-bundle.sh \
                     | grep -o '"[^"]*"' | tr -d '"')
(( ${#PINS[@]} > 0 )) || { bad "could not read THIRD_PARTY from build-bundle.sh"; exit 1; }

# The files that name images: deployment config, scripts and customer docs.
# Load-test result logs are data, not configuration.
mapfile -t FILES < <(git ls-files deploy THIRD-PARTY-NOTICES.md 2>/dev/null \
  | grep -E '\.(ya?ml|sh|py|md)$' | grep -v '^deploy/load-test/results/')
# Without git (or when git refuses the checkout — "dubious ownership" in a
# container) fall back to the tree itself. An EMPTY list must never pass: grep
# with no file operand reads stdin, finds nothing, and every pin "agrees".
if (( ${#FILES[@]} == 0 )); then
  mapfile -t FILES < <(find deploy THIRD-PARTY-NOTICES.md -type f \
    \( -name '*.yml' -o -name '*.yaml' -o -name '*.sh' -o -name '*.py' -o -name '*.md' \) \
    2>/dev/null | grep -v '^deploy/load-test/results/' | sort)
fi
(( ${#FILES[@]} > 50 )) || { bad "found only ${#FILES[@]} deployment files to check — refusing to pass on nothing"; exit 1; }

for pin in "${PINS[@]}"; do
  repo="${pin%:*}"; tag="${pin##*:}"
  # `repo:TAG` where the repo is not the tail of a longer name (e.g. a registry
  # prefix is fine: `hub.example/clickhouse/clickhouse-server:…` still counts).
  re="(^|[^A-Za-z0-9_.-])${repo//./\\.}:[A-Za-z0-9][A-Za-z0-9._-]*"
  wrong=()
  while IFS= read -r hit; do
    file="${hit%%:*}"; rest="${hit#*:}"; lineno="${rest%%:*}"; match="${rest#*:}"
    found="${match##*"${repo}:"}"
    # An all-digit "tag" is a port in a connection string (postgres:5432),
    # not an image — none of the shipped pins is a bare number.
    [[ "$found" =~ ^[0-9]+$ ]] && continue
    [[ "$found" == "$tag" ]] || wrong+=("$file:$lineno names $repo:$found")
  done < <(grep -nHoE "$re" -- "${FILES[@]}" 2>/dev/null </dev/null)
  if (( ${#wrong[@]} == 0 )); then
    pass "$pin — every reference agrees"
  else
    bad "$pin is the shipped pin, but:"
    printf '        %s\n' "${wrong[@]}"
  fi
done

# Images the product replaced on purpose, which must not come back in any
# `image:` line. redis:7 resolves to 7.4, dual-licensed RSALv2/SSPL — not open
# source, and not redistributable in a bundle; compose ships Valkey.
denied=$(grep -nHE '^[[:space:]]*(-[[:space:]]+)?image:[[:space:]]*"?redis:' -- "${FILES[@]}" 2>/dev/null </dev/null)
if [[ -z "$denied" ]]; then
  pass "no manifest runs redis: (the product ships valkey/valkey)"
else
  bad "redis: image still in use (RSALv2/SSPL — use valkey/valkey as compose does):"
  sed 's/^/        /' <<<"$denied"
fi

printf '\n'
(( fail == 0 )) && { printf '  %s✓%s third-party pins agree\n\n' "$GRN" "$R"; exit 0; }
printf '  %s✗%s %d problem(s)\n\n' "$RED" "$R" "$fail"
exit 1
