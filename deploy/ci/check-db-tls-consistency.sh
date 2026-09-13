#!/usr/bin/env bash
# =============================================================================
#  Every Postgres DSN this repo writes must use a TLS mode the server accepts.
#
#  THE BUG THIS EXISTS TO PREVENT
#
#  compose.prod.yml points Postgres at our own pg_hba.conf, which has no plain
#  `host` line at all — only `hostssl … scram-sha-256`. A TCP client that
#  disables TLS is refused outright:
#
#      no pg_hba.conf entry for host "…", user "sentinel", SSL off
#
#  install-2vm.sh generated both DSNs with `sslmode=disable`. So on a fresh
#  2-VM master the control plane and migrate could not connect at all: the
#  control plane started in degraded mode, every login returned 503, and the
#  installer still exited 0 — its only health probe watches the DATA plane,
#  which serves from a cached config and needs no database.
#
#  install.sh had written the correct DSN for the single-host path all along.
#  One file disagreed with the server's own policy, and nothing compared them.
#
#  WHAT THIS CHECKS
#
#  Not "is TLS on" as a preference. It reads the ACTUAL policy out of
#  pg_hba.conf and holds every generated DSN to it, so if the policy is ever
#  relaxed deliberately this check relaxes with it rather than having to be
#  remembered.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
fail=0
HBA=deploy/docker/pg_hba.conf

printf '\n%s%s==> generated DSNs match what pg_hba actually accepts%s\n\n' "$B" "$YEL" "$R"

[[ -f "$HBA" ]] || { printf '  %s✗%s %s missing\n\n' "$RED" "$R" "$HBA"; exit 1; }

# Does the server accept a NON-TLS TCP connection? `local` lines are unix-socket
# only and do not count; `hostssl` requires TLS; a bare `host` accepts either.
if grep -qE '^[[:space:]]*host[[:space:]]' "$HBA"; then
  TLS_REQUIRED=0
  printf '  %spg_hba has a plain `host` line: non-TLS TCP is accepted%s\n\n' "$DIM" "$R"
else
  TLS_REQUIRED=1
  printf '  %spg_hba is hostssl-only: TLS is mandatory for every TCP client%s\n\n' "$DIM" "$R"
fi

# sslmode values that do NOT guarantee TLS. `prefer` negotiates TLS first and
# would happen to work, but it silently falls back, which is exactly the kind of
# "works until it doesn't" this deployment should not ship.
INSECURE_RE='sslmode=(disable|allow|prefer)'

# Everything that writes a DSN a deployment will actually use.
FILES=(
  deploy/package/customer/install.sh
  deploy/2vm/install-2vm.sh
  deploy/docker/.env.example
)

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || { printf '  %s✗%s %s missing\n' "$RED" "$R" "$f"; fail=$((fail + 1)); continue; }

  # Only lines that actually assign a DSN — a comment explaining sslmode is not
  # a defect, and several of these files document the reasoning at length.
  dsns=$(grep -nE 'SENTINEL_DB_URL[A-Z_]*[= ]' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | grep 'postgres://')

  if [[ -z "$dsns" ]]; then
    printf '  %s·%s %s writes no DSN\n' "$DIM" "$R" "$(basename "$f")"
    continue
  fi

  bad_lines=""
  missing_mode=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if (( TLS_REQUIRED == 1 )); then
      if printf '%s' "$line" | grep -qE "$INSECURE_RE"; then
        bad_lines+="      $line"$'\n'
      elif ! printf '%s' "$line" | grep -q 'sslmode='; then
        missing_mode+="      $line"$'\n'
      fi
    fi
  done <<< "$dsns"

  if [[ -z "$bad_lines" && -z "$missing_mode" ]]; then
    printf '  %s✓%s %s\n' "$GRN" "$R" "$(basename "$f")"
  else
    if [[ -n "$bad_lines" ]]; then
      printf '  %s✗%s %s disables or downgrades TLS, and the server refuses that:\n' \
        "$RED" "$R" "$(basename "$f")"
      printf '%s' "$bad_lines"
      fail=$((fail + 1))
    fi
    if [[ -n "$missing_mode" ]]; then
      printf '  %s✗%s %s writes a DSN with no sslmode at all (libpq defaults to prefer):\n' \
        "$RED" "$R" "$(basename "$f")"
      printf '%s' "$missing_mode"
      fail=$((fail + 1))
    fi
  fi
done

# A verifying mode needs a CA to verify against, or libpq errors at connect time
# with a message about a root certificate rather than about configuration.
printf '\n'
for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || continue
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if printf '%s' "$line" | grep -qE 'sslmode=verify-(full|ca)' \
       && ! printf '%s' "$line" | grep -q 'sslrootcert='; then
      printf '  %s✗%s %s: verify-* without sslrootcert\n' "$RED" "$R" "$(basename "$f")"
      printf '      %s%s%s\n' "$DIM" "$line" "$R"
      fail=$((fail + 1))
    fi
  done <<< "$(grep -nE 'SENTINEL_DB_URL[A-Z_]*[= ]' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | grep 'postgres://')"
done

if (( fail == 0 )); then
  printf '  %s✓%s every generated DSN matches the server policy\n\n' "$GRN" "$R"
  exit 0
fi
printf '  %s✗%s %d problem(s) — a control plane would start with no database\n\n' "$RED" "$R" "$fail"
exit 1
