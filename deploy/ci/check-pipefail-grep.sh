#!/usr/bin/env bash
# =============================================================================
#  No unbounded producer may be piped into `grep -q` under `set -o pipefail`.
#
#  THE BUG THIS EXISTS TO PREVENT
#
#  Every deploy script sets `pipefail`. In a pipeline, `grep -q` exits the
#  instant it matches; the producer on the left is then killed by SIGPIPE and
#  exits 141; pipefail makes the PIPELINE status 141. So:
#
#      if docker logs X 2>&1 | grep -q 'degraded mode'; then   # never taken
#
#  A pattern that IS present reads as ABSENT. Measured, not theorised: a
#  200k-line producer piped into `grep -q` on a string it contains returns 141
#  and takes the else branch, while a one-line producer finishes before grep
#  exits and behaves correctly. That size dependence is what makes it hide — it
#  works on a quiet box and inverts on a busy one.
#
#  It bit three checks at once. The customer installer's own verifier reported a
#  control plane that had logged "degraded mode" as healthy, and verify-deploy's
#  Raft check announced "no Raft references" precisely when there were some
#  (there the `!` flipped it the dangerous way round).
#
#  A `tail` in the middle does not save it: tail becomes the process that dies.
#
#  THE FIX, and what this script enforces
#
#      logs=$(docker logs X 2>&1 || true)
#      if grep -q 'pattern' <<<"$logs"; then
#
#  Capture first, match the variable, no pipeline, no exit-status puzzle.
#
#  SCOPE: unbounded producers, AND the Docker CLI's list commands. `echo`,
#  `printf`, `ss`, `ip` and a `psql -tAc` are buffered: they hand grep their
#  whole output in one write and are done before it can exit, so they are left
#  alone. Size is not the whole story, though. Docker and Compose are Go
#  programs whose stdout is unbuffered — one write per LINE — so a short list is
#  enough when the match is not its last line. `dc config --services` (13
#  lines, in a different order every run) dropped the dashboard from
#  rolling-update.sh in 2 runs of 15 on .71, and the 1.1.20 roll reported
#  success with the console still on the old image.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

# Producers whose output has no bound. `docker logs` is the one that bit us;
# `journalctl`, `cat` of a log, and `docker compose logs` are the same shape.
# Then Docker's list commands, written a line at a time (see SCOPE): `ps`,
# `port`, `images`, `inspect`, and Compose's `config` / `ps`, including through
# rolling-update.sh's `dc` wrapper. POSIX classes only, no `\b`: CI runs this
# under Alpine's busybox grep, where `\b` silently matches nothing.
UNBOUNDED='docker logs|docker compose logs|docker-compose logs|journalctl'
UNBOUNDED+='|docker[[:space:]]+(ps|port|images|inspect)([[:space:]]|$)'
UNBOUNDED+='|docker[ -]compose[^|]*[[:space:]](config|ps)([[:space:]]|$)'
UNBOUNDED+='|(^|[^[:alnum:]_])dc[[:space:]]+(config|ps)([[:space:]]|$)'

printf '\n%s%s==> no unbounded producer piped into grep -q%s\n\n' "$B" "$YEL" "$R"

# `grep -v` drops comment lines: this script documents the broken form in its
# own header, and a guard that fails on its own explanation is no use to anyone.
hits=$(grep -rnE "(${UNBOUNDED})[^|]*\|([^|]*\|)*[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q" \
         deploy --include='*.sh' 2>/dev/null \
       | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)

if [[ -z "$hits" ]]; then
  printf '  %s✓%s no deploy script pipes an unbounded producer into grep -q\n\n' "$GRN" "$R"
  exit 0
fi

printf '  %s✗%s these invert under pipefail — a present pattern reads as absent:\n\n' "$RED" "$R"
printf '%s\n' "$hits" | while IFS= read -r line; do
  printf '      %s\n' "$line"
done
printf '\n      %scapture first, then match the variable:%s\n' "$DIM" "$R"
printf '      %s  logs=$(docker logs X 2>&1 || true)%s\n' "$DIM" "$R"
printf '      %s  if grep -q '\''pattern'\'' <<<"$logs"; then%s\n\n' "$DIM" "$R"
exit 1
