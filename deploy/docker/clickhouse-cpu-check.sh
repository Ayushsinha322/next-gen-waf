#!/usr/bin/env bash
# =============================================================================
#  Can this host's CPU run a ClickHouse image?
#
#      clickhouse-cpu-check.sh clickhouse/clickhouse-server:26.3.35.3-alpine
#
#  Exit 0: it runs. Exit 3: this CPU cannot run it (SIGILL). Exit 4: the check
#  could not be made (Docker refused, the image cannot be pulled, …) — the
#  reason is printed and is NOT a CPU problem. Pulls the image if it is not
#  present, so a later `compose up` does not have to.
#
#  WHY: ClickHouse's official builds raise their CPU baseline over time. 26.8
#  needs x86-64-v2 (SSE4.2, SSSE3, POPCNT) and dies at once with SIGILL — exit
#  132 — on a virtual machine whose CPU model hides them; .71's "Common KVM
#  processor" exposes none. Under compose that is an endless restart loop
#  whose only visible symptom is `/entrypoint.sh: cd: null directory`, and an
#  installer then times out on a generic "ClickHouse" health check. The
#  installers run this before starting anything, upgrade.sh has the same probe
#  (and more) in its Step 4, and the k8s manifests run it as an initContainer.
# =============================================================================
set -uo pipefail

img="${1:-}"
[[ -n "$img" ]] || { echo "usage: $0 <clickhouse image>" >&2; exit 2; }

out=$(docker run --rm --network none --entrypoint clickhouse "$img" local -q "SELECT 1" 2>&1)
rc=$?
if [[ $rc -eq 0 ]]; then
  exit 0
elif [[ $rc -eq 132 ]]; then
  echo "this host's CPU cannot run $img (SIGILL): on a virtual machine its CPU model hides SSE4.2/SSSE3/POPCNT — ask for a host-passthrough or newer CPU model"
  exit 3
fi
# Docker's LAST line is "See 'docker run --help'."; the first line naming an
# error is the one that says what went wrong.
why=$(grep -m1 -i 'error' <<<"$out" || tail -1 <<<"$out")
echo "could not run $img to check it (exit $rc): $why"
exit 4
