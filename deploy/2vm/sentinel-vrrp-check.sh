#!/usr/bin/env bash
# VRRP health check: may THIS node serve traffic right now?
#
# Exit 0 = yes, keep/take the VIP. Non-zero = no, hand it to the peer.
#
# Deliberately checks the data plane's own health endpoint rather than the host or
# the docker daemon. A node can be perfectly alive and completely unable to serve —
# container crash-looping, config never synced, listener not bound — and in that
# state holding the VIP is worse than being down, because traffic arrives and dies.
set -uo pipefail

# Host port 80, NOT 8080: compose.prod.yml publishes the data plane as "80:8080",
# so the container's 8080 is the host's 80. Defaulting to 8080 here would fail every
# check, keepalived would consider both nodes ineligible, and the VIP would never
# come up at all — a total outage caused by the health check rather than the WAF.
# There is no HAProxy in the 2-VM topology (that is compose.ha.yml), so the data
# plane owns host :80 directly.
DP_HEALTH="${SENTINEL_DP_HEALTH:-http://127.0.0.1:80/healthz}"
TIMEOUT="${SENTINEL_DP_TIMEOUT:-2}"

body=$(curl -fsS --max-time "$TIMEOUT" "$DP_HEALTH" 2>/dev/null) || exit 1

# "sites":0 means the data plane is up but has no configuration, so it would 502
# every request. That is not a node worth sending traffic to.
case "$body" in
  *'"sites":0'*) exit 1 ;;
esac
case "$body" in
  *'"status":"ok"'*) exit 0 ;;
esac

# Some builds report health without a status field; a parseable body with at least
# one site is good enough rather than failing closed on a cosmetic difference.
case "$body" in
  *'"sites":'*) exit 0 ;;
esac
exit 1
