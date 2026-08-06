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

# NOT gated on healthz's "upstreams_healthy". Measured on this deployment: it
# reported 1/1 while real requests returned 502 during startup, and later reported
# 0/1 while real requests returned 200 — wrong in BOTH directions, and in the second
# case it locked a perfectly healthy node out of the VIP. The real-request probe
# below is accurate either way, so the counter adds nothing but false verdicts.

case "$body" in
  *'"status":"ok"'*) : ;;
  *'"sites":'*)      : ;;   # older builds omit "status"; a parseable body will do
  *) exit 1 ;;
esac

# ── The authoritative test: actually serve a request ─────────────────────────
#
# Everything above is the data plane describing itself, and during startup that
# description is optimistic. Measured across three reboot tests: healthz reported
# "status":"ok" with "upstreams_healthy":1 while real requests returned 502,
# because the origin was still binding and the proxy's circuit breaker was opening
# and resetting ("all upstream servers have open circuits; forcing reset").
#
# Raising `rise` did not fix it — the node genuinely looked healthy by every
# self-reported measure. The only reliable predictor of "can this node serve" is
# to make a real request and see.
#
# The Host header matters: an unmatched Host returns 502 regardless of health, so
# the probe has to use a hostname the site actually claims. The installer writes
# the VIP here, which is always one of the site's domains in this topology.
PROBE_HOST_FILE="${SENTINEL_VRRP_PROBE_HOST_FILE:-/etc/sentinel/2vm-probe-host}"
PROBE_HOST="${SENTINEL_VRRP_PROBE_HOST:-}"
[ -z "$PROBE_HOST" ] && [ -r "$PROBE_HOST_FILE" ] && PROBE_HOST=$(cat "$PROBE_HOST_FILE" 2>/dev/null)

if [ -n "$PROBE_HOST" ] && [ "${SENTINEL_VRRP_PROBE:-1}" = "1" ]; then
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
           -H "Host: $PROBE_HOST" "http://127.0.0.1:80/" 2>/dev/null || echo 000)
  case "$code" in
    502|503|504|000)
      # The origin is unreachable through this node. Any other code — 200, 301,
      # 307, 401, even 404 — means the request completed end to end, which is all
      # this needs to establish. A 403 would mean the WAF blocked our own probe,
      # which is also proof the pipeline works.
      exit 1 ;;
  esac
fi

exit 0
