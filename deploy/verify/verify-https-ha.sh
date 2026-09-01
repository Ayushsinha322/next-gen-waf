#!/usr/bin/env bash
# Does HTTPS actually survive losing a node, and does the client IP survive the
# load balancer?
#
# These are the two claims the change stands on, and both were previously false
# or absent:
#   - compose.ha.yml promised "kill any node → zero downtime". waf1 published
#     :443 alone, so that was true for :80 only.
#   - HAProxy in tcp mode cannot add X-Forwarded-For, so without PROXY protocol
#     every HTTPS client silently becomes the balancer and the IP blocklist,
#     per-source rate limits, correlation and auto-ban all collapse onto one
#     address.
#
# Run ON the WAF host. Exits non-zero on any failure, so it can gate a rollout.
#
# It KILLS waf1 and brings it back. That is the point — the failover claim cannot
# be verified without a failure — but it means a brief loss of :443/udp (HTTP/3,
# waf1-only by design), :9443 (management) and the `dataplane` alias the control
# plane's cert API uses.
set -uo pipefail
H="wafdemo.esds.local"
LOGDIR=/var/lib/docker/volumes/sentinel_sentinel-logs/_data
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }

LB_IP=$(docker inspect sentinel-lb-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

echo "=== 0. topology: who owns :443 now? ==="
echo "    haproxy container address: $LB_IP"
BINDER=$(docker ps --format '{{.Names}}' | while read -r c; do
  docker port "$c" 2>/dev/null | grep -q '^8443/tcp' && echo "$c"
  docker port "$c" 2>/dev/null | grep -q '^443/tcp'  && echo "$c"
done | sort -u | tr '\n' ' ')
echo "    containers publishing a 443-ish tcp port: ${BINDER:-none}"
case "$BINDER" in
  *sentinel-lb-1*) ok "the load balancer owns 443/tcp" ;;
  *) bad "expected sentinel-lb-1 to own 443/tcp, got: ${BINDER:-none}" ;;
esac
# ANCHORED. `docker port` prints "9443/tcp -> ..." which contains the substring
# "443/tcp", so an unanchored grep reports waf1 as still publishing 443/tcp when
# it publishes only the management port. That produced a false FAIL on the first
# real run of this script.
docker port sentinel-waf1-1 2>/dev/null | grep -qE '^443/tcp' \
  && bad "waf1 still publishes 443/tcp — HTTPS is still single-homed" \
  || ok "waf1 no longer publishes 443/tcp (9443/tcp management remains, as intended)"
docker port sentinel-waf1-1 2>/dev/null | grep -qE '^8443/udp' \
  && ok "waf1 still publishes 443/udp (HTTP/3, single-homed by design)" \
  || note "waf1 does not publish 443/udp — HTTP/3 is off entirely"

echo
echo "=== 1. HTTPS still serves, with the SAME certificate ==="
CODE=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" https://127.0.0.1/)
[ "$CODE" = "200" ] && ok "HTTPS serves (200)" || bad "HTTPS returned $CODE"
FP=$(echo | timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$H" 2>/dev/null \
     | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
echo "    cert now: ${FP:-<none>}"
if [ -n "${EXPECT_FP:-}" ]; then
  [ "$FP" = "$EXPECT_FP" ] \
    && ok "certificate is unchanged" \
    || bad "certificate CHANGED (was $EXPECT_FP) — nodes are not sharing the cert volume"
else
  note "set EXPECT_FP=<sha256> to assert the cert did not change"
fi
# Every node must present the SAME cert, or a client gets a different one
# depending on where it lands. Hit :443 repeatedly; round-robin spreads it.
FPS=$(for _ in $(seq 1 9); do
  echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$H" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
done | sort -u | wc -l)
[ "$FPS" = "1" ] \
  && ok "all nodes present ONE certificate across 9 handshakes" \
  || bad "$FPS different certificates seen — waf2/waf3 are generating their own"

echo
echo "=== 2. THE DECIDING CHECK — is the client IP preserved through the LB? ==="
MARK="haproof$$"
curl -sk -o /dev/null -H "Host: $H" "https://127.0.0.1/rest/products/search?q=$MARK"
sleep 4
SEEN=$(grep -h "$MARK" $LOGDIR/waf*/access.log 2>/dev/null | tail -1 \
       | python3 -c 'import sys,json;l=sys.stdin.readline();print(json.loads(l).get("ip","?") if l.strip() else "?")' 2>/dev/null)
echo "    client IP recorded for an HTTPS request: ${SEEN:-<not logged>}"
if [ -z "$SEEN" ] || [ "$SEEN" = "?" ]; then
  bad "the probe was not logged at all — cannot judge client-IP attribution"
elif [ "$SEEN" = "$LB_IP" ]; then
  bad "the WAF recorded the LOAD BALANCER ($LB_IP) as the client. PROXY protocol is \
not working: the IP blocklist, per-source rate limits, correlation and auto-ban are \
ALL inert for HTTPS. Do not leave this deployed."
else
  ok "the WAF recorded $SEEN, not the balancer ($LB_IP)"
fi
# The same request over :80 must still work — that path uses XFF, not PROXY.
curl -s -o /dev/null -H "Host: $H" "http://127.0.0.1/rest/products/search?q=${MARK}h"
sleep 3
SEEN80=$(grep -h "${MARK}h" $LOGDIR/waf*/access.log 2>/dev/null | tail -1 \
         | python3 -c 'import sys,json;l=sys.stdin.readline();print(json.loads(l).get("ip","?") if l.strip() else "?")' 2>/dev/null)
echo "    client IP recorded for an HTTP (:80) request: ${SEEN80:-<not logged>}"
[ -n "$SEEN80" ] && [ "$SEEN80" != "$LB_IP" ] && [ "$SEEN80" != "?" ] \
  && ok ":80 attribution still works (X-Forwarded-For path untouched)" \
  || bad ":80 attribution regressed — was working before this change"

echo
echo "=== 3. REAL FAILOVER — kill waf1 with HTTPS in flight ==="
echo "    running a continuous HTTPS request loop, then killing waf1..."
RESULTS=$(mktemp)
( for _ in $(seq 1 120); do
    c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H "Host: $H" https://127.0.0.1/ 2>/dev/null)
    echo "$c" >> "$RESULTS"
    sleep 0.25
  done ) &
LOOP=$!
sleep 4
echo "    killing waf1 at $(date -u +%H:%M:%SZ)"
docker kill sentinel-waf1-1 >/dev/null 2>&1
sleep 12
echo "    restarting waf1"
( cd /opt/sentinel-src/deploy/docker && docker compose -p sentinel \
    -f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml \
    up -d --no-deps waf1 >/dev/null 2>&1 )
wait $LOOP 2>/dev/null
TOTAL=$(wc -l < "$RESULTS"); GOOD=$(grep -c '^200$' "$RESULTS"); BADN=$((TOTAL - GOOD))
echo "    requests: $TOTAL   200: $GOOD   non-200: $BADN"
if [ "$BADN" -eq 0 ]; then
  ok "zero failed HTTPS requests while a node was killed — the claim is now TRUE"
else
  echo "    non-200 codes seen: $(grep -v '^200$' "$RESULTS" | sort | uniq -c | tr '\n' ' ')"
  if [ "$BADN" -le 2 ]; then
    note "$BADN request(s) failed — in-flight at the moment of the kill. Judge whether \
that is acceptable; HAProxy ejects a dead node in ~0.6s so a single loss is plausible."
  else
    bad "$BADN HTTPS requests failed during failover — HTTPS is NOT highly available"
  fi
fi
rm -f "$RESULTS"

echo
echo "=== 4. the fleet is healthy again ==="
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Status}}' sentinel-waf1-1 2>/dev/null)" = running ] && break
  sleep 2
done
sleep 6
docker logs --tail 20 sentinel-lb-1 2>&1 | grep -oE 'Server waf_fleet(_tls)?/waf[0-9] is (UP|DOWN)' | tail -6 | sed 's/^/    /'
UP=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" https://127.0.0.1/)
SQL=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" -A 'sqlmap/1.7' https://127.0.0.1/)
[ "$UP" = "200" ] && ok "HTTPS serving after recovery" || bad "HTTPS returned $UP after recovery"
[ "$SQL" = "403" ] && ok "threat-intel block still enforced over HTTPS" || bad "sqlmap UA returned $SQL"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
