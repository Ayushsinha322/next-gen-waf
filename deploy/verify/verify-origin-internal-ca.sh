#!/usr/bin/env bash
# Can the WAF proxy to an origin whose certificate is signed by an INTERNAL CA?
#
# Run ON the WAF host. Creates a temporary origin, CA and site, and removes all
# three afterwards.
#
# THE DEFECT: the origin connector pinned `.with_webpki_roots()` with no
# override, so an origin whose certificate chains to a corporate/internal CA —
# the ordinary enterprise case for the app a WAF sits in front of — failed
# verification and the site returned 502 for ever. Nothing in the UI said so.
#
# THE TEST is the operator's actual situation, end to end: a real nginx origin
# holding a certificate signed by a CA this box invents, fronted by a real site.
#   502 with no CA configured   = the defect.
#   200 once SENTINEL_UPSTREAM_CA_FILE names that CA = the fix.
# Both halves are measured here, so the "after" is not credited without the
# "before" reproducing the failure first.
set -uo pipefail
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }
D=/opt/sentinel-src/deploy/docker
C="docker compose -p sentinel -f $D/compose.prod.yml -f $D/compose.cluster.yml -f $D/compose.ha.yml"
PSQL="docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -At -c"
ORIGIN=internal-origin.local
SITE=ca-probe
DOMAIN=ca-probe.local
WORK=/root/origin-ca-test
CADIR=$D/origin-ca

probe() { curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $DOMAIN" "https://127.0.0.1/" 2>/dev/null; }
# Majority across a few tries: the LB spreads requests over three nodes and a
# single sample could land on whichever node is mid-restart.
probe_majority() {
  local a b c
  a=$(probe); sleep 1; b=$(probe); sleep 1; c=$(probe)
  if [ "$a" = "$b" ] || [ "$a" = "$c" ]; then echo "$a"; elif [ "$b" = "$c" ]; then echo "$b"; else echo "$a/$b/$c"; fi
}

cleanup() {
  $PSQL "delete from sites where name='$SITE'" >/dev/null 2>&1
  docker rm -f ca-test-origin >/dev/null 2>&1
  rm -f "$CADIR/origin-ca.pem"
  if [ -f "$D/.env.ca-backup" ]; then mv "$D/.env.ca-backup" "$D/.env"; fi
  $C up -d --no-deps --force-recreate waf1 waf2 waf3 controlplane >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== 0. the running image supports an origin CA at all ==="
c=$(docker create "$(docker inspect sentinel-waf1-1 --format '{{.Config.Image}}')" 2>/dev/null)
docker cp "$c:/usr/local/bin/sentinel" /tmp/ca-probe-bin >/dev/null 2>&1; docker rm "$c" >/dev/null 2>&1
N=$(grep -a -c 'SENTINEL_UPSTREAM_CA_FILE' /tmp/ca-probe-bin || true)
rm -f /tmp/ca-probe-bin
if [ "${N:-0}" -gt 0 ]; then ok "the deployed binary knows SENTINEL_UPSTREAM_CA_FILE"
else bad "deployed binary has no SENTINEL_UPSTREAM_CA_FILE — image predates this change"; echo "=== RESULT: $pass passed, $fail failed ==="; exit 1; fi

echo
echo "=== 1. stand up an origin holding an INTERNAL-CA certificate ==="
rm -rf "$WORK"; mkdir -p "$WORK"
docker run --rm -v "$WORK:/w" alpine:3.20 sh -c '
  apk add --no-cache openssl >/dev/null 2>&1
  cd /w
  openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 2 -nodes \
    -subj "/CN=sentinel-internal-test-CA" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -keyout srv.key -out srv.csr -nodes \
    -subj "/CN=internal-origin.local" >/dev/null 2>&1
  printf "subjectAltName=DNS:internal-origin.local\n" > ext.cnf
  openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out srv.crt -days 2 -extfile ext.cnf >/dev/null 2>&1
  chmod 644 srv.key ca.crt srv.crt
' >/dev/null 2>&1
[ -s "$WORK/ca.crt" ] && [ -s "$WORK/srv.crt" ] && ok "generated a private CA and an origin certificate it signed" \
  || { bad "certificate generation failed"; echo "=== RESULT: $pass passed, $fail failed ==="; exit 1; }
cat > "$WORK/nginx.conf" <<'NG'
events {}
http {
  server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/priv/srv.crt;
    ssl_certificate_key /etc/ssl/priv/srv.key;
    location / { return 200 "internal origin ok\n"; }
  }
}
NG
NET=$(docker inspect sentinel-waf1-1 --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
docker rm -f ca-test-origin >/dev/null 2>&1
docker run -d --name ca-test-origin --network "$NET" --network-alias "$ORIGIN" \
  -v "$WORK:/etc/ssl/priv:ro" -v "$WORK/nginx.conf:/etc/nginx/nginx.conf:ro" \
  nginx:alpine >/dev/null 2>&1
sleep 4
docker ps --filter name=ca-test-origin --format '{{.Status}}' | head -1 | sed 's/^/    origin: /'
IN=$(docker exec sentinel-waf1-1 sh -c "wget -qO- --no-check-certificate https://$ORIGIN/ 2>/dev/null || true" 2>/dev/null)
[ -n "$IN" ] && ok "the origin is reachable from the WAF (TLS serving, verification aside)" \
  || note "could not confirm reachability from inside the WAF container (no wget?) — continuing"

echo
echo "=== 2. front it with a real site ==="
$PSQL "delete from sites where name='$SITE'" >/dev/null 2>&1
$PSQL "insert into sites (id, tenant_id, name, domains, upstream, waf_policy, status)
       select gen_random_uuid(), tenant_id, '$SITE', ARRAY['$DOMAIN'],
              jsonb_build_object('lb','round_robin','load_balancer','round_robin','timeout_secs',30,
                'servers', jsonb_build_array(jsonb_build_object('host','$ORIGIN','port',443,'weight',1,'tls',true))),
              waf_policy, 'active'
       from sites where name='Juice Shop'" >/dev/null 2>&1
$PSQL "select name||' -> '||(upstream->'servers'->0->>'host')||':'||(upstream->'servers'->0->>'port')||' tls='||(upstream->'servers'->0->>'tls') from sites where name='$SITE'" | sed 's/^/    /'
cp "$D/.env" "$D/.env.ca-backup"
$C up -d --no-deps --force-recreate controlplane >/dev/null 2>&1
sleep 20

echo
echo "=== 3. BEFORE — no origin CA configured ==="
B=$(probe_majority)
echo "    HTTP status: $B"
if [ "$B" = "502" ]; then
  ok "the internal-CA origin FAILS verification and 502s — the defect, reproduced"
else
  bad "expected 502 with no CA configured, got $B — the 'before' did not reproduce, so the 'after' proves nothing"
fi

echo
echo "=== 4. AFTER — point SENTINEL_UPSTREAM_CA_FILE at that CA ==="
cp "$WORK/ca.crt" "$CADIR/origin-ca.pem"
sed -i '/^SENTINEL_UPSTREAM_CA_FILE=/d' "$D/.env"
echo 'SENTINEL_UPSTREAM_CA_FILE=/etc/sentinel/origin-ca/origin-ca.pem' >> "$D/.env"
$C up -d --no-deps --force-recreate waf1 waf2 waf3 >/dev/null 2>&1
for _ in $(seq 1 40); do [ "$(docker inspect -f '{{.State.Status}}' sentinel-waf3-1 2>/dev/null)" = running ] && break; sleep 2; done
sleep 12
A=$(probe_majority)
echo "    HTTP status: $A"
if [ "$A" = "200" ]; then
  ok "the SAME origin now verifies and is proxied — 502 -> 200 with only the CA added"
else
  bad "expected 200 after trusting the CA, got $A"
  docker logs --since 3m sentinel-waf1-1 2>&1 | grep -i "upstream TLS" | tail -3 | sed 's/^/      /'
fi
docker logs --since 3m sentinel-waf1-1 2>&1 | grep -i "upstream TLS: trusting a private CA" | tail -1 \
  | python3 -c "import sys,json; l=sys.stdin.readline().strip(); print('    log:', json.loads(l)['fields']['message'] if l else '(none)')" 2>/dev/null

echo
echo "=== 5. public-CA origins are NOT broken by adding a private one ==="
# The additive contract: Juice Shop keeps working, and the public root count is
# still in the store (a replacing implementation would drop ~150 anchors).
J=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: wafdemo.esds.local' https://127.0.0.1/ 2>/dev/null)
echo "    Juice Shop: $J"
[ "$J" = "200" ] && ok "the pre-existing site is unaffected by the new trust anchor" \
  || bad "adding a private CA disturbed an existing site (got $J)"

echo
echo "=== 6. cleanup ==="
cleanup
trap - EXIT
sleep 10
echo "    sites: $($PSQL "select string_agg(name,',') from sites")"
echo "    juice shop after restore: $(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: wafdemo.esds.local' https://127.0.0.1/)"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
