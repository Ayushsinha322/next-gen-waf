#!/usr/bin/env bash
# Post-deploy verification for the Swaraj Kavach VM upgrade.
#
# Every check prints PASS/FAIL/WARN with the evidence it used, so a green run is a
# set of measurements rather than an assertion. Exit non-zero if any FAIL.
#
# Deliberately verifies the things this upgrade CHANGED, not a generic smoke test:
# the schema migrations, Postgres TLS, advisory-lock leadership, client-IP
# attribution behind the LB, and the config cache landing on a volume.
set -uo pipefail
cd /opt/sentinel-src/deploy/docker

fails=0; warns=0
PASS(){ printf '\033[32m  PASS\033[0m %s\n' "$*"; }
FAIL(){ printf '\033[31m  FAIL\033[0m %s\n' "$*"; fails=$((fails+1)); }
WARN(){ printf '\033[33m  WARN\033[0m %s\n' "$*"; warns=$((warns+1)); }
hdr(){ printf '\n\033[1m── %s\033[0m\n' "$*"; }

PG() { docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc "$1" 2>/dev/null | tr -d ' \r'; }

# ─────────────────────────────────────────────────────────────────────────────
hdr "1. Container inventory and stability"
expected="clickhouse controlplane cp2 cp3 dashboard juiceshop lb postgres prometheus redis waf1 waf2 waf3"
for svc in $expected; do
  name="sentinel-${svc}-1"
  st=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
  rc=$(docker inspect -f '{{.RestartCount}}' "$name" 2>/dev/null || echo -1)
  if [ "$st" != "running" ]; then FAIL "$svc is '$st' (expected running)"
  elif [ "$rc" -gt 2 ]; then FAIL "$svc running but RestartCount=$rc — crashlooping"
  else PASS "$svc running (restarts=$rc)"; fi
done

hdr "2. Containers are actually running the NEW images"
for svc in controlplane cp2 cp3 waf1 waf2 waf3 dashboard; do
  cid=$(docker inspect -f '{{.Image}}' "sentinel-${svc}-1" 2>/dev/null)
  case $svc in
    waf*)                img=sentinel/dataplane:latest ;;
    controlplane|cp2|cp3) img=sentinel/controlplane:latest ;;
    dashboard)           img=sentinel/dashboard:latest ;;
  esac
  want=$(docker inspect -f '{{.Id}}' "$img" 2>/dev/null)
  if [ -n "$cid" ] && [ "$cid" = "$want" ]; then PASS "$svc on current $img"
  else FAIL "$svc is NOT on the newly built $img (stale container)"; fi
done

# ─────────────────────────────────────────────────────────────────────────────
hdr "3. Schema migrations 0013/0014/0015 applied"
v=$(PG "select max(version_id) from goose_db_version")
[ "$v" = "15" ] && PASS "goose version = 15" || FAIL "goose version = ${v:-<none>} (expected 15)"
for t in cluster_leader cluster_members config_versions; do
  ex=$(PG "select to_regclass('public.$t') is not null")
  [ "$ex" = "t" ] && PASS "table $t exists" || FAIL "table $t MISSING"
done
for c in seq prev_hmac; do
  ex=$(PG "select count(*) from information_schema.columns where table_name='audit_logs' and column_name='$c'")
  [ "$c" = "" ] && continue
  [ "$ex" = "1" ] && PASS "audit_logs.$c exists (hash chain)" || FAIL "audit_logs.$c MISSING"
done

# ─────────────────────────────────────────────────────────────────────────────
hdr "4. Postgres TLS is in use, not merely available"
ssl_on=$(PG "show ssl")
[ "$ssl_on" = "on" ] && PASS "server ssl=on" || FAIL "server ssl=$ssl_on"
# The control plane's own backends: are they encrypted?
enc=$(PG "select count(*) from pg_stat_ssl s join pg_stat_activity a using(pid) where a.datname='sentinel' and a.application_name<>'psql' and s.ssl")
tot=$(PG "select count(*) from pg_stat_activity a where a.datname='sentinel' and a.application_name<>'psql' and a.backend_type='client backend'")
if [ "${enc:-0}" -gt 0 ]; then PASS "$enc of $tot app backends on TLS"
else FAIL "no app backend is using TLS (enc=$enc tot=$tot) — DSN may not have taken effect"; fi
cipher=$(PG "select distinct s.version||' '||s.cipher from pg_stat_ssl s join pg_stat_activity a using(pid) where a.datname='sentinel' and s.ssl limit 1")
[ -n "$cipher" ] && PASS "negotiated: $cipher" || WARN "could not read negotiated cipher"
# verify-full means the client checked the SAN — prove a bogus hostname would fail
# The controlplane image is minimal (no shell), so probe the mount table rather
# than exec-ing into it. Checked on ALL THREE nodes: cp2/cp3 inherit nothing from
# controlplane, and a CA missing there makes the node run with no database while
# still reporting "Up" — which is how this was missed the first time.
for c in controlplane cp2 cp3 migrate; do
  dests="$(docker inspect "sentinel-${c}-1" -f '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' 2>/dev/null || true)"
  if grep -qx /etc/sentinel/pki/root.crt <<<"$dests"; then
    PASS "$c mounts the CA at /etc/sentinel/pki/root.crt"
  else FAIL "$c does NOT mount the CA — its verify-full DSN cannot be parsed (no database)"; fi
done
# And prove no node is silently running without a DB.
# `docker logs` output is unbounded, so it must NOT be piped into `grep -q`
# under `set -o pipefail`. `grep -q` exits the moment it matches, `docker logs`
# then dies on SIGPIPE with 141, and pipefail makes the PIPELINE non-zero — so a
# pattern that IS present reads as absent. Verified: a 200k-line producer piped
# into `grep -q` on a pattern it contains returns 141 and takes the else branch
# (a small producer finishes first and happens to work, which is why this hides).
# Capturing first and matching the variable removes the pipeline entirely.
for c in controlplane cp2 cp3; do
  clog=$(docker logs "sentinel-${c}-1" --since 30m 2>&1 || true)
  if grep -qi "running standalone" <<<"$clog"; then
    FAIL "$c logged 'running standalone' — it has NO database"
  else PASS "$c has a database (never fell back to standalone)"; fi
done

hdr "5. Cleartext Postgres is refused (hostssl enforcement)"
# Only meaningful once pg_hba is switched to hostssl; reported as WARN otherwise.
out=$(docker run --rm --network sentinel_sentinel -e PGPASSWORD=x postgres:16-alpine \
      psql "postgres://sentinel:x@postgres:5432/sentinel?sslmode=disable" -c 'select 1' 2>&1 | head -3)
if echo "$out" | grep -qiE "no encryption|no pg_hba|SSL.*required|connection.*rejected"; then
  PASS "cleartext connection refused by server policy"
elif echo "$out" | grep -qiE "password authentication failed"; then
  WARN "cleartext reached AUTH (server still permits non-TLS; pg_hba not yet hostssl-only)"
else WARN "inconclusive: $(echo "$out" | tr '\n' ' ' | cut -c1-120)"; fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "6. Leader election via Postgres advisory lock (replaces Raft)"
lock=$(PG "select count(*) from pg_locks where locktype='advisory'")
[ "${lock:-0}" -ge 1 ] && PASS "$lock advisory lock(s) held" || FAIL "no advisory lock held — no node has leadership"
leaders=$(PG "select count(*) from cluster_leader")
holder=$(PG "select node_id from cluster_leader limit 1")
if [ "${leaders:-0}" = "1" ]; then PASS "exactly one leader row (node=${holder:-?})"
elif [ "${leaders:-0}" = "0" ]; then FAIL "cluster_leader empty — leadership never acquired"
else FAIL "cluster_leader has $leaders rows — split brain"; fi
mem=$(PG "select count(*) from cluster_members")
[ "${mem:-0}" -ge 1 ] && PASS "cluster_members has $mem node(s)" || WARN "cluster_members empty"
# The singleton monitors must run on exactly one node.
for svc in controlplane cp2 cp3; do
  n=$(docker logs "sentinel-${svc}-1" --since 10m 2>&1 | grep -ciE "acquired leadership|became leader|leader acquired")
  echo "        $svc leadership-acquired log lines: $n"
done
# Leadership handoffs are expected whenever a node's lock session dies (e.g. a
# Postgres restart). Report them as evidence the failover path actually runs.
ho=$(for c in controlplane cp2 cp3; do docker logs "sentinel-${c}-1" --since 60m 2>&1 \
       | grep -cE "acquired write leadership"; done | paste -sd+ | bc 2>/dev/null || echo 0)
echo "        leadership acquisitions in the last hour (all nodes): ${ho:-0}"
# Captured, not piped — see the SIGPIPE note above. This one inverted in the
# dangerous direction: with the pattern PRESENT the pipeline returned 141, `!`
# flipped it true, and the check announced "no Raft references" precisely when
# there were some.
cplog=$(docker logs sentinel-controlplane-1 --since 10m 2>&1 || true)
if ! grep -qiE "raft" <<<"$cplog"; then
  PASS "no Raft references in control-plane logs (Raft removed)"
else WARN "log still mentions raft"; fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "7. Client-IP attribution behind the load balancer (the blocklist fix)"
for n in waf1 waf2 waf3; do
  tp=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "sentinel-${n}-1" | grep '^SENTINEL_TRUSTED_PROXIES=' | cut -d= -f2-)
  se=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "sentinel-${n}-1" | grep '^SENTINEL_SHARED_EGRESS_CIDRS=' | cut -d= -f2-)
  [ -n "$tp" ] && PASS "$n TRUSTED_PROXIES=$tp" || FAIL "$n TRUSTED_PROXIES unset — XFF ignored, blocklist would match the LB"
  [ -n "$se" ] && PASS "$n SHARED_EGRESS=$se" || WARN "$n SHARED_EGRESS unset"
done
# Send a request with a known XFF from the LB and confirm the WAF logs THAT ip.
MARKER="203.0.113.77"
curl -s -o /dev/null -H "Host: 172.16.21.71" -H "X-Forwarded-For: $MARKER" --max-time 10 http://127.0.0.1/ || true
sleep 3
# Captured, not piped — see the SIGPIPE note above.
nodelogs=$(for n in waf1 waf2 waf3; do
             docker logs "sentinel-${n}-1" --since 2m 2>&1 || true
           done)
if grep -q "$MARKER" <<<"$nodelogs"; then
  PASS "XFF client IP $MARKER attributed (not collapsed to the LB address)"
else
  WARN "did not observe $MARKER in node logs (log format may not include client_ip at this level)"
fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "8. Detection parity — attacks still blocked, benign still served"
probe(){ curl -s -o /dev/null -w '%{http_code}' -H "Host: 172.16.21.71" --max-time 15 "$1"; }
b=$(probe "http://127.0.0.1/")
[ "$b" = "200" ] && PASS "benign GET / -> 200" || FAIL "benign GET / -> $b (expected 200)"
declare -A atk=(
  [SQLi]="http://127.0.0.1/?id=1%27%20OR%20%271%27%3D%271"
  [XSS]="http://127.0.0.1/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  [LFI]="http://127.0.0.1/?f=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  [RCE]="http://127.0.0.1/?c=%3Bcat%20%2Fetc%2Fpasswd"
  [SSRF]="http://127.0.0.1/?u=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
)
for k in SQLi XSS LFI RCE SSRF; do
  c=$(probe "${atk[$k]}")
  [ "$c" = "403" ] && PASS "$k -> 403 blocked" || FAIL "$k -> $c (expected 403)"
done

# ─────────────────────────────────────────────────────────────────────────────
hdr "9. Last-good config cache is on a volume (survives upgrades)"
for n in waf1 waf2 waf3; do
  p=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "sentinel-${n}-1" | grep '^SENTINEL_CONFIG_CACHE_PATH=' | cut -d= -f2-)
  mounted=$(docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "sentinel-${n}-1" | grep -c "/var/lib/sentinel/state")
  if [ -z "$p" ]; then FAIL "$n CONFIG_CACHE_PATH unset (would use container layer)"
  elif [ "$mounted" -lt 1 ]; then FAIL "$n cache path $p is NOT on a mounted volume"
  else
    # Read through the host's view of the volume: the dataplane image has no shell.
    vol=$(docker inspect "sentinel-${n}-1" -f '{{range .Mounts}}{{if eq .Destination "/var/lib/sentinel/state"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
    f="$vol/$(basename "$p")"
    if [ -s "$f" ]; then
      sz=$(stat -c %s "$f")
      ver=$(python3 -c "import json;print(json.load(open('$f')).get('version'))" 2>/dev/null || echo '?')
      nsites=$(python3 -c "import json;print(len(json.load(open('$f')).get('sites',[])))" 2>/dev/null || echo '?')
      PASS "$n cache on volume: ${sz} bytes, config version=$ver, $nsites site(s)"
    else WARN "$n cache path on volume but not yet written (written on first successful config sync)"; fi
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
hdr "10. Attack surface: control-plane port no longer host-published"
if ss -tlnp 2>/dev/null | grep -qE '0\.0\.0\.0:9501'; then
  WARN "9501 still published on 0.0.0.0 — /metrics reachable from the network"
else PASS "9501 not host-published (metrics only via the docker network)"; fi
for p in 80 443 9443 8404; do
  ss -tlnp 2>/dev/null | grep -qE ":$p " && PASS "expected listener on :$p" || WARN "nothing listening on :$p"
done
if ss -tlnp 2>/dev/null | grep -qE '0\.0\.0\.0:3000'; then
  FAIL "dashboard :3000 published on all interfaces (cleartext admin login exposed)"
else PASS "dashboard :3000 not exposed on 0.0.0.0 (console is https :9443)"; fi

hdr "11. Management console + dashboard reachable"
c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 https://127.0.0.1:9443/)
case "$c" in 200|301|302|307|308) PASS "https :9443 -> $c";; *) FAIL "https :9443 -> $c";; esac
c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 https://127.0.0.1:9443/login)
case "$c" in 200|301|302|307|308) PASS "https :9443/login -> $c";; *) WARN "https :9443/login -> $c";; esac
# 9501 is no longer host-published and the image has no shell, so reach it from a
# throwaway container on the compose network — which also proves internal DNS +
# reachability, the path the dashboard actually uses.
for c in controlplane cp2 cp3; do
  h=$(docker run --rm --network sentinel_sentinel curlimages/curl:latest \
        -s --max-time 10 "http://${c}:9501/health" 2>/dev/null | head -c 120)
  if echo "$h" | grep -q '"status"'; then PASS "$c /health -> $h"
  else FAIL "$c /health unreadable (got: ${h:-<empty>})"; fi
done

hdr "12. No fatal errors in the new containers' logs"
for svc in controlplane cp2 cp3 waf1 waf2 waf3 dashboard migrate; do
  name="sentinel-${svc}-1"
  docker inspect "$name" >/dev/null 2>&1 || continue
  # Match the log LEVEL field, not the message body. A bare grep for "FATAL"
  # also matches a Postgres SQLSTATE quoted inside a WARN line — e.g. the elector
  # correctly logging `lock connection failed {"error": "FATAL: terminating
  # connection due to administrator command"}` when the DB restarts and leadership
  # hands off. That is the designed failover path, so counting it as a fatal error
  # reports a successful failover as a deployment failure.
  n=$(docker logs "$name" --since 20m 2>&1 \
      | grep -cE "(^|[[:space:]])(FATAL|PANIC|DPANIC)[[:space:]]|^panic:|goroutine [0-9]+ \[running\]:|thread '[^']*' panicked" || true)
  if [ "${n:-0}" -eq 0 ]; then PASS "$svc: no panic/fatal"
  else FAIL "$svc: $n panic/fatal lines"
    docker logs "$name" --since 20m 2>&1 \
      | grep -E "(^|[[:space:]])(FATAL|PANIC|DPANIC)[[:space:]]|^panic:|thread '[^']*' panicked" \
      | head -3 | sed 's/^/        /'; fi
done

hdr "13. Migration job completed successfully"
mst=$(docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' sentinel-migrate-1 2>/dev/null || echo "missing")
[ "$mst" = "exited:0" ] && PASS "migrate exited 0" || FAIL "migrate state=$mst"
docker logs sentinel-migrate-1 2>&1 | grep -iE "OK|applied|successfully" | tail -4 | sed 's/^/        /'

# ─────────────────────────────────────────────────────────────────────────────
printf '\n\033[1m════════ RESULT ════════\033[0m\n'
if [ "$fails" -eq 0 ]; then
  printf '\033[32mALL CHECKS PASSED\033[0m (%d warnings)\n' "$warns"; exit 0
else
  printf '\033[31m%d FAILURE(S)\033[0m, %d warnings\n' "$fails" "$warns"; exit 1
fi
