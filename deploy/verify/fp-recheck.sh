#!/usr/bin/env bash
# Did the newly-enabled protocol rules false-positive on REAL traffic?
#
# READ-ONLY. It generates no requests, so it is safe to run repeatedly and adds
# nothing to a live FPR pilot window. That matters: the battery in
# verify-protocol-rules.sh sends probes, and re-running it hourly to answer this
# one question would pollute the very sample the answer depends on.
#
# The question it answers is the one the unit tests cannot: five protocol rules
# (920180, 920430, 920540, 920270, 920271) inspect EVERY request rather than
# hunting a payload, so a mistake in them does not miss an attack — it fires on
# ordinary traffic. 920180 flagged a "clean" POST in the test suite within
# minutes of working. It was right and the fixture was wrong, but that is the
# shape of the risk.
#
# Usage:  ./fp-recheck.sh [SINCE_ISO]        default: when waf2 last started
#
# Exit: 0 clean · 1 a rule fired on real traffic · 2 sample too small to judge
set -uo pipefail
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"
SINCE="${1:-$(docker inspect -f '{{.State.StartedAt}}' sentinel-waf2-1 | cut -c1-19)Z}"
# Below this, "nothing fired" is not evidence — it is an empty sample. Reporting
# it as a pass would be a guard that cannot fail.
MIN_SAMPLE="${FP_MIN_SAMPLE:-100}"
export SINCE MIN_SAMPLE LOGDIR

python3 - <<'PY'
import json, glob, os, collections, sys

since      = os.environ["SINCE"]
min_sample = int(os.environ["MIN_SAMPLE"])
logdir     = os.environ["LOGDIR"]

TOOL = ("curl","wget","python-requests","go-http-client","vegeta","k6","sqlmap",
        "nikto","nmap","gotestwaf","postman","httpie","pilotcheck","openssl")
LOCAL = ("172.17.0.1","172.18.0.1","127.0.0.1","::1")
NEW = {"920180","920430","920540","920270","920271"}
WINDOW, MIN_UAS, MIN_REQS = 600, 5, 50


def load(pattern):
    for f in glob.glob(pattern):
        try:
            fh = open(f, errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def bucket(ts):
    try:
        return (ts[:10], (int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + int(ts[17:19])) // WINDOW)
    except (ValueError, IndexError):
        return None


def looks_human(d):
    ip, ua = d.get("ip") or "", d.get("ua") or ""
    if ip in LOCAL:
        return False
    if any(t in ua.lower() for t in TOOL):
        return False
    return "Mozilla" in ua


# Scanner addresses, judged the same way fpr-analyse.py does: many distinct
# browser UAs from ONE address inside a short window. Over a whole log a person
# whose browser updated across weeks looks identical to a scanner; only the rate
# separates them.
per_ip_bucket, per_ip_n = collections.defaultdict(lambda: collections.defaultdict(set)), collections.Counter()
denom = 0
for d in load(logdir + "/waf*/access.log"):
    ts = d.get("ts", "")
    if ts < since or not looks_human(d):
        continue
    denom += 1
    ip = d.get("ip") or ""
    b = bucket(ts)
    if ip and b is not None:
        per_ip_bucket[ip][b].add((d.get("ua") or "")[:64])
        per_ip_n[ip] += 1

scanners = {
    ip for ip, bs in per_ip_bucket.items()
    if per_ip_n[ip] >= MIN_REQS and max((len(u) for u in bs.values()), default=0) >= MIN_UAS
}
denom -= sum(per_ip_n[ip] for ip in scanners)

hits = collections.Counter()
detail = collections.defaultdict(lambda: {"paths": set(), "ips": set(), "wb": 0})
for d in load(logdir + "/waf*/waf.log"):
    if d.get("ts", "") < since or not looks_human(d):
        continue
    if (d.get("ip") or "") in scanners:
        continue
    r = d.get("rule") or ""
    if r in NEW:
        hits[r] += 1
        detail[r]["paths"].add(d.get("path"))
        detail[r]["ips"].add(d.get("ip"))
        if d.get("would_block"):
            detail[r]["wb"] += 1

print()
print("  FALSE-POSITIVE RE-CHECK — the five newly-enabled protocol rules")
print("  " + "=" * 66)
print("  window starts              %s" % since)
print("  real human requests        %d" % denom)
if scanners:
    print("  excluded as automated      %s" % ", ".join(sorted(scanners)))
print()

if hits:
    print("  \033[31mA NEW RULE FIRED ON REAL TRAFFIC\033[0m")
    for r, n in hits.most_common():
        v = detail[r]
        print("    rule %s  hits=%d  uniq_ip=%d  would_block=%d" % (r, n, len(v["ips"]), v["wb"]))
        for p in sorted(v["paths"])[:6]:
            print("        %s" % p)
    print()
    print("  920180 is the likeliest: it flags an HTTP/1.1 request with a body and")
    print("  neither Content-Length nor Transfer-Encoding. If a real client trips it,")
    print("  check whether that client is genuinely malformed before excluding it.")
    sys.exit(1)

if denom < min_sample:
    print("  \033[33mINCONCLUSIVE\033[0m — only %d real requests (need %d)." % (denom, min_sample))
    print("  'Nothing fired' over a sample this small is not evidence. Re-run after")
    print("  people have been browsing.")
    sys.exit(2)

print("  \033[32mCLEAN\033[0m — none of the five fired across %d real human requests." % denom)
sys.exit(0)
PY
