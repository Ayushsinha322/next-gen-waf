# Real-traffic false-positive baseline

**Measured 2026-08-28 on the .71 cluster, from its own NDJSON logs.**
Reproduce with:

```bash
cat /var/log/sentinel/waf*/access.log > /tmp/all-access.log
cat /var/log/sentinel/waf*/waf.log    > /tmp/all-waf.log
./fpr-analyse.py /tmp/all-access.log /tmp/all-waf.log --client-net 10.212.134.
```

## The result

| | |
|---|---|
| Requests judged real | **10,512** |
| Distinct real client IPs | 19 |
| Distinct user agents | 3 (Chrome/Linux, Chrome/Windows, Firefox/Linux) |
| Distinct paths | 109 (51 hit exactly once) |
| A rule fired | 9,237 — **87.87%** |
| The WAF **blocked** | 0 — **0.0000%** |
| The WAF **would have blocked** | 1 — **0.0095%** |

**Verdict: NOT A PASS.** The rate is far under the 1% gate, and it still does not
count. See "Why this is not the gate" below.

## What is genuinely established

1. **No CRS rule other than 920350 fired on any of it.** Across 10,512 real
   requests from 19 real browsers over 109 paths, the tuned ruleset produced
   exactly one would-block, and that one was 920350. Every other rule family —
   SQLi, XSS, LFI, RCE, PHP, Java, protocol, session-fixation — stayed silent on
   real traffic. That is a real signal about the ruleset and it is good.

2. **Rule 920350 fires on 87.87% of real requests, and it is an artefact.**
   "Host header is a numeric IP address" trips because teammates reach the box as
   `https://172.16.21.71`. Spread confirms it: 318 distinct IPs across 429 paths
   in the unscoped sample — maximally systematic, which is the definition of a
   false positive rather than an attack.

   On its own it scores 3 against a threshold of 10, so it is harmless in
   isolation. **It stops being harmless when it stacks.** Observed scores were
   3, 6, 8 and 13: the correlation engine escalates an address with recent
   matches (up to +4) and the ML layer can add up to +12, so a teammate who keeps
   browsing eventually crosses 10 on nothing but the bare-IP artefact. That
   mechanism is why the contaminated sample showed a 29.73% would-block rate.

   **Consequence: an FPR pilot on a site reached by IP address cannot produce a
   usable number.** Give the application a real hostname (or exclude 920350 for
   that site) before the window opens.

## Why this is not the gate

The analyser refused the sample, correctly, for reasons that are properties of
the traffic and not of the WAF:

- **94% of requests hit one path**, `/socket.io/` — Juice Shop's SPA long-poll.
  Only ~600 requests touched the other 108 paths, so the app surface actually
  exercised is thin.
- **Juice Shop is the wrong application.** It is a deliberately vulnerable SPA
  serving assets and a REST API. It exercises none of the shapes where real false
  positives live: file uploads, long HTML/rich-text form fields, SAML or OIDC
  redirects (which can exceed the 8192-byte URI limit), base64 blobs, XML/SOAP
  bodies, admin search boxes containing SQL-ish words.
- **Detections against Juice Shop are ambiguous by construction.** Teammates
  poking a vulnerable app generate genuine attacks, so a detection there is not
  evidence of a false positive.

## What the gate still needs

A real internal business application, in learning mode, for a full business cycle
(target two weeks, one week minimum), reached by **hostname**. Then re-run the
command above. The prerequisites are now in place:

- learning mode no longer rejects oversize bodies, long URIs, header floods or
  unlisted methods (previously a "safe" soak answered 413/414/431/405 to real
  users — fixed 2026-08-28, commit `5f452d2`)
- the learning report survives a control-plane restart and is served from
  ClickHouse
- events carry the matched payload, query string and referer, so a detection can
  be triaged without reproducing the request
- `fpr-analyse.py` refuses a sample it cannot stand behind, rather than printing
  a reassuring percentage

## The discipline this file exists to protect

A rate whose denominator you generated yourself is not a measurement. This
project has produced two such numbers already: a "0.1824% — under the 1% gate"
where 364 of 373 requests were keepalived's own health probe, and a 16.67% off
six self-generated requests. Both looked like results. Neither was.

Check what is in the denominator before believing any ratio.
