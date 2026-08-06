# Next-Gen ESDS WAF — Live Demo Runbook

**Goal:** in ~5 minutes, prove to the room that the WAF (a) lets real users through, (b) blocks the full OWASP Top 10 on contact, and (c) logs every attack in a searchable, auditable console — so they *trust* it.

**Kit:**
- `demo/waf-demo.sh` — self-verifying attack script (all 17 payloads verified → 403 on 2026-07-07).
- This runbook.

---

## 0 · The one-line story
> "Legitimate traffic flows normally. The moment an attack — SQL injection, XSS, Log4Shell, a scanner — touches the WAF, it's blocked in under a millisecond and lands in the console, fully attributed. Nothing reaches the application."

---

## 1 · Pre-flight checklist (do ~10 min before)

1. **VM reachable** — from your laptop:
   ```
   curl -k -o /dev/null -w "%{http_code}\n" -H "Host: 172.16.21.71" http://172.16.21.71/     # expect 200
   ```
2. **Reset the behavioral engine** (clears any leftover attacker flags + counters), on the VM:
   ```
   ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71 \
     'cd /opt/sentinel-src && docker compose -f deploy/docker/compose.prod.yml restart dataplane'
   ```
   Do this **3–5 min before** the demo — the threat-intel feed (29k IOCs) re-syncs within ~60s of restart.
3. **Open the console** → `https://172.16.21.71:9443`  (login: `admin@sentinel.local` / `Admin@123#`).
   - Accept the cert warning (private CA — this is itself a talking point, see §5).
   - Open these in tabs/windows so you can flip fast:
     - **Overview** — watch the *Threats Blocked* / *Blocked IPs* counters.
     - **Logs** (LIVE) — the real-time block stream.
     - **Threat Search** — searchable attack history.
     - **Threat Intel → Recent Intel Blocks** — where the scanner (sqlmap/Nikto) hits show up.
4. **Dry run** the script once now (it's your safety check — must print `17 / 17 BLOCKED`):
   ```
   ./demo/waf-demo.sh --fast
   ```
   If anything shows `NOT BLOCKED`, ping me before the demo. Then **wait ~90s** (lets your laptop's IP flag age out) before the live run, or run the live demo from a different device.

---

## 2 · Dashboard setup (what to have on screen)

| Panel | Route | What it shows during the demo |
|---|---|---|
| Overview | `/overview` | *Threats Blocked* counter climbing live; sub-ms p99 latency card |
| Logs | `/logs` | Live block events streaming in as you attack |
| Threat Search | `/events` | Filter/inspect each blocked attack (IP, payload, rule, decision) |
| Threat Intel | `/threat-intel` | 29k live IOCs; *Recent Intel Blocks* shows the sqlmap/Nikto hits |

---

## 3 · The demo flow (narration + actions)

**Step 1 — Legitimate user works (10s).**
Open the protected app through the WAF (`http://172.16.21.71/` or the Juice Shop link) — it loads normally.
> "This is a real app behind the WAF. Normal users are completely unaffected."

**Step 2 — Launch the attacks (2–3 min).** In your terminal:
```
./demo/waf-demo.sh            # paced: press Enter before each attack so you can narrate
```
As each attack fires and returns **🛡 BLOCKED (403)**, do the split-screen move — point at the terminal, then the dashboard:
- SQL injection → "classic data-theft attempt — blocked."
- XSS → "session-hijacking script — blocked."
- **Log4Shell (CVE-2021-44228)** → "the vulnerability that broke the internet in 2021 — blocked by default."
- Command injection / RCE → "trying to run commands on the server — blocked."
- **sqlmap / Nikto recon** → flip to **Threat Intel** → "we don't even evaluate rules for these — the source is a known-bad tool in our threat feed, blocked on sight."

**Step 3 — Show it's all logged (1 min).** Flip to **Threat Search** (`/events`):
> "Every attack is captured — source IP, the exact payload, the rule that caught it, the block decision. Searchable, exportable, audit-ready."
Point at **Overview**: *Threats Blocked* has jumped.

**Step 4 — Close on trust (30s).** See §5 talking points.

---

## 4 · A crisp per-attack story (optional polish)
The WAF has a **behavioral correlation engine**: after a burst of blocks from one IP it fingerprints the attacker and blocks *everything* from it (shown as `ANOMALY` in the logs). This is a feature — but it means if you fire all 17 back-to-back, later rows say `ANOMALY` instead of `SQL Injection` / `XSS`.
- **Want distinct rule labels per attack?** Use **paced mode** (default) and narrate ~15s each — the headline attacks show their real rule before escalation kicks in.
- **Or turn it into a highlight:** "Watch — after a few hits, the WAF stops bothering with per-rule checks and just shields us from this now-known attacker. That's behavioral defense on top of the rules."

---

## 5 · Trust talking points (why it's real, not a toy)
- **Full OWASP Top 10 coverage** — 2,541 OWASP Core Rule Set rules, verified blocking SQLi, XSS, traversal, injection, SSRF, XXE, Log4Shell.
- **Live threat intelligence** — 29,674 IOCs auto-synced hourly from Tor / abuse.ch Feodo / URLhaus; known-bad sources blocked *before* rules even run.
- **ML anomaly engine** — behavioral scoring + repeat-attacker correlation, not just static signatures.
- **Sub-millisecond latency** — p99 < 1ms; the Rust data plane adds effectively zero user-facing delay.
- **Modern stack** — HTTP/3 (QUIC), per-site TLS, private-CA management console.
- **Full observability** — every decision logged, searchable, and auditable in the console (what you're looking at).

---

## 6 · Gotchas & recovery
| Symptom | Cause | Fix |
|---|---|---|
| Clean traffic returns **403** during the demo | You attacked from this IP < 60s ago → correlation flag | Wait ~60–90s, or `restart dataplane` to reset, or show clean traffic **first** |
| Attack shows **HTTP 000** | Bad Host header / network | Ensure `-H "Host: 172.16.21.71"` (script does this); check VPN/reachability |
| Logs / Threat Search look **empty** | Time window or nothing sent yet | Fire the script; Threat Search defaults to a recent window |
| Cert warning on `:9443` / `:443` | Private CA (by design) | Accept it, or import the root CA — and use it as the "private-CA, VPN-only" talking point |
| Attack row says **ANOMALY** not the rule | Correlation engine escalated | Expected — see §4; pace attacks for distinct labels |

---

## 7 · Backup plan
- The dry run already seeded attack history — even if the live network hiccups, **Threat Search still has data to show**.
- If the VM is unreachable at demo time, you can run `./demo/waf-demo.sh` against any reachable instance by setting `TARGET=` / `HOST_HDR=`.

---

## 8 · Quick reference
```
# Attack (paced, narrate):     ./demo/waf-demo.sh
# Attack (fast, no pauses):    ./demo/waf-demo.sh --fast
# Preview only (no traffic):   ./demo/waf-demo.sh --list
# Over HTTPS:                  TARGET=https://172.16.21.71 ./demo/waf-demo.sh
# Console:  https://172.16.21.71:9443   admin@sentinel.local / Admin@123#
# Reset engine (VM):  docker compose -f deploy/docker/compose.prod.yml restart dataplane
```
