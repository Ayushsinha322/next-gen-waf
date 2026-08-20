# Fixes to be made

**Register of known defects and gaps in Next-Gen ESDSWAF.** Every entry states how
it was found and what evidence supports it, so nothing here rests on an opinion.

**Last verified:** 2026-08-20, then re-verified against the running WAF on
`172.16.21.101` after deploying revision `0a60ee4`, against v1.0.2 running on `172.16.21.101`
(registry-mode install, 20 h uptime, 8/8 containers, zero restarts).

**Rule for this file:** an item leaves it when the fix is *verified*, not when the
code is written. Several entries below exist because something was written, looked
correct, and never actually ran.

---

## P0 — Contradicts a claim we make

### 0. Twelve of the 25 shipped CRS files can never reach the data plane

> **FIXED 2026-08-20**, verified on the running WAF at `172.16.21.101`
> (`controlplane:1.0.4-test`). Six RESPONSE-* families are now selectable per
> site; the other six files stay unwired **on purpose** and the reasons are now
> recorded in code (`crsUnwiredFiles`) instead of nowhere.
>
> Measured before and after on the same site, same policy, nothing else changed —
> an origin that leaks `You have an error in your SQL syntax`:
>
> | | rules loaded | leak page | clean page |
> |---|---|---|---|
> | before (`1.0.3-test`) | 120 | **HTTP 200, leak reached the client** | 200 |
> | after (`1.0.4-test`)  | 181 | **HTTP 403, leak withheld** | 200 |
>
> `+61` is exactly `leak_sql` (26) + `web_shells` (35). The data plane logged
> `response-body rule matched — blocking`. Before the fix the API had **accepted
> and echoed back** `["sqli","xss","leak_sql","web_shells"]` while shipping the
> data plane only the two request files — stored, echoed, dropped.
>
> **No behaviour change for existing sites**, which is why response families are
> opt-in rather than part of "all categories": the site with no explicit
> selection still loads 340 rules, still answers 302/403, and still does not
> buffer responses. `verify.sh`: 21 passed, 0 failed, 0 warnings.
>
> Guards added so this class cannot recur silently:
> `control-plane/cmd/controllerd/crs_wiring_test.go` fails if any shipped `.conf`
> is neither wired nor explicitly excused, or if a category key exists in the map
> but not the load order (the accepted-then-dropped shape). Both were
> negative-tested by breaking them.
> `crates/sentinel-rules/tests/response_body_families.rs` pins that each wired
> family imports rules, detects a real disclosure **and blocks**, does not fire on
> ordinary pages, and — the subtle one — that detection depends on the proxy
> seeding `DETECTION_PARANOIA_LEVEL`. Every RESPONSE-* file opens with a
> `@lt 1 … skipAfter` gate, so deleting that one proxy line would silently switch
> response inspection off with every other test still green.


**Found while verifying the CRS work on the running WAF, and it is larger than the
importer bugs it was found behind.**

The control plane offers the data plane a curated list of **13 `REQUEST-*` files**
(`handlers.go`, the rule-file map). The image ships **25**. The other 12 — **222
rules** — are unreachable regardless of site configuration, because nothing can
select them:

| File | Rules |
|---|---|
| `RESPONSE-955-WEB-SHELLS.conf` | 35 |
| `REQUEST-901-INITIALIZATION.conf` | 29 |
| `REQUEST-949-BLOCKING-EVALUATION.conf` | 28 |
| `RESPONSE-959-BLOCKING-EVALUATION.conf` | 28 |
| `RESPONSE-951-DATA-LEAKAGES-SQL.conf` | 26 |
| `RESPONSE-980-CORRELATION.conf` | 21 |
| `RESPONSE-953-DATA-LEAKAGES-PHP.conf` | 13 |
| `RESPONSE-954-DATA-LEAKAGES-IIS.conf` | 13 |
| `RESPONSE-950-DATA-LEAKAGES.conf` | 12 |
| `RESPONSE-952-DATA-LEAKAGES-JAVA.conf` | 11 |
| `REQUEST-922-MULTIPART-ATTACK.conf` | 4 |
| `REQUEST-905-COMMON-EXCEPTIONS.conf` | 2 |

**Seven of them are `RESPONSE-*`, so this product currently has no response-body
inspection capability at all.** Data-leakage detection (SQL, Java, PHP, IIS) and
web-shell detection are shipped, compiled, tested — and unreachable. `verify.sh`
cannot see it, the console cannot enable it, and the site wizard offers no control
for it.

`REQUEST-922-MULTIPART-ATTACK` being absent also means multipart attack rules are
unavailable, which matters for any upload endpoint.

**Fix:** add the missing files to the control plane's rule-file map and expose the
response-body families in the site policy. The data plane already supports
`Phase::ResponseBody` — `tests/target_names_coverage.rs` drives it directly — so
this was wiring, not new engine work.

**This also activates the `@pmFromFile` repair below.** All three files that fix
rescued are `RESPONSE-*`; two of them (`RESPONSE-952`, `RESPONSE-953`) are now
wired as `leak_java` and `leak_php`, so that work reaches production for the
first time. `RESPONSE-955` (web shells) is wired as `web_shells`.

**Deliberately still unwired** — recorded in `crsUnwiredFiles` with reasons:
`REQUEST-901` (would set CRS's `inbound_anomaly_score_threshold=5` and
`blocking_paranoia_level=1`, fighting the site's tuned 10 / PL2),
`REQUEST-949` + `RESPONSE-959` (CRS's anomaly evaluators — redundant, because the
importer maps every `tx.inbound_anomaly_score_plN` delta onto the rule score so
the VM already blocks at the site's threshold; loading them would add a second
deny path at CRS's defaults of 5 and 4), `RESPONSE-980` (reports on aggregates
only 949/959 produce), and `REQUEST-905` (2 importable rules, both Apache-pinger
exceptions whose payload is `ctl:ruleRemoveByTag=OWASP_CRS`; `ctl:` is a
documented no-op so they are inert — zero benefit, and a loopback-shaped hole the
day `ctl:` is implemented).


### 1. About half the OWASP CRS ruleset never loads

> **PARTIALLY FIXED 2026-08-20** (commits `e412183`, `0a60ee4`). **Corrected
> claim:** the commit message said "137 rules recovered". That was wrong — see
> below. The measured production effect is **+6 rules loading (334 → 340)** plus
> restored inspection of cookie names, header names and query-only args inside
> ~129 rules that were already loading blind to them.
> `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS_NAMES`, `ARGS_GET`, `ARGS_GET_NAMES`
> and `QUERY_STRING` are implemented. Rules blocked by unsupported target tokens:
> **149 → 12.** The operators and `%{}` interpolation remain.

| | |
|---|---|
| **Where** | `crates/sentinel-rules/src/crs_compat/importer.rs`, `compiler/vm.rs` |
| **Impact** | "We run OWASP CRS" still needs qualifying until the remainder lands |

**Two corrections to the first version of this entry**, both overstatements of my
own:

1. It cited "1,264 import warnings" as if that were 1,264 lost rules. It is not —
   the importer re-runs on every config reload, so the log count is inflated
   roughly fourfold. **Static analysis of the shipped ruleset is the reliable
   measure**, not warning counts.
2. It counted *"rule has `action:score` but no score field"* (436 warnings) as lost
   coverage. It is not: `compiler/analysis.rs` only warns, and the rule still loads
   and compiles.

3. **"137 rules recovered" counted rules that REFERENCE an unsupported token, not
   rules that were dropped.** A CRS rule lists many targets — 942100 has eight —
   and the importer only discards a rule when *every* target is unsupported (36
   warnings), skipping just the unknown one otherwise. So those 129 cookie-name
   rules were already running; they were simply blind to cookie names.

   The value is real but it is **coverage inside existing rules, not more rules**.
   Proven on the running WAF: a SQL injection placed in a COOKIE NAME, with a
   clean URI, now scores 30 and returns 403 against rules
   `942100,942180,942330,942390,9900100`. Before the fix that request was invisible.
   A benign cookie name (`PHPSESSID`, `lang`) still scores 0.

The real picture, measured statically:

| Cause | Rules blocked | Status |
|---|---|---|
| Unsupported target tokens | 149 *referenced*, 6 *dropped* | **fixed 2026-08-20** |
| `%{...}` interpolation in the pattern | 27 | open |
| `@pm` | 8 | open — cheap, phrase match |
| `@validateByteRange` | 5 | open |
| `@streq` | 3 | open — cheap, string equality |
| `@validateUrlEncoding` | 3 | open |
| `@validateUtf8Encoding` | 1 | open |

**Next, in yield order:** `@pm` and `@streq` (11 rules, both straightforward),
then `%{}` interpolation (27 rules — needs variable expansion at match time, so
genuinely harder), then the six niche tokens (12 rules), then the three
`validate*` operators (9 rules).

**Regression guards added with the fix.** Switching on 129 rules that had never
executed is exactly how a false-positive incident starts, so
`tests/target_names_coverage.rs` asserts both directions: ordinary session cookies
(`PHPSESSID`, `_ga`, `cookie_consent`, `csrftoken`, `lang`) score **zero**, and a
genuine session-fixation attempt is still caught. A quiet ruleset is not a working
one — without the second assertion the first could be satisfied by rules that match
nothing, which is precisely the state these 129 were in.

### Scope decision — API schema validation is a separate project

**Decided by Ayush on 2026-08-20:** item 14 is *not* part of this audit
remediation and is not a deployment blocker. It is a **new product capability**
(OpenAPI/JSON-Schema import, per-endpoint request/response validation, drift
detection, a schema store and its UI), not a defect in something we already
claim. Nothing shipping today advertises it, so there is no false claim to
correct — unlike the SSO button, which had to be fixed because the UI asserted a
capability that did not exist.

It stays on this register only so the competitive gap remains visible. Do not
treat it as unfinished remediation work, and do not start it inside a
deploy-hardening branch.

### 2. Kernel XDP fails to load on every boot

| | |
|---|---|
| **Evidence** | `WARN kernel XDP: failed to load ELF error: "error parsing BPF object: error parsing ELF data"` then `EbpfManager initialised mode: "software"` |
| **Where** | `crates/sentinel-ebpf/src/bpf/sentinel_xdp.o`, loaded via `include_bytes!` at `lib.rs:361` |
| **Impact** | The DDoS path is userspace-only, always. The competitive assessment claimed "verified in-kernel on Linux 6.8" — corrected 2026-08-20 |

**This is not an environment limitation.** All four capabilities are granted
(`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`), `enable_kernel:
true`, BTF present (6,068,679 bytes), kernel 6.8.0-55. The committed `.o` is a
structurally valid BPF ELF (correct magic, machine `0xf7`, relocatable, 13,208
bytes).

> **FIXED 2026-08-20.** The object was never the problem, and the fix previously
> proposed here — *"rebuild the BPF object against the aya version in use"* — was
> **wrong**. It was tested: a fresh rebuild with clang 19.1.7 fails identically,
> and the original committed object works untouched once the real cause is fixed.
> The `.o` in git is byte-identical to what it always was.
>
> **Root cause: `include_bytes!` carries no alignment guarantee.** It expands to a
> plain byte array, so the linker may place it at any address. aya parses the ELF
> through the `object` crate, which reads the ELF64 header as a `Pod` requiring
> 8-byte alignment; on an odd address it returns `Invalid ELF header size or
> alignment`, which aya flattens into the opaque `error parsing ELF data`.
>
> Because the outcome is decided by the final link layout, the *same* object
> parses in one binary and fails in another. That is why it looked like a
> toolchain problem, and why it reproduced 100% of the time within any one build
> while resisting every explanation about clang, BTF, capabilities and kernel
> version. Demonstrated directly: with the identical `.o`, the aya-path test
> binary failed to parse while a second test binary parsed it fine.
>
> **The fix** is a `#[repr(align(8))]` wrapper around the embedded bytes in
> `crates/sentinel-ebpf/src/lib.rs`, so alignment is guaranteed regardless of
> layout. The array length comes from the macro itself, so the two cannot drift.
>
> **Guard:** `crates/sentinel-ebpf/tests/xdp_object_parses.rs` asserts the
> embedded bytes are 8-byte aligned *and* that aya parses them, failing only on a
> parse error so it still runs unprivileged in CI (map creation needs CAP_BPF).
> Negative-tested: reverting to a bare `include_bytes!` makes it fail and name its
> own cause.
>
> **Three further defects found while verifying this, all fixed here.** Making
> kernel XDP load turned out to be necessary but not sufficient:
>
> 1. **`EbpfManager::start()` was never called** — anywhere. The stats task that
>    reads the per-CPU BPF map back into userspace never ran, so
>    `stats_interval_secs` was dead config. Packets dropped by XDP in the driver
>    path never reach userspace, so `xdp_drop` would have read **0 forever while
>    the kernel was dropping traffic**. Measured before the fix: kernel map 1202,
>    reported 21 (the reported figure was a userspace per-connection count, ~1 per
>    HTTP request against ~8.7 packets). After: kernel 470, reported 467 — the
>    poll-interval lag, which is correct.
> 2. **The eBPF mode was not observable at all.** `/healthz` had no eBPF field and
>    the counters went nowhere, so the only evidence of six weeks of silent
>    software-mode fallback was one WARN at container startup. `/healthz` now
>    reports `mode`, `kernel_requested`, `interface` and the counters, and
>    `verify.sh` asserts it — requested-but-software is a WARN rather than a FAIL,
>    because falling back on hosts that cannot do XDP is deliberate and failing
>    verification there would be a false alarm. The point is that the degradation
>    is now visible instead of silent.
> 3. **Three documented XDP knobs were never plumbed into the container.**
>    `compose.prod.yml` passed only `SENTINEL_XDP_ENABLE` and
>    `SENTINEL_XDP_IFACE`, so `SENTINEL_XDP_BLOCK`, `SENTINEL_XDP_AUTOBAN` and
>    `SENTINEL_XDP_AUTOBAN_BLOCKS` did nothing and said nothing when set — the
>    same stored-echoed-dropped shape as the CRS categories. Auto-ban is **on by
>    default**, so until now an operator whose traffic tripped the threshold had
>    no switch. Now plumbed and verified: seeding `203.0.113.7` (RFC 5737
>    TEST-NET-3) produced `seed_entries: 1` and the in-kernel LPM entry
>    `{prefixlen: 32, addr: 0x077100CB}`, proving the userspace→kernel write path
>    the auto-ban depends on. `SENTINEL_XDP_AUTOBAN_INCLUDE_PRIVATE` is
>    deliberately left unplumbed — see below.
>
> **Note on blast radius, checked before enabling this.** `SENTINEL_XDP_ENABLE=1`
> is already set in the shipped compose, so this fix turns a dead code path into a
> live in-kernel drop on every deployment. XDP drops below the socket, so a
> wrongly-banned address is far harder to diagnose than a userspace 403 — and on a
> single-node install every client appears as the Docker gateway. That footgun is
> already handled: `autoban_eligible` excludes private, loopback and link-local by
> default, `is_shared_egress` excludes NAT/CGNAT ranges first regardless, and the
> `SENTINEL_XDP_AUTOBAN_INCLUDE_PRIVATE` escape hatch is documented test-only and
> is **not set anywhere in `deploy/`**. The BPF program itself fails open, passing
> any packet it cannot parse and dropping only explicit blocklist hits.



### 3. The login page has a decoy SSO button

> **FIXED 2026-08-20** (commit `5b84adf`).

The button now starts an OIDC login, and renders **only when OIDC is actually
configured** — gated on a new `GET /api/v1/auth/oidc/status`. `handleOIDCLogin`
answers 501 when unconfigured, so an always-visible button would have been the same
defect wearing a different label. The "or continue with" divider is gated on the
same condition, since a divider with nothing after it is just a line.

The status endpoint is unauthenticated by necessity — the login page must ask
before anyone has logged in — and returns only a boolean. Never the issuer, client
id, secret or redirect URL: those would tell an unauthenticated caller which
identity provider to attack.

**Still to verify:** end-to-end against a running control plane. The deployment on
`.101` predates the route, so this is checked as compiling and type-clean, not as
observed working.

### 0b. `REQUEST-922-MULTIPART-ATTACK` imports 0 of its 6 rules

Found while wiring the above. All four of its `SecRule`s target
`MULTIPART_PART_HEADERS`, which the engine does not implement, so the file
imports **nothing**. It is therefore *not* wired to a category: offering a
"Multipart Attacks" toggle that detects nothing would be worse than not offering
it.

This is an **engine gap, not a wiring gap** — it needs `MULTIPART_PART_HEADERS`
as a target (alongside the existing multipart handling), then a category key.
Multipart attack rules matter for any file-upload endpoint, so this is real
missing coverage rather than a cosmetic hole.

### 0c. `sentinel-cli` still defaults to a rule list including 901 and 949

`crates/sentinel-cli/src/main.rs` `default_crs_files()` lists 15 files including
`REQUEST-901-INITIALIZATION.conf` and `REQUEST-949-BLOCKING-EVALUATION.conf`,
whose comment still asserts "949 evaluates the anomaly score". A site created
through the CLI therefore gets CRS's own blocking evaluator at threshold **5**,
while a site created through the API/dashboard blocks at the site's tuned **10**.

Not urgent and deliberately left alone in this change: `sentinel-cli` is **not
shipped** in the customer bundle or any image, and `first-site.sh` onboards
through the API, so no deployed installation is affected. It should be aligned
before the CLI is ever handed to an operator, so the two paths cannot produce
sites that enforce differently.


## P1 — Product defects that will reach a customer

Found in the 2026-08-14 audit. All are *documented* in the manual; none are fixed.

| # | Defect | Evidence | Effect |
|---|---|---|---|
| 4 | **No password change or reset, for any user** | `handleUpdateUser` binds `role` and `status` only; no route matches `/password`; nothing writes `password_hash` after seeding | The seeded admin password is permanent. A user who forgets theirs must be deleted and recreated |
| 5 | **"Force HTTPS" does nothing** | `handlers.go` classifies the whole `frontend` block as deliberately stored-only | The switch is stored, echoed back, never enforced. No per-site HTTP→HTTPS redirect exists |
| 6 | **HTTPS origins must chain to a public CA** | `crates/sentinel-proxy/src/upstream.rs` — `build_client` pins webpki roots with no override | An internal-CA origin 502s forever while every troubleshooting check passes |
| 7 | **Learning mode does not relax the four request limits** | Limit checks run before phase 1, gated only on `mode != Off`, returning `error_response` without passing through `enforce_mode` | 413/414/431/405 reject during a supposedly safe soak, and never appear in the FPR report |
| 8 | **A new site is unprotected for ~5 s** | Measured: SQLi passed with `rule_matches=0` 1.5 s before `rule engine loaded rules=334`. Engines rebuild on a 5 s poll | A site created directly in Blocking mode **fails open** through that window |

**Fix order:** 4 first (it is the one that can lock a customer out of their own
appliance), then 7 and 8 (both fail *open* or block legitimately without telling
anyone), then 5 and 6.

---

## P2 — Day-2 operations

| # | Defect | Evidence |
|---|---|---|
| 9 | **Post-upgrade database restore can never succeed** | `upgrade.sh` records the backup *parent* directory; `restore.sh` requires the timestamped child that `backup.sh` actually writes |
| 10 | **Rollback does not restore compose files** | `upgrade.sh` overwrites them with no backup |
| 11 | **`upgrade.sh` reintroduces a python3 dependency** | `install.sh` deliberately removed it — Ubuntu minimal images lack python3 — and blames the package when missing |
| 12 | **The administrator email is discarded** | `install.sh` prompts for it, writes `SENTINEL_ADMIN_EMAIL`, and nothing reads it. The seeded account is hardcoded `admin@sentinel.local` |
| 13 | **`issue-ip-cert.sh` hardcodes `/var/lib/docker`** | On a host with a relocated data-root the default TLS certificate lands where no container can see it |

---

## P3 — Feature gaps versus enterprise WAFs

Not defects. Stated so nobody promises them.

| # | Gap | Who has it | Why it matters |
|---|---|---|---|
| 14 | **API schema validation** (OpenAPI import + enforcement) | F5, Imperva | The most-asked-about API security feature. Absent entirely. **Scoped OUT of this remediation as a separate product/feature project — Ayush, 2026-08-20.** See the note below the table |
| 15 | **Positive-security / entity-learning model** | F5 (core differentiator) | Our API discovery is a toggle, not a learned baseline |
| 16 | **Bot defence: JS challenges, device fingerprinting** | F5, HaltDOS | We have JA4 + heuristics, which is real but narrower |
| 17 | **Compliance reporting** (PCI DSS packs) | F5, Imperva, HaltDOS | Procurement asks for it by name |
| 18 | **Scheduled reports** | most commercial WAFs | Absent — previously mis-stated as shipped |
| 19 | **Global anycast DDoS scrubbing** | Cloudflare, Akamai, F5 XC | **Structural, not a roadmap item.** Requires a CDN, not a WAF. Do not put this on a plan |

---

## P4 — Verification debt

### 20. Real-traffic false-positive rate has never been measured

The single most important open gap, and the assessment already marks it ○. Every
detection number we publish comes from a synthetic corpus (GoTestWAF). Nobody has
measured how often this WAF wrongly blocks a **real** application's users.

Until that number exists, "leave new sites in Learning for one to two weeks" is not
caution, it is the only defensible position.

### 21. The offline bundle has never been installed from

Built and contents-verified; never used to perform an install. It is also the
**only** variant that can reach a customer datacentre, so it is where an untested
assumption costs most.

**Fix:** one install on `.101` with the network fully blocked. About an hour.

---

## P5 — Infrastructure, not code

| # | Item | Detail |
|---|---|---|
| 22 | **GitLab runner 45 cannot schedule any job** | `0/2 nodes available: 1 node(s) had untolerated taint {node.kubernetes.io/unreachable:}, 1 node(s) didn't match Pod's node affinity/selector`. Every job fails at `prepare environment`, including GitLab's own `secret_detection`. Blocks all MR checks |
| 23 | **CI cannot reach Harbor** | The `ai-docs` runner resolves `hub.enlight.dev` and has a route, but TCP 443 to `172.16.23.2` times out — silently dropped. Docker Hub and GitLab are reachable from the same container. One firewall rule |
| 24 | **Harbor robot token expires 2026-09-16** | Harbor 1.9 robot tokens are fixed 30-day JWTs — they cannot be extended, only replaced. CI publishing will start failing that day |
| 25 | **Internal RFC1918 addresses published in public DNS** | `hub.enlight.dev` resolves to `172.16.23.2` from 1.1.1.1 and 8.8.8.8. Unroutable externally, so not an exposure — but it hands an outsider the internal addressing scheme |

---

## What is genuinely solid

Recorded so this register is not mistaken for the whole picture. All measured, not
asserted:

| | |
|---|---|
| Detection | **99.60% composite** (app-TP 99.09%, TN 99.29%, API 100%) — GoTestWAF, 2026-07-26 |
| Throughput | **5,939 rps at 8 cores**, p99 18.1 ms, 100% success. Scaling efficiency *rises* with core count (71% → 78%) |
| Soak | **2,160,001 requests** at a sustained 1,200 rps, p99 3.58 ms, memory flat |
| Stability | 20 h uptime, 8/8 containers, **zero restarts**, ~950 MB total |
| Tests | 695 Rust, 197 Go, 5 dashboard suites |
| Install | Three paths; **registry mode verified on a clean VM with Docker Hub blackholed** — all eight containers pulled from Harbor |
| HA | 3-node Raft control plane; 100% of 1,279 requests served through a full reboot of the active node |
| Honesty surfaces | The console marks each setting ● Enforced or ◐ Stored; `verify.sh` refuses to claim enforcement it has not measured |

---

*Register opened 2026-08-20. Update the "Last verified" date whenever an entry is
re-checked, and delete entries only when the fix has been verified on a real
install.*
