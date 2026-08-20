# Fixes to be made

**Register of known defects and gaps in Next-Gen ESDSWAF.** Every entry states how
it was found and what evidence supports it, so nothing here rests on an opinion.

**Last verified:** 2026-08-20, against v1.0.2 running on `172.16.21.101`
(registry-mode install, 20 h uptime, 8/8 containers, zero restarts).

**Rule for this file:** an item leaves it when the fix is *verified*, not when the
code is written. Several entries below exist because something was written, looked
correct, and never actually ran.

---

## P0 — Contradicts a claim we make

### 1. About half the OWASP CRS ruleset never loads

| | |
|---|---|
| **Evidence** | 679 SecRule directives ship; the engine reports `rules=334`. 1,264 import warnings on every boot |
| **Where** | `crates/sentinel-rules/` — the CRS importer |
| **Impact** | "We run OWASP CRS" does not survive someone reading the logs. ModSecurity-based competitors (BunkerWeb, anything on libmodsecurity) run it unmodified |

The warnings, by cause:

```
656x  CRS importer: unknown target token, skipping
436x  rule has action:score but no score field
 56x  pattern contains %{...} interpolation — rule disabled
 36x  skipping rule — all targets unsupported
 24x  unsupported operator 'validatebyterange' — rule disabled
 12x  unsupported operator 'validateurlencoding' — rule disabled
```

38 of the shortfall are *correctly* excluded by paranoia-level gating. The rest are
importer limitations.

**Mitigating fact, which must not become an excuse:** measured detection is still
99.09% app true-positive, because libinjection and the ML layer cover the same
attack classes. The gap is in *coverage claims and novel-attack surface*, not in
benchmarked detection.

**Fix:** implement the missing target tokens and the two operators; handle
`action:score` without an explicit score; support `%{}` interpolation. Weeks of
work, and the highest-value weeks available.

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
bytes) — so `aya 0.13` is rejecting something about how it was built.

**Fix:** rebuild the BPF object against the aya version in use and re-verify
attach, **or** stop shipping `--features kernel` and describe the DDoS path
honestly as userspace. Either is acceptable; shipping a failing load is not.

### 3. The login page has a decoy SSO button

| | |
|---|---|
| **Evidence** | `dashboard/app/(auth)/login/page.tsx:385` — button reads "Sign in with SAML / LDAP", `onClick={doLogin}` |
| **Impact** | Clicking it performs an ordinary password login. There is no SAML and no LDAP in the control plane |

Worse, the inverse is also true: **OIDC *is* implemented** — `/api/v1/auth/oidc/login`,
`/oidc/callback`, real discovery in `control-plane/internal/auth/oidc.go` — and has
no button at all.

**Fix:** delete the SAML/LDAP button, add one for OIDC. An afternoon, and it
removes a credibility landmine from every demo.

---

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
| 14 | **API schema validation** (OpenAPI import + enforcement) | F5, Imperva | The most-asked-about API security feature. Absent entirely |
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
