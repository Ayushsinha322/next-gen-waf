# Sentinel WAF — Deployment Readiness Checklist

**Goal:** get from "97.33% benchmark" to a **single-tenant product** deployable in **blocking mode** in front of
a real ESDS site. **Model:** one dedicated stack per customer (per the 2026-07-14 GTM decision) — no multi-tenant work.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · **★** = the gate that actually blocks deployment.

---

## Phase 0 — Lock in the work (Day 1, do this first)

The 97.33% detection work exists only in the working tree. Nothing is deployable until it's committed, pushed,
and CI-green.

- [ ] Review the uncommitted diff: `crates/sentinel-rules/src/compiler/vm.rs` (unpadded base64Decode),
      `rules/custom/coverage.conf` (new rules 9900209–14 + base64Decode on 9900203/05/06/07), 
      `crates/sentinel-ml/src/models/ngram_classifier.rs`, `crates/sentinel-ml/model/payload_ngram.json`,
      `crates/sentinel-proxy/src/lib.rs`.
- [ ] **Generalize the overfit rule** before committing: rule `9900212` matches the literal `curDate` variable
      from the GoTestWAF payload — rewrite that branch to the timing-loop *shape* so it catches renamed variants.
- [ ] Decide on the untracked FP-suppression experiment (`training/train_fp_suppression.py`,
      `payload_ngram_fp_suppress.json`, `adversarial_benign.txt`) — keep, gitignore, or delete. Don't commit dead files.
- [ ] `cargo fmt --all` + `cargo clippy --workspace -D warnings` + `cargo test --workspace` all green (match CI).
- [ ] Commit the detection work in logical commits; push `integration/waf-v1-hardening`.
- [ ] Confirm CI pipeline **green** on the push (fmt + clippy + test + build).
- [ ] Merge `integration/waf-v1-hardening` → `main` via MR.

---

## Phase 1 — Prove it holds (validation — no code, just evidence)

These are the "never actually run" gaps from the readiness audit. Cheap, but they're real go/no-go evidence.

- [ ] **★ 48–72h soak test** — full prod stack (CRS + ML + ClickHouse) under sustained load against a real backend
      (Juice Shop or a staging site). Watch for memory growth, FD leaks, latency drift, crashes. Record results.
- [ ] **Real load-test p99 on target hardware** — re-confirm the 21k rps / p99 8.5ms block-path number on the
      actual deployment box, not the dev machine. `deploy/load-test/`.
- [ ] **Live ACME / Let's Encrypt staging test** — issue + auto-renew a real cert end-to-end (never done live).
      Confirm SNI hot-reload and expiry alerting fire.
- [ ] Confirm **fail-open behavior**: kill the WAF process mid-traffic → verify the documented failure mode
      (pass-through vs hard-fail) matches policy. Decide and document which one you want.

---

## Phase 2 — Shadow-mode pilot ★ (the real deployment gate)

You cannot flip blocking mode on real traffic until you've measured the **real-traffic** false-positive rate.
GoTestWAF's benign corpus is adversarial and synthetic — it is not your traffic. As of 2026-07-26 we score
99.29% true-negative on it (0.71% FPR), which says the engine is well calibrated and says nothing about
whether blocking breaks a real login flow.

**Runbook: `deploy/LEARNING-MODE-PILOT.md`. Measurement tool: `deploy/load-test/fpr-report.sh`.**

- [ ] Deploy WAF in **log-only / detection mode** in front of 1–2 real internal ESDS apps (zero user impact).
- [ ] Run for **1–2 weeks**; capture every "would-block" event on legitimate traffic.
- [ ] Triage would-blocks → real-traffic FPR. Each false block = a rule to tune (exclusion, threshold, or fix).
- [ ] **★ Tune real-traffic FPR to <1%** (rule exclusions + anomaly threshold + targeted rule fixes).
- [ ] Flip **one** app to blocking mode; monitor 48h; then expand app-by-app.

---

## Phase 3 — Operational readiness (parallel with Phase 1–2)

- [ ] **Runbook**: deploy, upgrade, rollback, config hot-reload, emergency "WAF off" switch. One doc, tested.
- [ ] **Backup + restore drill**: Postgres (config/rules/users) + certs. Actually restore, don't just back up.
- [ ] **Monitoring live**: Prometheus scraping the control plane (no Grafana — bring your own) showing block rate, latency,
      anomaly scores, health. Confirm they render on the deploy box.
- [ ] **Alerting**: page on block-rate spikes (possible FP storm or attack), cert expiry, WAF/DB down, ML model
      load failure.
- [x] Confirm the **threshold-10 tuned config** (anomaly_threshold 10, rule 920230 disabled) is the deploy default.
      Both halves now default in the control plane: `buildRustWaf` defaults `anomaly_threshold` to 10 and injects
      the 920230 disable via `defaultRuleExclusions`, pinned by `waf_defaults_test.go`. Sites created before this
      change store an explicit `anomaly_threshold`, which still wins — migrate those rows per-deployment.
- [ ] Set required env: `SENTINEL_INTERNAL_SECRET`, admin bootstrap password, DB DSN. No `admin123`.

---

## Phase 4 — Honest packaging (before any customer sees the pitch)

Align the sales material with what actually ships, so a customer's pentest/CTO doesn't catch an overclaim.

- [ ] Fix overstated features in docs/pitch: **ONNX/deep-learning** (logistic + isolation-forest + TI-prior are
      real; "deep learning" is not), **eBPF/XDP DDoS** (userspace fallback), **HA active/active** (it's
      leader-elected active/passive), **JA3/JA4** (not populated yet).
- [ ] Finalize the benchmark report (`docs/benchmark/`) as the detection evidence — already done.
- [ ] Write a one-page "what's included / what's roadmap" sheet for sales.

---

## Phase 5 — Detection polish (optional; not a deployment blocker)

- [ ] Close the remaining **18 GoTestWAF bypasses** (concentrated: mail-injection, nosql, sqli, sst) with targeted
      class-general rules — nice-to-have, diminishing returns.
- [ ] Add a real-traffic-informed benign corpus to the ML training set (from the Phase 2 pilot) to lower FPR at
      the model layer, not just via exclusions.

---

## The critical path (what actually gates "deployable")

```
Phase 0 (commit/push/merge)  →  Phase 1 soak + load + ACME  →  Phase 2 shadow pilot + FPR <1%  →  BLOCKING MODE
```

Everything else (Phase 3 ops, Phase 4 packaging) runs in parallel. **The single hardest gate is Phase 2** —
measuring and tuning real-traffic false positives. That's the difference between "great benchmark" and
"safe to put in front of a paying customer."

**Realistic estimate:** Phase 0 = 1 day. Phase 1 = ~1 week (soak dominates). Phase 2 = ~2 weeks (pilot window).
Ops/packaging in parallel. **~3 weeks to first blocking-mode production site**, assuming the pilot FPR tunes cleanly.
