# Code Review — SOC Overhaul

**Scope:** `HEAD~3..HEAD` (base `2920bb7`)
- `8debc94` feat(data-plane): TLS/ACME + native PoW challenge, learning signal, ClickHouse log writers, off-tmpfs rotating logs
- `58efd34` feat(control-plane): alerting+notifications, learning report, geoip blocking, ClickHouse search, cert mgmt
- `183da31` feat(dashboard): SOC overhaul — alerts, learning report, threat map+geoip, ClickHouse search, audit, readability

**Method:** recall-mode review (xhigh). 12 finder angles + gap sweep over the ~9.5k-line diff across Rust/Go/TS; each candidate adversarially verified (3-state). 76 surviving findings; the distinct set is below, deduped across angles.

**Date:** 2026-06-25
**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done
**Confidence:** all CONFIRMED unless tagged *(PLAUSIBLE)*.

---

## 🔴 High — block the release on #1 and #2

- [x] **1. GeoIP block/unblock bypasses Raft consensus**
  - **Where:** `control-plane/cmd/controllerd/geoip_handlers.go` — `geoipMutate`, loop ~L94–107; route wired without `cl` at `main.go:223-224`.
  - **Bug:** calls `store.UpdateSite(...)` directly and bumps `configVersion` locally. Every other site mutation goes through `proposeBest(c, cl, cluster.CmdSiteUpdate, …)` first (`handlers.go:368/515/570`, `sites_config.go:145`), which 503s on a follower and replicates via Raft. The handler isn't even passed `*cluster.Cluster`.
  - **Impact:** in an HA cluster a country block commits only to the receiving node; peers never enforce it and it vanishes on leader change / snapshot restore — a security control is silently non-deterministic.
  - **Also here:** per-site loop aborts on first `UpdateSite` error after persisting sites 1..N-1 (**partial apply, no rollback**); N+1 transactions + a redundant second `ListSites`.
  - **Fix:** pass `cl` to the handler and route the mutation through `proposeBest`; batch the writes; add rollback/idempotency.

- [x] **2. Valid clearance cookie ignored for rule/plugin-initiated challenges → perpetual PoW loop**
  - **Where:** `crates/sentinel-proxy/src/lib.rs:1589` (also `:1570`, `:1617`); root cause `crates/sentinel-proxy/src/challenge.rs:159` `resolve()`.
  - **Bug:** only the *SuspiciousBot* branch (`lib.rs:1535-1537`) guards with `!clearance_valid(...)`. When a CRS rule or WASM plugin returns `Challenge`, `resolve()` gates solely on the `pow` cookie (max-age 120s, deleted on grant), never on the clearance cookie.
  - **Impact:** a legitimate user who already solved the PoW is re-challenged every request and loops forever, never reaching origin.
  - **Fix (altitude):** move the `clearance_valid` check *into* `challenge::resolve` (the single point of challenge consumption) instead of bolting it onto one decision branch.

- [x] **3. Log-rotation race in `append_rotating`**
  - **Where:** `crates/sentinel-proxy/src/lib.rs:2580`.
  - **Bug:** unsynchronized check-then-rotate (`metadata` → `remove_file` → shift `rename`s → reopen) invoked inline from the per-request `proxy` fn on the multi-threaded tokio runtime — no mutex/channel/dedicated writer.
  - **Impact:** under load two requests both pass the size check and both run the rename sequence; the second clobbers the first's `.1` backup, and lines written to a renamed-out fd land in the wrong/dropped file → **corrupted backup chain and silently lost log lines.**
  - **Fix:** serialize rotation behind a mutex, or move logging to a single dedicated writer task.

---

## 🟠 Medium

- [x] **4. `challenge_response` ignores configured `ChallengeMode`**
  - **Where:** `lib.rs:2130` + `challenge.rs:159`. `resolve()` takes no mode and always returns native PoW `interstitial()`; caller hardcodes `X-Sentinel-Challenge: pow`.
  - **Impact:** `challenge: recaptcha|hcaptcha|turnstile` (documented) all silently serve native PoW — the operator's CAPTCHA provider is never used, no warning.

- [x] **5. Challenged POST/PUT loses body and downgrades to GET**
  - **Where:** `lib.rs:1161` + `challenge.rs:169/162`. Challenge served in Phase 1 (headers, before body collection) as `200` HTML for any method; the grant returns `302` → browsers re-issue as GET.
  - **Impact:** a human hitting a challenge mid-`POST` (login/upload) loses the form body and method — submission silently fails.

- [x] **6. Learning-mode `would_block` events with no rule match dropped from `waf.log`**
  - **Where:** `lib.rs:2654` (gate: `!rule_matches.is_empty() || decision==Block`). GeoIP/rate-limit/bot-challenge/smuggling blocks downgraded to `Log` in learning mode set `would_block=true` but push no `rule_match`; the learning report (`hub.go:488`) only consumes the waf stream.
  - **Impact:** the learning report undercounts exactly the would-have-blocked events it exists to surface.

- [x] **7. Dashboard "Attack breakdown" overcounts**
  - **Where:** `control-plane/internal/logs/hub.go:475` — `attackCats[cat]++` fires for *every* `waf.log` row, including PASSed rule matches and learning DETECTs; non-rule blocks carry `rule="-"` and fall into "other".
  - **Impact:** the breakdown counts matches, not blocks, and misattributes geoip/ratelimit blocks.

- [x] **8. Synchronous alert dispatch stalls the hub consumer**
  - **Where:** `control-plane/internal/alerting/engine.go:212`. `raise()` → `dispatch()` blocks on `wg.Wait` (up to the 8s per-channel timeout) inside the single consumer goroutine (`go e.loop(ch)`); subscriber channel is `chan Entry, 64`; full → hub drops events (`hub.go:235` default).
  - **Impact:** one unreachable syslog/webhook channel makes the alerting engine drop WAF events during an attack spike. (Global hub counters update before fan-out, so only the engine's consumption degrades.)
  - **Fix:** dispatch on a worker goroutine / buffered queue.

- [x] **9. Rule 932236 `ARGS_NAMES` exclusion cannot be removed**
  - **Where:** `control-plane/cmd/controllerd/handlers.go:898`. `buildRustWaf` re-appends `{rule_id:932236, exclude_targets:[ARGS_NAMES]}` whenever the list lacks a 932236 entry.
  - **Impact:** `DELETE /sites/:id/exclusions/932236` is silently overridden on the next build — no representable "fully enable 932236" state.

- [x] **10. Stale `run` closure in Threat Search**
  - **Where:** `dashboard/app/(dashboard)/events/page.tsx:65` (`clearFilters`) and `:133/:134` (facet `onPick`). `setRule(k); setTimeout(run, 0)` — `run` is a `useCallback` over `[…,rule,action,ip]`; the timer captures the current render's closure with old values.
  - **Impact:** first facet click searches with the previous filter; "✕ Clear" re-issues with the pre-clear filters (inputs clear visually, results don't).
  - **Fix:** drive the re-search from a `useEffect` on the changed deps, or pass explicit filters into `run`.

- [x] **11. `Toggle` never reverts on a failed backend update**
  - **Where:** `dashboard/components/ui/Toggle.tsx:14,18`. `onClick` does `setOn(next); onChange?.(next)` with no rollback if `onChange`'s persistence fails.
  - **Impact:** a channel enable/disable (or any toggle) shows the opposite of the persisted state after a failed save.

- [x] **12. `ChallengeMode` serde renamed `lowercase` → `snake_case`** *(PLAUSIBLE)*
  - **Where:** `crates/sentinel-core/src/config/mod.rs:500`. A persisted value written under the old scheme (e.g. `nativepow`) no longer deserializes to `native_pow`.
  - **Impact:** after upgrade, existing site configs using the multi-word challenge value fail to parse.
  - **Fix:** add `#[serde(alias = "nativepow")]` or a migration.

---

## 🟡 Low / robustness

- [x] **13. DLP response-body match hard-blocks in Learning mode** — `lib.rs` ~1421 (Phase 5): sets `WafDecision::Block` + `block_response` with no `enforce_mode`, unlike the rule path just above it. A learning-mode site still blocks (and rewrites the response) on a DLP hit.
- [x] **14. ClickHouse event-buffer leak when CH disabled** — `lib.rs:2518/4031`: `record_event()` always buffers, but the drainer task spawns only when CH is configured → buffer grows to its 20k cap, never freed.
- [x] **15. `handleEventsStatus` has no RBAC check** — `control-plane/cmd/controllerd/events_handlers.go:16`: unlike `search/timeline/facets` (all `enf.Allow(...)`), it exposes ClickHouse reachability + total row counts to any authenticated role.
- [x] **16. `SENTINEL_LOG_KEEP=0` → unbounded backups** — `lib.rs` ~4120: live file renamed to `.1`, shift loop empty, nothing pruned.
- [x] **17. PoW cookie max-age (120s) < accept window (`CHALLENGE_TTL_SECS=300`)** — `challenge.rs:223`: a slow device loses the cookie before submitting a valid solution.
- [x] **18. `default_ts_database` changed `"sentinel"` → `"sentinel_logs"`** — `config/mod.rs`: configs omitting `storage.timeseries.database` now point the writer at a different DB.
- [x] **19. Alert throttle key collapses** — `engine.go` ~1226: rule+IP key becomes `"sev::"` when both absent, so distinct critical blocks coalesce into one alert.
- [x] **20. `waf_events.country` always empty** — `lib.rs:2528` writes `String::new()` though `country_code` is in hand at block time (comment says "populated once GeoIP is loaded" — likely a known TODO).
- [x] **21. `runMemSampler` reports `memUsed = total`** — `hub.go:581` when `/proc/meminfo` lacks `MemAvailable` (some containers/kernels).
- [x] **22. Events flusher INSERTs every 1s** — `lib.rs:3762`: drains on each 1s tick instead of the 5s/500-row cadence used for traffic (contradicts its comment).
- [x] **23. `cefExtension` drops `"0"` values** — `control-plane/internal/notify/senders.go`: skips any field whose value is exactly `"0"`.
- [x] **24. `EnsureNotificationSchema` creates the table but not the `updated_at` trigger**, and the bare `CREATE TRIGGER` (no `IF NOT EXISTS`) is non-idempotent — `0002_notifications.sql` vs the startup path diverge.

---

## 🧹 Cleanup / efficiency (cross-cutting)

- [ ] `esc()`/`eq()` SQL escaping in the Go reader (`control-plane/internal/clickhouse/client.go`) duplicates `crates/sentinel-storage/src/clickhouse.rs`. — _left: cross-language, can't share code._
- [ ] `firstNonEmpty` (`geoip_handlers.go`) duplicates `nonEmpty` (`notify/senders.go`). — _left: a 4-line helper in two packages; merging would add cross-package coupling for no real gain._
- [ ] `notifyChannelFromRow` (`notify_handlers.go`) duplicates `toNotifyChannel` (`alerting/engine.go`); `sharedDispatcher` duplicates the engine's dispatcher. — _left: `notify` is intentionally dependency-free (no `db` import); the two stateless `Dispatcher`s are correct separation (the test endpoint shouldn't reach into the engine)._
- [~] Hot-path cost: `record_event`/`record_traffic` take a global `Mutex` per request, and `ndjson_log` runs `fs::metadata` per logged line (syscall per line). — _partly addressed: both now no-op entirely when ClickHouse is off (#14); the per-line stat() is inherent to size-based rotation and left as a tradeoff vs. caching file size in memory._
- [x] `dashboard/app/(dashboard)/alerts/page.tsx:63`: `JSON.stringify(a).toLowerCase()` per alert on every render even when the search box is empty.
- [x] `dashboard/app/(dashboard)/certificates/page.tsx`: fetches certs/sites sequentially (independent); recomputes cert↔site match per row each render.
- [x] `events_handlers.go:17`: `handleEventsStatus` checks an `err` that `ch.Status` never returns non-nil → dead branch.
- [x] `dashboard/app/(dashboard)/overview/page.tsx`: ML-anomaly health indicator uses `mlDet >= 0 && …` (always true) → reflects only WAF-running.
