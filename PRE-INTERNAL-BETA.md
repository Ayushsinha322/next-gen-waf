# Pre-internal-beta fix list

Consolidated from the 2026-09-10 audit: a live walk of 20 of 22 console pages on the
deployment host, a backend sweep, a frontend-to-backend API cross-reference, a licensing
audit, and a side-by-side against SafeLine 9.4.1 (console and on-disk packaging).

**Nothing on this list stops the product working.** The console is fully wired: 78 API paths
referenced, all 78 exist. The cluster is healthy, all seven background jobs are green, the
engine inspects and blocks correctly, and the 46-hour stability run passed. What follows is
the difference between working and finished.

Ordering is by risk, not by effort. P0 items either cause an incident or are visibly wrong
to anyone clicking through.

---

## P0 — this week. Incident risk, or visibly wrong in a demo.

> **All nine closed and DEPLOYED to .71 as `bf0e4bc` on 2026-09-10.** Verified on the
> box, 16 checks passing, against a pre-roll baseline that reproduced every defect
> (14 uncapped logs, 7 containers with no healthcheck, 11 open criticals, 78 acked
> `cmdinj`, `dataplane.runtime` absent). Evidence in the control-plane log:
> `resolved stale node_down alerts count:3`, `resolved orphaned infrastructure
> alerts count:8`, `auto-resolved quiet alerts count:78`. B2 was proved
> behaviourally by seeding one open alert outside the 200-row window — old logic
> counted 0, new logic counted 1 — then deleting it.
>
> ⚠️ **Roll this box with `--profile demo`.** Without it compose leaves
> `juiceshop` untouched, so it kept a 163 MB uncapped log through a roll that
> capped everything else. `juice.local` is NOT one of its domains — the site
> answers on `172.16.21.71`, `juice`, `localhost`, `wafdemo.esds.local`, and it is
> deliberately in **learning** mode, so an attack there returns 200 with a scored
> event (`anomaly_score 67`, 12 CRS rules), not a block.


### Operational hygiene

- [x] **A1. No log rotation on any service.** Not one service in `compose.prod.yml` caps its
      json-file log. The soak accumulated **648 MB in 46 hours at 3 requests/second** with no
      rotation in force; at production rates this fills a customer's disk. SafeLine caps four
      of its seven services at 100 MB across five files. Add `logging.options.max-size` and
      `max-file` per service. Six lines each.
      **Fixed** (`7e1de8b`) — All 14 services capped at 100 MB x 5 via an `x-logging`
      anchor in prod, cluster and ha compose files. The anchor must precede the first
      top-level key, not `services:` — `x-wafnode` references it earlier. Merged 3-file
      config validates.

- [x] **A2. No healthcheck on any of our own containers.** We have four, all on third-party
      images (Postgres, ClickHouse, Redis, Prometheus). `controlplane`, `dataplane`,
      `dashboard` and `migrate` have none, so `docker ps` reports "Up" for a hung control
      plane and compose cannot express `depends_on: service_healthy`. The endpoints already
      exist: data plane `/healthz` and `/readyz`, control plane `/metrics`.
      **Fixed** (`7e1de8b`) — The distroless images have no shell, curl or wget, so a
      command healthcheck could not work: added `cmd/healthprobe`, a stdlib-only static
      binary, copied into both distroless stages. Dashboard uses wget (its image has
      one). All four exit codes checked.

- [x] **A4. Deploy sync can delete runtime data.** `rsync --delete` of the repo removed
      `deploy/docker/geoip/dbip-country-lite.mmdb` from the host on 2026-09-09, because that
      directory is a bind mount inside the synced tree and the `.mmdb` is gitignored locally.
      GeoIP silently went inert until the refresh job was re-run. Same class as the earlier
      `.env` clobber. Commit a `deploy/sync-to-host.sh` that carries the exclusions
      (`.env*`, `deploy/docker/geoip/`, `deploy/docker/origin-ca/`) so they cannot be
      forgotten.
      **Fixed** (`7e1de8b`) — `deploy/sync-to-host.sh` carries the exclusions and
      verifies `.env`, the `.mmdb` and the CA anchors survived the sync; refuses to run
      outside the repo root; `DRY_RUN=1` and `--list-runtime-mounts` for inspection.

### Console credibility

- [x] **B1. Eleven CRITICAL alerts open since 13 July** ("node down" ×3, "control-plane node
      unreachable" ×5, "quorum at risk" ×3) while the Cluster page correctly shows 3 of 3
      healthy. Two causes: `raiseDataPlaneRecovered` raises a *new* `node_recovered` alert
      instead of resolving the open `node_down`; and `AutoResolveQuietAlerts` only covers
      `EventDrivenKinds` (attack kinds plus the `*_recovered` notices), so infrastructure
      kinds are owned by nothing. `cp_node_down` and `quorum_at_risk` have no raise site in
      the current Go at all — those rows are legacy.
      **Fixed** (`18a6e69`) — `node_down` is now reconciled against live heartbeats
      rather than waiting for a transition, and the two kinds nothing in this build
      raises are swept as orphaned. Covered by unit tests plus four integration tests
      against real Postgres — which disproved the assumption that `details` could be
      NULL.

- [x] **B2. The Alerts page shows "0 open" while the API returns 11.** `api.alerts.list()`
      is called with no state filter, the backend caps at `LIMIT 200 ORDER BY created_at DESC`,
      and `openCount` is then computed client-side, so older open rows fall off the list and
      out of the count. Overview uses `?state=open` and is right. Two screens disagree.
      **Fixed** (`4beb4f5`) — The page asks for the open set explicitly and merges it
      into the display set; count, severity breakdown and Acknowledge-all all derive
      from the open rows.

- [x] **B3. Overview shows "Instances: 1, standalone" on a three-node cluster.** It reads
      `cluster.status().status.peers`, which the API does not return (the payload has
      `enabled, node_id, role, leader_id, leader_addr, since_unix`), so the catch sets 1.
      **Fixed** (`4beb4f5`) — Switched to `/cluster/health`, the fleet roll-up the
      Cluster page already used. An unreachable roll-up renders —, not a fleet of one.

- [x] **B4. "Sub-millisecond target" caption under a p99 of 80 ms.** Static string. The 80 ms
      is end-to-end including the demo origin; the WAF's own share is about 3 ms per the
      access log. Either fix the caption or show the WAF-only figure, which is both truer and
      more flattering.
      **Fixed** (`4beb4f5`) — Captioned “end-to-end, incl. origin” with the per-node WAF
      share pointed to on the Cluster page. Kept the end-to-end figure: it is the one a
      customer experiences.

- [x] **B5. Global Settings says "eBPF / XDP: off"** while the data plane reports
      `mode: kernel-xdp` with 11 million packets passed. The page reads `cfg.ebpf.enable`
      from the node's config file; the runtime is enabled by `SENTINEL_XDP_ENABLE=1`. Show
      effective state, not file state.
      **Fixed** (`4beb4f5`) — Root cause was worse than a stale read: `cfg.ebpf.enable`
      has ZERO consumers in the data plane, and `EbpfMode` has no “off” state at all, so
      the card was reporting an inert key about a binary that does not exist. The
      control plane now returns `dataplane.runtime` from the node's `/healthz`; the card
      shows the three real states including software-while-kernel-was-requested, and
      “unknown” when unreachable. Verified against .71: kernel-xdp on eth0, 11,657,160
      passed.

- [x] **B12. Clean up the alert backlog.** 78 acknowledged alerts, all older than seven days,
      never resolved. One-time sweep after B1 lands.
      **Fixed** (`d866ea1`) — Not a cleanup after all — a live bug. All 78 are seeder
      rows (no empty-table guard, 78 boots x 7 kinds), and `cmdinj` alone survived July
      because `EventDrivenKinds` is an allowlist and nothing named it. Added to the
      legacy group; the guard test now states the rule, and a new test asserts the two
      sweep lists are disjoint. Both guards checked by reintroducing the defect.

---

## P1 — this week if time. Polish and honesty.

> **All six closed and DEPLOYED to .71 as `0fda530` on 2026-09-11.** 23 checks passing,
> and the P0 fixes re-checked in the same run (logs capped, seven containers healthy, no
> unresolved alerts, eBPF still kernel-xdp).
>
> B6 was proved by revocation, not by inspection: a token returned 200, `POST /auth/logout`
> was called with it, and the same token then returned **401**.
>
> ⚠️ **Roll the whole stack, not just the changed service.** `up -d dashboard` recreated the
> control plane as a dependency but left cp2, cp3 and waf1–3 on the previous tag, so the
> fleet reported two versions at once on a deployment whose whole point is one version
> string. The images were byte-identical (verified by image ID); the tag was not.
>
> **Not a defect, worth knowing:** the data plane's own NDJSON logs are rotated separately
> from the container logs A1 capped — `SENTINEL_LOG_MAX_MB` (100) × `SENTINEL_LOG_KEEP` (5),
> so ~600 MB per stream per node, ~3.6 GB worst case across the three. Currently 651 MB.
>
> **Measurement note:** a p99 is a tail, and the load I generated while verifying pushed the
> Overview's p99 to 1.2 s. After flushing the 1000-sample ring with sequential traffic it
> reads **33 ms end-to-end, 15.6 ms WAF**. Typical WAF cost over the last 300 requests is a
> median of **3.92 ms**, which is the figure the audit quoted.


- [x] **B6. Logout is client-only.** `lib/auth.ts` clears local storage and the cookie but
      never calls `POST /api/v1/auth/logout`, so the server-side refresh-token revocation
      built in July is inert from the UI and a refresh token stays valid for its full window.
      **Fixed** (`9cd9824`) — Added `signOut()`, which calls the endpoint and then
      clears locally; best-effort so a failed revoke cannot trap someone in a session
      they asked to leave. Only the TopBar control was rewired — the password-change and
      password-reset flows have already invalidated every session for the account, so
      their token is dead and the local-only clear is right. Kept separate from
      `logout()`, which the 401 path calls.

- [x] **B7. "Pro ● CURRENT PLAN" badge** is `ACTIVE_PLAN = "pro"` hardcoded in
      `lib/plans.ts`. Marketing furniture on an operations screen. Remove, or wire to a real
      entitlement.
      **Fixed** (`9cd9824`) — Removed, along with `lib/plans.ts`. No entitlement concept
      exists to wire it to, and it advertised limits nothing enforces (90-day logs,
      unlimited sites) in the prime row of an operations screen.

- [x] **B8. Mixed branding and internal strings in the UI.** "Next-Gen ESDS WAF" appears six
      times and "Sentinel WAF" once; a shipped certificate is named
      *"shared fleet self-signed (interim — see fix/https-ha-single-homing)"*, putting a git
      branch name in front of a customer; Settings carries developer text naming source files
      ("Adding a language is one file in dashboard/lib/i18n.tsx"). Product name should be
      **Swaraj Kavach** per the branding decision.
      **Fixed** (`9cd9824`) — One `PRODUCT_NAME` constant beside `PRODUCT_VERSION`,
      which exists for the same reason. Six hand-written call sites had already drifted
      three ways. The Settings hint no longer names a source file. The two certificate
      labels were DATA on .71, not code — renamed on the box, including the one carrying
      a git branch name in front of a customer.

- [x] **C2. Tooltips on every KPI.** Overview has thirteen stat blocks and one `title`
      attribute. Every number needs what it counts and over what window. SafeLine has a
      tooltip on every statistic. This also fixes the root cause behind B4 and B13.
      **Fixed** (`9cd9824`) — A tooltip on all twelve statistics, with windows read off
      the hub rather than guessed (10-second ring for RPS, 1000-sample ring per p99,
      plain counters elsewhere that reset with the control plane). Found another false
      caption of the B4 kind on the way: Requests/sec claimed “live · 1-sec samples”
      over a 10-second window. Also surfaces `p99_waf_ms`, which the snapshot always
      carried and this page never read, so the card now shows the WAF's own share — what
      B4 actually asked for.

- [x] **C5. First-run explainer banners with "Don't show again."** We have zero across the
      console; SafeLine has them on Attacks, Rate Limiting and Anti-Bot. Add to Rules,
      Threat Search, Plugins and Blocked Sources.
      **Fixed** (`9cd9824`) — New `components/ui/FirstRunNote.tsx` on Rules, Threat
      Search, Plugins and Blocked Sources. Each states the one thing that screen cannot
      be inferred from. Dismissal is per-browser: orientation is not tenant
      configuration. Every claim was checked against the code first — the 500-per-type
      indicator cap came from the handler.

- [x] **A3. Pin `juice-shop:latest`** in `compose.prod.yml`, or move it out of the production
      compose entirely. It is behind a `demo` profile so it does not start by default, but a
      deliberately vulnerable application with a floating tag in the production compose is
      what an auditor circles. It has already shipped starting unconditionally once.
      **Fixed** (`9cd9824`) — Pinned by tag AND registry manifest digest
      (`v20.1.1@sha256:cd58d79c…`), verified to resolve on a host that has not pulled
      it. It had already floated: `latest` resolved to `sha256:73c53fbf…` while the box
      ran 20.1.1 and v20.2.0 was published. Moving it out of the production compose is
      the stronger fix and is deliberately NOT done — it would break the documented
      `--profile demo` procedure on the .88/.89 pair.

---

## P2 — next sprint. Real work, not this week.

> **13 of 14 closed and DEPLOYED to .71 as `68fc4e1` on 2026-09-11** (26 checks, with P0 and
> P1 re-checked in the same run). C4 is scoped, not built, and its phase 1 shipped — see
> `PRE-INTERNAL-BETA-C4-SCOPE.md`.
>
> **Valkey is live and proven in the real path**, not just at the connection: waf1 logs
> `rate limiting: distributed mode (Redis backend active)`, and enabling a temporary per-IP
> limit produced the exact `rate:ip:<site>:<ip>` and `rate:site:<site>` keys the Lua writes,
> with commands going 29 → 390. The policy was restored byte-identically afterwards.
>
> ⚠️ **The distributed limiter is not exercised on .71 in normal operation** — the only site
> has no `rate_limit` policy, so `check_async` is never called. And the site is in learning
> mode, where `enforce_mode` downgrades a rate-limit block, so it would answer 200 rather
> than 429 even if it tripped. Worth knowing before anyone reads a green rate-limit check
> as proof of enforcement.
>
> **B10's real number: 13,500 block-tier indicators**, where the tile used to read 500.
>
> ⚠️ **Removing a dependency is mostly a documentation job.** Deleting the Grafana service
> took one commit; the eleven stale references that told an operator to tunnel to
> `127.0.0.1:3001` took another. The compose check that caught the first one only failed
> because it asserted on the file rather than trusting the removal.


### UX fine-tuning (the SafeLine craft gap)

- [x] **C1. A quick-add site path.** SafeLine creates a working site from **six fields in one
      modal** with ports 80/443 pre-filled. Ours asks **127 labelled fields** across five
      steps in Easy mode and ten in Advanced. Add a three-field express lane (name, domain,
      upstream) that takes the defaults already in the wizard, with the full wizard behind an
      Advanced link. Highest perceived-quality gain per hour on the whole list.
      **Fixed** (`a4951fa..`) — New `components/sites/QuickAddSite.tsx`: domain, origin,
      optional name. It does NOT build its own payload — it takes `emptyForm()`, sets
      three values and calls the same `formToPayload()` the wizard uses, because
      `buildRustWaf` is an allowlist and a second hand-rolled payload is how a key gets
      stored, echoed back and silently dropped. Dry-runs `sites.validate` first, states
      which defaults it applies (learning mode above all), and hands off to the full
      wizard carrying what was typed. Both create paths now share one post-create flow.

- [x] **C3. Explain the remaining fields.** 55 of 127 wizard fields carry a hint; 72 do not.
      SafeLine explains nearly every toggle in one line underneath it.
      **Fixed** (`a4951fa..`) — All 100 `<Field>` elements now carry a hint (was 56);
      the 31 section toggles already had descriptions, so the real gap was 44, not 72.
      ⚠️ JSX attribute strings are NOT JS string literals — a `\u2014` escape renders as
      those six characters, so the em dashes had to be real glyphs.

- [ ] **C4. Per-field "Use global / Customize" inheritance.** SafeLine's Advanced tab gives
      every setting a two-state control, greying the field but still showing the inherited
      value, so an operator sees exactly what this site overrides. We have source badges on
      Global Settings and nothing equivalent per site. With 127 fields nobody can tell what
      they changed from what shipped. The one genuine architectural gap in our UX; scope it
      properly rather than rushing it.

      **Scoped, not built** — see `PRE-INTERNAL-BETA-C4-SCOPE.md`. It needs a tenant-level
      site-defaults store, a stored policy that can express "not set" (today an absent
      `paranoia_level` and a stored `0` are the same value after `buildRustWaf`
      unmarshals), and one server-side resolver. The tempting shortcut — omit inherited
      fields from the payload — lands straight in `buildRustWaf`'s ALLOWLIST, which
      stores, echoes back and silently drops unknown keys: a wrong inheritance
      implementation is worse than none. **Phase 1 (diff the site against `emptyForm()`
      and mark what differs from the shipped default) is ~a day, needs no schema change,
      and answers most of the complaint.** Phases 2-4 are a sprint and should not start
      in beta week.

- [x] **C6. Make the site detail page a launcher, not a config dump.** Ours opens with five
      KPIs, seven tabs and roughly thirty key-value rows across six panels. SafeLine's shows
      four read-only basics, a prominent mode toggle with its consequence spelled out, and
      chips that jump to the relevant config page. Keep our density behind the existing
      Effective Config tab.
      **Fixed** (`a4951fa..`) — The overview tab is now four identifying facts plus a
      jump to whichever screen answers the next question. The six config cards and their
      ~30 rows moved behind Effective Config, where a configuration listing belongs and
      the data-plane diff already lives. The prominent mode control with its consequence
      spelled out already existed above the tabs.

- [x] **C7. Docs and support links in the sidebar footer.** SafeLine keeps Homepage, Get
      Support and Documentation permanently visible. We show a version and nothing else.
      **Fixed** (`a4951fa..`) — Ask Copilot is in-product and always shown.
      Documentation and Get support are `NEXT_PUBLIC_DOCS_URL` /
      `NEXT_PUBLIC_SUPPORT_URL` and render only when set — this repo cannot know an ESDS
      documentation host, and a link that 404s is worse than none.

### Smaller console items

- [x] **B9.** Rules library renders 107 CRS paranoia-level marker rules as empty "— —" rows
      (176 exist in the CRS source). Filter them or label them as internal.
      **Fixed** (`a4951fa`) — They are CRS paranoia GATES (`SecRule
      TX:DETECTION_PARANOIA_LEVEL "@lt N" … skipAfter`) — control flow that never
      matches traffic, which is exactly why they have no message, category or score and
      are cleanly separable (107 of 350). Hidden behind a toggle, labelled when shown,
      and still counted.

- [x] **B10.** Blocked Sources "THREAT INTEL 500" is the page cap, not the 18,013 block-tier
      total.
      **Fixed** (`a4951fa`) — `ListIOCs` already returned the true total and the handler
      discarded it. Now returns `indicators_total`; the tile counts that and the table
      says "listing 500 of 18,013" — a tile reading 18,013 above a 500-row table would
      just be a different lie.

- [x] **B11.** Site page shows "TLS mode: auto · letsencrypt" for an IP-only site that cannot
      use ACME.
      **Fixed** (`a4951fa`) — A site whose domains are all IPs now reads "auto — no DNS
      name, so ACME cannot issue; serving the internal-CA certificate", which is what
      actually happens.

- [x] **B13.** "Threats blocked" mixes a lifetime hub counter with a windowed snapshot on one
      screen, so the number changes between reads with no window stated.
      **Fixed** (`a4951fa`) — Three blocked numbers share the Overview, from three
      stores over three windows. They were never meant to agree; the defect was that
      none said so. Each now names its store and window.

- [x] **A5. Topology legibility.** Production is 1,275 lines across three compose files with
      an override chain; SafeLine's whole deployment is one 143-line file. Not a reason to
      restructure, but a generated `deploy/TOPOLOGY.md` would let an operator hold it in their
      head.
      **Fixed** (`a4951fa`) — `deploy/gen-topology.py` → `deploy/TOPOLOGY.md`, generated
      from the merged compose config. Two things it had to get right: healthchecks for
      the distroless images live in the Dockerfile, not compose, so it distinguishes
      `compose` from `image` rather than reporting "no health" for healthy containers;
      and the `:latest` tags are an artefact of SENTINEL_VERSION being unset at
      generation time, which it states.

### Licensing (blocks a customer bundle, not the internal beta)

- [x] **D1. Redis 7.4.9 is not open source.** The `redis:7-alpine` tag now resolves to 7.4,
      dual-licensed RSALv2 and SSPL, and the offline bundle redistributes it. We use six
      commands inside one Lua script, all supported by Valkey. One-line compose change.
      **Fixed** (`27fa728`) — Valkey 8 (BSD-3) replaces redis:7-alpine (7.4,
      RSALv2/SSPL). The exact rate-limit Lua was run against Valkey 8.1.10 — 5 allowed,
      6th denied, both EXPIREs applied — plus every other command the client issues.
      Service name and `redis://` scheme kept deliberately.

- [x] **D2. Grafana is AGPLv3, starts by default, ships in the bundle, and nothing uses it.**
      Zero references in the dashboard or control plane; left over from the July observability
      round. Remove it.
      **Fixed** (`27fa728`) — Removed entirely: service, volume, provisioning tree,
      bundle and mirror entries, the generated admin password in three installers, and
      the docs. compose.prod.yml no longer needs GRAFANA_ADMIN_PASSWORD to parse, which
      is its own proof. It also exposed that the install walkthrough told operators to
      point their first site at `grafana:3000` — now prometheus:9090, which is a real
      listener.

- [x] **D3. No LICENSE, NOTICE or third-party notices file anywhere.** Apache 2.0 requires
      shipping the licence text when redistributing, and 34 Rust crates plus the OWASP Core
      Rule Set are Apache 2.0. The CRS licence file is not even in the tree, only the
      per-rule headers. Generate a notices file into the bundle.
      **Fixed** (`27fa728`) — CRS Apache-2.0 text added where its own headers point,
      plus `deploy/gen-notices.py`. It separates redistributed from build-only, which
      the first cut did not: that reported 944 components including axe-core (MPL) and
      @vercel/og (undeclared), both devDependencies that never ship. Real figure is 420
      redistributed — none AGPL/GPL-only/SSPL, all declaring a licence. Deliberately not
      in CI: regenerating needs cargo+go+npm and deploy-shell is alpine with none of
      them. **The product's own LICENSE is still unchosen — a business decision.**

- [x] **D4. Classifier training data provenance.** The 32,768 weights compiled into the binary
      were trained on six sources; two are MIT, four have no licence file at all, which means
      all rights reserved. The shipped artifact is hashed weights with no raw text and the
      corpora are not in the repo, but the clean fix is to retrain on the MIT sources plus our
      own data, which the pipeline already supports. Needs a legal opinion either way.
      **Fixed** (`8407ac2`) — Documented in `crates/sentinel-ml/TRAINING-DATA-
      PROVENANCE.md`. Verified: the shipped model is 32,768 hashed floats with no
      recoverable text, and the corpora are not redistributed — so the question is
      whether TRAINING was permitted. The audit undercounted: nine upstreams, ~1.57M
      lines, exactly ONE with a licence file (HttpParamsDataset, MIT). Deliberately NOT
      retrained — that trades the 99.64% headline against a legal question that is not
      mine to answer.

---

## P3 — programme work. Cannot be closed in a week.

- [ ] **E1. The ML login-form false positive.** A login form carrying a remember-me field is
      refused: the classifier scores 13 against a blocking threshold of 10, so it blocks on
      its own with no signature match. Two of eight ordinary form bodies affected, both login
      forms. Attributed by running two instances differing only in `ml.enable`. The fix is
      training-corpus coverage, not threshold tuning. **Until it lands, run authentication
      paths in learning mode per site.**
- [ ] **E2. Real-traffic false-positive rate has never been measured.** The gate on the
      readiness rating and on any external precision claim. Needs roughly two weeks of
      mirrored production traffic plus a week of triage. The internal beta in learning mode
      *is* this measurement.
- [ ] **E4. Live certificate issuance never tested.** No record of a real Let's Encrypt
      issuance on any deployment. Verify before any customer-facing deployment.
- [ ] **E5. Seven of twelve module subsystems emit no log lines.** Counters exist; narrative
      log lines do not. Hurts incident forensics for those modules.

---

## Closed by this audit — do not re-chase

- **The soak "memory leak" was page cache, not a leak.** Measured through the cgroup, the two
  nodes sit at 343 MB and 338 MB, effectively identical; anonymous memory differs by 7 MB. The
  80 MB gap `docker stats` displayed is because it subtracts `inactive_file`, and the two nodes
  had opposite active/inactive cache splits. The 16 MB "steps" were file pages being promoted
  to active. **Measure container memory with cgroup `memory.stat`, never `docker stats`.**
- **The console has no broken API calls.** 78 paths referenced, 78 exist. An earlier
  cross-reference that flagged every path on both sides was a normaliser bug in the audit
  script, not a finding.
- **"39,534 threats blocked" is real.** Scanner user-agents blocked at the edge; all three
  control planes agree. The label is imprecise (B13), the number is not.
- **The 63,079 5xx are origin errors** from the demo application on 4 and 6 August, recorded
  as DETECT, not WAF faults.
- **Rules are 350 of 350 compiled with zero dropped.** An older note saying 347 is stale.
- **GeoIP reporting "0 configured"** simply means no site has a country rule yet.
