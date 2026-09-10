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

- [ ] **B6. Logout is client-only.** `lib/auth.ts` clears local storage and the cookie but
      never calls `POST /api/v1/auth/logout`, so the server-side refresh-token revocation
      built in July is inert from the UI and a refresh token stays valid for its full window.
- [ ] **B7. "Pro ● CURRENT PLAN" badge** is `ACTIVE_PLAN = "pro"` hardcoded in
      `lib/plans.ts`. Marketing furniture on an operations screen. Remove, or wire to a real
      entitlement.
- [ ] **B8. Mixed branding and internal strings in the UI.** "Next-Gen ESDS WAF" appears six
      times and "Sentinel WAF" once; a shipped certificate is named
      *"shared fleet self-signed (interim — see fix/https-ha-single-homing)"*, putting a git
      branch name in front of a customer; Settings carries developer text naming source files
      ("Adding a language is one file in dashboard/lib/i18n.tsx"). Product name should be
      **Swaraj Kavach** per the branding decision.
- [ ] **C2. Tooltips on every KPI.** Overview has thirteen stat blocks and one `title`
      attribute. Every number needs what it counts and over what window. SafeLine has a
      tooltip on every statistic. This also fixes the root cause behind B4 and B13.
- [ ] **C5. First-run explainer banners with "Don't show again."** We have zero across the
      console; SafeLine has them on Attacks, Rate Limiting and Anti-Bot. Add to Rules,
      Threat Search, Plugins and Blocked Sources.
- [ ] **A3. Pin `juice-shop:latest`** in `compose.prod.yml`, or move it out of the production
      compose entirely. It is behind a `demo` profile so it does not start by default, but a
      deliberately vulnerable application with a floating tag in the production compose is
      what an auditor circles. It has already shipped starting unconditionally once.

---

## P2 — next sprint. Real work, not this week.

### UX fine-tuning (the SafeLine craft gap)

- [ ] **C1. A quick-add site path.** SafeLine creates a working site from **six fields in one
      modal** with ports 80/443 pre-filled. Ours asks **127 labelled fields** across five
      steps in Easy mode and ten in Advanced. Add a three-field express lane (name, domain,
      upstream) that takes the defaults already in the wizard, with the full wizard behind an
      Advanced link. Highest perceived-quality gain per hour on the whole list.
- [ ] **C3. Explain the remaining fields.** 55 of 127 wizard fields carry a hint; 72 do not.
      SafeLine explains nearly every toggle in one line underneath it.
- [ ] **C4. Per-field "Use global / Customize" inheritance.** SafeLine's Advanced tab gives
      every setting a two-state control, greying the field but still showing the inherited
      value, so an operator sees exactly what this site overrides. We have source badges on
      Global Settings and nothing equivalent per site. With 127 fields nobody can tell what
      they changed from what shipped. The one genuine architectural gap in our UX; scope it
      properly rather than rushing it.
- [ ] **C6. Make the site detail page a launcher, not a config dump.** Ours opens with five
      KPIs, seven tabs and roughly thirty key-value rows across six panels. SafeLine's shows
      four read-only basics, a prominent mode toggle with its consequence spelled out, and
      chips that jump to the relevant config page. Keep our density behind the existing
      Effective Config tab.
- [ ] **C7. Docs and support links in the sidebar footer.** SafeLine keeps Homepage, Get
      Support and Documentation permanently visible. We show a version and nothing else.

### Smaller console items

- [ ] **B9.** Rules library renders 107 CRS paranoia-level marker rules as empty "— —" rows
      (176 exist in the CRS source). Filter them or label them as internal.
- [ ] **B10.** Blocked Sources "THREAT INTEL 500" is the page cap, not the 18,013 block-tier
      total.
- [ ] **B11.** Site page shows "TLS mode: auto · letsencrypt" for an IP-only site that cannot
      use ACME.
- [ ] **B13.** "Threats blocked" mixes a lifetime hub counter with a windowed snapshot on one
      screen, so the number changes between reads with no window stated.
- [ ] **A5. Topology legibility.** Production is 1,275 lines across three compose files with
      an override chain; SafeLine's whole deployment is one 143-line file. Not a reason to
      restructure, but a generated `deploy/TOPOLOGY.md` would let an operator hold it in their
      head.

### Licensing (blocks a customer bundle, not the internal beta)

- [ ] **D1. Redis 7.4.9 is not open source.** The `redis:7-alpine` tag now resolves to 7.4,
      dual-licensed RSALv2 and SSPL, and the offline bundle redistributes it. We use six
      commands inside one Lua script, all supported by Valkey. One-line compose change.
- [ ] **D2. Grafana is AGPLv3, starts by default, ships in the bundle, and nothing uses it.**
      Zero references in the dashboard or control plane; left over from the July observability
      round. Remove it.
- [ ] **D3. No LICENSE, NOTICE or third-party notices file anywhere.** Apache 2.0 requires
      shipping the licence text when redistributing, and 34 Rust crates plus the OWASP Core
      Rule Set are Apache 2.0. The CRS licence file is not even in the tree, only the
      per-rule headers. Generate a notices file into the bundle.
- [ ] **D4. Classifier training data provenance.** The 32,768 weights compiled into the binary
      were trained on six sources; two are MIT, four have no licence file at all, which means
      all rights reserved. The shipped artifact is hashed weights with no raw text and the
      corpora are not in the repo, but the clean fix is to retrain on the MIT sources plus our
      own data, which the pipeline already supports. Needs a legal opinion either way.

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
