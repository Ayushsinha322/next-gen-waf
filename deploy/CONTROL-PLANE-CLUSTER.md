# How the Next-Gen ESDS WAF control-plane cluster works

A plain-language guide to the 3-node control-plane on the deployment VM: the
mental model, how to check health, how to deploy/rebuild without breaking it,
and what happens when a node dies.

---

## 1. The one-sentence mental model

**Three control-plane nodes share one Postgres database. You can talk to any
node and it just works** — reads are answered locally, and writes are
automatically routed to whichever node is currently the "leader". You never have
to know or care which node is the leader.

```
                 ┌── controlplane (node 1)  ← you connect here (:9501 / console :9443)
   client ──▶    ├── cp2  (node 2)
                 └── cp3  (node 3)
        all three share ONE Postgres (the real source of truth)
```

## 2. Why three nodes

If one control-plane **process/container** dies, the other two keep the admin
API and config-writes online. Throughout, the **WAF data plane keeps blocking
attacks** — it is a separate fleet and does not depend on the control plane
being up (it runs on its last-synced config).

> Single-VM limitation: this protects against a control-plane *container* dying,
> not the whole host dying (all three are on one VM). Whole-host HA needs the
> multi-VM / Kubernetes deployment.

## 3. Reads vs. writes — what happens to your request

| Request | Where it runs |
|---|---|
| GET / list / dashboard / live-log stream | Served **locally** by whichever node you hit |
| create / update / delete (POST/PUT/PATCH/DELETE) | **Forwarded** to the current leader, transparently |

So in normal operation you never see a `not the leader` error — the node you hit
forwards the write for you (the `leaderForward` middleware).

## 4. Who is the leader, and how to check

From the VM (any node's REST port is reachable on the docker network; node 1 is
published on the host at `:9501`):

```bash
TOKEN=$(curl -s http://127.0.0.1:9501/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinel.local","password":"<admin pw>"}' | jq -r .access_token)

curl -s http://127.0.0.1:9501/api/v1/cluster/status -H "Authorization: Bearer $TOKEN" | jq .
```

Read `status.role` / `status.leader_id`. **Caveat:** on a *follower*, the
`peers[].reachable` field always shows `false` — that is a cosmetic quirk (a
follower doesn't probe its peers), NOT a real connectivity problem. Trust the
**leader's** view, or check `role`/`leader_id`, which every node agrees on.

## 5. Failover — what you'll see when a node dies

Kill the leader and the other two hold an election (sub-second). During that
brief window a write may return:

```
503  {"error":"no leader elected yet — retry shortly"}
```

**Retry once** and it succeeds against the new leader. Reads keep working the
whole time. The WAF never drops traffic. When the dead node comes back it
rejoins automatically as a follower.

## 6. Deploy / rebuild WITHOUT the crash

The one way this cluster breaks is **deploy-artifact drift**: rebuilding the
image to newer code whose required env the `.env`/compose doesn't supply. The
binary fails fast at boot on a missing secret, so all nodes crash-loop.

Rules that prevent it:

1. Always bring the cluster up with **both** overlay files:
   `docker compose -f compose.prod.yml -f compose.cluster.yml [-f compose.ha.yml] up -d`
2. Every node must get a **byte-identical** control-plane env — that is why the
   shared env lives in one `x-cp-env` anchor in `compose.cluster.yml`.
3. **Run `./preflight.sh` before `up`** on any rebuild or `.env` change.

Boot-fatal env every control-plane node needs (see `.env.example`):
`SENTINEL_JWT_SECRET` and `SENTINEL_AUDIT_HMAC_KEY` (each ≥32 chars),
`SENTINEL_ALLOW_SUPERUSER_DB=1` (single-tenant demo), `SENTINEL_RAFT_SECRET`
(≥32 chars, **not** the demo default), `SENTINEL_INTERNAL_SECRET`,
`SENTINEL_DB_URL`, and the `CLICKHOUSE_*` values.

## 7. Preflight checklist (the hard gate)

`deploy/docker/preflight.sh` verifies, before you start containers, that:
every boot-fatal key is present and long enough; `docker compose config` renders
(it now *fails* if `SENTINEL_RAFT_SECRET` is unset — no more insecure default);
and the rendered env is **identical across all three nodes**. If it fails, fix
the `.env`/compose — do not `up`.

## 8. What Postgres guarantees (and what Raft does *not*)

**Postgres is the single source of truth for all configuration.** The Raft layer
only (a) elects a leader and (b) lets any node route writes to it. Losing the
Raft log — e.g. on a container rebuild — **never loses your configuration**,
because the config lives in Postgres, not in the Raft log. (Raft state is not
persisted to a volume today; safe precisely because Postgres is authoritative.)

## 9. Singleton duties live on node 1

Alerting, the threat-intel feed fetcher, and the cert/node-health monitors run on
**node 1 only** (not on every node), so you get one alert per event, not three.
If node 1 is down these pause until it returns; alerts already raised remain in
Postgres and are visible from any node.

## 10. Troubleshooting quick reference

| Symptom | Look at |
|---|---|
| A node won't start / restart-loops | `docker logs <cp>` — a `fatal: … must be set` line means a missing/short env key; run `preflight.sh` |
| Writes return 503 briefly | Normal during an election — retry once |
| Writes return 503 persistently | Quorum lost (2 of 3 nodes down) — bring a node back; writes need a majority |
| `/cluster/status` shows peers unreachable on a node | Cosmetic if that node is a follower — check the leader's view |
| Duplicate alerts | A node other than node 1 is running singleton duties — check the `primary` gate / node ids |
