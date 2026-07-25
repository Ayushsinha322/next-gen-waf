# 2‑VM active‑passive deployment (Docker Compose)

Two machines. Traffic is served by **both**; the database has a primary on one and a
streaming standby on the other; promotion is **scripted, not automatic**.

Same hardened build and the same security posture as the other topologies — TLS to
Postgres with `sslmode=verify-full`, no cleartext management plane, tamper‑evident
audit log.

| Topology | Platform | Posture | Guide |
|---|---|---|---|
| 1 VM | k3s (single node) | standalone | `../k8s/standalone/README.md` |
| **2 VM** | **Docker Compose** | **active‑passive** | **this document** |
| 3 VM | k3s (3 servers) | HA active‑active | `../k8s/ha/3VM-HA-GUIDE.md` |

## What is active‑active, automatic, and manual

This distinction is the whole design, so it is worth being precise:

| Layer | Posture on 2 VMs | Why |
|---|---|---|
| **Data plane** | **active‑active** | Stateless, and it keeps enforcing its last‑synced config regardless of the control plane. Both VMs serve; a VIP or DNS points at either. |
| **Control‑plane write leadership** | **automatic** | Both VMs run a control plane and both contend for the same Postgres advisory lock. Exactly one accepts writes; the other forwards to it. No extra machinery, no manual step. |
| **Postgres** | **manual / scripted promotion** | A majority of 2 is 2, so nothing can safely arbitrate. See below. |
| **ClickHouse** | active VM only | Two nodes cannot form a Keeper quorum, so a second instance would be a separate dataset, not a replica. Protected by backup. |
| **Redis** | one per VM, independent | It holds only 1‑second rate‑limit windows with persistence off. Independent caches mean limits are per‑VM rather than fleet‑wide — bounded and fail‑closed. |

> **Control‑plane leadership being automatic here is new.** Under the old hand‑rolled
> Raft, a 2‑node control plane could not form a quorum and **refused every write** even
> with the database healthy. Retiring Raft for a Postgres advisory lock removed that:
> config writes now continue as long as Postgres is reachable. This is the main reason
> the 2‑VM option is more defensible than it used to be.

## Why promotion is not automatic

Because automating it on two nodes is how you get **split‑brain**: two primaries taking
divergent writes, which is materially worse than the outage it was meant to avoid. With
three nodes a majority can decide; with two, there is no majority to consult.

`promote-standby.sh` therefore:

- refuses to promote while it can still reach a healthy primary, and tells you to fence
  the old one first;
- reports how far behind replication is, so you know what you are about to lose
  (replication is asynchronous — recent commits may not have arrived);
- requires you to type `PROMOTE`.

## One‑time setup

### 1. Certificates — issue ONE cert covering BOTH VMs

`sslmode=verify-full` checks the hostname against the certificate SAN, and the WAL
stream between the VMs is `hostssl`, so **both** addresses must be in the SAN and both
VMs need the cert and key.

```bash
# On the ACTIVE VM:
PG_HOSTS='postgres,<active-ip>,<passive-ip>,localhost' \
PG_IPS='<active-ip>,<passive-ip>,127.0.0.1' \
  sudo deploy/docker/issue-postgres-cert.sh

# Copy the cert, key and CA to the PASSIVE VM (key stays 0600 owned by uid 70):
scp /opt/sentinel-pki/pg-server.crt /opt/sentinel-pki/pg-server.key \
    /opt/sentinel-pki/root.crt root@<passive-ip>:/opt/sentinel-pki/
ssh root@<passive-ip> 'chown 70:70 /opt/sentinel-pki/pg-server.* && chmod 600 /opt/sentinel-pki/pg-server.key'
```

The passive VM needs its own copy because Postgres is started with `-c ssl=on`, and a
command‑line option cannot be overridden from the data directory — it will not start
without a certificate. It also needs one to serve the application the moment it is
promoted.

### 2. `.env` — the same file on both VMs, plus these

```ini
# Replication (used by the primary's init hook and the standby's clone)
SENTINEL_REPL_USER=replicator
SENTINEL_REPL_PASSWORD=            # openssl rand -hex 24
SENTINEL_STANDBY_CIDR=<passive-ip>/32     # keep it a /32 — this grants full replication
SENTINEL_PRIMARY_HOST=<active-ip>

# The PASSIVE VM's control plane and migrations must target the PRIMARY, because a
# standby is read‑only. Its SAN must cover this address.
SENTINEL_DB_URL_PRIMARY=postgres://sentinel:<pw>@<active-ip>:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt

# Bind Postgres to the interface the peer uses, and firewall the rest. Unlike the
# single‑host posture, port 5432 must be reachable from the passive VM.
SENTINEL_PG_BIND=<active-ip>
```

### 3. Bring up the ACTIVE VM first

```bash
cd /opt/sentinel-src/deploy/docker
docker compose -f compose.prod.yml -f compose.2vm-active.yml up -d
./preflight.sh            # catches DSN downgrades and missing secrets
```

The replication role, replication slot and `hostssl` pg_hba entry are created by
`pg-init-replication.sh` on **first initialisation only** — that is deliberate, since
they are cluster‑level state that must not be rewritten on every boot. If Postgres was
already initialised without them, create them by hand (see the script for the exact
SQL and pg_hba line).

### 4. Then the PASSIVE VM

```bash
cd /opt/sentinel-src/deploy/docker
docker compose -f compose.prod.yml -f compose.2vm-passive.yml up -d
```

On an empty volume the entrypoint takes a `pg_basebackup` from the primary over
verify‑full TLS and starts as a streaming standby. On a populated volume it starts
without re‑cloning — it will **never** overwrite existing data, because silently
re‑cloning could destroy the only surviving copy.

### 5. Confirm replication is actually running

```bash
# On the ACTIVE VM — the standby should appear, with state 'streaming':
docker compose -f compose.prod.yml -f compose.2vm-active.yml exec postgres \
  psql -U sentinel -d sentinel -c \
  "SELECT client_addr, state, sync_state, replay_lag FROM pg_stat_replication;"

# On the PASSIVE VM — should print 't' (in recovery):
docker compose -f compose.prod.yml -f compose.2vm-passive.yml exec postgres \
  psql -U sentinel -d sentinel -tAc "SELECT pg_is_in_recovery();"
```

If `pg_stat_replication` is empty, replication is **not** working and the standby is a
stale snapshot. Do not treat the deployment as protected until that query shows
`streaming`.

## Failing over

```bash
# On the PASSIVE VM, after confirming the active VM is genuinely down:
cd /opt/sentinel-src/deploy/docker
export SENTINEL_PRIMARY_HOST=<active-ip> POSTGRES_USER=sentinel POSTGRES_DB=sentinel
./promote-standby.sh
```

It prints the remaining cutover steps: point this VM's control plane at the local
database, move the VIP/DNS, and optionally restore the ClickHouse backup for event
history. The control plane needs no promotion of its own — whichever node reaches the
new primary takes the advisory lock.

**Rebuilding the old VM.** Its data directory has diverged and cannot follow the new
primary. Delete its volume and bring it up with the *passive* overlay pointing at the
new primary. The promotion script prints the commands.

## What you give up versus 3 VMs

| Failure | 2 VM active‑passive | 3 VM HA |
|---|---|---|
| A container crashes | restarted in place | restarted, other replicas absorb |
| A VM dies | traffic continues on the survivor; **config writes continue**; database needs a scripted promotion | fully automatic |
| Disk loss on the active VM | standby has the data up to the last replayed WAL (async → possible loss of recent commits) | synchronous replication → committed writes survive |
| Event history (ClickHouse) | **not node‑loss durable** — restore from backup | replicated storage, RF=3 |
| Node maintenance | promote, then work on the other VM | rolling, no promotion |

Two things hold in every topology: **traffic protection never depends on the control
plane, Postgres, Redis or ClickHouse** — the data plane keeps enforcing its last‑synced
config through a total management‑layer outage. And because a VM loss here can cost
recent commits and all event history, **backups are the recovery mechanism, not a
formality.** Verify a restore actually works before calling this production.
