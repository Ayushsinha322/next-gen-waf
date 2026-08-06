# 3‑VM High‑Availability deployment — the plan

> **Three supported topologies.** This document covers the 3‑VM active‑active
> target. The other two are:
>
> | Topology | Platform | Posture | Guide |
> |---|---|---|---|
> | **1 VM** | k3s (single node) | standalone — no node‑loss survival | `deploy/k8s/standalone/README.md` |
> | **2 VM** | Docker Compose | active‑passive, scripted promotion | `deploy/docker/2VM-ACTIVE-PASSIVE.md` |
> | **3 VM** | k3s (3 servers) | HA active‑active | this document |
>
> All three run the **same** hardened build with the same security posture (TLS to
> Postgres, no cleartext management plane, tamper‑evident audit log). They differ
> only in what survives a machine dying.

Why **3** VMs (not 2)? Independent layers each need a **majority (quorum)**, and a
majority needs an **odd number ≥ 3** spread across **3 failure domains**:

| Layer | Needs 3 for |
|---|---|
| k3s control plane (embedded etcd) | Kubernetes' own HA / quorum |
| Replicated storage (OpenEBS/Longhorn, RF=3) | one copy of every volume per node |
| Postgres (CloudNativePG, 3 instances) | sync replication + auto‑failover without split‑brain |

> **The WAF control plane no longer belongs in that table.** It used to run a
> hand‑rolled 3‑member Raft cluster, so "our Raft needs quorum" was a fourth reason
> to want 3 VMs. Raft was **removed**: write leadership is now a single Postgres
> advisory lock (`internal/leader`). The control plane therefore has **no quorum of
> its own** — it inherits Postgres's. Losing control‑plane replicas no longer affects
> whether writes are accepted, only how much spare capacity remains.

## What runs where

```
        Clients ─▶ MetalLB VIP (:80/:443/:9443) ── one virtual IP across all 3 VMs
   ┌────────── VM‑1 ──────────┐ ┌────────── VM‑2 ──────────┐ ┌────────── VM‑3 ──────────┐
   │ WAF data-plane pod       │ │ WAF data-plane pod       │ │ WAF data-plane pod       │  active-active (Deployment×3)
   │ control-plane-0          │ │ control-plane-1          │ │ control-plane-2          │  3 replicas, any accepts writes
   │ postgres instance-0      │ │ postgres instance-1      │ │ postgres instance-2      │  CloudNativePG (app replication)
   │ clickhouse (+replica vol)│ │ (clickhouse vol replica) │ │ (clickhouse vol replica) │  replicated storage RF=3
   │ k3s server + etcd        │ │ k3s server + etcd        │ │ k3s server + etcd        │  k8s HA control plane
   └──────────────────────────┘ └──────────────────────────┘ └──────────────────────────┘
```

Control‑plane pods have no per‑pod volume any more — the Raft log PVC is gone. Any
replica accepts writes; a follower transparently forwards them to whichever node
holds the advisory lock.

## How each piece survives a VM dying

| Component | Survives node loss via | Result of losing 1 VM |
|---|---|---|
| **WAF data plane** | stateless + LB health‑check | LB routes to the other 2 VMs — **no traffic impact** |
| **Control plane** | Postgres advisory lock | the lock is released and another replica takes it; **writes continue** |
| **Postgres** | CloudNativePG replication | a standby is promoted automatically |
| **ClickHouse** | **replicated storage** (`sentinel-replicated`) | its volume replica on another node re‑attaches to a rescheduled pod |
| **Redis** | stateless, no PVC → freely rescheduled | rate limits fall back to per‑pod for ~30s (see below), then fleet‑wide again |

### The thing that actually governed recovery time

Kubernetes' default tolerations for `node.kubernetes.io/not-ready` and
`/unreachable` are **300 seconds**. Nothing overrode them, so when a VM died every
pod on it sat un‑rescheduled for **five minutes** — no matter how good the storage
replication or the PodDisruptionBudgets were.

Every pod spec now carries a **20s** toleration, cutting that to roughly 30 seconds.
This mattered more than any datastore replication change: it is the difference
between five minutes of degraded rate limiting and thirty seconds of it.

### Why Redis is a single pod on purpose

Redis holds only 1‑second sliding‑window rate‑limit counters, with persistence
disabled (`--save "" --appendonly no`) and no PVC. There is nothing to replicate, and
an empty cache after a restart costs nothing.

While Redis is away, each WAF pod falls back to its own in‑process limiter — which
**never disables limiting** (fail‑closed, see `rate_limit/mod.rs`), but does mean
limits become per‑pod. With 3 data‑plane pods a 100 rps cap behaves like ~300 rps for
that window. That is the honest cost, and the 20s toleration is what keeps the window
short.

**Do not scale the Redis Deployment to 2.** Redis is not multi‑master: two pods
behind one Service are two independent caches and the Service round‑robins between
them, so a 100 rps limit would admit ~200 rps. It looks like added redundancy and is
actually a silent loss of enforcement accuracy.

### Why ClickHouse replicates at the storage layer, not with Keeper

ClickHouse Keeper + `ReplicatedMergeTree` is the textbook answer and was deliberately
not used here. It would mean 3 Keeper pods, a `MergeTree` → `ReplicatedMergeTree`
schema migration, and a two‑replica write path — to protect a store whose loss costs
only Threat Search queries, because **protection never reads from ClickHouse**.
Replicated storage (RF=3) gives no event loss and recovery in about a pod reschedule,
which is the better trade for this component.

The cost of that choice: it depends on a replicated CSI driver being installed
(Mayastor needs HugePages and the `nvme-tcp` module; Longhorn is easier). If none is
installed, comment out `storageClassName` in `30-datastores.yaml` — the WAF runs
fine, and only event history loses node‑loss durability.

## Install order (once, on the 3‑node k3s cluster)

```bash
# 0. 3 nodes as k3s servers (embedded-etcd HA). On node 1:
curl -sfL https://get.k3s.io | sh -s - server --cluster-init --disable servicelb
# On nodes 2 and 3 (token from /var/lib/rancher/k3s/server/node-token on node 1):
curl -sfL https://get.k3s.io | sh -s - server --server https://<node1-ip>:6443 --token <TOKEN> --disable servicelb

# 1. Replicated storage — OpenEBS (Mayastor) [what we discussed]
kubectl apply -f https://openebs.github.io/charts/openebs-operator.yaml
#    (or Longhorn — simpler: kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/v1.6.2/deploy/longhorn.yaml)

# 2. CloudNativePG (HA Postgres operator)
kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.0.yaml

# 3. MetalLB (the Kubernetes LoadBalancer)
helm repo add metallb https://metallb.github.io/metallb
helm install metallb metallb/metallb -n metallb-system --create-namespace

# 4. Our stack (creates the sentinel-replicated StorageClass + everything else)
kubectl apply -f deploy/k8s/ha/90-metallb-pool.yaml   # set your VIP range first
kubectl apply -k deploy/k8s/ha
```

**Postgres TLS is already handled on k8s.** The DSN is `sslmode=verify-full`, and
CloudNativePG issues its own server certificate and publishes the CA in the
`sentinel-postgres-ca` secret, which `20-controlplane.yaml` mounts at the
`sslrootcert` path. Nothing extra to run. (The Compose topologies need
`sudo deploy/docker/issue-postgres-cert.sh` instead — verification fails closed
without it, by design.)

Full step‑by‑step + troubleshooting: `INSTALL.md`.

## The 2‑VM answer — now materially better than it was

The original objection to 2 VMs was that "a full‑VM loss pauses config writes."
**That is no longer true.** It was a consequence of the hand‑rolled Raft requiring
control‑plane quorum: losing 2 of 3 members refused every write even while Postgres
was healthy and writable. Raft is gone, so **config writes continue as long as
Postgres is reachable**, and Postgres on 2 VMs runs primary + standby with promotion.

What you still cannot get on 2 VMs:

- **Replicated storage** — RF=3 needs 3 nodes, so ClickHouse event history is not
  node‑loss durable (recover from backup instead).
- **Automatic, split‑brain‑free promotion** — a majority of 2 is 2, so *something*
  has to decide when to promote. On 2 VMs that decision is scripted or human, which is
  exactly why the 2‑VM topology is documented as **active‑passive** rather than
  active‑active.

So the honest positioning: 2 VMs gives traffic HA (data plane on both), Postgres
primary+standby, and uninterrupted config writes — with a human or script in the
promotion path. 3 VMs makes promotion automatic and adds node‑loss durability for
event history. And in every topology, **traffic protection itself never depends on any
of this**: the WAF keeps enforcing its last‑synced config even with the whole control
and storage layer down.

## Specs (suggested)

Each of the 3 VMs: **4–8 vCPU / 12–16 GB RAM / 100 GB SSD** (SSD matters for
replicated storage + Postgres). All on the same L2 segment so MetalLB can hand out a
VIP. Fast disks + a low‑latency network between the 3 nodes keep storage replication
and Postgres replication healthy.
