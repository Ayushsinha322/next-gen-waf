# Sentinel WAF — Kubernetes **HA** deployment

The high-availability, production evolution of the base manifests in
`deploy/k8s/`. The base set is a single-node k3s translation of the compose
stack — it runs the control plane + data plane together in one "edge pod"
(`30-sentinel-edge.yaml`) with a single Postgres/Redis, which is **fine for a
pilot but not HA** (that pod / that VM is a single point of failure).

This `ha/` set splits the tiers and makes every layer redundant, so there is no
single point of failure — the step from single-VM pilot to real enterprise HA.

## What changes vs the base set

| | Base `deploy/k8s/` (pilot) | This `ha/` (production HA) |
|---|---|---|
| Data plane | inside the edge pod (×1) | own **Deployment ×3**, node-spread, HPA, PDB |
| Control plane | inside the edge pod (×1) | own **StatefulSet ×3 (Raft quorum)**, PDB |
| Postgres | StatefulSet ×1 | **CloudNativePG cluster ×3** (auto-failover) |
| Redis | Deployment ×1 (ephemeral) | Redis operator (replication + Sentinel); optional |
| Entrypoint | MetalLB Service | `LoadBalancer` Service, cloud LB / MetalLB-BGP (no single LB) |
| Failure of a node | **outage** | survived (≥2 replicas elsewhere) |

## What makes it HA (by construction)

| Layer | Mechanism | Survives |
|---|---|---|
| WAF data plane | Deployment ×3 + **required podAntiAffinity** + zone spread + HPA | any node loss; scales with load |
| Control plane | StatefulSet ×3 **Raft** + headless DNS + per-pod PVC | 1 node loss (2/3 quorum); state persists |
| Postgres | **CloudNativePG** 3-instance, sync replication, auto-failover | primary node loss |
| Redis | operator (replication + Sentinel) — *optional*, degrades to per-pod | Redis loss = per-pod limits, no protection drop |
| External LB | `LoadBalancer` + cloud LB / **MetalLB (BGP)** | LB node loss (no single LB box) |
| Disruptions | **PodDisruptionBudgets** (minAvailable 2) both tiers | drains/upgrades keep quorum + fleet |
| Rollouts | RollingUpdate maxUnavailable 0 | zero-downtime deploys |

## Mapping to the 7-VM cluster
Spread across **≥3 racks / availability zones** — HA is only real if the VMs are
in different failure domains:
- 3 VMs = Kubernetes control-plane (etcd/API) — HA masters.
- 4 VMs = workers; anti-affinity/topology rules spread the WAF fleet + control
  plane + Postgres across them.

Label nodes by zone so the spread works:
```
kubectl label node <node> topology.kubernetes.io/zone=<az>
```

## The set (11 files)
Core (deployed by `kustomization.yaml`):
`00-namespace-config` (Namespace + proxy ConfigMap + Secrets) · `10-dataplane`
(WAF fleet + HPA + PDB) · `20-controlplane` (3-node Raft StatefulSet) ·
`30-datastores` (CNPG Postgres + Redis + ClickHouse) · `40-loadbalancer` (VIP,
:80/:443/:9443) · `50-dashboard` (admin UI) · `60-networkpolicy`.
Applied separately (need extra operators/CRDs): `70-monitoring` (Prometheus
Operator) · `80-tls` (cert-manager, optional — the WAF does its own TLS) ·
`90-metallb-pool` (MetalLB, `metallb-system` ns).

## Prerequisites (install BEFORE apply)
1. Kubernetes v1.28+ across the VMs, nodes labelled by zone.
2. Images in a registry the cluster can pull — replace
   `registry.example.com/sentinel/{dataplane,controlplane,dashboard}:latest`.
3. **CloudNativePG operator** (Postgres `Cluster`).
4. **MetalLB** (bare metal) → then `kubectl apply -f 90-metallb-pool.yaml`. (Cloud: the cloud LB is automatic.)
5. **metrics-server** (for the data-plane HPA).
6. A **NetworkPolicy-enforcing CNI** (Calico/Cilium) for `60-networkpolicy`.
7. Real values in the `sentinel-secrets` **and** `sentinel-postgres-app` Secrets
   (`00-namespace-config.yaml`) — the Postgres password must match `db-url`.

## Apply
```
kubectl apply -k deploy/k8s/ha          # the whole core set, one command
# then the separate add-ons, once their operators are installed:
kubectl apply -f deploy/k8s/ha/90-metallb-pool.yaml   # bare-metal VIP
kubectl apply -f deploy/k8s/ha/70-monitoring.yaml     # Prometheus Operator present
kubectl apply -f deploy/k8s/ha/80-tls.yaml            # cert-manager present (optional)
```

## Application follow-ups — all done
1. ✅ **`/readyz`** on the data plane (readiness only; `startupProbe` uses
   `/healthz` so a cold cluster doesn't CrashLoop the fleet).
2. ✅ **Control-plane NODE_ID from pod ordinal** (`deriveRaftTopology`).
3. ✅ **Redis, ClickHouse, Dashboard** HA workloads + wiring.
4. ✅ **Management console (:9443)** exposed via the LB + mgmt upstreams.
5. ✅ **ServiceMonitor + PrometheusRule** (scrape the control plane's `/metrics`).
Deploy-time: push real images; set real Secret values; choose MetalLB L2 vs BGP.

## What this gives you — and what it doesn't
- ✅ **Single-cluster, multi-AZ enterprise HA** — survives node and (with zone
  spread) AZ failures, self-heals, autoscales, zero-downtime deploys. Matches or
  beats on-prem enterprise WAFs (F5/HaltDOS).
- ❌ **Not multi-region / global anycast** (the Cloudflare/AWS tier). That's a
  further step (replicate per region + GeoDNS/anycast) and a different product
  category — not required for the enterprise/private-cloud market this targets.
