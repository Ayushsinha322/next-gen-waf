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

## Prerequisites
1. Kubernetes v1.28+ across the 7 VMs, nodes labelled by zone.
2. Images in a registry the cluster can pull — replace
   `registry.example.com/sentinel/{dataplane,controlplane}:latest`.
3. **CloudNativePG operator** (see `30-datastores.yaml`).
4. External LB: cloud LB, or **MetalLB** (BGP) on bare metal (see `40-loadbalancer.yaml`).
5. (Optional) Redis operator for shared-rate-limit HA.
6. Real values in `sentinel-secrets` (`00-namespace-config.yaml`).

## Apply order
```
kubectl apply -f 00-namespace-config.yaml
kubectl apply -f 30-datastores.yaml     # after the CNPG operator is installed
kubectl apply -f 20-controlplane.yaml
kubectl apply -f 10-dataplane.yaml
kubectl apply -f 40-loadbalancer.yaml
```

## Follow-ups
Done — the manifests are turnkey against the current images:
1. ✅ **`/readyz` on the data plane** — returns 200 only when config has synced
   (`sites > 0`), 503 otherwise. The readiness + startup probes point at it, so a
   pod never receives traffic before its rules load (no 502s on rollout/recovery).
   (`crates/sentinel-proxy/src/lib.rs`.)
2. ✅ **Control-plane NODE_ID from pod ordinal** — `controllerd` derives
   `SENTINEL_NODE_ID` + `SENTINEL_RAFT_PEERS` from the pod ordinal natively (no
   entrypoint/shell needed in the distroless image) via
   `SENTINEL_RAFT_POD_NAME` / `_REPLICAS` / `_SERVICE`. See `deriveRaftTopology`
   in `control-plane/cmd/controllerd/main.go`.

Still environment-specific (do at deploy time):
3. **TLS/cert management** — wire cert-manager or the built-in ACME for HTTPS.
4. **Push images to a registry**; set `imagePullSecrets` if private.

## What this gives you — and what it doesn't
- ✅ **Single-cluster, multi-AZ enterprise HA** — survives node and (with zone
  spread) AZ failures, self-heals, autoscales, zero-downtime deploys. Matches or
  beats on-prem enterprise WAFs (F5/HaltDOS).
- ❌ **Not multi-region / global anycast** (the Cloudflare/AWS tier). That's a
  further step (replicate per region + GeoDNS/anycast) and a different product
  category — not required for the enterprise/private-cloud market this targets.
