# 1‑VM standalone deployment (single‑node k3s)

```bash
kubectl apply -k deploy/k8s/standalone
```

This is an **overlay on `deploy/k8s/ha`**, not a copy. Security fixes made to the HA
manifests reach this topology automatically rather than drifting apart.

## What this is for

One machine, full functionality, **no survival of that machine dying**. Suitable for a
pilot, a single‑tenant internal deployment, a demo, or a staging environment. Not
suitable when an outage of the VM is unacceptable.

The security posture is **identical** to the 3‑VM HA topology — TLS to Postgres with
`sslmode=verify-full`, no cleartext management plane, tamper‑evident audit log, no
default credentials. Nothing is relaxed for convenience. The only difference is
redundancy.

## What changes versus the HA base, and why

Applying the HA manifests unchanged to one node does not fail cleanly — it
half‑deploys and looks broken for reasons unrelated to the WAF. Each of these is
corrected by a patch in this directory:

| Base setting | Problem on one node | Overlay |
|---|---|---|
| control plane: 3 replicas, **required** anti‑affinity | 1 pod schedules, 2 Pending forever | 1 replica, anti‑affinity removed |
| Postgres: 3 instances, `minSyncReplicas: 1` | 2 instances Pending, and **every write blocks** waiting for a synchronous standby that cannot exist | 1 instance, `minSyncReplicas: 0` |
| ClickHouse PVC: `sentinel-replicated` (RF=3) | PVC Pending forever; Threat Search never starts | cluster default StorageClass (k3s: `local-path`) |
| PDBs: `minAvailable: 2` | unsatisfiable at 1 replica, so `kubectl drain` and upgrades **hang** | PDBs deleted |
| data‑plane HPA: `minReplicas: 3` | immediately undoes the scale‑down; also needs metrics‑server | HPA deleted |

`Postgres minSyncReplicas: 0` is the one to remember. Left at 1, the control plane
does not error — it *hangs*, which is much harder to diagnose.

The `sentinel-replicated` StorageClass from the base is still created but goes unused;
a StorageClass whose provisioner is not installed is inert, so it is left alone rather
than patched out.

## Before you apply

1. **Postgres TLS.** The DSN uses `sslmode=verify-full`. CloudNativePG issues the
   server certificate and publishes the CA in the `sentinel-postgres-ca` secret, which
   the control plane already mounts — so there is nothing to do here. Verification
   fails closed if that breaks, which is intentional.
2. **Secrets.** Fill `sentinel-secrets` and `sentinel-postgres-app` in
   `../ha/00-namespace-config.yaml`. The Postgres password must match the one embedded
   in `db-url`, or the primary never finishes bootstrap.
3. **Images.** Replace `registry.example.com/*` with a registry this node can pull
   from.
4. **CloudNativePG operator** must be installed even for a single instance:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.0.yaml
   ```
5. **Reaching the WAF.** The base ships a `LoadBalancer` Service. On single‑node k3s
   either keep the bundled ServiceLB (do **not** pass `--disable servicelb` when
   installing k3s) or install MetalLB with a single‑address pool. Without one of those
   the Service stays `<pending>` and nothing is reachable externally.

## What you give up, stated plainly

| Failure | 1 VM | 3 VM HA |
|---|---|---|
| A pod crashes | restarted in place — brief blip | other replicas absorb it, no blip |
| The VM dies | **full outage** until it returns; recovery from backup | traffic and writes continue on the survivors |
| Disk loss | **data loss** back to the last backup | replicated storage / Postgres replicas |
| Node drain / upgrade | **downtime for the duration** | rolling, no downtime |

Because a VM loss is a full outage, **backups are the recovery mechanism here, not a
formality.** Configure and verify CloudNativePG backups before treating this as
production, and confirm a restore actually works — an untested backup is not a backup.

One property still holds even here: the data plane keeps enforcing its last‑synced
configuration even if the control plane, Postgres and ClickHouse are all down. Losing
the management layer degrades manageability and event history, not protection.

## Growing out of it

Moving to 3‑VM HA is `kubectl apply -k deploy/k8s/ha` against a 3‑node cluster plus a
data migration — the manifests are the same base. See `../ha/3VM-HA-GUIDE.md`. If you
only ever get two machines, `deploy/docker/2VM-ACTIVE-PASSIVE.md` describes the
active‑passive posture, which is a better fit for two nodes than a Kubernetes cluster
that cannot form a quorum.
