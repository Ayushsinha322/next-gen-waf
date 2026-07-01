# Sentinel WAF on Kubernetes (k3s + MetalLB + local-path)

Kubernetes translation of the production Docker Compose stack
(`deploy/docker/compose.prod.yml`), targeting a small bare-metal cluster
(the 7-VM endgame). Tuned for **k3s** with **MetalLB** (LoadBalancer) and the
**local-path** StorageClass, but the manifests are plain Kubernetes and work on
any conformant cluster with equivalent add-ons.

## What's here

| File | Purpose |
|---|---|
| `00-namespace.yaml` | `sentinel` namespace |
| `10-config.yaml` | non-secret env (`sentinel-env`) + proxy `sentinel.yaml` (`sentinel-proxy-config`) |
| `11-secrets.example.yaml` | **template** for the `sentinel-secrets` Secret (copy → edit → apply) |
| `20-postgres.yaml` | Postgres StatefulSet + headless Service + PVC |
| `21-redis.yaml` | Redis Deployment + Service (ephemeral) |
| `22-clickhouse.yaml` | ClickHouse StatefulSet + Service + PVC (**Threat Search store**) |
| `30-sentinel-edge.yaml` | the edge pod (control plane + data plane) + migrate initContainer + Services |
| `40-dashboard.yaml` | Next.js dashboard Deployment + Service |
| `41-juiceshop.yaml` | demo upstream (delete for real deployments) |
| `90-metallb-pool.example.yaml` | example MetalLB IP pool |
| `kustomization.yaml` | `kubectl apply -k .` entrypoint |

## Architecture notes (how this differs from compose)

- **Edge pod = control plane + data plane in ONE pod.** The Go control-plane log
  hub *tails the NDJSON the Rust proxy writes*, and that stream powers live
  dashboard logs, the overview/per-site metrics, the learning report, **and the
  alert engine**. Compose shares a named volume between the two services; the
  faithful K8s equivalent on RWO (`local-path`) storage is a shared `emptyDir`
  inside one pod. **Threat Search does not depend on this** — the proxy writes
  ClickHouse and the control plane reads it over the network.
  - Consequence: **`sentinel-edge` is pinned to `replicas: 1`.** Multiple copies
    would run multiple alert engines (duplicate alerts) against one Postgres.
    Scaling the data plane horizontally is a later step that requires the hub to
    ingest events over the network (ClickHouse/gRPC) instead of a shared file.
- **The console is reached through the WAF's own `:9443` management listener** —
  the data plane reverse-proxies `/api/*` → control plane and everything else →
  dashboard, same-origin, so live-log SSE needs no CORS. The control-plane
  Service stays `ClusterIP` (never exposed). One MetalLB VIP serves `:80`,
  `:443`, and `:9443`.
- **Migrations-as-code.** A `sentinel/migrate` image (goose + the SQL) runs as an
  initContainer (`goose up`, idempotent, retries until Postgres is up) *before*
  the control plane seeds. No more manual `psql`.

## Prerequisites

1. **k3s** cluster. If using MetalLB, start k3s with the bundled load balancer
   disabled so they don't conflict:
   ```
   curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable servicelb" sh -
   ```
   (You *can* skip MetalLB and use k3s's built-in servicelb instead — then just
   remove the `metallb.universe.tf/loadBalancerIPs` annotation from
   `30-sentinel-edge.yaml`.)
2. **local-path** StorageClass — bundled with k3s and the default. Confirm:
   `kubectl get storageclass` shows `local-path (default)`.
3. **MetalLB** installed, then apply an address pool:
   ```
   kubectl apply -f 90-metallb-pool.example.yaml   # edit the IP range first
   ```

## Build & publish the images

Four images are needed. Build from the repo root:

```bash
cd /path/to/waf-development
VIP=172.16.21.80          # the WAF LoadBalancer VIP (see 90-metallb-pool + 30-edge)

docker build -f deploy/docker/Dockerfile --target sentinel-dataplane    -t sentinel/dataplane:latest .
docker build -f deploy/docker/Dockerfile --target sentinel-controlplane -t sentinel/controlplane:latest .
docker build -f deploy/docker/Dockerfile --target sentinel-migrate      -t sentinel/migrate:latest .
docker build -f deploy/docker/Dockerfile.dashboard \
  --build-arg CONTROL_PLANE_URL=http://controlplane:9501 \
  --build-arg NEXT_PUBLIC_CONTROL_PLANE_URL=https://$VIP:9443 \
  -t sentinel/dashboard:latest dashboard
```

> **`NEXT_PUBLIC_CONTROL_PLANE_URL` is baked at build time.** Rebuild the
> dashboard image whenever the external console URL/VIP changes.

Make the images available to every node. Either:

- **Import into each node's containerd** (no registry needed; matches
  `imagePullPolicy: IfNotPresent`):
  ```bash
  for img in dataplane controlplane migrate dashboard; do
    docker save sentinel/$img:latest | sudo k3s ctr images import -
  done
  ```
- **Or push to a registry** (e.g. the GitLab registry) the cluster can pull, then
  retag the `image:` fields and add `imagePullSecrets`.

## Deploy

```bash
cd deploy/k8s

# 1) Namespace FIRST — the Secret and every resource live in it, and
#    `kubectl apply -f secrets.yaml` fails if the namespace doesn't exist yet.
kubectl apply -f 00-namespace.yaml

# 2) Secret (never committed)
cp 11-secrets.example.yaml secrets.yaml
#    edit secrets.yaml — replace every CHANGE_ME (openssl rand -hex 24 / -hex 64),
#    keep CLICKHOUSE_PASSWORD == SENTINEL_CLICKHOUSE_PASSWORD, embed the postgres
#    password in SENTINEL_DB_URL.
kubectl apply -f secrets.yaml

# 3) Everything else (re-applies the namespace harmlessly)
kubectl apply -k .
```

Order is handled by the manifests themselves: the edge pod's `migrate`
initContainer waits for Postgres and applies the schema before the control plane
starts; the control plane retries its DB connection; the proxy hot-syncs sites
once the control plane is up.

## Verify

```bash
kubectl -n sentinel get pods            # all Running; sentinel-edge 2/2
kubectl -n sentinel get svc sentinel-waf  # EXTERNAL-IP = your VIP

VIP=172.16.21.80
curl -sk https://$VIP/         | head        # WAF serves the protected site
curl -sk "https://$VIP/?q=1'+OR+'1'='1"      # SQLi → 403 (WAF blocks)
# Console: open https://$VIP:9443  (login admin@sentinel.local)
```

### Threat Search (ClickHouse)

This is the feature ClickHouse enables. After some traffic (and at least one
blocked attack):

1. Open the console → **Threat Search** (`/events`).
2. You should see the timeline + events table populate. The data plane writes
   `traffic_buckets` + `waf_events`; the control plane reads them.

Sanity-check from inside the cluster:
```bash
kubectl -n sentinel exec statefulset/clickhouse -- \
  wget -qO- 'http://sentinel:PASSWORD@localhost:8123/?query=SELECT+count()+FROM+sentinel_logs.waf_events'
```
If Threat Search is empty: confirm `sentinel-edge` logs show
`clickhouse connected` / `clickhouse flusher started` (writer) and the control
plane logs `clickhouse reader enabled` (reader).

## Optional: Root CA download (browser trust)

The Certificates page can offer the WAF's private Root CA for download. To enable,
publish the **public** CA cert as a ConfigMap and mount it (the CA *key* never
leaves your PKI host):

```bash
kubectl -n sentinel create configmap sentinel-root-ca --from-file=root-ca.crt=/opt/sentinel-pki/root.crt
```
then add to the `controlplane` container in `30-sentinel-edge.yaml`:
```yaml
        env: [{ name: SENTINEL_ROOT_CA_PATH, value: /etc/sentinel/root-ca.crt }]
        volumeMounts: [{ name: root-ca, mountPath: /etc/sentinel/root-ca.crt, subPath: root-ca.crt, readOnly: true }]
# and a pod volume:
#   - { name: root-ca, configMap: { name: sentinel-root-ca } }
```
Left unset, the feature simply hides (the endpoint reports `available: false`).

## Roadmap from here

- Decouple the planes (network event ingest → no shared log volume → scale the
  data plane to N replicas behind the VIP).
- Harden `securityContext` (run non-root, `fsGroup`, read-only rootfs).
- Replace the local Secret with sealed-secrets / external-secrets.
- Replicated storage (Longhorn) instead of node-local `local-path` for DB HA.
