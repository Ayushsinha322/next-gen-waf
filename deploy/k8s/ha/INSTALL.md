# Sentinel WAF — Production HA install (Kubernetes)

A start-to-finish walkthrough for standing up the HA deployment on a fresh
Kubernetes cluster (the target: ~7 VMs across ≥3 availability zones). Everything
here is copy-pasteable; replace the two placeholders throughout:

| Placeholder | Meaning | Example |
|---|---|---|
| `REG` | your image registry | `registry.esds.local/sentinel` |
| `VIP` | the external WAF virtual IP | `172.16.21.80` |

Manifests live in `deploy/k8s/ha/`. Run commands from the repo root.

---

## 0. Prerequisites

- A Kubernetes cluster **v1.28+** with `kubectl` access, nodes spread across
  ≥3 failure domains.
- A **NetworkPolicy-enforcing CNI** (Calico / Cilium). This is chosen at cluster
  creation — if your CNI doesn't enforce NetworkPolicy, `60-networkpolicy.yaml`
  is silently ignored (not fatal, but no segmentation).
- A container **registry** the cluster can pull from (`REG`).
- Docker/BuildKit on a build host (glibc-matched build happens inside the image,
  so any host works).

---

## 1. Build & push the images

Four images build from `deploy/docker/Dockerfile` (+ the dashboard's own
Dockerfile). The dashboard bakes the **browser-facing** console URL at build
time, so build it with your `VIP`.

```bash
REG=registry.esds.local/sentinel
VIP=172.16.21.80
TAG=v1.0.0

# Rust data plane + Go control plane + goose migrate image
docker build -f deploy/docker/Dockerfile --target sentinel-dataplane   -t $REG/dataplane:$TAG .
docker build -f deploy/docker/Dockerfile --target sentinel-controlplane -t $REG/controlplane:$TAG .
docker build -f deploy/docker/Dockerfile --target sentinel-migrate      -t $REG/migrate:$TAG .

# Next.js dashboard — bake the external console URL (used by the live-log SSE)
docker build -f deploy/docker/Dockerfile.dashboard \
  --build-arg CONTROL_PLANE_URL=http://sentinel-controlplane:9501 \
  --build-arg NEXT_PUBLIC_CONTROL_PLANE_URL=https://$VIP:9443 \
  -t $REG/dashboard:$TAG dashboard

docker push $REG/dataplane:$TAG
docker push $REG/controlplane:$TAG
docker push $REG/migrate:$TAG
docker push $REG/dashboard:$TAG
```

---

## 2. Install cluster add-ons (operators)

```bash
# 2a. CloudNativePG — HA Postgres operator (REQUIRED)
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.0.yaml

# 2b. MetalLB — bare-metal LoadBalancer (REQUIRED on-prem; skip on a cloud that
#     provides its own LB)
helm repo add metallb https://metallb.github.io/metallb && helm repo update
helm install metallb metallb/metallb -n metallb-system --create-namespace

# 2c. metrics-server — needed by the data-plane HPA (REQUIRED)
kubectl apply -f \
  https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# 2d. Prometheus Operator — OPTIONAL (for 70-monitoring.yaml)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts && helm repo update
helm install kube-prom prometheus-community/kube-prometheus-stack -n monitoring --create-namespace

# 2e. cert-manager — OPTIONAL (for 80-tls.yaml; the WAF does its own TLS by default)
helm repo add jetstack https://charts.jetstack.io && helm repo update
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set crds.enabled=true
```

Wait for the operators to be Ready:
```bash
kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager
kubectl -n metallb-system rollout status deploy/metallb-controller
```

---

## 3. Label nodes by zone

Topology spread only works if nodes advertise a zone:
```bash
kubectl label node <node-a> topology.kubernetes.io/zone=az1
kubectl label node <node-b> topology.kubernetes.io/zone=az2
kubectl label node <node-c> topology.kubernetes.io/zone=az3
# …repeat for the rest
```

---

## 4. Set secrets & image registry

**Secrets** — edit `deploy/k8s/ha/00-namespace-config.yaml` and replace every
`CHANGE_ME`. Generate strong values:
```bash
openssl rand -hex 32   # run for jwt-secret, internal-secret, raft-secret, passwords
```
Two rules:
- The **Postgres password is in two places** — `sentinel-secrets/db-url` and
  `sentinel-postgres-app/password` — they **must be identical**.
- `sentinel-secrets/clickhouse-password` must match what the ClickHouse
  StatefulSet uses (it reads the same key), which is automatic.

*(Production: prefer Sealed Secrets or an external secrets manager over plaintext
`stringData`.)*

**Image registry** — point the manifests at your images (one line, no editing):
```bash
cd deploy/k8s/ha
kustomize edit set image \
  registry.example.com/sentinel/dataplane=$REG/dataplane:$TAG \
  registry.example.com/sentinel/controlplane=$REG/controlplane:$TAG \
  registry.example.com/sentinel/dashboard=$REG/dashboard:$TAG
cd -
```
*(Or edit the `image:` lines in `10/20/50-*.yaml` directly.)*

---

## 5. Deploy — datastores first, then migrate, then the rest

The control plane expects the DB schema to exist, and the schema is created by
the **goose migrate image** (not auto-run at boot). So the order is: bring up
Postgres → run migrations → deploy the app.

```bash
# 5a. Namespace, config, secrets, datastores (Postgres/Redis/ClickHouse)
kubectl apply -f deploy/k8s/ha/00-namespace-config.yaml
kubectl apply -f deploy/k8s/ha/30-datastores.yaml

# 5b. Wait for the CloudNativePG primary to be ready
kubectl -n sentinel wait --for=condition=Ready cluster/sentinel-postgres --timeout=300s
# (or: kubectl -n sentinel get cluster sentinel-postgres -w  → until "Cluster in healthy state")

# 5c. Run DB migrations as a one-shot Job (goose)
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: sentinel-migrate
  namespace: sentinel
spec:
  backoffLimit: 3
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: $REG/migrate:$TAG
          env:
            - name: GOOSE_DBSTRING       # goose reads this; the db-url DSN works as-is
              valueFrom: { secretKeyRef: { name: sentinel-secrets, key: db-url } }
YAML
kubectl -n sentinel wait --for=condition=complete job/sentinel-migrate --timeout=180s

# 5d. Deploy the whole app (idempotent — re-applies 00/30 too)
kubectl apply -k deploy/k8s/ha

# 5e. The bare-metal VIP pool (MetalLB), then the optional add-ons
kubectl apply -f deploy/k8s/ha/90-metallb-pool.yaml
kubectl apply -f deploy/k8s/ha/70-monitoring.yaml   # if Prometheus Operator installed
kubectl apply -f deploy/k8s/ha/80-tls.yaml          # if cert-manager installed (optional)
```

---

## 6. Verify

```bash
# All pods Running/Ready — 3 dataplane, 3 controlplane, redis, clickhouse, 2 dashboard
kubectl -n sentinel get pods -o wide

# Postgres HA: 3 instances, one primary
kubectl -n sentinel get cluster sentinel-postgres

# The LB got the VIP
kubectl -n sentinel get svc sentinel-waf-lb   # EXTERNAL-IP should be your VIP

# Control-plane cluster health (from inside the cluster)
kubectl -n sentinel exec deploy/sentinel-dashboard -- \
  wget -qO- http://sentinel-controlplane:9501/healthz ; echo

# Open the console in a browser:  https://<VIP>:9443   (self-signed cert warning is expected)
```

Expected on the **Cluster** page: data plane 3/3, control plane 3/3 quorum with a
leader, overall HEALTHY.

---

## 7. Prove failover (the demo)

```bash
# Kill one WAF pod — the Service reroutes instantly, K8s reschedules it
POD=$(kubectl -n sentinel get pod -l app=sentinel,tier=dataplane -o name | head -1)
kubectl -n sentinel delete "$POD"
kubectl -n sentinel get pods -l tier=dataplane -w      # watch fleet stay ≥2, pod come back

# Kill the Raft leader — a follower is elected in <1s, quorum holds at 2/3
kubectl -n sentinel delete pod sentinel-controlplane-0
kubectl -n sentinel logs -l tier=controlplane --tail=20 | grep -i "becoming leader"
```

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `sentinel-waf-lb` EXTERNAL-IP stuck `<pending>` | MetalLB not installed or `90-metallb-pool.yaml` not applied / pool range not routable |
| Postgres pods never Ready | CNPG operator not installed, or `sentinel-postgres-app` Secret missing / password ≠ `db-url` |
| Control-plane pods crash / degraded, "relation does not exist" | migrate Job didn't run before the control plane — run step 5c, then `kubectl -n sentinel rollout restart statefulset/sentinel-controlplane` |
| Data-plane pods CrashLoop on boot | image pull error, or a bad `sentinel-proxy-config` edit (keep `protocol:`, not `protocols:`) |
| HPA shows `<unknown>` targets | metrics-server not installed (step 2c) |
| Dashboard loads but live logs / console URL wrong | the dashboard image was built with the wrong `NEXT_PUBLIC_CONTROL_PLANE_URL` — rebuild with `https://$VIP:9443` |
| ImagePullBackOff | registry not reachable / images not pushed / add `imagePullSecrets` for a private registry |

---

## 9. Day-2 operations

- **Rolling update**: rebuild + push a new `TAG`, `kustomize edit set image …`,
  `kubectl apply -k deploy/k8s/ha`. maxUnavailable/maxSurge keep ≥2 pods serving.
- **Scale the fleet**: the HPA autoscales 3→12 on CPU; or
  `kubectl -n sentinel scale deploy/sentinel-dataplane --replicas=N`.
- **Rotate secrets**: update the Secret, `rollout restart` the affected workloads.
- **Postgres**: CNPG handles failover automatically; back up with its scheduled
  backups (configure in the `Cluster` spec).

You now have single-region multi-AZ enterprise HA. Multi-region (global anycast)
is a further, separate step (replicate this per region + GeoDNS/anycast).
