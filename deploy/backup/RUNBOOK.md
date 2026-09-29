# Swaraj Kavach — Backup & Restore Runbook

**Problem this solves:** before this, a disk/host loss = **total data loss**. The
control plane's state (sites, rules, users, API keys, certs, audit log) lives in
**PostgreSQL**; all traffic/event history (Threat Search) lives in **ClickHouse**.
This runbook backs up both, ships them offsite, and gives a **drilled** restore.

## What is backed up

| Store | Contents | Method | Restorable with |
|---|---|---|---|
| PostgreSQL | control-plane state (sites, rules, RBAC, keys, certs, audit) | `pg_dump -Fc` (custom, compressed) | `pg_restore --clean --if-exists` |
| ClickHouse | `traffic_buckets`, `waf_events`, … (event/log store) | per-table `SHOW CREATE` + `SELECT … FORMAT Native` (gzip) | recreate DDL + `INSERT … FORMAT Native` |

Redis is intentionally **not** backed up — it's an ephemeral cache/rate-limit
store (`--save "" --appendonly no`); it rebuilds itself. Nothing durable lives there.

Each run writes `$BACKUP_ROOT/<UTC-timestamp>/` containing `postgres.dump`,
`clickhouse/<table>.schema.sql` + `<table>.native.gz`, a `MANIFEST.txt`, and
`SHA256SUMS`. Local copies older than `RETENTION_DAYS` (default 14) are pruned
after a successful offsite push.

## Scheduling

**Docker Compose host** — systemd timer (nightly 02:30, jittered):
```bash
sudo cp deploy/backup/systemd/sentinel-backup.* /etc/systemd/system/
sudo mkdir -p /etc/sentinel && sudo cp deploy/backup/systemd/backup.env.example /etc/sentinel/backup.env
sudo $EDITOR /etc/sentinel/backup.env          # set SENTINEL_REPO + ONE offsite target
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-backup.timer
systemctl list-timers sentinel-backup.timer    # confirm next run
```

**Kubernetes** — CronJobs (pg 02:30, ch 02:45, offsite 03:15):
```bash
# put a real rclone.conf into the secret first:
kubectl -n sentinel create secret generic sentinel-backup-rclone \
  --from-file=rclone.conf=$HOME/.config/rclone/rclone.conf \
  --from-literal=remote-path='offsite:sentinel-backups'
kubectl apply -f deploy/backup/k8s-backup-cronjob.yaml
```

## ⚠️ Offsite is mandatory for DR

A backup on the same disk as the database does **not** protect against disk/host
loss. Configure **exactly one** offsite target (`BACKUP_RCLONE_REMOTE` or
`BACKUP_RSYNC_DEST` for compose; the rclone secret for k8s). If none is set, the
scripts still run but log a loud warning and the backup is local-only.

## Run a backup on demand

```bash
# compose (creds come from the running containers):
SENTINEL_REPO=/opt/sentinel-waf BACKUP_RCLONE_REMOTE=offsite:sentinel-backups \
  deploy/backup/backup.sh
```

---

## RESTORE PROCEDURE (Docker Compose)

> Destructive: overwrites the live databases. Do it deliberately.

1. **Get the backup local.** If restoring after host loss, pull the latest backup
   dir from offsite into `$BACKUP_ROOT` first (e.g. `rclone copy offsite:sentinel-backups/<ts> /var/backups/sentinel/<ts>`).

2. **Bring up only the datastores; stop the writers** so nothing writes mid-restore:
   ```bash
   cd /opt/sentinel-waf
   docker compose -f deploy/docker/compose.prod.yml up -d postgres clickhouse
   docker compose -f deploy/docker/compose.prod.yml stop controlplane dataplane dashboard
   ```

3. **Restore** (verifies checksums, prompts for `YES`):
   ```bash
   deploy/backup/restore.sh /var/backups/sentinel/<timestamp>
   #   or: deploy/backup/restore.sh latest
   ```

4. **Verify** before letting traffic back in:
   ```bash
   docker compose -f deploy/docker/compose.prod.yml exec -T postgres \
     psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt" -c "SELECT count(*) FROM sites;"
   docker compose -f deploy/docker/compose.prod.yml exec -T clickhouse \
     clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
     -q "SELECT table, sum(rows) FROM system.parts WHERE active GROUP BY table"
   ```

5. **Restart the planes:**
   ```bash
   docker compose -f deploy/docker/compose.prod.yml up -d controlplane dataplane dashboard
   ```
   Then confirm the dashboard's Sites/Rules/Cluster pages populate and the WAF proxies.

## RESTORE PROCEDURE (Kubernetes)

1. Scale down writers: `kubectl -n sentinel scale deploy/controlplane deploy/dataplane --replicas=0`.
2. Mount the `sentinel-backup` PVC (or pull from offsite) in a throwaway pod, then:
   - **Postgres:** `kubectl -n sentinel exec -i postgres-0 -- pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB" < postgres.dump`
   - **ClickHouse:** for each table, pipe the saved `*.schema.sql` and `*.native.gz` into
     `clickhouse-client` on `clickhouse-0` (`DROP TABLE IF EXISTS` → run DDL → `INSERT … FORMAT Native`), exactly as `restore.sh` does.
3. Scale writers back up and verify as above.

---

## Drill (this mechanism is TESTED, not theoretical)

`deploy/backup/drill.sh` spins up throwaway `postgres:16-alpine` +
`clickhouse-server:26.8.14.3-alpine` (same versions as prod), seeds known rows, runs the **real**
`backup.sh`, destroys the tables, runs the **real** `restore.sh --force`, and asserts
the restored rows/data match the seed. Run it any time — especially after touching
the scripts or bumping DB image versions:

```bash
deploy/backup/drill.sh
```

**Last drilled: 2026-07-14 — PASSED.** PostgreSQL round-tripped 3/3 rows (data
`alpha,bravo,charlie` verified) and ClickHouse 4/4 rows through a full
backup → drop → restore cycle. Re-run before trusting any change to this suite.

## Targets

- **RPO** (max data loss): ≤ 24 h with the nightly schedule. Tighten by running the
  timer/CronJob more often (Postgres dumps are small; ClickHouse Native dumps scale
  with event volume — watch `$BACKUP_ROOT` size and PVC capacity).
- **RTO** (time to restore): minutes for Postgres; for ClickHouse it scales with data
  volume (Native re-insert). The drill restores a small dataset in seconds.
- **Test cadence:** run `drill.sh` at least quarterly and after any schema/image change.
