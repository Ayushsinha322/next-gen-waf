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
| Secrets (1.1.18 on) | `.env`, the internal PKI in `/opt/sentinel-pki` (root CA key included), the certificate store volume (ACME + uploaded keys — the only copy) | one `tar`, paths as on the host | `extract-secrets.sh` |

Redis is intentionally **not** backed up — it's an ephemeral cache/rate-limit
store (`--save "" --appendonly no`); it rebuilds itself. Nothing durable lives there.

Each run writes `$BACKUP_ROOT/<UTC-timestamp>/` containing `postgres.dump`,
`clickhouse/<table>.schema.sql` + `<table>.native.gz`, `secrets.tar`, a
`MANIFEST.txt`, and `SHA256SUMS`. Local copies older than `RETENTION_DAYS`
(default 14) are pruned after a successful offsite push.

## Encryption and permissions (1.1.18 on)

Every data and secrets file is encrypted with gpg as it is written; only
`MANIFEST.txt`, `clickhouse/TABLES.txt` and `SHA256SUMS` stay readable. The
backup root is `0700` and every file `0600`.

- **Default — a key file.** AES-256 under the passphrase in
  `/etc/sentinel/backup.key` (`BACKUP_KEY_FILE`), which the installer creates.
  **It is in no backup. Copy it off the host when you install** (a password
  manager, a vault): after a host loss, the backups are useless without it.
  `MANIFEST.txt` records the `key_id` each backup needs, so after a key change
  you can tell which key opens which backup.
- **Or a public key.** Set `BACKUP_GPG_RECIPIENT` and `gpg --import` the public
  key into root's keyring; the private key then never has to be on the host.
  Restoring needs it imported where you restore.
- **No gpg on the host** (`apt-get install gnupg` fixes it): backups are still
  written, root-only but unencrypted, and are **never** sent offsite.

`restore.sh` and `extract-secrets.sh` check that the key decrypts the backup
**before** anything is stopped or changed. Backups taken before 1.1.18 are
unencrypted and restore as before.

## Scheduling

**Docker Compose host** — systemd timer (nightly 02:30, jittered). `install.sh`
installs and enables it (1.1.18 on) and writes `/etc/sentinel/backup.env`; add
an offsite target there. On an older install, or by hand:
```bash
sudo cp /opt/sentinel/current/scripts/backup/systemd/sentinel-backup.* /etc/systemd/system/
sudo mkdir -p /etc/sentinel && sudo cp /opt/sentinel/current/scripts/backup/systemd/backup.env.example /etc/sentinel/backup.env
sudo chmod 600 /etc/sentinel/backup.env
sudo $EDITOR /etc/sentinel/backup.env          # check the paths + set ONE offsite target
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
sudo systemctl start sentinel-backup.service     # as the timer would, with backup.env
journalctl -u sentinel-backup -n 30              # what it did
# or directly (creds come from the running containers; the key from backup.env):
sudo /opt/sentinel/current/scripts/backup/backup.sh
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

3. **Restore** (verifies checksums and the key, prompts for `YES`). On a new
   host, put the backup key back at `/etc/sentinel/backup.key` first:
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

## Rebuilding on a new host: the secrets

The databases alone do not bring a node back: the console's sessions and API
keys are signed with secrets from `.env`, Postgres and ClickHouse run on
certificates from the internal PKI, and every site's TLS key is in the
certificate store. With the backup key in place:

```bash
sudo /opt/sentinel/current/scripts/backup/extract-secrets.sh /var/backups/sentinel/<ts> /root/restored
sudo find /root/restored -type f            # a tree mirroring the old host
```

Install the bundle with the old `.env` (`cp /root/restored/opt/sentinel/current/.env`
into place before `install.sh --force`, which keeps an existing `.env`), copy
`/root/restored/opt/sentinel-pki/` to `/opt/sentinel-pki/`, and the certificate
store's contents into the new `sentinel_sentinel-certs` volume, before restoring
the databases.

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
`clickhouse-server:26.3.35.3-alpine` (same versions as prod), seeds known rows, runs the **real**
`backup.sh`, destroys the tables, runs the **real** `restore.sh --force`, and asserts
the restored rows/data match the seed. It also checks that the backup is
encrypted and root-only, that the wrong key is refused before anything changes,
and that `extract-secrets.sh` gives back the `.env`, PKI and certificates it was
given. Run it any time — especially after touching the scripts or bumping DB
image versions:

```bash
deploy/backup/drill.sh
```

**Last drilled: 2026-10-08 — PASSED** (encrypted, gpg 2.4). PostgreSQL
round-tripped 3/3 rows (data `alpha,bravo,charlie` verified) and ClickHouse
4 + 2 rows over two tables through a full backup → drop → restore cycle; the
wrong key was refused with the data untouched; the secrets came back identical.
Re-run before trusting any change to this suite.

## Targets

- **RPO** (max data loss): ≤ 24 h with the nightly schedule. Tighten by running the
  timer/CronJob more often (Postgres dumps are small; ClickHouse Native dumps scale
  with event volume — watch `$BACKUP_ROOT` size and PVC capacity).
- **RTO** (time to restore): minutes for Postgres; for ClickHouse it scales with data
  volume (Native re-insert). The drill restores a small dataset in seconds.
- **Test cadence:** run `drill.sh` at least quarterly and after any schema/image change.
