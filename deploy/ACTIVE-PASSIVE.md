# Next-Gen ESDSWAF — 2-VM Active/Passive Installation

Two VMs and one virtual IP. Clients use the VIP; it follows whichever node can
actually serve traffic, and moves back when the preferred node recovers.

For a single VM, use [STANDALONE.md](STANDALONE.md). Install that first at least
once — this guide assumes you have seen the standalone flow work.

**Time:** about 25 minutes for the pair, plus the failover drill (§8), which is not
optional.

---

## 1. What actually fails over — read this first

This is the whole design, and being precise about it is the difference between a
deployment you can defend and one that surprises you at 3 a.m.

| Layer | Behaviour on node loss | Automatic? |
|---|---|---|
| **Traffic** | The VIP moves to the survivor in ~4–6 s. The data plane is stateless and keeps enforcing its last-synced config with no control plane and no database, so the surviving node protects traffic on its own. | **Yes** |
| **Config write leadership** | Both control planes contend for one Postgres advisory lock. Whichever holds it accepts writes; the other forwards to it. | **Yes** |
| **Postgres** | Stays a read-only standby. Traffic keeps being served and protected; **configuration changes are refused** until a human promotes. | **No — on purpose** |
| **ClickHouse (event history)** | Runs on the master only. History is not node-loss durable; restore from backup. | **No** |
| **Redis** | One per VM, independent. Holds only 1-second rate-limit windows, so limits become per-VM rather than fleet-wide — bounded and fail-closed. | n/a |

### Why Postgres promotion is manual

Because automating it on two nodes is how you get **split-brain**: two primaries
taking divergent writes, which is materially worse than the outage it was meant to
prevent. A majority of 2 is 2 — neither node can tell "my peer is dead" from "my
peer is unreachable", and guessing wrong is unrecoverable.

If you need automatic promotion, that needs a third arbitrator. That is the 3-VM
cluster, not this topology.

So after a failover:

```
traffic   →  served and protected by the surviving node
config    →  read-only until someone runs promote-standby.sh
```

---

## 2. Requirements

Everything in [STANDALONE.md §1](STANDALONE.md) applies **per VM**, plus:

| | Requirement |
|---|---|
| Addresses | **Three**: VM1, VM2, and a free VIP. The VIP must be a third address, not either VM's own |
| L2 | Both VMs on the same subnet — the VIP moves by ARP |
| VRRP | IP protocol **112** must pass between the two VMs |
| keepalived | Installed automatically via apt if absent |
| Root | Required on both nodes |

The installer validates the addressing before it changes anything: all three must be
valid IPv4, the VIP must differ from both nodes, and the interface must exist.

**On the VIP already answering:** the installer distinguishes three cases by MAC
address — this node re-installing (fine), the *peer* holding it (fine, that is the
whole point of the pair), and a stranger using the address (fatal). Only the third
stops you, and it should.

---

## 3. Order of operations

Non-negotiable: **master first, completely, then the slave.** The slave cannot
generate its own secrets — it needs three artifacts from the master that do not
exist until the master install finishes.

```
VM1 (master)  ──install──▶  copy 3 artifacts  ──▶  VM2 (slave) install
```

---

## 4. Install the master (VM1)

From the extracted bundle, or a repo checkout:

```bash
sudo ./scripts/2vm/install-2vm.sh \
     --role master \
     --this 172.16.21.88 \
     --peer 172.16.21.89 \
     --vip  172.16.21.87
```

Or run it with no flags and answer the prompts.

It runs eight steps: role → addressing → preflight → secrets → Postgres cert →
ClickHouse cert → images → start. What it does that matters:

- **Generates every shared secret** into `.env` (mode 0600)
- **Issues the internal CA and certificates**, with SANs covering `postgres`,
  localhost, **both VMs, and the VIP** — because the standby dials the primary by
  address, and after a role swap the other node serves
- **Loads the container images** from the bundle if they are not present
- **Restricts the published ClickHouse port** to the peer `/32`
- **Writes keepalived config** and starts it

### The ClickHouse firewall rule

The master publishes ClickHouse on 8443 so the slave's data plane has somewhere to
send event history. The rule that restricts it lives in the `DOCKER-USER` chain —
not `INPUT`, not `ufw`. Docker publishes ports by DNAT in its own chains, which
bypass `INPUT` entirely and are invisible to ufw. That is the single most common way
an operator believes a container port is firewalled when it is wide open.

It matches on `--ctorigdstport`, not `--dport`, because two containers share
container port 8443 (ClickHouse, and the data plane's HTTPS listener). A plain
`--dport 8443` silently blackholes every client HTTPS request to the WAF. The
installer verifies the data path still works immediately after adding the rule,
because this pair of rules is one typo away from a silent outage.

**These rules do not survive a reboot on their own:**

```bash
apt-get install -y iptables-persistent
```

---

## 5. Copy three artifacts to the slave

The master prints these exact commands at the end. **None of the three is optional.**

```bash
scp  /path/to/.env                 root@172.16.21.89:/path/to/.env
scp  /etc/sentinel/2vm-vrrp-pass   root@172.16.21.89:/etc/sentinel/2vm-vrrp-pass
rsync -a /opt/sentinel-pki/        root@172.16.21.89:/opt/sentinel-pki/
```

| Artifact | What breaks without it |
|---|---|
| `.env` | Divergent `SENTINEL_JWT_SECRET` / `INTERNAL_SECRET` / `AUDIT_HMAC_KEY` give you two stacks that silently reject each other's tokens and cannot verify the audit chain. No obvious symptom until something fails oddly, much later |
| `2vm-vrrp-pass` | Each node ignores the other's VRRP adverts and **both become master** — two hosts answering on one IP |
| `/opt/sentinel-pki/` | Two independently generated CAs cannot verify each other, so replication fails TLS validation |

The slave install refuses to proceed if `.env` or the PKI directory is missing, and
checks that the shared secrets are actually present and non-empty rather than
assuming the copy worked.

---

## 6. Install the slave (VM2)

```bash
sudo ./scripts/2vm/install-2vm.sh \
     --role slave \
     --this 172.16.21.89 \
     --peer 172.16.21.88 \
     --vip  172.16.21.87
```

Note `--this` and `--peer` are **swapped** relative to the master.

The slave additionally rewrites two node-specific values that cannot come from the
master's copy of `.env`:

- `SENTINEL_PRIMARY_HOST` → the peer, since from here the primary *is* the peer
- `SENTINEL_CLICKHOUSE_URL_PRIMARY` → the master's ClickHouse, because this node has
  none and its event history would otherwise go nowhere

On an empty volume the standby takes a `pg_basebackup` from the primary and starts
streaming. On a populated volume it starts **without** re-cloning — deliberately, as
silently re-cloning could destroy the only surviving copy of your data.

---

## 7. Verify the pair

```bash
# On BOTH nodes — exactly one must hold the VIP
ip -4 addr show | grep 172.16.21.87

# On both
sudo ./scripts/2vm/install-2vm.sh --check

# On the SLAVE — must print 't'
docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc "SELECT pg_is_in_recovery();"

# On the MASTER — the standby must appear with state 'streaming'
docker exec sentinel-postgres-1 psql -U sentinel -d sentinel \
  -c "SELECT client_addr, state, sync_state, replay_lag FROM pg_stat_replication;"
```

If `pg_stat_replication` is **empty**, replication is not working and your standby is
a stale snapshot. Do not treat the deployment as protected until that shows
`streaming`.

### "No sites configured, node not eligible for the VIP"

Expected on a first install, and not a fault. The health check refuses a node
reporting `"sites":0`, because a WAF with no configuration would 502 every request —
and a node that cannot serve must not attract traffic. Add your first site and the
VIP comes up within a few seconds.

### What the health check actually tests

Not the host, and not Docker. It asks the data plane to **serve a real request**,
with `Host:` set to the VIP:

- `healthz` reporting `"status":"ok"` was measured lying in both directions — 200s
  while it claimed unhealthy, and 502s while it claimed healthy with
  `upstreams_healthy: 1`. So the self-report is a precondition, not the verdict.
- Any completed response — 200, 301, 401, even 403 — counts as healthy. Only 502,
  503, 504 and connection failure count as unable to serve.

Timings are deliberately asymmetric: **leave fast, return slowly.**
`fall 2` (~4 s) so a broken node stops attracting traffic quickly; `rise 5` (~10 s)
so a recovering node must be *continuously* healthy before reclaiming the VIP. A
recovering master with `rise 2` was measured reclaiming the VIP during origin
warm-up and serving 502s for ~11 seconds before releasing it again.

---

## 8. The failover drill — do this before going live

An untested failover is an assumption, not a capability.

```bash
# 1. Note which node holds the VIP
ip -4 addr show | grep 172.16.21.87

# 2. Put continuous traffic through the VIP from a third host
while true; do curl -sk -o /dev/null -w '%{http_code} ' https://172.16.21.87/; sleep 0.5; done

# 3. Kill the data plane on the holder — NOT the whole VM. This is the
#    interesting case: host alive, WAF dead.
docker stop sentinel-dataplane-1

# 4. Expect: VIP moves within ~4-6s, curl resumes. A few failures are normal.

# 5. Bring it back
docker start sentinel-dataplane-1

# 6. Expect: VIP returns to the master after ~10s of sustained health

# 7. Watch transitions on both nodes
tail -f /var/log/sentinel-vrrp.log
```

Then repeat with a hard `reboot` of the master. The two cases fail differently and
both are worth seeing.

---

## 9. When the master is genuinely lost

Traffic is already fine — the VIP moved and the survivor is protecting it. What is
blocked is configuration changes.

```bash
# On the surviving node, AFTER confirming the master is genuinely down and fenced
/path/to/promote-standby.sh
```

The script refuses to promote while it can still reach a healthy primary, reports
how far behind replication is (asynchronous — recent commits may not have arrived),
and requires you to type `PROMOTE`.

**Rebuilding the old master.** Its data directory has diverged and cannot follow the
new primary. Delete its volume and bring it up with the *passive* overlay pointing at
the new primary. The promotion script prints the commands.

---

## 10. Known limitations — state these, don't discover them

- **Replication DSNs are generated with `sslmode=disable`.** The installer warns
  about this. Replication streams the entire database across the network. Issue
  certificates and switch both DSNs to `verify-full` before this carries real
  traffic.

- **⚠️ Postgres client auth is weaker on the active node than on a standalone
  install, and this is not yet fixed.** `compose.prod.yml` starts Postgres with
  `-c hba_file=/etc/sentinel/pg/pg_hba.conf`, a file whose whole purpose is to
  reject cleartext TCP (`hostssl ... scram-sha-256`). Compose **replaces**
  `command` rather than merging it, and `compose.2vm-active.yml` re-specifies the
  command without `hba_file` — so the active node falls back to the stock
  `pg_hba.conf`, which ends in `host all all all scram-sha-256` (SSL not
  required). That happens on the one node that publishes 5432 to the network.

  It is not a one-line fix: `pg-init-replication.sh` appends the `hostssl
  replication` grant to `$PGDATA/pg_hba.conf`, which would be **ignored** if
  `hba_file` were restored, breaking replication. The correct fix is to ship a
  2-VM `pg_hba.conf` containing the replication grant templated with the standby
  CIDR, and restore `-c hba_file=...` to the overlay.

  Until then: keep 5432 reachable only from the peer (`SENTINEL_PG_BIND` binds it
  to the peer-facing address, but add a firewall rule too), and treat the
  replication link as an untrusted-network hop.
- **ClickHouse event history is not node-loss durable.** Two nodes cannot form a
  Keeper quorum, so a second instance would be a separate dataset, not a replica.
  Backups are the recovery mechanism.
- **Asynchronous replication** means a hard master loss can cost recent commits.
- **iptables rules are not persistent** without `iptables-persistent` (§4).
- **Redis rate limits are per-VM**, not fleet-wide.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Both nodes hold the VIP | VRRP password differs, or protocol 112 is blocked | Compare `/etc/sentinel/2vm-vrrp-pass` on both; check the path between them |
| Neither node holds the VIP | No sites configured, so both are correctly ineligible | Add a site |
| `cannot locate compose.prod.yml` | Script run from an unexpected layout | It auto-detects repo / bundle / installed trees; otherwise set `SENTINEL_COMPOSE_DIR` |
| `missing container images` | Images not loaded, and no bundle found to load from | Run from inside the extracted bundle, or build them — the error prints both commands |
| `pg_stat_replication` empty | Standby never attached | Check the PKI copy, `SENTINEL_PRIMARY_HOST`, and that 5432 is reachable from the slave |
| HTTPS to the WAF times out right after install | The ClickHouse firewall rule caught the data path | `iptables -L DOCKER-USER -n --line-numbers` — see §4 |
| VIP flaps | Origin warm-up flapping the health check | Expected briefly at startup; `rise 5` rides it out. Sustained flapping means the origin is genuinely unstable |

Transitions are logged to `/var/log/sentinel-vrrp.log` on both nodes.
