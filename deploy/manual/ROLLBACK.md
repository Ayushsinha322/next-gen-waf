# Swaraj Kavach — Rollback and Recovery

**Who this is for:** whoever is holding the problem right now. Sections are
ordered **fastest and safest first**. Start at the top and only go further down if
the one above does not solve it.

> ## Before you undo anything — 15 seconds well spent
>
> **Capture the evidence first.** Take the **request ID** from the block page or
> from Events, and note the time. Once you change or remove the configuration,
> the reason it went wrong is gone, and you will be guessing next time.
>
> The one exception: if customers are down right now, use §1 immediately and
> collect evidence afterwards. Restoring service wins.

---

## Which one do I need?

| Situation | Use | Takes | Loses |
|---|---|---|---|
| The WAF is blocking real users **right now** | **§1 — Mode: Off** | Seconds | Nothing |
| Blocking is too aggressive, but you want to keep watching | **§2 — Mode: Learning** | Seconds | Nothing |
| You need the WAF completely out of the path | **§3 — DNS back to origin** | DNS propagation | Nothing |
| This site should not exist at all | **§4 — Delete the site** | Seconds | That site's config |
| A new version misbehaves | **§5 — Version rollback** | ~5 min | Possibly data, read carefully |
| Data is corrupt or lost | **§6 — Restore from backup** | 15+ min | Everything since the backup |
| Remove the WAF from this VM | **§7 — Uninstall** | ~2 min | Nothing, unless `--purge` |

---

## 1. Emergency brake — set the site to Off

**Use this when legitimate users are being blocked and you need it to stop now.**

Console → **Sites** → the site → **Security Mode** → **Off** → save.

- Takes effect in **seconds**. No restart. Other sites are unaffected.
- Traffic **keeps flowing** to the application — the WAF still proxies, it just
  stops inspecting.
- The website stays up. You have removed protection, not availability.

**Verify it worked** — reproduce the request that was being blocked. It should now
succeed.

This is the correct first move in almost every "the WAF broke our app" situation.
It buys you time to diagnose properly with
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) §5 instead of working under pressure.

**Afterwards:** do not leave it Off and forget. Find the false positive, fix it
narrowly, and go back to Learning and then Blocking.

---

## 2. Step down to Learning mode

**Use this when blocking is causing problems but you still want visibility.**

Console → **Sites** → the site → **Security Mode** → **Learning** → save.

The WAF inspects everything and records what it *would* have blocked, without
blocking it. You keep the full detection picture with none of the customer impact.

This is the better choice than **Off** whenever users are not actively broken,
because you keep collecting the data you need to fix the underlying problem.

---

## 3. Take the WAF out of the path completely

**Use this when the WAF itself is the problem** — the VM is down, the whole node
is unhealthy, or you cannot explain what is happening and the business needs the
application back.

Ask the DNS / network team to point the hostname **back at the origin server**, or
back at whatever was in front of it before (an F5, a load balancer).

```
Before:  www.customer.com → WAF → origin
After:   www.customer.com → origin
```

Be aware:

- **DNS caching means this is not instant.** How long depends on the record's TTL.
  If you expect ever to need this, ask the DNS team to lower the TTL *before* the
  cutover, not during the incident.
- The application is now **unprotected**. Tell whoever needs to know.
- If the certificate lived on the WAF, the origin needs its own valid certificate
  or visitors get warnings.

**This is worth rehearsing once, in a maintenance window, before you need it.** A
rollback path nobody has tested is not a rollback path.

---

## 4. Delete a site

**Use this when the site should not exist** — created by mistake, wrong customer,
or a test you are finished with.

Console → **Sites** → the site → Delete.

**Verify it is actually gone** rather than assuming:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Host: www.customer.com' https://127.0.0.1/
```

Expect **404** with the WAF's own message, "No site is configured for this
hostname" — no site claims that name any more. If you still get 200, the deletion has not reached the data plane yet;
wait about 5 seconds for the next configuration poll and check again.

Deleting a site removes its configuration. Its recorded events stay in the event
store for history.

---

## 5. Roll back to the previous version

**Use this when an upgrade went wrong** — a regression under real traffic, a
behaviour change you do not want, detections misfiring on your workload.

> **`upgrade.sh` already rolls back on its own** if its health checks fail. This
> section is for the other case: the upgrade passed its checks, was committed, and
> a problem appeared later.

### What to run

```bash
sudo ./rollback.sh --list          # what you can roll back to
sudo ./rollback.sh                 # back to the recorded previous version
sudo ./rollback.sh --to 1.0.0      # back to a specific version
```

### Read this before you run it

**Container images roll back completely.** They are still on disk, so switching
back is a restart.

**Database schema does not.** Migrations are **forward-only** — there is no
"un-migrate". This gives two very different outcomes:

| The upgrade you are undoing | What rollback does |
|---|---|
| Applied **no** migrations | Clean and complete. Old images, same data. Nothing lost |
| **Did** apply migrations | Old code will be running against a newer schema — **not a supported state**. A complete rollback then also needs the pre-upgrade database restored |

Restoring the pre-upgrade database means **discarding everything written since the
upgrade**: sites added, rules edited, users created, and all attack history in
between. That is a real cost, which is why the script never does it silently:

```bash
sudo ./rollback.sh --restore-db     # explicit, and it will confirm with you
```

**The script detects which case you are in and tells you**, rather than reporting
a clean rollback it did not actually perform. Read what it prints.

### After a rollback

```bash
sudo ./verify.sh
```

Then test a real site end to end, and tell R&D what happened and why you rolled
back — that is the information that prevents the next release repeating it.

---

## 6. Restore from backup

**Use this when data is lost or corrupt** — a failed VM, a bad restore, an
accidental mass deletion.

```bash
sudo /opt/sentinel/current/scripts/backup/restore.sh
```

Full procedure: `scripts/backup/RUNBOOK.md`.

**Understand the cost first:**

- A restore returns the system to **exactly** the moment the backup was taken.
- **Everything after that point is gone** — sites added, policy changes, users,
  and all event history in between.
- You also need `/opt/sentinel/current/.env` from the same period. It holds every
  generated secret; without the matching one, a restore cannot reconnect to its
  own databases.

**Check what you have before you begin:**

```bash
ls -la /var/backups/sentinel/          # or your configured BACKUP_ROOT
```

Pick the most recent backup **from before the problem started** — not simply the
newest, which may already contain the damage.

> **If you have never run `drill.sh`, an incident is a bad time to find out
> whether your backups restore.** Run the drill once when you set backups up, and
> quarterly after that. [ADMIN-GUIDE.md](ADMIN-GUIDE.md) §6.

---

## 7. Uninstall

```bash
sudo ./uninstall.sh              # removes containers, KEEPS all data
sudo ./uninstall.sh --purge      # ALSO DESTROYS all data — IRREVERSIBLE
```

**Keeping data is the default deliberately.** "I only wanted to reinstall" is the
common case, and an uninstall that silently destroys the configuration database,
the attack history and the certificate authority is not recoverable.

`--purge` removes the data volumes: configuration, event history, certificates,
the internal certificate authority. There is no undo. **Take a backup first, even
if you are certain.**

After a plain uninstall you can reinstall and your sites, users and history are
still there.

---

## Undo anything you changed in the console

Console → **Audit**. It records who changed what, and when. Use it to see the
previous value of a setting so you can put it back deliberately, instead of
reconstructing it from memory.

---

## Rehearse these

The two worth practising in a maintenance window, before you need them:

1. **§1 — Mode: Off.** Everyone on the on-call rota should have done this once.
   It is the single most useful action during an incident, and it should be muscle
   memory, not something read for the first time under pressure.
2. **§3 — DNS back to the origin.** Confirm the origin still works when reached
   directly, and confirm you know the current TTL.

## Related

- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — diagnose before you undo
- [ADMIN-GUIDE.md](ADMIN-GUIDE.md) — backups, upgrades, escalation
- [SITE-ONBOARDING.md](SITE-ONBOARDING.md) — the go-live gate that prevents most of this
