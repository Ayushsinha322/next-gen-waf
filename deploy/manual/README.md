# Next-Gen ESDSWAF — Operator Manual

## Installing? You need exactly one document

### 👉 **[INSTALL-WALKTHROUGH.md](../vm-deploy/INSTALL-WALKTHROUGH.md)**

Empty VM → download → install → dashboard open → a real attack blocked. **One
file, start to finish, nothing to cross-reference.** Every command can be copied
and pasted, and it was written by following it on a real machine.

Do not read anything else on this page until you have finished it.

---

## Afterwards — running the thing

These four are **reference**, not reading. Open the one that matches the question
you have:

| I want to… | Read |
|---|---|
| Put a real customer website behind the WAF, properly | **[SITE-ONBOARDING.md](SITE-ONBOARDING.md)** |
| Run it day to day — users, certificates, backups, upgrades | **[ADMIN-GUIDE.md](ADMIN-GUIDE.md)** |
| Fix something that is broken | **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** |
| Undo something | **[ROLLBACK.md](ROLLBACK.md)** |

> **Why is site onboarding covered twice?** The walkthrough adds a *test* site in
> five minutes, to prove the WAF works. SITE-ONBOARDING.md is for a **real
> customer application** — what to ask the app owner first, the settings that
> break real apps, the certificate, the DNS cutover, and the gate you must pass
> before switching on blocking. Use the walkthrough to learn the product; use
> SITE-ONBOARDING.md when someone is depending on it.

---

## The whole journey, once

```
Fresh VM  →  Install  →  Login  →  Add website  →  Backend  →  TLS  →  DNS  →  Test  →  Monitor
└─────── INSTALL-WALKTHROUGH.md ───────┘
                                   └────────────── SITE-ONBOARDING.md ──────────────────┘
```

## What the WAF actually is

A **reverse-proxy security gateway**. It sits in front of a website. Visitors
reach the WAF, the WAF inspects the request, and only acceptable requests are
passed to the real server behind it.

```
Visitor  →  public IP / DNS  →  WAF  →  application server  →  the website
```

The WAF is **not** the website, and it does not replace your network. It is the
doorway that checks who comes through.

---

## Four things worth knowing before you start

**1. A brand-new install returns `502` to everything.** That is correct — you have
not told it about any website yet, so there is nothing behind the door.

**2. The admin console is not reachable from your laptop directly.** It is bound
to `127.0.0.1` on purpose. Reach it through an SSH tunnel:

```bash
ssh -L 9443:127.0.0.1:9443 root@<vm-ip>       # then browse to https://127.0.0.1:9443
```

**3. Every new site must start in Learning mode**, not Blocking — even though the
wizard's dropdown starts on Blocking. Nobody has yet measured how the WAF treats
*your* application's normal traffic. Learning mode records what it would have
blocked without blocking it, so you find out safely.
[SITE-ONBOARDING.md](SITE-ONBOARDING.md) §3 and §8.

**4. The emergency brake is one dropdown.** If the WAF is ever blocking real
users, set that site's Security Mode to **Off**. Seconds, no restart, traffic
keeps flowing. [ROLLBACK.md](ROLLBACK.md) §1. Practise it once before you need it.

---

## Getting help

Escalate to ESDS / R&D with:

1. What you expected and what happened
2. The **request ID** — from the block page's Support ID, or from the Events page
3. The site name and the exact hostname used
4. The time, with timezone
5. `docker compose -p sentinel ps`
6. For install problems: `/var/log/sentinel/install.log`

A request ID turns a 30-minute investigation into a 30-second one. Get one before
you change anything.
