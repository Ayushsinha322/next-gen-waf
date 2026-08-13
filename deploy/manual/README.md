# Next-Gen ESDSWAF — Operator Manual

Five documents. **Start with the one that matches what you are doing right now.**

| I want to… | Read | Time |
|---|---|---|
| Install the WAF on a fresh VM | **[INSTALL.md](INSTALL.md)** | 30 min |
| Put a website behind the WAF | **[SITE-ONBOARDING.md](SITE-ONBOARDING.md)** | 20 min + a learning period |
| Run it day to day — users, certificates, backups, upgrades | **[ADMIN-GUIDE.md](ADMIN-GUIDE.md)** | reference |
| Fix something that is broken | **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** | reference |
| Undo something | **[ROLLBACK.md](ROLLBACK.md)** | reference |

You do not need to read these in order, and you do not need to know how the WAF
works internally to use them.

---

## The whole journey, once

```
Fresh VM  →  Install  →  Login  →  Add website  →  Backend  →  TLS  →  DNS  →  Test  →  Monitor
└──────────── INSTALL.md ────────┘  └──────────────── SITE-ONBOARDING.md ────────────────────┘
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
