# C4 — per-field "Use global / Customize" inheritance: scope

**Status: scoped, not built.** The fix list calls this "the one genuine
architectural gap in our UX; scope it properly rather than rushing it", and that
is the right call. This document says what it actually requires, why the obvious
shortcut is dangerous in this codebase specifically, and how it splits into
phases that can each ship on their own.

## What is being asked for

SafeLine's Advanced tab gives every setting a two-state control: **Use global**
or **Customize**. When it is inherited, the field is greyed but still shows the
inherited value, so an operator can see at a glance exactly which settings this
site overrides and what it would fall back to.

We have 127 fields per site and no equivalent. With that many fields, nobody can
tell what they changed from what shipped — which is the real complaint. It is not
about the control; it is that the current design makes a site's configuration
unreadable.

## Why this is not a UI change

The console cannot render an inheritance state that the data model does not
have. Three separate things are missing.

**1. There is no tenant-level notion of site defaults.**

`global_settings` (`control-plane/internal/db/settings_store.go`) already has
exactly the right shape — `(tenant_id, key, value)` with a `source` of
`db | env | default` and a Reset that drops the override so the value falls back.
That is precisely the tri-state model this feature needs.

But it holds **node-wide operational** settings — logging, limits, cluster sync.
It is not a store of default *site policy*, and a site's `waf_policy` does not
consult it. So the thing a field would inherit *from* does not exist yet.

**2. A stored site policy cannot express "not set".**

`buildRustWaf` (`control-plane/cmd/controllerd/handlers.go:1988`) unmarshals the
stored blob into a struct of concrete values:

```go
ParanoiaLevel    int    `json:"paranoia_level"`
AnomalyThreshold int    `json:"anomaly_threshold"`
```

After unmarshalling, an absent `paranoia_level` and a stored `0` are the same
value. Inheritance requires telling those apart for every inheritable field —
pointers (`*int`), or a separate explicit set of overridden keys.

**3. `buildRustWaf` is an allowlist.**

A `waf_policy` key it does not name is stored, echoed back to the console, and
silently dropped before it reaches the data plane. This has already produced a
class of bug in this repository six times over: the control plane reports
success and the data plane never acts.

That makes the tempting shortcut — "just leave inherited fields out of the
payload" — the worst available option. Omitted fields would land in exactly the
path that discards silently, and the console would show an inherited value that
the data plane resolved differently or not at all. **A wrong inheritance
implementation is worse than none**, because the current design is at least
honest: every value shown is a value that was sent.

## Phases

Each phase is independently shippable and independently useful.

### Phase 1 — show what differs from the shipped defaults (UI only, no schema)

`emptyForm()` in `dashboard/lib/siteConfig.ts` is already the single source of
shipped defaults. Diff the loaded site against it and mark every field that
differs, with the default shown alongside.

This answers most of the actual complaint — "nobody can tell what they changed
from what shipped" — needs no backend change, and cannot introduce a
silently-inert path because nothing about the payload changes. **Do this first.**
It is perhaps a day, and it is most of the perceived value.

### Phase 2 — tenant-level site defaults

A `site_defaults` store keyed like `global_settings`, seeded from `emptyForm()`,
with its own screen. Sites keep storing complete policies; this only establishes
what "global" *means* so Phase 3 has something to inherit from.

### Phase 3 — a real override set

Add an explicit `overridden: ["paranoia_level", "rate_limit.rps", …]` list to
the stored site policy, and resolve at sync time:

```
effective = overridden.contains(key) ? site[key] : site_defaults[key] ?? shipped_default[key]
```

Resolution must happen in **one** place, server-side, and both the sync path and
`GET /sites/:id/effective` must call it. Two resolvers is the same bug in a new
coat.

Non-negotiable for this phase:

* Every inheritable field becomes a pointer or is gated on the override set, so
  absent is distinguishable from zero.
* `buildRustWaf`'s allowlist is extended in the same commit as any new key.
  Adding a field is two changes — frontend and Go — and always has been.
* A test that asserts, for every inheritable field, that changing the tenant
  default changes the effective config of a non-overriding site, and does **not**
  change an overriding one. Without that test this feature is unverifiable by
  inspection.

### Phase 4 — the per-field control

Only now is the two-state control implementable: a toggle per field, the
inherited value greyed but visible, and a site-level "12 settings overridden"
summary. The Effective Config tab gains a third state — inherited, overridden,
and drifted-on-the-data-plane — which is the thing that would make a 127-field
site readable at last.

## Estimate

Phase 1 alone is a day and captures most of the value. Phases 2–4 are a sprint,
not an afternoon: a schema change, a resolver with a test matrix over ~127
fields, and a UI pass across ten wizard steps. It should not be started in the
same week as an internal beta.

## Recommendation

Ship Phase 1 now. Schedule 2–4 deliberately, after the beta, and treat the
resolver test matrix as the deliverable that makes the rest safe — not as
optional hardening.
