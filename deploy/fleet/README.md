# Internal fleet releases

How the engineering team updates **our own** boxes. Customers never see this
directory — `deploy/package/build-bundle.sh` stages an explicit allowlist of
files into the release bundle, and `deploy/fleet/` is not on it.

| | Internal fleet (this directory) | Customer install |
|---|---|---|
| Artefact | images shipped node-to-node as a `docker save` tarball | versioned release bundle |
| Entry point | `deploy/fleet/fleet.sh` | `install.sh` inside the bundle |
| Inventory | `deploy/fleet/fleet.conf` | the customer's own host |

## The one command

```bash
./deploy/fleet/fleet.sh release
```

That is: build locally → ship images **and source** to every node → roll each
node's services in order → verify. Add `--dry-run` to print every command and
change nothing, or `--only waf-active` to target a single node.

```bash
./deploy/fleet/fleet.sh status            # what is each node running? (read-only)
./deploy/fleet/fleet.sh verify            # post-deploy checks only
./deploy/fleet/fleet.sh release --dry-run
```

## Why images are built once and shipped

A data-plane build is ~14 min on the demo host and ~35 min on the pair — any
change to `sentinel-core` invalidates the Rust dependency graph, so it is a cold
release build with LTO. Shipping the same image between nodes takes ~8 s
(measured). Building once and shipping is the right trade, and it also
guarantees byte-identical images across the fleet instead of three builds that
merely *ought* to agree.

## Why `ship` always syncs the source

On 2026-08-10 the ship-a-tarball approach was run by hand, and the hand-run
version skipped the source sync. All three VMs then ran `main` while
`/opt/sentinel-src` sat 21 commits behind. Nothing appeared wrong — every box was
healthy, serving and protecting. The damage was latent: the next
`docker compose build` on any node would have rebuilt the stale tree and silently
reverted three fixes (the `@pm` case-insensitivity fix, the `accept(2)`
classifier, the ML de-fabrication), and reported success while doing it.

So the coupling is structural, not remembered:

- `ship` calls the sync itself. There is no flag to skip it.
- Every image carries its commit in `org.opencontainers.image.revision`, so
  *"what is this node running?"* is one `docker image inspect` away. Before the
  label existed, answering it meant `docker cp`-ing the binary out of a
  distroless image and grepping it for a string only the new build contained.
- `status` prints source commit, image revision and container image per node, so
  drift is visible before it matters rather than after.

## What it refuses to do

| Guard | Why |
|---|---|
| Build or ship from a dirty tree | A label that names a commit must describe those bits. `--allow-dirty` stamps `-dirty`; `ship` still refuses it without `--force`. |
| Ship an image labelled `unknown` | An unlabelled image is one whose provenance we would have to reconstruct later. |
| Roll a node whose containers were created with a different compose file set than its role declares | On 2026-08-07 a roll with `compose.prod.yml` **alone** on a pair node dropped the active overlay. Replication died, `.89` lost its ClickHouse sink, and connection-layer blocking silently switched off. |
| Sync `deploy/` or any `.env` | The node copies carry drift invisible to git (`SENTINEL_TRUSTED_PROXIES`) and gitignored secrets. Syncing `deploy/docker/.env` on 2026-07-27 silently downgraded the control plane to plaintext Postgres and broke the audit HMAC chain. |

## Inventory

`fleet.conf` is `name host role ssh_key`, and **the order of lines is the roll
order**. The passive node of a pair is listed before the active one on purpose:
recreating the active data plane moves the VIP (~3.5 s, measured), and it should
move to a node that already carries the new build.

`role` selects the compose file set and the service roll order — it is the single
source of truth for both, so no caller can improvise a `docker compose` line:

| role | compose files | roll order |
|---|---|---|
| `standalone-ha` | `prod` + `cluster` + `ha` | cp2, cp3, controlplane, waf2, waf3, waf1, dashboard |
| `pair-active` | `prod` + `2vm-active` | controlplane, dataplane, dashboard |
| `pair-passive` | `prod` + `2vm-passive` | controlplane, dataplane, dashboard |
| `standalone` | `prod` | controlplane, dataplane, dashboard |

## Rollback

`ship` tags the outgoing images `sentinel/<svc>:rollback-<UTC timestamp>` on each
node before repointing `:latest`. To go back:

```bash
ssh root@<host> 'docker tag sentinel/dataplane:rollback-20260811-053000 sentinel/dataplane:latest'
./deploy/fleet/fleet.sh roll --only <name>
```

Note what rollback does **not** cover: database migrations. `goose` is applied
by the `migrate` service and is not reversed by retagging an image. Take a dump
before any release that carries a new migration.

## Expected output on a fleet built before this landed

`status` will report `<unlabelled: built before provenance landed>` for images
built prior to 2026-08-11. That is honest, not a fault — those images genuinely
carry no revision label. The first `release` replaces them with labelled ones.
