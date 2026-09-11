#!/usr/bin/env python3
"""
Generate deploy/TOPOLOGY.md — one readable page describing what actually runs.

WHY THIS EXISTS

Production is three compose files with an override chain, well over a thousand
lines in total (the generated page reports the current count). The comparison
product describes its entire deployment in one 143-line file. That is not a reason to restructure ours — the overrides buy real things
(an HA fleet, a control-plane cluster, profile-gated demo content) — but it does
mean no operator can hold the topology in their head, and the answer to "what
talks to what, and which file decided that?" currently requires reading all
three and mentally applying the merge.

So generate the answer from the merge itself. Derived, never hand-written: a
hand-written topology document describes last month's deployment.

    deploy/gen-topology.py            # write deploy/TOPOLOGY.md
    deploy/gen-topology.py --check    # exit 1 if it is out of date

`docker compose config` only parses and interpolates — it never contacts a
daemon — so this works anywhere the CI image runs. Secrets are supplied as
obvious placeholders because compose interpolates every variable before it
filters by profile, and would otherwise refuse to parse.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCKER = REPO / "deploy" / "docker"
OUT = REPO / "deploy" / "TOPOLOGY.md"

FILES = ["compose.prod.yml", "compose.cluster.yml", "compose.ha.yml"]

# Placeholders only. compose interpolates before profile filtering, so every
# referenced variable must resolve or the parse fails; none of these reach a
# container.
PLACEHOLDER_ENV = {
    "POSTGRES_USER": "x", "POSTGRES_PASSWORD": "x", "POSTGRES_DB": "x",
    "SENTINEL_DB_URL": "x", "SENTINEL_DB_URL_PRIMARY": "x",
    "SENTINEL_JWT_SECRET": "x", "SENTINEL_INTERNAL_SECRET": "x",
    "CLICKHOUSE_USER": "x", "CLICKHOUSE_DB": "x", "CLICKHOUSE_PASSWORD": "x",
    "SENTINEL_AUDIT_HMAC_KEY": "x",
}


def compose_config(profile: bool) -> dict | None:
    cmd = ["docker", "compose", "--env-file", os.devnull]
    if profile:
        cmd += ["--profile", "demo"]
    for f in FILES:
        cmd += ["-f", f]
    cmd += ["config", "--format", "json"]
    env = {**os.environ, **PLACEHOLDER_ENV}
    try:
        r = subprocess.run(cmd, cwd=DOCKER, capture_output=True, text=True,
                           timeout=300, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def defining_files() -> dict[str, list[str]]:
    """Which compose file mentions each service, in override order."""
    out: dict[str, list[str]] = {}
    for f in FILES:
        try:
            text = (DOCKER / f).read_text()
        except OSError:
            continue
        in_services = False
        for line in text.splitlines():
            if line.startswith("services:"):
                in_services = True
                continue
            if in_services and line and not line[0].isspace():
                in_services = False
            if in_services and len(line) > 2 and line.startswith("  ") \
                    and not line[2].isspace() and line.rstrip().endswith(":"):
                name = line.strip().rstrip(":")
                out.setdefault(name, [])
                if f not in out[name]:
                    out[name].append(f)
    return out


def image_healthcheck_targets() -> set[str]:
    """Build targets in deploy/docker/Dockerfile that bake a HEALTHCHECK.

    Compose only knows about healthchecks declared in compose. Ours live in the
    Dockerfile for the distroless images (there is no shell in them, so the check
    is a static probe binary), and a topology page that reported "no health" for
    a container the deployment shows as `healthy` would be worse than silent.
    """
    try:
        text = (DOCKER / "Dockerfile").read_text()
    except OSError:
        return set()
    targets, current = set(), None
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("FROM ") and " AS " in st:
            current = st.rsplit(" AS ", 1)[1].strip()
        elif st.startswith("HEALTHCHECK") and current:
            targets.add(current)
    return targets


def fmt_ports(svc: dict) -> str:
    ports = svc.get("ports") or []
    bits = []
    for p in ports:
        if isinstance(p, dict):
            host = p.get("published", "")
            ip = p.get("host_ip", "")
            tgt = p.get("target", "")
            bits.append(f"{ip + ':' if ip else ''}{host}→{tgt}")
        else:
            bits.append(str(p))
    return ", ".join(bits) or "—"


def fmt_deps(svc: dict) -> str:
    d = svc.get("depends_on") or {}
    if isinstance(d, dict):
        return ", ".join(sorted(d)) or "—"
    return ", ".join(sorted(d)) or "—"


def build() -> str:
    cfg = compose_config(profile=True)
    if cfg is None:
        raise SystemExit("docker compose config failed — cannot generate topology")
    base = compose_config(profile=False) or {"services": {}}
    always_on = set(base.get("services") or {})

    services = cfg.get("services") or {}
    volumes = cfg.get("volumes") or {}
    networks = cfg.get("networks") or {}
    owners = defining_files()

    total_lines = 0
    for f in FILES:
        try:
            total_lines += len((DOCKER / f).read_text().splitlines())
        except OSError:
            pass

    hc_targets = image_healthcheck_targets()
    ours = [n for n, s in services.items()
            if str(s.get("image", "")).startswith(("sentinel/", "${SENTINEL_IMAGE_PREFIX"))]

    L = []
    L.append("# Deployment topology\n")
    L.append(
        "**Generated** by `deploy/gen-topology.py` from the merged compose "
        f"configuration. Do not edit by hand.\n\n"
        f"The production deployment is **{len(FILES)} compose files, {total_lines} lines**, "
        "applied as an override chain:\n\n")
    for i, f in enumerate(FILES, 1):
        L.append(f"{i}. `deploy/docker/{f}`\n")
    L.append(
        "\nLater files override earlier ones. Every command against this deployment "
        "must pass all three `-f` flags in this order, plus `--profile demo` on a "
        "demo or pilot box — a profile gates what is **recreated** as well as what "
        "starts, so omitting it silently leaves those containers on their old "
        "image and configuration.\n\n")

    L.append(f"## Services ({len(services)})\n\n")
    L.append(
        "Image tags read `:latest` here because `SENTINEL_VERSION` is not set when this "
        "page is generated; on a deployment the tag is that variable's value. "
        "**Health** is `compose` for a check declared in compose, `image` for one baked "
        "into the Dockerfile — the distroless images have no shell, so theirs is a static "
        "probe binary (`control-plane/cmd/healthprobe`) and compose cannot see it.\n\n")
    L.append("| Service | Image | Ports | Depends on | Health | Starts by default |\n")
    L.append("|---|---|---|---|---|---|\n")
    for name in sorted(services):
        s = services[name]
        img = str(s.get("image", "—"))
        if s.get("healthcheck") and not (s.get("healthcheck") or {}).get("disable"):
            hc = "compose"
        elif any(f"sentinel-{t}" in img or f"sentinel/{t}" in img
                 for t in ("dataplane", "controlplane")) and hc_targets:
            hc = "image"
        else:
            hc = "—"
        prof = "yes" if name in always_on else f"profile: {', '.join(s.get('profiles') or [])}"
        L.append(f"| `{name}` | `{img}` | {fmt_ports(s)} | {fmt_deps(s)} | {hc} | {prof} |\n")

    L.append("\n### Which file defines each service\n\n")
    L.append("| Service | Defined / overridden in |\n|---|---|\n")
    for name in sorted(services):
        chain = owners.get(name) or ["—"]
        L.append(f"| `{name}` | {' → '.join(chain)} |\n")

    L.append(f"\n## Our own images ({len(ours)})\n\n")
    L.append("Everything else is third-party and pulled at install time. "
             "See `THIRD-PARTY-NOTICES.md`.\n\n")
    for n in sorted(ours):
        L.append(f"- `{n}` — `{services[n].get('image')}`\n")

    L.append(f"\n## Named volumes ({len(volumes)})\n\n")
    L.append("State that survives a container. Anything not listed here is lost on "
             "recreate.\n\n")
    for v in sorted(volumes):
        users = sorted(n for n, s in services.items()
                       if any((m or {}).get("source") == v
                              for m in (s.get("volumes") or []) if isinstance(m, dict)))
        L.append(f"- `{v}` — used by {', '.join(f'`{u}`' for u in users) or '(nothing)'}\n")

    L.append(f"\n## Networks ({len(networks)})\n\n")
    for n in sorted(networks):
        L.append(f"- `{n}`\n")

    L.append("\n## Bind mounts from inside the source tree\n\n"
             "These are the paths a `rsync --delete` of the repository can destroy on a "
             "host. `deploy/sync-to-host.sh --list-runtime-mounts <host>` classifies what "
             "is actually mounted on a running deployment; run that rather than trusting "
             "this list, which is only what the compose files declare.\n\n")
    seen = set()
    for name in sorted(services):
        for m in (services[name].get("volumes") or []):
            if isinstance(m, dict) and m.get("type") == "bind":
                src = str(m.get("source", ""))
                if "/deploy/docker" in src and src not in seen:
                    seen.add(src)
                    rel = src.split("/deploy/docker/", 1)[-1]
                    L.append(f"- `deploy/docker/{rel}` → `{m.get('target')}`\n")
    if not seen:
        L.append("_None declared._\n")
    return "".join(L)


def main() -> int:
    text = build()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("deploy/TOPOLOGY.md is out of date — run deploy/gen-topology.py",
                  file=sys.stderr)
            return 1
        print("deploy/TOPOLOGY.md is up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(REPO)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
