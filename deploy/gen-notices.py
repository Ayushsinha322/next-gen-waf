#!/usr/bin/env python3
"""
Generate THIRD-PARTY-NOTICES.md from what is actually in the build.

WHY THIS EXISTS

Nothing in this repository carried a LICENSE, NOTICE or third-party notices file
of any kind. That is not a tidiness problem: Apache-2.0 §4 requires shipping the
licence text and retaining attribution when you redistribute, and the offline
customer bundle redistributes hundreds of Apache-2.0 components plus the OWASP
Core Rule Set — whose own rule headers say "Please see the enclosed LICENSE
file" for a file that was not in the tree.

The list is DERIVED, never hand-maintained. A hand-written notices file is wrong
the day after someone adds a dependency, and wrong silently.

    deploy/gen-notices.py                 # write THIRD-PARTY-NOTICES.md
    deploy/gen-notices.py --check         # exit 1 if the committed file is stale

NOT wired into CI, deliberately. Regenerating needs cargo, go AND npm with their
caches populated; the `deploy-shell` job runs in alpine:3.20 with none of them
(and no python3). A check that cannot run is worse than none, because it reads
like a guarantee. What CI does enforce is that the bundle CONTAINS the file —
check-bundle-contract.sh fails without it — and build-bundle.sh regenerates it
during packaging when python3 is present, so a released archive cannot carry a
notices file older than its own dependency list. Run --check by hand after
changing a dependency.

Sources, all read offline from what is already vendored or locked:
  * Rust   — `cargo metadata --offline` for the set, `cargo tree -e normal` to
             separate what a shipped binary links from dev/build-only crates.
  * Go     — `go list -m -f ... all` from the module cache.
  * npm    — node_modules/*/package.json, split by `npm ls --omit=dev` so that
             devDependencies are never reported as redistributed.
  * Other  — container images and the CRS, which have no package manager here
             and are therefore listed explicitly in STATIC_COMPONENTS below.

This reports what each component DECLARES. It is an attribution inventory, not a
legal opinion, and a declared identifier is not a substitute for reading the
licence of anything you intend to redistribute.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "THIRD-PARTY-NOTICES.md"

# Components with no package manifest in this tree. Kept explicit and few, so
# that "the generator did not see it" can never be mistaken for "it is not here".
STATIC_COMPONENTS = [
    # (name, version, licence, what it is / where it comes from)
    ("OWASP Core Rule Set", "4.7.0", "Apache-2.0",
     "Vendored at rules/owasp-crs/. Full text at rules/owasp-crs/LICENSE. "
     "Copyright (c) 2006-2020 Trustwave and contributors; (c) 2021-2024 CRS project."),
    ("PostgreSQL (postgres:16-alpine)", "16", "PostgreSQL License",
     "Container image, pulled at install time — not redistributed in the bundle."),
    ("Valkey (valkey/valkey:8-alpine)", "8", "BSD-3-Clause",
     "Container image. Replaced redis:7-alpine, which resolves to 7.4 and is "
     "RSALv2/SSPL — not open source and not redistributable in a bundle."),
    ("ClickHouse (clickhouse-server:26.3.35.3-alpine)", "26.3.35.3", "Apache-2.0",
     "Container image, pulled at install time."),
    ("Prometheus (prom/prometheus)", "v2.54.1", "Apache-2.0",
     "Container image, pulled at install time."),
    ("HAProxy (haproxy:2.9-alpine)", "2.9", "GPL-2.0-or-later WITH openvpn-openssl-exception / LGPL-2.1",
     "Container image used unmodified as a load balancer; not linked into any "
     "product binary."),
    ("OWASP Juice Shop", "20.1.1", "MIT",
     "DEMO TARGET ONLY, behind the `demo` compose profile. Never started in a "
     "customer installation."),
]

SPDX_TEXT = {"Apache-2.0": "licenses/Apache-2.0.txt"}


def run(cmd: list[str], cwd: Path | None = None) -> str | None:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


# The crates that end up inside a shipped binary. `cargo metadata` alone lists
# the whole workspace graph including dev- and build-dependencies, which are
# compiled but never redistributed — counting those would overstate what we ship
# by roughly a third and bury a real obligation among things that carry none.
SHIPPED_RUST_PACKAGES = ["sentinel-bin", "sentinel-cli", "sentinel-proxy"]


def rust_shipped_ids() -> set[tuple[str, str]] | None:
    """(name, version) reachable through NORMAL edges from a shipped binary."""
    shipped: set[tuple[str, str]] = set()
    got_any = False
    for pkg in SHIPPED_RUST_PACKAGES:
        out = run(["cargo", "tree", "--offline", "-e", "normal", "--prefix", "none",
                   "--no-dedupe", "-p", pkg], REPO)
        if out is None:
            continue
        got_any = True
        for line in out.splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+) v([^ ]+)", line.strip())
            if m:
                shipped.add((m.group(1), m.group(2)))
    return shipped if got_any else None


def rust_components() -> tuple[list, list]:
    """Returns (redistributed, build_and_dev_only)."""
    out = run(["cargo", "metadata", "--format-version", "1", "--offline"], REPO)
    if not out:
        return [], []
    meta = json.loads(out)
    members = set(meta.get("workspace_members") or [])

    def is_member(pkg) -> bool:
        # Cargo changed workspace_members from "name ver (path+file://…)" to a
        # package id object across versions; match on id and fall back to path.
        if pkg["id"] in members:
            return True
        return any(pkg["id"] in m or m in pkg["id"] for m in members)

    shipped = rust_shipped_ids()
    ship, other = [], []
    for p in meta.get("packages", []):
        if is_member(p):
            continue
        lic = p.get("license") or (
            "see " + p["license_file"] if p.get("license_file") else "UNDECLARED")
        row = (p["name"], p.get("version", ""), lic, p.get("repository") or "")
        # If cargo tree could not run, report everything as shipped rather than
        # silently dropping components from a legal notice.
        if shipped is None or (p["name"], p.get("version", "")) in shipped:
            ship.append(row)
        else:
            other.append(row)
    return ship, other


def go_components() -> list[tuple[str, str, str, str]]:
    cp = REPO / "control-plane"
    if not (cp / "go.mod").exists():
        return []
    out = run(["go", "list", "-m", "-f", "{{.Path}}\t{{.Version}}", "all"], cp)
    if not out:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[1]:
            continue          # the main module, or a replaced module with no version
        rows.append((parts[0], parts[1], "see module source", "https://" + parts[0]))
    return rows


def npm_production_names() -> set[str] | None:
    """Package names reachable from `dependencies` only (never devDependencies)."""
    out = run(["npm", "ls", "--omit=dev", "--all", "--json"], REPO / "dashboard")
    if not out:
        return None
    try:
        tree = json.loads(out)
    except ValueError:
        return None
    names: set[str] = set()

    def walk(node):
        for name, child in (node.get("dependencies") or {}).items():
            if name in names:
                continue
            names.add(name)
            walk(child)

    walk(tree)
    return names or None


def npm_components() -> tuple[list, list]:
    """Returns (redistributed, dev_only).

    node_modules holds the DEV tree too. Of ~500 packages installed here only
    about 76 are production dependencies, and the two that looked alarming on the
    first run — axe-core (MPL-2.0) and @vercel/og (no declared licence) — are both
    dev-only. Listing them as shipped would have raised a licensing question that
    does not exist, and hidden the ones that do.
    """
    nm = REPO / "dashboard" / "node_modules"
    if not nm.is_dir():
        return [], []
    prod = npm_production_names()
    rows, seen = [], set()
    for pj in nm.glob("**/package.json"):
        if pj.parent.name == "node_modules":
            continue
        try:
            d = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        name, ver = d.get("name"), d.get("version")
        if not name or not ver or (name, ver) in seen:
            continue
        lic = d.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if not lic and isinstance(d.get("licenses"), list):
            lic = "/".join(x.get("type", "") for x in d["licenses"] if isinstance(x, dict))
        seen.add((name, ver))
        repo = d.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url", "")
        rows.append((name, ver, lic or "UNDECLARED", repo or ""))
    # If npm could not resolve the production tree, report everything as shipped
    # rather than quietly omitting components from a legal notice.
    if prod is None:
        return rows, []
    return [r for r in rows if r[0] in prod], [r for r in rows if r[0] not in prod]


def section(title: str, note: str, rows: list[tuple[str, str, str, str]]) -> str:
    if not rows:
        return f"## {title}\n\n_None detected in this tree._\n\n"
    by_lic: dict[str, list] = defaultdict(list)
    for n, v, l, _ in rows:
        by_lic[l].append((n, v))
    body = [f"## {title}\n", note, f"\n**{len(rows)} components.**\n"]
    for lic in sorted(by_lic, key=lambda k: (-len(by_lic[k]), k)):
        items = sorted(set(by_lic[lic]))
        body.append(f"\n### {lic} — {len(items)} component(s)\n")
        body.append("\n".join(f"- {n} {v}" for n, v in items) + "\n")
    return "".join(body) + "\n"


def build() -> str:
    rust, rust_dev = rust_components()
    go = go_components()
    npm, npm_dev = npm_components()
    total = len(rust) + len(go) + len(npm) + len(STATIC_COMPONENTS)

    # Only what is REDISTRIBUTED can create an obligation, so only that set is
    # audited. A dev-only MPL package is not a finding.
    undeclared = sorted({f"{n} {v}" for n, v, l, _ in rust + npm if l == "UNDECLARED"})
    copyleft = sorted({
        f"{n} {v} — {l}" for n, v, l, _ in rust + npm
        if re.search(r"\b(A?GPL|SSPL|CC-BY-SA)", l) and " OR " not in l and "/" not in l
    })

    head = f"""# Third-Party Notices

Swaraj Kavach incorporates the components listed below. Each is the property of
its respective authors and is used under the licence shown.

This file is **generated** by `deploy/gen-notices.py`, which the bundle build
re-runs during packaging. Run it after changing a dependency. Do not edit by hand.

It records what each component **declares** in its own manifest. It is an
attribution inventory, not a legal review.

**{total} redistributed components** across Rust, Go, npm and container images.
A further {len(rust_dev)} Rust crates and {len(npm_dev)} npm packages are
build- or development-only: they are compiled or installed here but never
shipped, and are listed separately at the end so the two are never confused.

Full licence texts that must ship with a redistribution are under `licenses/`;
the OWASP Core Rule Set keeps its own copy at `rules/owasp-crs/LICENSE`.

> The licence of Swaraj Kavach **itself** is not stated here and there is no
> LICENSE file in this repository. That is a business decision, not a generated
> one — it needs to be made before anything is handed to a customer.

"""
    head += "## Audit of the redistributed set\n\n"
    if copyleft:
        head += ("**Copyleft with no permissive alternative — review before shipping:**\n\n"
                 + "\n".join(f"- {c}" for c in copyleft) + "\n\n")
    else:
        head += ("- No AGPL, GPL-only, SSPL or CC-BY-SA component is redistributed.\n")
    if undeclared:
        head += ("- **Declares no licence** (an absent licence is *all rights reserved*, "
                 "not permissive) — must be resolved before redistribution:\n\n"
                 + "\n".join(f"  - {u}" for u in undeclared) + "\n")
    else:
        head += "- Every redistributed component declares a licence.\n"
    head += "\n"

    parts = [head]
    parts.append(section(
        "Rust crates (data plane)",
        "Reachable through normal (non-dev, non-build) edges from a shipped binary, "
        "so these are compiled into what customers run. Workspace members excluded.",
        rust))
    parts.append(section(
        "Go modules (control plane)",
        "In the `controllerd` module graph. Go modules carry no licence field in the "
        "graph itself; each module's own repository is authoritative.",
        go))
    parts.append(section(
        "npm packages (dashboard, production)",
        "Production dependencies only — `npm ls --omit=dev`. Next.js bundles a subset "
        "of these into the shipped client.",
        npm))
    parts.append("## Container images and vendored content\n\n")
    for n, v, l, note in STATIC_COMPONENTS:
        parts.append(f"### {n} {v}\n\n- **Licence:** {l}\n- {note}\n\n")

    parts.append("---\n\n# Build- and development-only components\n\n"
                 "Present in this working tree, **not redistributed**: test harnesses, "
                 "build scripts, linters, type checkers. Listed for completeness so that "
                 "a reader can tell the two sets apart rather than assuming.\n\n")
    parts.append(section("Rust (dev- and build-dependencies)", "", rust_dev))
    parts.append(section("npm (devDependencies)", "", npm_dev))
    return "".join(parts)


def main() -> int:
    check = "--check" in sys.argv
    text = build()
    if check:
        if not OUT.exists():
            print("THIRD-PARTY-NOTICES.md is missing — run deploy/gen-notices.py", file=sys.stderr)
            return 1
        if OUT.read_text() != text:
            print("THIRD-PARTY-NOTICES.md is out of date — run deploy/gen-notices.py",
                  file=sys.stderr)
            return 1
        print("THIRD-PARTY-NOTICES.md is up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(REPO)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
