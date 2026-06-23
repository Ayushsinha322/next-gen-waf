# Sentinel WAF — Documentation

Public documentation for Sentinel WAF. (Internal/working notes are kept out of
the repository.)

## Contents

- [Architecture Overview](architecture/overview.md) — two-plane design and the
  request lifecycle through the Rust data plane.
- [Architecture Diagram](architecture/architecture-diagram.html) — interactive
  system diagram (open in a browser).
- [Raft Cluster](architecture/raft-cluster.md) — control-plane high-availability
  topology and the Raft consensus design.
- [`sentinel.sh` Launcher](launcher.md) — one-command local/dev startup and the
  available operator commands.
