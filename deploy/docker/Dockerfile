# =====================================================
# Swaraj Kavach — multi-stage production Dockerfile
#
# Build targets:
#   sentinel-dataplane     — Rust proxy (distroless cc, glibc)
#   sentinel-controlplane  — Go control plane (distroless static)
#
# glibc note: the Rust builder is pinned to bookworm (glibc 2.36) so the
# binary it produces runs on the distroless cc-debian12 runtime (also 2.36).
# Do NOT switch the builder to a trixie-based image (glibc 2.41) — the binary
# would then fail to start on the older runtime.
#
# ── BUILD PROVENANCE ─────────────────────────────────────────────────────────
# GIT_SHA/BUILD_DATE/VERSION are stamped into OCI labels on every final stage so
# that "which commit is this image?" is a one-line query:
#
#   docker image inspect sentinel/dataplane:latest \
#     --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
#
# This exists because of a real incident (2026-08-10/11). Images were built on a
# workstation and shipped to three VMs as `docker save` tarballs, but nothing
# synced the source, so /opt/sentinel-src sat 21 commits behind what was running.
# Every cheap way to ask what a box was running gave the WRONG answer: the source
# tree said 21 commits stale, the compose files said current. Establishing the
# truth meant `docker cp`-ing the binary out of a distroless image and grepping it
# for a string only the new build contained — forensics, to answer a question a
# label answers instantly.
#
# Unset args default to "unknown" rather than failing the build: a local
# `docker build` for debugging should not need git. It is deploy/fleet/fleet.sh
# that refuses to SHIP an image whose revision is unknown.
# =====================================================
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0

FROM rust:1.85-slim-bookworm AS rust-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev clang cmake protobuf-compiler && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# --features kernel enables aya-based XDP (the committed BPF ELF is embedded via
# include_bytes!, so no BPF toolchain is needed here). At runtime it attaches
# XDP when the container has CAP_BPF/CAP_NET_ADMIN, else falls back to software.
RUN cargo build --release --bin sentinel-bin --features kernel

# ---- SRL validator (Rust), for the control plane ----
# The rule DSL is compiled in Rust and the control plane is Go, so the control
# plane executes this binary rather than owning a second parser: one compiler
# means a rule that validates in the API is a rule that will run in the proxy.
#
# Its OWN stage on purpose. Built alongside sentinel-bin in the rust-builder
# stage above, it made the control-plane image depend on the whole data-plane
# build — turning a ~1 minute CP build into ~12 minutes on every crate change.
# This stage compiles only sentinel-core + sentinel-rules and their deps, and
# Docker skips it entirely when building the data plane.
FROM rust:1.85-slim-bookworm AS srl-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config clang && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin sentinel-srl-validate

FROM golang:1.25-alpine AS go-builder
ENV CGO_ENABLED=0
WORKDIR /src/control-plane
COPY control-plane ./
# Stamp the binary with its commit and build date so /api/v1/cluster/status
# reports what it was built from. The product version itself is a constant in
# internal/version, pinned to the repo-root VERSION file by CI.
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
RUN go build -ldflags="-s -w \
      -X github.com/your-org/sentinel-waf/control-plane/internal/version.CommitLinked=${GIT_SHA} \
      -X github.com/your-org/sentinel-waf/control-plane/internal/version.BuildDateLinked=${BUILD_DATE}" \
      -o /out/controllerd ./cmd/controllerd \
 && go build -ldflags="-s -w" -o /out/sentinelctl  ./cmd/sentinelctl

# ---- Data plane (Rust proxy) ----

# A container healthcheck for the distroless runtime stages. Both distroless
# images have no shell, no curl and no wget, so a compose `healthcheck` had
# nowhere to run and neither container ever reported health to Docker. Static,
# stdlib-only, ~5 MB stripped.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/healthprobe ./cmd/healthprobe/

FROM gcr.io/distroless/cc-debian12 AS sentinel-dataplane
# Re-declared inside the stage: an ARG before the first FROM is global but is NOT
# in scope in any stage until named again. Omitting these is the classic way to
# ship labels that silently read "unknown".
ARG GIT_SHA
ARG BUILD_DATE
ARG VERSION
LABEL org.opencontainers.image.title="Swaraj Kavach data plane" \
      org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.source="https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf"
WORKDIR /opt/sentinel
COPY --from=rust-builder /src/target/release/sentinel-bin /usr/local/bin/sentinel
# CRS + custom rule packs. The proxy resolves the config's relative rule paths
# (rules/owasp-crs/...) from its working directory, so they live under CWD here.
COPY rules ./rules
ENV SENTINEL_CONFIG=/etc/sentinel/sentinel.yaml \
    SENTINEL_LOG_DIR=/var/log/sentinel \
    # Just `info`. A `sentinel=info` directive here silently disabled every log
    # line from the sentinel-modules crate — geoip, bot_detect, dlp, jwt_auth,
    # anti_ddos, rate_limit, ip_reputation, threat_intel, smuggling,
    # tls_fingerprint, graphql, grpc. Twelve subsystems, invisible on every
    # deployment, which is why GeoIP's "database not found" warning went
    # unnoticed for months. Proven on .71 by toggling only this value.
    #
    # This is the IMAGE default, so it is the value anyone running the container
    # without compose inherits — the place a fix is most easily missed.
    RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sentinel"]

# ---- Control plane (Go) ----
# distroless/cc, not distroless/static: the Go binaries are static but
# srl-validate is a normal glibc-linked Rust binary, so the runtime needs a libc.
# The alternative was cross-compiling it against musl, which means carrying a musl
# toolchain and a second link configuration to save a few megabytes — the data
# plane already runs on cc.
# Container healthcheck. See control-plane/cmd/healthprobe for why a binary is
# needed rather than a curl one-liner.
COPY --from=go-builder /out/healthprobe /healthprobe
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=4 \
  CMD ["/healthprobe", "http://127.0.0.1:8080/readyz"]

FROM gcr.io/distroless/cc-debian12 AS sentinel-controlplane
ARG GIT_SHA
ARG BUILD_DATE
ARG VERSION
LABEL org.opencontainers.image.title="Swaraj Kavach control plane" \
      org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.source="https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf"
COPY --from=go-builder /out/controllerd /usr/local/bin/controllerd
COPY --from=go-builder /out/sentinelctl  /usr/local/bin/sentinelctl
COPY --from=srl-builder /src/target/release/sentinel-srl-validate /usr/local/bin/srl-validate
EXPOSE 9501
ENTRYPOINT ["/usr/local/bin/controllerd"]
# Container healthcheck. See control-plane/cmd/healthprobe for why a binary is
# needed rather than a curl one-liner.
COPY --from=go-builder /out/healthprobe /healthprobe
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=4 \
  CMD ["/healthprobe", "http://127.0.0.1:9501/readyz"]

# ---- DB migrations (goose) ----
# Self-contained migration runner: bundles the goose CLI + the SQL migrations so
# a K8s initContainer/Job (or `docker run`) can bring a fresh database to the
# current schema. goose tracks applied versions in goose_db_version, so it is
# safe to re-run — `up` is a no-op once the DB is current. This replaces the
# manual "apply goose Up via psql" step (raw psql is wrong here: the .sql files
# carry goose Up/Down markers). Connection comes from GOOSE_DBSTRING at runtime.
FROM golang:1.25-alpine AS goose-builder
ENV CGO_ENABLED=0
# Pinned for reproducibility; no_sqlite3 keeps the build pure-Go (postgres only).
RUN go install -tags='no_sqlite3' github.com/pressly/goose/v3/cmd/goose@v3.22.1

FROM alpine:3.20 AS sentinel-migrate
ARG GIT_SHA
ARG BUILD_DATE
ARG VERSION
LABEL org.opencontainers.image.title="Swaraj Kavach migrations" \
      org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.source="https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf"
RUN apk add --no-cache ca-certificates
COPY --from=goose-builder /go/bin/goose /usr/local/bin/goose
COPY control-plane/internal/db/migrations /migrations
ENV GOOSE_DRIVER=postgres \
    GOOSE_MIGRATION_DIR=/migrations
# GOOSE_DBSTRING (the postgres DSN) is injected at run time. Default: apply Up.
ENTRYPOINT ["goose"]
CMD ["up"]
