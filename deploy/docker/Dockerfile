# =====================================================
# Sentinel WAF — multi-stage production Dockerfile
#
# Build targets:
#   sentinel-dataplane     — Rust proxy (distroless cc, glibc)
#   sentinel-controlplane  — Go control plane (distroless static)
#
# glibc note: the Rust builder is pinned to bookworm (glibc 2.36) so the
# binary it produces runs on the distroless cc-debian12 runtime (also 2.36).
# Do NOT switch the builder to a trixie-based image (glibc 2.41) — the binary
# would then fail to start on the older runtime.
# =====================================================
FROM rust:1.85-slim-bookworm AS rust-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev clang cmake protobuf-compiler && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin sentinel-bin

FROM golang:1.24-alpine AS go-builder
ENV CGO_ENABLED=0
WORKDIR /src/control-plane
COPY control-plane ./
RUN go build -ldflags="-s -w" -o /out/controllerd ./cmd/controllerd \
 && go build -ldflags="-s -w" -o /out/sentinelctl  ./cmd/sentinelctl

# ---- Data plane (Rust proxy) ----
FROM gcr.io/distroless/cc-debian12 AS sentinel-dataplane
WORKDIR /opt/sentinel
COPY --from=rust-builder /src/target/release/sentinel-bin /usr/local/bin/sentinel
# CRS + custom rule packs. The proxy resolves the config's relative rule paths
# (rules/owasp-crs/...) from its working directory, so they live under CWD here.
COPY rules ./rules
ENV SENTINEL_CONFIG=/etc/sentinel/sentinel.yaml \
    SENTINEL_LOG_DIR=/var/log/sentinel \
    RUST_LOG=info,sentinel=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sentinel"]

# ---- Control plane (Go) ----
FROM gcr.io/distroless/static-debian12 AS sentinel-controlplane
COPY --from=go-builder /out/controllerd /usr/local/bin/controllerd
COPY --from=go-builder /out/sentinelctl  /usr/local/bin/sentinelctl
EXPOSE 9500 9501
ENTRYPOINT ["/usr/local/bin/controllerd"]
