# =====================================================
# Sentinel WAF — multi-stage production Dockerfile
# =====================================================
FROM rust:1.82-slim AS rust-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev clang cmake protobuf-compiler && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin sentinel-bin

FROM golang:1.22-alpine AS go-builder
WORKDIR /src
COPY control-plane ./control-plane
WORKDIR /src/control-plane
RUN go build -ldflags="-s -w" -o /out/controllerd ./cmd/controllerd \
 && go build -ldflags="-s -w" -o /out/sentinelctl  ./cmd/sentinelctl

FROM gcr.io/distroless/cc-debian12 AS sentinel-dataplane
COPY --from=rust-builder /src/target/release/sentinel-bin /usr/local/bin/sentinel
EXPOSE 80 443
USER nonroot
ENTRYPOINT ["/usr/local/bin/sentinel"]

FROM gcr.io/distroless/static-debian12 AS sentinel-controlplane
COPY --from=go-builder /out/controllerd /usr/local/bin/controllerd
COPY --from=go-builder /out/sentinelctl  /usr/local/bin/sentinelctl
EXPOSE 7443
USER nonroot
ENTRYPOINT ["/usr/local/bin/controllerd"]
