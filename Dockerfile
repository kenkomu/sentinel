# Multi-stage build → a small, self-contained watchtower image.
FROM rust:1-slim AS build
WORKDIR /app
# Build straight from the real source. (A dummy-src dependency-cache layer is
# omitted on purpose: it silently ships a stale placeholder binary when cargo
# doesn't notice the real source replaced it. Correctness over a caching trick.)
COPY . .
RUN cargo build --release --bin sentinel --bin verify

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/sentinel /usr/local/bin/sentinel
COPY --from=build /app/target/release/verify /usr/local/bin/verify
# HTTP surface (dashboard, /attestation, /metrics) and JSON-RPC watchtower port.
EXPOSE 8080 23456
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:8080/health || exit 1
# http_port honors $PORT and ckb_rpc_url honors $CKB_RPC_URL, so a PaaS (Render,
# Railway, Fly) can run this image with zero arg changes — it binds the injected
# port and points at whatever CKB endpoint the env sets.
ENTRYPOINT ["sentinel"]
CMD ["--data-dir", "/data", "--rpc-port", "23456"]
