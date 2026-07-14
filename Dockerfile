# Multi-stage build → a small, self-contained watchtower image.
FROM rust:1-slim AS build
WORKDIR /app
# Cache deps first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo 'fn main(){}' > src/main.rs && \
    echo '' > src/lib.rs && \
    echo 'fn main(){}' > src/bin/verify.rs && \
    cargo build --release 2>/dev/null; rm -rf src
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
ENTRYPOINT ["sentinel"]
CMD ["--data-dir", "/data", "--http-port", "8080", "--rpc-port", "23456"]
