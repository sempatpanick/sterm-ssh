FROM rust:bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server

RUN cargo build --release --package sterm-sync-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY --from=builder /app/target/release/sterm-sync-server /usr/local/bin/sterm-sync-server
ENV STERM_SYNC_BIND=0.0.0.0:8787
ENV STERM_SYNC_DB=/data/sterm-sync.db
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -fsS http://127.0.0.1:8787/health || exit 1
CMD ["sterm-sync-server"]
