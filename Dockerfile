# syntax=docker/dockerfile:1

# ---- Builder stage -----------------------------------------------------
# Matches the pinned toolchain in rust-toolchain.toml exactly.
FROM rust:1.97-slim-bookworm AS builder

# josekit -> openssl (dynamically linked, not vendored) needs pkg-config +
# libssl-dev headers to build openssl-sys against the system OpenSSL.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --bin foundry

# ---- Runtime stage ------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: outbound TLS (e.g. status-list fetches, remote trust anchors)
# libssl3: runtime counterpart of the builder's libssl-dev (dynamic link)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /app --shell /usr/sbin/nologin foundry

COPY --from=builder /app/target/release/foundry /usr/local/bin/foundry

WORKDIR /app
USER foundry

# Wallet-facing listener (server.wallet_facing.bind) and admin listener
# (server.admin.bind) per config.yaml. Mount config, keys, trust anchors,
# and the SQLite storage path (storage.path) as volumes at runtime, e.g.:
#   docker run -v $PWD/config.yaml:/app/config.yaml \
#              -v $PWD/keys:/app/keys \
#              -v $PWD/trust:/app/trust \
#              -v $PWD/data:/app/data \
#              -p 8443:8443 -p 9000:9000 <image>
EXPOSE 8443 9000

ENTRYPOINT ["foundry"]
CMD ["serve", "--config", "/app/config.yaml"]