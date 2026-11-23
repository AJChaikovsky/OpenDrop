# The OpenDrop relay as a container (used by fly.toml at the repo root).
# Build from the repo root:  docker build -f relay/Dockerfile .

FROM rust:1-bookworm AS build
WORKDIR /src
# The whole workspace has to be present for Cargo to load it; only the
# relay and the core crate it uses get compiled.
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY tests tests
COPY relay relay
COPY app/src-tauri app/src-tauri
RUN cargo build --release --locked -p opendrop-relay

FROM debian:bookworm-slim
# CA roots for HTTPS calls out (emailing sign-in links through Resend).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/opendrop-relay /usr/local/bin/opendrop-relay
# Accounts, devices, the encrypted inbox and its key: mount a volume here.
VOLUME /data
EXPOSE 8787
CMD ["opendrop-relay", "--bind", "0.0.0.0:8787", "--data", "/data"]
