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

# The relay makes no outbound TLS calls (and rustls carries its own roots),
# so the slim image needs nothing added.
FROM debian:bookworm-slim
COPY --from=build /src/target/release/opendrop-relay /usr/local/bin/opendrop-relay
# Accounts, devices, the encrypted inbox and its key: mount a volume here.
VOLUME /data
EXPOSE 8787
CMD ["opendrop-relay", "--bind", "0.0.0.0:8787", "--data", "/data"]
