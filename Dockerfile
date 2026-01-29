# -- multistage docker build: stage #1: build stage
FROM rust:1.89-bullseye AS build

RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto ./proto
COPY src ./src

RUN cargo build --release

# --- multistage docker build: stage #2: runtime image
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/dnsseeder /app/dnsseeder

ENTRYPOINT ["/app/dnsseeder"]
