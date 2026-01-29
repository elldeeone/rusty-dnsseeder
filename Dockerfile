# -- multistage docker build: stage #1: chef base
FROM rust:1.89-bullseye AS chef

RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler ca-certificates && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef

WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./

RUN mkdir -p src && printf "fn main() {}\n" > src/main.rs

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto ./proto
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/dnsseeder /app/dnsseeder

# --- multistage docker build: stage #2: runtime image
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/dnsseeder /app/dnsseeder

ENTRYPOINT ["/app/dnsseeder"]
