# Stage 1: Build
FROM rust:1.97-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked

# Stage 2: Runtime
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/jiraleaks /usr/local/bin/jiraleaks
USER 65532
ENTRYPOINT ["jiraleaks"]
