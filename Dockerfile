# syntax=docker/dockerfile:1
#
# jiraleaks — container image (multi-stage, unprivileged runtime).
#
# Build:
#   docker build -t jiraleaks .
#
# Run (paths are pinned by ENV below: reports -> /data/reports, findings store
# -> /data/state; both are volumes, so report and store history survive the
# container):
#   docker run --rm \
#     -e JIRA_URL=https://jira.example.com \
#     -e JIRA_JQL='project = SEC AND updated >= -7d' \
#     -e JIRA_PAT \
#     -e REPORT_FORMAT=all \
#     -v jiraleaks-reports:/data/reports \
#     -v jiraleaks-state:/data/state \
#     jiraleaks
#
# Smoke tests (no Jira credentials needed):
#   docker run --rm jiraleaks --help
#   docker run --rm jiraleaks completions bash

# ---------- Stage 1: builder ----------
FROM rust:1.97-slim AS builder

WORKDIR /build
# src/store.rs embeds the schema with include_str!("../migrations/0001_init.sql"),
# which the compiler resolves at build time — migrations/ is part of the build
# context, not just a runtime asset.
COPY Cargo.toml Cargo.lock ./
COPY migrations/ migrations/
COPY src/ src/
RUN cargo build --release --locked

# ---------- Stage 2: runtime ----------
FROM debian:trixie-slim AS runtime

LABEL org.opencontainers.image.title="jiraleaks" \
      org.opencontainers.image.description="Scan Jira issues, comments and attachments for leaked secrets and credentials" \
      org.opencontainers.image.source="https://github.com/wsgoggway/Jiraleaks" \
      org.opencontainers.image.licenses="MIT"

# ca-certificates is kept for tooling that reads the system trust store; the
# binary itself verifies TLS with rustls' bundled webpki roots.
# The runtime identity uses numeric UID/GID 65532 so that the Kubernetes
# securityContext (runAsUser/runAsGroup/fsGroup: 65532) matches it exactly.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 65532 jiraleaks; \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin jiraleaks; \
    install -d -o 65532 -g 65532 -m 0750 /data /data/reports /data/state

COPY --from=builder /build/target/release/jiraleaks /usr/local/bin/jiraleaks

# The findings store is opened before any report is written, so the process
# needs a writable working directory: with CWD=/ (no WORKDIR) the sqlite store
# fails on the read-only / for UID 65532 and the scan exits 5 without reports.
WORKDIR /data
ENV REPORT_OUTPUT_PATH=/data/reports \
    JIRALEAKS_DB_URL=sqlite:///data/state/findings.db?mode=rwc

# Checkpoint state has no environment variable — pass it explicitly when using
# --incremental: `--state-dir /data/state`. Without that flag the relative
# default (./.jiraleaks-state) lands in the writable working directory, never /.
VOLUME ["/data/reports", "/data/state"]

USER 65532:65532
ENTRYPOINT ["jiraleaks"]
