# jiraleaks task runner.
#
# `just` with no arguments lists the recipes. The Rust toolchain, docker and
# mermaid-cli are expected on PATH (mise manages them).
set shell := ["bash", "-uc"]

jira_url := env("JIRA_URL", "https://jira.example.com")
jql := env("JQL", "project = SEC AND updated >= -7d")

# List available recipes
default:
    @just --list

# Compile the release binary into target/release/jiraleaks
build:
    cargo build --release --locked

# Run unit and integration tests for every target
test:
    cargo test --all-targets --locked

# Run clippy over every target (non-fatal; lint-strict adds -D warnings)
lint:
    cargo clippy --all-targets --locked

# Clippy with warnings treated as errors — the target state for CI
lint-strict:
    cargo clippy --all-targets --locked -- -D warnings

# Check formatting without rewriting files
fmt-check:
    cargo fmt --all -- --check

# Apply rustfmt in place
fmt:
    cargo fmt --all

# Build the container image as jiraleaks:dev
docker-build:
    docker build -t jiraleaks:dev .

# Build the image and smoke-test the entrypoint (no Jira credentials needed)
docker-smoke: docker-build
    docker run --rm jiraleaks:dev --help
    docker run --rm jiraleaks:dev completions bash

# Render every ```mermaid block in tracked Markdown files with mermaid-cli
docs-mermaid:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v mmdc >/dev/null 2>&1; then
      echo "docs-mermaid: mmdc (mermaid-cli) is not installed." >&2
      echo "Install it with: mise use -g npm:mermaid-cli" >&2
      exit 1
    fi
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    while IFS= read -r md; do
      stem="${md//\//_}"
      awk -v dir="$tmp" -v stem="$stem" '
        /^[[:space:]]*```mermaid/ { inblock = 1; n++; file = sprintf("%s/%s-%02d.mmd", dir, stem, n); next }
        inblock && /^[[:space:]]*```/ { inblock = 0; next }
        inblock { print > file }
      ' "$md"
    done < <(git ls-files '*.md')
    shopt -s nullglob
    blocks=("$tmp"/*.mmd)
    if (( ${#blocks[@]} == 0 )); then
      echo "docs-mermaid: no mermaid blocks found in tracked Markdown files"
      exit 0
    fi
    for block in "${blocks[@]}"; do
      if ! mmdc_out="$(mmdc -i "$block" -o "$block.svg" --quiet 2>&1)"; then
        echo "docs-mermaid: mmdc failed for $(basename "$block"):" >&2
        echo "$mmdc_out" >&2
        exit 1
      fi
    done
    echo "docs-mermaid: ${#blocks[@]} diagram(s) rendered OK"

# Example dry run against Jira — parses and scans, writes no reports.
# Override the target with: JQL='project = X' JIRA_URL=https://... just scan
scan:
    cargo run --release --locked -- \
      --jira-url "{{jira_url}}" \
      --jql "{{jql}}" \
      --format summary \
      --dry-run \
      --no-proxy

# Remove build artifacts (reports/ and the local state dir are left alone)
clean:
    cargo clean
