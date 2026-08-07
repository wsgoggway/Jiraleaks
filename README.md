# jiraleaks

**Find leaked secrets, API keys, and credentials in Jira issues, comments, and attachments.**

`jiraleaks` is a fast, single-binary Rust CLI that scans a Jira instance for leaked
secrets. It is **read-only** against Jira, writes structured reports in six formats,
keeps a findings store for cross-scan reconciliation, and can alert via Slack, Teams,
or a generic webhook. Raw secret values are **never** stored — reports, the store, and
logs contain only a redacted preview and a SHA-256 hash.

- Read-only: fetches issues via the Jira REST API and never mutates Jira state.
- Safe by default: every emitted finding carries a redacted secret + hash, never the
  raw value. Log spans are masked too.
- Runs anywhere: static release binary, minimal Docker image, Kubernetes CronJob, or a
  systemd timer.

## Features

- **20+ builtin detectors** spanning cloud providers, dev platforms, SaaS/messaging,
  databases/connection strings, and key/token formats.
- **Credential-pair detection** — finds `user:password` pairs in URLs, JSON objects,
  and key/value proximity.
- **Custom YAML rules** with fancy-regex, entropy, char-class, context-keyword, and
  denylist controls; user rules override builtins by `rule_id`.
- **Allowlist** by value, SHA-256, pattern, rule id, issue key, or project key.
- **False-positive controls**: Shannon entropy thresholds, a global placeholder filter,
  character-class requirements, context keywords, and per-issue finding caps.
- **Six report formats**: JSON, NDJSON, CSV, SARIF 2.1.0, DefectDojo Generic Findings
  Import, and a human-readable summary.
- **Findings store** (SQLite or PostgreSQL) with status reconciliation across scans:
  New / Recurring / Closed / Confirmed / FalsePositive / Resolved.
- **Alerts** via Slack, Microsoft Teams, or a generic webhook (fire-and-forget).
- **Jira Cloud and Server / Data Center** via REST API v2; `bearer`, `basic`, or `none`
  authentication.
- **Concurrent streaming scan** with bounded backpressure and an interactive progress bar.
- **Secret redaction** in logs and all report formats.
- **Deployment-ready**: non-root Docker image, Kubernetes CronJob, systemd timer.
- **Shell completions** for bash, zsh, fish, elvish, and PowerShell.

## How it works

1. **JQL fetch** — issues are selected by a JQL query, fetched in paginated pages.
2. **Streaming** — pages flow into a bounded channel; issues are processed concurrently
   as they arrive (backpressure at `concurrency × 2` in-flight tasks).
3. **Text extraction** — per issue, text is extracted from fields, comments, and
   (optionally) attachments; nested JSON and Atlassian Document Format are traversed
   recursively, and segments are truncated at `max_text_size_kb`.
4. **Detection** — regex rules plus the credential-pair detector run over each segment.
5. **Filtering** — allowlist, placeholder, entropy, char-class, and context-keyword
   filters discard likely false positives.
6. **Redaction & dedup** — matches are redacted to a preview + hash, then deduplicated.
7. **Reconciliation** — findings are reconciled against the persistent store.
8. **Output** — reports, metrics, and alerts are emitted.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the module map and internal design.

## Installation

**From source** (needs Rust ≥ 1.97):

```bash
git clone https://github.com/appsec-team/jiraleaks
cd jiraleaks
cargo build --release
# binary: target/release/jiraleaks
```

**Via cargo** (once published):

```bash
cargo install jiraleaks
```

**Docker**:

```bash
docker build -t jiraleaks .
```

## Quick start

```bash
jiraleaks \
  --jira-url https://jira.example.com \
  --auth bearer \
  --jql "project = SEC AND updated >= -7d"
```

The token may be passed with `--pat` or the `JIRA_PAT` environment variable (alias
`JIRA_API_TOKEN`). Run with `--dry-run` to exercise the pipeline without writing reports.

## Authentication

| Mode | Use | Credentials |
| --- | --- | --- |
| `bearer` (default) | Jira Server / Data Center PAT | `--pat` / `JIRA_PAT` |
| `basic` | Jira Cloud (email + API token) | `--email` / `JIRA_EMAIL` + `--pat` / `JIRA_PAT` |
| `none` | Public / unauthenticated instances | none |

## Configuration

### CLI flags

| Flag | Env | Default | Notes |
| --- | --- | --- | --- |
| `--jira-url` | `JIRA_URL` | — | Base URL of the Jira instance. |
| `--auth` | `JIRA_AUTH` | `bearer` | `bearer` \| `basic` \| `none`. |
| `--pat` | `JIRA_PAT` (`JIRA_API_TOKEN`) | — | Token (masked). |
| `--email` | `JIRA_EMAIL` | — | Required for `basic`. |
| `--jql` | `JIRA_JQL` | — | JQL query selecting issues. |
| `--page-size` | `SCAN_PAGE_SIZE` | `50` | Issues per search page. |
| `--max-issues` | `SCAN_MAX_ISSUES` | `0` | `0` = unlimited. |
| `--concurrency` | `SCAN_CONCURRENCY` | `2` | Concurrent issue tasks. |
| `--fields` | `SCAN_FIELDS` | `*navigable` | Jira fields to fetch. |
| `--comments-mode` | `SCAN_COMMENTS_MODE` | `all` | `all` \| `none`. |
| `--scan-attachments` | `SCAN_ATTACHMENTS_ENABLED` | `false` | Download & scan attachments (experimental). |
| `--max-attachment-size-mb` | — | `10` | Max attachment size to download. |
| `--max-text-size-kb` | — | `2048` | Truncate extracted text segments. |
| `--max-findings-per-issue` | — | `1000` | Per-issue finding cap. |
| `--allowlist` | `ALLOWLIST_PATH` | — | YAML allowlist. |
| `--rules` | `RULES_PATH` | — | YAML custom rules. |
| `--min-confidence` | — | `low` | `low` \| `medium` \| `high`. |
| `--format` | `REPORT_FORMAT` | `json` | Comma-separated: `json,ndjson,csv,sarif,summary,defectdojo,all`. |
| `--report-dir` | `REPORT_OUTPUT_PATH` | `./reports` | Report output directory. |
| `--report-layout` | `JIRALEAKS_REPORT_LAYOUT` | `flat` | `flat` \| `nested`. |
| `--dry-run` | — | `false` | Do not write report files. |
| `--incremental` | `JIRALEAKS_INCREMENTAL` | `false` | Experimental — see note below. |
| `--state-dir` | — | `./.jiraleaks-state` | Checkpoint / state directory. |
| `--db-url` | `JIRALEAKS_DB_URL` | `sqlite://{state_dir}/findings.db` | Findings store; empty disables. |
| `--metrics-path` | — | — | Write a metrics summary to this path. |
| `--metrics-format` | — | `json` | `json` (Prometheus exposition writer also exists). |
| `--log-level` | `LOG_LEVEL` | `info` | `trace`..`error`. |
| `--no-proxy` | `JIRA_NO_PROXY` | `false` | Bypass proxy settings. |
| `--alerts` | — | — | YAML alerts config (Slack/Teams/webhook). |
| `completions <shell>` | — | — | Print a shell completion script. |

> **`--incremental` is experimental.** A checkpoint is written after a successful scan,
> but it is not yet used to narrow the JQL query, so rescans re-process previously seen
> issues. Treat it as a foundation, not a working incremental mode.

### Environment variables

`JIRA_URL`, `JIRA_AUTH`, `JIRA_PAT` / `JIRA_API_TOKEN`, `JIRA_EMAIL`, `JIRA_JQL`,
`SCAN_PAGE_SIZE`, `SCAN_MAX_ISSUES`, `SCAN_CONCURRENCY`, `SCAN_FIELDS`,
`SCAN_COMMENTS_MODE`, `SCAN_ATTACHMENTS_ENABLED`, `ALLOWLIST_PATH`, `RULES_PATH`,
`REPORT_FORMAT`, `REPORT_OUTPUT_PATH`, `JIRALEAKS_REPORT_LAYOUT`,
`JIRALEAKS_INCREMENTAL`, `JIRALEAKS_DB_URL`, `LOG_LEVEL`, `JIRA_NO_PROXY`.

## Detectors

20 builtin rules. "Validation" lists the active control beyond the regex match.

| Rule ID | Category | Validation |
| --- | --- | --- |
| `aws_access_key_id` | Cloud | `aws_key_checksum` format check |
| `aws_secret_access_key` | Cloud | entropy ≥ 3.0, min 3 digits, context keywords |
| `google_api_key` | Cloud | — |
| `github_token` | Dev platform | — |
| `github_pat_v2` | Dev platform | — |
| `gitlab_token` | Dev platform | — |
| `npm_token` | Dev platform | — |
| `slack_token` | SaaS / messaging | — |
| `telegram_bot_token` | SaaS / messaging | — |
| `sendgrid_api_key` | SaaS / messaging | — |
| `stripe_key` | SaaS / payments | — |
| `jdbc_url_with_password` | Database / connection | — |
| `db_url_credentials` | Database / connection | — |
| `private_key_block` | Key / token | PEM block regex |
| `jwt` | Key / token | `jwt_structure` check |
| `basic_auth_header` | Key / token | — |
| `bearer_token_generic` | Key / token | — |
| `generic_password_assignment` | Credential assignment | entropy ≥ 2.0, min 1 digit |
| `generic_api_key_assignment` | Credential assignment | min 1 digit |
| `generic_secret_assignment` | Credential assignment | min 1 digit |

> The `github_token_checksum` validator (CRC32 + base62) is available for **user-defined
> rules** via the `validator:` field, but is not attached to any builtin rule by default.

## Credential-pair detection

A dedicated detector (`rule_id: credential_pair`, severity **High**) finds
username/password pairs that appear together:

- **URL userinfo** — `scheme://user:pass@host`.
- **Key/value proximity** — a username-like key and a password-like key within 200
  characters of each other.
- **JSON objects** — adjacent `user`/`username` and `password`/`pass` fields.

Credential-pair findings are always reported at high confidence.

## Custom rules

Provide extra or override rules with `--rules path/to/rules.yaml`. User rules override
builtins that share the same `rule_id`. Each rule supports:

`rule_id`, `description`, `severity`, `confidence`, `regex` (fancy-regex),
`capture_group`, `min_length`, `min_entropy`, `context_keywords`, `denylist`, `validator`,
`enabled`, `ignore_if_contains`, `min_digits`, `min_uppercase`, `min_lowercase`,
`min_special_chars`, `special_chars`, `disable_default_placeholders`, `examples`,
`references`.

```yaml
- rule_id: my_custom_token
  description: Internal service token
  severity: high
  confidence: high
  regex: '\bsvc_[A-Za-z0-9]{32}\b'
  min_entropy: 3.0
  min_digits: 1
  context_keywords:
    - service_token
    - svc-token
  references:
    - https://wiki.example.com/auth/tokens
```

## Reducing false positives

- **Allowlist** (YAML) — suppress findings by raw value, SHA-256 hash, regex pattern,
  `rule_id`, issue key, or project key.
- **Global placeholder filter** — 14 common placeholder strings (`example`, `test`,
  `sample`, `demo`, `dummy`, `placeholder`, `changeme`, `your_key`, `yourkey`,
  `your-key`, `xxxx`, `foobar`, `redacted`, `fake`) are filtered for every rule. A rule
  can opt out with `disable_default_placeholders: true` (used by `stripe_key`, where
  `test` is part of the legitimate `sk_test_`/`rk_test_` format).
- **Entropy, char-class, context-keyword, and denylist** filters per rule.
- **Per-issue finding cap** (`--max-findings-per-issue`).

## Reports

| Format | Description |
| --- | --- |
| `json` | One JSON document with the scan run and all findings (default). |
| `ndjson` | One JSON object per line. |
| `csv` | Tabular findings. |
| `sarif` | SARIF 2.1.0 for IDE / CI integration. |
| `summary` | Human-readable console summary. |
| `defectdojo` | DefectDojo Generic Findings Import JSON. |

Use `--report-layout nested` to file reports under `<report-dir>/<project>/<date>/`,
grouped by the JQL project segment; `flat` writes `<report-dir>/<timestamp>_report.*`.

Every report stores only the **redacted** secret and its SHA-256 hash — never the raw
value.

## Findings store

When a database URL is configured (`--db-url`, default
`sqlite://{state_dir}/findings.db`), findings are persisted and reconciled across scans:

- **Statuses**: `new`, `recurring`, `closed`, `confirmed`, `false_positive`, `resolved`.
- A finding absent from a re-scanned issue is marked `closed`; a repeat is `recurring`
  with `first_seen` preserved and `times_seen` incremented. Issues not included in the
  current JQL scope are left untouched (never falsely closed).
- PostgreSQL is also supported (`postgres://user:pass@host/db`).
- An external validation system can populate a `live_validations` table (by secret hash);
  validated secrets are surfaced on findings and can promote severity. **No external
  validation provider is wired into jiraleaks itself** — the table is a schema slot for an
  external checker.

## Alerts

Configure notifications with `--alerts path/to/alerts.yaml`:

```yaml
slack:   { webhook_url: "https://hooks.slack.com/services/..." }
teams:   { webhook_url: "https://outlook.office.com/webhook/..." }
webhook: { url: "https://example.com/hook" }
min_confidence: medium
```

Each channel posts a scan summary plus top findings (filtered by `min_confidence`).
Alert delivery is fire-and-forget — a failed webhook never fails the scan.

## Deployment

- **Docker** — non-root image (UID 65532). Build with `docker build -t jiraleaks .` and
  run with `JIRA_*` env vars.
- **Kubernetes CronJob** — see `deploy/k8s/cronjob.yaml` (weekly, `security` namespace,
  pulling `JIRA_*` from a `jira-credentials` Secret).
- **systemd timer** — see `deploy/systemd/` (weekly `jiraleaks.timer` driving the
  `jiraleaks.service` oneshot).

Examples use a generic `project = SEC` JQL scope; adjust to your environment.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (or non-critical errors logged during the run). |
| `1` | Configuration error. |
| `2` | Jira access error (auth failure, unreachable host). |
| `3` | Critical scan error. |
| `4` | Report write error. |
| `5` | Store / persistence error. |

## Shell completions

```bash
jiraleaks completions bash      # or: zsh | fish | elvish | powershell
```

## Security notes

- jiraleaks is **read-only** against Jira.
- Raw secrets are **never persisted**: reports, the findings store, and logs contain only
  a redacted preview (first-2 / last-2 characters) plus a SHA-256 hash.
- Log spans covering matched secrets are masked.
- Use a **least-privilege, read-only** Jira account for scanning.

## License

MIT — see [`LICENSE`](LICENSE).

## Contributing

Pull requests are welcome. Please run `cargo test` and `cargo clippy --all-targets`
before submitting.
