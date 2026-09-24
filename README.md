# jiraleaks

**Find leaked secrets, API keys, and credentials in Jira issues, comments, and attachments.**

`jiraleaks` is a single-binary Rust CLI that scans a Jira instance for leaked secrets.
It is **read-only** against Jira, writes reports in six formats, keeps a findings store
for cross-scan reconciliation, and can alert via Slack, Teams, or a generic webhook.

Raw secret values are **never** written to a report, the findings store, a log line, or
an alert: every sink carries only a redacted preview, a SHA-256 hash, and a snippet in
which the secret and its neighbours are masked.

- Read-only: fetches issues via the Jira REST API and never mutates Jira state.
- Safe by default: every emitted finding carries a redacted secret plus hash, never the
  raw value. Snippets are masked, log spans are masked, and the Jira token and webhook
  URLs are never printed.
- Runs anywhere: release binary, minimal Docker image, Kubernetes CronJob, or a systemd
  timer.

## Features

- **20 builtin detectors** spanning cloud providers, dev platforms, SaaS/messaging,
  databases/connection strings, and key/token formats.
- **Credential-pair detection** — finds `user:password` pairs in URLs, JSON objects,
  and key/value proximity.
- **Custom YAML rules** with fancy-regex, entropy, char-class, context-keyword, and
  denylist controls; user rules override builtins by `rule_id`.
- **Full comment coverage** — every page of an issue's comment thread is fetched and
  scanned, not just the page embedded in the issue payload.
- **Text attachment scanning** (opt-in, `--scan-attachments`) — the attachment body is
  fetched, streamed under a size limit, and scanned by the same rules engine.
- **Allowlist** by value, SHA-256, pattern, rule id, issue key, project key, and field
  path, with strict loading that rejects an unusable record instead of ignoring it.
- **False-positive controls**: Shannon entropy thresholds, a shared placeholder
  dictionary, character-class requirements, context keywords, and per-issue caps.
- **Six report formats**: JSON, NDJSON, CSV, SARIF 2.1.0, DefectDojo Generic Findings
  Import, and a human-readable summary.
- **Findings store** (SQLite or PostgreSQL) with status reconciliation across scans:
  New / Recurring / Closed / Confirmed / FalsePositive / Resolved.
- **Alerts** via Slack, Microsoft Teams, or a generic webhook (fire-and-forget, with the
  delivered/failed outcome logged).
- **Jira Cloud and Server / Data Center** via REST API v2; `bearer`, `basic`, or `none`
  authentication.
- **Concurrent streaming scan** with bounded backpressure and an interactive progress bar.
- **Hostile input is bounded**: text from Jira is treated as untrusted, every per-segment
  loop has a cost ceiling, and reported text is neutralised for terminals and spreadsheets.
- **Deployment-ready**: non-root Docker image, Kubernetes CronJob, systemd timer, `justfile`,
  and a GitHub Actions CI workflow.
- **Shell completions** for bash, zsh, fish, elvish, and PowerShell.

## How it works

1. **JQL fetch** — issues are selected by a JQL query and fetched in paginated pages.
2. **Streaming** — pages flow into a bounded channel; issues are processed concurrently
   as they arrive (backpressure at `concurrency × 2` in-flight tasks).
3. **Text extraction** — per issue, text is extracted from the issue fields, from every
   page of the comment thread, and, with `--scan-attachments`, from the bodies of text
   attachments; nested JSON and Atlassian Document Format are traversed recursively, and
   each segment is truncated at `max_text_size_kb`.
4. **Detection** — regex rules plus the credential-pair detector run over each segment.
5. **Filtering** — allowlist, placeholder, entropy, char-class, and context-keyword
   filters discard likely false positives; every rejection is logged at debug level with
   its reason.
6. **Redaction & dedup** — matches are redacted to a preview plus hash, snippets are
   masked, and findings are deduplicated by (secret hash, rule id).
7. **Reconciliation** — findings are reconciled against the persistent store.
8. **Output** — reports, metrics, and alerts are emitted; with `--incremental`, the JQL was
   narrowed to the window since the last successful scan, and a checkpoint is written after
   a successful scan.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the module map and internal design.

## Installation

**From source** (needs Rust ≥ 1.97):

```bash
git clone https://github.com/wsgoggway/Jiraleaks
cd Jiraleaks
cargo build --release --locked
# binary: target/release/jiraleaks
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

The token is taken from the first of `--pat`, `JIRA_PAT`, and `JIRA_API_TOKEN`, so an
empty or unset variable cannot shadow a real token from a lower-priority source. Run with
`--dry-run` to exercise the pipeline without writing reports.

## Authentication

| Mode | Use | Credentials |
| --- | --- | --- |
| `bearer` (default) | Jira Server / Data Center PAT | `--pat`, else `JIRA_PAT`, else `JIRA_API_TOKEN` |
| `basic` | Jira Cloud (email + API token) | `--email` / `JIRA_EMAIL` + the token above |
| `none` | Public / unauthenticated instances | none |

## Configuration

### CLI flags

Every flag below is the actual `--help` output of the binary; `Default` is the value
`Config::default()` and the clap default agree on.

| Flag | Env | Default | Notes |
| --- | --- | --- | --- |
| `--jira-url <URL>` | `JIRA_URL` | — | Required. Must start with `http://` or `https://`. |
| `--auth <MODE>` | `JIRA_AUTH` | `bearer` | `bearer` \| `basic` \| `none`. |
| `--pat <TOKEN>` | `JIRA_PAT`, then `JIRA_API_TOKEN` | — | Required unless `--auth none`. Never logged. |
| `--email <EMAIL>` | `JIRA_EMAIL` | — | Required for `basic`. |
| `--jql <JQL>` | `JIRA_JQL` | — | Required and must not be empty. |
| `--page-size <N>` | `SCAN_PAGE_SIZE` | `50` | Issues per search page, ≥ 1. |
| `--max-issues <N>` | `SCAN_MAX_ISSUES` | `0` | `0` = no limit. |
| `--concurrency <N>` | `SCAN_CONCURRENCY` | `2` | Concurrent issue tasks, ≥ 1. |
| `--fields <LIST>` | `SCAN_FIELDS` | `*navigable` | Jira fields fetched per issue. |
| `--comments-mode <MODE>` | `SCAN_COMMENTS_MODE` | `all` | `all` \| `none`. |
| `--scan-attachments` | `SCAN_ATTACHMENTS_ENABLED` | `false` | Scan text attachment bodies. |
| `--max-attachment-size-mb <N>` | — | `10` | Per-file download limit, ≥ 1. |
| `--max-text-size-kb <N>` | — | `2048` | Truncate an extracted segment beyond this, ≥ 1. |
| `--max-findings-per-issue <N>` | — | `1000` | Per-issue finding cap, ≥ 1. |
| `--allowlist <PATH>` | `ALLOWLIST_PATH` | — | YAML allowlist. |
| `--rules <PATH>` | `RULES_PATH` | — | YAML custom rules. |
| `--min-confidence <L>` | — | `low` | `low` \| `medium` \| `high`. |
| `--format <LIST>` | `REPORT_FORMAT` | `json` | Comma-separated: `json,ndjson,csv,sarif,summary,defectdojo,all`. |
| `--report-dir <DIR>` | `REPORT_OUTPUT_PATH` | `./reports` | Report output directory. |
| `--report-layout <L>` | `JIRALEAKS_REPORT_LAYOUT` | `flat` | `flat` \| `nested`. |
| `--dry-run` | — | `false` | Do not write report files. |
| `--incremental` | `JIRALEAKS_INCREMENTAL` | `false` | Narrow the JQL to changes since the last successful scan — see below. |
| `--state-dir <DIR>` | — | `./.jiraleaks-state` | Checkpoint directory, and the default location of the findings store. |
| `--db-url <URL>` | `JIRALEAKS_DB_URL` | `sqlite://{state_dir}/findings.db?mode=rwc` | `sqlite://…?mode=rwc` or `postgres://…`; an empty string disables the store. |
| `--metrics-path <PATH>` | — | — | Write a metrics summary to this path. |
| `--metrics-format <F>` | — | `json` | `json` \| `prom` \| `prometheus`. |
| `--log-level <L>` | `LOG_LEVEL` | `info` | `trace` \| `debug` \| `info` \| `warn` \| `error`; `RUST_LOG` is the fallback. |
| `--no-proxy` | `JIRA_NO_PROXY` | `false` | Bypass proxy settings for Jira requests. |
| `--alerts <PATH>` | — | — | YAML alerts config (Slack/Teams/webhook). |
| `completions <SHELL>` | — | — | Print a shell completion script. |

`-h` / `--help` and `-V` / `--version` print to stdout and exit `0`.

### `--incremental`

**Working, off by default.** With `--incremental`, the query sent to Jira is narrowed to the
issues that changed since the last successful scan of the same query:

```text
(<configured JQL>) AND updated >= "<yyyy-MM-dd HH:mm>"
```

The checkpoint is `checkpoint.json` in `--state-dir`. It is versioned and stores the instant
the previous scan finished, the **configured** JQL, the Jira base URL, and the scan's status.

- The narrowing is applied only when the checkpoint can be trusted: the file exists and
  parses, its format version is current, its status is `success`, its JQL equals the
  configured one (compared with whitespace collapsed, so a reformatted query still counts as
  the same), its `jira_url` is this instance, and its timestamp is a valid RFC 3339 instant
  in the past. Anything else falls back to a full scan with the reason logged at `info`
  level — never a silent narrowing.
- The window starts **5 minutes** before that instant, so an issue updated while the previous
  scan was still running is queried again instead of falling outside every later window.
- The configured JQL is always parenthesized before the `AND` is appended: without the
  parentheses an `OR` in the query would let the `AND` bind to its last operand only, and half
  the query would be silently unfiltered.
- A checkpoint is written only when `--incremental` is on **and** the scan finished
  successfully; a cancelled or partially failed scan does not move the baseline, because the
  issues it never reached would drop out of every later window.
- The reports show the query that actually ran (`scan_run.jql`); the checkpoint keeps the
  configured query as the baseline for the next run.

**Time zone caveat.** The timestamp is written as naive UTC (`yyyy-MM-dd HH:mm`), and Jira
reads a naive JQL timestamp in the time zone of the requesting user's profile. On an instance
whose Jira profile is not on UTC the window shifts by that offset; the five-minute overlap
absorbs clock skew, not a time-zone difference. The overlap is not configurable: it is the
`WINDOW_OVERLAP` constant in `src/checkpoint.rs` (five minutes), so an instance that needs a
wider one needs a code change and a rebuild, not a flag.

Without the flag nothing incremental happens: `--incremental` is the only thing that both
reads and writes a checkpoint.

### Environment variables

`JIRA_URL`, `JIRA_AUTH`, `JIRA_PAT` / `JIRA_API_TOKEN`, `JIRA_EMAIL`, `JIRA_JQL`,
`SCAN_PAGE_SIZE`, `SCAN_MAX_ISSUES`, `SCAN_CONCURRENCY`, `SCAN_FIELDS`,
`SCAN_COMMENTS_MODE`, `SCAN_ATTACHMENTS_ENABLED`, `ALLOWLIST_PATH`, `RULES_PATH`,
`REPORT_FORMAT`, `REPORT_OUTPUT_PATH`, `JIRALEAKS_REPORT_LAYOUT`,
`JIRALEAKS_INCREMENTAL`, `JIRALEAKS_DB_URL`, `LOG_LEVEL`, `JIRA_NO_PROXY`.

`RUST_LOG` is read only as a fallback: an explicit `--log-level` or `LOG_LEVEL` always
wins over it.

### Validation

`Config::validate()` runs before the first Jira request and rejects, with exit code `1`:
an empty or scheme-less `jira_url`, an empty JQL, a missing token unless `auth = none`,
`basic` without an email, an unknown `auth`, a zero `page_size`, `concurrency`,
`max_findings_per_issue`, `max_text_size_kb` or `max_attachment_size_mb`, an unknown
`report_layout`, an unknown `min_confidence`, and an unknown report format. A command line
that clap itself rejects exits with the same code `1`.

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
| `stripe_key` | SaaS / payments | default placeholder list disabled (its format contains `test`) |
| `jdbc_url_with_password` | Database / connection | — |
| `db_url_credentials` | Database / connection | — |
| `private_key_block` | Key / token | PEM block regex |
| `jwt` | Key / token | `jwt_structure` check |
| `basic_auth_header` | Key / token | — |
| `bearer_token_generic` | Key / token | — |
| `generic_password_assignment` | Credential assignment | entropy ≥ 2.0, min length 8, min 1 digit |
| `generic_api_key_assignment` | Credential assignment | min 1 digit |
| `generic_secret_assignment` | Credential assignment | min 1 digit |

Rules with a `references` list carry those URLs into the findings and the reports.

> The `github_token_checksum` validator (CRC32 + base62) is available for **user-defined
> rules** via the `validator:` field, but is not attached to any builtin rule by default.
> The three available validators are `aws_key_checksum`, `jwt_structure`, and
> `github_token_checksum`; an unknown validator name accepts every value.

## Credential-pair detection

A dedicated detector (`rule_id: credential_pair`, severity **High**) finds
username/password pairs that appear together:

- **URL userinfo** — `scheme://user:pass@host`.
- **Key/value proximity** — a username-like key and a password-like key within 200 bytes
  of each other, matched line by line (`user`/`username`/`login`/`email`/`client_id`/…
  against `pass`/`password`/`passwd`/`pwd`/`secret`/`api_key`/…).
- **JSON objects** — adjacent username and password fields, with alias duplicates
  collapsed so one secret yields one finding.

Credential-pair findings are always reported at high confidence, and the password is
replaced by a redacted preview plus hash.

The detector is bounded, because the text it reads is attacker-controlled: at most
**64 KiB of a segment** is inspected, at most **4096 matches per pattern** are
materialised, and at most **256 hits** are returned for one segment. The proximity
heuristic pairs matches with a two-cursor sliding window rather than a cross-product, so a
segment of `user=a\npassword=b\n` repeated half a million times costs milliseconds, not
minutes.

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

- **Allowlist** (YAML) — suppress findings by value, SHA-256, regex pattern, `rule_id`,
  issue key, project key, or field path. See the next section.
- **Shared placeholder dictionary** — 18 words in one table, read under two semantics:
  - the rules engine's default `ignore_if_contains` list is the **substring** subset
    (14 words: `example`, `test`, `sample`, `demo`, `dummy`, `placeholder`, `changeme`,
    `your_key`, `yourkey`, `your-key`, `xxxx`, `foobar`, `redacted`, `fake`) — a match
    containing any of them is dropped, and a rule can opt out with
    `disable_default_placeholders: true`;
  - the credential-pair detector and the post-scan check use the **equality** subset
    (10 words, which adds `password`, `secret`, `your_secret_here`, `xxxxxx` and drops the
    rules-engine-only ones), plus template markers (`<...>`, `${...}`, `{{...}}`) — so
    `xxxx` is a placeholder for a rule match but a valid password for the pair detector.
- **Entropy, char-class, context-keyword, and denylist** filters per rule.
- **Per-issue finding cap** (`--max-findings-per-issue`).
- Every dropped candidate is logged at `debug` level with the rule, the issue, the field
  path, and the reason — never with the value.

## Allowlist

The allowlist is a YAML list of records. Matching predicates are OR-ed inside a record and
records are OR-ed across the file:

```yaml
- value: "AKIAIOSFODNN7EXAMPLE"        # exact secret value, anywhere
  reason: "public AWS docs example"
- sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
- pattern: '^ghp_example_'             # regex searched inside the value
  field: comment                       # ... only under the comment subtree
  reason: "documentation snippets"
- rule_id: aws_access_key_id           # a whole rule
  project_key: SEC                     # ... only in one project
- issue_key: SEC-123                   # a single issue
```

- `value` compares byte-for-byte; `sha256` accepts 64 hex digits with or without the
  `sha256:` prefix, case-insensitively; `pattern` is a `fancy_regex` search anywhere inside
  the value and runs under a backtracking budget (a pattern that exceeds it is logged and
  treated as **not** matching, so the finding survives).
- `rule_id`, `issue_key`, and `project_key` are exact and case-sensitive; `project_key` is
  the part of the issue key before the first `-`.
- `field` is a **scope**, not a predicate: it narrows the whole record — key predicates
  included — to the finding's field path or a subpath of it. `field: comment` covers
  `comment`, `comment.body`, and `comment.comments[0].body`, but not `comments`,
  `commentary`, or `fields.comment`.
- `reason` is audit only: it never affects matching and is written to the debug log with
  the suppression it justifies. The secret value is never logged.

Loading is strict, because a silently useless record is a missed leak: an unknown key, a
record with no predicate (`field` alone is not one), an empty `value`/`pattern`/`sha256`,
a malformed digest, or a regex that does not compile is a configuration error (exit `1`)
naming the offending record. An empty allowlist file is valid and suppresses nothing, and
is logged as a warning.

## Comments and attachments

### Comments

With `--comments-mode all` (the default), **every** comment of an issue is scanned, not
just the first page Jira embeds in the issue payload. The extra pages are fetched from the
comment endpoint, capped at 40 pages of 50 comments (2000 comments after the first page);
reaching the cap logs a warning and the scan continues. A fetch that fails is logged and
never fails the issue: the issue's other findings are still reported. `--comments-mode
none` reads only what the payload already contains.

### Attachments

`--scan-attachments` is off by default. When enabled, an attachment is downloaded and
scanned only if it can plausibly be text:

- **Scanned extensions** (`TEXT_EXTENSIONS`): `txt`, `log`, `env`, `ini`, `conf`, `cfg`,
  `properties`, `pem`, `key`, `crt`, `cer`, `pub`, `json`, `yaml`, `yml`, `toml`, `xml`,
  `csv`, `sql`, `md`, `sh`, `ps1`, `py`, `rb`, `js`, `ts`, `go`, `rs`, `java`, `tf`,
  `tfvars`, `dockerfile`, `gitconfig`, `npmrc`.
- **Extensionless text files** matched by whole basename: `Dockerfile`, `Makefile`,
  `Gemfile`.
- **Text MIME types** accept an otherwise unknown extension: `text/*`, `application/json`,
  `application/xml`, `application/x-yaml` (parameters such as `; charset=utf-8` are
  ignored).
- **Never fetched**: archives and compressed files (`zip`, `tar`, `gz`, `tgz`, `bz2`, `xz`,
  `7z`, `rar`), executables and libraries (`exe`, `dll`, `so`, `dylib`, `bin`, `iso`),
  images (`png`, `jpg`, `jpeg`, `gif`, `bmp`, `ico`, `webp`, `svg`), PDFs, and office
  documents (`doc(x)`, `xls(x)`, `ppt(x)`, `odt`, `ods`, `odp`). The denylist is checked
  *before* the allowlist, so a misleading MIME type cannot get an archive fetched.
  Archives are skipped because the size limit is enforced on the bytes that arrive: a 1 MB
  `.zip` is under any per-attachment limit and can still expand to gigabytes, and the
  archived text would need a format-specific reader anyway. Binary and office formats are
  skipped because lossy UTF-8 decoding of compressed or structured binary produces noise,
  not reviewable findings.

Limits, on top of `--max-attachment-size-mb` (per file, default 10 MB):

- **20 attachments per issue** — a cap on requests, not bytes.
- **32 MiB per issue**, across all of its attachments — this is what bounds the scanner's
  memory to `concurrency × 32 MiB` at the defaults, since the per-file limit alone would
  allow 20 × 10 MB for one issue.

The declared size is checked before a request, so an oversized attachment costs nothing,
and the same limit is enforced again on the response while streaming: the body is read
chunk by chunk and cut off at the limit, so a response that declares no length, lies about
it, or is gzip-encoded cannot allocate past the limit.

The `content` URL that Jira reports for an attachment is attacker-controlled, so it must
resolve to the **same origin** as the configured Jira base URL — same scheme, host, and
effective port. A foreign host, a scheme downgrade, another port, a protocol-relative
`//host/path`, `file:`, or `javascript:` URL is refused with a warning and never fetched
(this is the SSRF guard, and it is an origin comparison rather than a prefix check, so
`https://jira.example.com.evil.tld/…` does not pass). The URL is re-validated inside the
download call, so the check cannot be skipped by a caller.

A scanned attachment becomes a segment named `attachment[<filename>]`: the name is
neutralised of terminal escapes, flattened of newlines and tabs, and capped at 128
characters, because it is repeated in every finding of that attachment and in every report.
Everything else about the scan is unchanged — the attachment text goes through the same
rules engine, credential-pair detector, allowlist, and confidence chain as a description.
An attachment that cannot be fetched, decoded, or trusted is warned about and counted; it
never fails the issue.

The scan summary reports real `comments_scanned` and `attachments_scanned` counters (the
numbers of comment bodies and attachment texts actually scanned).

## Reports

| Format | File extension | Description |
| --- | --- | --- |
| `json` | `.json` | One JSON document with the scan run and all findings (default). |
| `ndjson` | `.ndjson` | One JSON object per line. |
| `csv` | `.csv` | Tabular findings. |
| `sarif` | `.sarif` | SARIF 2.1.0 for IDE / CI integration. |
| `summary` | `.txt` | Human-readable console summary. |
| `defectdojo` | `.defectdojo.json` | DefectDojo Generic Findings Import JSON. |

- `--format` is a comma-separated list. `all` may appear anywhere in the list — `json,all`
  behaves like `all` — duplicates collapse, and an unknown or empty name is an error
  (exit `1`) raised before any directory is created, never a silent no-op.
- `--report-layout flat` (default) writes `<report-dir>/<date>T<time>_report.<ext>`.
  `nested` writes `<report-dir>/<project>/<date>/<time>_report.<ext>`, where `<project>` is
  a single project token taken from the JQL (`project = SEC` and `project in (SEC)` give
  `SEC`; several projects give `_multi`; anything else gives `_default`). The segment is
  filtered down to `[A-Za-z0-9_-]` and re-validated as a plain path component, so a hostile
  JQL cannot write a report outside `--report-dir`.
- **Snippets are always masked.** A snippet is a ±50-byte window around the match, so it
  can contain the secrets of neighbouring findings of the same segment; every one of them is
  replaced by `[REDACTED:<rule_id>]` before the snippet reaches a report, the findings store,
  or a webhook alert. The redacted secret is a first-2 / last-2 preview (`[REDACTED]` for
  values shorter than 8 characters) plus a `sha256:` hash.
- **CSV** cells have control characters removed and are prefixed with an apostrophe when the
  first visible character is a spreadsheet formula sigil (`=`, `+`, `-`, `@`), so a snippet
  cannot execute when the report is opened in Excel or LibreOffice.
- **Summary** text is stripped of terminal escape sequences (CSI, OSC — including OSC 52
  clipboard writes — and other control characters).

### SARIF

Results carry the Jira issue URL, the issue key, the field path, the confidence, the
status, the secret hash, and the tags. `tool.driver.rules` is populated for every rule the
results reference, described from the findings themselves with
`defaultConfiguration.level` set to the most severe level the rule produced.

A run that did not complete says so: `invocations[].executionSuccessful` is `false` for a
partial or failed scan, accompanied by a `toolExecutionNotifications` entry naming the
coverage (`N of M issues scanned, E errors`), because a partial scan must not be read as
evidence that nothing leaked.

### DefectDojo

Generic Findings Import JSON, importable with `scan_type=Generic Findings Import`.

- `unique_id_from_tool` is `fp:<64 hex>#<ordinal>` — the deterministic fingerprint of the
  finding's primary location `(secret_hash, rule_id, issue_key)`. It is identical on every
  scan of the same state, so DefectDojo updates an existing record instead of importing a
  new one, and closes a finding that stopped being reported. (A per-scan UUID used to be
  sent here, which made every import create fresh findings.)
- `verified` is `true` only when an external validation says the credential is live: a rule
  match is a candidate, not a confirmation, and importing candidates as verified hides the
  triage work.
- `active` and `false_p` are mutually exclusive: Closed, Resolved, and FalsePositive are
  imported inactive, and a false positive is imported inactive as well, so a finding the
  scan itself dismissed is not re-opened.

## Findings store

When a database URL is configured (`--db-url`, default `sqlite://{state_dir}/findings.db`),
findings are persisted and reconciled across scans:

- **Statuses**: `new`, `recurring`, `closed`, `confirmed`, `false_positive`, `resolved`.
- Identity is the deterministic fingerprint over `(secret_hash, rule_id, issue_key)`, so a
  secret found in each of N issues owns N rows with their own history. A finding absent from
  a re-scanned issue is marked `closed`; a repeat is `recurring` with `first_seen` preserved
  and `times_seen` incremented. Issues not included in the current JQL scope are left
  untouched, never falsely closed.
- PostgreSQL is also supported (`postgres://user:pass@host/db`).
- An external validation system can populate the `live_validations` table (by secret hash);
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

Each channel posts a scan summary plus top findings filtered by `min_confidence`
(default `medium`): Slack and Teams post the 10 highest-confidence findings as linked
lines, the generic webhook posts up to 20, together with the scan run.

Configuration is validated strictly, before the scan: unknown keys, an unreadable file, a
config with no channel at all, a blank channel URL, and an invalid `min_confidence` are all
configuration errors (exit `1`) — a typo in `webhook_url` would otherwise disable a channel
silently, and a `min_confidence` typo used to fall back to `low` and push low-confidence
findings to a production channel.

All three channels share one HTTP transport with a 10-second timeout, and channels are
delivered in parallel, so a dead destination costs one timeout rather than one per channel.
Delivery is fire-and-forget by contract — a failed webhook never fails the scan — but the
outcome is logged with the exact delivered/failed counts, and a channel that panics is
counted as that channel's failure rather than losing its siblings' delivery. Webhook URLs
are bearer secrets and are never logged or rendered in `Debug` output.

## Metrics

`--metrics-path <PATH>` writes a scan summary (issues scanned, findings by severity, errors,
duration, scanner version). `--metrics-format` accepts `json` (default), `prom`, and
`prometheus`; the retired `text` spelling is rejected. The parent directory is created when
missing.

## Deployment

- **Docker** — multi-stage build, runtime as non-root UID/GID 65532 with `WORKDIR /data`.
  The image sets `REPORT_OUTPUT_PATH=/data/reports` and
  `JIRALEAKS_DB_URL=sqlite:///data/state/findings.db?mode=rwc`, and declares
  `/data/reports` and `/data/state` as volumes. `--state-dir` has no environment variable:
  pass `--state-dir /data/state` to keep checkpoints on the volume. Build with
  `docker build -t jiraleaks .` and run with `JIRA_*` env vars; `docker run --rm jiraleaks
  --help` needs no credentials.
- **Kubernetes CronJob** — see [`deploy/k8s/cronjob.yaml`](deploy/k8s/cronjob.yaml):
  weekly (Mondays 03:00 UTC), `security` namespace, `Forbid` concurrency, a PVC holding
  both reports and the findings store, and a `securityContext` matching UID 65532
  (`runAsNonRoot`, `readOnlyRootFilesystem`, dropped capabilities). Credentials come from
  a `jira-credentials` Secret.
- **systemd timer** — see [`deploy/systemd/`](deploy/systemd/): a weekly
  `jiraleaks.timer` driving the `jiraleaks.service` oneshot, with credentials in
  `/etc/jiraleaks/env` (mode 0600), `StateDirectory=jiraleaks`, and a hardened unit.
- **Task runner** — `just --list` lists the recipes: `build`, `test`, `lint`,
  `lint-strict`, `fmt`, `fmt-check`, `docker-build`, `docker-smoke`, `docs-mermaid`,
  `scan`, `clean`.
- **CI** — [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `rustfmt --check`,
  `clippy`, `cargo test --all-targets`, and a Docker build with an entrypoint smoke test.

Examples use a generic `project = SEC` JQL scope; adjust to your environment.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success — including a scan that completed with non-critical per-issue errors logged. |
| `1` | Configuration error: invalid values, an unusable allowlist/alerts file, or a command line clap rejected. |
| `2` | Jira access error (authentication failure, unreachable host, refused attachment origin). |
| `3` | Critical scan error, or an unclassified internal error — a failure that prevented a stage from running. |
| `4` | Report write error (also used for checkpoint/state-directory write failures). |
| `5` | Store / persistence error. |

## Shell completions

```bash
jiraleaks completions bash      # or: zsh | fish | elvish | powershell
```

## Security notes

- jiraleaks is **read-only** against Jira: it fetches issues, comments, and (opt-in)
  attachment bodies, and never mutates Jira state.
- **Raw secrets never reach a sink.** Reports, the findings store, logs, and alerts contain
  a redacted preview (first-2 / last-2 characters) plus a SHA-256 hash. Snippets are masked
  for the matched value **and** for every other secret found in the same snippet window, so
  a neighbouring finding cannot leak through it. `Debug` impls of the config, the raw hit,
  and the candidate render the token and the secret as `***` / a preview.
- **Log lines are masked**: the token, alert webhook URLs, and matched secrets never appear
  in a log message, and `Config`'s `Debug` masks `pat`.
- **Text from Jira is untrusted input.** The summary report strips terminal escape
  sequences (including OSC 52 clipboard writes) and control characters; the CSV report
  neutralises spreadsheet formulas; attachment names are neutralised and length-capped
  before they are used as field paths; all reported text passes through one sanitiser.
- **Attachments are fetched only from the configured Jira origin**, with an SSRF guard that
  compares scheme, host, and effective port rather than a URL prefix, and downloads are
  streamed under a per-file limit and a per-issue byte budget.
- **Cost ceilings on hostile input**: the credential-pair detector reads at most 64 KiB of
  a segment and returns at most 256 hits, comment pagination is capped, per-issue attachment
  counts and bytes are capped, and `--max-findings-per-issue` bounds one issue's output.
- **Configuration is validated strictly**: the CLI, the allowlist, and the alerts config all
  reject unknown keys and unusable values at startup rather than degrading silently.
- Use a **least-privilege, read-only** Jira account for scanning, and keep `.env` files,
  reports, and the findings store out of version control (the repository's `.gitignore` and
  `.dockerignore` already cover `reports/`, the state directories, and `*.db`).

## License

MIT — see [`LICENSE`](LICENSE).

## Contributing

Pull requests are welcome. Run `just test`, `just fmt-check`, and `just lint` (or
`just lint-strict`) before submitting.
