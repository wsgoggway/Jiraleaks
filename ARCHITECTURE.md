# Architecture

Developer-facing internals for `jiraleaks`. For usage, see [`README.md`](README.md).

## Components

| Module | Responsibility |
| --- | --- |
| `config` | CLI flags + env vars (clap), validation, defaults. |
| `jira/client` | HTTP client for Jira REST API v2: auth, retries, rate-limit semaphore, gzip. |
| `jira/models` | Serde types for search pages, issues, comments, attachments, server info. |
| `fetcher` | Paginated JQL fetch; streams issues over a bounded channel. |
| `extract` | Per-issue text extraction: recursive JSON walk, ADF traversal, source-type tagging, size truncation. |
| `detectors/builtin` | The 20 builtin rule definitions (embedded YAML). |
| `rules` | Rule schema, YAML load/merge, compilation, non-overlapping regex scan. |
| `credpair` | Credential-pair detector (URL userinfo, proximity, JSON). |
| `entropy` | Shannon entropy scoring. |
| `allowlist` | Allowlist load + match (value / sha256 / pattern / rule_id / issue / project). |
| `redact` | Secret masking: redacted preview + sha256 hash. |
| `dedup` | Cross-issue deduplication of findings. |
| `pipeline` | Orchestrates the full scan: fetch → process → reconcile → report. |
| `store` | SQLite/PostgreSQL findings store + cross-scan reconciliation + live-validation join. |
| `checkpoint` | Writes incremental-scan checkpoint state. |
| `report/*` | Output writers: `json`, `ndjson`, `csv`, `sarif`, `defectdojo`, `summary`; layout + project segment. |
| `alert/*` | Notifications: `slack`, `teams`, `webhook` (fire-and-forget). |
| `metrics` | Scan metrics summary (JSON / Prometheus exposition writer). |
| `progress` | `indicatif` progress bar + counters. |
| `log` | `tracing` subscriber setup with secret-span masking. |
| `error` | `ScannerError` enum → exit-code mapping. |
| `hash` | SHA-256 secret hashing for fingerprints / dedup. |
| `validators` | Rule validators: `aws_key_checksum`, `jwt_structure`, `github_token_checksum`. |

## Scan pipeline

`pipeline::run` drives a streaming, concurrent scan:

1. **Init** — load/merge rules, load allowlist, build the extractor, credpair detector,
   and deduplicator. A `CancellationToken` is created and wired to SIGINT/SIGTERM for
   graceful shutdown.
2. **Fetch stream** — `fetcher.fetch_issues_stream` opens a bounded mpsc channel and
   pushes issues page by page. An `indicatif` progress bar tracks `pos/len`.
3. **Concurrent processing** — issues pulled from the channel are spawned onto a
   `JoinSet`. **Backpressure**: before each spawn, completed tasks are drained while
   `join_set.len() >= concurrency * 2`, bounding in-flight work to `concurrency × 2`.
4. **Per-issue processing** (`process_issue`) — extract text segments → run rules engine
   → run credpair detector → apply allowlist → adjust confidence (context-keyword boost)
   → redact → cap findings per issue.
5. **Drain** — remaining tasks are collected; the fetch task is awaited for errors.
6. **Dedup** — all findings are inserted into the deduplicator and collapsed.
7. **Reconcile** — if a DB URL is configured, findings are reconciled against the store.
8. **Tally** — findings are counted by severity; `ScanRun` is assembled.
9. **Emit** — reports (`--dry-run` skips), metrics, and alerts are written.
10. **Persist** — the scan is recorded in the store audit table; a checkpoint is written
    on success when `--incremental` is set.

Cancellation short-circuits the fetch loop and produces a `Partial` scan status while
still emitting the partial results gathered so far.

## Rule schema

Each rule (YAML, fields mirror `rules::Rule`):

```
rule_id, description, severity, confidence, regex,
capture_group, min_length, min_entropy,
context_keywords, denylist, ignore_if_contains,
min_digits, min_uppercase, min_lowercase, min_special_chars, special_chars,
validator, enabled, disable_default_placeholders,
examples, references
```

- `severity` ∈ critical/high/medium/low/info; `confidence` ∈ high/medium/low.
- Defaults: `severity = medium`, `confidence = medium`, `enabled = true`.
- User rules override builtins sharing the same `rule_id`.

**Matching algorithm** (non-overlapping scan per rule per text segment):

1. The compiled regex scans the segment. When `capture_group` is set, the named/numbered
   group is the candidate; otherwise the whole match is.
2. Candidates are filtered, in order: placeholder list (global defaults unless
   `disable_default_placeholders`), `ignore_if_contains`, `denylist`, `min_length`,
   char-class requirements (`min_digits`/`min_uppercase`/`min_lowercase`/
   `min_special_chars` against `special_chars`), `min_entropy` (Shannon), and
   `context_keywords` (presence within a ±50 char window can boost confidence).
3. After a match, the cursor advances past the match end so matches never overlap.
4. An optional `validator` (e.g. `aws_key_checksum`, `jwt_structure`) re-checks the
   candidate and discards invalid ones.

The global placeholder list (14 entries) intentionally excludes bare digit runs so that
real tokens embedding digit sequences (Telegram bot ids, Slack workspace numbers) are not
rejected.

## Text extraction

`TextExtractor` walks each issue's fields and comments (and attachments when enabled):

- Recursive descent over JSON values; Atlassian Document Format (`adf`) nodes are
  traversed to collect text content.
- Each segment is tagged with a `SourceType` (`description`, `comment`, `attachment`,
  `customfield`) so findings carry provenance.
- Segments longer than `max_text_size_kb` are truncated before scanning.

## Report formats

- **json** — `{ scan_run, findings: [...] }`.
- **ndjson** — one finding (or scan-run header) object per line.
- **csv** — one row per finding with fixed columns.
- **sarif** — SARIF 2.1.0; `tool.driver` identifies jiraleaks; per-result `properties`
  carry `rule_id`, severity, confidence, `issue_key`, `times_seen`, and optional
  `external_validation`.
- **defectdojo** — Generic Findings Import JSON; `active`/`verified`/`false_p`/tags are
  derived from `FindingStatus`; severity is title-cased.
- **summary** — human-readable counts by severity.

Layout: `flat` → `<report-dir>/<timestamp>_report.<ext>`; `nested` →
`<report-dir>/<project>/<date>/<time>_report.<ext>`, where `<project>` is derived from the
JQL `project` clause (single project token, or `_multi` / `_default`).

All formats emit the **redacted** secret and its sha256 hash only.

## Findings store

Backed by `sqlx::Any`, so the same code targets SQLite (local) and PostgreSQL
(deployment). Schema (`migrations/0001_init.sql`):

- **`findings`** — `fingerprint` (PK), `secret_hash`, `rule_id`, `issue_key`,
  `issue_url`, `severity`, `confidence`, `status`, `field_path`, `source_type`,
  `redacted_secret`, `snippet`, `locations_json`, `references_json`, `username`,
  `first_seen`, `last_seen`, `closed_at`, `times_seen`, `scan_id_last`.
  Indexes on `issue_key`, `secret_hash`, `status`.
- **`live_validations`** — `secret_hash` (PK), `valid`, `checked_at`, `source`,
  `details`. Populated by an external checker; joined during reconcile to annotate and
  promote findings.
- **`scans`** — `scan_id` (PK), `started_at`, `finished_at`, `status`, `jira_url`,
  `jql`, `issues_scanned`, `findings_total`. Audit log of completed scans.

**Fingerprint** (stable PK) = `fp:` + sha256(`secret_hash` `\x1f` `rule_id` `\x1f`
`issue_key`). The per-issue `finding_id` (UUID v4) is regenerated each scan and is **not**
a stable key.

**Reconciliation** (per scan, in a transaction):

1. Expand current findings to per-(`hash`, `rule`, `issue`) rows using the fingerprint.
2. Read stored rows for the issues actually scanned this run.
3. **Close** — a stored row whose issue was rescanned but whose fingerprint is absent
   from the current set is marked `closed` (with `closed_at`). Issues outside the current
   JQL scope are never closed.
4. **Upsert** — current rows are inserted or updated (portable `ON CONFLICT`). `New` if
   `first_seen` is within this scan; `Recurring` otherwise, with `times_seen` incremented
   and `first_seen` preserved.
5. **Live-validation join** — if a `live_validations` row exists for a finding's hash, it
   is attached; a `valid=true` validation can promote the effective severity/confidence
   on the reported finding (the stored DB severity is unchanged).
