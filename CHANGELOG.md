# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comment scanning now covers the whole thread: the comment pages after the one embedded
  in the issue payload are fetched (up to `MAX_COMMENT_PAGES` pages, warning when the cap
  is hit) and scanned with the same rules engine, allowlist and confidence chain. A failed
  extra-page fetch is logged and never fails the issue.
- Attachment scanning is real, not a placeholder: attachments are filtered by an extension
  allowlist (`TEXT_EXTENSIONS`) with a denylist for archives, binaries, images, PDFs and
  office formats checked first, by whole-basename text files (`Dockerfile`, `Makefile`,
  `Gemfile`), and by text MIME type as a fallback; the body is streamed with a cut-off at
  `--max-attachment-size-mb`, the `content` URL must be same-origin with the configured
  Jira base URL (scheme, host, effective port) or it is never fetched, and the scanned text
  becomes a segment named `attachment[<name>]`. Per-issue limits: 20 attachments and 32 MiB.
- `--incremental` narrows the query sent to Jira to `(<configured JQL>) AND updated >=
  "<UTC timestamp>"` where the timestamp is the previous successful scan's finish time minus
  a 5-minute overlap, so boundary changes are not missed. The versioned checkpoint records
  the configured JQL, the Jira base URL, the finish instant and the scan status, and is used
  only when all of them match the current run; a missing, stale, foreign or future-dated
  checkpoint falls back to a full scan with the reason logged at info level. The configured
  JQL is parenthesized before the `AND` is appended, and a checkpoint is written only after a
  fully successful scan.
- Real `comments_scanned` and `attachments_scanned` counters in `scan_run` (they were
  hardcoded to 0).
- One owner of the candidate verdict (`candidate` module): a single placeholder dictionary
  (18 words, read in `contains` and `exact` modes), a single context-word list, a single
  ordered filter chain, and a `DropReason` logged at debug level for every rejected
  candidate.
- Strict configuration loading for the allowlist and the alerts config: unknown keys, an
  entry with no match condition, an empty predicate, a malformed SHA-256, an
  uncompilable regex, a config with no channel, and an invalid `min_confidence` are
  configuration errors (exit 1).
- Alert channels behind an `AlertChannel` trait with pure payload builders and one shared
  HTTP transport (10-second timeout, one failure shape); delivery stays fire-and-forget,
  but the delivered/failed outcome is logged, and a panicking channel is counted as that
  channel's failure instead of losing its siblings' delivery.
- DefectDojo `unique_id_from_tool` is now `fp:<64 hex>#<ordinal>`, derived from the stable
  finding fingerprint `(secret_hash, rule_id, issue_key)`.
- SARIF: `invocations[].executionSuccessful` is `false` for a partial or failed scan, with a
  `toolExecutionNotifications` entry naming the coverage; `tool.driver.rules` is populated
  for the rules the results reference.
- Single report-format catalogue: names, extensions and dispatch come from one table, so a
  format cannot be half-added.
- Infrastructure: `justfile` task runner, GitHub Actions CI (`fmt`, `clippy`, `test`,
  Docker build + entrypoint smoke test), `.gitignore`/`.dockerignore` coverage for
  `reports/`, the state directories and `*.db`, `docs-mermaid` recipe.

### Changed

- Commands and flags now tell the truth about what the code does: the typed
  `MetricsFormat` accepts `json`, `prom` and `prometheus` (the retired `text` spelling is
  rejected instead of silently producing JSON), the JQL-derived path segment is sanitised,
  and exit codes come from one mapping.
- `--format` handling: `all` works anywhere in the list (`json,all`), duplicates collapse,
  an unknown or empty name is an error (exit 1) raised before any directory is created, and
  every format has one file extension (`summary` → `.txt`, `defectdojo` → `.defectdojo.json`).
- DefectDojo semantics: `verified` is true only when an external validation marks the
  credential live, and `active` / `false_p` are mutually exclusive, so a finding the scan
  dismissed is not re-opened on import and candidates are not imported as verified.
- Log filter precedence: an explicit `--log-level` or `LOG_LEVEL` wins over `RUST_LOG`,
  which is now only a fallback.
- `JIRA_API_TOKEN` is a real environment fallback for `JIRA_PAT` (precedence: `--pat`,
  `JIRA_PAT`, `JIRA_API_TOKEN`); previously the documented alias was an argument alias and
  was never read from the environment.
- `Config::validate()` checks the Jira URL scheme, a non-empty JQL, positive size limits,
  the report layout, the confidence level, the auth mode and the token requirement, and a
  library caller gets the same rejections as the binary.
- Checkpoint and state directories are created with 0700 permissions; report directories
  likewise.
- Docker: `WORKDIR /data`, pinned `REPORT_OUTPUT_PATH` / `JIRALEAKS_DB_URL` environment
  variables, and `VOLUME ["/data/reports", "/data/state"]` — the image previously failed to
  build (migrations were not copied) and the documented `docker run` exited 5 with no
  reports.
- Kubernetes CronJob: PVC-backed reports and store, `securityContext` matching UID 65532,
  `readOnlyRootFilesystem`, and `--state-dir /data/state`.
- systemd unit: `StateDirectory` / `WorkingDirectory`, credentials from an
  `EnvironmentFile`, hardening, and `--state-dir` passed explicitly.

### Removed

- The `--config <PATH>` flag, which parsed a path and read nothing.
- The accepted value `text` for `--metrics-format`.
- The second placeholder list in the credential-pair detector (merged into the shared
  dictionary).
- The dead `detect_yaml_properties` stub.

### Fixed

- **Credential-pair denial of service**: the proximity heuristic built the full
  cross-product of username and password matches, so one hostile field could pin a worker
  for minutes. It now uses a two-cursor sliding window, inspects at most 64 KiB of a
  segment, materialises at most 4096 matches per pattern and returns at most 256 hits.
- **UTF-8 panics on long fields**: text truncation and snippet/context windows are backed
  off to character boundaries, so a Cyrillic or emoji payload no longer panics the scanner.
- **Nested report layout path traversal**: the project segment taken from `project in
  (...)` is filtered to `[A-Za-z0-9_-]` and re-validated as a plain path component, so a
  hostile JQL cannot write a report outside `--report-dir`.
- Allowlist `field` is honoured: the scope matches the finding's field path exactly or as a
  subpath (`field: comment` covers `comment.body`, but not `comments` or
  `fields.comment`) and narrows the whole record, key predicates included. `reason` is
  written to the debug log with the suppression it justifies.
- Comment pages after the first are scanned instead of fetched and dropped (a silent loss
  of findings); attachment and comment counters report real numbers.
- SARIF and DefectDojo statements about a scan now match what the scan actually knows.
- DefectDojo imports no longer create a new finding per scan.
- Report writes and metrics writes: the metrics parent directory is created, and a report
  is logged as written only after its writer returned `Ok`.
- A rejected command line exits 1 (clap's own exit code 2 collided with "Jira access
  error"); an unclassified internal error exits 3 instead of 0.

### Security

- **Raw secret leak in `snippet` closed**: a snippet is a ±50-byte window around the match
  and could carry the secrets of neighbouring findings of the same segment. Every secret in
  the window is now masked as `[REDACTED:<rule_id>]` before the snippet reaches a report,
  the findings store or a webhook alert. Previously raw JWT values were reported in full.
- **Spreadsheet formula injection**: CSV fields have control characters removed and are
  prefixed with an apostrophe when the first visible character is `=`, `+`, `-` or `@`.
- **Terminal escape injection**: summary text, log messages and attachment names are
  stripped of CSI/OSC sequences (including OSC 52 clipboard writes), C0/C1 controls and
  DEL, so Jira content cannot repaint an operator's terminal or write to their clipboard.
- **SSRF in attachment fetching**: the attachment `content` URL is validated against the
  configured Jira origin (scheme, host, effective port) with a protocol-relative URL
  refused before resolution, re-validated inside the download call, and the body is
  streamed with both the declared and the actual size enforced.
- **Attachment and comment resource exhaustion**: bounded comment pages, attachment count
  and byte budgets per issue, and streaming downloads that stop at the limit instead of
  buffering a body and truncating afterwards.
- **Allowlist patterns** run under an explicit backtracking budget; a pattern that exceeds
  it is logged and treated as not matching, so it can never silently suppress a finding.
- Alert webhook URLs and the Jira token are treated as bearer secrets: never logged, masked
  in `Debug`, and never part of an alert error message.

## [0.1.0] - 2026-08-07

### Added

- Kingfisher-inspired detection accuracy practices (offline; no network validation):
  - `ignore_if_contains` per-rule substring filter plus a global default placeholder list
    (`example`, `test`, `sample`, `demo`, `dummy`, `placeholder`, `changeme`, `your_key`,
    `yourkey`, `your-key`, `xxxx`, `foobar`, `redacted`, `fake`) applied to every rule;
    opt out per rule with `disable_default_placeholders: true` (used by `stripe_key`,
    where `test` is part of the `sk_test_`/`rk_test_` format).
  - Character-class requirements per rule: `min_digits`, `min_uppercase`,
    `min_lowercase`, `min_special_chars`, `special_chars`. `aws_secret_access_key`
    requires `min_digits: 3`; the generic assignment rules require `min_digits: 1`.
  - `examples` and `references` on rules; references surface on findings and JSON
    reports. Builtin rules enriched with examples/references from mongodb/kingfisher.
  - `github_token_checksum` validator (CRC32 + base62). Not attached to any builtin
    rule; available for user rules via the `validator:` field.
  - Confidence now upgrades Medium → High when a secret context keyword appears within
    ±50 chars and entropy is above threshold (previously the context signal was
    hardcoded false).

### Changed

- Removed the dead `allowed_context` field from the rule schema.
- `DEFAULT_PLACEHOLDERS` excludes bare digit runs so real tokens embedding them (Telegram
  bot ids, Slack workspace numbers) are not rejected.
- `tests/detection_quality.rs` fixtures use realistic non-placeholder values, since AWS
  `...EXAMPLE` keys are now correctly rejected by the placeholder filter.

### Fixed

- `AKIAIOSFODNN7EXAMPLE`-style documentation examples are no longer reported.
