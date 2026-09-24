//! End-to-end scan: the real `jiraleaks` process against a mocked Jira.
//!
//! `tests/attachments.rs` already drives `pipeline::run` in-process. This suite
//! deliberately covers the layer above it: the **binary** is spawned with a
//! command line an operator would write, so the process wiring is under test —
//! clap's `--format all` expansion, the default findings store, and the report
//! files that end up on disk. What is asserted is what an operator can see:
//! the exit code, the files, and their content.
//!
//! The one invariant that matters most here is a *negative*: the raw secret must
//! not appear in any file the scan writes. Each report format is read back as a
//! string for that check, not only parsed — a leak into a CSV column or a SARIF
//! message would otherwise hide behind a successful parse.
//!
//! The Jira mock is a wiremock server on localhost; the binary is always given
//! `--no-proxy` and a scrubbed environment so nothing outside this process can
//! decide the outcome.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── fixture ─────────────────────────────────────────────────────────────────

/// Alphanumerics a fixture token is built from. Deliberately free of every
/// placeholder word the scanner filters on (`example`, `test`, `demo`, `sample`,
/// `fake`, `xxxx`, `foobar`, `dummy`, `changeme`, `redacted`, `placeholder`,
/// `your_key`): the point of the fixture is detection, not filtering.
const TOKEN_BODY: &str = "Qz3Kf8Rm2Tb7Vn5Wp1Yh4Ld6Jc9Sg0Ax2EyBw9";

/// A token the built-in `github_token` rule matches: `ghp_` + 36 alphanumerics.
///
/// `tag` distinguishes the call sites so each finding can be attributed to
/// exactly one place in the fixture — deduplication merges by secret hash, so
/// equal tokens would collapse into a single finding.
fn token(tag: &str) -> String {
    assert!(tag.len() < 36, "the tag must leave room for the token body");
    format!("ghp_{tag}{}", &TOKEN_BODY[..36 - tag.len()])
}

/// The issue body of the attachment the mock serves.
fn attachment_body() -> String {
    format!(
        "image: registry.internal/payments:1.2.3\npasted-output: {}\n",
        token("c")
    )
}

fn issue(id: &str, key: &str, fields: Value) -> Value {
    json!({"id": id, "key": key, "fields": fields})
}

/// The two issues the mock search returns, one per page.
///
/// `TEST-1` carries all three places a secret can hide — description, comment
/// body, attachment text — so the counters `comments_scanned` and
/// `attachments_scanned` are one each; `TEST-2` is clean and proves the scan
/// reports on issues it finds nothing in.
fn fixture_pages(server_uri: &str) -> (Value, Value) {
    let first = issue(
        "1",
        "TEST-1",
        json!({
            "summary": "Rotate the deploy credential",
            "description": format!(
                "Rotated the deploy credential. New value is {} and the old one is revoked.",
                token("a")
            ),
            "comment": {
                "total": 1,
                "startAt": 0,
                "maxResults": 50,
                "comments": [{
                    "id": "100",
                    "author": {"displayName": "Operator"},
                    "body": format!("Checked the pipeline logs, everything looks fine. Ref {}", token("b")),
                }],
            },
            "attachment": [{
                "id": "10001",
                "filename": "prod.env",
                "size": attachment_body().len(),
                "mimeType": "text/plain",
                "content": format!("{server_uri}/secure/attachment/10001/prod.env"),
            }],
        }),
    );
    let second = issue(
        "2",
        "TEST-2",
        json!({
            "summary": "Release notes",
            "description": "Nothing sensitive here, just the release notes for the sprint.",
        }),
    );

    (
        json!({"total": 2, "startAt": 0, "maxResults": 1, "issues": [first]}),
        json!({"total": 2, "startAt": 1, "maxResults": 1, "issues": [second]}),
    )
}

/// Mount the whole Jira surface the scan touches: `serverInfo` (the binary
/// checks it before scanning), two search pages, and the attachment body.
async fn mount_jira(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "baseUrl": server.uri(),
            "version": "9.12.37",
            "deploymentType": "Server",
            "serverTitle": "Mock Jira",
        })))
        .mount(server)
        .await;

    let (page_one, page_two) = fixture_pages(&server.uri());
    for (start_at, page) in [(0, page_one), (1, page_two)] {
        Mock::given(method("GET"))
            .and(path("/rest/api/2/search"))
            .and(query_param("startAt", start_at.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(page))
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/secure/attachment/10001/prod.env"))
        .respond_with(ResponseTemplate::new(200).set_body_string(attachment_body()))
        .mount(server)
        .await;
}

// ── process plumbing ────────────────────────────────────────────────────────

/// The compiled binary, with an environment that cannot change the outcome.
fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jiraleaks"));
    for var in [
        "JIRA_URL",
        "JIRA_JQL",
        "JIRA_PAT",
        "JIRA_API_TOKEN",
        "JIRA_EMAIL",
        "JIRA_AUTH",
        "JIRA_NO_PROXY",
        "SCAN_PAGE_SIZE",
        "SCAN_MAX_ISSUES",
        "SCAN_CONCURRENCY",
        "SCAN_FIELDS",
        "SCAN_COMMENTS_MODE",
        "SCAN_ATTACHMENTS_ENABLED",
        "REPORT_FORMAT",
        "REPORT_OUTPUT_PATH",
        "JIRALEAKS_REPORT_LAYOUT",
        "JIRALEAKS_INCREMENTAL",
        "JIRALEAKS_DB_URL",
        "ALLOWLIST_PATH",
        "RULES_PATH",
        "LOG_LEVEL",
        "RUST_LOG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(var);
    }
    command
}

/// Run the binary to completion off the async runtime's worker threads: the
/// mock server needs a thread to answer on while the child process runs.
async fn run_binary(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        binary()
            .args(&args)
            .output()
            .expect("the jiraleaks binary must be runnable")
    })
    .await
    .expect("the blocking run must not panic")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the binary must exit normally, not be killed by a signal")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A temporary directory removed by its guard, on the panic path included.
///
/// The name carries the pid, a per-process counter *and* the wall clock: a
/// directory left behind by an interrupted run would otherwise be reused, and
/// two test binaries started at the same moment would collide on the pid alone.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "jiraleaks-e2e-{tag}-{}-{}-{nanos}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The single file in `dir` whose name ends with `_report.<ext>`.
///
/// Exactly one is required: two would mean a format was written twice, none
/// would mean `--format` promised a report that never appeared.
fn report_file(dir: &Path, ext: &str) -> PathBuf {
    let suffix = format!("_report.{ext}");
    let matching: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("report dir {} is unreadable: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().ends_with(&suffix))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one {suffix} file in {}, found {matching:?}",
        dir.display()
    );
    matching[0].clone()
}

/// Every file in `dir`, with its content, for the leak check.
fn all_files_with_content(dir: &Path) -> Vec<(PathBuf, String)> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{} is unreadable: {e}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .map(|path| {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} is unreadable: {e}", path.display()));
            (path, content)
        })
        .collect()
}

/// Every file under `root`, recursively, whatever its format.
fn all_files_recursive(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

// ── the happy path ──────────────────────────────────────────────────────────

/// One full scan: every report format, the store, the metrics file.
struct ScanOutcome {
    output: Output,
    report_dir: PathBuf,
    temp: TempDir,
}

async fn full_scan(extra: &[&str]) -> ScanOutcome {
    let server = MockServer::start().await;
    mount_jira(&server).await;

    let temp = TempDir::new("full");
    let report_dir = temp.path().join("reports");
    let state_dir = temp.path().join("state");

    let mut args: Vec<String> = vec![
        "--jira-url".into(),
        server.uri(),
        "--jql".into(),
        "project = TEST".into(),
        "--pat".into(),
        "test-token".into(),
        "--no-proxy".into(),
        "--format".into(),
        "all".into(),
        "--report-dir".into(),
        report_dir.display().to_string(),
        "--state-dir".into(),
        state_dir.display().to_string(),
        // Two pages of one issue each: the pagination loop is exercised, not
        // only a single search request.
        "--page-size".into(),
        "1".into(),
        "--concurrency".into(),
        "1".into(),
        "--scan-attachments".into(),
        "--metrics-path".into(),
        temp.path().join("metrics.json").display().to_string(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));

    let output = run_binary(args).await;
    ScanOutcome {
        output,
        report_dir,
        temp,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_scan_writes_every_report_format() {
    let scan = full_scan(&[]).await;
    let output = &scan.output;
    assert_eq!(
        code(output),
        0,
        "the scan failed. stdout: {}",
        stdout(output)
    );

    let dir = &scan.report_dir;
    assert!(dir.is_dir(), "no report directory was created");

    // json — the machine-readable report, and the one the counters live in.
    let json_path = report_file(dir, "json");
    let json_text = std::fs::read_to_string(&json_path).expect("json report readable");
    let json_report: Value = serde_json::from_str(&json_text).expect("json report parses");
    let scan_run = &json_report["scan_run"];

    assert_eq!(scan_run["issues_scanned"], 2, "issues_scanned");
    assert_eq!(scan_run["issues_total"], 2, "issues_total");
    assert_eq!(scan_run["comments_scanned"], 1, "comments_scanned");
    assert_eq!(scan_run["attachments_scanned"], 1, "attachments_scanned");
    assert_eq!(scan_run["findings_total"], 3, "findings_total");
    assert_eq!(scan_run["errors_total"], 0, "errors_total");
    assert_eq!(scan_run["findings_high"], 3, "findings_high");
    assert_eq!(scan_run["status"], "success", "status");
    assert_eq!(scan_run["jql"], "project = TEST");

    // The three findings are the three fixture secrets, each attributed to the
    // place it was found in.
    let findings = json_report["findings"]
        .as_array()
        .expect("findings is an array")
        .clone();
    assert_eq!(findings.len(), 3, "findings: {findings:#?}");
    let mut field_paths: Vec<&str> = findings
        .iter()
        .map(|f| {
            assert_eq!(f["rule_id"], "github_token", "unexpected rule: {f}");
            f["field_path"].as_str().expect("field_path is a string")
        })
        .collect();
    field_paths.sort_unstable();
    assert_eq!(
        field_paths,
        vec![
            "attachment[prod.env]",
            "comment.comments[0].body",
            "description"
        ],
        "each secret must be attributed to its own field path"
    );

    // ndjson — one finding per line.
    let ndjson_path = report_file(dir, "ndjson");
    let ndjson_text = std::fs::read_to_string(&ndjson_path).expect("ndjson report readable");
    let lines: Vec<&str> = ndjson_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 3, "ndjson lines: {lines:?}");
    for line in &lines {
        let parsed: Value = serde_json::from_str(line).expect("every ndjson line parses");
        assert_eq!(parsed["rule_id"], "github_token");
    }

    // csv — parsed with the csv crate, as any consumer would.
    let csv_path = report_file(dir, "csv");
    let mut reader = csv::Reader::from_path(&csv_path).expect("csv report opens");
    let headers = reader.headers().expect("csv header").clone();
    assert!(
        headers.iter().any(|h| h == "rule_id"),
        "csv header lacks rule_id: {headers:?}"
    );
    let rows: Vec<csv::StringRecord> = reader
        .records()
        .map(|record| record.expect("csv record parses"))
        .collect();
    assert_eq!(rows.len(), 3, "csv rows: {rows:?}");
    let rule_column = headers.iter().position(|h| h == "rule_id").unwrap();
    for row in &rows {
        assert_eq!(&row[rule_column], "github_token");
    }

    // sarif — a JSON document with the version consumers dispatch on.
    let sarif_path = report_file(dir, "sarif");
    let sarif: Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).expect("sarif readable"))
            .expect("sarif parses");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("sarif results")
            .len(),
        3
    );

    // summary — the human-readable report, and the counters in it.
    let summary_path = report_file(dir, "txt");
    let summary = std::fs::read_to_string(&summary_path).expect("summary readable");
    assert!(summary.contains("Issues scanned:    2"), "{summary}");
    assert!(summary.contains("Comments scanned:  1"), "{summary}");
    assert!(summary.contains("Findings"), "{summary}");

    // defectdojo — a second JSON schema, written to its own extension.
    let defectdojo_path = report_file(dir, "defectdojo.json");
    let defectdojo: Value = serde_json::from_str(
        &std::fs::read_to_string(&defectdojo_path).expect("defectdojo readable"),
    )
    .expect("defectdojo parses");
    let defectdojo_findings = defectdojo["findings"]
        .as_array()
        .or_else(|| defectdojo["results"].as_array())
        .expect("defectdojo findings array");
    assert_eq!(defectdojo_findings.len(), 3, "{defectdojo:#?}");

    // metrics — written by the same run, in its own file.
    let metrics: Value = serde_json::from_str(
        &std::fs::read_to_string(scan.temp.path().join("metrics.json")).expect("metrics readable"),
    )
    .expect("metrics parses");
    assert_eq!(metrics["findings_total"], 3);
    assert_eq!(metrics["issues_scanned"], 2);

    // The store was opened and migrated: the default db_url derives from
    // --state-dir, and the file is the proof.
    assert!(
        scan.temp.path().join("state/findings.db").is_file(),
        "the findings store was not created under --state-dir"
    );

    // ── the invariant: the raw secret is in no file the scan wrote ──
    let secrets: Vec<String> = ["a", "b", "c"].iter().map(|tag| token(tag)).collect();
    let files = all_files_with_content(dir);
    assert!(files.len() >= 6, "expected six reports, got {files:?}");
    let mut checked = 0usize;
    for (path, content) in &files {
        for secret in &secrets {
            assert!(
                !content.contains(secret.as_str()),
                "the raw secret leaked into {}",
                path.display()
            );
        }
        checked += 1;
    }
    // The secret is reported, only never raw: the redacted form is present.
    for secret in &secrets {
        let redacted = format!("{}...{}", &secret[..2], &secret[secret.len() - 2..]);
        assert!(
            json_text.contains(&redacted),
            "the redacted form {redacted} is missing from the json report"
        );
    }
    assert_eq!(checked, files.len());

    // And again at the byte level, over *every* file the run wrote — the metrics
    // file and the sqlite store included. Both are written by the same process
    // from the same findings, and a leak into either would not survive the
    // string comparison above: the store is the file that stays on disk after
    // the run, so it is the one where a cleartext secret would go unnoticed
    // longest.
    let all = all_files_recursive(scan.temp.path());
    assert!(
        all.iter().any(|path| path.ends_with("state/findings.db")),
        "the store must be part of the byte-level sweep: {all:?}"
    );
    for path in &all {
        let bytes = std::fs::read(path).expect("every file the run wrote is readable");
        for secret in &secrets {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "the raw secret leaked into {}",
                path.display()
            );
        }
    }
}

/// `--dry-run` writes no report — that is the whole point of the flag, and the
/// store still runs (it is not what `--dry-run` disables).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dry_run_writes_no_report_files() {
    let scan = full_scan(&["--dry-run"]).await;
    assert_eq!(code(&scan.output), 0, "stdout: {}", stdout(&scan.output));

    assert!(
        !scan.report_dir.exists(),
        "a dry run created {}",
        scan.report_dir.display()
    );
    // No report file may appear anywhere under the scan's temp directory.
    for (path, _) in all_files_with_content(scan.temp.path()) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        assert!(
            !name.contains("_report."),
            "a dry run wrote {}",
            path.display()
        );
    }
}

// ── store failures ──────────────────────────────────────────────────────────

/// A store that cannot be opened is exit code 5 (Store) **and** the reports of
/// that run are still written.
///
/// The store is a side channel: it enriches a finding with its history (status,
/// `times_seen`, live validation) and keeps the audit row of the run, but the
/// findings are collected without it. A scan that found secrets must never be
/// silent, so `pipeline::run` warns about the store, keeps going on the
/// unenriched findings, emits the reports, metrics, alerts and checkpoint as
/// usual, and returns the remembered store error at the very end — which is what
/// leaves the exit code at 5 without costing the operator the report.
///
/// `sqlite://<tmp>/blocker/findings.db` is used rather than an unwritable system
/// path: `<tmp>/blocker` is a regular *file*, so creating its "parent directory"
/// fails with `Not a directory` on any machine, root or not, without touching
/// anything outside `std::env::temp_dir()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unavailable_store_still_writes_the_reports_and_exits_five() {
    let server = MockServer::start().await;
    mount_jira(&server).await;

    let temp = TempDir::new("store-failure");
    let report_dir = temp.path().join("reports");
    let blocker = temp.path().join("blocker");
    std::fs::write(&blocker, b"a file where a directory is needed").expect("write the blocker");

    let args: Vec<String> = vec![
        "--jira-url".into(),
        server.uri(),
        "--jql".into(),
        "project = TEST".into(),
        "--pat".into(),
        "test-token".into(),
        "--no-proxy".into(),
        "--format".into(),
        "all".into(),
        "--report-dir".into(),
        report_dir.display().to_string(),
        "--page-size".into(),
        "1".into(),
        "--concurrency".into(),
        "1".into(),
        "--db-url".into(),
        format!("sqlite://{}/findings.db?mode=rwc", blocker.display()),
    ];

    let output = run_binary(args).await;
    assert_eq!(
        code(&output),
        5,
        "a store failure must exit with the store code. stdout: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("Store error"),
        "the failure must be reported: {}",
        stdout(&output)
    );

    // The findings survived the store failure: this run has no
    // `--scan-attachments`, so the description and the comment body are the two
    // secrets it found.
    let json_path = report_file(&report_dir, "json");
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("json report readable"))
            .expect("json report parses");
    assert_eq!(
        report["scan_run"]["findings_total"], 2,
        "the findings of the scan must reach the report even when the store is gone: {report:#?}"
    );
    assert_eq!(
        report["findings"]
            .as_array()
            .expect("findings is an array")
            .len(),
        2,
        "both findings must be in the report: {report:#?}"
    );

    // Every format, not only json: the report stage ran to its end.
    for ext in ["json", "ndjson", "csv", "sarif", "txt", "defectdojo.json"] {
        let path = report_file(&report_dir, ext);
        assert!(
            path.is_file() && path.metadata().expect("metadata").len() > 0,
            "{} is empty after a store failure",
            path.display()
        );
    }
}

/// An empty `--db-url` disables the store for real: the same scan, with the
/// store off, writes its reports and creates no database anywhere.
///
/// `--state-dir` is still set, so a store that ignored the empty URL would be
/// caught by the missing `findings.db`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_db_url_disables_the_store_and_keeps_the_reports() {
    let scan = full_scan(&["--db-url", ""]).await;
    assert_eq!(code(&scan.output), 0, "stdout: {}", stdout(&scan.output));

    let json_path = report_file(&scan.report_dir, "json");
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("json report readable"))
            .expect("json report parses");
    assert_eq!(report["scan_run"]["findings_total"], 3);

    for (path, _) in all_files_with_content(scan.temp.path()) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        assert!(
            !name.ends_with(".db"),
            "an empty --db-url created a store: {}",
            path.display()
        );
    }
}

// ── the remaining exit codes: 3 (critical scan) and 4 (report write) ────────

/// Exit code 3: a failure that stops the scan. A search response the client
/// cannot parse means the scanner does not know what it did not read, so the run
/// must not end successfully — and no report may claim otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_search_response_exits_three() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "baseUrl": server.uri(),
            "version": "9.12.37",
            "deploymentType": "Server",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not a search page"))
        .mount(&server)
        .await;

    let temp = TempDir::new("scan-critical");
    let report_dir = temp.path().join("reports");
    let args: Vec<String> = vec![
        "--jira-url".into(),
        server.uri(),
        "--jql".into(),
        "project = TEST".into(),
        "--pat".into(),
        "test-token".into(),
        "--no-proxy".into(),
        "--report-dir".into(),
        report_dir.display().to_string(),
        "--state-dir".into(),
        temp.path().join("state").display().to_string(),
    ];

    let output = run_binary(args).await;
    assert_eq!(
        code(&output),
        3,
        "a malformed search response must be a critical scan error. stdout: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("Failed to parse search results"),
        "the failure must name the stage that broke: {}",
        stdout(&output)
    );
    assert!(
        !report_dir.exists(),
        "an aborted scan must not leave a report behind"
    );
}

/// Exit code 4: the scan ran to the end but the report could not be written.
///
/// The report directory is a regular *file* here, so `create_dir_all` fails on
/// the first write. The point of the test is the code: a run whose findings
/// never reached disk must not report success, and it must be distinguishable
/// from the store failure above (code 5) — the two stages are different failures
/// for the operator.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unwritable_report_directory_exits_four() {
    let server = MockServer::start().await;
    mount_jira(&server).await;

    let temp = TempDir::new("report-write");
    let blocked_report_dir = temp.path().join("reports");
    std::fs::write(&blocked_report_dir, b"a file where a directory is needed")
        .expect("write the blocker");

    let args: Vec<String> = vec![
        "--jira-url".into(),
        server.uri(),
        "--jql".into(),
        "project = TEST".into(),
        "--pat".into(),
        "test-token".into(),
        "--no-proxy".into(),
        "--report-dir".into(),
        blocked_report_dir.display().to_string(),
        "--state-dir".into(),
        temp.path().join("state").display().to_string(),
    ];

    let output = run_binary(args).await;
    assert_eq!(
        code(&output),
        4,
        "an unwritable report directory is a report write error. stdout: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("Report write error"),
        "the failure must name the report stage: {}",
        stdout(&output)
    );
    // The store is a different stage and it did succeed: the run got past it.
    assert!(
        temp.path().join("state/findings.db").is_file(),
        "the store is opened before the reports are written"
    );
}
