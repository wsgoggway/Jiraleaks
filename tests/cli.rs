//! CLI contract tests: the process-level behaviour of the `jiraleaks` binary.
//!
//! Everything here is asserted through a real child process, because these are
//! exactly the properties no in-process test can prove:
//!
//! * the **exit codes** of the spec §15 table (1 config, 2 Jira access, …) as a
//!   caller and CI system observes them;
//! * `--help` / `--version` / `completions` succeed and print what they promise;
//! * a command line clap rejected is a *configuration* error (code 1), never the
//!   code 2 that is reserved for "Jira access error";
//! * which log lines reach the operator at each level, and that an explicitly
//!   configured level beats the inherited `RUST_LOG`.
//!
//! The runs that reach the Jira stage point at `http://127.0.0.1:1`, a port
//! nothing listens on (RFC 5737-style "closed port" trick, no network involved);
//! the client's three attempts with 500 ms + 1 s backoff fail in about two
//! seconds, so each such test stays well inside a few seconds. No test here
//! touches a network or writes outside `std::env::temp_dir()`.
//!
//! Note: `tracing_subscriber::fmt()` writes to **stdout**, not stderr, so the
//! log-level assertions below inspect stdout; stderr carries only the messages
//! `main` prints directly (configuration errors from `Config::validate`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Exit code of a command line the parser rejected — `ScannerError::CLI_PARSE_EXIT_CODE`.
/// Spelled out here rather than imported so that a change to the constant is
/// reported by this test as a contract change, not silently followed.
const CLI_ERROR: i32 = 1;
/// Exit code of a configuration error (`Config::validate`).
const CONFIG_ERROR: i32 = 1;
/// Exit code of "Jira access error" — auth failure, unreachable host.
const JIRA_ACCESS_ERROR: i32 = 2;

/// The compiled binary under test.
///
/// `assert_cmd` would be the usual choice and is deliberately not used: this
/// workspace builds `--offline` and neither `assert_cmd` nor `predicates` is in
/// the local registry cache, so the two assertions they would contribute —
/// "the process exited with this code" and "stdout contains this text" — are
/// three lines each here, on top of `std::process::Command`.
fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jiraleaks"));

    // The host environment must not decide the outcome: a developer shell that
    // exports `JIRA_URL`, or a CI image that sets `LOG_LEVEL`, would otherwise
    // change every assertion below. clap reads these variables itself (`env =
    // ...`), so they are removed here rather than overridden one by one.
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
        // reqwest honours the proxy variables; a corporate proxy must not be
        // able to intercept an unreachable-host run and change its outcome.
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

/// Run the binary with `args` and return the captured output.
fn run(args: &[&str]) -> Output {
    binary()
        .args(args)
        .output()
        .expect("the jiraleaks binary must be runnable")
}

/// A configuration good enough to reach the Jira stage, pointing at a closed
/// port. `--auth none` skips the token requirement; `--dry-run` keeps the run
/// from writing a report if it ever got that far.
fn unreachable_jira_args(extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--jira-url".into(),
        "http://127.0.0.1:1".into(),
        "--jql".into(),
        "project = CLI".into(),
        "--auth".into(),
        "none".into(),
        "--dry-run".into(),
        "--no-proxy".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));
    args
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A unique temporary directory, removed when the returned guard is dropped.
///
/// `std::process::id()` alone is not unique enough: test binaries in one `cargo
/// test` run share a process identity with whatever else the harness starts, and
/// a directory left behind by an earlier failed run would be reused. The pid, a
/// per-process counter and the wall clock together are unique per call *and* per
/// run, and the guard makes the cleanup run on the panic path too.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "jiraleaks-cli-{tag}-{}-{}-{nanos}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
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

// ── --help, --version, completions ──────────────────────────────────────────

/// Every long flag the CLI documents. Kept as data so the test says *which*
/// flag went missing instead of failing on a wall of text comparison.
const DOCUMENTED_FLAGS: &[&str] = &[
    "--jira-url",
    "--auth",
    "--pat",
    "--email",
    "--jql",
    "--page-size",
    "--max-issues",
    "--concurrency",
    "--fields",
    "--comments-mode",
    "--scan-attachments",
    "--max-attachment-size-mb",
    "--max-text-size-kb",
    "--max-findings-per-issue",
    "--allowlist",
    "--rules",
    "--min-confidence",
    "--format",
    "--report-dir",
    "--report-layout",
    "--dry-run",
    "--incremental",
    "--state-dir",
    "--db-url",
    "--metrics-path",
    "--metrics-format",
    "--log-level",
    "--no-proxy",
    "--alerts",
    "--help",
    "--version",
];

#[test]
fn help_exits_zero_and_documents_every_flag_group() {
    let output = run(&["--help"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));

    let text = stdout(&output);
    for flag in DOCUMENTED_FLAGS {
        assert!(text.contains(flag), "`--help` does not document {flag}");
    }
    // The auxiliary command must be discoverable from `--help` alone.
    assert!(text.contains("completions"));
    assert!(text.contains("Usage: jiraleaks"));
    // Help goes to stdout: an operator piping `--help` into `less` must see it.
    assert!(
        stderr(&output).is_empty(),
        "`--help` wrote to stderr: {}",
        stderr(&output)
    );
}

/// `--help` must win over a broken command line: clap reports help before it
/// validates anything else, and an operator debugging a flag wants the text.
#[test]
fn help_wins_over_a_broken_command_line() {
    let output = run(&["--jira-url", "not-a-url", "--jql", "", "--help"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Usage: jiraleaks"));
}

#[test]
fn version_exits_zero_and_prints_the_package_version() {
    let output = run(&["--version"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    let expected = format!("jiraleaks {}", env!("CARGO_PKG_VERSION"));
    assert!(
        stdout(&output).contains(&expected),
        "expected {expected:?} in {:?}",
        stdout(&output)
    );
}

/// Every shell `clap_complete` supports gets a script; an unknown shell is a
/// command-line error (code 1, not a Jira error).
#[test]
fn completions_are_generated_for_every_documented_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = run(&["completions", shell]);
        assert_eq!(
            code(&output),
            0,
            "`completions {shell}` failed: {}",
            stderr(&output)
        );
        let script = stdout(&output);
        assert!(
            script.len() > 100,
            "`completions {shell}` produced {} bytes",
            script.len()
        );
        assert!(
            script.contains("jiraleaks"),
            "`completions {shell}` does not mention the program name"
        );
    }
}

#[test]
fn completions_reject_an_unknown_shell() {
    let output = run(&["completions", "nushell"]);
    assert_eq!(code(&output), CLI_ERROR, "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("nushell"),
        "the error must name the rejected shell: {}",
        stderr(&output)
    );
}

#[test]
fn completions_help_exits_zero() {
    let output = run(&["completions", "--help"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("completions"));
}

// ── parse errors: code 1, never code 2 ──────────────────────────────────────

/// A flag that does not exist used to be indistinguishable from a failed
/// authentication: both reported code 2. Code 2 now means exactly one thing.
#[test]
fn an_unknown_flag_is_a_configuration_error_not_a_jira_error() {
    let output = run(&["--not-a-real-flag"]);
    assert_eq!(code(&output), CLI_ERROR, "stderr: {}", stderr(&output));
    assert_ne!(code(&output), JIRA_ACCESS_ERROR);
    assert!(
        stderr(&output).contains("--not-a-real-flag"),
        "the error must name the offending argument: {}",
        stderr(&output)
    );
}

/// `--metrics-format text` named a writer that never existed — the value was
/// accepted and silently produced JSON. It is rejected now.
#[test]
fn the_retired_metrics_format_text_is_rejected() {
    let output = run(&["--metrics-format", "text"]);
    assert_eq!(code(&output), CLI_ERROR, "stderr: {}", stderr(&output));

    let text = stderr(&output);
    assert!(text.contains("metrics format"), "unhelpful error: {text}");
    // The message must name the accepted spellings, or the operator cannot fix
    // the command line without reading the source.
    for accepted in ["json", "prom"] {
        assert!(
            text.contains(accepted),
            "error does not offer {accepted}: {text}"
        );
    }
}

/// A value clap rejects for an enum-like flag is a configuration error too.
#[test]
fn a_rejected_enum_value_is_a_configuration_error() {
    for (args, needle) in [
        (vec!["--auth", "nope"], "--auth"),
        (vec!["--metrics-format", "yaml"], "--metrics-format"),
    ] {
        let output = run(&args);
        assert_eq!(
            code(&output),
            CLI_ERROR,
            "`{args:?}` exited with {}: {}",
            code(&output),
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(needle),
            "`{args:?}` error does not name {needle}: {}",
            stderr(&output)
        );
    }
}

// ── configuration errors: code 1, message names the problem ─────────────────

/// Values that reach `Config::validate` — the library-level contract, which is
/// enforced for a `Config` built by a caller too, not only by clap.
#[test]
fn invalid_configuration_values_exit_one_and_name_the_problem() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["--jira-url", "", "--jql", "project = X"],
            "JIRA_URL is required",
        ),
        (
            &["--jira-url", "not-a-url", "--jql", "project = X"],
            "must start with http://",
        ),
        (
            &["--jira-url", "https://jira.example.com", "--jql", ""],
            "JIRA_JQL",
        ),
        // A token is supplied on purpose: `validate` checks the token before the
        // email, so without it this case would test the wrong rule.
        (
            &[
                "--jira-url",
                "https://jira.example.com",
                "--jql",
                "project = X",
                "--auth",
                "basic",
                "--pat",
                "tok",
            ],
            "JIRA_EMAIL",
        ),
    ];

    for (args, needle) in cases {
        let output = run(args);
        assert_eq!(
            code(&output),
            CONFIG_ERROR,
            "`{args:?}` exited with {}: {}",
            code(&output),
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(needle),
            "`{args:?}` error does not mention {needle}: {}",
            stderr(&output)
        );
    }
}

/// A missing `--jira-url` is reported as a configuration error by name.
#[test]
fn a_missing_jira_url_is_a_configuration_error() {
    let output = run(&["--jql", "project = X", "--auth", "none"]);
    assert_eq!(code(&output), CONFIG_ERROR, "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("JIRA_URL is required"),
        "unhelpful error: {}",
        stderr(&output)
    );
}

/// Values whose *range* is wrong: clap's ranged parsers reject them at parse
/// time, so they never reach `validate()`.
#[test]
fn out_of_range_values_exit_one_and_name_the_flag() {
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "--jira-url",
                "https://jira.example.com",
                "--jql",
                "project = X",
                "--page-size",
                "0",
            ],
            "--page-size",
        ),
        (
            &[
                "--jira-url",
                "https://jira.example.com",
                "--jql",
                "project = X",
                "--concurrency",
                "0",
            ],
            "--concurrency",
        ),
        (
            &[
                "--jira-url",
                "https://jira.example.com",
                "--jql",
                "project = X",
                "--report-layout",
                "wrong",
            ],
            "--report-layout",
        ),
        (
            &[
                "--jira-url",
                "https://jira.example.com",
                "--jql",
                "project = X",
                "--min-confidence",
                "nope",
            ],
            "--min-confidence",
        ),
        (
            &[
                "--jira-url",
                "https://jira.example.com",
                "--jql",
                "project = X",
                "--format",
                "pdf",
            ],
            "--format",
        ),
    ];

    for (args, needle) in cases {
        let output = run(args);
        assert_eq!(
            code(&output),
            CONFIG_ERROR,
            "`{args:?}` exited with {}: {}",
            code(&output),
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(needle),
            "`{args:?}` error does not name {needle}: {}",
            stderr(&output)
        );
    }
}

// ── Jira access: code 2 ─────────────────────────────────────────────────────

/// Nothing listens on port 1, so the client exhausts its retries and reports a
/// Jira access error. This is the only exit code a caller may read as "Jira",
/// which is why the parse and configuration cases above assert it is *not* 2.
#[test]
fn an_unreachable_jira_host_exits_two() {
    let args = unreachable_jira_args(&["--log-level", "error"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let started = std::time::Instant::now();
    let output = run(&refs);
    let elapsed = started.elapsed();

    assert_eq!(
        code(&output),
        JIRA_ACCESS_ERROR,
        "stdout: {} / stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    // The retry budget is a few seconds, not a hang: a test that waited for a
    // 30-second request timeout would be a bug in the test.
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "the unreachable-host run took {elapsed:?}"
    );
    assert!(
        stdout(&output).contains("Failed to connect to Jira"),
        "the failure must be reported to the operator: {}",
        stdout(&output)
    );
}

// ── logging: level filtering and the RUST_LOG fallback ──────────────────────

/// One row of the log-level table: how the level is configured, and which of the
/// three lines of an unreachable-host run must then appear.
struct LogCase {
    label: &'static str,
    /// Extra command-line arguments for this case.
    args: &'static [&'static str],
    /// Extra environment variables for this case.
    env: &'static [(&'static str, &'static str)],
    expect_info: bool,
    expect_warn: bool,
    expect_error: bool,
}

/// The three sources of the level and their documented priority
/// (`src/log.rs::resolve_filter`).
///
/// All six runs go through the unreachable-host path, which is what makes them
/// observable: it emits an INFO line at startup, WARN lines per retry and an
/// ERROR line at the end, so each level's effect is visible in one run.
#[test]
fn log_level_decides_which_lines_reach_the_operator() {
    const INFO_LINE: &str = "Starting jiraleaks";
    const WARN_LINE: &str = "Network error, retrying";
    const ERROR_LINE: &str = "Failed to connect to Jira";

    let cases = [
        LogCase {
            label: "default level (info)",
            args: &[],
            env: &[],
            expect_info: true,
            expect_warn: true,
            expect_error: true,
        },
        LogCase {
            label: "--log-level error",
            args: &["--log-level", "error"],
            env: &[],
            expect_info: false,
            expect_warn: false,
            expect_error: true,
        },
        LogCase {
            label: "RUST_LOG=error fallback",
            args: &[],
            env: &[("RUST_LOG", "error")],
            expect_info: false,
            expect_warn: false,
            expect_error: true,
        },
        LogCase {
            label: "LOG_LEVEL=error from the environment",
            args: &[],
            env: &[("LOG_LEVEL", "error")],
            expect_info: false,
            expect_warn: false,
            expect_error: true,
        },
        // An explicit level wins over an inherited RUST_LOG: this is the
        // contract that stops a developer shell from re-enabling debug output.
        LogCase {
            label: "--log-level warn beats RUST_LOG=debug",
            args: &["--log-level", "warn"],
            env: &[("RUST_LOG", "debug")],
            expect_info: false,
            expect_warn: true,
            expect_error: true,
        },
        LogCase {
            label: "--log-level error beats RUST_LOG=trace",
            args: &["--log-level", "error"],
            env: &[("RUST_LOG", "trace")],
            expect_info: false,
            expect_warn: false,
            expect_error: true,
        },
    ];

    for case in &cases {
        let label = case.label;
        let output = {
            let args = unreachable_jira_args(case.args);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut command = binary();
            command.args(&refs);
            for (key, value) in case.env {
                command.env(key, value);
            }
            command.output().expect("the binary must be runnable")
        };

        assert_eq!(
            code(&output),
            JIRA_ACCESS_ERROR,
            "{label}: {}",
            stderr(&output)
        );
        let text = stdout(&output);
        for (line, expected, what) in [
            (INFO_LINE, case.expect_info, "an info line"),
            (WARN_LINE, case.expect_warn, "a warn line"),
            (ERROR_LINE, case.expect_error, "the error line"),
        ] {
            assert_eq!(
                text.contains(line),
                expected,
                "{label}: {what} ({line:?}) presence should be {expected}, output was:\n{text}"
            );
        }
    }
}

// ── the store: `--db-url ''` is a legal value ───────────────────────────────

/// An empty `--db-url` means "no store" (`Config::db_url`), so it must parse and
/// get past validation: the run proceeds to the Jira stage and fails there with
/// code 2, exactly like a run without the flag. A rejected value would exit 1
/// with a configuration error, and a value that meant "open the default store"
/// would create one.
///
/// That the store is not actually opened is asserted where it is observable —
/// against a working Jira mock, in `tests/e2e_pipeline.rs`.
#[test]
fn an_empty_db_url_is_accepted_and_means_no_store() {
    let temp = TempDir::new("empty-db-url");
    let state_dir = temp.path().join("state");

    let args = unreachable_jira_args(&[
        "--db-url",
        "",
        "--state-dir",
        state_dir.to_str().expect("utf-8 temp path"),
    ]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&refs);

    assert_eq!(
        code(&output),
        JIRA_ACCESS_ERROR,
        "an empty --db-url must not be a configuration error: {}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("Configuration error"));
    // Nothing opened a store, so nothing created one either: the Jira stage is
    // reached before the store is, and it fails.
    assert!(
        !state_dir.join("findings.db").exists(),
        "an empty --db-url must not open the default store"
    );
}

/// The failures of this suite must not leave state behind: the guard removes a
/// temp directory on the panic path too.
#[test]
fn temp_directories_are_unique_per_call() {
    let first = TempDir::new("unique");
    let second = TempDir::new("unique");
    assert_ne!(first.path(), second.path());
    let created = first.path().to_path_buf();
    std::fs::create_dir_all(&created).expect("create temp dir");
    assert!(created.is_dir());
    drop(first);
    assert!(!created.exists(), "the guard must remove the directory");
}
