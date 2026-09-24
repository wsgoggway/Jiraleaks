//! Allowlist filter tests: every match type with its negatives, the `field`
//! scope contract, strict loading, and hostile patterns.
//!
//! The filter decides what an operator never hears about, so a bug here is a
//! missed leak rather than a noisy report. The two properties under test are
//! therefore: a record suppresses exactly what it says (no wider), and a record
//! that cannot work is a configuration error (never a silent no-op).

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jiraleaks::allowlist::{AllowlistEntry, AllowlistFilter};
use jiraleaks::error::ScannerError;
use jiraleaks::hash::secret_hash;

/// A unique path under the temp dir, removed by each test when it is done with it.
fn temp_path(extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "jiraleaks_allowlist_{}_{}.{extension}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

fn entry(yaml: &str) -> AllowlistEntry {
    serde_yaml::from_str(yaml).expect("valid allowlist entry yaml")
}

fn filter(yaml: &str) -> AllowlistFilter {
    AllowlistFilter::from_entries(vec![entry(yaml)]).expect("entry compiles")
}

fn config_error(yaml: &str) -> String {
    match AllowlistFilter::from_entries(vec![entry(yaml)]) {
        Err(ScannerError::Config(msg)) => msg,
        other => panic!("expected a Config error for {yaml:?}, got {other:?}"),
    }
}

// ── match by value ──

#[test]
fn value_matches_exactly_and_only_exactly() {
    let f = filter("value: AKIAIOSFODNN7EXAMPLE\n");
    assert!(f.is_allowed(
        "AKIAIOSFODNN7EXAMPLE",
        "aws_access_key_id",
        "SEC-1",
        "description"
    ));
    // Superstring, substring and a different case are different secrets.
    assert!(!f.is_allowed(
        "AKIAIOSFODNN7EXAMPLEZ",
        "aws_access_key_id",
        "SEC-1",
        "description"
    ));
    assert!(!f.is_allowed(
        "AKIAIOSFODNN7EXAMPL",
        "aws_access_key_id",
        "SEC-1",
        "description"
    ));
    assert!(!f.is_allowed(
        "akiaiosfodnn7example",
        "aws_access_key_id",
        "SEC-1",
        "description"
    ));
    // The value survives whitespace: only key fields are trimmed.
    let spaced = filter("value: ' secret with spaces '\n");
    assert!(spaced.is_allowed(" secret with spaces ", "r", "SEC-1", "description"));
    assert!(!spaced.is_allowed("secret with spaces", "r", "SEC-1", "description"));
}

// ── match by sha256 ──

#[test]
fn sha256_matches_both_documented_forms() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let digest = secret_hash(secret); // "sha256:<hex>", as reports print it
    let bare = digest.strip_prefix("sha256:").expect("prefix").to_string();

    let prefixed = filter(&format!("sha256: '{digest}'\n"));
    assert!(prefixed.is_allowed(secret, "r", "SEC-1", "description"));

    let unprefixed = filter(&format!("sha256: '{bare}'\n"));
    assert!(unprefixed.is_allowed(secret, "r", "SEC-1", "description"));

    let uppercase = filter(&format!("sha256: '{}'\n", bare.to_ascii_uppercase()));
    assert!(uppercase.is_allowed(secret, "r", "SEC-1", "description"));
}

#[test]
fn sha256_does_not_match_another_value() {
    let other = secret_hash("SOMEOTHEREXAMPLEVALUE");
    let f = filter(&format!("sha256: '{other}'\n"));
    assert!(!f.is_allowed("AKIAIOSFODNN7EXAMPLE", "r", "SEC-1", "description"));
}

// ── match by pattern ──

#[test]
fn pattern_matches_unanchored_search_and_negative() {
    let f = filter("pattern: 'EXAMPLE'\n");
    assert!(f.is_allowed("AKIAIOSFODNN7EXAMPLE", "r", "SEC-1", "description"));
    assert!(!f.is_allowed("AKIAIOSFODNN7REALKEY", "r", "SEC-1", "description"));
}

#[test]
fn pattern_anchors_are_honoured() {
    let anchored = filter("pattern: '^ghp_docs_'\n");
    assert!(anchored.is_allowed(
        "ghp_docs_abcdefghijklmnopqrstuvwxyz012345",
        "r",
        "SEC-1",
        "d"
    ));
    assert!(!anchored.is_allowed(
        "prefix-ghp_docs_abcdefghijklmnopqrstuvwxyz012345",
        "r",
        "SEC-1",
        "d"
    ));

    let end_anchored = filter("pattern: '_docs$'\n");
    assert!(end_anchored.is_allowed("ghp_docs", "r", "SEC-1", "d"));
    assert!(!end_anchored.is_allowed("ghp_docs_tail", "r", "SEC-1", "d"));
}

#[test]
fn pattern_with_backreference_is_supported() {
    // Forces the fancy-regex VM rather than the delegated engine.
    let f = filter("pattern: '^(\\w+)-\\1$'\n");
    assert!(f.is_allowed("token-token", "r", "SEC-1", "description"));
    assert!(!f.is_allowed("token-other", "r", "SEC-1", "description"));
}

// ── match by rule_id / issue_key / project_key ──

#[test]
fn rule_id_matches_exactly() {
    let f = filter("rule_id: aws_access_key_id\n");
    assert!(f.is_allowed("any", "aws_access_key_id", "SEC-1", "description"));
    assert!(!f.is_allowed("any", "aws_secret_access_key", "SEC-1", "description"));
    assert!(!f.is_allowed("any", "AWS_ACCESS_KEY_ID", "SEC-1", "description"));
}

#[test]
fn issue_key_matches_exactly() {
    let f = filter("issue_key: SEC-123\n");
    assert!(f.is_allowed("any", "r", "SEC-123", "description"));
    assert!(!f.is_allowed("any", "r", "SEC-1234", "description"));
    assert!(!f.is_allowed("any", "r", "OPS-123", "description"));
    assert!(!f.is_allowed("any", "r", "sec-123", "description"));
}

#[test]
fn project_key_matches_the_issue_key_prefix() {
    let f = filter("project_key: SEC\n");
    assert!(f.is_allowed("any", "r", "SEC-1", "description"));
    assert!(f.is_allowed("any", "r", "SEC-9999", "comment[0].body"));
    assert!(!f.is_allowed("any", "r", "SECRET-1", "description"));
    assert!(!f.is_allowed("any", "r", "OPS-1", "description"));
}

// ── field scope ──

#[test]
fn field_scope_matches_exact_path_and_subpaths() {
    let f = filter("value: SECRETVALUE123456\nfield: comment\n");
    for path in [
        "comment",
        "comment.body",
        "comment[0].text",
        "comment.comments[0].body",
    ] {
        assert!(
            f.is_allowed("SECRETVALUE123456", "r", "SEC-1", path),
            "field: comment must cover {path}"
        );
    }
}

#[test]
fn field_scope_does_not_suppress_outside_the_scope() {
    // The regression this change exists for: `field: description` used to
    // suppress the value in every field of the issue, hiding a second leak in a
    // comment. It must not.
    let f = filter("value: SECRETVALUE123456\nfield: description\n");
    assert!(f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "description"));
    assert!(!f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "comment.body"));
    assert!(!f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "summary"));
    assert!(!f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "attachment:dump.txt"));
    assert!(!f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "fields.description"));
    // Same prefix, different path: not a subpath, no suppression.
    assert!(!f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "descriptions"));
}

#[test]
fn entry_without_field_suppresses_in_every_field() {
    let f = filter("value: SECRETVALUE123456\nreason: docs sample\n");
    for path in [
        "description",
        "comment[0].body",
        "summary",
        "attachment:dump.txt",
    ] {
        assert!(
            f.is_allowed("SECRETVALUE123456", "r", "SEC-1", path),
            "an entry without `field` must cover {path}"
        );
    }
}

#[test]
fn field_scope_narrows_rule_and_key_predicates_as_well() {
    // Documented decision: `field` narrows the whole record, key predicates
    // included, so a scoped record can never suppress outside its scope.
    let by_rule = filter("rule_id: aws_access_key_id\nfield: description\n");
    assert!(by_rule.is_allowed("any", "aws_access_key_id", "SEC-1", "description"));
    assert!(!by_rule.is_allowed("any", "aws_access_key_id", "SEC-1", "comment.body"));

    let by_project = filter("project_key: SEC\nfield: comment\n");
    assert!(by_project.is_allowed("any", "r", "SEC-1", "comment[1].body"));
    assert!(!by_project.is_allowed("any", "r", "SEC-1", "description"));

    let by_issue = filter("issue_key: SEC-123\nfield: summary\n");
    assert!(by_issue.is_allowed("any", "r", "SEC-123", "summary"));
    assert!(!by_issue.is_allowed("any", "r", "SEC-123", "description"));

    let by_hash = filter(&format!(
        "sha256: '{}'\nfield: description\n",
        secret_hash("x")
    ));
    assert!(by_hash.is_allowed("x", "r", "SEC-1", "description"));
    assert!(!by_hash.is_allowed("x", "r", "SEC-1", "comment.body"));
}

#[test]
fn scoped_and_unscoped_records_coexist() {
    let f = AllowlistFilter::from_entries(vec![
        entry("value: SCOPEDVALUE12345\nfield: description\n"),
        entry("value: GLOBALVALUE12345\n"),
    ])
    .expect("both records compile");

    assert!(f.is_allowed("SCOPEDVALUE12345", "r", "SEC-1", "description"));
    assert!(!f.is_allowed("SCOPEDVALUE12345", "r", "SEC-1", "comment.body"));
    assert!(f.is_allowed("GLOBALVALUE12345", "r", "SEC-1", "comment.body"));
}

#[test]
fn multiple_records_are_or_ed() {
    let f = AllowlistFilter::from_entries(vec![
        entry("rule_id: aws_access_key_id\n"),
        entry("issue_key: SEC-7\n"),
        entry("pattern: 'EXAMPLE$'\n"),
    ])
    .expect("all records compile");

    assert!(f.is_allowed("any", "aws_access_key_id", "OPS-7", "summary"));
    assert!(f.is_allowed("any", "r", "SEC-7", "summary"));
    assert!(f.is_allowed("PLAINEXAMPLE", "r", "OPS-7", "summary"));
    assert!(!f.is_allowed("any", "r", "OPS-7", "summary"));
}

// ── reason is an audit trail ──

/// Captures `tracing` output of the current thread into a shared buffer.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("log buffer").clone()).expect("utf8 logs")
    }
}

#[test]
fn reason_is_logged_when_the_entry_suppresses() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();

    let f = filter("value: SECRETVALUE123456\nfield: description\nreason: public docs example\n");

    let suppressed = tracing::subscriber::with_default(subscriber, || {
        f.is_allowed(
            "SECRETVALUE123456",
            "aws_access_key_id",
            "SEC-1",
            "description",
        )
    });

    assert!(suppressed, "the entry must still match with a reason set");
    let text = logs.text();
    assert!(
        text.contains("public docs example"),
        "the operator's reason must reach the log: {text}"
    );
    assert!(text.contains("aws_access_key_id"), "{text}");
}

#[test]
fn no_log_and_no_match_without_a_reason() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();

    let f = filter("value: SECRETVALUE123456\n");
    let suppressed = tracing::subscriber::with_default(subscriber, || {
        f.is_allowed("DIFFERENTVALUE1234", "r", "SEC-1", "description")
    });

    assert!(!suppressed);
    assert!(
        logs.text().trim().is_empty(),
        "a non-matching candidate must not be logged: {}",
        logs.text()
    );
}

// ── strict loading ──

#[test]
fn unknown_key_is_a_config_error() {
    let err = serde_yaml::from_str::<AllowlistEntry>("valeu: AKIAIOSFODNN7EXAMPLE\n")
        .expect_err("a typo must not deserialize");
    let msg = err.to_string();
    assert!(msg.contains("valeu"), "the error must name the key: {msg}");
}

#[test]
fn unknown_key_in_a_file_names_the_file() {
    let path = temp_path("yaml");
    std::fs::write(&path, "- issue_key: SEC-1\n  valeu: SECRETVALUE123456\n").expect("write");
    let err = AllowlistFilter::from_file(&path).expect_err("typo must fail the load");
    let _ = std::fs::remove_file(&path);

    match err {
        ScannerError::Config(msg) => {
            assert!(msg.contains("valeu"), "the error must name the key: {msg}");
            assert!(
                msg.contains(path.to_string_lossy().as_ref()),
                "the error must name the file: {msg}"
            );
            // serde_yaml supplies the position of the offending key, and the
            // message keeps it: the operator has to find the record.
            assert!(
                msg.contains("line 2"),
                "the error must carry a position: {msg}"
            );
        }
        other => panic!("expected a Config error, got {other:?}"),
    }
}

#[test]
fn entry_without_any_predicate_is_a_config_error() {
    let msg = config_error("reason: looks harmless\n");
    assert!(msg.contains("entry #1"), "{msg}");
    assert!(msg.contains("no match condition"), "{msg}");
}

#[test]
fn empty_predicate_values_are_config_errors() {
    // `pattern: ''` would match every value — the whole scan would go silent.
    assert!(config_error("pattern: ''\n").contains("empty"));
    assert!(config_error("value: ''\n").contains("empty"));
    assert!(config_error("value: '   '\n").contains("empty"));
    assert!(config_error("issue_key: ''\nvalue: x\n").contains("empty"));
    assert!(config_error("field: ''\nvalue: x\n").contains("empty"));
    // `field` is a scope, not a predicate: it cannot stand alone.
    assert!(config_error("field: description\n").contains("no match condition"));
}

#[test]
fn invalid_regex_is_a_config_error_naming_the_pattern() {
    let msg = config_error("pattern: 'a('\n");
    assert!(msg.contains("entry #1"), "{msg}");
    assert!(msg.contains("a("), "the error must name the pattern: {msg}");
}

#[test]
fn malformed_sha256_is_a_config_error() {
    let msg = config_error("sha256: deadbeef\n");
    assert!(msg.contains("deadbeef"), "{msg}");
    assert!(msg.contains("SHA-256"), "{msg}");
    assert!(config_error(&format!("sha256: '{}'\n", "z".repeat(64))).contains("SHA-256"));
}

// ── loading from a file ──

#[test]
fn file_round_trip_loads_and_filters() {
    let path = temp_path("yaml");
    std::fs::write(
        &path,
        "- value: SCOPEDVALUE12345\n  field: comment\n  reason: docs sample\n\
         - rule_id: aws_access_key_id\n",
    )
    .expect("write allowlist");
    let f = AllowlistFilter::from_file(&path).expect("allowlist loads");
    let _ = std::fs::remove_file(&path);

    assert!(f.is_allowed("SCOPEDVALUE12345", "r", "SEC-1", "comment[0].body"));
    assert!(!f.is_allowed("SCOPEDVALUE12345", "r", "SEC-1", "description"));
    assert!(f.is_allowed("any", "aws_access_key_id", "SEC-1", "description"));
}

#[test]
fn empty_file_and_null_document_are_valid_and_suppress_nothing() {
    for content in ["", "\n", "   \n", "null\n", "[]\n"] {
        let path = temp_path("yaml");
        std::fs::write(&path, content).expect("write allowlist");

        // An unused allowlist is legal but loud: a path typo that yields an empty
        // file must not look like a working configuration.
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let filter =
            tracing::subscriber::with_default(subscriber, || AllowlistFilter::from_file(&path));
        let _ = std::fs::remove_file(&path);

        let filter = filter.unwrap_or_else(|e| panic!("{content:?} must load: {e}"));
        assert!(
            logs.text().contains("allowlist is empty"),
            "{content:?} must warn about an empty allowlist: {}",
            logs.text()
        );
        assert!(
            !filter.is_allowed(
                "AKIAIOSFODNN7EXAMPLE",
                "aws_access_key_id",
                "SEC-1",
                "description"
            ),
            "{content:?} must suppress nothing"
        );
    }
}

#[test]
fn missing_file_is_a_config_error() {
    let path = temp_path("yaml");
    match AllowlistFilter::from_file(&path) {
        Err(ScannerError::Config(msg)) => assert!(
            msg.contains(path.to_string_lossy().as_ref()),
            "must name the missing file: {msg}"
        ),
        other => panic!("expected a Config error, got {other:?}"),
    }
}

// ── hostile input ──

/// Ceiling for one hostile match. A pattern without a backtracking limit does
/// not finish at all on these inputs; the tripwire is generous by orders of
/// magnitude on purpose.
const HOSTILE_BUDGET: Duration = Duration::from_secs(2);

#[test]
fn catastrophic_backtracking_pattern_terminates_quickly() {
    // Both shapes: `(a+)+$` (delegated or fancy depending on the engine's
    // analysis) and the backreference form, which always takes the fancy VM.
    // The value must make the pattern *fail*: `(a+)+$` matches a string of only
    // `a`s on the first try and never backtracks, so a trailing `b` is what
    // turns it catastrophic.
    for pattern in [r"(a+)+$", r"^(a+)+\1$"] {
        let f = filter(&format!("pattern: '{pattern}'\n"));
        let value = format!("{}b", "a".repeat(20_000));
        let started = Instant::now();
        let suppressed = f.is_allowed(&value, "r", "SEC-1", "description");
        let elapsed = started.elapsed();

        assert!(
            elapsed < HOSTILE_BUDGET,
            "pattern {pattern} took {elapsed:?} on a 20 000 byte value"
        ); // Fail-open for detection: a pattern that cannot finish never suppresses.
        assert!(
            !suppressed,
            "pattern {pattern} must not suppress on timeout"
        );
    }
}

#[test]
fn huge_pattern_is_rejected_at_load_time() {
    let huge = "(".repeat(5_000) + &")".repeat(5_000);
    let started = Instant::now();
    let result = AllowlistFilter::from_entries(vec![entry(&format!("pattern: '{huge}'\n"))]);
    assert!(
        started.elapsed() < HOSTILE_BUDGET,
        "compiling a hostile pattern took {:?}",
        started.elapsed()
    );
    // Either it compiles or it is a clean configuration error — never a panic.
    match result {
        Ok(f) => assert!(!f.is_allowed("aaaaaaaaaa", "r", "SEC-1", "description")),
        Err(ScannerError::Config(msg)) => {
            assert!(msg.contains("invalid regex pattern"), "{msg}")
        }
        Err(other) => panic!("expected a Config error, got {other:?}"),
    }
}

#[test]
fn long_value_is_matched_without_quadratic_blowup() {
    // A megabyte-long matched value is reachable: a rule like `[^\s]+` on a
    // segment crafted by an attacker produces one. Exact equality and an
    // anchored pattern search both have to stay linear in the value length.
    let value = format!("{}needle-at-the-end", "a".repeat(1_000_000));

    let by_value = filter(&format!("value: '{value}'\n"));
    let started = Instant::now();
    assert!(by_value.is_allowed(&value, "r", "SEC-1", "description"));
    let equality_elapsed = started.elapsed();
    assert!(
        equality_elapsed < HOSTILE_BUDGET,
        "exact equality on a 1 MB value took {equality_elapsed:?}"
    );

    let by_pattern = filter("pattern: 'needle-at-the-end$'\n");
    let started = Instant::now();
    assert!(by_pattern.is_allowed(&value, "r", "SEC-1", "description"));
    let pattern_elapsed = started.elapsed();
    assert!(
        pattern_elapsed < HOSTILE_BUDGET,
        "a pattern search over a 1 MB value took {pattern_elapsed:?}"
    );
}
