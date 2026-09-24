//! Integration tests for `--incremental`: the checkpoint file, the JQL it
//! narrows, and every case in which it must *not* narrow anything.
//!
//! The narrowing is the risky half of incremental scanning — an issue left out of
//! the window is a leak reported nowhere — so the tests here are mostly about the
//! fallbacks: no file, a corrupt file, a file for another query or another Jira
//! instance, a baseline from a scan that did not succeed.

use std::path::PathBuf;

use jiraleaks::checkpoint::{self, checkpoint_path, plan_incremental_scan, window_start};
use jiraleaks::config::Config;
use jiraleaks::finding::{ScanRun, ScanStatus};
use time::OffsetDateTime;

const JIRA_URL: &str = "https://jira.example.com";

/// The JQL the incremental tests run with.
const JQL: &str = "project = SEC OR project = OPS";

fn at(rfc3339: &str) -> OffsetDateTime {
    OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339)
        .expect("valid test timestamp")
}

/// A throwaway `--state-dir`, removed when the test ends — pass or fail.
struct TempState {
    dir: PathBuf,
}

impl TempState {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("jiraleaks-checkpoint-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp state dir");
        Self { dir }
    }

    fn config(&self, jql: &str) -> Config {
        let mut config = Config::test_config(JIRA_URL, "test-token");
        config.state_dir = self.dir.clone();
        config.incremental = true;
        config.jql = Some(jql.to_string());
        config
    }

    fn checkpoint_file(&self) -> PathBuf {
        self.dir.join("checkpoint.json")
    }

    fn write_raw(&self, content: &str) {
        std::fs::write(self.checkpoint_file(), content).expect("write the raw checkpoint");
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn scan_run(status: ScanStatus, finished_at: &str) -> ScanRun {
    ScanRun {
        scan_id: "scan-1".into(),
        status,
        started_at: "2026-01-02T03:00:00Z".into(),
        finished_at: finished_at.into(),
        jira_url: JIRA_URL.into(),
        jql: JQL.into(),
        issues_scanned: 1,
        issues_total: 1,
        findings_total: 0,
        findings_critical: 0,
        findings_high: 0,
        findings_medium: 0,
        findings_low: 0,
        findings_info: 0,
        errors_total: 0,
        comments_scanned: 0,
        attachments_scanned: 0,
        scanner_version: "0.1.0".into(),
        duration_secs: 1.0,
    }
}

// ── the query ──

#[test]
fn a_single_project_query_is_parenthesized() {
    assert_eq!(
        checkpoint::narrow_jql("project = SEC", at("2026-01-02T03:04:05Z")),
        "(project = SEC) AND updated >= \"2026-01-02 03:04\""
    );
}

#[test]
fn an_or_query_keeps_the_and_out_of_the_operands() {
    // Unparenthesized, Jira binds the `AND` to the last operand only: the scan
    // would silently cover `project = OPS` unfiltered.
    assert_eq!(
        checkpoint::narrow_jql("project = SEC OR project = OPS", at("2026-01-02T03:04:05Z")),
        "(project = SEC OR project = OPS) AND updated >= \"2026-01-02 03:04\""
    );
}

#[test]
fn an_empty_query_degrades_to_the_bare_window() {
    // `Config::validate` rejects an empty JQL, so this is unreachable from the
    // CLI; the function stays total and never emits an empty `()` group, which
    // Jira rejects as a syntax error.
    for empty in ["", "   ", "\n\t"] {
        assert_eq!(
            checkpoint::narrow_jql(empty, at("2026-01-02T03:04:05Z")),
            "updated >= \"2026-01-02 03:04\"",
            "input {empty:?}"
        );
    }
}

#[test]
fn the_timestamp_is_jql_shaped_and_normalized_to_utc() {
    let jql = checkpoint::narrow_jql("project = SEC", at("2026-03-04T05:06:07+03:00"));
    assert!(jql.ends_with("updated >= \"2026-03-04 02:06\""), "{jql}");
    // Jira does not parse RFC 3339 here: no `T`, no offset, no `Z`, no seconds.
    assert!(!jql.contains('T'), "{jql}");
    assert!(!jql.contains('+'), "{jql}");
    assert!(!jql.contains('Z'), "{jql}");
    assert!(!jql.contains(":07"), "{jql}");
}

#[test]
fn normalization_ignores_layout_but_not_content() {
    assert_eq!(
        checkpoint::normalize_jql("  project   =  SEC \n\t OR project = OPS "),
        checkpoint::normalize_jql("project = SEC OR project = OPS")
    );
    assert_ne!(
        checkpoint::normalize_jql("project = SEC"),
        checkpoint::normalize_jql("project = OPS")
    );
}

// ── a whole run: write, then narrow ──

#[test]
fn the_first_run_scans_everything_and_the_next_one_narrows() {
    let state = TempState::new("cycle");
    let config = state.config(JQL);

    // No checkpoint yet: nothing to narrow with.
    assert!(plan_incremental_scan(&config, JQL).is_none());

    checkpoint::maybe_write_checkpoint(
        &config,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z"),
    )
    .expect("the checkpoint is written");

    let plan = plan_incremental_scan(&config, JQL).expect("the checkpoint narrows the second run");
    assert_eq!(
        plan.jql,
        "(project = SEC OR project = OPS) AND updated >= \"2026-01-02 02:59\""
    );
    assert_eq!(plan.checkpoint_finished_at, at("2026-01-02T03:04:05Z"));
    // The five-minute margin: an issue updated while the previous scan ran must
    // stay inside the window.
    assert_eq!(
        plan.checkpoint_finished_at - plan.since,
        time::Duration::minutes(5)
    );
    assert_eq!(plan.since, at("2026-01-02T02:59:05Z"));
}

#[test]
fn the_written_file_is_the_documented_v2_shape() {
    let state = TempState::new("shape");
    let config = state.config(JQL);
    checkpoint::maybe_write_checkpoint(
        &config,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z"),
    )
    .expect("the checkpoint is written");

    // `checkpoint_path` is the only place the file name is decided.
    assert_eq!(checkpoint_path(&config), state.checkpoint_file());

    let raw = std::fs::read_to_string(state.checkpoint_file()).expect("checkpoint file");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("checkpoint is JSON");
    assert_eq!(json["version"], checkpoint::CHECKPOINT_VERSION);
    assert_eq!(json["finished_at"], "2026-01-02T03:04:05Z");
    // The *configured* query, never the narrowed one: the next run compares this
    // against its own configuration.
    assert_eq!(json["jql"], JQL);
    assert_eq!(json["jira_url"], JIRA_URL);
    assert_eq!(json["status"], "success");
}

#[test]
fn a_reformatted_query_still_matches_its_checkpoint() {
    let state = TempState::new("whitespace");
    let config = state.config(JQL);
    checkpoint::maybe_write_checkpoint(
        &config,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z"),
    )
    .expect("the checkpoint is written");

    let reformatted = "  project = SEC   OR\n  project = OPS  ";
    assert!(plan_incremental_scan(&config, reformatted).is_some());
}

// ── the fallbacks ──

#[test]
fn a_different_query_or_instance_is_not_narrowed() {
    let state = TempState::new("foreign");
    let config = state.config(JQL);
    checkpoint::maybe_write_checkpoint(
        &config,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z"),
    )
    .expect("the checkpoint is written");

    let mut other_query = state.config("project = SEC");
    assert!(plan_incremental_scan(&other_query, "project = SEC").is_none());

    // Same query, another Jira: the baseline says nothing about this instance.
    other_query.jira_url = "https://jira.other.example".into();
    assert!(plan_incremental_scan(&other_query, JQL).is_none());

    // Neither fallback may consume the checkpoint: the next compatible run can
    // still use it.
    assert!(plan_incremental_scan(&config, JQL).is_some());
}

#[test]
fn a_corrupt_checkpoint_falls_back_to_the_full_scan() {
    for raw in [
        "not json at all",
        "{}",
        // A file from an older layout, without the fields the window needs.
        r#"{"last_run_at":"2026-01-02T03:04:05Z","status":"success"}"#,
        // Same layout, unknown format version.
        r#"{"version":99,"finished_at":"2026-01-02T03:04:05Z",
            "jql":"project = SEC","jira_url":"https://jira.example.com","status":"success"}"#,
    ] {
        let state = TempState::new("corrupt");
        let config = state.config(JQL);
        state.write_raw(raw);
        assert!(
            plan_incremental_scan(&config, JQL).is_none(),
            "raw checkpoint {raw:?} must not narrow the scan"
        );
    }
}

#[test]
fn a_broken_finish_time_is_not_narrowed() {
    let cp = checkpoint::Checkpoint {
        version: checkpoint::CHECKPOINT_VERSION,
        finished_at: "yesterday".into(),
        jql: JQL.into(),
        jira_url: JIRA_URL.into(),
        status: "success".into(),
    };
    assert!(window_start(&cp, JQL, JIRA_URL).is_err());
}

#[test]
fn a_future_baseline_is_not_narrowed() {
    // A clock moved backwards would put every issue outside the window and the
    // scan would look successful with no findings.
    let cp = checkpoint::Checkpoint {
        version: checkpoint::CHECKPOINT_VERSION,
        finished_at: "2999-01-01T00:00:00Z".into(),
        jql: JQL.into(),
        jira_url: JIRA_URL.into(),
        status: "success".into(),
    };
    assert!(window_start(&cp, JQL, JIRA_URL).is_err());
}

#[test]
fn only_a_successful_scan_advances_the_baseline() {
    let state = TempState::new("status");
    let config = state.config(JQL);

    checkpoint::maybe_write_checkpoint(
        &config,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z"),
    )
    .expect("the successful scan writes the baseline");
    let after_success = std::fs::read_to_string(state.checkpoint_file()).expect("checkpoint");

    // A partial scan found the same issues it could reach; the ones it never
    // reached must stay inside the next window, so the baseline does not move.
    for status in [ScanStatus::Partial, ScanStatus::Failed] {
        checkpoint::maybe_write_checkpoint(&config, &scan_run(status, "2026-01-05T00:00:00Z"))
            .expect("a non-successful scan is not an error");
        assert_eq!(
            std::fs::read_to_string(state.checkpoint_file()).expect("checkpoint"),
            after_success,
            "a {status:?} scan must not rewrite the baseline"
        );
    }

    // And an error path: a state directory that cannot be created is reported,
    // not swallowed.
    let mut blocked = state.config(JQL);
    blocked.state_dir = PathBuf::from("/dev/null/nope");
    assert!(checkpoint::write_checkpoint(
        &blocked,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z")
    )
    .is_err());

    // The plan still describes the successful baseline.
    let plan = plan_incremental_scan(&config, JQL).expect("the baseline survives");
    assert_eq!(plan.checkpoint_finished_at, at("2026-01-02T03:04:05Z"));
}

/// `--incremental` off is the default: no file is written and no query is
/// narrowed, whatever is already on disk.
#[test]
fn without_the_flag_nothing_is_written_or_narrowed() {
    let state = TempState::new("off");
    let config = state.config(JQL);
    checkpoint::maybe_write_checkpoint(
        &config,
        &scan_run(ScanStatus::Success, "2026-01-02T03:04:05Z"),
    )
    .expect("baseline written while the flag is on");

    let mut off = state.config(JQL);
    off.incremental = false;
    assert!(plan_incremental_scan(&off, JQL).is_none());

    std::fs::remove_file(state.checkpoint_file()).expect("drop the baseline");
    checkpoint::maybe_write_checkpoint(
        &off,
        &scan_run(ScanStatus::Success, "2026-01-09T00:00:00Z"),
    )
    .expect("an off-flag scan writes nothing");
    assert!(!state.checkpoint_file().exists());
}
