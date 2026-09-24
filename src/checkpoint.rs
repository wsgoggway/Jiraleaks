//! Incremental scanning (spec §10.16): the checkpoint file and the JQL query it
//! narrows.
//!
//! A checkpoint records the moment a scan finished successfully together with the
//! configuration that produced it — the configured `jql` and the `jira_url`. The
//! next run with `--incremental` reads it and asks Jira only for what changed
//! since:
//!
//! ```text
//! (<configured JQL>) AND updated >= "<finished_at - WINDOW_OVERLAP>"
//! ```
//!
//! Two rules make the narrowing safe, because an issue skipped here is a leak
//! reported nowhere:
//!
//! * the checkpoint is used **only** when it can be trusted: the file exists and
//!   parses, its [`CHECKPOINT_VERSION`] is current, its `jql` and `jira_url` are
//!   the ones this run uses, and its finish time is a valid past timestamp.
//!   Anything else falls back to the full query, with the reason logged at `info`
//!   level — never a silent narrowing;
//! * the window reaches [`WINDOW_OVERLAP`] back before the previous scan's finish
//!   time, so an issue updated while that scan was running is queried again
//!   instead of being lost forever.
//!
//! The configured JQL is always parenthesized before the `AND` is appended.
//! `project = A OR project = B AND updated >= ...` binds the `AND` to `project =
//! B` alone — half the query would be silently unfiltered and the other half
//! silently dropped.
//!
//! # Time zone assumption
//!
//! The JQL timestamp is written as a naive UTC `yyyy-MM-dd HH:mm`. Jira reads a
//! naive JQL timestamp in the time zone of the requesting user's profile: a
//! profile *behind* UTC shifts the window that many hours later and can hide
//! issues from it. The five-minute overlap absorbs clock skew, not a time-zone
//! offset — an instance whose Jira profile is not on UTC needs the overlap raised
//! (see the `--incremental` note in `README.md`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::config::Config;
use crate::error::ScannerError;
use crate::finding::{ScanRun, ScanStatus};

/// On-disk format version of the checkpoint file.
///
/// A file written by another version is not interpreted: its layout may have
/// changed, and a misread checkpoint narrows a scan silently. An unknown version
/// is treated exactly like an unparsable file — full scan, reason logged.
pub const CHECKPOINT_VERSION: u32 = 2;

/// How far the incremental window reaches back before the previous scan's finish
/// time.
///
/// `finished_at` is stamped after the last page has been processed, so a window
/// starting exactly there would exclude an issue updated in the seconds between
/// that update and the timestamp — and no later run would ever look at it again.
/// Five minutes is far wider than that skew and still narrow enough to skip the
/// bulk of a project.
pub const WINDOW_OVERLAP: time::Duration = time::Duration::minutes(5);

/// Name of the checkpoint file inside `--state-dir`.
const CHECKPOINT_FILE: &str = "checkpoint.json";

/// `status` a trusted checkpoint carries: only a fully successful scan may
/// advance the window.
const SUCCESS_STATUS: &str = "success";

/// The incremental baseline written after a successful scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Layout version of this file; see [`CHECKPOINT_VERSION`].
    pub version: u32,
    /// RFC 3339 instant at which the scan finished successfully.
    pub finished_at: String,
    /// The **configured** JQL that scan ran — never the narrowed one it sent.
    ///
    /// The next run compares this against its own configured JQL to decide
    /// whether the two scans cover the same issue set. Storing the narrowed query
    /// here would make every run compare a narrowed string against a configured
    /// one and fall back to a full scan forever.
    pub jql: String,
    /// Jira base URL the baseline was taken from.
    pub jira_url: String,
    /// Outcome of the scan; only [`SUCCESS_STATUS`] is trusted.
    pub status: String,
}

/// The decision to narrow one scan, and the window it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalPlan {
    /// Query to send to Jira: the configured JQL, parenthesized, with the
    /// `updated >=` clause appended.
    pub jql: String,
    /// Time the previous successful scan finished.
    pub checkpoint_finished_at: OffsetDateTime,
    /// Lower bound of the window:
    /// [`IncrementalPlan::checkpoint_finished_at`] minus [`WINDOW_OVERLAP`].
    pub since: OffsetDateTime,
}

/// Path of the checkpoint file inside the configured `--state-dir`.
pub fn checkpoint_path(config: &Config) -> PathBuf {
    config.state_dir.join(CHECKPOINT_FILE)
}

/// Read a checkpoint file, or `None` when it cannot be used.
///
/// `None` is not an error: a missing, unreadable or unparsable checkpoint means
/// the run cannot be narrowed, and every reason is logged. Validation of the
/// *contents* against this run is [`window_start`]'s job — this function only
/// answers "is there a checkpoint file, and does it parse".
pub fn read_checkpoint(path: &Path) -> Option<Checkpoint> {
    if !path.exists() {
        tracing::info!(
            path = %path.display(),
            "No checkpoint file found; running the full scan"
        );
        return None;
    }

    match fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<Checkpoint>(&content) {
            Ok(checkpoint) => {
                tracing::info!(
                    path = %path.display(),
                    finished_at = %checkpoint.finished_at,
                    "Loaded checkpoint"
                );
                Some(checkpoint)
            }
            Err(e) => {
                tracing::info!(
                    path = %path.display(),
                    error = %e,
                    "Checkpoint does not parse; running the full scan"
                );
                None
            }
        },
        Err(e) => {
            tracing::info!(
                path = %path.display(),
                error = %e,
                "Checkpoint cannot be read; running the full scan"
            );
            None
        }
    }
}

/// Validate a checkpoint against this run and return the window's lower bound.
///
/// Pure — the caller has already read the file. `Ok` is the first instant the
/// narrowed query asks for (the checkpoint's finish time minus
/// [`WINDOW_OVERLAP`]); `Err` carries the reason for the fallback log. Every
/// rejection is deliberately conservative: when anything about the checkpoint is
/// not exactly what this run expects, the scan is not narrowed.
pub fn window_start(
    checkpoint: &Checkpoint,
    jql: &str,
    jira_url: &str,
) -> Result<OffsetDateTime, String> {
    if checkpoint.version != CHECKPOINT_VERSION {
        return Err(format!(
            "checkpoint format version {} is not the supported version {CHECKPOINT_VERSION}",
            checkpoint.version
        ));
    }
    if checkpoint.status != SUCCESS_STATUS {
        return Err(format!(
            "the checkpoint is from a scan that did not complete successfully (status {:?})",
            checkpoint.status
        ));
    }
    if normalize_jql(&checkpoint.jql) != normalize_jql(jql) {
        return Err(format!(
            "the checkpoint is for a different JQL ({:?})",
            normalize_jql(&checkpoint.jql)
        ));
    }
    if checkpoint.jira_url != jira_url {
        return Err(format!(
            "the checkpoint is for a different Jira instance ({})",
            checkpoint.jira_url
        ));
    }

    let finished_at = OffsetDateTime::parse(
        &checkpoint.finished_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| {
        format!(
            "checkpoint timestamp {:?} is not a valid RFC 3339 instant: {e}",
            checkpoint.finished_at
        )
    })?;

    let now = OffsetDateTime::now_utc();
    if finished_at > now {
        // A future baseline would narrow the window past "now" and match nothing
        // at all — the whole scan would come back empty and look successful.
        return Err(format!(
            "checkpoint timestamp {} is in the future (now {})",
            checkpoint.finished_at,
            now.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        ));
    }

    Ok(finished_at - WINDOW_OVERLAP)
}

/// Decide whether this run can be narrowed, and by which query.
///
/// `None` means "run `jql` unchanged" and is returned when `--incremental` is
/// off, when there is no checkpoint, or when the checkpoint cannot be trusted
/// ([`window_start`]). Off-flag runs are silent — that is the default path; every
/// other fallback is logged at `info` with its reason, because the operator asked
/// for incremental mode and has to learn why they did not get it. A successful
/// narrowing is logged with the window it covers.
pub fn plan_incremental_scan(config: &Config, jql: &str) -> Option<IncrementalPlan> {
    if !config.incremental {
        return None;
    }

    let path = checkpoint_path(config);
    let checkpoint = read_checkpoint(&path)?;

    match window_start(&checkpoint, jql, &config.jira_url) {
        Ok(since) => {
            let plan = IncrementalPlan {
                jql: narrow_jql(jql, since),
                checkpoint_finished_at: since + WINDOW_OVERLAP,
                since,
            };
            tracing::info!(
                since = %jql_timestamp(plan.since),
                previous_scan_finished_at = %checkpoint.finished_at,
                jql = %plan.jql,
                "Incremental scan: query narrowed to issues updated since the last successful scan"
            );
            Some(plan)
        }
        Err(reason) => {
            tracing::info!(
                path = %path.display(),
                reason = %reason,
                "Checkpoint cannot narrow this scan; running the full scan"
            );
            None
        }
    }
}

/// The query for a window that starts at `since`: `(<jql>) AND updated >= "<ts>"`.
///
/// `since` must already include [`WINDOW_OVERLAP`] — this function formats, it
/// does not widen. The parentheses are load-bearing: without them an `OR` in
/// `jql` lets the `AND` bind to the last operand only.
///
/// An empty `jql` (unreachable from the CLI — `Config::validate` rejects it)
/// degrades to the bare window clause rather than an empty `()` group, which Jira
/// rejects as a syntax error.
pub fn narrow_jql(jql: &str, since: OffsetDateTime) -> String {
    let window = format!("updated >= \"{}\"", jql_timestamp(since));
    let jql = jql.trim();
    if jql.is_empty() {
        return window;
    }
    format!("({jql}) AND {window}")
}

/// A JQL-compatible timestamp, `yyyy-MM-dd HH:mm` in UTC.
///
/// Jira does not accept RFC 3339 here, so the offset is dropped and the value is
/// normalized to UTC first — see the time-zone note in the module documentation.
fn jql_timestamp(at: OffsetDateTime) -> String {
    let utc = at.to_offset(time::UtcOffset::UTC);
    let format =
        time::format_description::parse_borrowed::<1>("[year]-[month]-[day] [hour]:[minute]")
            .expect("static format description is valid");
    utc.format(&format).unwrap_or_default()
}

/// The comparison form of a JQL query: runs of whitespace collapsed, trimmed.
///
/// Two scans cover the same issue set when their normalized queries are equal, so
/// a reformatted (but equivalent) query in the configuration still matches its
/// checkpoint, while a genuinely different one does not.
pub fn normalize_jql(jql: &str) -> String {
    jql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The checkpoint this scan should write, without touching the file system.
///
/// `jql` is the **configured** query: see [`Checkpoint::jql`] for why the narrowed
/// one must not be stored here.
fn checkpoint_for(config: &Config, scan_run: &ScanRun) -> Checkpoint {
    Checkpoint {
        version: CHECKPOINT_VERSION,
        finished_at: scan_run.finished_at.clone(),
        jql: config.jql().unwrap_or("").to_string(),
        jira_url: config.jira_url.clone(),
        status: SUCCESS_STATUS.to_string(),
    }
}

/// Advance the incremental baseline, if this scan may do so.
///
/// The pipeline calls this instead of [`write_checkpoint`]: it keeps the
/// checkpoint written only when `--incremental` is on **and** the scan finished
/// [`ScanStatus::Success`]. A cancelled or partially failed scan must not move the
/// baseline — the issues it never reached would fall outside every later window.
pub fn maybe_write_checkpoint(config: &Config, scan_run: &ScanRun) -> Result<(), ScannerError> {
    if !config.incremental {
        return Ok(());
    }
    if !matches!(scan_run.status, ScanStatus::Success) {
        tracing::info!(
            status = ?scan_run.status,
            "Scan did not complete successfully; keeping the previous checkpoint"
        );
        return Ok(());
    }
    write_checkpoint(config, scan_run)
}

/// Write a checkpoint after a successful scan.
///
/// Unconditional: it does not look at `--incremental` or at the scan status. The
/// pipeline goes through [`maybe_write_checkpoint`].
pub fn write_checkpoint(config: &Config, scan_run: &ScanRun) -> Result<(), ScannerError> {
    let state_dir = &config.state_dir;
    fs::create_dir_all(state_dir).map_err(|e| {
        ScannerError::ReportWrite(format!(
            "Failed to create state dir {}: {e}",
            state_dir.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700)).ok();
    }

    let checkpoint = checkpoint_for(config, scan_run);

    let json = serde_json::to_string_pretty(&checkpoint)
        .map_err(|e| ScannerError::ReportWrite(format!("Checkpoint serialization error: {e}")))?;

    let path = checkpoint_path(config);
    fs::write(&path, json)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to write checkpoint: {e}")))?;

    tracing::info!(path = %path.display(), "Checkpoint written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> OffsetDateTime {
        OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339)
            .expect("valid test timestamp")
    }

    fn checkpoint(jql: &str, jira_url: &str, finished_at: &str) -> Checkpoint {
        Checkpoint {
            version: CHECKPOINT_VERSION,
            finished_at: finished_at.to_string(),
            jql: jql.to_string(),
            jira_url: jira_url.to_string(),
            status: SUCCESS_STATUS.to_string(),
        }
    }

    #[test]
    fn narrow_jql_parenthesizes_the_original_query() {
        let since = at("2026-01-02T03:04:05Z");
        assert_eq!(
            narrow_jql("project = SEC", since),
            "(project = SEC) AND updated >= \"2026-01-02 03:04\""
        );
        // Without the parentheses the AND would bind to `project = B` alone.
        assert_eq!(
            narrow_jql("project = A OR project = B", since),
            "(project = A OR project = B) AND updated >= \"2026-01-02 03:04\""
        );
    }

    #[test]
    fn narrow_jql_timestamp_is_jql_shaped_and_utc() {
        // A non-UTC input is normalized, and the offset never reaches the query.
        let since = at("2026-03-04T05:06:07+03:00");
        let jql = narrow_jql("project = SEC", since);
        assert!(jql.ends_with("updated >= \"2026-03-04 02:06\""), "{jql}");
        assert!(!jql.contains('T'), "{jql}");
        assert!(!jql.contains('+'), "{jql}");
        assert!(!jql.contains('Z'), "{jql}");
    }

    #[test]
    fn normalize_jql_collapses_whitespace() {
        assert_eq!(normalize_jql("  project   =  SEC \n"), "project = SEC");
        assert_eq!(normalize_jql("project = SEC"), "project = SEC");
        assert_eq!(normalize_jql(""), "");
    }

    #[test]
    fn window_start_rejects_a_different_jql_or_instance() {
        let cp = checkpoint(
            "project = SEC",
            "https://jira.example.com",
            "2026-01-02T03:04:05Z",
        );
        let jql = "project = SEC";

        assert!(window_start(&cp, jql, "https://jira.example.com").is_ok());

        // Whitespace-only differences are the same query.
        assert!(window_start(&cp, "project  =  SEC", "https://jira.example.com").is_ok());
        assert!(window_start(&cp, "project = OPS", "https://jira.example.com").is_err());
        assert!(window_start(&cp, jql, "https://jira.other.example").is_err());
    }

    #[test]
    fn window_start_rejects_untrusted_checkpoints() {
        let jql = "project = SEC";
        let url = "https://jira.example.com";

        let mut wrong_version = checkpoint(jql, url, "2026-01-02T03:04:05Z");
        wrong_version.version = CHECKPOINT_VERSION + 1;
        assert!(window_start(&wrong_version, jql, url).is_err());

        let mut not_success = checkpoint(jql, url, "2026-01-02T03:04:05Z");
        not_success.status = "partial".to_string();
        assert!(window_start(&not_success, jql, url).is_err());

        let broken_time = checkpoint(jql, url, "yesterday");
        assert!(window_start(&broken_time, jql, url).is_err());

        let future = checkpoint(jql, url, "2999-01-01T00:00:00Z");
        assert!(window_start(&future, jql, url).is_err());
    }

    #[test]
    fn window_start_subtracts_the_overlap() {
        let cp = checkpoint(
            "project = SEC",
            "https://jira.example.com",
            "2026-01-02T03:04:05Z",
        );
        let since = window_start(&cp, "project = SEC", "https://jira.example.com")
            .expect("checkpoint is usable");
        assert_eq!(since, at("2026-01-02T02:59:05Z"));
    }

    #[test]
    fn checkpoint_for_stores_the_configured_query() {
        let mut config = Config::test_config("https://jira.example.com", "token");
        config.jql = Some("  project = SEC  ".to_string());
        let scan_run = ScanRun {
            scan_id: "scan-1".into(),
            status: ScanStatus::Success,
            started_at: "2026-01-02T03:00:00Z".into(),
            finished_at: "2026-01-02T03:04:05Z".into(),
            jira_url: "https://jira.example.com".into(),
            jql: "(project = SEC) AND updated >= \"2026-01-02 02:59\"".into(),
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
        };

        let cp = checkpoint_for(&config, &scan_run);
        assert_eq!(cp.jql, "  project = SEC  ");
        assert_eq!(cp.finished_at, "2026-01-02T03:04:05Z");
        assert_eq!(cp.version, CHECKPOINT_VERSION);
    }
}
