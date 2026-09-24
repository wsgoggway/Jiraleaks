//! Hostile-input regression tests.
//!
//! Everything the scanner parses — issue descriptions, comments, attachment names,
//! field paths — is written by whoever filed the issue, so for the scanner it is
//! attacker-controlled. These tests replay the two attacks that content enables:
//!
//! * *Denial of service*: a large field whose shape maximises the detector's work
//!   (`user=a\npassword=b\n` repeated up to the extractor's 2 MiB per-segment cap).
//!   Before the fix the proximity heuristic formed the full cross-product of matches
//!   (~62e9 comparisons and tens of millions of allocations for this input), so one
//!   issue could pin a worker for minutes.
//! * *Output injection*: control sequences and spreadsheet formulas in reported
//!   text, which attack the operator's terminal and spreadsheet rather than the
//!   scanner.
//!
//! Every timing assertion here is generous by an order of magnitude: it is a
//! regression tripwire against a reintroduced nested loop or unbounded scan, not a
//! benchmark.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use jiraleaks::credpair::CredentialPairDetector;
use jiraleaks::finding::{
    Confidence, Finding, FindingStatus, ScanRun, ScanStatus, Severity, SourceType,
};
use jiraleaks::report::{csv as csv_report, summary, ReportInput};
use jiraleaks::sanitize;

/// The pipeline checks `max_findings_per_issue` only after a segment has been
/// scanned, so the detector must bound its own output: this is the contract.
const EXPECTED_HIT_CAP: usize = 256;

/// Ceiling for one hostile segment. The pre-fix code did not finish in 250 s.
const HOSTILE_BUDGET: Duration = Duration::from_secs(2);

/// `max_text_size_kb` default is 2048, i.e. a single extracted segment can be 2 MiB.
const SEGMENT_BYTES: usize = 2 * 1024 * 1024;

/// A unique path under the temp dir, removed by each test when it is done with it.
fn temp_path(extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "jiraleaks_hostile_{}_{}.{extension}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// A segment of exactly [`SEGMENT_BYTES`], built from repetitions of `unit`.
fn segment_of(unit: &str) -> String {
    let mut text = unit.repeat(SEGMENT_BYTES / unit.len() + 1);
    text.truncate(SEGMENT_BYTES);
    text
}

fn hostile_finding(snippet: &str, issue_key: &str, field_path: &str) -> Finding {
    Finding {
        finding_id: "11111111-2222-3333-4444-555555555555".to_string(),
        issue_key: issue_key.to_string(),
        issue_url: "https://jira.example.com/browse/SEC-1234".to_string(),
        field_path: field_path.to_string(),
        rule_id: "credential_pair".to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        redacted_secret: "hu...et".to_string(),
        secret_hash: "sha256:1111".to_string(),
        snippet: snippet.to_string(),
        detected_at: "2026-08-07T13:00:00Z".to_string(),
        scanner_version: "0.1.0".to_string(),
        locations: Vec::new(),
        source_type: SourceType::Comment,
        status: FindingStatus::New,
        username: Some("svc_app".to_string()),
        references: Vec::new(),
        first_seen: None,
        times_seen: None,
        external_validation: None,
    }
}

fn scan_run() -> ScanRun {
    ScanRun {
        scan_id: "00000000-0000-0000-0000-000000000001".to_string(),
        status: ScanStatus::Success,
        started_at: "2026-08-07T13:00:00Z".to_string(),
        finished_at: "2026-08-07T13:00:01Z".to_string(),
        jira_url: "https://jira.example.com".to_string(),
        jql: "project = SEC".to_string(),
        issues_scanned: 1,
        issues_total: 1,
        findings_total: 1,
        findings_critical: 0,
        findings_high: 1,
        findings_medium: 0,
        findings_low: 0,
        findings_info: 0,
        errors_total: 0,
        comments_scanned: 1,
        attachments_scanned: 0,
        scanner_version: "0.1.0".to_string(),
        duration_secs: 1.0,
    }
}

#[test]
fn hostile_proximity_segment_is_bounded_and_finishes() {
    // The exact shape from the threat model, sized to the per-segment cap.
    let text = segment_of("user=a\npassword=b\n");
    assert_eq!(text.len(), SEGMENT_BYTES);

    let detector = CredentialPairDetector::new().expect("patterns compile");
    let started = Instant::now();
    let hits = detector.detect(&text, "description");
    let elapsed = started.elapsed();

    assert!(
        hits.len() <= EXPECTED_HIT_CAP,
        "per-segment hit cap breached: {} hits",
        hits.len()
    );
    assert!(!hits.is_empty(), "the hostile segment is still scanned");
    assert!(
        elapsed < HOSTILE_BUDGET,
        "hostile proximity segment took {elapsed:?}, budget {HOSTILE_BUDGET:?}"
    );
}

#[test]
fn hostile_url_userinfo_segment_is_bounded_and_finishes() {
    let text = segment_of("a://svc_app:sup3rsecret@h ");
    assert_eq!(text.len(), SEGMENT_BYTES);

    let detector = CredentialPairDetector::new().expect("patterns compile");
    let started = Instant::now();
    let hits = detector.detect(&text, "attachment:dump.txt");
    let elapsed = started.elapsed();

    assert!(hits.len() <= EXPECTED_HIT_CAP, "{} hits", hits.len());
    assert!(!hits.is_empty());
    assert!(
        elapsed < HOSTILE_BUDGET,
        "hostile url-userinfo segment took {elapsed:?}, budget {HOSTILE_BUDGET:?}"
    );
}

#[test]
fn hostile_segment_without_matches_finishes() {
    // Few or no matches is the shape that cost the most: the regex engine still walks
    // the whole (bounded) segment before it can report "nothing found".
    let text = "f".repeat(SEGMENT_BYTES);

    let detector = CredentialPairDetector::new().expect("patterns compile");
    let started = Instant::now();
    let hits = detector.detect(&text, "attachment:blob.bin");
    let elapsed = started.elapsed();

    assert!(hits.is_empty());
    assert!(
        elapsed < HOSTILE_BUDGET,
        "matchless hostile segment took {elapsed:?}, budget {HOSTILE_BUDGET:?}"
    );
}

#[test]
fn hostile_text_cannot_control_the_summary_report() {
    // An attachment name / comment body that tries to clear the operator's screen and
    // plant a reassuring "CLEAN" line, plus an OSC 52 clipboard write.
    let snippet = "\u{1b}[2K\r\u{1b}[1;32mCLEAN: no secrets\u{1b}[0m\u{1b}]52;c;aGFja2Vk\u{7}";
    let finding = hostile_finding(
        snippet,
        "\u{1b}[31mSEC-1234",
        "attachment:\u{1b}[2Jname.yaml",
    );
    let path = temp_path("txt");

    let run = scan_run();
    summary::write(
        &path,
        &ReportInput {
            scan_run: &run,
            findings: &[finding],
        },
    )
    .expect("summary write");
    let content = std::fs::read_to_string(&path).expect("read summary");
    let _ = std::fs::remove_file(&path);

    assert!(!content.contains('\u{1b}'), "ESC reached the report");
    assert!(!content.contains('\u{7}'), "BEL reached the report");
    assert!(
        !content.contains('\r'),
        "carriage return reached the report"
    );
    assert!(
        !content.contains("52;c;"),
        "OSC 52 payload reached the report"
    );
    assert!(
        !content.contains("aGFja2Vk"),
        "clipboard payload reached the report"
    );
    // The plain-text residue is still reported, so nothing is silently swallowed.
    assert!(content.contains("CLEAN: no secrets"));
    assert!(content.contains("SEC-1234"));
}

#[test]
fn hostile_snippet_cannot_inject_a_spreadsheet_formula() {
    let snippet = "=cmd|'/C calc'!A1";
    let finding = hostile_finding(snippet, "+1+1", "@SUM(A1)");
    let path = temp_path("csv");

    let run = scan_run();
    csv_report::write(
        &path,
        &ReportInput {
            scan_run: &run,
            findings: &[finding],
        },
    )
    .expect("csv write");
    let mut reader = csv::Reader::from_path(&path).expect("csv reader");
    let rows: Vec<csv::StringRecord> = reader.records().map(|r| r.expect("record")).collect();
    let _ = std::fs::remove_file(&path);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 16, "the table shape must not change");

    // The formula sigil is neutralised by a leading apostrophe, not deleted: the
    // report still shows what was found.
    let snippet_cell = rows[0].get(9).expect("snippet cell");
    assert_eq!(snippet_cell, sanitize::csv_field(snippet));
    assert!(snippet_cell.starts_with('\''));
    assert!(snippet_cell.contains("cmd|'/C calc'!A1"));

    for (idx, cell) in rows[0].iter().enumerate() {
        assert!(
            !matches!(cell.as_bytes().first(), Some(b'=' | b'+' | b'-' | b'@')),
            "column {idx} still starts with a formula sigil: {cell:?}"
        );
    }
}

#[test]
fn sanitize_helpers_are_exposed_for_report_writers() {
    // The report writers rely on these two entry points; keep them public contract.
    assert_eq!(sanitize::terminal("\u{1b}[31mred\u{1b}[0m"), "red");
    assert_eq!(sanitize::csv_field("=1+1"), "'=1+1");
    assert_eq!(sanitize::csv_field("plain"), "plain");
}
