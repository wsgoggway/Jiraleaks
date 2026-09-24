//! Contract tests for the `report` facade: the format catalogue and the two
//! properties the reports have to keep — a report is never written outside
//! `report_dir`, and it never claims more about a scan than the scan itself knows.
//!
//! These tests go through [`jiraleaks::report::write_reports`], i.e. the same entry
//! point the pipeline uses, so they cover the catalogue, `--format` resolution, the
//! file layout and each writer at once.

use std::path::{Path, PathBuf};

use jiraleaks::config::Config;
use jiraleaks::finding::{
    Confidence, ExternalValidation, Finding, FindingKey, FindingStatus, Location, ScanRun,
    ScanStatus, Severity, SourceType,
};
use jiraleaks::report::{self, ReportInput, CATALOGUE, FORMAT_NAMES};

/// The formats the CLI documents.
///
/// `config::parse_formats` validates `--format` against the catalogue, so this list
/// and [`CATALOGUE`] must agree: a name here without a writer is a broken promise to
/// the operator. It lives here rather than being imported from `config` only because
/// `config::REPORT_FORMATS` does not exist yet — when it lands, this constant should
/// become that import.
const EXPECTED_FORMATS: &[&str] = &["json", "ndjson", "csv", "sarif", "summary", "defectdojo"];

fn scan_run(status: ScanStatus) -> ScanRun {
    ScanRun {
        scan_id: "scan-1".into(),
        status,
        started_at: "2026-01-01T00:00:00Z".into(),
        finished_at: "2026-01-01T00:00:01Z".into(),
        jira_url: "https://jira.example.com".into(),
        jql: "project = SEC".into(),
        issues_scanned: 3,
        issues_total: 10,
        findings_total: 1,
        findings_critical: 0,
        findings_high: 1,
        findings_medium: 0,
        findings_low: 0,
        findings_info: 0,
        errors_total: 2,
        comments_scanned: 1,
        attachments_scanned: 0,
        scanner_version: "0.1.0".into(),
        duration_secs: 1.0,
    }
}

fn finding(finding_id: &str, issue_key: &str, rule_id: &str) -> Finding {
    Finding {
        finding_id: finding_id.into(),
        issue_key: issue_key.into(),
        issue_url: format!("https://jira.example.com/browse/{issue_key}"),
        field_path: "fields.description".into(),
        rule_id: rule_id.into(),
        severity: Severity::High,
        confidence: Confidence::High,
        redacted_secret: "[REDACTED]".into(),
        secret_hash: "sha256:deadbeef".into(),
        snippet: "[REDACTED]".into(),
        detected_at: "2026-01-01T00:00:00Z".into(),
        scanner_version: "0.1.0".into(),
        locations: vec![Location {
            issue_key: issue_key.into(),
            field_path: "fields.description".into(),
            source_type: SourceType::Description,
        }],
        source_type: SourceType::Description,
        status: FindingStatus::New,
        username: None,
        references: Vec::new(),
        first_seen: None,
        times_seen: None,
        external_validation: None,
    }
}

fn config(report_dir: &Path, format: &str) -> Config {
    let mut cfg = Config::test_config("https://jira.example.com", "tok");
    cfg.report_dir = report_dir.to_path_buf();
    cfg.report_layout = "flat".into();
    cfg.format = format.into();
    cfg
}

/// A clean temp directory, named after the test so concurrent tests cannot collide.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jiraleaks-formats-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn basenames(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn read_json(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path).expect("report readable");
    serde_json::from_str(&raw).expect("report is valid JSON")
}

#[test]
fn every_documented_format_has_a_writer_and_an_extension() {
    let names: Vec<&str> = CATALOGUE.iter().map(|f| f.name).collect();
    assert_eq!(names, EXPECTED_FORMATS, "catalogue names");
    assert_eq!(FORMAT_NAMES, EXPECTED_FORMATS, "FORMAT_NAMES is derived");

    for format in CATALOGUE {
        assert!(!format.ext.is_empty(), "{} has no extension", format.name);
        assert!(
            !format.ext.contains('/') && !format.ext.contains('\\') && !format.ext.contains(".."),
            "{} has an extension that is not a plain file name: {:?}",
            format.name,
            format.ext
        );
    }
}

#[test]
fn a_writer_runs_for_every_catalogue_entry() {
    // `all` is the only mode that exercises every entry of the catalogue, so it also
    // proves that each one has a writer that actually writes.
    let dir = temp_dir("all-writers");
    report::write_reports(
        &config(&dir, "all"),
        &scan_run(ScanStatus::Success),
        &[finding("f-1", "SEC-1", "aws-access-key")],
    )
    .expect("all formats");

    let files = files_under(&dir);
    let names = basenames(&files);
    assert_eq!(
        names.len(),
        EXPECTED_FORMATS.len(),
        "one report per format: {names:?}"
    );
    for format in CATALOGUE {
        let suffix = format!("_report.{}", format.ext);
        let written = names.iter().filter(|n| n.ends_with(&suffix)).count();
        assert_eq!(written, 1, "{} -> {names:?}", format.name);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_format_is_rejected_instead_of_skipped() {
    let dir = temp_dir("unknown-format");

    let err = report::write_reports(
        &config(&dir, "json,bogus"),
        &scan_run(ScanStatus::Success),
        &[],
    )
    .expect_err("an unknown format must fail the run");
    assert!(
        matches!(err, jiraleaks::error::ScannerError::Config(_)),
        "expected a config error, got {err:?}"
    );
    assert!(
        !dir.exists() || files_under(&dir).is_empty(),
        "a rejected format must not write reports"
    );

    // The same format alone, and the empty spec, are errors too — never a silent
    // "nothing to write".
    assert!(report::resolve_formats("bogus").is_err());
    assert!(report::resolve_formats("").is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn all_and_all_inside_a_list_write_each_format_once() {
    let dir = temp_dir("all-inside-list");
    report::write_reports(
        &config(&dir, "json,all"),
        &scan_run(ScanStatus::Success),
        &[],
    )
    .expect("json,all");
    assert_eq!(
        files_under(&dir).len(),
        EXPECTED_FORMATS.len(),
        "json,all writes every format exactly once"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // Duplicates collapse in the resolution, so no path is written twice.
    let resolved = report::resolve_formats("json,json,sarif").expect("resolve");
    assert_eq!(
        resolved.iter().map(|f| f.name).collect::<Vec<_>>(),
        vec!["json", "sarif"]
    );
    assert_eq!(
        report::resolve_formats("all,all").expect("resolve").len(),
        EXPECTED_FORMATS.len()
    );

    let dir = temp_dir("duplicate-format");
    report::write_reports(
        &config(&dir, "json,json"),
        &scan_run(ScanStatus::Success),
        &[],
    )
    .expect("json,json");
    let files = files_under(&dir);
    assert_eq!(
        files.len(),
        1,
        "duplicates write one file: {:?}",
        basenames(&files)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sarif_is_valid_and_does_not_claim_a_partial_run_succeeded() {
    let dir = temp_dir("sarif-partial");
    report::write_reports(
        &config(&dir, "sarif"),
        &scan_run(ScanStatus::Partial),
        &[finding("f-1", "SEC-1", "aws-access-key")],
    )
    .expect("sarif report");

    let files = files_under(&dir);
    assert_eq!(files.len(), 1);
    let doc = read_json(&files[0]);

    assert_eq!(doc["version"], "2.1.0");
    assert!(
        doc["$schema"]
            .as_str()
            .unwrap_or_default()
            .contains("sarif"),
        "missing $schema: {}",
        doc["$schema"]
    );
    assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "jiraleaks");

    let invocation = &doc["runs"][0]["invocations"][0];
    assert_eq!(
        invocation["executionSuccessful"], false,
        "a partial scan must not be reported as successful"
    );
    let notification = &invocation["toolExecutionNotifications"][0];
    assert_eq!(notification["level"], "warning");
    assert!(notification["message"]["text"]
        .as_str()
        .unwrap_or_default()
        .contains("3 of 10"));

    // Every result references a rule the document declares.
    let declared: Vec<&str> = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    let results = doc["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    for result in results {
        assert!(declared.contains(&result["ruleId"].as_str().unwrap_or_default()));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sarif_marks_a_complete_run_successful() {
    let dir = temp_dir("sarif-success");
    report::write_reports(&config(&dir, "sarif"), &scan_run(ScanStatus::Success), &[])
        .expect("sarif report");
    let doc = read_json(&files_under(&dir)[0]);
    assert_eq!(
        doc["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert!(doc["runs"][0]["invocations"][0]
        .get("toolExecutionNotifications")
        .is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn defectdojo_identity_is_stable_and_distinguishes_findings() {
    let first_dir = temp_dir("dd-stable-a");
    let second_dir = temp_dir("dd-stable-b");

    // The same state scanned twice: a fresh UUID per scan, one DefectDojo record.
    report::write_reports(
        &config(&first_dir, "defectdojo"),
        &scan_run(ScanStatus::Success),
        &[finding("uuid-a", "SEC-1", "aws-access-key")],
    )
    .expect("defectdojo report");
    report::write_reports(
        &config(&second_dir, "defectdojo"),
        &scan_run(ScanStatus::Success),
        &[finding("uuid-b", "SEC-1", "aws-access-key")],
    )
    .expect("defectdojo report");

    let id = |dir: &Path| -> String {
        let doc = read_json(&files_under(dir)[0]);
        doc["findings"][0]["unique_id_from_tool"]
            .as_str()
            .expect("unique_id_from_tool")
            .to_string()
    };
    let (a, b) = (id(&first_dir), id(&second_dir));
    assert_eq!(a, b, "identity must not follow the per-scan finding_id");
    assert!(a.starts_with("fp:"), "got {a}");
    assert!(a.ends_with("#0"), "got {a}");

    // A different location is a different record.
    let other_dir = temp_dir("dd-other");
    report::write_reports(
        &config(&other_dir, "defectdojo"),
        &scan_run(ScanStatus::Success),
        &[finding("uuid-a", "SEC-2", "aws-access-key")],
    )
    .expect("defectdojo report");
    assert_ne!(id(&other_dir), a);

    // Semantic flags: a rule match is an active but unverified candidate, and only
    // an external validation that says the credential is live makes it verified.
    let doc = read_json(&files_under(&first_dir)[0]);
    assert_eq!(doc["findings"][0]["active"], true);
    assert_eq!(doc["findings"][0]["verified"], false);
    assert_eq!(doc["findings"][0]["false_p"], false);

    let mut validated = finding("uuid-a", "SEC-1", "aws-access-key");
    validated.external_validation = Some(ExternalValidation {
        valid: true,
        source: "ext-sys".into(),
        checked_at: "2026-01-01T00:00:00Z".into(),
    });
    let mut closed = finding("uuid-c", "SEC-3", "aws-access-key");
    closed.status = FindingStatus::FalsePositive;
    let dir = temp_dir("dd-validated");
    report::write_reports(
        &config(&dir, "defectdojo"),
        &scan_run(ScanStatus::Success),
        &[validated, closed],
    )
    .expect("defectdojo report");
    let doc = read_json(&files_under(&dir)[0]);
    assert_eq!(
        doc["findings"][0]["verified"], true,
        "live validation verifies"
    );
    assert_eq!(doc["findings"][1]["false_p"], true);
    assert_eq!(
        doc["findings"][1]["active"], false,
        "a false positive is not active work"
    );
    // Two findings, two ids.
    assert_ne!(
        doc["findings"][0]["unique_id_from_tool"],
        doc["findings"][1]["unique_id_from_tool"]
    );

    // The stable id really is the primary location fingerprint of the finding.
    let key = FindingKey::new("sha256:deadbeef", "aws-access-key", "SEC-1");
    assert_eq!(a, format!("{}#0", key.fingerprint()));

    for dir in [first_dir, second_dir, other_dir, dir] {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn nested_layout_confines_a_traversing_jql() {
    let pid = std::process::id();
    let traversal = format!("../../../../tmp/jiraleaks-escape-{pid}");

    for (jql, segment) in [
        (format!("project in ({traversal})"), "_default"),
        ("project in (\"SEC\")".to_string(), "SEC"),
    ] {
        let dir = temp_dir(&format!("traversal-{segment}"));
        let escape_target = dir.join(&traversal);
        // Collapse the `..` without touching the filesystem: this is where the
        // written report would land if the segment were not filtered.
        let mut lexical = PathBuf::new();
        for component in escape_target.components() {
            match component {
                std::path::Component::ParentDir => {
                    lexical.pop();
                }
                other => lexical.push(other.as_os_str()),
            }
        }
        let _ = std::fs::remove_dir_all(&lexical);

        let mut cfg = config(&dir, "json");
        cfg.report_layout = "nested".into();
        cfg.jql = Some(jql.clone());
        report::write_reports(&cfg, &scan_run(ScanStatus::Success), &[]).expect("nested report");

        let files = files_under(&dir);
        assert_eq!(
            files.len(),
            1,
            "one report for `{jql}`: {:?}",
            basenames(&files)
        );
        assert!(
            files[0].starts_with(dir.join(segment)),
            "`{jql}` should be grouped under {segment}, got {}",
            files[0].display()
        );
        assert!(
            !lexical.exists(),
            "`{jql}` escaped the report dir into {}",
            lexical.display()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn report_input_is_the_only_way_to_call_a_writer() {
    // The unified signature is what lets the catalogue exist; pin it from outside.
    let run = scan_run(ScanStatus::Success);
    let findings = [finding("f-1", "SEC-1", "aws-access-key")];
    let dir = temp_dir("report-input");
    let path = dir.join("direct.json");

    jiraleaks::report::json::write(
        &path,
        &ReportInput {
            scan_run: &run,
            findings: &findings,
        },
    )
    .expect("json writer");
    let doc = read_json(&path);
    assert_eq!(doc["scan_run"]["scan_id"], "scan-1");
    assert_eq!(doc["findings"].as_array().map(|a| a.len()), Some(1));

    let _ = std::fs::remove_dir_all(&dir);
}
