use std::fs;
use std::path::Path;

use crate::error::ScannerError;
use crate::report::ReportInput;
use crate::sanitize;

/// Write a human-readable summary text report.
///
/// This report is read on a terminal, so every free-text value that comes out of
/// Jira content is passed through [`sanitize::terminal`]: without it an attachment
/// called `\x1b[2K\x1b[32mCLEAN` could repaint the operator's screen, and an OSC 52
/// sequence in a comment would write to their clipboard.
pub fn write(path: &Path, input: &ReportInput<'_>) -> Result<(), ScannerError> {
    let scan_run = input.scan_run;
    let findings = input.findings;
    let mut out = String::new();

    out.push_str("=== Jira Secret Scanner — Scan Summary ===\n\n");
    out.push_str(&format!(
        "Scan ID:      {}\n",
        sanitize::terminal(&scan_run.scan_id)
    ));
    out.push_str(&format!("Status:       {:?}\n", scan_run.status));
    out.push_str(&format!(
        "Jira URL:     {}\n",
        sanitize::terminal(&scan_run.jira_url)
    ));
    out.push_str(&format!(
        "JQL:          {}\n",
        sanitize::terminal(&scan_run.jql)
    ));
    out.push_str(&format!(
        "Started:      {}\n",
        sanitize::terminal(&scan_run.started_at)
    ));
    out.push_str(&format!(
        "Finished:     {}\n",
        sanitize::terminal(&scan_run.finished_at)
    ));
    out.push_str(&format!("Duration:     {:.1}s\n\n", scan_run.duration_secs));

    out.push_str("--- Scan Statistics ---\n");
    out.push_str(&format!(
        "  Issues scanned:    {}\n",
        scan_run.issues_scanned
    ));
    out.push_str(&format!(
        "  Comments scanned:  {}\n",
        scan_run.comments_scanned
    ));
    out.push_str(&format!(
        "  Attachments:       {}\n",
        scan_run.attachments_scanned
    ));
    out.push_str(&format!(
        "  Errors:            {}\n\n",
        scan_run.errors_total
    ));

    out.push_str("--- Findings ---\n");
    out.push_str(&format!(
        "  Total:             {}\n",
        scan_run.findings_total
    ));
    out.push_str(&format!(
        "  Critical:          {}\n",
        scan_run.findings_critical
    ));
    out.push_str(&format!(
        "  High:              {}\n",
        scan_run.findings_high
    ));
    out.push_str(&format!(
        "  Medium:            {}\n",
        scan_run.findings_medium
    ));
    out.push_str(&format!("  Low:               {}\n", scan_run.findings_low));
    out.push_str(&format!(
        "  Info:              {}\n\n",
        scan_run.findings_info
    ));

    if !findings.is_empty() {
        out.push_str("--- Finding Details ---\n\n");
        for (i, f) in findings.iter().enumerate() {
            let live = if f
                .external_validation
                .as_ref()
                .map(|ev| ev.valid)
                .unwrap_or(false)
            {
                " [LIVE-VALIDATED]"
            } else {
                ""
            };
            out.push_str(&format!(
                "[{}] {} | {} | {:?} {:?} | {:?}{}\n",
                i + 1,
                sanitize::terminal(&f.issue_key),
                sanitize::terminal(&f.rule_id),
                f.severity,
                f.confidence,
                f.status,
                live,
            ));
            out.push_str(&format!("    URL: {}\n", sanitize::terminal(&f.issue_url)));
            out.push_str(&format!(
                "    Field: {}\n",
                sanitize::terminal(&f.field_path)
            ));
            if let (Some(first_seen), Some(times)) = (f.first_seen.as_ref(), f.times_seen) {
                out.push_str(&format!(
                    "    First seen: {} | Times seen: {}\n",
                    sanitize::terminal(first_seen),
                    times
                ));
            }
            out.push_str(&format!(
                "    Snippet: {}\n\n",
                sanitize::terminal(&f.snippet)
            ));
        }
    } else {
        out.push_str("No findings detected.\n");
    }

    fs::write(path, out)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to write summary report: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Finding, FindingStatus, ScanRun, Severity, SourceType};

    fn scan_run() -> ScanRun {
        ScanRun {
            scan_id: "scan-1".to_string(),
            status: crate::finding::ScanStatus::Success,
            started_at: "2026-08-07T12:00:00Z".to_string(),
            finished_at: "2026-08-07T12:00:05Z".to_string(),
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
            duration_secs: 5.0,
        }
    }

    fn finding_with(snippet: &str, issue_key: &str, field_path: &str) -> Finding {
        Finding {
            finding_id: "f-1".to_string(),
            issue_key: issue_key.to_string(),
            issue_url: "https://jira.example.com/browse/SEC-1".to_string(),
            field_path: field_path.to_string(),
            rule_id: "credential_pair".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            redacted_secret: "hu...et".to_string(),
            secret_hash: "sha256:abc".to_string(),
            snippet: snippet.to_string(),
            detected_at: "2026-08-07T12:00:00Z".to_string(),
            scanner_version: "0.1.0".to_string(),
            locations: Vec::new(),
            source_type: SourceType::Comment,
            status: FindingStatus::New,
            username: None,
            references: Vec::new(),
            first_seen: None,
            times_seen: None,
            external_validation: None,
        }
    }

    fn write_to_temp(findings: &[Finding], name: &str) -> String {
        let path = std::env::temp_dir().join(format!("jiraleaks_summary_{name}.txt"));
        let _ = std::fs::remove_file(&path);
        write(
            &path,
            &ReportInput {
                scan_run: &scan_run(),
                findings,
            },
        )
        .expect("summary write");
        let content = std::fs::read_to_string(&path).expect("read summary");
        let _ = std::fs::remove_file(&path);
        content
    }

    #[test]
    fn test_terminal_escapes_never_reach_the_report() {
        let snippet = "token=\u{1b}[2K\u{1b}[1;32mCLEAN\u{1b}[0m =cmd\u{7}\u{8}!";
        let content = write_to_temp(
            &[finding_with(snippet, "\u{1b}[31mSEC-1", "body\u{1b}[2J")],
            "escapes",
        );

        assert!(
            !content.contains('\u{1b}'),
            "escape character survived into the report"
        );
        assert!(!content.contains('\u{7}'));
        assert!(!content.contains('\u{8}'));
        assert!(!content.contains("[2K"));
        assert!(!content.contains("[1;32m"));
        // The harmless remainder of the snippet is still reported.
        assert!(content.contains("Snippet: token=CLEAN =cmd!"));
        assert!(content.contains("SEC-1"));
        assert!(content.contains("Field: body"));
    }

    #[test]
    fn test_osc52_sequence_never_reaches_the_report() {
        let snippet = "before\u{1b}]52;c;aGFja2VkIGNsaXBib2FyZA==\u{7}after";
        let content = write_to_temp(&[finding_with(snippet, "SEC-2", "body")], "osc");

        assert!(!content.contains('\u{1b}'));
        assert!(!content.contains("52;c;"));
        assert!(!content.contains("aGFja2Vk"));
        assert!(content.contains("Snippet: beforeafter"));
    }

    #[test]
    fn test_ordinary_report_is_unchanged() {
        let content = write_to_temp(
            &[finding_with(
                "token = [REDACTED:github_token]",
                "SEC-3",
                "comment[1].body",
            )],
            "clean",
        );

        assert!(content.contains("=== Jira Secret Scanner — Scan Summary ==="));
        assert!(content.contains("Snippet: token = [REDACTED:github_token]"));
        assert!(content.contains("SEC-3"));
        assert!(content.contains("JQL:          project = SEC"));
    }
}
