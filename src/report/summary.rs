use std::fs;
use std::path::Path;

use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Write a human-readable summary text report.
pub fn write(
    path: &Path,
    scan_run: &ScanRun,
    findings: &[Finding],
) -> Result<(), ScannerError> {
    let mut out = String::new();

    out.push_str("=== Jira Secret Scanner — Scan Summary ===\n\n");
    out.push_str(&format!("Scan ID:      {}\n", scan_run.scan_id));
    out.push_str(&format!("Status:       {:?}\n", scan_run.status));
    out.push_str(&format!("Jira URL:     {}\n", scan_run.jira_url));
    out.push_str(&format!("JQL:          {}\n", scan_run.jql));
    out.push_str(&format!("Started:      {}\n", scan_run.started_at));
    out.push_str(&format!("Finished:     {}\n", scan_run.finished_at));
    out.push_str(&format!("Duration:     {:.1}s\n\n", scan_run.duration_secs));

    out.push_str("--- Scan Statistics ---\n");
    out.push_str(&format!("  Issues scanned:    {}\n", scan_run.issues_scanned));
    out.push_str(&format!("  Comments scanned:  {}\n", scan_run.comments_scanned));
    out.push_str(&format!("  Attachments:       {}\n", scan_run.attachments_scanned));
    out.push_str(&format!("  Errors:            {}\n\n", scan_run.errors_total));

    out.push_str("--- Findings ---\n");
    out.push_str(&format!("  Total:             {}\n", scan_run.findings_total));
    out.push_str(&format!("  Critical:          {}\n", scan_run.findings_critical));
    out.push_str(&format!("  High:              {}\n", scan_run.findings_high));
    out.push_str(&format!("  Medium:            {}\n", scan_run.findings_medium));
    out.push_str(&format!("  Low:               {}\n", scan_run.findings_low));
    out.push_str(&format!("  Info:              {}\n\n", scan_run.findings_info));

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
                f.issue_key,
                f.rule_id,
                f.severity,
                f.confidence,
                f.status,
                live,
            ));
            out.push_str(&format!("    URL: {}\n", f.issue_url));
            out.push_str(&format!("    Field: {}\n", f.field_path));
            if let (Some(first_seen), Some(times)) = (f.first_seen.as_ref(), f.times_seen) {
                out.push_str(&format!(
                    "    First seen: {} | Times seen: {}\n",
                    first_seen, times
                ));
            }
            out.push_str(&format!("    Snippet: {}\n\n", f.snippet));
        }
    } else {
        out.push_str("No findings detected.\n");
    }

    fs::write(path, out).map_err(|e| {
        ScannerError::ReportWrite(format!("Failed to write summary report: {e}"))
    })?;

    Ok(())
}
