use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicU64;

use crate::error::ScannerError;
use crate::finding::ScanRun;

/// In-process metrics counters (spec §16).
pub struct Metrics {
    pub scan_started_total: AtomicU64,
    pub scan_completed_total: AtomicU64,
    pub scan_failed_total: AtomicU64,
    pub issues_scanned_total: AtomicU64,
    pub findings_total: AtomicU64,
    pub findings_by_severity_critical: AtomicU64,
    pub findings_by_severity_high: AtomicU64,
    pub findings_by_severity_medium: AtomicU64,
    pub findings_by_severity_low: AtomicU64,
    pub comments_scanned_total: AtomicU64,
    pub attachments_scanned_total: AtomicU64,
    pub errors_total: AtomicU64,
    pub jira_rate_limited_total: AtomicU64,
    pub scan_duration_seconds: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            scan_started_total: AtomicU64::new(0),
            scan_completed_total: AtomicU64::new(0),
            scan_failed_total: AtomicU64::new(0),
            issues_scanned_total: AtomicU64::new(0),
            findings_total: AtomicU64::new(0),
            findings_by_severity_critical: AtomicU64::new(0),
            findings_by_severity_high: AtomicU64::new(0),
            findings_by_severity_medium: AtomicU64::new(0),
            findings_by_severity_low: AtomicU64::new(0),
            comments_scanned_total: AtomicU64::new(0),
            attachments_scanned_total: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            jira_rate_limited_total: AtomicU64::new(0),
            scan_duration_seconds: AtomicU64::new(0),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Write metrics to a file in the specified format.
pub fn write_metrics(path: &Path, format: &str, scan_run: &ScanRun) -> Result<(), ScannerError> {
    match format {
        "json" => write_metrics_json(path, scan_run),
        "prom" => write_metrics_prometheus(path, scan_run),
        _ => {
            tracing::warn!(format, "Unknown metrics format, using json");
            write_metrics_json(path, scan_run)
        }
    }
}

fn write_metrics_json(path: &Path, scan_run: &ScanRun) -> Result<(), ScannerError> {
    let metrics = serde_json::json!({
        "scan_id": scan_run.scan_id,
        "status": scan_run.status,
        "issues_scanned": scan_run.issues_scanned,
        "findings_total": scan_run.findings_total,
        "findings_by_severity": {
            "critical": scan_run.findings_critical,
            "high": scan_run.findings_high,
            "medium": scan_run.findings_medium,
            "low": scan_run.findings_low,
            "info": scan_run.findings_info,
        },
        "errors_total": scan_run.errors_total,
        "duration_secs": scan_run.duration_secs,
        "scanner_version": scan_run.scanner_version,
    });

    let json = serde_json::to_string_pretty(&metrics)
        .map_err(|e| ScannerError::ReportWrite(format!("Metrics JSON error: {e}")))?;

    fs::write(path, json)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to write metrics: {e}")))?;

    Ok(())
}

fn write_metrics_prometheus(path: &Path, scan_run: &ScanRun) -> Result<(), ScannerError> {
    let mut out = String::new();
    out.push_str(&format!(
        "jiraleaks_issues_scanned{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.issues_scanned
    ));
    out.push_str(&format!(
        "jiraleaks_findings_total{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.findings_total
    ));
    out.push_str(&format!(
        "jiraleaks_findings_critical{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.findings_critical
    ));
    out.push_str(&format!(
        "jiraleaks_findings_high{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.findings_high
    ));
    out.push_str(&format!(
        "jiraleaks_findings_medium{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.findings_medium
    ));
    out.push_str(&format!(
        "jiraleaks_findings_low{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.findings_low
    ));
    out.push_str(&format!(
        "jiraleaks_errors_total{{scan_id=\"{}\"}} {}\n",
        scan_run.scan_id, scan_run.errors_total
    ));
    out.push_str(&format!(
        "jiraleaks_duration_seconds{{scan_id=\"{}\"}} {:.1}\n",
        scan_run.scan_id, scan_run.duration_secs
    ));

    fs::write(path, out).map_err(|e| {
        ScannerError::ReportWrite(format!("Failed to write Prometheus metrics: {e}"))
    })?;

    Ok(())
}
