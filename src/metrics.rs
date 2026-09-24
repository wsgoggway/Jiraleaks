use std::fs;
use std::path::Path;

use crate::config::MetricsFormat;
use crate::error::ScannerError;
use crate::finding::ScanRun;

/// Write metrics to a file in the requested format.
///
/// The parent directory of `path` is created when missing: a scan configured
/// with `--metrics-path /var/lib/jiraleaks/metrics.json` used to fail at its very
/// last step — after the reports were written — just because the directory did
/// not exist yet.
pub fn write_metrics(
    path: &Path,
    format: MetricsFormat,
    scan_run: &ScanRun,
) -> Result<(), ScannerError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                ScannerError::ReportWrite(format!(
                    "Failed to create metrics directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }
    }

    // Exhaustive on purpose: a new format must not fall back to another writer
    // silently, which is how `--metrics-format text` used to produce JSON.
    match format {
        MetricsFormat::Json => write_metrics_json(path, scan_run),
        MetricsFormat::Prometheus => write_metrics_prometheus(path, scan_run),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::ScanStatus;

    fn scan_run() -> ScanRun {
        ScanRun {
            scan_id: "scan-1".into(),
            status: ScanStatus::Success,
            started_at: "2026-01-01T00:00:00Z".into(),
            finished_at: "2026-01-01T00:00:01Z".into(),
            jira_url: "https://jira.example.com".into(),
            jql: "project = SEC".into(),
            issues_scanned: 2,
            issues_total: 2,
            findings_total: 1,
            findings_critical: 0,
            findings_high: 1,
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

    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("jiraleaks-metrics-{name}-{}", std::process::id()))
    }

    /// The missing parent directory is created instead of failing the scan after
    /// the reports were already written.
    #[test]
    fn creates_missing_parent_directory() {
        let dir = temp_dir("nested");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("deep").join("metrics.json");

        write_metrics(&path, MetricsFormat::Json, &scan_run()).expect("metrics write");

        let written = fs::read_to_string(&path).expect("metrics file exists");
        assert!(written.contains("\"issues_scanned\": 2"), "got {written}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prometheus_format_writes_exposition_lines() {
        let dir = temp_dir("prom");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("metrics.prom");

        write_metrics(&path, MetricsFormat::Prometheus, &scan_run()).expect("metrics write");

        let written = fs::read_to_string(&path).expect("metrics file exists");
        assert!(
            written.contains("jiraleaks_findings_total{scan_id=\"scan-1\"} 1"),
            "got {written}"
        );
        assert!(
            written.contains("jiraleaks_issues_scanned{scan_id=\"scan-1\"} 2"),
            "got {written}"
        );
        assert!(
            !written.contains("\"issues_scanned\""),
            "the Prometheus writer must not emit JSON: {written}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A bare filename has no parent directory to create and must not fail.
    #[test]
    fn relative_file_name_without_parent_is_written() {
        let dir = temp_dir("bare");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("metrics-bare.json");

        write_metrics(&path, MetricsFormat::Json, &scan_run()).expect("metrics write");
        assert!(path.is_file());
        let _ = fs::remove_dir_all(&dir);
    }
}
