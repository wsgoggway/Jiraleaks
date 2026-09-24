use std::fs;
use std::path::Path;

use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun, Severity};
use serde_json::json;

/// Write findings in SARIF v2.1.0 format (spec §10.14).
pub fn write(path: &Path, scan_run: &ScanRun, findings: &[Finding]) -> Result<(), ScannerError> {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": severity_to_sarif_level(&f.severity),
                "message": {
                    "text": format!("{}: {}", f.rule_id, f.redacted_secret)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.issue_url
                        }
                    }
                }],
                "properties": {
                    "finding_id": f.finding_id,
                    "issue_key": f.issue_key,
                    "field_path": f.field_path,
                    "confidence": format!("{:?}", f.confidence).to_lowercase(),
                    "status": format!("{:?}", f.status).to_lowercase(),
                    "secret_hash": f.secret_hash,
                    "detected_at": f.detected_at,
                    "first_seen": f.first_seen.clone(),
                    "times_seen": f.times_seen,
                    "external_validation": f.external_validation.as_ref().map(|ev| {
                        json!({
                            "valid": ev.valid,
                            "source": ev.source,
                            "checked_at": ev.checked_at,
                        })
                    }),
                    "tags": sarif_tags(f),
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "jiraleaks",
                    "version": scan_run.scanner_version,
                    "informationUri": "https://github.com/appsec-team/jiraleaks",
                    "rules": []  // Could populate from rules engine
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "startTimeUtc": scan_run.started_at,
                "endTimeUtc": scan_run.finished_at
            }]
        }]
    });

    let json_str = serde_json::to_string_pretty(&sarif)
        .map_err(|e| ScannerError::ReportWrite(format!("SARIF serialization error: {e}")))?;

    fs::write(path, json_str)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to write SARIF report: {e}")))?;

    Ok(())
}
/// Tags for SARIF properties: source type, status, and live-validated when
/// an external validation marks the secret as valid.
fn sarif_tags(f: &Finding) -> Vec<String> {
    let mut tags = vec![
        format!("{:?}", f.source_type).to_lowercase(),
        format!("{:?}", f.status).to_lowercase(),
    ];
    if f.external_validation
        .as_ref()
        .map(|ev| ev.valid)
        .unwrap_or(false)
    {
        tags.push("live-validated".into());
    }
    tags
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
