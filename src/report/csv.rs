use std::path::Path;

use crate::error::ScannerError;
use crate::finding::Finding;

/// Write findings as a flat CSV table.
pub fn write(path: &Path, findings: &[Finding]) -> Result<(), ScannerError> {
    let mut wtr = csv::Writer::from_path(path).map_err(|e| {
        ScannerError::ReportWrite(format!("CSV writer creation error: {e}"))
    })?;

    // Header
    wtr.write_record([
        "finding_id",
        "issue_key",
        "issue_url",
        "field_path",
        "rule_id",
        "severity",
        "confidence",
        "redacted_secret",
        "secret_hash",
        "snippet",
        "detected_at",
        "source_type",
        "status",
        "first_seen",
        "times_seen",
        "external_validation",
    ])
    .map_err(|e| ScannerError::ReportWrite(format!("CSV header error: {e}")))?;

    for f in findings {
        let first_seen = f.first_seen.clone().unwrap_or_default();
        let times_seen = f
            .times_seen
            .map(|t| t.to_string())
            .unwrap_or_default();
        let external_validation = match &f.external_validation {
            Some(ev) => format!("valid={}@{}", ev.valid, ev.source),
            None => String::new(),
        };
        wtr.write_record([
            &f.finding_id,
            &f.issue_key,
            &f.issue_url,
            &f.field_path,
            &f.rule_id,
            &format!("{:?}", f.severity).to_lowercase(),
            &format!("{:?}", f.confidence).to_lowercase(),
            &f.redacted_secret,
            &f.secret_hash,
            &f.snippet,
            &f.detected_at,
            &format!("{:?}", f.source_type).to_lowercase(),
            &format!("{:?}", f.status).to_lowercase(),
            &first_seen,
            &times_seen,
            &external_validation,
        ])
        .map_err(|e| ScannerError::ReportWrite(format!("CSV write error: {e}")))?;
    }

    wtr.flush()
        .map_err(|e| ScannerError::ReportWrite(format!("CSV flush error: {e}")))?;

    Ok(())
}
