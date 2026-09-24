use std::path::Path;

use crate::error::ScannerError;
use crate::finding::Finding;
use crate::sanitize;

/// Write findings as a flat CSV table.
///
/// Every free-text column is passed through [`sanitize::csv_field`] first: issue
/// keys, attachment names, field paths and snippets are written by Jira users, and a
/// snippet starting with `=` would otherwise be evaluated as a spreadsheet formula
/// when the report is opened. Columns derived from enums or numbers are written as
/// they are.
pub fn write(path: &Path, findings: &[Finding]) -> Result<(), ScannerError> {
    let mut wtr = csv::Writer::from_path(path)
        .map_err(|e| ScannerError::ReportWrite(format!("CSV writer creation error: {e}")))?;

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
        let first_seen = sanitize::csv_field(f.first_seen.as_deref().unwrap_or_default());
        let times_seen = f.times_seen.map(|t| t.to_string()).unwrap_or_default();
        let external_validation_raw = match &f.external_validation {
            Some(ev) => format!("valid={}@{}", ev.valid, ev.source),
            None => String::new(),
        };
        let external_validation = sanitize::csv_field(&external_validation_raw);

        let finding_id = sanitize::csv_field(&f.finding_id);
        let issue_key = sanitize::csv_field(&f.issue_key);
        let issue_url = sanitize::csv_field(&f.issue_url);
        let field_path = sanitize::csv_field(&f.field_path);
        let rule_id = sanitize::csv_field(&f.rule_id);
        let redacted_secret = sanitize::csv_field(&f.redacted_secret);
        let secret_hash = sanitize::csv_field(&f.secret_hash);
        let snippet = sanitize::csv_field(&f.snippet);
        let detected_at = sanitize::csv_field(&f.detected_at);

        wtr.write_record([
            finding_id.as_ref(),
            issue_key.as_ref(),
            issue_url.as_ref(),
            field_path.as_ref(),
            rule_id.as_ref(),
            format!("{:?}", f.severity).to_lowercase().as_str(),
            format!("{:?}", f.confidence).to_lowercase().as_str(),
            redacted_secret.as_ref(),
            secret_hash.as_ref(),
            snippet.as_ref(),
            detected_at.as_ref(),
            format!("{:?}", f.source_type).to_lowercase().as_str(),
            format!("{:?}", f.status).to_lowercase().as_str(),
            first_seen.as_ref(),
            times_seen.as_str(),
            external_validation.as_ref(),
        ])
        .map_err(|e| ScannerError::ReportWrite(format!("CSV write error: {e}")))?;
    }

    wtr.flush()
        .map_err(|e| ScannerError::ReportWrite(format!("CSV flush error: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, FindingStatus, Severity, SourceType};

    /// A finding whose every free-text field carries hostile content.
    fn hostile_finding() -> Finding {
        Finding {
            finding_id: "=cmd|'/C calc'!A1".to_string(),
            issue_key: "+1+1".to_string(),
            issue_url: "@SUM(A1)".to_string(),
            field_path: "-2+3".to_string(),
            rule_id: "=rule".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            redacted_secret: "@secret".to_string(),
            secret_hash: "=hash".to_string(),
            snippet: "=cmd|'/C calc'!A1".to_string(),
            detected_at: "+2026-08-07".to_string(),
            scanner_version: "0.1.0".to_string(),
            locations: Vec::new(),
            source_type: SourceType::Comment,
            status: FindingStatus::New,
            username: None,
            references: Vec::new(),
            first_seen: Some("=first".to_string()),
            times_seen: Some(2),
            external_validation: None,
        }
    }

    fn write_to_temp(findings: &[Finding], name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("jiraleaks_csv_{name}.csv"));
        let _ = std::fs::remove_file(&path);
        write(&path, findings).expect("csv write");
        path
    }

    #[test]
    fn test_hostile_fields_are_prefixed_and_shape_is_preserved() {
        let path = write_to_temp(&[hostile_finding()], "hostile");
        let mut rdr = csv::Reader::from_path(&path).expect("reader");

        let headers = rdr.headers().expect("headers").clone();
        assert_eq!(headers.len(), 16);

        let rows: Vec<csv::StringRecord> = rdr.records().map(|r| r.expect("record")).collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 16, "one row, sixteen columns");

        let row = &rows[0];
        for (idx, column) in [
            (0usize, "finding_id"),
            (1, "issue_key"),
            (2, "issue_url"),
            (3, "field_path"),
            (4, "rule_id"),
            (7, "redacted_secret"),
            (8, "secret_hash"),
            (9, "snippet"),
            (10, "detected_at"),
            (13, "first_seen"),
        ] {
            let value = row.get(idx).unwrap_or_default();
            assert!(
                value.starts_with('\''),
                "column {column} must be neutralised, got {value:?}"
            );
        }

        // The dangerous payload itself is still recognisable as text, just inert.
        assert_eq!(row.get(9), Some("'=cmd|'/C calc'!A1"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_ordinary_fields_are_written_unchanged() {
        let mut finding = hostile_finding();
        finding.finding_id = "0f3d1e6e-1111-2222-3333-444455556666".to_string();
        finding.issue_key = "SEC-1234".to_string();
        finding.issue_url = "https://jira.example.com/browse/SEC-1234".to_string();
        finding.field_path = "comment[3].body".to_string();
        finding.rule_id = "github_token".to_string();
        finding.redacted_secret = "gh...en".to_string();
        finding.secret_hash = "sha256:abc".to_string();
        finding.snippet = "token = [REDACTED:github_token]".to_string();
        finding.detected_at = "2026-08-07T13:00:00Z".to_string();
        finding.first_seen = Some("2026-08-07T13:00:00Z".to_string());

        let path = write_to_temp(&[finding], "clean");
        let mut rdr = csv::Reader::from_path(&path).expect("reader");
        let row = rdr.records().next().expect("one record").expect("record");

        assert_eq!(row.get(0), Some("0f3d1e6e-1111-2222-3333-444455556666"));
        assert_eq!(row.get(1), Some("SEC-1234"));
        assert_eq!(row.get(2), Some("https://jira.example.com/browse/SEC-1234"));
        assert_eq!(row.get(3), Some("comment[3].body"));
        assert_eq!(row.get(4), Some("github_token"));
        assert_eq!(row.get(5), Some("high"));
        assert_eq!(row.get(9), Some("token = [REDACTED:github_token]"));
        assert_eq!(row.get(14), Some("2"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_characters_do_not_break_the_table() {
        let mut finding = hostile_finding();
        finding.snippet = "line1\r\nline2".to_string();
        finding.issue_key = "SEC-\u{1b}[31m1234".to_string();

        let path = write_to_temp(&[finding], "controls");
        let mut rdr = csv::Reader::from_path(&path).expect("reader");
        let rows: Vec<csv::StringRecord> = rdr.records().map(|r| r.expect("record")).collect();

        assert_eq!(rows.len(), 1, "embedded CR/LF must not forge a row");
        assert_eq!(rows[0].len(), 16);
        assert_eq!(rows[0].get(1), Some("SEC-1234"));
        assert_eq!(rows[0].get(9), Some("line1line2"));

        let _ = std::fs::remove_file(&path);
    }
}
