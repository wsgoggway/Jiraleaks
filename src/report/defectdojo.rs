use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::error::ScannerError;
use crate::finding::{Finding, FindingStatus, Severity};
use serde_json::json;

/// A finding in DefectDojo "Generic Findings Import" JSON format.
/// Importable via UI "Import Scan Results" or API `/api/v2/import-scan/`
/// with `scan_type=Generic Findings Import`.
#[derive(Serialize)]
struct DefectDojoFinding {
    title: String,
    severity: String,
    description: String,
    date: String,
    mitigation: String,
    references: String,
    file_path: String,
    active: bool,
    verified: bool,
    false_p: bool,
    duplicate: bool,
    static_finding: bool,
    unique_id_from_tool: String,
    tags: Vec<String>,
}

/// Write findings as a DefectDojo Generic Findings Import JSON document.
pub fn write(path: &Path, findings: &[Finding]) -> Result<(), ScannerError> {
    let output = json!({
        "findings": findings.iter().map(map_finding).collect::<Vec<_>>(),
    });

    let json_str = serde_json::to_string_pretty(&output).map_err(|e| {
        ScannerError::ReportWrite(format!("DefectDojo serialization error: {e}"))
    })?;

    fs::write(path, json_str).map_err(|e| {
        ScannerError::ReportWrite(format!("Failed to write DefectDojo report: {e}"))
    })?;

    Ok(())
}

fn status_label(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::New => "new",
        FindingStatus::Recurring => "recurring",
        FindingStatus::Closed => "closed",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false-positive",
        FindingStatus::Resolved => "resolved",
    }
}

fn map_finding(f: &Finding) -> DefectDojoFinding {
    let live_validated = f
        .external_validation
        .as_ref()
        .map(|ev| ev.valid)
        .unwrap_or(false);

    let mut description = format!(
        "Rule: {rule_id}\n\
         Issue: {issue_key} ({issue_url})\n\
         Field: {field_path} ({source_type})\n\
         Detected secret: {secret}\n\
         Snippet: {snippet}\n\
         Confidence: {confidence}\n\
         Secret hash (sha256): {secret_hash}\n\
         Detected at: {detected_at}\n\
         Status: {status}\n\
         Scanner version: {scanner_version}",
        rule_id = f.rule_id,
        issue_key = f.issue_key,
        issue_url = f.issue_url,
        field_path = f.field_path,
        source_type = format!("{:?}", f.source_type).to_lowercase(),
        secret = f.redacted_secret,
        snippet = f.snippet,
        confidence = format!("{:?}", f.confidence).to_lowercase(),
        secret_hash = f.secret_hash,
        detected_at = f.detected_at,
        status = status_label(f.status),
        scanner_version = f.scanner_version,
    );
    if let (Some(first_seen), Some(times)) = (f.first_seen.as_ref(), f.times_seen) {
        description.push_str(&format!("\nFirst seen: {first_seen}\nTimes seen: {times}"));
    }
    if let Some(ev) = f.external_validation.as_ref() {
        description.push_str(&format!(
            "\nExternal validation: valid={} (source: {}, checked_at: {})",
            ev.valid, ev.source, ev.checked_at
        ));
    }

    let mut tags = vec![
        "jira".to_string(),
        "secret-scanner".to_string(),
        format!("{:?}", f.source_type).to_lowercase(),
        format!("status:{}", status_label(f.status)),
    ];
    if live_validated {
        tags.push("live-validated".into());
    }

    DefectDojoFinding {
        title: format!("{} in {}", f.rule_id, f.issue_key),
        severity: severity_to_dd(&f.severity).to_string(),
        description,
        date: f.detected_at.clone(),
        mitigation: "Rotate the exposed credential, remove it from the Jira issue, and review who had access to the issue while it was exposed.".into(),
        references: f.issue_url.clone(),
        file_path: f.issue_key.clone(),
        active: f.status != FindingStatus::Resolved && f.status != FindingStatus::Closed,
        verified: true,
        false_p: f.status == FindingStatus::FalsePositive,
        duplicate: false,
        static_finding: true,
        unique_id_from_tool: f.finding_id.clone(),
        tags,
    }
}

fn severity_to_dd(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Location, SourceType};

    fn sample_finding(status: FindingStatus) -> Finding {
        Finding {
            finding_id: "f-123".into(),
            issue_key: "SEC-42".into(),
            issue_url: "https://jira/browse/SEC-42".into(),
            field_path: "fields.description".into(),
            rule_id: "aws-access-key".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            redacted_secret: "AKIA********EXAMPLE".into(),
            secret_hash: "deadbeef".into(),
            snippet: "aws_access_key_id = AKIA********EXAMPLE".into(),
            detected_at: "2026-08-06T12:00:00Z".into(),
            scanner_version: "0.1.0".into(),
            locations: vec![Location {
                issue_key: "SEC-42".into(),
                field_path: "fields.description".into(),
                source_type: SourceType::Description,
            }],
            source_type: SourceType::Description,
            status,
            username: None,
            references: Vec::new(),
            first_seen: None,
            times_seen: None,
            external_validation: None,
        }
    }

    #[test]
    fn severity_is_capitalized_for_defectdojo() {
        assert_eq!(severity_to_dd(&Severity::Critical), "Critical");
        assert_eq!(severity_to_dd(&Severity::High), "High");
        assert_eq!(severity_to_dd(&Severity::Medium), "Medium");
        assert_eq!(severity_to_dd(&Severity::Low), "Low");
        assert_eq!(severity_to_dd(&Severity::Info), "Info");
    }

    #[test]
    fn maps_detected_finding() {
        let dd = map_finding(&sample_finding(FindingStatus::Confirmed));
        assert_eq!(dd.title, "aws-access-key in SEC-42");
        assert_eq!(dd.severity, "High");
        assert_eq!(dd.file_path, "SEC-42");
        assert_eq!(dd.unique_id_from_tool, "f-123");
        assert!(dd.active);
        assert!(dd.verified);
        assert!(!dd.false_p);
        assert!(dd.static_finding);
        assert!(dd.description.contains("AKIA********EXAMPLE"));
        assert!(dd.description.contains("https://jira/browse/SEC-42"));
        assert_eq!(
            dd.tags,
            vec![
                "jira",
                "secret-scanner",
                "description",
                "status:confirmed"
            ]
        );
        assert!(dd.description.contains("Status: confirmed"));
    }

    #[test]
    fn false_positive_and_resolved_statuses() {
        let fp = map_finding(&sample_finding(FindingStatus::FalsePositive));
        assert!(fp.false_p);
        assert!(fp.active);
        let resolved = map_finding(&sample_finding(FindingStatus::Resolved));
        assert!(!resolved.active);
        assert!(!resolved.false_p);
    }

    #[test]
    fn closed_is_inactive() {
        let closed = map_finding(&sample_finding(FindingStatus::Closed));
        assert!(!closed.active);
        assert!(!closed.false_p);
        assert!(closed.tags.contains(&"status:closed".to_string()));
    }

    #[test]
    fn live_validated_adds_tag_and_history() {
        let mut f = sample_finding(FindingStatus::Recurring);
        f.first_seen = Some("2026-01-01T00:00:00Z".into());
        f.times_seen = Some(3);
        f.external_validation = Some(crate::finding::ExternalValidation {
            valid: true,
            source: "ext-sys".into(),
            checked_at: "2026-08-07T00:00:00Z".into(),
        });
        let dd = map_finding(&f);
        assert!(dd.tags.contains(&"live-validated".to_string()));
        assert!(dd.description.contains("First seen: 2026-01-01T00:00:00Z"));
        assert!(dd.description.contains("Times seen: 3"));
        assert!(dd.description.contains("External validation: valid=true"));
    }

    #[test]
    fn writes_valid_generic_import_json() {
        let dir = std::env::temp_dir().join(format!("dd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write(&path, &[sample_finding(FindingStatus::New)]).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let findings = doc["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "High");
        assert_eq!(findings[0]["title"], "aws-access-key in SEC-42");
        assert_eq!(findings[0]["active"], true);
    }
}
