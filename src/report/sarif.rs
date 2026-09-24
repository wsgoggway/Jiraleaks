use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun, ScanStatus, Severity};
use crate::report::ReportInput;
use serde_json::json;

/// Write findings in SARIF v2.1.0 format (spec §10.14).
pub fn write(path: &Path, input: &ReportInput<'_>) -> Result<(), ScannerError> {
    let scan_run = input.scan_run;
    let findings = input.findings;

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
                        // `uri` is the Jira issue URL, not a filesystem path: this
                        // scanner's artifact is a Jira issue, and its URL is the only
                        // stable, absolute locator a finding has. SARIF takes any URI
                        // here, so the choice is kept — and made explicit for consumers
                        // that would read it as a file path — by tagging the artifact
                        // kind and repeating the exact origin of the secret
                        // (`issueKey` plus `fieldPath`) next to it. The relative
                        // alternative (`uriBaseId` pointing at the Jira base with a
                        // `browse/SEC-1` relative URI) is resolved against a base that
                        // file-oriented viewers do not know and drops the host, so it
                        // would locate the finding less precisely.
                        "artifactLocation": {
                            "uri": f.issue_url,
                            "description": {
                                "text": "Jira issue that contains the leaked secret"
                            },
                            "properties": {
                                "artifactKind": "jira-issue",
                                "issueKey": f.issue_key,
                                "fieldPath": f.field_path,
                            }
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

    let mut invocation = json!({
        // The truth about the run: a partial scan saw only part of its input, so
        // "no finding here" is not evidence of absence and the run must not claim
        // it was successful (SARIF §3.20.2).
        "executionSuccessful": scan_run.status == ScanStatus::Success,
        "startTimeUtc": scan_run.started_at,
        "endTimeUtc": scan_run.finished_at
    });
    if let Some((level, text)) = incomplete_run_notification(scan_run) {
        invocation["toolExecutionNotifications"] = json!([{
            "level": level,
            "message": { "text": text }
        }]);
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "jiraleaks",
                    "version": scan_run.scanner_version,
                    "informationUri": "https://github.com/appsec-team/jiraleaks",
                    "rules": collect_rules(findings)
                }
            },
            "results": results,
            "invocations": [invocation]
        }]
    });

    let json_str = serde_json::to_string_pretty(&sarif)
        .map_err(|e| ScannerError::ReportWrite(format!("SARIF serialization error: {e}")))?;

    fs::write(path, json_str)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to write SARIF report: {e}")))?;

    Ok(())
}

/// Notification describing a run that did not complete, or `None` for a clean one.
///
/// A partial or failed run is reported per SARIF §3.20.20
/// (`invocation.toolExecutionNotifications`) rather than only in the report's
/// metadata, because `executionSuccessful: false` alone does not say how much of
/// the input was actually seen.
fn incomplete_run_notification(scan_run: &ScanRun) -> Option<(&'static str, String)> {
    let coverage = format!(
        "{} of {} issues scanned, {} errors",
        scan_run.issues_scanned, scan_run.issues_total, scan_run.errors_total
    );
    match scan_run.status {
        ScanStatus::Success => None,
        ScanStatus::Partial => Some((
            "warning",
            format!(
                "Partial scan ({coverage}): results are incomplete, so a missing finding is not proof that a secret is absent."
            ),
        )),
        ScanStatus::Failed => Some((
            "error",
            format!("Failed scan ({coverage}): results are incomplete and must not be read as a clean scan."),
        )),
    }
}

/// `tool.driver.rules` entries for the rules the results actually reference.
///
/// SARIF expects every `result.ruleId` to resolve to an entry of
/// `tool.driver.rules`; with an empty array every result dangles and viewers show
/// a bare id. Rule metadata (description, declared severity) lives in `rules.rs`,
/// which this writer is not given, so each rule is described from what the
/// findings themselves carry: its id, a generic short description, and
/// `defaultConfiguration.level` set to the most severe level its findings produced
/// — the level a consumer should use when it re-evaluates the rule instead of
/// trusting `result.level`. Order and content are deterministic: rules appear in
/// first-reference order, and tidier metadata from the rule catalogue can replace
/// the generic text without changing the ids.
fn collect_rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut rules: Vec<(&str, &'static str)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();

    for f in findings {
        let level = severity_to_sarif_level(&f.severity);
        match index.get(f.rule_id.as_str()).copied() {
            Some(i) => {
                let seen = &mut rules[i].1;
                if level_rank(level) < level_rank(seen) {
                    *seen = level;
                }
            }
            None => {
                index.insert(f.rule_id.as_str(), rules.len());
                rules.push((f.rule_id.as_str(), level));
            }
        }
    }

    rules
        .into_iter()
        .map(|(id, level)| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": format!("Secret leak pattern '{id}' matched in Jira content") },
                "defaultConfiguration": { "level": level },
            })
        })
        .collect()
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

/// Rank of a SARIF level, most severe first, for collapsing the severities of one
/// rule into the single `defaultConfiguration.level`.
fn level_rank(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warning" => 1,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, FindingStatus, Location, ScanRun, SourceType};

    const SCHEMA_URI: &str =
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

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

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            finding_id: "f-1".into(),
            issue_key: "SEC-42".into(),
            issue_url: "https://jira.example.com/browse/SEC-42".into(),
            field_path: "fields.description".into(),
            rule_id: rule_id.into(),
            severity,
            confidence: Confidence::High,
            redacted_secret: "AKIA********EXAMPLE".into(),
            secret_hash: "deadbeef".into(),
            snippet: "[REDACTED]".into(),
            detected_at: "2026-01-01T00:00:00Z".into(),
            scanner_version: "0.1.0".into(),
            locations: vec![Location {
                issue_key: "SEC-42".into(),
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

    /// Write one document to a per-test directory and hand back the parsed JSON.
    fn write_to_value(tag: &str, status: ScanStatus, findings: &[Finding]) -> serde_json::Value {
        let dir =
            std::env::temp_dir().join(format!("jiraleaks-sarif-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.sarif");
        let run = scan_run(status);
        write(
            &path,
            &ReportInput {
                scan_run: &run,
                findings,
            },
        )
        .expect("sarif write");
        let doc = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        doc
    }

    #[test]
    fn document_has_the_required_sarif_shape() {
        let doc = write_to_value(
            "shape",
            ScanStatus::Success,
            &[finding("aws-access-key", Severity::High)],
        );
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["$schema"], SCHEMA_URI);
        assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "jiraleaks");
    }

    #[test]
    fn execution_success_follows_the_scan_status() {
        let success = write_to_value("status-success", ScanStatus::Success, &[]);
        assert_eq!(
            success["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        assert!(success["runs"][0]["invocations"][0]
            .get("toolExecutionNotifications")
            .is_none());

        let partial = write_to_value("status-partial", ScanStatus::Partial, &[]);
        assert_eq!(
            partial["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        let notification = &partial["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(notification["level"], "warning");
        let text = notification["message"]["text"]
            .as_str()
            .expect("message text");
        assert!(text.contains("Partial scan"), "got {text}");
        assert!(text.contains("3 of 10 issues"), "got {text}");

        let failed = write_to_value("status-failed", ScanStatus::Failed, &[]);
        assert_eq!(
            failed["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(
            failed["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["level"],
            "error"
        );
    }

    #[test]
    fn every_referenced_rule_is_declared_once() {
        let findings = [
            finding("aws-access-key", Severity::High),
            finding("aws-access-key", Severity::Medium),
            finding("github_token", Severity::Low),
        ];
        let doc = write_to_value("rules", ScanStatus::Success, &findings);
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");

        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["aws-access-key", "github_token"]);
        // The rule keeps the most severe level its findings produced.
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "error");
        assert_eq!(rules[1]["defaultConfiguration"]["level"], "note");
        assert!(rules[0]["name"].is_string());
        assert!(rules[0]["shortDescription"]["text"].is_string());

        // No result dangles: every ruleId resolves to a declared rule.
        let results = doc["runs"][0]["results"].as_array().expect("results array");
        for result in results {
            let rule_id = result["ruleId"].as_str().unwrap();
            assert!(ids.contains(&rule_id), "undeclared rule {rule_id}");
        }
    }

    #[test]
    fn artifact_location_names_the_jira_issue() {
        let doc = write_to_value(
            "artifact",
            ScanStatus::Success,
            &[finding("aws-access-key", Severity::High)],
        );
        let artifact =
            &doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(artifact["uri"], "https://jira.example.com/browse/SEC-42");
        assert_eq!(artifact["properties"]["artifactKind"], "jira-issue");
        assert_eq!(artifact["properties"]["issueKey"], "SEC-42");
        assert_eq!(artifact["properties"]["fieldPath"], "fields.description");
    }

    #[test]
    fn rules_are_empty_without_findings() {
        let doc = write_to_value("no-findings", ScanStatus::Success, &[]);
        assert_eq!(
            doc["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}
