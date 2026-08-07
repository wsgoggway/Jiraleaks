use serde::{Deserialize, Serialize};

/// Severity levels for findings (spec §24.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence levels for findings (spec §10.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Source type indicating where a finding was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Description,
    Comment,
    Attachment,
    CustomField,
}


impl From<crate::extract::SourceType> for SourceType {
    fn from(st: crate::extract::SourceType) -> Self {
        match st {
            crate::extract::SourceType::Description => SourceType::Description,
            crate::extract::SourceType::Comment => SourceType::Comment,
            crate::extract::SourceType::Attachment => SourceType::Attachment,
            crate::extract::SourceType::CustomField => SourceType::CustomField,
        }
    }
}
/// Finding status (spec §24.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    New,
    Recurring,
    Closed,
    Confirmed,
    FalsePositive,
    Resolved,
}

/// A location where a finding was detected within an issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub issue_key: String,
    pub field_path: String,
    pub source_type: SourceType,
}

/// External live-validation result for a secret, written by another system
/// into the `live_validations` table (by `secret_hash`) and joined by the store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalValidation {
    pub valid: bool,
    pub source: String,
    pub checked_at: String,
}

/// A single finding (spec §24.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub issue_key: String,
    pub issue_url: String,
    pub field_path: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub redacted_secret: String,
    pub secret_hash: String,
    pub snippet: String,
    pub detected_at: String,
    pub scanner_version: String,
    pub locations: Vec<Location>,
    pub source_type: SourceType,
    pub status: FindingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_seen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_validation: Option<ExternalValidation>,
}

/// Scan run result with aggregate statistics (spec §24.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub scan_id: String,
    pub status: ScanStatus,
    pub started_at: String,
    pub finished_at: String,
    pub jira_url: String,
    pub jql: String,
    pub issues_scanned: u64,
    pub issues_total: u64,
    pub findings_total: u64,
    /// Findings by severity.
    pub findings_critical: u64,
    pub findings_high: u64,
    pub findings_medium: u64,
    pub findings_low: u64,
    pub findings_info: u64,
    /// Errors encountered (non-critical).
    pub errors_total: u64,
    pub comments_scanned: u64,
    pub attachments_scanned: u64,
    pub scanner_version: String,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Success,
    Failed,
    Partial,
}

/// Adjust confidence based on runtime signals.
pub fn adjust_confidence(
    base: Confidence,
    has_context_keyword: bool,
    entropy_above_threshold: bool,
    looks_like_placeholder: bool,
) -> Confidence {
    use Confidence::*;

    if looks_like_placeholder {
        return Low;
    }

    match base {
        High => {
            if has_context_keyword || entropy_above_threshold {
                High
            } else {
                Medium
            }
        }
        Medium => {
            if has_context_keyword && entropy_above_threshold {
                High
            } else if !has_context_keyword && !entropy_above_threshold {
                Low
            } else {
                Medium
            }
        }
        Low => Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_confidence_placeholder_drops_to_low() {
        assert_eq!(
            adjust_confidence(Confidence::High, true, true, true),
            Confidence::Low
        );
    }

    #[test]
    fn test_adjust_confidence_high_with_signals() {
        assert_eq!(
            adjust_confidence(Confidence::High, true, false, false),
            Confidence::High
        );
    }

    #[test]
    fn test_adjust_low_stays_low() {
        assert_eq!(
            adjust_confidence(Confidence::Low, true, true, false),
            Confidence::Low
        );
    }

    #[test]
    fn test_adjust_medium_upgrades_to_high_with_context_and_entropy() {
        assert_eq!(
            adjust_confidence(Confidence::Medium, true, true, false),
            Confidence::High
        );
    }
}
