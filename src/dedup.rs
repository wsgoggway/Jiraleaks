use std::collections::HashMap;

use crate::finding::{Finding, MergeKey};

/// Deduplicates findings by hash(secret) + rule_id.
///
/// One secret found in N locations = 1 finding with N locations
/// (spec §10.12.3). The identity used here is [`Finding::merge_key`]: it
/// deliberately ignores the issue key, so the same secret surfacing in several
/// issues collapses into one finding. The keys are held as their
/// [`MergeKey`] string form (`"{secret_hash}:{rule_id}"`), which is the exact
/// map key the deduplicator has always used.
///
/// Persistence uses a different identity: [`crate::finding::FindingKey`] keeps
/// the issue key so every issue retains its own status history.
pub struct Deduplicator {
    /// Map of (hash, rule_id) → Finding index
    seen: HashMap<String, usize>,
    findings: Vec<Finding>,
}

impl Deduplicator {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            findings: Vec::new(),
        }
    }

    /// Insert a finding, deduplicating by secret hash + rule_id.
    /// Returns the index in the internal list.
    pub fn insert(&mut self, finding: Finding) -> usize {
        let key: MergeKey = finding.merge_key();
        let key = key.to_string();
        if let Some(&idx) = self.seen.get(&key) {
            // Duplicate — merge locations
            let existing = &mut self.findings[idx];
            for loc in finding.locations {
                if !existing.locations.contains(&loc) {
                    existing.locations.push(loc);
                }
            }
            idx
        } else {
            let idx = self.findings.len();
            self.seen.insert(key, idx);
            self.findings.push(finding);
            idx
        }
    }

    /// Consume and return all deduped findings.
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    /// Number of unique findings.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether the deduplicator is empty.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Finding, Location, Severity, SourceType};
    use crate::hash::secret_hash;

    fn make_finding(value: &str, rule_id: &str, field: &str) -> Finding {
        make_finding_in(value, rule_id, "TEST-1", field)
    }

    fn make_finding_in(value: &str, rule_id: &str, issue_key: &str, field: &str) -> Finding {
        Finding {
            finding_id: uuid::Uuid::new_v4().to_string(),
            issue_key: issue_key.into(),
            issue_url: format!("https://jira.example.com/browse/{issue_key}"),
            field_path: field.into(),
            rule_id: rule_id.into(),
            severity: Severity::High,
            confidence: Confidence::High,
            redacted_secret: crate::redact::redact(value),
            secret_hash: secret_hash(value),
            snippet: format!("[REDACTED:{rule_id}]"),
            detected_at: "2024-01-01T00:00:00Z".into(),
            scanner_version: "0.1.0".into(),
            locations: vec![Location {
                issue_key: issue_key.into(),
                field_path: field.into(),
                source_type: SourceType::Description,
            }],
            source_type: SourceType::Description,
            status: crate::finding::FindingStatus::New,
            username: None,
            references: Vec::new(),
            first_seen: None,
            times_seen: None,
            external_validation: None,
        }
    }

    #[test]
    fn test_dedup_same_secret_two_fields() {
        let mut dedup = Deduplicator::new();
        dedup.insert(make_finding("ghp_test123", "github_token", "description"));
        dedup.insert(make_finding(
            "ghp_test123",
            "github_token",
            "comment[0].body",
        ));
        assert_eq!(dedup.len(), 1);
        let findings = dedup.into_findings();
        assert_eq!(findings[0].locations.len(), 2);
    }

    #[test]
    fn test_different_secrets_no_dedup() {
        let mut dedup = Deduplicator::new();
        dedup.insert(make_finding(
            "secret_a",
            "generic_password_assignment",
            "desc",
        ));
        dedup.insert(make_finding(
            "secret_b",
            "generic_password_assignment",
            "desc",
        ));
        assert_eq!(dedup.len(), 2);
    }

    #[test]
    fn test_same_value_different_rules() {
        let mut dedup = Deduplicator::new();
        dedup.insert(make_finding("same_value", "rule_a", "desc"));
        dedup.insert(make_finding("same_value", "rule_b", "desc"));
        assert_eq!(dedup.len(), 2); // Different rule_id → separate findings
    }

    #[test]
    fn merges_one_secret_found_in_several_issues() {
        // The deduplicator keys off `Finding::merge_key()`, which ignores the
        // issue key: the same secret in two issues stays ONE finding with two
        // locations, while the per-location `FindingKey` distinguishes them.
        let mut dedup = Deduplicator::new();
        let first = make_finding_in("ghp_cross_issue", "github_token", "SEC-1", "description");
        let second = make_finding_in(
            "ghp_cross_issue",
            "github_token",
            "SEC-2",
            "comment[0].body",
        );
        assert_eq!(first.merge_key(), second.merge_key());
        assert_ne!(first.key().fingerprint(), second.key().fingerprint());

        dedup.insert(first);
        dedup.insert(second);
        assert_eq!(dedup.len(), 1);

        let findings = dedup.into_findings();
        assert_eq!(findings.len(), 1);
        let issues: Vec<&str> = findings[0]
            .locations
            .iter()
            .map(|l| l.issue_key.as_str())
            .collect();
        assert_eq!(issues, vec!["SEC-1", "SEC-2"]);
        assert_eq!(findings[0].location_keys().len(), 2);
    }
}
