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

impl Severity {
    /// Parse a severity name, case-insensitively.
    ///
    /// **Lenient by contract**: an unknown or empty value yields
    /// [`Severity::Medium`], it never fails. This is the behaviour the scanner
    /// has always had for rule output — `severity` is free-form text in a user
    /// rules file — and it must stay that way, because a typo in a custom rule
    /// must not abort a scan. Use [`Severity::parse_opt`] where an unknown value
    /// has to be detected (configuration validation does).
    pub fn parse(s: &str) -> Self {
        Self::parse_opt(s).unwrap_or(Severity::Medium)
    }

    /// Strict counterpart of [`Severity::parse`]: `None` for an unknown value.
    pub fn parse_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }

    /// Canonical lowercase name, the spelling used by JSON reports and by the
    /// rules files.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

impl std::str::FromStr for Severity {
    /// Infallible: the lenient contract of [`Severity::parse`] has no error case,
    /// because an unknown severity must default rather than fail. Prefer the
    /// explicit [`Severity::parse`]; this impl only makes `"high".parse()`
    /// available for generic code.
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Severity::parse(s))
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence levels for findings (spec §10.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Parse a confidence name, case-insensitively.
    ///
    /// **Lenient by contract**: an unknown or empty value yields
    /// [`Confidence::Low`], it never fails — same reasoning as
    /// [`Severity::parse`]. Use [`Confidence::parse_opt`] where an unknown value
    /// has to be detected.
    pub fn parse(s: &str) -> Self {
        Self::parse_opt(s).unwrap_or(Confidence::Low)
    }

    /// Strict counterpart of [`Confidence::parse`]: `None` for an unknown value.
    pub fn parse_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "high" => Some(Confidence::High),
            "medium" => Some(Confidence::Medium),
            "low" => Some(Confidence::Low),
            _ => None,
        }
    }

    /// Canonical lowercase name, the spelling used by JSON reports and by the
    /// rules files.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

impl std::str::FromStr for Confidence {
    /// Infallible: see [`Severity`]'s impl — the lenient parse has no error case.
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Confidence::parse(s))
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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

/// Identity of ONE finding location: one secret value, detected by one rule, in
/// one Jira issue.
///
/// This is the granularity the findings store persists: the `findings` table is
/// keyed by [`FindingKey::fingerprint`], so every issue that carries the secret
/// keeps its own row and its own status history (`first_seen`, `times_seen`,
/// `closed_at`). A secret reported from N issues therefore owns N rows, which is
/// exactly what lets the reconciler close the secret in a re-scanned issue while
/// leaving the other issues untouched.
///
/// Do not confuse this with [`MergeKey`], which deliberately drops the issue
/// key: deduplication merges the same secret seen in several issues into one
/// reportable finding, while persistence needs the per-issue detail.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FindingKey {
    /// `sha256:`-prefixed hash of the secret value ([`crate::hash::secret_hash`]).
    pub secret_hash: String,
    /// Rule that produced the finding.
    pub rule_id: String,
    /// Jira issue key this location lives in.
    pub issue_key: String,
}

impl FindingKey {
    /// Build a key from its three parts.
    pub fn new(
        secret_hash: impl Into<String>,
        rule_id: impl Into<String>,
        issue_key: impl Into<String>,
    ) -> Self {
        Self {
            secret_hash: secret_hash.into(),
            rule_id: rule_id.into(),
            issue_key: issue_key.into(),
        }
    }

    /// Deterministic, scan-independent primary key of a stored location.
    ///
    /// Format: `fp:` followed by the 64 lowercase hex digits of
    /// `sha256("{secret_hash}\x1f{rule_id}\x1f{issue_key}")`. `\x1f` (ASCII unit
    /// separator) cannot occur in any of the three components, so the
    /// concatenation stays unambiguous.
    ///
    /// This string is the value of the `findings.fingerprint` column of every
    /// database written so far, and `finding_id` (a UUID v4 regenerated on each
    /// scan) is NOT a substitute for it. The format must never change: altering
    /// it would orphan all existing state and re-open every finding. The golden
    /// vectors in the tests below pin it.
    pub fn fingerprint(&self) -> String {
        let mut input = String::with_capacity(
            self.secret_hash.len() + self.rule_id.len() + self.issue_key.len() + 2,
        );
        input.push_str(&self.secret_hash);
        input.push('\x1f');
        input.push_str(&self.rule_id);
        input.push('\x1f');
        input.push_str(&self.issue_key);
        format!("fp:{}", crate::hash::sha256_hex(input.as_bytes()))
    }
}

/// Identity used when MERGING duplicate findings within a scan: the same secret
/// value detected by the same rule.
///
/// The issue key is deliberately absent: one secret found in N places is one
/// finding with N locations (spec §10.12.3), so the merge key must ignore where
/// it was found. [`std::fmt::Display`] renders exactly the string the
/// deduplicator has always used as its map key, `"{secret_hash}:{rule_id}"`; that
/// format is frozen for the same reason as the fingerprint's.
///
/// Compare with [`FindingKey`], which keeps the issue key and identifies a
/// single persisted location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeKey {
    /// `sha256:`-prefixed hash of the secret value.
    pub secret_hash: String,
    /// Rule that produced the finding.
    pub rule_id: String,
}

impl std::fmt::Display for MergeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.secret_hash, self.rule_id)
    }
}

impl Finding {
    /// Identity of this finding's own location: `(secret_hash, rule_id,
    /// issue_key)`, where `issue_key` is the issue the finding was reported
    /// from.
    ///
    /// For a finding that carries explicit `locations`, this equals the first
    /// entry of [`Finding::location_keys`].
    pub fn key(&self) -> FindingKey {
        FindingKey {
            secret_hash: self.secret_hash.clone(),
            rule_id: self.rule_id.clone(),
            issue_key: self.issue_key.clone(),
        }
    }

    /// Identity used for deduplication: issue-independent `(secret_hash,
    /// rule_id)`. See [`MergeKey`].
    pub fn merge_key(&self) -> MergeKey {
        MergeKey {
            secret_hash: self.secret_hash.clone(),
            rule_id: self.rule_id.clone(),
        }
    }

    /// Per-location identities of this finding, in location order — the set of
    /// store rows this finding owns.
    ///
    /// Mirrors persistence exactly: one key per entry of `locations`, or, when
    /// that list is empty, a single key for the location synthesized from the
    /// finding's own `issue_key` (see [`Finding::effective_locations`]).
    pub fn location_keys(&self) -> Vec<FindingKey> {
        self.effective_locations()
            .into_iter()
            .map(|loc| FindingKey {
                secret_hash: self.secret_hash.clone(),
                rule_id: self.rule_id.clone(),
                issue_key: loc.issue_key,
            })
            .collect()
    }

    /// Locations as they are persisted: `locations` when non-empty, otherwise a
    /// single location synthesized from this finding's own `issue_key`,
    /// `field_path` and `source_type`.
    ///
    /// Single source of truth for the store's write path and for
    /// [`Finding::location_keys`], so the rows written for a finding and the
    /// keys used to enrich it from stored state always agree — including the
    /// empty-`locations` case, where the synthesized location is the only row
    /// that exists.
    pub(crate) fn effective_locations(&self) -> Vec<Location> {
        if self.locations.is_empty() {
            vec![Location {
                issue_key: self.issue_key.clone(),
                field_path: self.field_path.clone(),
                source_type: self.source_type,
            }]
        } else {
            self.locations.clone()
        }
    }
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

    // --- identity keys ---

    /// A finding with the given identity and no explicit location list.
    fn finding(secret_hash: &str, rule_id: &str, issue_key: &str) -> Finding {
        Finding {
            finding_id: uuid::Uuid::new_v4().to_string(),
            issue_key: issue_key.into(),
            issue_url: format!("https://jira/browse/{issue_key}"),
            field_path: "fields.description".into(),
            rule_id: rule_id.into(),
            severity: Severity::High,
            confidence: Confidence::High,
            redacted_secret: "[REDACTED]".into(),
            secret_hash: secret_hash.into(),
            snippet: "[REDACTED]".into(),
            detected_at: "2026-01-01T00:00:00Z".into(),
            scanner_version: "0.1.0".into(),
            locations: Vec::new(),
            source_type: SourceType::Description,
            status: FindingStatus::New,
            username: None,
            references: Vec::new(),
            first_seen: None,
            times_seen: None,
            external_validation: None,
        }
    }

    fn location(issue_key: &str, field_path: &str) -> Location {
        Location {
            issue_key: issue_key.into(),
            field_path: field_path.into(),
            source_type: SourceType::Comment,
        }
    }

    /// Golden vectors captured from the original inline implementation in
    /// `store.rs` (before the fingerprint moved into `FindingKey`) and
    /// cross-checked with an independent `sha256sum`. These exact strings are
    /// the primary keys of every findings database already written, so any
    /// change to the format is a breaking change, not a refactor.
    #[test]
    fn finding_key_fingerprint_pins_persisted_format() {
        let cases = [
            (
                (
                    "sha256:3f786850e387550fdab836ed7e6dc881de23001b",
                    "github_token",
                    "SEC-1",
                ),
                "fp:6aa5cf7de5b23ac64e77617bf54e0ceddbd66e3af3269eb72479248210b57b8e",
            ),
            (
                ("sha256:abc123", "aws-access-key", "PROJ-123"),
                "fp:741e7f1a99b14329fd4fb147d348dfe013b8e644a52bb0e42a7d35427bebdf98",
            ),
            (
                ("", "", ""),
                "fp:b8c9e440ead3ddaccf7cc7e879d512a263272270df2d5504c0c3d1f85d16f9d9",
            ),
            (
                (
                    "sha256:deadbeef",
                    "generic_password_assignment",
                    "\u{422}\u{415}\u{421}\u{422}-1",
                ),
                "fp:baae764cbafa8795db4f39f6414e49cfd7cd50d77aac1296c24f3034d4700078",
            ),
            (
                (
                    "sha256:0123456789abcdef0123456789abcdef",
                    "private_key_block",
                    "AB-2",
                ),
                "fp:7ff44029be39b37e3a45b46b6174eb82adc7dc738247d2791dae3471b90138ca",
            ),
        ];
        for ((secret_hash, rule_id, issue_key), expected) in cases {
            let key = FindingKey::new(secret_hash, rule_id, issue_key);
            assert_eq!(
                key.fingerprint(),
                expected,
                "fingerprint format changed for {rule_id} in {issue_key}"
            );
            assert_eq!(key.fingerprint().len(), 3 + 64);
        }
    }

    #[test]
    fn fingerprint_is_deterministic_and_issue_sensitive() {
        let a = FindingKey::new("sha256:aaa", "github_token", "SEC-1");
        let b = FindingKey::new("sha256:aaa", "github_token", "SEC-1");
        let other_issue = FindingKey::new("sha256:aaa", "github_token", "SEC-2");
        let other_rule = FindingKey::new("sha256:aaa", "aws-access-key", "SEC-1");
        let other_secret = FindingKey::new("sha256:bbb", "github_token", "SEC-1");

        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.fingerprint(), other_issue.fingerprint());
        assert_ne!(a.fingerprint(), other_rule.fingerprint());
        assert_ne!(a.fingerprint(), other_secret.fingerprint());
        assert!(a.fingerprint().starts_with("fp:"));
    }

    #[test]
    fn separator_keeps_components_unambiguous() {
        // Without the \x1f separator these two pairs would hash identically.
        let a = FindingKey::new("sha256:ab", "c", "SEC-1");
        let b = FindingKey::new("sha256:a", "bc", "SEC-1");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn merge_key_renders_the_legacy_dedup_map_key() {
        let f = finding("sha256:abc", "aws-access-key", "SEC-1");
        assert_eq!(f.merge_key().to_string(), "sha256:abc:aws-access-key");
        assert_eq!(
            f.merge_key(),
            MergeKey {
                secret_hash: "sha256:abc".into(),
                rule_id: "aws-access-key".into(),
            }
        );
    }

    #[test]
    fn merge_key_ignores_issue_but_key_does_not() {
        let a = finding("sha256:abc", "aws-access-key", "SEC-1");
        let b = finding("sha256:abc", "aws-access-key", "SEC-2");
        assert_eq!(a.merge_key(), b.merge_key());
        assert_ne!(a.key().fingerprint(), b.key().fingerprint());
    }

    #[test]
    fn key_is_the_findings_own_issue() {
        let mut f = finding("sha256:abc", "aws-access-key", "SEC-1");
        f.locations = vec![location("SEC-8", "comment[0].body")];
        // `key()` describes the finding's own issue, not its first location.
        assert_eq!(f.key().issue_key, "SEC-1");
    }

    #[test]
    fn location_keys_without_locations_falls_back_to_own_issue() {
        let f = finding("sha256:abc", "aws-access-key", "SEC-1");
        assert!(f.locations.is_empty());
        let keys = f.location_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].issue_key, "SEC-1");
        assert_eq!(keys[0], f.key());
        // The fallback location reuses the finding's own field and source.
        let fallback = f.effective_locations();
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].issue_key, "SEC-1");
        assert_eq!(fallback[0].field_path, "fields.description");
        assert_eq!(fallback[0].source_type, SourceType::Description);
    }

    #[test]
    fn location_keys_follow_location_order_and_issues() {
        let mut f = finding("sha256:abc", "aws-access-key", "SEC-1");
        f.locations = vec![
            location("SEC-1", "fields.description"),
            location("SEC-4", "comment[2].body"),
            location("SEC-1", "comment[9].body"),
        ];
        let keys = f.location_keys();
        assert_eq!(
            keys.iter()
                .map(|k| k.issue_key.as_str())
                .collect::<Vec<_>>(),
            vec!["SEC-1", "SEC-4", "SEC-1"]
        );
        // Same secret and rule everywhere: keys differ only by issue, and two
        // locations of one issue share a fingerprint (which is why ids that
        // enumerate locations also carry an ordinal).
        assert_eq!(keys[0].fingerprint(), keys[2].fingerprint());
        assert_ne!(keys[0].fingerprint(), keys[1].fingerprint());
        assert_eq!(keys[0], f.key());
    }
}
