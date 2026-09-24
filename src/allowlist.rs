//! Operator allowlist: the suppression filter applied to every candidate finding.
//!
//! The file is a YAML sequence of records:
//!
//! ```yaml
//! - value: "AKIAIOSFODNN7EXAMPLE"        # suppress this exact value anywhere
//!   reason: "public AWS docs example"
//! - sha256: "sha256:9f86d0..."           # suppress this value, by digest
//! - pattern: '^ghp_example_'             # suppress values matching this regex
//!   field: comment                       # ... but only inside the comment subtree
//!   reason: "documentation snippets"
//! - rule_id: aws_access_key_id           # suppress a whole rule
//!   project_key: SEC                     # ... only in one project
//! ```
//!
//! Loading is strict on purpose: a misconfigured allowlist suppresses findings
//! the operator did not mean to suppress, which is a missed leak, so every
//! silently useless record is a configuration error rather than a no-op.

use fancy_regex::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::error::ScannerError;
use crate::hash::secret_hash;

/// Number of hex digits in a SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;

/// Backtracking budget for one allowlist pattern match.
///
/// `fancy_regex` itself defaults to this value; the scanner sets it explicitly so
/// that the worst case stays visible here and cannot drift with a dependency
/// bump. A pattern that exceeds the budget is treated as *not matching* (the
/// finding is reported) and logged — never as a silent suppression.
const PATTERN_BACKTRACK_LIMIT: usize = 1_000_000;

/// One record of the allowlist file.
///
/// Unknown keys are rejected: a typo such as `valeu:` would otherwise create an
/// entry that matches nothing while the operator believes the finding is
/// suppressed.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AllowlistEntry {
    /// Exact secret value to suppress.
    #[serde(default)]
    pub value: Option<String>,
    /// SHA-256 of the secret value, with or without the `sha256:` prefix.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Regex searched inside the secret value.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Jira project key (the part of the issue key before the first `-`).
    #[serde(default)]
    pub project_key: Option<String>,
    /// Exact Jira issue key, e.g. `SEC-123`.
    #[serde(default)]
    pub issue_key: Option<String>,
    /// Detector rule id, e.g. `aws_access_key_id`.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Field scope: restrict the entry to one field (and its subpaths).
    #[serde(default)]
    pub field: Option<String>,
    /// Free-form justification, logged when the entry suppresses a finding.
    #[serde(default)]
    pub reason: Option<String>,
}

/// A record's match predicates, compiled once at load time.
#[derive(Debug, Clone)]
struct CompiledEntry {
    /// `None` = the entry applies to every field path.
    field: Option<String>,
    value: Option<String>,
    /// Normalized to 64 lowercase hex digits (no `sha256:` prefix).
    sha256: Option<String>,
    /// Compiled pattern plus its source text, for diagnostics.
    pattern: Option<(Regex, String)>,
    project_key: Option<String>,
    issue_key: Option<String>,
    rule_id: Option<String>,
    reason: Option<String>,
}

impl CompiledEntry {
    /// Validate and compile one record. `position` is the 1-based record number
    /// in the allowlist file, used in every diagnostic.
    fn compile(entry: AllowlistEntry, position: usize) -> Result<Self, ScannerError> {
        let value = required_non_empty("value", entry.value, position)?;
        let pattern = match required_non_empty("pattern", entry.pattern, position)? {
            None => None,
            Some(source) => {
                let re = RegexBuilder::new(&source)
                    .backtrack_limit(PATTERN_BACKTRACK_LIMIT)
                    .build()
                    .map_err(|e| {
                        ScannerError::Config(format!(
                            "allowlist entry #{position}: invalid regex pattern {source:?}: {e}"
                        ))
                    })?;
                Some((re, source))
            }
        };
        let sha256 = match required_non_empty("sha256", entry.sha256, position)? {
            None => None,
            Some(raw) => Some(normalize_sha256(&raw).ok_or_else(|| {
                ScannerError::Config(format!(
                    "allowlist entry #{position}: sha256 {raw:?} is not a SHA-256 digest \
                     (expected 64 hex digits, optionally prefixed with 'sha256:')"
                ))
            })?),
        };
        let project_key = trimmed(required_non_empty(
            "project_key",
            entry.project_key,
            position,
        )?);
        let issue_key = trimmed(required_non_empty("issue_key", entry.issue_key, position)?);
        let rule_id = trimmed(required_non_empty("rule_id", entry.rule_id, position)?);
        let field = trimmed(required_non_empty("field", entry.field, position)?);
        let reason = entry.reason.filter(|r| !r.trim().is_empty());

        // `field` is a scope, not a predicate: a record that carries no predicate
        // suppresses nothing, whatever its scope says.
        if value.is_none()
            && sha256.is_none()
            && pattern.is_none()
            && project_key.is_none()
            && issue_key.is_none()
            && rule_id.is_none()
        {
            return Err(ScannerError::Config(format!(
                "allowlist entry #{position}: no match condition — set at least one of \
                 value, sha256, pattern, project_key, issue_key, rule_id"
            )));
        }

        Ok(Self {
            field,
            value,
            sha256,
            pattern,
            project_key,
            issue_key,
            rule_id,
            reason,
        })
    }

    /// Whether this entry suppresses the finding. `hash_hex` is the finding's
    /// SHA-256 digest without prefix, and is `None` when no loaded entry asks for
    /// one.
    fn matches(
        &self,
        value: &str,
        hash_hex: Option<&str>,
        rule_id: &str,
        issue_key: &str,
        field_path: &str,
    ) -> bool {
        if let Some(scope) = &self.field {
            if !field_scope_matches(scope, field_path) {
                return false;
            }
        }

        if self.value.as_deref() == Some(value) {
            return true;
        }

        if let (Some(expected), Some(actual)) = (self.sha256.as_deref(), hash_hex) {
            if expected == actual {
                return true;
            }
        }

        if let Some((regex, source)) = &self.pattern {
            match regex.is_match(value) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        pattern = %source,
                        error = %e,
                        "Allowlist pattern exceeded its backtracking budget; \
                         the finding is not suppressed"
                    );
                }
            }
        }

        if self.rule_id.as_deref() == Some(rule_id) {
            return true;
        }

        if self.issue_key.as_deref() == Some(issue_key) {
            return true;
        }

        if let Some(project) = &self.project_key {
            if issue_key.split('-').next() == Some(project.as_str()) {
                return true;
            }
        }

        false
    }
}

/// Trims a surrounding-whitespace-tolerant key value; `None` stays `None`.
fn trimmed(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string())
}

/// Rejects a predicate that is present but empty of content.
///
/// `value: ""` matches a secret that never occurs, but `pattern: ""` matches
/// *every* value — the difference between a useless record and an allowlist
/// that would hide the whole scan. Neither is ever meant literally.
fn required_non_empty(
    key: &str,
    raw: Option<String>,
    position: usize,
) -> Result<Option<String>, ScannerError> {
    match raw {
        None => Ok(None),
        Some(v) if v.trim().is_empty() => Err(ScannerError::Config(format!(
            "allowlist entry #{position}: '{key}' is empty; drop the key or give it a value"
        ))),
        Some(v) => Ok(Some(v)),
    }
}

/// Normalizes a SHA-256 digest to 64 lowercase hex digits, accepting both the
/// bare digest and the `sha256:`-prefixed form the reports print.
fn normalize_sha256(raw: &str) -> Option<String> {
    let hex = raw.strip_prefix("sha256:").unwrap_or(raw);
    if hex.len() == SHA256_HEX_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// The documented `field` scope rule: an entry applies when the finding's field
/// path is the scope itself or lies under it.
///
/// `field: comment` therefore matches `comment`, `comment.body` and
/// `comment[0].text` (the extractor builds paths as `a.b[i].c`), and matches
/// neither `comments`, nor `commentary`, nor `fields.comment`.
fn field_scope_matches(scope: &str, field_path: &str) -> bool {
    if scope == field_path {
        return true;
    }
    match field_path.strip_prefix(scope) {
        Some(rest) => rest.starts_with('.') || rest.starts_with('['),
        None => false,
    }
}

/// Pre-compiled allowlist for fast matching.
///
/// # Matching contract
///
/// A loaded record suppresses a finding when its `field` scope admits the
/// finding's `field_path` **and** at least one predicate matches; predicates are
/// OR-ed inside a record and records are OR-ed across the file.
///
/// * `value` — byte-for-byte equality with the finding's matched secret value.
/// * `sha256` — SHA-256 of that value, accepted as 64 hex digits with or without
///   the `sha256:` prefix and compared case-insensitively.
/// * `pattern` — a `fancy_regex` search anywhere inside the value; the pattern is
///   not anchored unless it anchors itself. The search runs under
///   [`PATTERN_BACKTRACK_LIMIT`]; a pattern that exceeds the budget is logged and
///   treated as not matching, so the finding survives.
/// * `rule_id` — exact, case-sensitive detector rule id.
/// * `issue_key` — exact, case-sensitive Jira issue key (`SEC-123`).
/// * `project_key` — exact, case-sensitive project key: the part of the issue key
///   before the first `-` (`SEC`).
///
/// `field` is the one structural filter and narrows the **whole** record, key
/// predicates included: `field: description` plus `rule_id: aws_access_key_id`
/// suppresses that rule only inside the `description` subtree, never elsewhere.
/// With `field` unset the record applies to every field path, as before.
///
/// The scope is compared with the finding's `field_path` — the extractor's path
/// to the scanned text, built as `a.b[i].c` (`description`,
/// `comment.comments[0].body`, `attachment:dump.txt`):
///
/// * the scope equals the path exactly (`field: comment` matches `comment`), or
///   is a prefix of it followed by `.` or `[`, i.e. a **subpath** (`field:
///   comment` matches `comment.body` and `comment[0].text`);
/// * consequently `field: comment` matches neither `comments`, `commentary` nor
///   `fields.comment`, and `field: description` never covers a comment.
///
/// Keys and the `field` scope are trimmed of surrounding whitespace; `value` is
/// compared exactly as written. Matching is prefix-based — no case folding, no
/// wildcards, no substring matching.
///
/// `reason` is audit only: it never affects matching and is logged (at debug
/// level) with the suppression it justifies.
#[derive(Debug, Clone)]
pub struct AllowlistFilter {
    entries: Vec<CompiledEntry>,
    /// True when at least one record matches by digest, so the digest of a
    /// candidate value is computed at most once per candidate.
    has_hashes: bool,
}

impl AllowlistFilter {
    /// Load an allowlist from a YAML file.
    ///
    /// An empty file (or one holding only a YAML null document) is a valid
    /// allowlist that suppresses nothing, and is logged as a warning: it is far
    /// more often a misconfigured path than an intentional file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ScannerError> {
        let yaml = std::fs::read_to_string(path).map_err(|e| {
            ScannerError::Config(format!(
                "Failed to read allowlist file {}: {e}",
                path.display()
            ))
        })?;

        let entries: Vec<AllowlistEntry> = if yaml.trim().is_empty() {
            Vec::new()
        } else {
            serde_yaml::from_str::<Option<Vec<AllowlistEntry>>>(&yaml)
                .map_err(|e| {
                    ScannerError::Config(format!(
                        "Failed to parse allowlist {}: {e}",
                        path.display()
                    ))
                })?
                .unwrap_or_default()
        };

        // Name the file in every record-level diagnostic: the operator has to
        // find the offending record in it.
        Self::from_entries(entries).map_err(|e| match e {
            ScannerError::Config(msg) => ScannerError::Config(format!("{}: {msg}", path.display())),
            other => other,
        })
    }

    /// Compile an explicit record list.
    ///
    /// Fails with [`ScannerError::Config`] when a record is unusable: an unknown
    /// key, an empty or non-matching record, an empty predicate, a malformed
    /// digest, or a regex that does not compile.
    pub fn from_entries(entries: Vec<AllowlistEntry>) -> Result<Self, ScannerError> {
        let mut compiled = Vec::with_capacity(entries.len());
        let mut has_hashes = false;
        for (index, entry) in entries.into_iter().enumerate() {
            let record = CompiledEntry::compile(entry, index + 1)?;
            has_hashes |= record.sha256.is_some();
            compiled.push(record);
        }

        if compiled.is_empty() {
            tracing::warn!("allowlist is empty: no finding will be suppressed by it");
        }

        Ok(Self {
            entries: compiled,
            has_hashes,
        })
    }

    /// A filter that suppresses nothing, for a scan without an allowlist.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            has_hashes: false,
        }
    }

    /// Whether the finding is allowlisted.
    ///
    /// `field_path` is the extractor's path to the scanned text (`a.b[i].c`,
    /// e.g. `description`, `comment.comments[0].body`, `attachment:dump.txt`);
    /// see the type-level contract for how `field` scopes compare to it.
    pub fn is_allowed(
        &self,
        secret_value: &str,
        rule_id: &str,
        issue_key: &str,
        field_path: &str,
    ) -> bool {
        let hash_hex = if self.has_hashes {
            let hashed = secret_hash(secret_value);
            Some(
                hashed
                    .strip_prefix("sha256:")
                    .unwrap_or(&hashed)
                    .to_string(),
            )
        } else {
            None
        };

        for entry in &self.entries {
            if entry.matches(
                secret_value,
                hash_hex.as_deref(),
                rule_id,
                issue_key,
                field_path,
            ) {
                // Audit trail: which record suppressed what, and why it says so.
                // The secret value itself is never logged.
                tracing::debug!(
                    rule_id = %rule_id,
                    issue = %issue_key,
                    field_path = %field_path,
                    reason = entry.reason.as_deref().unwrap_or("-"),
                    "Finding suppressed by allowlist"
                );
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(yaml: &str) -> AllowlistEntry {
        serde_yaml::from_str(yaml).expect("valid allowlist entry yaml")
    }

    fn filter(yaml: &str) -> AllowlistFilter {
        AllowlistFilter::from_entries(vec![entry(yaml)]).expect("entry compiles")
    }

    // ── field scope rule ──

    #[test]
    fn field_scope_matches_exact_and_subpaths() {
        assert!(field_scope_matches("comment", "comment"));
        assert!(field_scope_matches("comment", "comment.body"));
        assert!(field_scope_matches("comment", "comment[0].text"));
        assert!(field_scope_matches("comment.body", "comment.body"));
        assert!(field_scope_matches("comment[0]", "comment[0].body"));
        assert!(field_scope_matches("a.b", "a.b[3].c.d"));
    }

    #[test]
    fn field_scope_is_not_a_substring_match() {
        assert!(!field_scope_matches("comment", "comments"));
        assert!(!field_scope_matches("comment", "commentary"));
        assert!(!field_scope_matches("comment", "comment_x"));
        assert!(!field_scope_matches("comment", "fields.comment"));
        assert!(!field_scope_matches("description", "comment.body"));
        assert!(!field_scope_matches("comment.body", "comment"));
        assert!(!field_scope_matches("", "description"));
    }

    // ── digest normalization ──

    #[test]
    fn sha256_accepts_both_forms_and_is_case_insensitive() {
        let bare = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let prefixed = format!("sha256:{bare}");
        assert_eq!(normalize_sha256(bare), Some(bare.to_string()));
        assert_eq!(normalize_sha256(&prefixed), Some(bare.to_string()));
        assert_eq!(
            normalize_sha256(&bare.to_ascii_uppercase()),
            Some(bare.to_string())
        );
    }

    #[test]
    fn sha256_rejects_non_digests() {
        assert_eq!(normalize_sha256(""), None);
        assert_eq!(normalize_sha256("sha256:"), None);
        assert_eq!(normalize_sha256("9f86d0"), None);
        assert_eq!(normalize_sha256(&"z".repeat(64)), None);
        assert_eq!(normalize_sha256(&"a".repeat(65)), None);
    }

    // ── strict loading ──

    #[test]
    fn unknown_key_is_rejected_by_serde() {
        let err = serde_yaml::from_str::<AllowlistEntry>("valeu: AKIAIOSFODNN7EXAMPLE\n")
            .expect_err("typo must not parse");
        let msg = err.to_string();
        assert!(msg.contains("valeu"), "error must name the key: {msg}");
    }

    #[test]
    fn entry_without_any_predicate_is_rejected() {
        let err = AllowlistFilter::from_entries(vec![entry("reason: nothing\n")])
            .expect_err("record must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("entry #1"),
            "error must name the record: {msg}"
        );
        assert!(msg.contains("no match condition"), "{msg}");
    }

    #[test]
    fn field_alone_is_not_a_predicate() {
        assert!(AllowlistFilter::from_entries(vec![entry("field: description\n")]).is_err());
    }

    #[test]
    fn empty_predicates_are_rejected() {
        for yaml in [
            "value: ''\n",
            "pattern: ''\n",
            "value: '  '\n",
            "field: ''\nvalue: x\n",
        ] {
            let err = AllowlistFilter::from_entries(vec![entry(yaml)])
                .expect_err("empty predicate must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("empty"), "{yaml} -> {msg}");
        }
    }

    #[test]
    fn invalid_pattern_is_a_config_error_naming_the_pattern() {
        let err = AllowlistFilter::from_entries(vec![entry("pattern: 'a('\n")])
            .expect_err("broken regex must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("entry #1"), "{msg}");
        assert!(msg.contains("a("), "error must name the pattern: {msg}");
    }

    #[test]
    fn malformed_sha256_is_a_config_error() {
        let err = AllowlistFilter::from_entries(vec![entry("sha256: deadbeef\n")])
            .expect_err("short digest must be rejected");
        assert!(err.to_string().contains("deadbeef"), "{err}");
    }

    #[test]
    fn empty_list_is_valid_and_suppresses_nothing() {
        let filter = AllowlistFilter::from_entries(Vec::new()).expect("empty allowlist is valid");
        assert!(!filter.is_allowed("AKIAIOSFODNN7EXAMPLE", "aws", "SEC-1", "description"));
        assert!(!AllowlistFilter::empty().is_allowed("x", "r", "SEC-1", "description"));
    }

    #[test]
    fn second_record_reports_its_position() {
        let err =
            AllowlistFilter::from_entries(vec![entry("value: a\n"), entry("pattern: 'a('\n")])
                .expect_err("second record must fail");
        assert!(err.to_string().contains("entry #2"), "{err}");
    }

    // ── matching ──

    #[test]
    fn field_scope_narrows_value_matches() {
        let f = filter("value: SECRETVALUE123456\nfield: description\n");
        assert!(f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "description"));
        assert!(f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "description.text"));
        assert!(!f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "comment.body"));
    }

    #[test]
    fn field_scope_narrows_key_matches_too() {
        let f = filter("rule_id: aws_access_key_id\nfield: comment\n");
        assert!(f.is_allowed("any", "aws_access_key_id", "SEC-1", "comment[2].body"));
        assert!(!f.is_allowed("any", "aws_access_key_id", "SEC-1", "summary"));
    }

    #[test]
    fn entry_without_field_applies_everywhere() {
        let f = filter("value: SECRETVALUE123456\n");
        assert!(f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "summary"));
        assert!(f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "comment[0].body"));
    }

    #[test]
    fn reason_does_not_affect_matching() {
        let f = filter("value: SECRETVALUE123456\nreason: public docs example\n");
        assert!(f.is_allowed("SECRETVALUE123456", "r", "SEC-1", "description"));
        assert!(!f.is_allowed("OTHERVALUE1234567", "r", "SEC-1", "description"));
    }

    #[test]
    fn project_key_is_the_issue_key_prefix() {
        let f = filter("project_key: SEC\n");
        assert!(f.is_allowed("any", "r", "SEC-1", "description"));
        assert!(!f.is_allowed("any", "r", "OPS-1", "description"));
    }
}
