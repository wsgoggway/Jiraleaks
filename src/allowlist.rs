use std::collections::HashSet;

use fancy_regex::Regex;
use serde::Deserialize;

use crate::hash::secret_hash;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AllowlistEntry {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub project_key: Option<String>,
    #[serde(default)]
    pub issue_key: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Pre-compiled allowlist for fast matching.
#[derive(Debug, Clone)]
pub struct AllowlistFilter {
    values: HashSet<String>,
    hashes: HashSet<String>,
    patterns: Vec<(Regex, String)>,
    project_keys: HashSet<String>,
    issue_keys: HashSet<String>,
    rule_ids: HashSet<String>,
}

impl AllowlistFilter {
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::error::ScannerError> {
        let yaml = std::fs::read_to_string(path).map_err(|e| {
            crate::error::ScannerError::Config(format!(
                "Failed to read allowlist file {}: {e}",
                path.display()
            ))
        })?;
        let entries: Vec<AllowlistEntry> = serde_yaml::from_str(&yaml).map_err(|e| {
            crate::error::ScannerError::Config(format!("Failed to parse allowlist YAML: {e}"))
        })?;
        Ok(Self::from_entries(entries))
    }

    pub fn from_entries(entries: Vec<AllowlistEntry>) -> Self {
        let mut values = HashSet::new();
        let mut hashes = HashSet::new();
        let mut patterns = Vec::new();
        let mut project_keys = HashSet::new();
        let mut issue_keys = HashSet::new();
        let mut rule_ids = HashSet::new();

        for entry in entries {
            if let Some(v) = entry.value {
                values.insert(v);
            }
            if let Some(h) = entry.sha256 {
                hashes.insert(h);
            }
            if let Some(p) = entry.pattern {
                match Regex::new(&p) {
                    Ok(re) => patterns.push((re, p)),
                    Err(e) => {
                        tracing::warn!(
                            pattern = %p,
                            error = %e,
                            "Invalid allowlist regex pattern, skipping"
                        );
                    }
                }
            }
            if let Some(pk) = entry.project_key {
                project_keys.insert(pk);
            }
            if let Some(ik) = entry.issue_key {
                issue_keys.insert(ik);
            }
            if let Some(ri) = entry.rule_id {
                rule_ids.insert(ri);
            }
        }

        Self {
            values,
            hashes,
            patterns,
            project_keys,
            issue_keys,
            rule_ids,
        }
    }

    pub fn empty() -> Self {
        Self {
            values: HashSet::new(),
            hashes: HashSet::new(),
            patterns: Vec::new(),
            project_keys: HashSet::new(),
            issue_keys: HashSet::new(),
            rule_ids: HashSet::new(),
        }
    }

    pub fn is_allowed(
        &self,
        secret_value: &str,
        rule_id: &str,
        issue_key: &str,
        _field_path: &str,
    ) -> bool {
        if self.values.contains(secret_value) {
            return true;
        }

        let hash = secret_hash(secret_value);
        if self.hashes.contains(&hash) {
            return true;
        }

        for (re, _) in &self.patterns {
            if re.is_match(secret_value).unwrap_or(false) {
                return true;
            }
        }

        if self.rule_ids.contains(rule_id) {
            return true;
        }

        if let Some(proj) = issue_key.split('-').next() {
            if self.project_keys.contains(proj) {
                return true;
            }
        }

        if self.issue_keys.contains(issue_key) {
            return true;
        }

        false
    }
}
