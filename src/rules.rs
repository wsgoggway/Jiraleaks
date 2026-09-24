use std::collections::HashMap;
use std::ops::Range;

use fancy_regex::Regex;
use serde::Deserialize;

use crate::entropy;
use crate::redact;
use crate::validators;

/// Placeholder markers filtered out by default for every rule unless
/// `disable_default_placeholders` is set. Mirrors kingfisher's default
/// placeholder handling to cut false positives on documentation examples.
/// NOTE: no bare digit runs here — "contains" semantics would reject any
/// real token embedding them (e.g. `1234567890:` telegram ids, `123456789012`
/// slack workspaces).
const DEFAULT_PLACEHOLDERS: &[&str] = &[
    "example",
    "test",
    "sample",
    "demo",
    "dummy",
    "placeholder",
    "changeme",
    "your_key",
    "yourkey",
    "your-key",
    "xxxx",
    "foobar",
    "redacted",
    "fake",
];

fn default_special_chars() -> String {
    "!@#$%^&*()_+-=[]{}|;:,.<>?/".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub rule_id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    pub regex: String,
    #[serde(default)]
    pub capture_group: Option<usize>,
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub min_entropy: Option<f64>,
    #[serde(default)]
    pub context_keywords: Vec<String>,
    #[serde(default)]
    pub denylist: Vec<String>,
    #[serde(default)]
    pub validator: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Substrings whose presence in a match discards it (case-insensitive).
    /// Semantics follow kingfisher `pattern_requirements.ignore_if_contains`.
    #[serde(default)]
    pub ignore_if_contains: Vec<String>,
    /// Character-class requirements (kingfisher `pattern_requirements`).
    #[serde(default)]
    pub min_digits: Option<usize>,
    #[serde(default)]
    pub min_uppercase: Option<usize>,
    #[serde(default)]
    pub min_lowercase: Option<usize>,
    #[serde(default)]
    pub min_special_chars: Option<usize>,
    #[serde(default = "default_special_chars")]
    pub special_chars: String,
    /// Disable the global default placeholder list for this rule.
    #[serde(default)]
    pub disable_default_placeholders: bool,
    /// Sample values that the rule regex must match (tests + docs).
    #[serde(default)]
    pub examples: Vec<String>,
    /// Reference URLs for the rule (surfaced in reports).
    #[serde(default)]
    pub references: Vec<String>,
}

fn default_severity() -> String {
    "medium".into()
}
fn default_confidence() -> String {
    "medium".into()
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule_id: String,
    pub description: String,
    pub severity: String,
    pub confidence: String,
    pub regex: Regex,
    pub capture_group: usize,
    pub min_length: Option<usize>,
    pub min_entropy: Option<f64>,
    pub context_keywords: Vec<String>,
    pub denylist: Vec<String>,
    pub validator: Option<String>,
    pub enabled: bool,
    /// Effective ignore_if_contains: global default placeholders merged with
    /// the rule's own list.
    pub ignore_if_contains: Vec<String>,
    pub min_digits: Option<usize>,
    pub min_uppercase: Option<usize>,
    pub min_lowercase: Option<usize>,
    pub min_special_chars: Option<usize>,
    pub special_chars: Vec<char>,
    pub examples: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Clone)]
pub struct RawHit {
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    /// The secret itself: the capture group when the rule declares one,
    /// otherwise the whole regex match.
    pub matched_value: String,
    /// Byte range of `matched_value` in the scanned segment (absolute offsets).
    pub match_span: Range<usize>,
    /// Byte range of `matched_value` **relative to `snippet`**; the snippet is
    /// built around the match, so `snippet[snippet_span] == matched_value`.
    /// Computed here, where both offset systems are known, so that no caller
    /// has to do offset arithmetic.
    pub snippet_span: Range<usize>,
    pub snippet: String,
    pub field_path: String,
    pub references: Vec<String>,
}

/// Hand-written: `matched_value` and `snippet` hold raw secrets, so `{:?}` must
/// never print them (same reasoning as the masking `Debug` of `Config`).
impl std::fmt::Debug for RawHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawHit")
            .field("rule_id", &self.rule_id)
            .field("severity", &self.severity)
            .field("confidence", &self.confidence)
            .field("matched_value", &redact::redact(&self.matched_value))
            .field("match_span", &self.match_span)
            .field("snippet_span", &self.snippet_span)
            .field(
                "snippet",
                &redact::redact_snippet(
                    &self.snippet,
                    &self.matched_value,
                    self.snippet_span.clone(),
                    &self.rule_id,
                ),
            )
            .field("field_path", &self.field_path)
            .field("references", &self.references)
            .finish()
    }
}

impl RawHit {
    /// The snippet with every known secret masked.
    ///
    /// `siblings` is the full hit list of the scanned segment (this hit
    /// included): a ±50 byte snippet window can capture the secrets of
    /// neighbouring findings, and all of them have to be masked before the
    /// snippet reaches a report, the findings store or a webhook alert.
    /// Offset arithmetic stays inside this module — callers pass the hits as
    /// they got them from `RulesEngine::scan`.
    pub fn redacted_snippet(&self, siblings: &[RawHit]) -> String {
        let others: Vec<(&str, &str)> = siblings
            .iter()
            .map(|other| (other.matched_value.as_str(), other.rule_id.as_str()))
            .collect();

        redact::redact_snippet_with(
            &self.snippet,
            (
                self.matched_value.as_str(),
                self.snippet_span.clone(),
                self.rule_id.as_str(),
            ),
            &others,
        )
    }
}

/// Rules engine: loads, merges, and applies detection rules.
#[derive(Debug, Clone)]
pub struct RulesEngine {
    rules: Vec<CompiledRule>,
}

impl CompiledRule {
    /// Compile a single rule from its YAML/JSON representation.
    ///
    /// Split out of `RulesEngine` so that rules can be built in memory (tests,
    /// embedded corpora) without touching the filesystem.
    pub fn compile(rule: Rule) -> Result<Self, crate::error::ScannerError> {
        let regex = Regex::new(&rule.regex).map_err(|e| {
            crate::error::ScannerError::Config(format!(
                "Failed to compile regex for rule '{}': {e}",
                rule.rule_id
            ))
        })?;

        let mut eff_ignore: Vec<String> = if rule.disable_default_placeholders {
            Vec::new()
        } else {
            DEFAULT_PLACEHOLDERS.iter().map(|s| s.to_string()).collect()
        };
        eff_ignore.extend(rule.ignore_if_contains.iter().cloned());

        Ok(CompiledRule {
            rule_id: rule.rule_id.clone(),
            description: rule.description.clone(),
            severity: rule.severity.clone(),
            confidence: rule.confidence.clone(),
            regex,
            capture_group: rule.capture_group.unwrap_or(0),
            min_length: rule.min_length,
            min_entropy: rule.min_entropy,
            context_keywords: rule.context_keywords.clone(),
            denylist: rule.denylist.clone(),
            validator: rule.validator.clone(),
            enabled: rule.enabled,
            ignore_if_contains: eff_ignore,
            min_digits: rule.min_digits,
            min_uppercase: rule.min_uppercase,
            min_lowercase: rule.min_lowercase,
            min_special_chars: rule.min_special_chars,
            special_chars: rule.special_chars.chars().collect(),
            examples: rule.examples.clone(),
            references: rule.references.clone(),
        })
    }
}

impl RulesEngine {
    /// Build an engine from an explicit rule list (disabled rules are skipped).
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, crate::error::ScannerError> {
        let mut compiled = Vec::new();
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            compiled.push(CompiledRule::compile(rule)?);
        }
        Ok(Self { rules: compiled })
    }

    /// Load the builtin corpus, overridden by the user rules file when given.
    pub fn new(rules_path: Option<&std::path::Path>) -> Result<Self, crate::error::ScannerError> {
        let builtin_yaml = crate::detectors::builtin::BUILTIN_RULES_YAML;
        let builtin_rules: Vec<Rule> = serde_yaml::from_str(builtin_yaml).map_err(|e| {
            crate::error::ScannerError::Config(format!("Failed to parse builtin rules: {e}"))
        })?;

        let mut rules_map: HashMap<String, Rule> = HashMap::new();
        for rule in builtin_rules {
            rules_map.insert(rule.rule_id.clone(), rule);
        }

        if let Some(path) = rules_path {
            let user_yaml = std::fs::read_to_string(path).map_err(|e| {
                crate::error::ScannerError::Config(format!(
                    "Failed to read rules file {}: {e}",
                    path.display()
                ))
            })?;
            let user_rules: Vec<Rule> = serde_yaml::from_str(&user_yaml).map_err(|e| {
                crate::error::ScannerError::Config(format!("Failed to parse user rules: {e}"))
            })?;
            for rule in user_rules {
                rules_map.insert(rule.rule_id.clone(), rule);
            }
        }

        Self::from_rules(rules_map.into_values().collect())
    }

    pub fn scan(&self, text: &str, field_path: &str) -> Vec<RawHit> {
        let mut hits = Vec::new();

        for rule in &self.rules {
            let mut cursor = 0;
            while cursor < text.len() {
                let search_text = &text[cursor..];
                match rule.regex.find(search_text) {
                    Ok(Some(m)) => {
                        let match_start = cursor + m.start();
                        let match_end = cursor + m.end();

                        // A zero-width match (`a*`, `\b`, ...) consumes nothing,
                        // so the cursor would never advance: skip it and move on
                        // by one character to keep the scan finite.
                        if match_end <= cursor {
                            cursor = text.ceil_char_boundary(cursor + 1);
                            continue;
                        }

                        // The reported value is the capture group when the rule
                        // declares one; its span — not the whole regex match — is
                        // what gets masked and what the context filters inspect.
                        let (value_start, value_end, matched_value) = if rule.capture_group > 0 {
                            let caps = rule.regex.captures(search_text).ok().flatten();
                            let group = caps.as_ref().and_then(|c| c.get(rule.capture_group));
                            match group {
                                Some(g) => {
                                    (cursor + g.start(), cursor + g.end(), g.as_str().to_string())
                                }
                                None => (match_start, match_end, m.as_str().to_string()),
                            }
                        } else {
                            (match_start, match_end, m.as_str().to_string())
                        };

                        if !self.passes_filters(rule, &matched_value, text, value_start..value_end)
                        {
                            cursor = match_end;
                            continue;
                        }

                        let snippet_start =
                            text.floor_char_boundary(value_start.saturating_sub(50));
                        let snippet_end = text.ceil_char_boundary((value_end + 50).min(text.len()));

                        let snippet = text[snippet_start..snippet_end].to_string();
                        let snippet_span =
                            (value_start - snippet_start)..(value_end - snippet_start);
                        hits.push(RawHit {
                            rule_id: rule.rule_id.clone(),
                            severity: rule.severity.clone(),
                            confidence: rule.confidence.clone(),
                            matched_value,
                            match_span: match_start..match_end,
                            snippet_span,
                            snippet,
                            field_path: field_path.to_string(),
                            references: rule.references.clone(),
                        });

                        cursor = match_end;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(
                            rule_id = %rule.rule_id,
                            error = %e,
                            "Regex error during scan, skipping rule for this text"
                        );
                        break;
                    }
                }
            }
        }

        hits
    }

    fn passes_filters(
        &self,
        rule: &CompiledRule,
        value: &str,
        text: &str,
        value_span: Range<usize>,
    ) -> bool {
        if let Some(min_len) = rule.min_length {
            if value.chars().count() < min_len {
                return false;
            }
        }

        if let Some(min_ent) = rule.min_entropy {
            if entropy::shannon(value) < min_ent {
                return false;
            }
        }

        if !rule.denylist.is_empty() {
            let lower = value.to_lowercase();
            if rule
                .denylist
                .iter()
                .any(|d| lower.contains(&d.to_lowercase()))
            {
                return false;
            }
        }

        // Placeholder / ignore_if_contains (effective list incl. global default)
        if !rule.ignore_if_contains.is_empty() {
            let lower = value.to_lowercase();
            if rule
                .ignore_if_contains
                .iter()
                .any(|d| lower.contains(&d.to_lowercase()))
            {
                return false;
            }
        }

        // Character-class requirements (kingfisher pattern_requirements)
        let mut digits = 0usize;
        let mut upper = 0usize;
        let mut lower_cnt = 0usize;
        let mut special = 0usize;
        for c in value.chars() {
            if c.is_ascii_digit() {
                digits += 1;
            } else if c.is_ascii_uppercase() {
                upper += 1;
            } else if c.is_ascii_lowercase() {
                lower_cnt += 1;
            } else if rule.special_chars.contains(&c) {
                special += 1;
            }
        }
        if let Some(n) = rule.min_digits {
            if digits < n {
                return false;
            }
        }
        if let Some(n) = rule.min_uppercase {
            if upper < n {
                return false;
            }
        }
        if let Some(n) = rule.min_lowercase {
            if lower_cnt < n {
                return false;
            }
        }
        if let Some(n) = rule.min_special_chars {
            if special < n {
                return false;
            }
        }

        if !rule.context_keywords.is_empty() {
            let win_start = text.floor_char_boundary(value_span.start.saturating_sub(50));
            let win_end = text.ceil_char_boundary((value_span.end + 50).min(text.len()));
            let window = &text[win_start..win_end].to_lowercase();

            let found = rule
                .context_keywords
                .iter()
                .any(|kw| window.contains(&kw.to_lowercase()));

            if !found {
                return false;
            }
        }

        if let Some(ref validator) = rule.validator {
            if !validators::validate(validator, value) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_default_rejects_example_values() {
        let engine = RulesEngine::new(None).expect("builtin rules load");
        // AWS example key from AWS docs: contains "EXAMPLE" -> global default
        assert!(engine
            .scan("aws_access_key_id = ASIAOZW6VBVAZFJHJLQAE", "description")
            .is_empty());
        // GitHub-style token containing "test"
        assert!(engine
            .scan(
                "token = ghp_testtesttesttesttesttesttesttesttestt",
                "description"
            )
            .is_empty());
        // A non-placeholder key is still detected
        let hits = engine.scan("aws_access_key_id = ASIAOZW6VBVAZFJHJLQA", "description");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn min_digits_requirements_filter_values() {
        let engine = RulesEngine::new(None).expect("builtin rules load");
        let rule = engine
            .rules
            .iter()
            .find(|r| r.rule_id == "aws_secret_access_key")
            .expect("aws_secret_access_key compiled");

        let value_with_digits = "Abc123Xyz9+abcAbc123Xyz9+abcAbc123Xyz9+abc";
        let text = format!("aws_secret_access_key = {value_with_digits}");
        assert!(
            engine.passes_filters(rule, value_with_digits, &text, 0..value_with_digits.len()),
            "value with >=3 digits passes min_digits: 3"
        );

        let value_no_digits = "AbcdefghijAbcdefghijAbcdefghijAbcdefghij";
        let text = format!("aws_secret_access_key = {value_no_digits}");
        assert!(
            !engine.passes_filters(rule, value_no_digits, &text, 0..value_no_digits.len()),
            "value without digits is rejected by min_digits: 3"
        );
    }

    #[test]
    fn builtin_examples_match_their_regex() {
        let engine = RulesEngine::new(None).expect("builtin rules load");
        let mut checked = 0usize;
        for rule in &engine.rules {
            for example in &rule.examples {
                checked += 1;
                let m = rule
                    .regex
                    .find(example)
                    .expect("example matches rule regex");
                assert!(
                    m.is_some(),
                    "rule {} example {:?} does not match its regex",
                    rule.rule_id,
                    example
                );
            }
        }
        assert!(
            checked >= 10,
            "expected at least 10 examples, got {checked}"
        );
    }

    #[test]
    fn raw_hit_carries_references() {
        let engine = RulesEngine::new(None).expect("builtin rules load");
        let hits = engine.scan(
            "github token: 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",
            "description",
        );
        let hit = hits
            .iter()
            .find(|h| h.rule_id == "github_token")
            .expect("github_token hit present");
        assert!(!hit.references.is_empty());
        assert!(hit.references[0].starts_with("https://"));
    }

    fn yaml_rule(yaml: &str) -> Rule {
        serde_yaml::from_str(yaml).expect("valid rule yaml")
    }

    #[test]
    fn snippet_span_is_relative_to_snippet() {
        let engine = RulesEngine::new(None).expect("builtin rules load");
        let text = "x".repeat(1000) + " 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";
        let hits = engine.scan(&text, "description");
        let hit = hits
            .iter()
            .find(|h| h.rule_id == "github_token")
            .expect("github_token hit present");

        // The snippet is a window around the match, not the whole segment.
        assert!(hit.snippet.len() < text.len());
        assert_eq!(
            &hit.snippet[hit.snippet_span.clone()],
            hit.matched_value.as_str(),
            "snippet[snippet_span] must be the matched value"
        );
        assert_eq!(&text[hit.match_span.clone()], hit.matched_value.as_str());
        assert_ne!(
            hit.match_span, hit.snippet_span,
            "absolute and snippet-relative offsets must not be conflated"
        );
    }

    #[test]
    fn capture_group_span_points_at_the_group() {
        let rule = yaml_rule(
            r#"
rule_id: capture_test
regex: 'token=(\S+)'
capture_group: 1
disable_default_placeholders: true
"#,
        );
        let engine = RulesEngine::from_rules(vec![rule]).expect("engine builds");
        let text = "auth token=SECRETVALUE-1234567890 end";
        let hits = engine.scan(text, "description");
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.matched_value, "SECRETVALUE-1234567890");
        assert_eq!(
            &text[hit.match_span.clone()],
            "token=SECRETVALUE-1234567890"
        );
        assert_eq!(&hit.snippet[hit.snippet_span.clone()], hit.matched_value);
    }

    #[test]
    fn zero_width_rule_terminates_and_is_skipped() {
        let rule = yaml_rule(
            r#"
rule_id: zero_width
regex: 'a*'
disable_default_placeholders: true
"#,
        );
        let engine = RulesEngine::from_rules(vec![rule]).expect("engine builds");
        let hits = engine.scan("bbbbbbbbbb", "description");
        assert!(hits.is_empty(), "empty matches must not become hits");
    }

    #[test]
    fn debug_never_prints_the_raw_secret() {
        let engine = RulesEngine::new(None).expect("builtin rules load");
        let secret = "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";
        let hits = engine.scan(&format!("github token: {secret}"), "description");
        let hit = hits
            .iter()
            .find(|h| h.rule_id == "github_token")
            .expect("github_token hit present");
        let dbg = format!("{hit:?}");
        assert!(!dbg.contains(secret), "raw secret leaked into Debug: {dbg}");
        assert!(dbg.contains("gh...38"));
    }
}
