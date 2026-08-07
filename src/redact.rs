/// Redact a secret value, keeping only the first 2 and last 2 characters.
/// For values shorter than 8 characters, returns `[REDACTED]`.
///
/// Example: `ghp_abc123...token` → `gh...en`
/// Example: `abc` → `[REDACTED]`
pub fn redact(value: &str) -> String {
    let len = value.chars().count();
    if len < 8 {
        return "[REDACTED]".to_string();
    }

    let first_two: String = value.chars().take(2).collect();
    let last_two: String = value.chars().rev().take(2).collect::<String>().chars().rev().collect();

    format!("{first_two}...{last_two}")
}

/// Redact a snippet by replacing the matched span with a rule-id marker.
pub fn redact_snippet(snippet: &str, start: usize, end: usize, rule_id: &str) -> String {
    if start > snippet.len() || end > snippet.len() || start > end {
        return snippet.to_string();
    }

    let mut result = String::with_capacity(snippet.len() + 20);
    result.push_str(&snippet[..start]);
    result.push_str(&format!("[REDACTED:{rule_id}]"));
    result.push_str(&snippet[end..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_normal() {
        assert_eq!(redact("ghp_abc123xyz_token"), "gh...en");
    }

    #[test]
    fn test_redact_short() {
        assert_eq!(redact("abc"), "[REDACTED]");
    }

    #[test]
    fn test_redact_exactly_eight() {
        assert_eq!(redact("12345678"), "12...78");
    }

    #[test]
    fn test_redact_unicode() {
        // 10 chars
        assert_eq!(redact("секретныйкод"), "се...од");
    }

    #[test]
    fn test_redact_empty() {
        assert_eq!(redact(""), "[REDACTED]");
    }

    #[test]
    fn test_redact_snippet_basic() {
        let result = redact_snippet("prefix SECRET suffix", 7, 13, "test_rule");
        assert_eq!(result, "prefix [REDACTED:test_rule] suffix");
    }
}
