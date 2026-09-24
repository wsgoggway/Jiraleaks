//! Secret redaction helpers.
//!
//! Snippets travel to every report format, to the findings database and to the
//! webhook alerts, so masking here is unconditional: whatever offsets a caller
//! passes, a snippet returned by this module never carries the secret it
//! describes.

use std::ops::Range;

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
    let last_two: String = value
        .chars()
        .rev()
        .take(2)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    format!("{first_two}...{last_two}")
}

/// Marker that stands in for a masked occurrence of a secret.
///
/// The rule id is part of the marker, so it must not re-introduce the secret:
/// a value that happens to be a substring of its own marker falls back to the
/// generic marker, and to deletion in the degenerate case where even that
/// contains the value.
fn marker_for(rule_id: &str, value: &str) -> String {
    let with_rule = format!("[REDACTED:{rule_id}]");
    if value.is_empty() || !with_rule.contains(value) {
        return with_rule;
    }

    let generic = "[REDACTED]".to_string();
    if !generic.contains(value) {
        return generic;
    }

    String::new()
}

/// Replace every occurrence of `value` in `text` with the rule marker.
fn mask_all(text: &str, value: &str, rule_id: &str) -> String {
    if value.is_empty() {
        return text.to_string();
    }
    text.replace(value, &marker_for(rule_id, value))
}

/// Snap `span` (byte offsets into `snippet`) to char boundaries and to the
/// snippet bounds. Returns `None` when the span lies outside the snippet,
/// is inverted, or collapses to zero width.
///
/// Never panics: offsets that fall inside a multi-byte character are widened
/// to the whole character.
fn clamp_span(snippet: &str, span: &Range<usize>) -> Option<Range<usize>> {
    if span.start > span.end || span.end > snippet.len() {
        return None;
    }
    let start = snippet.floor_char_boundary(span.start);
    let end = snippet.ceil_char_boundary(span.end);
    if start >= end {
        return None;
    }
    Some(start..end)
}

/// Replace `range` with `replacement`; `range` must sit on char boundaries.
fn splice(snippet: &str, range: Range<usize>, replacement: &str) -> String {
    let mut out = String::with_capacity(snippet.len() + replacement.len());
    out.push_str(&snippet[..range.start]);
    out.push_str(replacement);
    out.push_str(&snippet[range.end..]);
    out
}

/// Last line of defence: no known secret may survive in the result.
///
/// Each secret is swept once and its marker cannot contain the secret itself
/// (see `marker_for`), so the sweep always terminates.
fn enforce_absent(mut text: String, secrets: &[(&str, &str)]) -> String {
    for (value, rule_id) in secrets {
        if value.is_empty() || !text.contains(value) {
            continue;
        }
        text = mask_all(&text, value, rule_id);
    }
    text
}

/// Redact a snippet by replacing the matched span with a rule-id marker.
///
/// `span` is the byte range of the match **relative to `snippet`** (as carried
/// by `RawHit::snippet_span`), `value` is the secret itself, `rule_id` names
/// the rule that produced the marker.
///
/// The contract is unconditional: the result never contains `value`.
///  * a usable span is replaced in place, keeping the surrounding context;
///  * a span that is out of bounds, inverted or empty falls back to masking
///    every occurrence of `value`;
///  * a final sweep removes any occurrence the span did not cover.
pub fn redact_snippet(snippet: &str, value: &str, span: Range<usize>, rule_id: &str) -> String {
    let masked = match clamp_span(snippet, &span) {
        Some(range) => splice(snippet, range, &marker_for(rule_id, value)),
        None => snippet.to_string(),
    };
    enforce_absent(masked, &[(value, rule_id)])
}

/// Mask `primary` in `snippet` and, on top of it, every other secret known to
/// occur in the same snippet.
///
/// A ±50 byte context window can capture the secrets of neighbouring findings,
/// so every finding of the segment contributes its value to `others` as a
/// `(value, rule_id)` pair. Offsets stay the caller's business only for the
/// primary match: the other values are masked by literal search, so no offset
/// arithmetic is needed for them.
///
/// The result never contains any of the given values.
pub fn redact_snippet_with(
    snippet: &str,
    primary: (&str, Range<usize>, &str),
    others: &[(&str, &str)],
) -> String {
    let (value, span, rule_id) = primary;

    let mut text = match clamp_span(snippet, &span) {
        Some(range) => splice(snippet, range, &marker_for(rule_id, value)),
        None => snippet.to_string(),
    };

    for (other_value, other_rule) in others {
        if other_value.is_empty() || *other_value == value {
            continue;
        }
        text = text.replace(other_value, &marker_for(other_rule, other_value));
    }

    let mut known: Vec<(&str, &str)> = Vec::with_capacity(others.len() + 1);
    known.push((value, rule_id));
    known.extend(others.iter().copied());

    enforce_absent(text, &known)
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
        let result = redact_snippet("prefix SECRET suffix", "SECRET", 7..13, "test_rule");
        assert_eq!(result, "prefix [REDACTED:test_rule] suffix");
    }

    #[test]
    fn test_redact_snippet_mask_every_occurrence() {
        // The value appears twice: the span covers the first occurrence only,
        // the sweep must remove the second one as well.
        let snippet = "token=a b token=a";
        let result = redact_snippet(snippet, "token=a", 0..7, "generic");
        assert!(!result.contains("token=a"), "value survived: {result}");
        assert_eq!(result, "[REDACTED:generic] b [REDACTED:generic]");
    }

    #[test]
    fn test_redact_snippet_out_of_bounds_span_masks_all() {
        // A stale/incorrect span must not fall back to returning the input.
        let snippet = "prefix SECRET suffix";
        let result = redact_snippet(snippet, "SECRET", 900..1000, "test_rule");
        assert!(!result.contains("SECRET"), "value survived: {result}");
        assert_eq!(result, "prefix [REDACTED:test_rule] suffix");
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)] // the inverted span is the point
    fn test_redact_snippet_inverted_span_masks_all() {
        let result = redact_snippet("prefix SECRET suffix", "SECRET", 13..7, "test_rule");
        assert!(!result.contains("SECRET"), "value survived: {result}");
    }

    #[test]
    fn test_redact_snippet_empty_span_masks_all() {
        let result = redact_snippet("prefix SECRET suffix", "SECRET", 7..7, "test_rule");
        assert!(!result.contains("SECRET"), "value survived: {result}");
    }

    #[test]
    fn test_redact_snippet_span_inside_multibyte_char_does_not_panic() {
        // Offsets that land inside a Cyrillic character are widened, not sliced.
        let snippet = "ключ секрет значение";
        let result = redact_snippet(snippet, "секрет", 3..11, "test_rule");
        assert!(!result.contains("секрет"), "value survived: {result}");
    }

    #[test]
    fn test_redact_snippet_keeps_context() {
        let result = redact_snippet("left context SECRET right context", "SECRET", 13..19, "jwt");
        assert_eq!(result, "left context [REDACTED:jwt] right context");
    }

    #[test]
    fn test_redact_snippet_empty_value_is_noop() {
        assert_eq!(
            redact_snippet("nothing here", "", 0..0, "x"),
            "nothing here"
        );
    }

    #[test]
    fn test_redact_snippet_with_masks_neighbour_secrets() {
        let snippet = "jwt eyJhbGci.eyJzdWIi.SflKxw and Bearer abcdefghijklmnopqrstuvwx";
        let result = redact_snippet_with(
            snippet,
            ("eyJhbGci.eyJzdWIi.SflKxw", 4..28, "jwt"),
            &[("abcdefghijklmnopqrstuvwx", "bearer_token_generic")],
        );
        assert!(!result.contains("eyJhbGci.eyJzdWIi.SflKxw"));
        assert!(!result.contains("abcdefghijklmnopqrstuvwx"));
        assert!(result.contains("[REDACTED:jwt]"));
        assert!(result.contains("[REDACTED:bearer_token_generic]"));
    }

    #[test]
    fn test_redact_snippet_with_invalid_primary_span_still_masks() {
        let snippet = "а Bearer abcdefghijklmnopqrstuvwx";
        let result = redact_snippet_with(
            snippet,
            (
                "abcdefghijklmnopqrstuvwx",
                999..1000,
                "bearer_token_generic",
            ),
            &[],
        );
        assert!(!result.contains("abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn test_marker_for_never_embeds_the_value() {
        // A value that is a substring of the marker itself must not survive.
        let snippet = "value=REDACTED";
        let result = redact_snippet(snippet, "REDACTED", 0..0, "generic");
        assert!(!result.contains("REDACTED"), "value survived: {result}");
    }
}
