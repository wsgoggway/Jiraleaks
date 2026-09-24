//! Snippet redaction tests: a snippet that reaches a report, the findings
//! store or a webhook alert must never carry a raw secret.
//!
//! Regression suite for the critical leak found on a production report, where
//! the pipeline computed the match offset inside the snippet with a formula
//! that overflowed `snippet.len()` and made `redact_snippet` silently return
//! the snippet untouched (19 findings, only 12 of them masked).

use std::time::{Duration, Instant};

use jiraleaks::extract::TextExtractor;
use jiraleaks::redact;
use jiraleaks::rules::{Rule, RulesEngine};

/// A GitHub-token-shaped secret that survives the placeholder filters.
const GITHUB_SECRET: &str = "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";
const GITHUB_SECRET_ALT: &str = "ghp_zQ7wR8tY2uP4aS6dF8gH1jK3lM5nB7vC9xZ2";

fn builtin_engine() -> RulesEngine {
    RulesEngine::new(None).expect("builtin rules load")
}

fn yaml_rule(yaml: &str) -> Rule {
    serde_yaml::from_str(yaml).expect("valid rule yaml")
}

/// Redact every snippet of a scan, in the same order as the hits.
/// This is the exact composition the pipeline uses.
fn redacted_snippets(hits: &[jiraleaks::rules::RawHit]) -> Vec<String> {
    hits.iter().map(|hit| hit.redacted_snippet(hits)).collect()
}

// ── 1. the main case: a match deep inside a long segment ────────────────────

#[test]
fn deep_match_offset_does_not_leak_the_secret() {
    let text = format!("{} {GITHUB_SECRET}", "x".repeat(1100));
    let engine = builtin_engine();
    let hits = engine.scan(&text, "description");

    let hit = hits
        .iter()
        .find(|h| h.rule_id == "github_token")
        .expect("github_token detected");
    assert!(
        hit.match_span.start > 1000,
        "match must sit deep in the text"
    );

    // Historic bug: `start - (snippet.len() - snippet.find(value))` exceeds the
    // snippet length here, and the old redactor returned the snippet as is.
    let old_start = hit.match_span.start
        - (hit.snippet.len() - hit.snippet.find(&hit.matched_value).unwrap_or(0));
    assert!(
        old_start > hit.snippet.len(),
        "the broken formula must be reproduced by this fixture"
    );

    let redacted = hit.redacted_snippet(&hits);
    assert!(
        !redacted.contains(hit.matched_value.as_str()),
        "raw secret survived in the snippet: {redacted}"
    );
    assert!(redacted.contains("[REDACTED:github_token]"), "{redacted}");
    // Context is preserved around the marker.
    assert!(redacted.contains("xxx"), "context lost: {redacted}");
}

// ── 2. match at the start, in the middle and at the end of the segment ──────

#[test]
fn match_at_the_start_is_masked() {
    let text = format!("{GITHUB_SECRET} tail context");
    let engine = builtin_engine();
    let hits = engine.scan(&text, "description");
    let hit = hits
        .iter()
        .find(|h| h.rule_id == "github_token")
        .expect("github_token detected");
    assert_eq!(hit.match_span.start, 0, "match must sit at the very start");

    let redacted = hit.redacted_snippet(&hits);
    assert!(!redacted.contains(hit.matched_value.as_str()), "{redacted}");
    assert!(redacted.contains("tail context"), "{redacted}");
}

#[test]
fn match_in_the_middle_is_masked() {
    let text = format!("{} {GITHUB_SECRET} {}", "a".repeat(60), "b".repeat(60));
    let engine = builtin_engine();
    let hits = engine.scan(&text, "description");
    let hit = hits
        .iter()
        .find(|h| h.rule_id == "github_token")
        .expect("github_token detected");

    let redacted = hit.redacted_snippet(&hits);
    assert!(!redacted.contains(hit.matched_value.as_str()), "{redacted}");
    assert!(
        redacted.contains("aaa") && redacted.contains("bbb"),
        "{redacted}"
    );
}

#[test]
fn match_at_the_end_is_masked() {
    let text = format!("{} {GITHUB_SECRET}", "c".repeat(80));
    let engine = builtin_engine();
    let hits = engine.scan(&text, "description");
    let hit = hits
        .iter()
        .find(|h| h.rule_id == "github_token")
        .expect("github_token detected");
    assert_eq!(hit.match_span.end, text.len(), "match must end the segment");

    let redacted = hit.redacted_snippet(&hits);
    assert!(!redacted.contains(hit.matched_value.as_str()), "{redacted}");
    assert!(redacted.contains("ccc"), "{redacted}");
}

// ── 3. capture-group rules ──────────────────────────────────────────────────

#[test]
fn capture_group_value_is_masked() {
    let engine = RulesEngine::from_rules(vec![yaml_rule(
        r#"
rule_id: capture_test
regex: 'password\s*=\s*(\S+)'
capture_group: 1
disable_default_placeholders: true
"#,
    )])
    .expect("engine builds");

    let text = format!(
        "{} password = S3cr3t-V4lue-42 {}",
        "p".repeat(70),
        "q".repeat(70)
    );
    let hits = engine.scan(&text, "description");
    assert_eq!(hits.len(), 1);
    let hit = &hits[0];

    // The reported value is the capture group, not the whole regex match.
    assert_eq!(hit.matched_value, "S3cr3t-V4lue-42");
    assert!(
        hit.match_span.start > 70,
        "the group is not at the segment start"
    );
    assert_eq!(
        &text[hit.match_span.clone()],
        "password = S3cr3t-V4lue-42",
        "match_span covers the whole match"
    );
    assert_eq!(
        &hit.snippet[hit.snippet_span.clone()],
        hit.matched_value,
        "snippet_span points at the value inside the snippet"
    );

    let redacted = hit.redacted_snippet(&hits);
    assert!(!redacted.contains("S3cr3t-V4lue-42"), "{redacted}");
    assert!(redacted.contains("[REDACTED:capture_test]"), "{redacted}");
}

// ── 4. non-ASCII text ───────────────────────────────────────────────────────

#[test]
fn cyrillic_and_emoji_snippets_are_masked_without_panicking() {
    let engine = builtin_engine();

    let cyrillic = format!("пароль от сервиса: {GITHUB_SECRET} — не публиковать");
    let hits = engine.scan(&cyrillic, "description");
    let hit = hits
        .iter()
        .find(|h| h.rule_id == "github_token")
        .expect("github_token detected");
    let redacted = hit.redacted_snippet(&hits);
    assert!(!redacted.contains(hit.matched_value.as_str()), "{redacted}");
    assert!(redacted.contains("пароль"), "context lost: {redacted}");

    let emoji = format!("🔥🔥🔥 {GITHUB_SECRET} ✅");
    let hits = engine.scan(&emoji, "description");
    let hit = hits
        .iter()
        .find(|h| h.rule_id == "github_token")
        .expect("github_token detected");
    let redacted = hit.redacted_snippet(&hits);
    assert!(!redacted.contains(hit.matched_value.as_str()), "{redacted}");
    assert!(redacted.contains("🔥"), "context lost: {redacted}");

    // Snippets built around non-ASCII context stay on char boundaries.
    for h in &hits {
        assert!(
            h.snippet.is_char_boundary(h.snippet_span.start)
                && h.snippet.is_char_boundary(h.snippet_span.end)
        );
    }
}

// ── 5. two secrets inside one ±50 byte window ───────────────────────────────

#[test]
fn neighbouring_secrets_in_the_same_window_are_both_masked() {
    let engine = builtin_engine();
    let text = format!("first={GITHUB_SECRET} second={GITHUB_SECRET_ALT}");
    let hits = engine.scan(&text, "description");
    let first = hits
        .iter()
        .find(|h| h.matched_value == GITHUB_SECRET)
        .expect("first secret detected");
    let second = hits
        .iter()
        .find(|h| h.matched_value == GITHUB_SECRET_ALT)
        .expect("second secret detected");
    assert!(
        second.match_span.start < first.match_span.end + 50,
        "fixture must place both secrets inside one snippet window"
    );

    let redacted = redacted_snippets(&hits);
    for snippet in &redacted {
        assert!(!snippet.contains(GITHUB_SECRET), "leak: {snippet}");
        assert!(!snippet.contains(GITHUB_SECRET_ALT), "leak: {snippet}");
    }
    // The first snippet sees the second secret and masks it.
    let first_snippet = first.redacted_snippet(&hits);
    assert!(
        first_snippet.contains("[REDACTED:github_token]"),
        "{first_snippet}"
    );
}

// ── 6. the same value twice in one segment ──────────────────────────────────

#[test]
fn duplicated_value_leaves_no_occurrence_in_the_snippet() {
    let engine = builtin_engine();
    let text = format!("{GITHUB_SECRET} {GITHUB_SECRET}");
    let hits = engine.scan(&text, "description");
    let token_hits: Vec<_> = hits
        .iter()
        .filter(|h| h.rule_id == "github_token")
        .collect();
    assert!(
        token_hits.len() >= 2,
        "fixture must yield two hits, got {}",
        token_hits.len()
    );

    for hit in &token_hits {
        let redacted = hit.redacted_snippet(&hits);
        assert!(
            !redacted.contains(hit.matched_value.as_str()),
            "second occurrence survived: {redacted}"
        );
    }
}

// ── 7. extract: truncation on a character boundary ──────────────────────────

#[test]
fn extract_truncates_multibyte_text_without_panicking() {
    let extractor = TextExtractor::new(1); // 1 KiB limit

    let cyrillic = "я".repeat(1000); // 2000 bytes, 2 bytes per char
    let fields = serde_json::json!({"description": cyrillic});
    let segments = extractor.extract("T-1", &fields);
    assert!(segments[0].text.len() <= 1024);
    assert!(segments[0].text.chars().all(|c| c == 'я'));

    let emoji = "🔥".repeat(500); // 2000 bytes, 4 bytes per emoji
    let fields = serde_json::json!({"description": emoji});
    let segments = extractor.extract("T-1", &fields);
    assert!(segments[0].text.len() <= 1024);
    assert!(segments[0].text.chars().all(|c| c == '🔥'));
}

// ── 8. invariant over a corpus ──────────────────────────────────────────────

#[test]
fn no_scan_result_leaks_its_value_in_the_snippet() {
    let engine = builtin_engine();
    let corpus = [
        format!("{} {GITHUB_SECRET}", "x".repeat(1200)),
        GITHUB_SECRET.to_string(),
        format!("token: {GITHUB_SECRET} and again {GITHUB_SECRET_ALT}"),
        format!("key=ABC123xyz {} auth Bearer {}", "y".repeat(300), "z".repeat(400)),
        "aws_access_key_id = ASIAOZW6VBVAZFJHJLQA\naws_secret_access_key = 3lyTWqHMt5UySny2drdPYheRTEzrNux8Cn5JWFHL".to_string(),
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string(),
        "пароль: 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 и рядом ghp_zQ7wR8tY2uP4aS6dF8gH1jK3lM5nB7vC9xZ2 🔥".to_string(),
        "multi\nline\nsecret\n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\nend".to_string(),
        "short".to_string(),
    ];

    let mut checked = 0usize;
    for text in &corpus {
        let hits = engine.scan(text, "description");
        let redacted = redacted_snippets(&hits);
        assert_eq!(redacted.len(), hits.len());
        for (hit, snippet) in hits.iter().zip(redacted.iter()) {
            checked += 1;
            assert!(
                !snippet.contains(hit.matched_value.as_str()),
                "rule {} leaked its value in the snippet: {snippet}",
                hit.rule_id
            );
            // Nothing else from the segment may survive either.
            for other in &hits {
                assert!(
                    !snippet.contains(other.matched_value.as_str()),
                    "rule {} leaked the value of {}: {snippet}",
                    hit.rule_id,
                    other.rule_id
                );
            }
        }
    }
    assert!(checked >= 5, "corpus must produce findings, got {checked}");
}

// ── 9. zero-width rules must not loop forever ───────────────────────────────

#[test]
fn zero_width_rule_terminates() {
    let engine = RulesEngine::from_rules(vec![yaml_rule(
        r#"
rule_id: zero_width
regex: 'a*'
disable_default_placeholders: true
"#,
    )])
    .expect("engine builds");

    let started = Instant::now();
    let hits = engine.scan(&"b".repeat(2000), "description");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "scan did not terminate promptly"
    );
    assert!(
        hits.is_empty(),
        "empty matches must be skipped, got {}",
        hits.len()
    );

    // Real (non-empty) matches of the same rule still come through.
    let hits = engine.scan("aaabbbaa", "description");
    assert!(hits.len() <= 2, "unexpected hit count: {}", hits.len());
    assert!(hits.iter().all(|h| !h.matched_value.is_empty()));
}

// ── the redact module contract, exercised through the public API ────────────

#[test]
fn redact_snippet_masks_every_occurrence_and_invalid_spans() {
    let snippet = "left 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 right";
    let value = "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";

    // Usable span: masked in place, context kept.
    let redacted = redact::redact_snippet(snippet, value, 5..45, "github_token");
    assert!(!redacted.contains(value), "{redacted}");
    assert!(redacted.contains("left") && redacted.contains("right"));

    // Broken spans fall back to masking the value everywhere.
    for span in broken_spans() {
        let redacted = redact::redact_snippet(snippet, value, span.clone(), "github_token");
        assert!(
            !redacted.contains(value),
            "span {span:?} leaked: {redacted}"
        );
    }

    // A span landing inside a multi-byte character is widened, not panicked on.
    let cyrillic = "ключ: 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 конец";
    let redacted = redact::redact_snippet(cyrillic, value, 7..50, "github_token");
    assert!(!redacted.contains(value), "{redacted}");
}

/// Spans that cannot be used as they are: out of bounds, inverted, zero width.
#[allow(clippy::reversed_empty_ranges)] // the inverted span is the point
fn broken_spans() -> Vec<std::ops::Range<usize>> {
    vec![900..1000, 45..5, 5..5, 0..0]
}

#[test]
fn redact_snippet_with_masks_the_other_secrets_too() {
    let snippet = format!("one {GITHUB_SECRET} two {GITHUB_SECRET_ALT}");
    let redacted = redact::redact_snippet_with(
        &snippet,
        (GITHUB_SECRET, 4..44, "github_token"),
        &[(GITHUB_SECRET_ALT, "github_token")],
    );
    assert!(!redacted.contains(GITHUB_SECRET), "{redacted}");
    assert!(!redacted.contains(GITHUB_SECRET_ALT), "{redacted}");
}
