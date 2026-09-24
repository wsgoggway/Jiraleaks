//! Verdicts of the candidate filter chain.
//!
//! The chain used to be spread over `rules.rs` (rule filters), `pipeline.rs`
//! (allowlist, placeholder, context boost, confidence, threshold) and
//! `credpair.rs` (a second placeholder list), with every rejection a bare
//! `return false`. These tests pin the result of the one owner that replaced it:
//! `jiraleaks::candidate`.
//!
//! What is covered here:
//!
//! * one constructed case per [`DropReason`], through the real entry points;
//! * the context boost — what it is and what it does not rescue;
//! * the shared placeholder dictionary, read by both the rules path and the
//!   credential-pair path, and the two modes that keep their original semantics;
//! * [`context_window`] on the boundaries (text start, text end, Cyrillic,
//!   out-of-range spans).

use std::ops::Range;

use jiraleaks::candidate::{
    context_window, has_context_word, Candidate, DropReason, Judge, PlaceholderPolicy, Verdict,
    CONTEXT_RADIUS, CONTEXT_WORDS,
};
use jiraleaks::credpair::CredentialPairDetector;
use jiraleaks::finding::Confidence;
use jiraleaks::rules::{CompiledRule, Rule, RulesEngine};

// ── helpers ─────────────────────────────────────────────────────────────────

fn yaml_rule(yaml: &str) -> Rule {
    serde_yaml::from_str(yaml).expect("valid rule yaml")
}

fn compiled(yaml: &str) -> CompiledRule {
    CompiledRule::compile(yaml_rule(yaml)).expect("rule compiles")
}

/// A candidate whose span is the value's real position in `text`.
fn candidate<'a>(value: &'a str, text: &'a str) -> Candidate<'a> {
    let start = text.find(value).expect("value occurs in the text");
    Candidate {
        value,
        text,
        value_span: start..start + value.len(),
        field_path: "description",
        issue_key: "APP-1",
    }
}

/// A rule that matches `secret = <value>` and reports the value as its hit.
fn assignment_rule() -> CompiledRule {
    compiled("rule_id: probe\nregex: 'secret\\s*=\\s*(\\S+)'\ncapture_group: 1\nmin_length: 4\n")
}

// ── one case per DropReason, through `Judge::rule_filters` ──────────────────

#[test]
fn rule_filters_report_the_first_failing_check() {
    let cases: Vec<(&str, &str, &str, &str, DropReason)> = vec![
        (
            "min_length",
            "rule_id: r\nregex: 'x'\nmin_length: 10\n",
            "secret = abc",
            "abc",
            DropReason::TooShort { min: 10, got: 3 },
        ),
        (
            "min_entropy",
            "rule_id: r\nregex: 'x'\nmin_entropy: 4.0\n",
            "secret = aaaaaaaa",
            "aaaaaaaa",
            DropReason::LowEntropy { min: 4.0, got: 0.0 },
        ),
        (
            "denylist",
            "rule_id: r\nregex: 'x'\ndenylist: [forbidden]\n",
            "secret = my-forbidden-key",
            "my-forbidden-key",
            DropReason::Denylisted,
        ),
        (
            "default placeholders",
            "rule_id: r\nregex: 'x'\n",
            "secret = changeme",
            "changeme",
            DropReason::Placeholder,
        ),
        (
            "min_digits",
            "rule_id: r\nregex: 'x'\nmin_digits: 3\n",
            "secret = abcdefgh",
            "abcdefgh",
            DropReason::MissingCharClass {
                required: "min_digits",
                min: 3,
                got: 0,
            },
        ),
        (
            "context_keywords",
            "rule_id: r\nregex: 'x'\ncontext_keywords: [api_key]\n",
            "credentials = abcdefgh",
            "abcdefgh",
            DropReason::MissingContextKeyword,
        ),
        (
            "validator",
            "rule_id: r\nregex: 'x'\nvalidator: jwt_structure\n",
            "secret = abcdefgh",
            "abcdefgh",
            DropReason::ValidatorRejected,
        ),
    ];

    let judge = Judge::new();
    for (name, yaml, text, value, expected) in cases {
        let rule = compiled(yaml);
        let cand = candidate(value, text);
        assert_eq!(
            judge.rule_filters(&rule, &cand),
            Err(expected),
            "case {name} must report its own reason"
        );
    }
}

#[test]
fn rule_filters_accept_a_value_that_satisfies_every_requirement() {
    let rule = compiled(
        "rule_id: r\nregex: 'x'\nmin_length: 8\nmin_entropy: 3.0\nmin_digits: 1\n\
         context_keywords: [secret]\nvalidator: jwt_structure\n",
    );
    let text = "secret = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij";
    let cand = candidate("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij", text);
    assert_eq!(Judge::new().rule_filters(&rule, &cand), Ok(()));
}

#[test]
fn the_rules_engine_keeps_the_contract_that_scan_returns_filtered_hits() {
    // `scan` returns hits that already passed the rule filters, so a placeholder
    // value never reaches a caller — this is what `tests/rules_detection.rs`
    // depends on.
    let engine = RulesEngine::from_rules(vec![yaml_rule(
        "rule_id: probe\nregex: 'secret\\s*=\\s*(\\S+)'\ncapture_group: 1\nmin_length: 4\n",
    )])
    .expect("engine builds");

    assert!(engine.scan("secret = changeme", "description").is_empty());
    assert_eq!(
        engine.scan("secret = hunter2secret", "description").len(),
        1
    );
}

// ── `Judge::finalize`: allowlist and the confidence floor ──────────────────

#[test]
fn finalize_reports_the_allowlist_verdict_with_its_reason() {
    let judge = Judge::new();
    let text = "secret = hunter2secret";
    let cand = candidate("hunter2secret", text);

    assert_eq!(
        judge.finalize(
            "probe",
            Confidence::High,
            &cand,
            Some(Some("public docs example".to_string())),
            Confidence::Low,
        ),
        Verdict::Drop(DropReason::Allowlisted {
            reason: Some("public docs example".to_string())
        })
    );
    assert_eq!(
        judge.finalize(
            "probe",
            Confidence::High,
            &cand,
            Some(None),
            Confidence::Low
        ),
        Verdict::Drop(DropReason::Allowlisted { reason: None })
    );
}

#[test]
fn finalize_drops_a_candidate_below_the_confidence_floor() {
    // No context word and a low-entropy value: a `low` rule stays `low`, which is
    // under a `medium` floor.
    let text = "value = aaaaaaaa";
    let cand = candidate("aaaaaaaa", text);
    let verdict = Judge::new().finalize("probe", Confidence::Low, &cand, None, Confidence::Medium);
    assert_eq!(
        verdict,
        Verdict::Drop(DropReason::BelowMinConfidence {
            min: Confidence::Medium,
            got: Confidence::Low
        })
    );
}

// ── the context boost ──────────────────────────────────────────────────────

#[test]
fn keep_reports_whether_a_context_word_boosted_the_confidence() {
    let judge = Judge::new();
    // A high-entropy value with no context word near it: kept, but not boosted.
    let secret = "kX7mP2qR9sT4vW1yZ3b";
    let boosted_text = format!("api_key = {secret}");
    let plain_text = format!("value = {secret}");

    let with_context = judge.finalize(
        "probe",
        Confidence::High,
        &candidate(secret, &boosted_text),
        None,
        Confidence::Low,
    );
    assert_eq!(
        with_context,
        Verdict::Keep {
            confidence: Confidence::High,
            boosted: true
        }
    );

    let without_context = judge.finalize(
        "probe",
        Confidence::High,
        &candidate(secret, &plain_text),
        None,
        Confidence::Low,
    );
    assert_eq!(
        without_context,
        Verdict::Keep {
            confidence: Confidence::High,
            boosted: false
        }
    );
}

#[test]
fn every_context_word_boosts_and_they_are_the_only_ones() {
    let judge = Judge::new();
    for word in CONTEXT_WORDS {
        let text = format!("{word} = hunter2secret");
        let cand = candidate("hunter2secret", &text);
        assert!(
            has_context_word(&text, &cand.value_span),
            "{word} must be a context word"
        );
        match judge.finalize("probe", Confidence::Low, &cand, None, Confidence::Low) {
            Verdict::Keep { boosted, .. } => assert!(boosted, "{word} must boost"),
            other => panic!("{word}: {other:?}"),
        }
    }

    // A word from outside the list boosts nothing. The window covers the value
    // itself, so the value must avoid the list too — `hunter2secret` would boost
    // itself through its own `secret` suffix.
    let text = "blob = kX7mP2qR9sT4vW1yZ3b";
    let cand = candidate("kX7mP2qR9sT4vW1yZ3b", text);
    assert!(!has_context_word(text, &cand.value_span));
}

#[test]
fn the_boost_does_not_rescue_a_rule_below_its_floor() {
    // `Low` stays `Low` however many signals fire, so a rule whose confidence is
    // low never reaches a `medium` floor.
    let text = "password = hunter2secret";
    let cand = candidate("hunter2secret", text);
    assert!(
        has_context_word(text, &cand.value_span),
        "the case must carry a context word"
    );
    assert_eq!(
        Judge::new().finalize("probe", Confidence::Low, &cand, None, Confidence::Medium),
        Verdict::Drop(DropReason::BelowMinConfidence {
            min: Confidence::Medium,
            got: Confidence::Low
        })
    );
}

// ── the placeholder check of `finalize` ────────────────────────────────────

#[test]
fn a_placeholder_value_keeps_the_historical_confidence_drop() {
    // The post-scan placeholder check has never dropped a candidate by itself: it
    // forces `low`, and the `min_confidence` floor decides. Both halves are
    // asserted here so the behaviour cannot drift silently.
    let judge = Judge::new();
    let text = "api_key = changeme";
    let cand = candidate("changeme", text);

    match judge.finalize("probe", Confidence::High, &cand, None, Confidence::Low) {
        Verdict::Keep { confidence, .. } => assert_eq!(
            confidence,
            Confidence::Low,
            "a placeholder value drops to low confidence"
        ),
        other => panic!("a placeholder stays a candidate at floor `low`: {other:?}"),
    }

    assert_eq!(
        judge.finalize("probe", Confidence::High, &cand, None, Confidence::Medium),
        Verdict::Drop(DropReason::BelowMinConfidence {
            min: Confidence::Medium,
            got: Confidence::Low
        })
    );
}

#[test]
fn finalize_judges_the_same_values_the_credential_pair_detector_does() {
    // The one dictionary, seen from both entry points. `changeme` is a placeholder
    // in both modes, so the pair detector never pairs it and the post-scan check
    // caps its confidence.
    let judge = Judge::new();
    let detector = CredentialPairDetector::new().expect("patterns compile");

    let text = "username=alice\npassword=changeme\n";
    assert!(
        detector.detect(text, "comment").is_empty(),
        "the pair detector must reject a placeholder password"
    );
    let cand = candidate("changeme", text);
    assert!(PlaceholderPolicy::exact().matches(cand.value));
    match judge.finalize("probe", Confidence::High, &cand, None, Confidence::Low) {
        Verdict::Keep { confidence, .. } => assert_eq!(confidence, Confidence::Low),
        other => panic!("{other:?}"),
    }
}

// ── one dictionary, two modes ──────────────────────────────────────────────

#[test]
fn the_rules_engine_builds_its_default_list_from_the_shared_dictionary() {
    // `ignore_if_contains` is the effective list a rule matches against; with no
    // rule entries of its own it must be exactly the dictionary's `Contains` mode,
    // in order. This is what makes the dictionary the only copy in the tree.
    let rule = compiled("rule_id: probe\nregex: 'x'\n");
    let expected: Vec<String> = PlaceholderPolicy::contains()
        .words()
        .map(str::to_string)
        .collect();
    assert_eq!(rule.ignore_if_contains, expected);

    // A rule's own entries extend the shared list rather than replacing it.
    let rule = compiled("rule_id: probe\nregex: 'x'\nignore_if_contains: [internal-only]\n");
    let mut extended = expected;
    extended.push("internal-only".to_string());
    assert_eq!(rule.ignore_if_contains, extended);

    // `disable_default_placeholders` still opts out of the dictionary entirely.
    let rule = compiled(
        "rule_id: probe\nregex: 'x'\ndisable_default_placeholders: true\n\
         ignore_if_contains: [internal-only]\n",
    );
    assert_eq!(rule.ignore_if_contains, vec!["internal-only".to_string()]);
}

#[test]
fn both_paths_reject_the_marker_values_of_the_dictionary() {
    let judge = Judge::new();
    let rule = assignment_rule();
    let engine = RulesEngine::from_rules(vec![yaml_rule(
        "rule_id: probe\nregex: 'secret\\s*=\\s*(\\S+)'\ncapture_group: 1\nmin_length: 4\n",
    )])
    .expect("engine builds");
    let detector = CredentialPairDetector::new().expect("patterns compile");

    for marker in ["changeme", "your_key", "xxxx"] {
        // Rules path: the hit is filtered out by the rule's default list ...
        let text = format!("secret = {marker}");
        assert!(
            engine.scan(&text, "description").is_empty(),
            "{marker} must not survive the rules path"
        );
        // ... and the judge names the reason.
        assert_eq!(
            judge.rule_filters(&rule, &candidate(marker, &text)),
            Err(DropReason::Placeholder),
            "{marker}"
        );
    }

    // Credential-pair path: `changeme` is a placeholder in the `Exact` mode the
    // detector uses, so a pair carrying it is never reported.
    assert!(detector
        .detect("username=alice\npassword=changeme\n", "comment")
        .is_empty());
}

#[test]
fn the_two_modes_keep_their_original_semantics() {
    // The dictionary is one table, but the two readers ask different questions,
    // and that asymmetry is a contract: the rules engine rejects a value that
    // *contains* a marker, while the pair detector only rejects a value that *is*
    // one — a literal `xxxx` password is weak, not a placeholder.
    assert!(PlaceholderPolicy::contains().matches("xxxx"));
    assert!(!PlaceholderPolicy::exact().matches("xxxx"));

    assert!(PlaceholderPolicy::contains().matches("my-changeme-key"));
    assert!(!PlaceholderPolicy::exact().matches("my-changeme-key"));

    // Template markers belong to the pair detector's side only.
    assert!(PlaceholderPolicy::exact().matches("${DB_PASS}"));
    assert!(!PlaceholderPolicy::contains().matches("${DB_PASS}"));

    // And the detector still reports such a pair.
    let detector = CredentialPairDetector::new().expect("patterns compile");
    assert_eq!(
        detector
            .detect("username=alice\npassword=xxxx\n", "comment")
            .len(),
        1,
        "`xxxx` is not an `Exact`-mode placeholder"
    );
}

// ── the window arithmetic ──────────────────────────────────────────────────

#[test]
fn context_window_handles_the_boundaries() {
    // Radius 0 is exactly the value.
    let text = "secret = hunter2secret";
    assert_eq!(context_window(text, &(9..22), 0), "hunter2secret");

    // A text longer than the radius, so both clamps below are observable.
    let long = format!("{}secret", "x".repeat(120));
    let tail = long.len() - "secret".len();

    // Start of the text: the window stops at the first byte.
    let window = context_window(&long, &(0..6), CONTEXT_RADIUS);
    assert_eq!(window.len(), 6 + CONTEXT_RADIUS);
    assert!(window.starts_with("xxxxxx"));

    // End of the text: the window stops at the last byte.
    let window = context_window(&long, &(tail..long.len()), CONTEXT_RADIUS);
    assert_eq!(window.len(), "secret".len() + CONTEXT_RADIUS);
    assert!(window.ends_with("secret"));

    // Cyrillic: every character is two bytes, so a ±50 byte window lands on an odd
    // offset and must be rounded to a character boundary instead of splitting one.
    let cyrillic = "я".repeat(200);
    assert_eq!(cyrillic.len(), 400);
    let window = context_window(&cyrillic, &(101..103), CONTEXT_RADIUS);
    assert_eq!(window.len(), 104, "50 bytes each side, both rounded out");
    assert!(window.chars().all(|c| c == 'я'), "window: {window:?}");

    // A span past the end of the text yields the empty tail, never a panic.
    let past: Range<usize> = 500..600;
    assert_eq!(context_window(text, &past, CONTEXT_RADIUS), "");
    assert_eq!(context_window("", &(0..0), CONTEXT_RADIUS), "");

    // Out-of-order spans cannot come out of the scanner; they must not panic
    // either, and still yield a slice of the text.
    #[allow(clippy::reversed_empty_ranges)]
    let inverted_span = 20..4;
    let inverted = context_window(text, &inverted_span, CONTEXT_RADIUS);
    assert!(text.contains(inverted));
}
