//! Near-miss negatives: values that look like a secret to a human — or to a
//! careless regex — and must not become findings.
//!
//! `tests/rules_detection.rs` covers the "wrong length" negatives. The corpus
//! here is the harder half of the false-positive surface:
//!
//! * **right length, wrong charset** — a 20-character AWS-shaped string with
//!   lowercase letters, a `glpat-` value with a character the alphabet does not
//!   allow, a JWT with two segments instead of three;
//! * **documentation stubs** — `example`, `changeme`, `your_key`, `xxx`,
//!   `dummy`, `sample`, `redacted`, `test` as a secret's value;
//! * **harmless blobs** — 40- and 64-character base64/hex strings with no
//!   context word anywhere near them;
//! * **rule requirements** — a value that satisfies the regex but not the rule's
//!   `context_keywords` or `min_digits`.
//!
//! Every negative is paired with a positive control, so a rule id typo or a rule
//! that stopped being loaded cannot make the corpus pass vacuously.
//!
//! The last test is a ReDoS guard: `private_key_block` is the one builtin rule
//! with an unbounded `.*?` between two markers, and it is fed megabytes of
//! markers with no terminator.

use std::time::{Duration, Instant};

use jiraleaks::rules::RulesEngine;

/// Upper bound for one scan of the ReDoS corpus.
///
/// A hang guard, not a benchmark: the measured baseline is 3.2–3.5 s for the
/// whole builtin engine over 1.1 MB (debug profile, this repository's machine),
/// so the budget leaves a margin of more than 2x for a slower or loaded one,
/// while a quadratic blowup — the failure this test exists for — would be
/// minutes or hours, not seconds.
const REDOS_BUDGET: Duration = Duration::from_secs(8);

fn engine() -> RulesEngine {
    RulesEngine::new(None).expect("builtin rules load")
}

/// Rule ids that fired on `text`.
fn hits(engine: &RulesEngine, text: &str) -> Vec<String> {
    engine
        .scan(text, "nearmiss")
        .into_iter()
        .map(|hit| hit.rule_id)
        .collect()
}

/// The rule must not fire on `text`.
fn assert_not_detected(engine: &RulesEngine, rule_id: &str, text: &str) {
    let found = hits(engine, text);
    assert!(
        !found.contains(&rule_id.to_string()),
        "rule '{rule_id}' fired on a near miss: {text:?} (all hits: {found:?})"
    );
}

/// The rule must fire on `text` — the positive control that keeps each negative
/// above honest.
fn assert_detected(engine: &RulesEngine, rule_id: &str, text: &str) {
    let found = hits(engine, text);
    assert!(
        found.contains(&rule_id.to_string()),
        "rule '{rule_id}' did not fire on a positive sample: {text:?} (all hits: {found:?})"
    );
}

// ── the corpus ──────────────────────────────────────────────────────────────

/// Right length, wrong charset: (rule id, near miss, positive control).
///
/// Each near miss is one character away from a value the rule *would* accept,
/// and each positive control is the near miss with that one character fixed —
/// so the pair proves the rejection comes from the character class and not from
/// a filter that would reject the whole pattern family.
fn charset_near_misses() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // The regex demands [0-9A-Z] after the prefix; AWS itself never issues
        // a lowercase key id.
        (
            "aws_access_key_id",
            "access key ASIAabcdefghijklmnop end",
            "access key ASIAABCDEFGHIJKLMNOP end",
        ),
        // Same, with the prefix lowercased: the prefix alternation is
        // case-sensitive.
        (
            "aws_access_key_id",
            "access key asia1234567890ABCDEF end",
            "access key ASIA1234567890ABCDEF end",
        ),
        // 20-character payload, but a `.` where the alphabet has none.
        (
            "gitlab_token",
            "token glpat-abcdefghijklmnopqrs. end",
            "token glpat-abcdefghijklmnopqrst end",
        ),
        // 34 characters after `AIza` plus a `.` — one short of the 35 the rule
        // needs, because `.` is not in the class.
        (
            "google_api_key",
            "key AIzaSyD4iE2xV1fR8tB8pL6nO3mQ9wK0jH5cA7. end",
            "key AIzaSyD4iE2xV1fR8tB8pL6nO3mQ9wK0jH5cA7s end",
        ),
        // `_` is word character but not a Slack token character: the 10-char
        // run that ends before it has no word boundary after it.
        (
            "slack_token",
            "token xoxb-1234567890_2-123456789012-abcdefghijkl end",
            "token xoxb-1234567890-2-123456789012-abcdefghijkl end",
        ),
        // A two-segment JWT: the structure the rule (and the validator behind
        // it) requires is three segments.
        (
            "jwt",
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 end",
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c end",
        ),
        // `.` inside the npm body: the longest run on either side is under the
        // 36 characters the rule needs.
        (
            "npm_token",
            "token npm_1A2b3C4d.E6f7G8h9I0jK1lM2nO3pQ4r5S6t7U8v end",
            "token npm_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4r5S6t7U8v9 end",
        ),
        // A short middle group where SendGrid has 16+ characters.
        (
            "sendgrid_api_key",
            "key SG.1A2b3C4d5E6f7G8h9I.0.1A2b3C4d5E6f7G8h9I0jK1lM2nO3p end",
            "key SG.1A2b3C4d5E6f7G8h9I0.1A2b3C4d5E6f7G8h9I0jK1lM2nO3p end",
        ),
        // Telegram's alphabet has no `.`: the run before it is too short.
        (
            "telegram_bot_token",
            "bot 1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAA end",
            "bot 1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end",
        ),
        // Stripe's body has no `.`: every run between the dots is under 24.
        (
            "stripe_key",
            "key sk_live_51H2jYkL4N8pQ.sT9vW1xZ4aB7cD.eF3gH5iJ6kL7mN end",
            "key sk_live_51H2jYkL4N8pQ3rS6tU9vW1xZ4aB7cD0eF3gH5iJ6kL end",
        ),
        // GitHub's body has no `.` either.
        (
            "github_token",
            "token ghp_AAAAAAAAAA.Ebbbbbbbbbbbbbbbbbbbbbbbbbbbbbb end",
            "token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end",
        ),
    ]
}

#[test]
fn wrong_charset_at_the_right_length_is_not_detected() {
    let engine = engine();
    for (rule_id, near_miss, positive) in charset_near_misses() {
        assert_not_detected(&engine, rule_id, near_miss);
        assert_detected(&engine, rule_id, positive);
    }
}

/// Documentation stubs and template values must never be reported for the
/// rules that read an assignment.
///
/// The value is deliberately a *valid* match of the rule's regex — 16+
/// characters, at least one digit — so the only thing that can reject it is the
/// placeholder dictionary.
#[test]
fn documentation_stubs_are_not_detected() {
    let engine = engine();

    // (placeholder word, value the regex accepts)
    let stubs = [
        ("example", "example_1234567890"),
        ("changeme", "changeme_1234567890"),
        ("your_key", "your_key_1234567890"),
        ("xxxx", "xxxxxxxxxxxxxxxxxx"),
        ("dummy", "dummy_1234567890"),
        ("sample", "sample_1234567890"),
        ("redacted", "redacted12345678"),
        ("test", "test_123456789012"),
    ];

    for (word, value) in stubs {
        // The rules that read a `key = value` / `secret = value` assignment.
        for rule_id in [
            "generic_api_key_assignment",
            "generic_secret_assignment",
            "generic_password_assignment",
        ] {
            let text = match rule_id {
                "generic_api_key_assignment" => format!("api_key = {value}"),
                "generic_secret_assignment" | "generic_password_assignment" => {
                    format!("secret = {value}")
                }
                _ => unreachable!(),
            };
            assert_not_detected(&engine, rule_id, &text);
        }

        // Case does not matter: the dictionary match is case-insensitive.
        assert_not_detected(
            &engine,
            "generic_api_key_assignment",
            &format!("api_key = {}", value.to_uppercase()),
        );

        // Control: the same shape with the marker replaced by random-looking
        // text is detected, so the rejection above is the dictionary's doing.
        assert_detected(
            &engine,
            "generic_api_key_assignment",
            "api_key = kO9mX2vB7nQ4pL8sT1zR6yU3wA5cD0eF",
        );
        // ... and the stub word is what the case above is about.
        assert!(
            value.to_lowercase().contains(word),
            "the fixture value for {word} does not contain it"
        );
    }
}

/// 40- and 64-character blobs with no context word around them are not secrets.
///
/// The first two are the shapes a scanner sees most often — a base64 digest and
/// a hex SHA-1 — and what separates them from an AWS secret key is the keyword
/// the rule requires, not the regex. The third is a SHA-256 digest, and it is
/// rejected by the regex itself: an AWS secret key is exactly 40 characters with
/// a word boundary on each side, so a 64-character run has none at the offsets
/// a match would need.
///
/// Lengths are asserted before the scan: a blob one character off is rejected by
/// the regex for the wrong reason, and that would make the negative below pass
/// while proving nothing.
#[test]
fn harmless_base64_and_hex_blobs_are_not_detected() {
    let engine = engine();

    // (blob, length, does the keyword bring it back as a finding)
    let blobs = [
        // base64-ish, 40 characters: matches `aws_secret_access_key`'s regex.
        ("kO9mX2vB7nQ4pL8sT1zR6yU3wA5cD0eF7gH2iJ4k", 40, true),
        // hex, 40 characters: also matches the same regex.
        ("d41d8cd98f00b204e9800998ecf8427e01234567", 40, true),
        // hex, 64 characters: a SHA-256 digest, or a git object id.
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            64,
            false,
        ),
    ];

    for (blob, expected_len, keyword_finds_it) in blobs {
        assert_eq!(
            blob.len(),
            expected_len,
            "fixture {blob:?} is not {expected_len} characters"
        );

        let text = format!("The pipeline printed checksum {blob} for the artifact.");
        let found = hits(&engine, &text);
        assert!(
            found.is_empty(),
            "a bare blob was reported by {found:?}: {text:?}"
        );

        // The same value next to the rule's keyword: a finding for the 40-char
        // blobs (the control that keeps the negative honest), and still not a
        // finding for the digest, which is the length the rule demands.
        let with_keyword = format!("aws_secret_access_key = {blob}");
        if keyword_finds_it {
            assert_detected(&engine, "aws_secret_access_key", &with_keyword);
        } else {
            assert_not_detected(&engine, "aws_secret_access_key", &with_keyword);
        }
    }
}

/// A rule that requires `context_keywords` rejects a value that has none, and a
/// rule that requires `min_digits` rejects a value without digits — both through
/// the public `scan`, not through the internal filter chain.
#[test]
fn rule_requirements_reject_the_value_that_satisfies_only_the_regex() {
    let engine = engine();

    // 40 characters from `aws_secret_access_key`'s class: the regex accepts it,
    // `min_digits: 3` and the context keywords are what decide.
    let without_digits = "AbCdEfGhIjAbCdEfGhIjAbCdEfGhIjAbCdEfGhIj";
    let with_digits = "AbCdEfGhIjAbCdEfGhIjAbCdEfGhIjAbCd1234Ij";
    assert_eq!(without_digits.len(), 40);
    assert_eq!(with_digits.len(), 40);
    assert_eq!(without_digits.matches(char::is_numeric).count(), 0);
    assert!(with_digits.matches(char::is_numeric).count() >= 3);

    // No context keyword: rejected, even though the value is perfect.
    assert_not_detected(
        &engine,
        "aws_secret_access_key",
        &format!("The value in the ticket is {with_digits}."),
    );

    // Keyword present, digits absent: rejected by `min_digits`.
    assert_not_detected(
        &engine,
        "aws_secret_access_key",
        &format!("aws_secret_access_key = {without_digits}"),
    );

    // Both satisfied: the control, so neither rejection above is vacuous.
    assert_detected(
        &engine,
        "aws_secret_access_key",
        &format!("aws_secret_access_key = {with_digits}"),
    );
}

/// CHARACTERIZATION of a defect, not an endorsement: the `aws_key_checksum`
/// validator documents the AWS alphabet as base32 (`A-Z, 2-7`) but its
/// implementation accepts every uppercase letter and digit, so a key id
/// containing `0`, `1`, `8` or `9` — which AWS never issues — is reported as a
/// finding.
///
/// The assertion is written the way the code behaves today so that the defect is
/// pinned and visible. When the validator starts enforcing the documented
/// alphabet, this test must be inverted (see the QA report of the task that
/// added it).
#[test]
fn aws_key_with_non_base32_digits_is_reported_today() {
    let engine = engine();
    let non_base32 = "ASIA0000000000000000";
    assert!(
        hits(&engine, &format!("aws_access_key_id = {non_base32}"))
            .contains(&"aws_access_key_id".to_string()),
        "the validator changed: `{non_base32}` is no longer reported, invert this test"
    );
}
// ── ReDoS ───────────────────────────────────────────────────────────────────

/// `private_key_block` is the only builtin rule with an unbounded lazy `.*?`
/// between two markers, which is the shape that can turn into quadratic
/// backtracking. A megabyte of markers must be scanned in seconds, and never
/// panic or hang.
///
/// The whole builtin engine is timed, not only that one rule: a scan pays for
/// every rule that runs over the text, so a regression may just as well live in
/// one of the other nineteen.
///
/// Three shapes are fed in: markers with no terminator at all, markers with a
/// terminator only at the very end, and — as the control — one well-formed
/// block, which must still be found.
#[test]
fn private_key_block_scanning_is_linear_enough_on_megabyte_inputs() {
    let engine = engine();

    let begin = "-----BEGIN PRIVATE KEY-----\n";
    let end = "-----END PRIVATE KEY-----\n";
    assert!(
        begin.len() * 40_000 > 1024 * 1024,
        "the corpus must be more than 1 MB"
    );

    // 1. Markers, no terminator anywhere: the regex can never match, and the
    //    engine must not look for a terminator at every position.
    let unterminated = begin.repeat(40_000);
    let started = Instant::now();
    let found = hits(&engine, &unterminated);
    let elapsed = started.elapsed();
    eprintln!(
        "redos: unterminated {} bytes in {elapsed:?}",
        unterminated.len()
    );
    assert!(
        elapsed < REDOS_BUDGET,
        "scanning {} bytes without a terminator took {elapsed:?}",
        unterminated.len()
    );
    assert!(
        !found.contains(&"private_key_block".to_string()),
        "a block without a terminator was reported"
    );

    // 2. A terminator after a megabyte of markers: the match spans the whole
    //    prefix, so the cost is a real match, not a failed one.
    let mut terminated = begin.repeat(40_000);
    terminated.push_str(end);
    let started = Instant::now();
    let found = hits(&engine, &terminated);
    let elapsed = started.elapsed();
    eprintln!(
        "redos: terminated {} bytes in {elapsed:?}",
        terminated.len()
    );
    assert!(
        elapsed < REDOS_BUDGET,
        "scanning {} bytes with a terminator took {elapsed:?}",
        terminated.len()
    );
    assert_eq!(
        found.iter().filter(|r| *r == "private_key_block").count(),
        1,
        "the single terminated block must be found exactly once, got {found:?}"
    );

    // 3. The control the two above need: without it, a rule that never fires
    //    would pass this test trivially.
    assert_detected(
        &engine,
        "private_key_block",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcQ0ZiG8n\n-----END RSA PRIVATE KEY-----\n",
    );
}
