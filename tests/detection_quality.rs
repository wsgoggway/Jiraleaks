//! Detection quality, measured on a corpus that is independent of the rules it
//! tests.
//!
//! Both halves of this suite used to be weaker than they looked:
//!
//! * the recall corpus *was* the `examples` list of the rules themselves, so it
//!   proved the rules match their own documentation sample and nothing else — and
//!   it counted "some rule fired", which hides a sample that only the generic
//!   fallback caught;
//! * the precision corpus was 15 short phrases with a threshold that tolerated
//!   four false positives.
//!
//! Both are replaced below by hand-written corpora: every positive names the
//! rule that must fire, every negative names none, and both thresholds are
//! pinned at the values these corpora produce today.
//!
//! **The thresholds are a baseline, not a target.** They are what the current
//! rule set achieves on this corpus; a change that lowers them means a rule
//! stopped working or started firing on ordinary prose, and the fix belongs in
//! the rules — not in this file. Raising the corpus (more negatives) is expected
//! and welcome; lowering `MIN_NEGATIVES`/`MIN_POSITIVES` to make the suite pass
//! is not.

use jiraleaks::rules::RulesEngine;

/// A sample that must be detected by the named rule.
///
/// The values are deliberately *not* the ones in the rules' own `examples`
/// lists: a corpus that shares its samples with the thing it tests cannot fail.
/// Each sample also avoids the placeholder dictionary (`example`, `test`,
/// `sample`, `demo`, `secret`, …), because a value such as
/// `postgres://user:secretpass@…` is rejected *by design* and would look like a
/// recall failure while being correct behaviour.
///
/// Every token body is built to the length the rule demands, from [`PAD`]: the
/// exact length is what separates a match from a near miss (`\b…{40}\b` matches
/// a 40-character run and nothing longer), so a hand-typed sample one character
/// off would look like a rule that stopped working.
const PAD: &str =
    "Kq7Zm2Xr9Wt4Yn3Bv6Lp8Rs1Qd5Hf2Jg0Ad2Xr9Wt4Yn3Bv6Lp8Rs1Qd5Hf2Jg0Ad2Xr9Wt4Yn3Bv6Lp8Rs1Qd";

/// `prefix` plus exactly `n` characters of [`PAD`].
fn exact(prefix: &str, n: usize) -> String {
    assert!(PAD.len() >= n, "PAD is too short for {n} characters");
    format!("{prefix}{}", &PAD[..n])
}

/// The positive corpus: `(rule that must fire, sample)`.
fn positives() -> Vec<(&'static str, String)> {
    vec![
        // AWS key id: 4-character prefix + 16 characters of the AWS base32
        // alphabet (`A-Z`, `2-7`). Not built from [`PAD`]: `PAD` contains `0`,
        // `1`, `8` and `9`, which the rule's `aws_key_checksum` validator
        // rejects, so a sample derived from it would exercise the validator
        // rather than the rule.
        ("aws_access_key_id", "AKIA234567ABCDEFGHIJ".to_string()),
        // AWS secret: exactly 40 characters, at least three digits, and the
        // keyword the rule requires within 50 bytes.
        (
            "aws_secret_access_key",
            format!("aws_secret_access_key = {}", &PAD[..40]),
        ),
        // GitHub classic PAT: `ghp_` + 36 alphanumerics.
        ("github_token", exact("ghp_", 36)),
        // GitHub fine-grained PAT: `github_pat_` + 82 characters.
        ("github_pat_v2", exact("github_pat_", 82)),
        ("gitlab_token", exact("glpat-", 20)),
        ("slack_token", exact("xoxb-", 20)),
        ("google_api_key", exact("AIza", 35)),
        (
            "private_key_block",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcQ0ZiG8nF8qN9Yv7VxM5LU1bRzCjXkP2sT4wH6yA\n-----END RSA PRIVATE KEY-----"
                .to_string(),
        ),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                .to_string(),
        ),
        ("telegram_bot_token", exact("7463829105:", 35)),
        ("stripe_key", exact("sk_live_", 24)),
        ("npm_token", exact("npm_", 36)),
        (
            "sendgrid_api_key",
            format!("SG.{}.{}", &PAD[..16], &PAD[16..32]),
        ),
        (
            "db_url_credentials",
            format!("postgres://svc_app:{}@db.corp.internal:5432/payments", &PAD[..12]),
        ),
        // NOTE: `db_url_credentials` matches inside this one too — a JDBC URL
        // contains the plain URL the other rule looks for. Both findings are
        // legitimate; the assertion below is about the JDBC rule.
        (
            "jdbc_url_with_password",
            format!(
                "jdbc:postgresql://svc_app:{}@db.corp.internal:5432/payments",
                &PAD[..12]
            ),
        ),
        (
            "basic_auth_header",
            "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".to_string(),
        ),
        ("bearer_token_generic", exact("Authorization: Bearer ", 28)),
        ("generic_api_key_assignment", format!("api_key = {}", &PAD[..20])),
        (
            "generic_secret_assignment",
            format!("client_secret = {}", &PAD[..20]),
        ),
        (
            // The trailing `!` keeps the value out of the rule's own
            // `min_digits` trap while leaving its entropy high enough.
            "generic_password_assignment",
            format!("password = {}!", &PAD[..16]),
        ),
    ]
}

/// An ordinary piece of text that must produce **no** finding at all.
///
/// These are the phrases a real Jira instance is full of: release chatter, log
/// lines, config examples with no credentials, and the near misses that a rule
/// for a real credential has to walk past — `Bearer of bad news` after a rule
/// for bearer tokens, `password: required` after one for password assignments.
const NEGATIVES: &[&str] = &[
    "Please review PR #1234 before the sprint review.",
    "The pipeline failed at the deploy step; rerun after fixing the manifest.",
    "Meeting notes: we agreed to move the release to Thursday.",
    "SELECT id, name FROM users WHERE active = true;",
    "export PATH=$PATH:/usr/local/bin:/opt/tools/bin",
    // A keyword without an assignment: `apiKey` is named, no value follows.
    "LOG.info(\"apiKey must be set in the config file\");",
    // `Bearer` followed by prose rather than by 20+ token characters.
    "The bearer of bad news: the build is broken again.",
    "Basic training starts on Monday, room 3B.",
    "curl -H 'Authorization: Bearer ${TOKEN}' https://api.internal/v1/health",
    "Add `password` to the list of required fields on the signup form.",
    // An assignment whose value has no digit: `min_digits` rejects it.
    "password: required",
    "Set secret to the vault-managed value at runtime.",
    "The token expires in 30 days; renew it through the portal.",
    "key = value pairs are documented in the wiki.",
    "host = db.internal.example.com",
    "INFO  [main] Application started in 3.2 seconds",
    "The service listens on 0.0.0.0:8080 by default.",
    "The commit hash is 4f2a9c1d (short form).",
    "Timeout: 30s, retries: 3, backoff: exponential.",
    "docker run -e DB_HOST=localhost -e DB_PORT=5432 payments:1.2.3",
    "aws configure --profile prod",
    "The API key rotation policy is documented in the runbook.",
    // 40 hexadecimal characters: the classic false positive for a rule that
    // looks for a 40-character AWS secret.
    "Merged commit d41d8cd98f00b204e9800998ecf8427e01234567 into main.",
    "md5: 098f6bcd4621d373cade4e832627b4f6",
    "Trace ID: 550e8400-e29b-41d4-a716-446655440000",
    // An SSH public key: a long base64 run with word boundaries only at its
    // ends, so the 40-character rules cannot match inside it.
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7Kq7Zm2Xr9Wt4Yn3Bv6Lp8Rs1Qd5Hf2Jg0Ad2Xr9Wt4Yn3Bv6Lp8Rs1Qd5Hf2Jg0Ad2Xr9Wt4Yn3Bv6Lp8Rs1Qd5Hf2Jg0Ad svc@build-agent",
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==",
];

/// Corpus sizes below which the suite would be able to pass by shrinking its own
/// corpus. Deliberately the current sizes — growing the corpus must not require
/// touching this file.
const MIN_POSITIVES: usize = 20;
const MIN_NEGATIVES: usize = 20;

fn engine() -> RulesEngine {
    RulesEngine::new(None).expect("Failed to load rules")
}

/// Every rule id the scan reports for `text`.
fn rules_hit(engine: &RulesEngine, text: &str) -> Vec<String> {
    engine
        .scan(text, "quality_corpus")
        .into_iter()
        .map(|hit| hit.rule_id)
        .collect()
}

/// Recall, as the rule that was *expected* — not "some rule fired".
#[test]
fn every_positive_is_detected_by_its_own_rule() {
    let engine = engine();
    let positives = positives();
    assert!(
        positives.len() >= MIN_POSITIVES,
        "the positive corpus shrank to {} entries",
        positives.len()
    );

    let mut missed: Vec<(&str, &str, Vec<String>)> = Vec::new();
    for (expected, sample) in &positives {
        let hits = rules_hit(&engine, sample);
        if !hits.iter().any(|rule| rule == expected) {
            missed.push((expected, sample, hits));
        }
    }

    let detected = positives.len() - missed.len();
    println!(
        "Recall: {detected}/{} = {:.1}% (every sample expected to hit its own rule)",
        positives.len(),
        detected as f64 / positives.len() as f64 * 100.0
    );

    assert!(
        missed.is_empty(),
        "{} of {} positives were not detected by their own rule: {missed:#?}",
        missed.len(),
        positives.len()
    );
}

/// Precision: no rule may fire on any of the negatives.
///
/// The threshold is zero false positives, which is what the current rule set
/// achieves on this corpus. Four out of fifteen used to be tolerated.
#[test]
fn no_negative_produces_a_finding() {
    let engine = engine();
    assert!(
        NEGATIVES.len() >= MIN_NEGATIVES,
        "the negative corpus shrank to {} entries",
        NEGATIVES.len()
    );

    let mut false_positives: Vec<(&str, Vec<String>)> = Vec::new();
    for phrase in NEGATIVES {
        let hits = rules_hit(&engine, phrase);
        if !hits.is_empty() {
            false_positives.push((phrase, hits));
        }
    }

    let clean = NEGATIVES.len() - false_positives.len();
    println!(
        "Precision: {clean}/{} negatives clean ({} false positives)",
        NEGATIVES.len(),
        false_positives.len()
    );

    assert!(
        false_positives.is_empty(),
        "the rule set reported {} of {} ordinary phrases: {false_positives:#?}",
        false_positives.len(),
        NEGATIVES.len()
    );
}
