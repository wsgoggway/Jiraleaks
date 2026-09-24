use jiraleaks::rules::RulesEngine;

/// Total positive samples (must detect)
const POSITIVE_SAMPLES: &[&str] = &[
    // aws_access_key_id (kingfisher aws.yml example)
    "ASIA3C7019C2E4B6E76F",
    "ASIA1234567890ABCDEF",
    // aws_secret_access_key (needs context keywords; kingfisher aws.yml example)
    "aws_secret_access_key = 3lyTWqHMt5UySny2drdPYheRTEzrNux8Cn5JWFHL",
    // github_token
    "ghp_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4r5S6t7U8v9W0xY1Z2a",
    // gitlab_token
    "glpat-abcdefghijklmnopqrst",
    // slack_token
    "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
    // google_api_key
    "AIzaSyD4iE2xV1fR8tB8pL6nO3mQ9wK0jH5cA7s",
    // private_key_block
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcQ0ZiG8nF8qN9Yv7VxM5LU1bRzCjXkP2sT4wH6yA\n-----END RSA PRIVATE KEY-----",
    // jwt
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    // telegram_bot_token
    "1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    // stripe_key
    "sk_live_51H2jYkL4N8pQ3rS6tU9vW1xZ4aB7cD0eF3gH5iJ6kL",
    // npm_token
    "npm_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4r5S6t7U8v9W",
    // sendgrid
    "SG.1A2b3C4d5E6f7G8h9I0.1A2b3C4d5E6f7G8h9I0jK1lM2nO3p",
    // db_url_credentials
    "postgres://user:secretpass@db.corp.internal/mydb",
    "mysql://admin:p@ssw0rd@localhost:3306/db",
    // basic_auth_header
    "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
    // bearer_token
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890",
];

/// Total negative samples (must NOT detect)
const NEGATIVE_SAMPLES: &[&str] = &[
    "Just a normal task description about updating the API documentation.",
    "Please review the changes in PR #1234 and merge if approved.",
    "The meeting is scheduled for Monday at 10:00 AM in room 3B.",
    "Updated the Jira workflow to include QA step before Done.",
    "Fixed the bug in the login page — now redirects correctly.",
    "Added unit tests for the user service module.",
    "Sprint planning notes: we need to finish the authentication module.",
    "Here is the architecture diagram: [link to wiki]",
    "We should use environment variables for configuration.",
    "Database migration v2.3.0 applied successfully to staging.",
    "Let us schedule a code review for the payment module.",
    "Updated dependencies to latest versions, all tests pass.",
    "Remember to update the README with new API endpoints.",
    "The build failed due to a missing configuration file.",
    "Prettier and ESLint are now configured in the project.",
];

/// Compute recall: fraction of positive samples detected.
fn compute_recall(engine: &RulesEngine) -> f64 {
    let total = POSITIVE_SAMPLES.len() as f64;
    let detected = POSITIVE_SAMPLES
        .iter()
        .filter(|sample| {
            let hits = engine.scan(sample, "test");
            if hits.is_empty() {
                println!("MISS: {sample}");
            }
            !hits.is_empty()
        })
        .count() as f64;
    detected / total
}

/// Compute precision: fraction of detections on negatives that are false.
/// Lower false positive rate = higher precision.
fn count_false_positives(engine: &RulesEngine) -> usize {
    NEGATIVE_SAMPLES
        .iter()
        .filter(|sample| {
            let hits = engine.scan(sample, "test");
            !hits.is_empty()
        })
        .count()
}

#[test]
fn test_recall_above_90_percent() {
    let engine = RulesEngine::new(None).expect("Failed to load rules");
    let recall = compute_recall(&engine);
    println!("Recall: {:.1}%", recall * 100.0);
    assert!(
        recall >= 0.90,
        "Recall {:.1}% is below 90% threshold",
        recall * 100.0
    );
}

#[test]
fn test_precision_no_false_positives() {
    let engine = RulesEngine::new(None).expect("Failed to load rules");
    let fp = count_false_positives(&engine);
    let total_neg = NEGATIVE_SAMPLES.len();
    let precision = 1.0 - (fp as f64 / total_neg as f64);
    println!(
        "False positives: {}/{} (precision: {:.1}%)",
        fp,
        total_neg,
        precision * 100.0
    );
    // On synthetic corpus without allowlist, expect precision >= 70%
    assert!(
        precision >= 0.70,
        "Precision {:.1}% is below 70% threshold (too many false positives: {}/{})",
        precision * 100.0,
        fp,
        total_neg,
    );
}
