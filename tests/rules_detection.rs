use jiraleaks::rules::RulesEngine;

fn engine() -> RulesEngine {
    RulesEngine::new(None).expect("Failed to load builtin rules")
}

fn assert_detects(rule_id: &str, text: &str) {
    let engine = engine();
    let hits = engine.scan(text, "test_field");
    let found = hits.iter().any(|h| h.rule_id == rule_id);
    assert!(found, "Rule '{rule_id}' should detect in: {text}");
}

fn assert_not_detects(rule_id: &str, text: &str) {
    let engine = engine();
    let hits = engine.scan(text, "test_field");
    let found = hits.iter().any(|h| h.rule_id == rule_id);
    assert!(!found, "Rule '{rule_id}' should NOT fire on: {text}");
}

// ── aws_access_key_id ──
#[test]
fn aws_key_positive() {
    assert_detects("aws_access_key_id", "ASIAOZW6VBVAZFJHJLQA");
    assert_detects("aws_access_key_id", "ASIA1234567890ABCDEF");
}

#[test]
fn aws_key_negative() {
    assert_not_detects("aws_access_key_id", "not a key");
    assert_not_detects("aws_access_key_id", "AKIA123");
}

// ── aws_secret_access_key ──
#[test]
fn aws_secret_positive() {
    assert_detects("aws_secret_access_key", "aws_secret_access_key = 3lyTWqHMt5UySny2drdPYheRTEzrNux8Cn5JWFHL");
}

#[test]
fn aws_secret_negative() {
    assert_not_detects("aws_secret_access_key", "short");
    assert_not_detects("aws_secret_access_key", "no-context-here-abcdefghijklmnopqrstuvwxyz0123");
}

// ── github_token ──
#[test]
fn github_token_positive() {
    let val = format!("gho_{}", "A".repeat(40));
    assert_detects("github_token", &val);
}

#[test]
fn github_token_negative() {
    assert_not_detects("github_token", "ghp_short");
}

// ── github_pat_v2 ──
#[test]
fn github_pat_v2_positive() {
    let val = format!("github_pat_{}", "A".repeat(82));
    assert_detects("github_pat_v2", &val);
}

#[test]
fn github_pat_v2_negative() {
    assert_not_detects("github_pat_v2", "github_pat_short");
}

// ── gitlab_token ──
#[test]
fn gitlab_token_positive() {
    assert_detects("gitlab_token", "glpat-abcdefghijklmnopqrst");
}

#[test]
fn gitlab_token_negative() {
    assert_not_detects("gitlab_token", "glpat-short");
}

// ── slack_token ──
#[test]
fn slack_token_positive() {
    assert_detects("slack_token", "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx");
}

#[test]
fn slack_token_negative() {
    assert_not_detects("slack_token", "xoxb-short");
}

// ── google_api_key ──
#[test]
fn google_api_key_positive() {
    assert_detects("google_api_key", "AIzaSyD4iE2xV1fR8tB8pL6nO3mQ9wK0jH5cA7s");
}

#[test]
fn google_api_key_negative() {
    assert_not_detects("google_api_key", "AIza_short");
}

// ── private_key_block ──
#[test]
fn private_key_positive() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcQ0ZiG8nF8qN9Yv7VxM5LU1bRzCjXkP2sT4wH6yA\n-----END RSA PRIVATE KEY-----";
    assert_detects("private_key_block", pem);
}

#[test]
fn private_key_negative() {
    assert_not_detects("private_key_block", "just some text");
}

// ── jwt ──
#[test]
fn jwt_positive() {
    assert_detects("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
}

#[test]
fn jwt_negative() {
    assert_not_detects("jwt", "not.a.jwt");
}

// ── telegram_bot_token ──
#[test]
fn telegram_token_positive() {
    let val = format!("1234567890:{}", "A".repeat(35));
    assert_detects("telegram_bot_token", &val);
}

#[test]
fn telegram_token_negative() {
    assert_not_detects("telegram_bot_token", "123:short");
}

// ── stripe_key ──
#[test]
fn stripe_key_positive() {
    assert_detects("stripe_key", "sk_live_51H2jYkL4N8pQ3rS6tU9vW1xZ4aB7cD0eF3gH5iJ6kL");
    assert_detects("stripe_key", "rk_test_abcdefghijklmnopqrstuvwx");
}

#[test]
fn stripe_key_negative() {
    assert_not_detects("stripe_key", "sk_short");
}

// ── npm_token ──
#[test]
fn npm_token_positive() {
    assert_detects("npm_token", "npm_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4r5S6t7U8v9W");
}

#[test]
fn npm_token_negative() {
    assert_not_detects("npm_token", "npm_short");
}

// ── sendgrid_api_key ──
#[test]
fn sendgrid_key_positive() {
    assert_detects("sendgrid_api_key", "SG.1A2b3C4d5E6f7G8h9I0.1A2b3C4d5E6f7G8h9I0jK1lM2nO3p");
}

#[test]
fn sendgrid_key_negative() {
    assert_not_detects("sendgrid_api_key", "SG.short");
}

// ── db_url_credentials ──
#[test]
fn db_url_creds_positive() {
    assert_detects("db_url_credentials", "postgres://user:secretpass@db.corp.internal/mydb");
    assert_detects("db_url_credentials", "mysql://admin:p@ssw0rd@localhost:3306/db");
    assert_detects("db_url_credentials", "mongodb://root:toor@cluster0.mongodb.net/appdb");
}

#[test]
fn db_url_creds_negative() {
    assert_not_detects("db_url_credentials", "postgres://localhost/mydb");
}

// ── generic_password_assignment ──
#[test]
fn generic_password_positive() {
    assert_detects("generic_password_assignment", "password = supers3cr3t!!");
}

#[test]
fn generic_password_negative() {
    assert_not_detects("generic_password_assignment", "password: short");
}

// ── generic_api_key_assignment ──
#[test]
fn generic_api_key_positive() {
    assert_detects("generic_api_key_assignment", "api_key = abcdefghijklmnopqrstuvwxyz123456");
}

#[test]
fn generic_api_key_negative() {
    assert_not_detects("generic_api_key_assignment", "api_key = short");
}

// ── generic_secret_assignment ──
#[test]
fn generic_secret_positive() {
    assert_detects("generic_secret_assignment", "secret = s3cr3tV4lu3!");
}

#[test]
fn generic_secret_negative() {
    assert_not_detects("generic_secret_assignment", "secret = abc");
}

// ── basic_auth_header ──
#[test]
fn basic_auth_positive() {
    assert_detects("basic_auth_header", "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
}

#[test]
fn basic_auth_negative() {
    assert_not_detects("basic_auth_header", "Basic short");
}

// ── bearer_token_generic ──
#[test]
fn bearer_token_positive() {
    assert_detects("bearer_token_generic", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890");
}

#[test]
fn bearer_token_negative() {
    assert_not_detects("bearer_token_generic", "Bearer short");
}
