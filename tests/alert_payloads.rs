//! Alert payload tests: exactly what a channel would post, asserted with no
//! network in the loop.
//!
//! The alert layer used to hide its payload builders behind private functions and
//! a `reqwest` call, so the only way to observe a payload was an HTTP mock, and
//! the three channels drifted into three near-identical transports. Payloads are
//! now pure ([`AlertChannel::payload`]) and the transport is one function, so this
//! suite can pin the parts that actually matter:
//!
//! * the shape a chat consumer renders (Slack `text`, Teams `MessageCard`),
//! * the `min_confidence` filter, and the empty-findings case,
//! * configuration validation — unknown keys, no channel, bad threshold,
//! * and the security property: no channel invents a place for secret material
//!   to travel, so nothing raw reaches a chat channel and the webhook adds no
//!   field of its own.
//!
//! The last one is a regression guard, not a redaction test: redaction happens
//! upstream in the pipeline (see `tests/snippet_redaction.rs`). The finding below
//! deliberately carries a raw value in `snippet`, standing in for the leak the
//! pipeline used to produce, so that a channel which starts interpolating
//! `snippet` fails here.

use std::path::Path;

use jiraleaks::alert::{
    post_json, send_alerts, AlertChannel, AlertsConfig, SlackChannel, TeamsChannel, WebhookChannel,
};
use jiraleaks::finding::{
    Confidence, Finding, FindingStatus, Location, ScanRun, ScanStatus, Severity, SourceType,
};

use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A raw secret value. Nothing in this file may put it on the wire.
const RAW_SECRET: &str = "ghp_RAW0SecretMustNeverReachAWebhook";
/// A substring of [`RAW_SECRET`], so a truncation cannot satisfy the assertion.
const RAW_MARKER: &str = "MustNeverReachAWebhook";
/// The redacted preview the pipeline would attach to the finding above.
const REDACTED_PREVIEW: &str = "ghp_R********************ook";

/// Field names that would mean raw secret material is on the wire. `Finding` is a
/// closed struct today; this list guards the day a `matched_value`-style field is
/// added to it or to a payload.
const RAW_VALUE_KEYS: &[&str] = &[
    "match",
    "matched_value",
    "raw",
    "raw_secret",
    "raw_value",
    "secret",
    "value",
];

fn finding(rule_id: &str, issue_key: &str, confidence: Confidence) -> Finding {
    Finding {
        finding_id: "f-1".into(),
        issue_key: issue_key.into(),
        issue_url: format!("https://jira.example.com/browse/{issue_key}"),
        field_path: "fields.description".into(),
        rule_id: rule_id.into(),
        severity: Severity::High,
        confidence,
        // Redacted preview and a snippet that still holds raw material: the state
        // a channel must never amplify, whatever the pipeline hands it.
        redacted_secret: REDACTED_PREVIEW.into(),
        secret_hash: "sha256:deadbeef".into(),
        snippet: format!("token = {RAW_SECRET}"),
        detected_at: "2026-09-24T10:00:00Z".into(),
        scanner_version: "0.1.0".into(),
        locations: vec![Location {
            issue_key: issue_key.into(),
            field_path: "fields.description".into(),
            source_type: SourceType::Description,
        }],
        source_type: SourceType::Description,
        status: FindingStatus::New,
        username: None,
        references: Vec::new(),
        first_seen: None,
        times_seen: None,
        external_validation: None,
    }
}

fn scan_run() -> ScanRun {
    ScanRun {
        scan_id: "scan-1".into(),
        status: ScanStatus::Success,
        started_at: "2026-09-24T10:00:00Z".into(),
        finished_at: "2026-09-24T10:00:12Z".into(),
        jira_url: "https://jira.example.com".into(),
        jql: "project = SEC".into(),
        issues_scanned: 42,
        issues_total: 42,
        findings_total: 3,
        findings_critical: 0,
        findings_high: 2,
        findings_medium: 1,
        findings_low: 0,
        findings_info: 0,
        errors_total: 0,
        comments_scanned: 100,
        attachments_scanned: 5,
        scanner_version: "0.1.0".into(),
        duration_secs: 12.5,
    }
}

fn slack(min: Confidence) -> SlackChannel {
    SlackChannel::new("https://hooks.slack.com/services/SECRET/SECRET/SECRET", min)
}

fn teams(min: Confidence) -> TeamsChannel {
    TeamsChannel::new("https://outlook.office.com/webhook/SECRET", min)
}

fn webhook(min: Confidence) -> WebhookChannel {
    WebhookChannel::new("https://example.com/hook/SECRET", min)
}

/// Keys reachable anywhere in a JSON value.
fn keys_of(value: &serde_json::Value) -> Vec<String> {
    let mut keys = Vec::new();
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            serde_json::Value::Object(map) => {
                for (key, nested) in map {
                    keys.push(key.clone());
                    stack.push(nested);
                }
            }
            serde_json::Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    keys
}

fn assert_no_raw_value_key(payload: &serde_json::Value) {
    for key in keys_of(payload) {
        assert!(
            !RAW_VALUE_KEYS.contains(&key.as_str()),
            "payload exposes a raw-secret field `{key}`: {payload}"
        );
    }
}

// ---------------------------------------------------------------- Slack

#[test]
fn slack_payload_is_one_text_message_with_scan_counters() {
    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let payload = slack(Confidence::High).payload(&run, &findings);

    let object = payload.as_object().expect("payload is an object");
    assert_eq!(
        object.len(),
        1,
        "an incoming webhook takes a single text blob"
    );
    let text = payload["text"].as_str().expect("text is a string");

    assert!(text.contains("*Jira Secret Scanner — Scan Complete*"));
    assert!(text.contains("Status: *Success*"));
    assert!(text.contains("Issues: 42"));
    assert!(text.contains("Critical: 0 | High: 2 | Medium: 1 | Low: 0"));
    assert!(text.contains("Duration: 12.5s"));
    assert!(
        text.contains("github_token"),
        "the rule id identifies the finding"
    );
    assert!(text.contains("https://jira.example.com/browse/SEC-7"));
    assert!(text.contains("|SEC-7>"), "the issue key is the link label");
}

#[test]
fn slack_text_never_carries_secret_material() {
    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let payload = slack(Confidence::High).payload(&run, &findings);
    let text = payload["text"].as_str().expect("text is a string");

    assert!(
        !text.contains(RAW_MARKER),
        "raw secret material reached the Slack message"
    );
    assert!(
        !text.contains(REDACTED_PREVIEW),
        "even the redacted preview is withheld: chat history is outside the \
         scanner's retention control, the report is not"
    );
    assert_no_raw_value_key(&payload);
}

#[test]
fn slack_message_counts_the_findings_it_truncated() {
    let run = scan_run();
    let findings: Vec<Finding> = (0..12)
        .map(|i| finding("github_token", &format!("SEC-{i}"), Confidence::High))
        .collect();
    let payload = slack(Confidence::High).payload(&run, &findings);
    let text = payload["text"].as_str().expect("text is a string");

    assert!(text.contains("10: "), "the tenth finding is listed");
    assert!(!text.contains("11: "), "the eleventh is not");
    assert!(
        text.contains("... and 2 more"),
        "the remainder is stated: {text}"
    );
}

// ---------------------------------------------------------------- Teams

#[test]
fn teams_payload_is_a_message_card_with_scan_counters() {
    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let payload = teams(Confidence::High).payload(&run, &findings);

    assert_eq!(payload["@type"], "MessageCard");
    assert_eq!(payload["@context"], "https://schema.org/extensions");
    assert_eq!(payload["title"], "Jira Secret Scanner — Scan Complete");
    assert_eq!(payload["summary"], "Jira Secret Scanner: 3 findings");

    let text = payload["text"].as_str().expect("text is a string");
    assert!(text.contains("**Status:** Success"));
    assert!(text.contains("**Issues scanned:** 42"));
    assert!(text.contains("**Findings:** 3 total (Critical: 0, High: 2, Medium: 1, Low: 0)"));
    assert!(text.contains("**Duration:** 12.5s"));
    assert!(text.contains("[SEC-7](https://jira.example.com/browse/SEC-7)"));
}

#[test]
fn teams_text_never_carries_secret_material() {
    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let payload = teams(Confidence::High).payload(&run, &findings);

    assert!(!payload.to_string().contains(RAW_MARKER));
    assert!(!payload.to_string().contains(REDACTED_PREVIEW));
    assert_no_raw_value_key(&payload);
}

// ---------------------------------------------------------------- webhook

#[test]
fn webhook_payload_passes_scan_run_and_findings_through_untouched() {
    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let payload = webhook(Confidence::High).payload(&run, &findings);

    assert_eq!(payload["scanner"], "jiraleaks");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        payload["scan_run"],
        serde_json::to_value(&run).expect("run is serialisable")
    );
    assert_eq!(payload["findings_count"], 1);
    assert_eq!(
        payload["top_findings"][0],
        serde_json::to_value(&findings[0]).expect("finding is serialisable"),
        "a consumer parses exactly the finding type, no alert-shaped variant of it"
    );
}

#[test]
fn webhook_payload_adds_no_second_copy_of_secret_material() {
    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let payload = webhook(Confidence::High).payload(&run, &findings);

    // The finding's own serialisation is the only source of its fields; the alert
    // layer wraps it and duplicates nothing.
    let finding_json = serde_json::to_string(&findings[0]).expect("finding is serialisable");
    let payload_json = payload.to_string();
    assert_eq!(
        payload_json.matches(RAW_MARKER).count(),
        finding_json.matches(RAW_MARKER).count(),
        "the alert layer copied secret-bearing text outside the finding it was given"
    );
    assert_no_raw_value_key(&payload);
}

#[test]
fn webhook_top_findings_are_capped_and_counted() {
    let run = scan_run();
    let findings: Vec<Finding> = (0..25)
        .map(|i| finding("github_token", &format!("SEC-{i}"), Confidence::High))
        .collect();
    let payload = webhook(Confidence::High).payload(&run, &findings);

    assert_eq!(
        payload["findings_count"], 25,
        "the count describes the scan"
    );
    assert_eq!(
        payload["top_findings"].as_array().expect("array").len(),
        20,
        "the payload stays small; the report carries the rest"
    );
}

// ------------------------------------------------- min_confidence filtering

#[test]
fn min_confidence_filters_by_the_level_not_by_its_name() {
    let run = scan_run();
    let findings = vec![
        finding("high_rule", "SEC-1", Confidence::High),
        finding("medium_rule", "SEC-2", Confidence::Medium),
        finding("low_rule", "SEC-3", Confidence::Low),
    ];

    let channel_payloads: Vec<(&str, serde_json::Value)> = vec![
        ("slack", slack(Confidence::Medium).payload(&run, &findings)),
        ("teams", teams(Confidence::Medium).payload(&run, &findings)),
        (
            "webhook",
            webhook(Confidence::Medium).payload(&run, &findings),
        ),
    ];

    for (name, payload) in channel_payloads {
        let json = payload.to_string();
        assert!(json.contains("high_rule"), "{name} dropped a high finding");
        assert!(
            json.contains("medium_rule"),
            "{name} dropped a medium finding"
        );
        assert!(!json.contains("low_rule"), "{name} kept a low finding");
    }
}

#[test]
fn min_confidence_high_keeps_only_high_findings() {
    let run = scan_run();
    let findings = vec![
        finding("high_rule", "SEC-1", Confidence::High),
        finding("medium_rule", "SEC-2", Confidence::Medium),
        finding("low_rule", "SEC-3", Confidence::Low),
    ];
    let payload = slack(Confidence::High).payload(&run, &findings);
    let text = payload["text"].as_str().expect("text is a string");

    assert!(text.contains("high_rule"));
    assert!(!text.contains("medium_rule"));
    assert!(!text.contains("low_rule"));
}

#[test]
fn empty_findings_produce_a_valid_payload_for_every_channel() {
    let run = scan_run();
    let none: Vec<Finding> = Vec::new();

    let slack_payload = slack(Confidence::Low).payload(&run, &none);
    let slack_text = slack_payload["text"].as_str().expect("text is a string");
    assert!(slack_text.contains("Findings: *3* total"));
    assert!(!slack_text.contains("Top findings"));

    let teams_payload = teams(Confidence::Low).payload(&run, &none);
    assert!(!teams_payload["text"]
        .as_str()
        .expect("text is a string")
        .contains("Top findings"));

    let webhook_payload = webhook(Confidence::Low).payload(&run, &none);
    assert_eq!(webhook_payload["findings_count"], 0);
    assert_eq!(
        webhook_payload["top_findings"]
            .as_array()
            .expect("array")
            .len(),
        0
    );
}

// ------------------------------------------------------------- config

const README_YAML: &str = r#"
slack:   { webhook_url: "https://hooks.slack.com/services/T000/B000/XXXX" }
teams:   { webhook_url: "https://outlook.office.com/webhook/XXXX" }
webhook: { url: "https://example.com/hook" }
min_confidence: medium
"#;

fn channel_names(config: &AlertsConfig) -> Vec<&'static str> {
    config
        .channels()
        .expect("channels build")
        .iter()
        .map(|channel| channel.name())
        .collect()
}

/// The configuration error `config` must produce.
///
/// A helper rather than `expect_err`, because the success type is a trait object
/// and `expect_err` would require `dyn AlertChannel: Debug` — a bound the trait
/// deliberately does not carry (rendering a channel is a logging concern, and
/// every implementation masks its URL on its own).
#[track_caller]
fn channels_error(config: &AlertsConfig) -> jiraleaks::error::ScannerError {
    match config.channels() {
        Ok(channels) => panic!(
            "expected a configuration error, got {} usable channel(s)",
            channels.len()
        ),
        Err(error) => error,
    }
}

#[test]
fn readme_example_config_builds_every_channel_it_names() {
    let config = AlertsConfig::from_yaml(README_YAML).expect("the README example parses");
    assert_eq!(channel_names(&config), vec!["slack", "teams", "webhook"]);
    assert_eq!(
        config.min_confidence().expect("valid level"),
        Confidence::Medium
    );
}

#[test]
fn config_without_any_channel_is_an_error() {
    let config =
        AlertsConfig::from_yaml("min_confidence: high\n").expect("an empty document parses");
    let err = channels_error(&config);

    assert!(
        err.to_string().contains("no channel"),
        "the message must say what is missing: {err}"
    );
}

#[test]
fn invalid_min_confidence_is_an_error() {
    for level in ["urgent", "", "medium-high"] {
        let yaml = format!(
            "slack: {{ webhook_url: \"https://hooks.slack.com/x\" }}\nmin_confidence: \"{level}\"\n"
        );
        let config = AlertsConfig::from_yaml(&yaml).expect("the document parses");
        let err = channels_error(&config);
        assert!(
            err.to_string().contains("min_confidence"),
            "the message must name the offending key: {err}"
        );
    }
}

#[test]
fn min_confidence_defaults_to_medium() {
    let config = AlertsConfig::from_yaml("webhook: { url: \"https://example.com/hook\" }\n")
        .expect("a config may omit min_confidence");
    assert_eq!(
        config.min_confidence().expect("valid level"),
        Confidence::Medium
    );
}

#[test]
fn unknown_config_keys_are_rejected() {
    let cases = [
        // A typo at the top level would otherwise disable a channel silently.
        "slacks: { webhook_url: \"https://hooks.slack.com/x\" }",
        // A typo inside a channel is the same failure one level down.
        "slack: { url: \"https://hooks.slack.com/x\" }",
        "teams: { webhook_url: \"https://outlook.office.com/x\", channel: \"#sec\" }",
        "webhook: { url: \"https://example.com/hook\", headers: { X: \"1\" } }",
        "min_confidence: high\nmax_findings: 5",
    ];

    for yaml in cases {
        let err = AlertsConfig::from_yaml(yaml).expect_err("an unknown key must not be ignored");
        let message = err.to_string();
        assert!(
            message.contains("unknown field"),
            "serde must name the unknown key in {yaml:?}: {message}"
        );
    }
}

#[test]
fn blank_channel_url_is_an_error() {
    let config = AlertsConfig::from_yaml("webhook: { url: \"   \" }").expect("the document parses");
    let err = channels_error(&config);
    assert!(err.to_string().contains("URL is empty"), "{err}");
}

#[test]
fn alerts_config_load_reads_the_file_and_reports_a_missing_one() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("jiraleaks-alerts-{}.yaml", uuid::Uuid::new_v4()));
    std::fs::write(&path, README_YAML).expect("temp config is writable");

    let config = AlertsConfig::load(&path).expect("the README example loads from disk");
    assert_eq!(channel_names(&config), vec!["slack", "teams", "webhook"]);

    std::fs::remove_file(&path).expect("temp config is removable");

    let err = AlertsConfig::load(Path::new("/nonexistent/alerts.yaml"))
        .expect_err("a missing config file is a configuration error");
    assert!(
        err.to_string().contains("Failed to read alerts config"),
        "{err}"
    );
}

#[test]
fn no_channel_renders_or_transmits_its_webhook_url() {
    let run = scan_run();
    let none: Vec<Finding> = Vec::new();

    // A webhook URL is a bearer secret: whoever holds it can post to the channel.
    // It must reach neither a log line nor the payload a chat consumer stores.
    let rendered = [
        ("slack", format!("{:?}", slack(Confidence::Low))),
        ("teams", format!("{:?}", teams(Confidence::Low))),
        ("webhook", format!("{:?}", webhook(Confidence::Low))),
    ];
    for (name, debug) in rendered {
        assert!(
            !debug.contains("SECRET"),
            "{name} leaked its URL through Debug: {debug}"
        );
    }

    let payloads = [
        ("slack", slack(Confidence::Low).payload(&run, &none)),
        ("teams", teams(Confidence::Low).payload(&run, &none)),
        ("webhook", webhook(Confidence::Low).payload(&run, &none)),
    ];
    for (name, payload) in payloads {
        assert!(
            !payload.to_string().contains("SECRET"),
            "{name} put its URL into the payload: {payload}"
        );
    }

    let config = AlertsConfig::from_yaml(README_YAML).expect("parses");
    assert!(!format!("{config:?}").contains("hooks.slack.com"));
}

// --------------------------------------------------------- transport

#[tokio::test]
async fn send_alerts_attempts_every_channel_and_never_fails_the_scan() {
    let accepted = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&accepted)
        .await;

    let rejected = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&rejected)
        .await;

    // Nothing listens on port 1, so this channel fails without leaving the
    // machine — the "dead webhook" the README promises cannot fail a scan.
    let yaml = format!(
        "slack:   {{ webhook_url: \"{}/slack\" }}\n\
         teams:   {{ webhook_url: \"{}/teams\" }}\n\
         webhook: {{ url: \"http://127.0.0.1:1/dead\" }}\n\
         min_confidence: low\n",
        accepted.uri(),
        rejected.uri(),
    );

    let path = std::env::temp_dir().join(format!("jiraleaks-alerts-{}.yaml", uuid::Uuid::new_v4()));
    std::fs::write(&path, &yaml).expect("temp config is writable");

    let run = scan_run();
    let findings = vec![finding("github_token", "SEC-7", Confidence::High)];
    let config_path = path.clone();
    let outcome = tokio::task::spawn_blocking(move || send_alerts(&config_path, &run, &findings))
        .await
        .expect("the delivery task does not panic");
    std::fs::remove_file(&path).expect("temp config is removable");

    assert!(
        outcome.is_ok(),
        "two dead channels must not become a scan failure: {outcome:?}"
    );

    // Every configured channel was attempted, not just the first.
    let slack_requests = accepted.received_requests().await.expect("slack requests");
    assert_eq!(slack_requests.len(), 1);
    let body: serde_json::Value =
        serde_json::from_slice(&slack_requests[0].body).expect("the body is JSON");
    assert!(
        body["text"]
            .as_str()
            .expect("slack text")
            .contains("github_token"),
        "the channel posted its own payload: {body}"
    );

    let teams_requests = rejected.received_requests().await.expect("teams requests");
    assert_eq!(teams_requests.len(), 1);
    let body: serde_json::Value =
        serde_json::from_slice(&teams_requests[0].body).expect("the body is JSON");
    assert_eq!(body["@type"], "MessageCard");
}

#[tokio::test]
async fn transport_posts_json_and_treats_only_2xx_as_delivered() {
    let accepted = MockServer::start().await;
    // The `content-type` matcher is part of the assertion: a request without
    // `Content-Type: application/json` does not match and the mock answers 404.
    Mock::given(method("POST"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&accepted)
        .await;

    let payload = serde_json::json!({ "text": "scan complete" });
    let url = format!("{}/SECRET-PATH-TOKEN", accepted.uri());
    let ok = deliver("slack", url, payload.clone()).await;
    assert!(ok.is_ok(), "2xx is a delivery: {ok:?}");

    let rejected = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&rejected)
        .await;

    let url = format!("{}/SECRET-PATH-TOKEN", rejected.uri());
    let err = deliver("slack", url, payload)
        .await
        .expect_err("500 is not a delivery");
    let message = err.to_string();
    assert!(
        message.contains("HTTP 500"),
        "the status is reported: {message}"
    );
    assert!(
        message.contains("slack"),
        "the channel is reported: {message}"
    );
    assert!(
        !message.contains("SECRET-PATH-TOKEN"),
        "the error leaked the webhook URL: {message}"
    );
}

#[tokio::test]
async fn transport_reports_a_dead_endpoint_without_its_url() {
    // Nothing listens on port 1: the connection is refused locally, no traffic
    // leaves the machine.
    let url = "http://127.0.0.1:1/SECRET-PATH-TOKEN";
    let err = deliver("teams", url.to_string(), serde_json::json!({"text": "x"}))
        .await
        .expect_err("an unreachable endpoint is a delivery failure");

    let message = err.to_string();
    assert!(message.contains("teams alert"), "{message}");
    assert!(
        !message.contains("SECRET-PATH-TOKEN"),
        "reqwest quotes the URL in its own errors; it must not reach ours: {message}"
    );
}

/// Call the blocking transport the way the scan does — off the async worker.
async fn deliver(
    channel: &'static str,
    url: String,
    payload: serde_json::Value,
) -> Result<(), jiraleaks::error::ScannerError> {
    tokio::task::spawn_blocking(move || post_json(channel, &url, &payload))
        .await
        .expect("the transport task does not panic")
}
