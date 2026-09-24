//! Alert delivery: one transport, one payload builder per channel.
//!
//! The layer is split along the seam that makes it testable:
//!
//! * a channel owns its destination and *builds* its payload — pure, no I/O and
//!   no clock — so a test asserts the JSON a channel would post without any
//!   network mock (`tests/alert_payloads.rs`);
//! * [`post_json`] is the single transport: one timeout, one status check and
//!   one failure shape shared by every channel, instead of three copies.
//!
//! Delivery is fire-and-forget by contract (README: "a failed webhook never
//! fails the scan"): a channel that cannot be reached is logged with the exact
//! delivered/failed counts and the scan continues. Only a broken
//! *configuration* — unreadable file, unknown key, no channel, invalid
//! `min_confidence` — is returned as [`ScannerError::Config`].

pub mod slack;
pub mod teams;
pub mod webhook;

pub use slack::SlackChannel;
pub use teams::TeamsChannel;
pub use webhook::WebhookChannel;

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::error::ScannerError;
use crate::finding::{Confidence, Finding, ScanRun};

/// Timeout of one alert POST. Alerts are best-effort: an unresponsive webhook
/// must not hold the scan open longer than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Marker left in `Debug` output where a webhook URL would have been.
const MASKED_URL: &str = "***";

/// One alert destination.
///
/// [`AlertChannel::payload`] is pure — no I/O, no clock — which is what lets
/// every channel's payload be asserted directly. Sending is [`post_json`]'s job,
/// and it is the only place in the module that touches the network.
pub trait AlertChannel: Send + Sync {
    /// Short channel name used in logs. Never the URL.
    fn name(&self) -> &'static str;

    /// Destination URL.
    ///
    /// A Slack or Teams webhook URL is a bearer secret — whoever holds it can
    /// post to the channel — so it is never logged and never rendered by
    /// `Debug` (see the channel types).
    fn endpoint(&self) -> &str;

    /// Payload is pure: no I/O — that is what makes it testable.
    ///
    /// An implementation filters [`Finding`]s by its own `min_confidence` and
    /// copies nothing but the redacted fields its payload format needs.
    fn payload(&self, scan_run: &ScanRun, findings: &[Finding]) -> serde_json::Value;
}

/// Alert configuration loaded from YAML.
///
/// Unknown keys are rejected: a typo in `webhook_url` would otherwise disable a
/// channel silently, and the operator would learn about it from the incident,
/// not from the config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    #[serde(default)]
    pub slack: Option<SlackConfig>,
    #[serde(default)]
    pub teams: Option<TeamsConfig>,
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackConfig {
    pub webhook_url: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamsConfig {
    pub webhook_url: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
}

// The nested config types mask their URL in `Debug` for the same reason
// `config::Config` masks the Jira token: a `info!(?config)` must never write a
// live webhook URL into a log file.

impl std::fmt::Debug for SlackConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackConfig")
            .field("webhook_url", &MASKED_URL)
            .finish()
    }
}

impl std::fmt::Debug for TeamsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamsConfig")
            .field("webhook_url", &MASKED_URL)
            .finish()
    }
}

impl std::fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &MASKED_URL)
            .finish()
    }
}

fn default_min_confidence() -> String {
    "medium".into()
}

impl AlertsConfig {
    /// Parse an alerts config from YAML text.
    pub fn from_yaml(yaml: &str) -> Result<Self, ScannerError> {
        serde_yaml::from_str(yaml)
            .map_err(|e| ScannerError::Config(format!("Failed to parse alerts config: {e}")))
    }

    /// Read and parse the alerts config at `path`.
    pub fn load(path: &Path) -> Result<Self, ScannerError> {
        let yaml = std::fs::read_to_string(path).map_err(|e| {
            ScannerError::Config(format!(
                "Failed to read alerts config {}: {e}",
                path.display()
            ))
        })?;
        Self::from_yaml(&yaml)
    }

    /// Confidence threshold every channel filters on, defaulting to `medium`.
    ///
    /// An unrecognised value is a configuration error rather than a silent
    /// fallback: a typo read as `low` would push every low-confidence finding to
    /// a production channel, and one read as `high` would silently withhold a
    /// real alert.
    pub fn min_confidence(&self) -> Result<Confidence, ScannerError> {
        let raw = self.min_confidence.trim();
        match raw.to_ascii_lowercase().as_str() {
            "low" | "medium" | "high" => Ok(Confidence::parse(raw)),
            _ => Err(ScannerError::Config(format!(
                "alerts config: invalid min_confidence {raw:?} (expected low, medium or high)"
            ))),
        }
    }

    /// Build the channels this config defines, in a fixed order (slack, teams,
    /// webhook).
    ///
    /// A config that names no channel is an error, not a no-op: `--alerts` with
    /// an empty file would otherwise fail silently at the one moment an operator
    /// is waiting for a notification.
    pub fn channels(&self) -> Result<Vec<Box<dyn AlertChannel>>, ScannerError> {
        let min_confidence = self.min_confidence()?;
        let mut channels: Vec<Box<dyn AlertChannel>> = Vec::new();

        if let Some(ref slack) = self.slack {
            channels.push(Box::new(SlackChannel::new(
                require_url("slack", &slack.webhook_url)?,
                min_confidence,
            )));
        }
        if let Some(ref teams) = self.teams {
            channels.push(Box::new(TeamsChannel::new(
                require_url("teams", &teams.webhook_url)?,
                min_confidence,
            )));
        }
        if let Some(ref webhook) = self.webhook {
            channels.push(Box::new(WebhookChannel::new(
                require_url("webhook", &webhook.url)?,
                min_confidence,
            )));
        }

        if channels.is_empty() {
            return Err(ScannerError::Config(
                "alerts config: no channel configured (set at least one of `slack`, `teams`, \
                 `webhook`)"
                    .to_string(),
            ));
        }

        Ok(channels)
    }
}

/// Reject a blank channel URL before the scan, not per finding at send time.
fn require_url<'a>(label: &str, url: &'a str) -> Result<&'a str, ScannerError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ScannerError::Config(format!(
            "alerts config: {label} URL is empty"
        )));
    }
    Ok(trimmed)
}

/// Findings at or above `min` confidence, in input order.
///
/// One comparison of [`Confidence`]'s own [`Ord`] — the filter used to round-trip
/// the level through a string only because it was written that way.
pub(crate) fn filter_by_confidence(findings: &[Finding], min: Confidence) -> Vec<&Finding> {
    findings.iter().filter(|f| f.confidence >= min).collect()
}

/// POST one JSON payload to one alert destination.
///
/// The single transport of the alert layer, so the timeout, the success check
/// and the error shape cannot drift apart between channels. `.json()` serialises
/// the body and sets `Content-Type: application/json`.
///
/// The URL never appears in the returned error and is never logged: a Slack or
/// Teams webhook URL is a bearer secret, and `reqwest`'s own `Display` quotes the
/// request URL — hence the classification below instead of the raw error.
pub fn post_json(
    channel: &str,
    url: &str,
    payload: &serde_json::Value,
) -> Result<(), ScannerError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| {
            ScannerError::Other(format!("{channel} alert: cannot build HTTP client: {e}"))
        })?;

    // `.json()` serialises the body and sets `Content-Type: application/json`
    // when the request does not already carry one; it is infallible here, and a
    // serialisation failure would surface from `send()` as a builder error.
    let response =
        client.post(url).json(payload).send().map_err(|e| {
            ScannerError::Other(format!("{channel} alert: {}", transport_failure(&e)))
        })?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ScannerError::Other(format!(
            "{channel} alert: webhook returned HTTP {}",
            status.as_u16()
        )))
    }
}

/// Classify a transport failure without its URL, for the reason stated on
/// [`post_json`].
fn transport_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "too many redirects"
    } else if error.is_body() || error.is_decode() {
        "invalid response body"
    } else if error.is_builder() {
        "invalid request"
    } else {
        "transport error"
    }
}

/// Send one payload per channel, in parallel, returning one outcome per channel.
///
/// Scoped OS threads rather than `tokio::task::JoinSet`: [`send_alerts`] is a
/// synchronous function whose signature is frozen by `pipeline::run`, and driving
/// an async `JoinSet` from it would need a runtime handle and a nested
/// `block_on` — which panics inside the runtime already running there. The
/// transport is the blocking client either way, so one thread per channel is the
/// smallest honest change: alert delivery is one POST per channel, not a workload
/// that wants a scheduler. Parallel rather than sequential so a dead destination
/// costs one timeout, not one timeout per channel.
fn deliver_all(
    channels: &[Box<dyn AlertChannel>],
    scan_run: &ScanRun,
    findings: &[Finding],
) -> Vec<(&'static str, Result<(), ScannerError>)> {
    let names: Vec<&'static str> = channels.iter().map(|channel| channel.name()).collect();

    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = channels
            .iter()
            .map(|channel| {
                scope.spawn(move || {
                    let payload = channel.payload(scan_run, findings);
                    post_json(channel.name(), channel.endpoint(), &payload)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });

    names
        .into_iter()
        .zip(outcomes)
        .map(|(name, outcome)| match outcome {
            // A panicking channel must not lose its sibling's delivery, and it
            // must not lose the count either: report it as that channel's failure.
            Ok(result) => (name, result),
            Err(_) => (
                name,
                Err(ScannerError::Other(format!(
                    "{name} alert: payload construction panicked"
                ))),
            ),
        })
        .collect()
}

/// Load the alerts config at `alerts_path` and send the scan summary to every
/// configured channel.
///
/// Only configuration problems come back as an `Err`; delivery is
/// fire-and-forget by contract, so an unreachable webhook is logged with the
/// exact delivered/failed counts and the scan continues.
pub fn send_alerts(
    alerts_path: &Path,
    scan_run: &ScanRun,
    findings: &[Finding],
) -> Result<(), ScannerError> {
    let config = AlertsConfig::load(alerts_path)?;
    let channels = config.channels()?;

    let results = deliver_all(&channels, scan_run, findings);
    let failed = results.iter().filter(|(_, result)| result.is_err()).count();
    for (name, result) in &results {
        if let Err(error) = result {
            // Name and outcome only: the URL is the secret, the counts are below.
            tracing::warn!(channel = name, error = %error, "Alert delivery failed");
        }
    }

    if failed == 0 {
        tracing::info!(delivered = results.len(), "Alerts delivered");
    } else {
        tracing::warn!(
            delivered = results.len() - failed,
            failed,
            "Alert delivery finished with failures"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const README_YAML: &str = r#"
slack:   { webhook_url: "https://hooks.slack.com/services/T000/B000/XXXX" }
teams:   { webhook_url: "https://outlook.office.com/webhook/XXXX" }
webhook: { url: "https://example.com/hook" }
min_confidence: medium
"#;

    #[test]
    fn readme_example_yields_the_three_channels() {
        let config = AlertsConfig::from_yaml(README_YAML).expect("README example parses");
        let channels = config.channels().expect("channels build");
        let names: Vec<&str> = channels.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["slack", "teams", "webhook"]);
        assert_eq!(
            config.min_confidence().expect("valid level"),
            Confidence::Medium
        );
    }

    #[test]
    fn channel_names_are_lowercase_log_keys() {
        for channel in AlertsConfig::from_yaml(README_YAML)
            .expect("parses")
            .channels()
            .expect("builds")
        {
            assert_eq!(channel.name(), channel.name().to_lowercase());
            assert!(!channel.name().is_empty());
        }
    }
}
