//! Slack channel: posts one mrkdwn `text` blob to a Slack incoming webhook.
//!
//! The payload is a single `text` field because that is what an incoming webhook
//! renders without an app manifest; the message body is built by [`message`],
//! which is pure and therefore tested directly (see `tests/alert_payloads.rs`).

use crate::finding::{Confidence, Finding, ScanRun};

use super::{filter_by_confidence, AlertChannel};

/// Findings listed in the message body. Slack truncates oversized messages, and
/// an alert is a summary that links back to the report — not a report.
const TOP_FINDINGS: usize = 10;

/// A Slack incoming-webhook destination.
///
/// The URL is a bearer secret; `Debug` masks it so an accidental `info!(?chan)`
/// cannot leak it into a log.
pub struct SlackChannel {
    webhook_url: String,
    min_confidence: Confidence,
}

impl SlackChannel {
    /// Build a channel that posts findings at or above `min_confidence`.
    pub fn new(webhook_url: impl Into<String>, min_confidence: Confidence) -> Self {
        Self {
            webhook_url: webhook_url.into(),
            min_confidence,
        }
    }
}

impl std::fmt::Debug for SlackChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackChannel")
            .field("webhook_url", &"***")
            .field("min_confidence", &self.min_confidence)
            .finish()
    }
}

impl AlertChannel for SlackChannel {
    fn name(&self) -> &'static str {
        "slack"
    }

    fn endpoint(&self) -> &str {
        &self.webhook_url
    }

    fn payload(&self, scan_run: &ScanRun, findings: &[Finding]) -> serde_json::Value {
        let visible = filter_by_confidence(findings, self.min_confidence);
        serde_json::json!({ "text": message(scan_run, &visible) })
    }
}

/// The mrkdwn body: scan counters plus the top findings as linked lines.
///
/// Only redacted, already-public fields are interpolated — severity, rule id,
/// issue key and the Jira URL. The secret never enters the message, not even in
/// its redacted form, because the alert is the one sink with no retention
/// policy the scanner controls.
fn message(scan_run: &ScanRun, findings: &[&Finding]) -> String {
    let mut msg = String::new();
    msg.push_str("*Jira Secret Scanner — Scan Complete*\n");
    msg.push_str(&format!(
        "Status: *{:?}* | Issues: {} | Duration: {:.1}s\n",
        scan_run.status, scan_run.issues_scanned, scan_run.duration_secs
    ));
    msg.push_str(&format!(
        "Findings: *{}* total | Critical: {} | High: {} | Medium: {} | Low: {}\n",
        scan_run.findings_total,
        scan_run.findings_critical,
        scan_run.findings_high,
        scan_run.findings_medium,
        scan_run.findings_low,
    ));

    if !findings.is_empty() {
        msg.push_str("\n*Top findings:*\n");
        for (i, f) in findings.iter().take(TOP_FINDINGS).enumerate() {
            msg.push_str(&format!(
                "{}: {:?} `{}` — <{}|{}> \n",
                i + 1,
                f.severity,
                f.rule_id,
                f.issue_url,
                f.issue_key,
            ));
        }
        if findings.len() > TOP_FINDINGS {
            msg.push_str(&format!("... and {} more\n", findings.len() - TOP_FINDINGS));
        }
    }

    msg
}
