//! Microsoft Teams channel: posts a legacy `MessageCard` to an Office 365
//! incoming webhook.
//!
//! Teams renders the card's `text` as Markdown, so the body is built by
//! [`message`] — pure, and tested directly (see `tests/alert_payloads.rs`).

use crate::finding::{Confidence, Finding, ScanRun};

use super::{filter_by_confidence, AlertChannel};

/// Findings listed on the card; a Teams card has a hard size limit and the alert
/// is a summary that links back to the report.
const TOP_FINDINGS: usize = 10;

/// A Microsoft Teams incoming-webhook destination.
///
/// The URL is a bearer secret; `Debug` masks it so an accidental `info!(?chan)`
/// cannot leak it into a log.
pub struct TeamsChannel {
    webhook_url: String,
    min_confidence: Confidence,
}

impl TeamsChannel {
    /// Build a channel that posts findings at or above `min_confidence`.
    pub fn new(webhook_url: impl Into<String>, min_confidence: Confidence) -> Self {
        Self {
            webhook_url: webhook_url.into(),
            min_confidence,
        }
    }
}

impl std::fmt::Debug for TeamsChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamsChannel")
            .field("webhook_url", &"***")
            .field("min_confidence", &self.min_confidence)
            .finish()
    }
}

impl AlertChannel for TeamsChannel {
    fn name(&self) -> &'static str {
        "teams"
    }

    fn endpoint(&self) -> &str {
        &self.webhook_url
    }

    fn payload(&self, scan_run: &ScanRun, findings: &[Finding]) -> serde_json::Value {
        let visible = filter_by_confidence(findings, self.min_confidence);
        serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": format!("Jira Secret Scanner: {} findings", scan_run.findings_total),
            "title": "Jira Secret Scanner — Scan Complete",
            "text": message(scan_run, &visible),
        })
    }
}

/// The Markdown body of the card: scan counters plus linked top findings.
///
/// As in the Slack builder, only redacted, already-public fields reach the text.
fn message(scan_run: &ScanRun, findings: &[&Finding]) -> String {
    let mut msg = String::new();
    msg.push_str(&format!("**Status:** {:?}  \n", scan_run.status));
    msg.push_str(&format!(
        "**Issues scanned:** {}  \n",
        scan_run.issues_scanned
    ));
    msg.push_str(&format!(
        "**Findings:** {} total (Critical: {}, High: {}, Medium: {}, Low: {})  \n",
        scan_run.findings_total,
        scan_run.findings_critical,
        scan_run.findings_high,
        scan_run.findings_medium,
        scan_run.findings_low,
    ));
    msg.push_str(&format!("**Duration:** {:.1}s  \n", scan_run.duration_secs));

    if !findings.is_empty() {
        msg.push_str("\n**Top findings:**  \n");
        for f in findings.iter().take(TOP_FINDINGS) {
            msg.push_str(&format!(
                "- {:?} `{}` — [{}]({})  \n",
                f.severity, f.rule_id, f.issue_key, f.issue_url,
            ));
        }
    }

    msg
}
