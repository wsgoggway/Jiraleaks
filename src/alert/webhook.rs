//! Generic webhook channel: posts machine-readable JSON to a SIEM, DefectDojo or
//! any other consumer.
//!
//! Unlike the chat channels, this payload carries whole [`Finding`]s, so its
//! security property is different: it adds *nothing* to a finding. Whatever the
//! finding type exposes is what goes on the wire, which keeps the guarantee
//! "raw secrets are never persisted or transmitted" a property of the finding
//! (redaction happens upstream, in the pipeline) rather than of this sink.

use crate::finding::{Confidence, Finding, ScanRun};

use super::{filter_by_confidence, AlertChannel};

/// Findings embedded in the payload. A webhook consumer pulls the full set from
/// the report; the alert only has to wake it up.
const TOP_FINDINGS: usize = 20;

/// A generic JSON webhook destination.
///
/// The URL is a bearer secret; `Debug` masks it so an accidental `info!(?chan)`
/// cannot leak it into a log.
pub struct WebhookChannel {
    url: String,
    min_confidence: Confidence,
}

impl WebhookChannel {
    /// Build a channel that posts findings at or above `min_confidence`.
    pub fn new(url: impl Into<String>, min_confidence: Confidence) -> Self {
        Self {
            url: url.into(),
            min_confidence,
        }
    }
}

impl std::fmt::Debug for WebhookChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookChannel")
            .field("url", &"***")
            .field("min_confidence", &self.min_confidence)
            .finish()
    }
}

impl AlertChannel for WebhookChannel {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn endpoint(&self) -> &str {
        &self.url
    }

    fn payload(&self, scan_run: &ScanRun, findings: &[Finding]) -> serde_json::Value {
        let visible = filter_by_confidence(findings, self.min_confidence);
        serde_json::json!({
            "scanner": "jiraleaks",
            "version": env!("CARGO_PKG_VERSION"),
            "scan_run": scan_run,
            "findings_count": visible.len(),
            "top_findings": visible.iter().take(TOP_FINDINGS).collect::<Vec<_>>(),
        })
    }
}
