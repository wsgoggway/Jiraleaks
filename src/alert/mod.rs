pub mod slack;
pub mod teams;
pub mod webhook;

use std::path::Path;

use serde::Deserialize;

use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Alert configuration loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TeamsConfig {
    pub webhook_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
}

fn default_min_confidence() -> String {
    "medium".into()
}

/// Load alerts config and send to all configured destinations.
pub fn send_alerts(
    alerts_path: &Path,
    scan_run: &ScanRun,
    findings: &[Finding],
) -> Result<(), ScannerError> {
    let yaml = std::fs::read_to_string(alerts_path).map_err(|e| {
        ScannerError::Config(format!(
            "Failed to read alerts config {}: {e}",
            alerts_path.display()
        ))
    })?;

    let config: AlertsConfig = serde_yaml::from_str(&yaml)
        .map_err(|e| ScannerError::Config(format!("Failed to parse alerts config: {e}")))?;

    // Filter findings by min_confidence
    let min_conf = match config.min_confidence.as_str() {
        "high" => crate::pipeline::parse_confidence("high"),
        "medium" => crate::pipeline::parse_confidence("medium"),
        _ => crate::pipeline::parse_confidence("low"),
    };

    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            let fc = match f.confidence {
                crate::finding::Confidence::High => crate::pipeline::parse_confidence("high"),
                crate::finding::Confidence::Medium => crate::pipeline::parse_confidence("medium"),
                crate::finding::Confidence::Low => crate::pipeline::parse_confidence("low"),
            };
            fc >= min_conf
        })
        .collect();

    // Send to Slack
    if let Some(ref slack_cfg) = config.slack {
        slack::send(&slack_cfg.webhook_url, scan_run, &filtered)?;
    }

    // Send to Teams
    if let Some(ref teams_cfg) = config.teams {
        teams::send(&teams_cfg.webhook_url, scan_run, &filtered)?;
    }

    // Send to generic webhook
    if let Some(ref webhook_cfg) = config.webhook {
        webhook::send(&webhook_cfg.url, scan_run, &filtered)?;
    }

    Ok(())
}
