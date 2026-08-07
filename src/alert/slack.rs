use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Send findings summary to a Slack webhook.
pub fn send(
    webhook_url: &str,
    scan_run: &ScanRun,
    findings: &[&Finding],
) -> Result<(), ScannerError> {
    let text = build_slack_message(scan_run, findings);

    // Fire-and-forget: log errors but don't fail the scan
    let client = reqwest::blocking::Client::new();
    let payload = serde_json::json!({
        "text": text,
    });

    match client
        .post(webhook_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
    {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::info!("Slack alert sent successfully");
            } else {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    "Slack webhook returned non-success status"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to send Slack alert");
        }
    }

    Ok(())
}

fn build_slack_message(scan_run: &ScanRun, findings: &[&Finding]) -> String {
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
        for (i, f) in findings.iter().take(10).enumerate() {
            msg.push_str(&format!(
                "{}: {:?} `{}` — <{}|{}> \n",
                i + 1,
                f.severity,
                f.rule_id,
                f.issue_url,
                f.issue_key,
            ));
        }
        if findings.len() > 10 {
            msg.push_str(&format!("... and {} more\n", findings.len() - 10));
        }
    }

    msg
}
