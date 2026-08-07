use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Send findings summary to Microsoft Teams webhook.
pub fn send(
    webhook_url: &str,
    scan_run: &ScanRun,
    findings: &[&Finding],
) -> Result<(), ScannerError> {
    let text = build_teams_message(scan_run, findings);

    let client = reqwest::blocking::Client::new();
    let payload = serde_json::json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": format!("Jira Secret Scanner: {} findings", scan_run.findings_total),
        "title": "Jira Secret Scanner — Scan Complete",
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
                tracing::info!("Teams alert sent successfully");
            } else {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    "Teams webhook returned non-success status"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to send Teams alert");
        }
    }

    Ok(())
}

fn build_teams_message(scan_run: &ScanRun, findings: &[&Finding]) -> String {
    let mut msg = String::new();
    msg.push_str(&format!(
        "**Status:** {:?}  \n", scan_run.status
    ));
    msg.push_str(&format!(
        "**Issues scanned:** {}  \n", scan_run.issues_scanned
    ));
    msg.push_str(&format!(
        "**Findings:** {} total (Critical: {}, High: {}, Medium: {}, Low: {})  \n",
        scan_run.findings_total,
        scan_run.findings_critical,
        scan_run.findings_high,
        scan_run.findings_medium,
        scan_run.findings_low,
    ));
    msg.push_str(&format!(
        "**Duration:** {:.1}s  \n",
        scan_run.duration_secs
    ));

    if !findings.is_empty() {
        msg.push_str("\n**Top findings:**  \n");
        for f in findings.iter().take(10) {
            msg.push_str(&format!(
                "- {:?} `{}` — [{}]({})  \n",
                f.severity, f.rule_id, f.issue_key, f.issue_url,
            ));
        }
    }

    msg
}
