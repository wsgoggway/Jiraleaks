use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Send findings to a generic webhook (SIEM, DefectDojo, etc.).
pub fn send(
    url: &str,
    scan_run: &ScanRun,
    findings: &[&Finding],
) -> Result<(), ScannerError> {
    let client = reqwest::blocking::Client::new();
    let payload = serde_json::json!({
        "scanner": "jiraleaks",
        "version": env!("CARGO_PKG_VERSION"),
        "scan_run": scan_run,
        "findings_count": findings.len(),
        "top_findings": findings.iter().take(20).collect::<Vec<_>>(),
    });

    match client
        .post(url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
    {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::info!("Webhook alert sent successfully");
            } else {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    "Webhook returned non-success status"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to send webhook alert");
        }
    }

    Ok(())
}
