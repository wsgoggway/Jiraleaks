use std::fs;
use std::path::Path;

use crate::error::ScannerError;
use crate::report::ReportInput;

/// Write findings as a single JSON object: `{ scan_run, findings }`.
pub fn write(path: &Path, input: &ReportInput<'_>) -> Result<(), ScannerError> {
    let output = serde_json::json!({
        "scan_run": input.scan_run,
        "findings": input.findings,
    });

    let json_str = serde_json::to_string_pretty(&output)
        .map_err(|e| ScannerError::ReportWrite(format!("JSON serialization error: {e}")))?;

    fs::write(path, json_str)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to write JSON report: {e}")))?;

    Ok(())
}
