use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::ScannerError;
use crate::report::ReportInput;

/// Write findings as newline-delimited JSON (one finding per line).
pub fn write(path: &Path, input: &ReportInput<'_>) -> Result<(), ScannerError> {
    let mut file = fs::File::create(path)
        .map_err(|e| ScannerError::ReportWrite(format!("Failed to create NDJSON file: {e}")))?;

    for finding in input.findings {
        let line = serde_json::to_string(finding)
            .map_err(|e| ScannerError::ReportWrite(format!("NDJSON serialization error: {e}")))?;
        writeln!(file, "{line}")
            .map_err(|e| ScannerError::ReportWrite(format!("NDJSON write error: {e}")))?;
    }

    Ok(())
}
