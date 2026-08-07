use std::process::ExitCode;

use thiserror::Error;

/// Central error enum for the scanner.
/// Each variant maps to a specific exit code per spec §15.
#[derive(Error, Debug)]
pub enum ScannerError {
    /// Configuration error (exit 1): missing required fields, invalid values, bad config file.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Jira access error (exit 2): auth failure (401/403), unreachable host.
    #[error("Jira access error: {0}")]
    JiraAccess(String),

    /// Critical scan error (exit 3): fatal error during scanning that prevents continuation.
    #[error("Scan critical error: {0}")]
    ScanCritical(String),

    /// Report write error (exit 4): cannot write the output report.
    #[error("Report write error: {0}")]
    ReportWrite(String),

    /// Non-critical error: logged but scan continues.
    #[error("Non-critical: {0}")]
    Other(String),

    /// Store/persistence error: DB open, migration, reconcile failure.
    #[error("Store error: {0}")]
    Store(String),
}

impl ScannerError {
    /// Maps the error variant to the corresponding exit code per spec §15.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            ScannerError::Config(_) => ExitCode::from(1),
            ScannerError::JiraAccess(_) => ExitCode::from(2),
            ScannerError::ScanCritical(_) => ExitCode::from(3),
            ScannerError::ReportWrite(_) => ExitCode::from(4),
            ScannerError::Store(_) => ExitCode::from(5),
            ScannerError::Other(_) => ExitCode::from(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        // ExitCode::from(1) == ExitCode::from(1) works via PartialEq
        assert_eq!(ScannerError::Config("x".into()).exit_code(), ExitCode::from(1));
        assert_eq!(ScannerError::JiraAccess("x".into()).exit_code(), ExitCode::from(2));
        assert_eq!(ScannerError::ScanCritical("x".into()).exit_code(), ExitCode::from(3));
        assert_eq!(ScannerError::ReportWrite("x".into()).exit_code(), ExitCode::from(4));
        assert_eq!(ScannerError::Other("x".into()).exit_code(), ExitCode::from(0));
        assert_eq!(ScannerError::Store("x".into()).exit_code(), ExitCode::from(5));
    }
}
