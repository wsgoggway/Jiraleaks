use thiserror::Error;

/// Central error enum for the scanner.
/// Each variant maps to a specific exit code per spec §15.
#[derive(Error, Debug)]
pub enum ScannerError {
    /// Configuration error (exit 1): missing required fields, invalid values, bad config file.
    ///
    /// Also covers a command line clap rejected: a flag that does not parse is a
    /// configuration error, not a Jira problem (exit code 2 is reserved for
    /// "Jira access error", see [`ScannerError::CLI_PARSE_EXIT_CODE`]).
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

    /// Unclassified internal error (exit 3): a failure that does not fit any of
    /// the specific variants and that prevented a stage from running — a
    /// credential-pair pattern that fails to compile at startup, a logging
    /// backend that refuses to initialize.
    ///
    /// It maps to the critical-scan code rather than to success: an earlier
    /// revision returned 0 here, which turned a hard startup failure into a
    /// green CI run. Do **not** use this variant for a problem the caller can
    /// survive — a recoverable per-issue problem is logged and swallowed at the
    /// call site (see `pipeline::collect_one`), it is not returned as an error.
    #[error("Internal error: {0}")]
    Other(String),

    /// Store/persistence error: DB open, migration, reconcile failure.
    #[error("Store error: {0}")]
    Store(String),
}

impl ScannerError {
    /// Exit code of every configuration error, including a command line that
    /// clap rejected.
    ///
    /// A clap parse failure never reaches [`ScannerError::exit_code`] (the error
    /// type is `clap::Error`, and `Config` does not exist yet), so the CLI layer
    /// uses this constant — the number is still defined in exactly one place.
    pub const CLI_PARSE_EXIT_CODE: u8 = 1;

    /// Maps the error variant to the corresponding exit code per spec §15.
    ///
    /// The only variant-to-code mapping in the crate: everything that exits
    /// non-zero (the CLI layer included) goes through this function or through
    /// [`ScannerError::CLI_PARSE_EXIT_CODE`], never through a literal.
    pub fn exit_code(&self) -> u8 {
        match self {
            ScannerError::Config(_) => Self::CLI_PARSE_EXIT_CODE,
            ScannerError::JiraAccess(_) => 2,
            ScannerError::ScanCritical(_) => 3,
            ScannerError::Other(_) => 3,
            ScannerError::ReportWrite(_) => 4,
            ScannerError::Store(_) => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        assert_eq!(ScannerError::Config("x".into()).exit_code(), 1);
        assert_eq!(ScannerError::JiraAccess("x".into()).exit_code(), 2);
        assert_eq!(ScannerError::ScanCritical("x".into()).exit_code(), 3);
        assert_eq!(ScannerError::ReportWrite("x".into()).exit_code(), 4);
        assert_eq!(ScannerError::Store("x".into()).exit_code(), 5);
    }

    /// Every failure must terminate the process with a non-zero code: an
    /// unclassified internal error is not a success, and every code stays inside
    /// the documented 1..=5 range of the README table.
    #[test]
    fn test_every_variant_is_a_failure() {
        let all = [
            ScannerError::Config("x".into()),
            ScannerError::JiraAccess("x".into()),
            ScannerError::ScanCritical("x".into()),
            ScannerError::ReportWrite("x".into()),
            ScannerError::Other("x".into()),
            ScannerError::Store("x".into()),
        ];
        for err in &all {
            let code = err.exit_code();
            assert_ne!(code, 0, "{err} must not exit successfully");
            assert!(
                (1..=5).contains(&code),
                "{err} exits with an undocumented code {code}"
            );
        }
        assert_eq!(ScannerError::Other("x".into()).exit_code(), 3);
        assert_eq!(
            ScannerError::Config("x".into()).exit_code(),
            ScannerError::CLI_PARSE_EXIT_CODE
        );
    }
}
