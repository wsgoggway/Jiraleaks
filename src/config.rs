use std::fmt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// jiraleaks — CLI configuration.
#[derive(Parser, Clone, Serialize, Deserialize)]
#[command(
    name = "jiraleaks",
    version = env!("CARGO_PKG_VERSION"),
    about = "Scan Jira for secrets, credentials, and sensitive data",
    long_about = None
)]
pub struct Config {
    /// Base URL of the Jira instance, e.g. https://jira.example.com
    #[arg(long, env = "JIRA_URL", default_value = "", hide_default_value = true)]
    pub jira_url: String,

    /// Authentication mode: bearer token, basic auth, or none
    #[arg(long, env = "JIRA_AUTH", default_value = "bearer", value_parser = ["bearer", "basic", "none"])]
    pub auth: String,

    /// Personal access token (or API token for basic auth)
    #[arg(
        long,
        env = "JIRA_PAT",
        alias = "JIRA_API_TOKEN",
        default_value = "",
        hide_default_value = true
    )]
    #[serde(skip_serializing)]
    pat: String,

    /// Email for basic auth
    #[arg(long, env = "JIRA_EMAIL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// JQL query to select issues to scan
    #[arg(long, env = "JIRA_JQL")]
    pub jql: Option<String>,

    /// Issues per Jira search page
    #[arg(long, env = "SCAN_PAGE_SIZE", default_value = "50", value_parser = clap::builder::RangedU64ValueParser::<u32>::new().range(1..))]
    pub page_size: u32,

    /// Maximum issues to scan; 0 = no limit
    #[arg(long, env = "SCAN_MAX_ISSUES", default_value = "0")]
    pub max_issues: u32,

    /// Concurrent issue processing tasks
    #[arg(long, env = "SCAN_CONCURRENCY", default_value = "2", value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub concurrency: usize,

    /// Jira fields to fetch per issue
    #[arg(long, env = "SCAN_FIELDS", default_value = "*navigable")]
    pub fields: String,

    /// Comment scanning mode: all or none
    #[arg(long, env = "SCAN_COMMENTS_MODE", default_value = "all", value_parser = ["none", "all"])]
    pub comments_mode: String,

    /// Scan attachments (experimental)
    #[arg(long, env = "SCAN_ATTACHMENTS_ENABLED", default_value = "false")]
    pub scan_attachments: bool,

    /// Max attachment size to download, in MB
    #[arg(long, default_value = "10", value_parser = clap::builder::RangedU64ValueParser::<u64>::new().range(1..))]
    pub max_attachment_size_mb: u64,

    /// Truncate extracted text segments beyond this size, in KB
    #[arg(long, default_value = "2048", value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub max_text_size_kb: usize,

    /// Stop collecting findings for an issue after this many
    #[arg(long, default_value = "1000", value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub max_findings_per_issue: usize,

    /// Path to YAML allowlist file
    #[arg(long, env = "ALLOWLIST_PATH")]
    pub allowlist: Option<PathBuf>,

    /// Path to YAML rules file
    #[arg(long, env = "RULES_PATH")]
    pub rules: Option<PathBuf>,

    /// Minimum confidence for findings: low, medium, or high
    #[arg(long, default_value = "low", value_parser = ["low", "medium", "high"])]
    pub min_confidence: String,

    /// Report format(s), comma-separated: json, ndjson, csv, sarif,
    /// summary, defectdojo, or all
    #[arg(long, env = "REPORT_FORMAT", default_value = "json", value_parser = parse_formats)]
    pub format: String,

    /// Directory to write reports into
    #[arg(long, env = "REPORT_OUTPUT_PATH", default_value = "./reports")]
    pub report_dir: PathBuf,

    /// Report directory layout: flat (report_dir/<ts>_report.ext) or nested
    /// (report_dir/<project>/<date>/<time>_report.ext).
    #[arg(long, env = "JIRALEAKS_REPORT_LAYOUT", default_value = "flat", value_parser = ["flat", "nested"])]
    pub report_layout: String,

    /// Do not write report files
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Enable incremental scanning via checkpoint files
    #[arg(long, env = "JIRALEAKS_INCREMENTAL", default_value = "false")]
    pub incremental: bool,

    /// State directory for checkpoints
    #[arg(long, default_value = "./.jiraleaks-state")]
    pub state_dir: PathBuf,
    /// Database URL for findings store (sqlite:///path?mode=rwc or postgres://...).
    /// Empty string disables the store. Default: sqlite://{state_dir}/findings.db?mode=rwc
    #[arg(long, env = "JIRALEAKS_DB_URL")]
    #[serde(skip_serializing)]
    pub db_url: Option<String>,

    /// Write metrics to this path
    #[arg(long)]
    pub metrics_path: Option<PathBuf>,

    /// Metrics file format: json or text
    #[arg(long, default_value = "json", value_parser = ["json", "text"])]
    pub metrics_format: String,

    /// Log level: trace, debug, info, warn, error
    #[arg(long, env = "LOG_LEVEL", default_value = "info", value_parser = ["trace", "debug", "info", "warn", "error"])]
    pub log_level: String,

    /// Bypass proxy settings for Jira requests
    #[arg(long, env = "JIRA_NO_PROXY", default_value = "false")]
    pub no_proxy: bool,

    /// Load base configuration from a YAML file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Send alerts (Slack/Teams/webhook) after the scan
    #[arg(long)]
    pub alerts: Option<PathBuf>,

    /// Auxiliary CLI commands
    #[command(subcommand)]
    #[serde(skip)]
    command: Option<CliCommand>,
}

/// Auxiliary CLI commands.
#[derive(Subcommand, Clone)]
enum CliCommand {
    /// Generate a shell completion script and print it to stdout
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// Validate the report format list: comma-separated known formats.
fn parse_formats(s: &str) -> Result<String, String> {
    const VALID: &[&str] = &[
        "json",
        "ndjson",
        "csv",
        "sarif",
        "summary",
        "defectdojo",
        "all",
    ];
    for f in s.split(',') {
        let f = f.trim();
        if f.is_empty() || !VALID.contains(&f) {
            return Err(format!(
                "unknown report format '{f}', expected one of: {}",
                VALID.join(", ")
            ));
        }
    }
    Ok(s.to_string())
}

impl Config {
    pub fn pat(&self) -> &str {
        &self.pat
    }

    pub fn jql(&self) -> Option<&str> {
        self.jql.as_deref()
    }

    /// Shell to generate completions for, if the `completions` subcommand
    /// was invoked.
    pub fn completions(&self) -> Option<clap_complete::Shell> {
        self.command
            .as_ref()
            .map(|CliCommand::Completions { shell }| *shell)
    }

    /// Resolved database URL for the findings store, or `None` if disabled.
    ///
    /// - `Some(non-empty)` → explicit URL.
    /// - `Some("")` or the field was set to empty → store disabled (`None`).
    /// - `None` (not provided) → default `sqlite://{state_dir}/findings.db?mode=rwc`,
    ///   unless `state_dir` is empty, in which case the store is disabled.
    pub fn db_url(&self) -> Option<String> {
        match &self.db_url {
            Some(u) => {
                if u.is_empty() {
                    None
                } else {
                    Some(u.clone())
                }
            }
            None => {
                if self.state_dir.as_os_str().is_empty() {
                    None
                } else {
                    Some(format!(
                        "sqlite://{}?mode=rwc",
                        self.state_dir.join("findings.db").display()
                    ))
                }
            }
        }
    }

    pub fn request_timeout_secs(&self) -> u64 {
        30
    }

    /// Create a Config for testing purposes.
    #[doc(hidden)]
    pub fn test_config(jira_url: &str, pat_token: &str) -> Self {
        Self {
            jira_url: jira_url.to_string(),
            auth: "bearer".to_string(),
            pat: pat_token.to_string(),
            email: None,
            jql: Some("project = TEST".into()),
            page_size: 50,
            max_issues: 0,
            concurrency: 1,
            fields: "*navigable".into(),
            comments_mode: "all".into(),
            scan_attachments: false,
            max_attachment_size_mb: 10,
            max_text_size_kb: 2048,
            max_findings_per_issue: 1000,
            allowlist: None,
            rules: None,
            min_confidence: "low".into(),
            format: "json".into(),
            report_dir: "/tmp/jiraleaks-test".into(),
            report_layout: "flat".into(),
            dry_run: true,
            incremental: false,
            state_dir: "/tmp/jiraleaks-test-state".into(),
            metrics_path: None,
            metrics_format: "json".into(),
            db_url: None,
            log_level: "info".into(),
            no_proxy: true,
            config: None,
            alerts: None,
            command: None,
        }
    }

    pub fn validate(&self) -> Result<(), crate::error::ScannerError> {
        use crate::error::ScannerError;
        if self.jira_url.is_empty() {
            return Err(ScannerError::Config("JIRA_URL is required".to_string()));
        }
        if self.jql.is_none() || self.jql.as_deref() == Some("") {
            return Err(ScannerError::Config(
                "JIRA_JQL / --jql is required".to_string(),
            ));
        }
        if self.pat.is_empty() && self.auth != "none" {
            return Err(ScannerError::Config(
                "JIRA_PAT / --pat is required".to_string(),
            ));
        }
        if self.auth == "basic" && self.email.is_none() {
            return Err(ScannerError::Config(
                "JIRA_EMAIL is required for basic auth".to_string(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("jira_url", &self.jira_url)
            .field("auth", &self.auth)
            .field("pat", &"***")
            .field("email", &self.email)
            .field("jql", &self.jql)
            .field("page_size", &self.page_size)
            .field("concurrency", &self.concurrency)
            .field("format", &self.format)
            .field("dry_run", &self.dry_run)
            .field("incremental", &self.incremental)
            .field("no_proxy", &self.no_proxy)
            .field("db_url", &self.db_url)
            .field("report_layout", &self.report_layout)
            .finish()
    }
}
