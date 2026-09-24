use std::fmt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Log level used when neither `--log-level`/`LOG_LEVEL` nor `RUST_LOG` is set.
///
/// See [`crate::log::resolve_filter`] for the priority rules, and
/// [`Config::effective_log_level`].
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Format of the file written to `--metrics-path`.
///
/// A typed enum rather than a string: the CLI used to accept `text`, which no
/// writer implemented — it silently produced JSON — while `prom`, the only
/// spelling the Prometheus writer understood, was rejected. Parsing into this
/// enum makes the accepted values and the writers agree by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetricsFormat {
    /// `--metrics-format json`, the default
    #[default]
    Json,
    /// `--metrics-format prom` or `--metrics-format prometheus`
    Prometheus,
}

impl MetricsFormat {
    /// Case-insensitive parse of the accepted CLI spellings.
    ///
    /// `json`, `prom` and `prometheus` are accepted; `prom` is the historical
    /// short spelling and is reported back as `prometheus`. Anything else —
    /// including the retired `text` — is an error.
    pub fn parse_opt(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "json" => Some(MetricsFormat::Json),
            "prom" | "prometheus" => Some(MetricsFormat::Prometheus),
            _ => None,
        }
    }

    /// Canonical, lowercase name of the format (what `--help` shows).
    pub fn as_str(self) -> &'static str {
        match self {
            MetricsFormat::Json => "json",
            MetricsFormat::Prometheus => "prometheus",
        }
    }
}

impl std::str::FromStr for MetricsFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_opt(s).ok_or_else(|| {
            format!("unknown metrics format '{s}', expected one of: json, prom, prometheus")
        })
    }
}

impl fmt::Display for MetricsFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// jiraleaks — CLI configuration.
///
/// Environment handling: clap reads the environment for most options (see the
/// `env` attributes), except the personal access token, whose three sources are
/// resolved by [`Config::resolve_pat_from_env`] — call it after parsing when the
/// process environment has to be honoured.
#[derive(Parser, Clone)]
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

    /// Personal access token (or API token for basic auth).
    ///
    /// Taken from the first of: `--pat`, `JIRA_PAT`, `JIRA_API_TOKEN` — see
    /// [`Config::resolve_pat_from_env`].
    #[arg(long, default_value = "", hide_default_value = true)]
    pat: String,

    /// Email for basic auth
    #[arg(long, env = "JIRA_EMAIL")]
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
    pub db_url: Option<String>,

    /// Write metrics to this path
    #[arg(long)]
    pub metrics_path: Option<PathBuf>,

    /// Metrics file format: json, prom, or prometheus (default: json)
    #[arg(long, default_value_t = MetricsFormat::default(), value_parser = clap::value_parser!(MetricsFormat))]
    pub metrics_format: MetricsFormat,

    /// Log level: trace, debug, info, warn, error (default: info).
    ///
    /// When neither this flag nor `LOG_LEVEL` is given, `RUST_LOG` is used as a
    /// fallback; an explicitly configured level always wins over `RUST_LOG`.
    #[arg(long, env = "LOG_LEVEL", value_parser = ["trace", "debug", "info", "warn", "error"])]
    pub log_level: Option<String>,

    /// Bypass proxy settings for Jira requests
    #[arg(long, env = "JIRA_NO_PROXY", default_value = "false")]
    pub no_proxy: bool,

    /// Send alerts (Slack/Teams/webhook) after the scan
    #[arg(long)]
    pub alerts: Option<PathBuf>,

    /// Auxiliary CLI commands
    #[command(subcommand)]
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

/// Resolve the personal access token from its three sources.
///
/// Priority, highest first:
/// 1. the `--pat` flag,
/// 2. the `JIRA_PAT` environment variable,
/// 3. the legacy `JIRA_API_TOKEN` environment variable, which the README has
///    always documented as an alias.
///
/// A candidate that is absent, empty or whitespace-only counts as not set, so an
/// empty variable (`JIRA_PAT=` left in a shell profile) cannot shadow a real
/// token from a lower-priority source. Non-empty candidates are returned
/// verbatim — only the emptiness test ignores surrounding whitespace.
///
/// Pure function: the caller passes the three candidates, so the precedence is
/// testable without touching the process environment.
pub fn resolve_pat(
    cli: Option<String>,
    env_pat: Option<String>,
    env_alias: Option<String>,
) -> Option<String> {
    fn present(value: Option<String>) -> Option<String> {
        value.filter(|v| !v.trim().is_empty())
    }

    present(cli)
        .or_else(|| present(env_pat))
        .or_else(|| present(env_alias))
}

/// Single source of truth for every default value of [`Config`].
///
/// The `default_value`s declared in the `clap` attributes above must agree with
/// these values: a library caller that builds `Config::default()` and the binary
/// must see the same configuration. `tests/config_cli.rs` pins both sets (and the
/// README table), so a divergence fails the build instead of silently giving the
/// integration tests a different configuration than production.
impl Default for Config {
    fn default() -> Self {
        Self {
            jira_url: String::new(),
            auth: "bearer".to_string(),
            pat: String::new(),
            email: None,
            jql: None,
            page_size: 50,
            max_issues: 0,
            concurrency: 2,
            fields: "*navigable".to_string(),
            comments_mode: "all".to_string(),
            scan_attachments: false,
            max_attachment_size_mb: 10,
            max_text_size_kb: 2048,
            max_findings_per_issue: 1000,
            allowlist: None,
            rules: None,
            min_confidence: "low".to_string(),
            format: "json".to_string(),
            report_dir: PathBuf::from("./reports"),
            report_layout: "flat".to_string(),
            dry_run: false,
            incremental: false,
            state_dir: PathBuf::from("./.jiraleaks-state"),
            db_url: None,
            metrics_path: None,
            metrics_format: MetricsFormat::Json,
            log_level: None,
            no_proxy: false,
            alerts: None,
            command: None,
        }
    }
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

    /// Effective log level: the configured one, or [`DEFAULT_LOG_LEVEL`].
    ///
    /// `log_level` is `None` exactly when neither `--log-level` nor `LOG_LEVEL`
    /// was given — that is what lets `RUST_LOG` act as a fallback
    /// ([`crate::log::resolve_filter`]) instead of being silently overridden by a
    /// default, which is what used to happen.
    pub fn effective_log_level(&self) -> &str {
        self.log_level.as_deref().unwrap_or(DEFAULT_LOG_LEVEL)
    }

    /// Fill in the personal access token from the environment.
    ///
    /// The whole precedence (`--pat` > `JIRA_PAT` > `JIRA_API_TOKEN`) lives in
    /// [`resolve_pat`]; this method only feeds it the three candidates and stores
    /// the winner. The token is read here rather than by clap because clap cannot
    /// express a fallback chain — the previous `alias = "JIRA_API_TOKEN"` was an
    /// alias for the *argument name* (a hidden `--JIRA_API_TOKEN` flag) and never
    /// looked at the environment, so the documented env alias was silently
    /// ignored.
    ///
    /// Called by the binary right after parsing. An embedder that parses `Config`
    /// itself must call it too, or `JIRA_PAT` / `JIRA_API_TOKEN` will not be read.
    pub fn resolve_pat_from_env(&mut self) {
        let cli = if self.pat.trim().is_empty() {
            None
        } else {
            Some(self.pat.clone())
        };
        self.pat = resolve_pat(
            cli,
            std::env::var("JIRA_PAT").ok(),
            std::env::var("JIRA_API_TOKEN").ok(),
        )
        .unwrap_or_default();
    }

    /// Create a Config for testing purposes.
    ///
    /// Built on [`Config::default`], so production and tests cannot drift: only
    /// the values a test must not inherit are overridden — a throwaway report and
    /// state directory under `/tmp`, the credentials under test, the isolation
    /// flags `dry_run` (never write reports) and `no_proxy` (the mock Jira server
    /// is always local), and `concurrency: 1` for deterministic ordering.
    #[doc(hidden)]
    pub fn test_config(jira_url: &str, pat_token: &str) -> Self {
        Self {
            jira_url: jira_url.to_string(),
            pat: pat_token.to_string(),
            jql: Some("project = TEST".into()),
            concurrency: 1,
            report_dir: "/tmp/jiraleaks-test".into(),
            dry_run: true,
            state_dir: "/tmp/jiraleaks-test-state".into(),
            no_proxy: true,
            ..Self::default()
        }
    }

    /// Validate the configuration, reporting the first violated rule.
    ///
    /// This is where the whole configuration contract is enforced, not only in
    /// clap's `value_parser`s: a `Config` built by a library caller or by a test
    /// never goes through clap, and a value that reaches a scan must be rejected
    /// identically either way. clap still rejects the same values at parse time
    /// (as a parse error, exit code 1); this function is the library-level
    /// guarantee behind it. Every message names the offending value.
    ///
    /// `metrics_format` has no check here on purpose: it is a typed
    /// [`MetricsFormat`], so an unrepresentable format cannot reach validation.
    pub fn validate(&self) -> Result<(), crate::error::ScannerError> {
        use crate::error::ScannerError;
        use crate::finding::Confidence;

        if self.jira_url.is_empty() {
            return Err(ScannerError::Config(
                "JIRA_URL is required; set JIRA_URL or --jira-url".to_string(),
            ));
        }
        let scheme = self.jira_url.to_ascii_lowercase();
        if !(scheme.starts_with("http://") || scheme.starts_with("https://")) {
            return Err(ScannerError::Config(format!(
                "jira_url must start with http:// or https://, got '{}'",
                self.jira_url
            )));
        }
        if self.jql.as_deref().unwrap_or("").is_empty() {
            return Err(ScannerError::Config(
                "JIRA_JQL / --jql is required and must not be empty".to_string(),
            ));
        }
        if self.pat.is_empty() && self.auth != "none" {
            return Err(ScannerError::Config(
                "JIRA_PAT / --pat is required (or JIRA_API_TOKEN); use --auth none to scan without credentials"
                    .to_string(),
            ));
        }
        if self.auth == "basic" && self.email.is_none() {
            return Err(ScannerError::Config(
                "JIRA_EMAIL is required for basic auth".to_string(),
            ));
        }
        if !["bearer", "basic", "none"].contains(&self.auth.as_str()) {
            return Err(ScannerError::Config(format!(
                "auth must be bearer, basic or none, got '{}'",
                self.auth
            )));
        }
        if self.page_size == 0 {
            return Err(ScannerError::Config(format!(
                "page_size must be greater than 0, got {}",
                self.page_size
            )));
        }
        if self.concurrency == 0 {
            return Err(ScannerError::Config(format!(
                "concurrency must be greater than 0, got {}",
                self.concurrency
            )));
        }
        if self.max_findings_per_issue == 0 {
            return Err(ScannerError::Config(format!(
                "max_findings_per_issue must be greater than 0, got {}",
                self.max_findings_per_issue
            )));
        }
        if self.max_text_size_kb == 0 {
            return Err(ScannerError::Config(format!(
                "max_text_size_kb must be greater than 0, got {}",
                self.max_text_size_kb
            )));
        }
        if self.max_attachment_size_mb == 0 {
            return Err(ScannerError::Config(format!(
                "max_attachment_size_mb must be greater than 0, got {}",
                self.max_attachment_size_mb
            )));
        }
        if !["flat", "nested"].contains(&self.report_layout.as_str()) {
            return Err(ScannerError::Config(format!(
                "report_layout must be flat or nested, got '{}'",
                self.report_layout
            )));
        }
        if Confidence::parse_opt(&self.min_confidence).is_none() {
            return Err(ScannerError::Config(format!(
                "min_confidence must be low, medium or high, got '{}'",
                self.min_confidence
            )));
        }
        if let Err(message) = parse_formats(&self.format) {
            return Err(ScannerError::Config(format!(
                "format: {message} (got '{}')",
                self.format
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for Config {
    /// Hand-written so that the token never reaches a log line: `pat` is always
    /// rendered as `***`.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The masking `Debug` impl is the reason it is hand-written — pin it.
    #[test]
    fn debug_masks_the_token() {
        let config = Config::test_config("https://jira.example.com", "super-secret-token");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("pat: \"***\""));
    }

    #[test]
    fn metrics_format_accepts_documented_spellings() {
        assert_eq!(MetricsFormat::parse_opt("json"), Some(MetricsFormat::Json));
        assert_eq!(MetricsFormat::parse_opt("JSON"), Some(MetricsFormat::Json));
        assert_eq!(
            MetricsFormat::parse_opt("prom"),
            Some(MetricsFormat::Prometheus)
        );
        assert_eq!(
            MetricsFormat::parse_opt("Prometheus"),
            Some(MetricsFormat::Prometheus)
        );
        assert_eq!(MetricsFormat::parse_opt("text"), None);
        assert_eq!(MetricsFormat::default(), MetricsFormat::Json);
    }

    #[test]
    fn resolve_pat_prefers_the_highest_priority_source() {
        let all = resolve_pat(
            Some("cli".into()),
            Some("env-pat".into()),
            Some("env-alias".into()),
        );
        assert_eq!(all.as_deref(), Some("cli"));
        assert_eq!(
            resolve_pat(None, Some("env-pat".into()), Some("env-alias".into())).as_deref(),
            Some("env-pat")
        );
        assert_eq!(
            resolve_pat(None, None, Some("env-alias".into())).as_deref(),
            Some("env-alias")
        );
        assert_eq!(resolve_pat(None, None, None), None);
        // Empty and blank values count as not set.
        assert_eq!(
            resolve_pat(Some(String::new()), Some("  ".into()), Some("env".into())).as_deref(),
            Some("env")
        );
    }
}
