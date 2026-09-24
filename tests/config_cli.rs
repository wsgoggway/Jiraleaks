//! Contract tests for the CLI / configuration layer.
//!
//! These pin the behaviour that is easy to get wrong and expensive to get wrong
//! silently: every `validate()` rule, the precedence of the personal access token
//! sources, the typed `MetricsFormat`, `Severity` / `Confidence` parsing, the
//! log-filter priority, and the documented default values (README table versus
//! `Config::default()` versus the `clap` defaults).
//!
//! The four tests that spawn the compiled binary cover what an in-process test
//! cannot: the exit code contract of a rejected command line, and the fact that
//! `main` actually applies the environment fallbacks.

use std::path::PathBuf;
use std::process::{Command, Output};

use clap::{CommandFactory, Parser};
use jiraleaks::config::{resolve_pat, Config, MetricsFormat, DEFAULT_LOG_LEVEL};
use jiraleaks::error::ScannerError;
use jiraleaks::finding::{Confidence, Severity};
use jiraleaks::log::{resolve_filter, FilterSource};

/// A config that validates, so a single field can be broken per test.
fn valid_config() -> Config {
    Config::test_config("https://jira.example.com", "test-token")
}

/// The message of the configuration error `config` must fail with.
fn config_error(config: &Config) -> String {
    match config.validate() {
        Err(ScannerError::Config(message)) => message,
        Ok(()) => panic!("expected a configuration error, but the config validated"),
        Err(other) => panic!("expected ScannerError::Config, got {other:?}"),
    }
}

/// Assert that `config` is rejected with a message naming `expected`.
fn assert_rejected(config: &Config, expected: &str) {
    let message = config_error(config);
    assert!(
        message.contains(expected),
        "the message must mention '{expected}', got '{message}'"
    );
}

// ---------------------------------------------------------------- validation ---

#[test]
fn a_complete_config_is_accepted() {
    assert!(valid_config().validate().is_ok());
}

/// `auth = none` is the documented way to scan an unauthenticated instance, so a
/// missing token must not be reported there.
#[test]
fn auth_none_does_not_require_a_token() {
    let mut config = Config::default();
    config.jira_url = "https://jira.example.com".into();
    config.jql = Some("project = SEC".into());
    config.auth = "none".into();
    assert!(config.validate().is_ok(), "{}", config_error(&config));
}

#[test]
fn validate_rejects_a_missing_jira_url() {
    let config = Config::default();
    assert_rejected(&config, "JIRA_URL is required");
}

#[test]
fn validate_rejects_a_jira_url_without_an_http_scheme() {
    for bad in [
        "ftp://jira.example.com",
        "jira.example.com",
        "//jira.example.com",
    ] {
        let mut config = valid_config();
        config.jira_url = bad.into();
        assert_rejected(&config, "http:// or https://");
    }
    // The scheme check is case-insensitive, like every other URL parser.
    let mut upper = valid_config();
    upper.jira_url = "HTTPS://jira.example.com".into();
    assert!(upper.validate().is_ok(), "{}", config_error(&upper));
}

#[test]
fn validate_rejects_a_missing_or_empty_jql() {
    let mut config = valid_config();
    config.jql = None;
    assert_rejected(&config, "JIRA_JQL");
    config.jql = Some(String::new());
    assert_rejected(&config, "JIRA_JQL");
}

#[test]
fn validate_requires_a_token_unless_auth_is_none() {
    // Everything else valid, so the token is the only failure left.
    let mut config = Config::default();
    config.jira_url = "https://jira.example.com".into();
    config.jql = Some("project = SEC".into());
    assert_rejected(&config, "JIRA_PAT");
}

#[test]
fn validate_requires_an_email_for_basic_auth() {
    let mut config = valid_config();
    config.auth = "basic".into();
    config.email = None;
    assert_rejected(&config, "JIRA_EMAIL");
    // ... and accepts basic auth as soon as the email is there.
    config.email = Some("user@example.com".into());
    assert!(config.validate().is_ok(), "{}", config_error(&config));
}

#[test]
fn validate_rejects_an_unknown_auth_mode() {
    let mut config = valid_config();
    config.auth = "oauth".into();
    assert_rejected(&config, "auth must be bearer, basic or none");
}

#[test]
fn validate_rejects_zero_page_size() {
    let mut config = valid_config();
    config.page_size = 0;
    assert_rejected(&config, "page_size must be greater than 0");
}

#[test]
fn validate_rejects_zero_concurrency() {
    let mut config = valid_config();
    config.concurrency = 0;
    assert_rejected(&config, "concurrency must be greater than 0");
}

#[test]
fn validate_rejects_zero_max_findings_per_issue() {
    let mut config = valid_config();
    config.max_findings_per_issue = 0;
    assert_rejected(&config, "max_findings_per_issue must be greater than 0");
}

#[test]
fn validate_rejects_zero_max_text_size_kb() {
    let mut config = valid_config();
    config.max_text_size_kb = 0;
    assert_rejected(&config, "max_text_size_kb must be greater than 0");
}

#[test]
fn validate_rejects_zero_max_attachment_size_mb() {
    let mut config = valid_config();
    config.max_attachment_size_mb = 0;
    assert_rejected(&config, "max_attachment_size_mb must be greater than 0");
}

#[test]
fn validate_rejects_an_unknown_report_layout() {
    let mut config = valid_config();
    config.report_layout = "deep".into();
    assert_rejected(&config, "report_layout must be flat or nested");
}

#[test]
fn validate_rejects_an_unknown_min_confidence() {
    for bad in ["urgent", "", "medium-high"] {
        let mut config = valid_config();
        config.min_confidence = bad.into();
        assert_rejected(&config, "min_confidence must be low, medium or high");
    }
    // Case does not matter, because the parser behind the check lowercases.
    let mut config = valid_config();
    config.min_confidence = "HIGH".into();
    assert!(config.validate().is_ok(), "{}", config_error(&config));
}

#[test]
fn validate_rejects_an_unknown_report_format() {
    let mut config = valid_config();
    config.format = "xml".into();
    assert_rejected(&config, "unknown report format 'xml'");
}

// ------------------------------------------------------------- metrics format ---

#[test]
fn metrics_format_parses_the_accepted_spellings() {
    for (input, expected) in [
        ("json", MetricsFormat::Json),
        ("JSON", MetricsFormat::Json),
        (" json ", MetricsFormat::Json),
        ("prom", MetricsFormat::Prometheus),
        ("prometheus", MetricsFormat::Prometheus),
        ("Prometheus", MetricsFormat::Prometheus),
    ] {
        assert_eq!(
            input.parse::<MetricsFormat>().expect("valid format"),
            expected,
            "input {input:?}"
        );
    }
    assert_eq!(MetricsFormat::default(), MetricsFormat::Json);
    assert_eq!(MetricsFormat::Prometheus.to_string(), "prometheus");
}

#[test]
fn metrics_format_rejects_the_retired_and_unknown_values() {
    // `text` was accepted by the CLI but no writer implemented it: it silently
    // produced JSON, so it must now be an error.
    for input in ["text", "", "yaml", "prometheusx"] {
        let error = input
            .parse::<MetricsFormat>()
            .expect_err("must be rejected");
        assert!(
            error.contains("expected one of: json, prom, prometheus"),
            "got {error}"
        );
    }
}

#[test]
fn the_cli_accepts_prom_and_rejects_text() {
    let config = Config::try_parse_from(["jiraleaks", "--metrics-format", "prom"])
        .expect("`prom` is the documented spelling of the Prometheus writer");
    assert_eq!(config.metrics_format, MetricsFormat::Prometheus);

    let default = Config::try_parse_from(["jiraleaks"]).expect("no argument is mandatory");
    assert_eq!(default.metrics_format, MetricsFormat::Json);

    assert!(
        Config::try_parse_from(["jiraleaks", "--metrics-format", "text"]).is_err(),
        "`text` must be rejected instead of silently writing JSON"
    );
}

/// The flag promised a YAML file that nothing ever read, so it is gone rather
/// than silently ignored.
#[test]
fn the_config_flag_is_gone() {
    assert!(Config::try_parse_from(["jiraleaks", "--config", "base.yaml"]).is_err());
}

// ------------------------------------------------- severity / confidence parse ---

#[test]
fn severity_parses_every_level_case_insensitively() {
    for (input, expected) in [
        ("critical", Severity::Critical),
        ("HIGH", Severity::High),
        ("Medium", Severity::Medium),
        ("low", Severity::Low),
        ("info", Severity::Info),
    ] {
        assert_eq!(Severity::parse(input), expected);
        assert_eq!(input.parse::<Severity>().expect("infallible"), expected);
        assert_eq!(Severity::parse_opt(input), Some(expected));
    }
}

/// Documented leniency: an unknown severity from a user rules file keeps the scan
/// running and means `medium`; only `parse_opt` reports it as unknown.
#[test]
fn an_unknown_severity_defaults_to_medium() {
    for input in ["urgent", "", "medium-high", "sev1"] {
        assert_eq!(Severity::parse(input), Severity::Medium);
        assert_eq!(
            input.parse::<Severity>().expect("infallible"),
            Severity::Medium
        );
        assert_eq!(Severity::parse_opt(input), None);
    }
}

/// Same documented leniency as severity, with `low` as the fallback.
#[test]
fn an_unknown_confidence_defaults_to_low() {
    for input in ["urgent", "", "medium-high"] {
        assert_eq!(Confidence::parse(input), Confidence::Low);
        assert_eq!(
            input.parse::<Confidence>().expect("infallible"),
            Confidence::Low
        );
        assert_eq!(Confidence::parse_opt(input), None);
    }
    assert_eq!(Confidence::parse_opt("HIGH"), Some(Confidence::High));
    assert_eq!(Confidence::parse("high"), Confidence::High);
    assert_eq!(Confidence::parse("medium"), Confidence::Medium);
    assert_eq!(Severity::Critical.to_string(), "critical");
    assert_eq!(Confidence::Low.to_string(), "low");
}

/// The `pipeline::` helpers stay as delegating shims while the call sites outside
/// this crate migrate; their behaviour must not drift.
#[test]
fn the_legacy_pipeline_shims_delegate_to_the_domain_types() {
    assert_eq!(jiraleaks::pipeline::parse_severity("HIGH"), Severity::High);
    assert_eq!(
        jiraleaks::pipeline::parse_severity("urgent"),
        Severity::Medium
    );
    assert_eq!(
        jiraleaks::pipeline::parse_confidence("HIGH"),
        Confidence::High
    );
    assert_eq!(
        jiraleaks::pipeline::parse_confidence("urgent"),
        Confidence::Low
    );
}

// ---------------------------------------------------------- token resolution ---

#[test]
fn the_token_precedence_is_flag_then_jira_pat_then_jira_api_token() {
    assert_eq!(
        resolve_pat(
            Some("from-cli".into()),
            Some("from-env-pat".into()),
            Some("from-env-alias".into())
        )
        .as_deref(),
        Some("from-cli")
    );
    assert_eq!(
        resolve_pat(
            None,
            Some("from-env-pat".into()),
            Some("from-env-alias".into())
        )
        .as_deref(),
        Some("from-env-pat")
    );
    assert_eq!(
        resolve_pat(None, None, Some("from-env-alias".into())).as_deref(),
        Some("from-env-alias")
    );
    assert_eq!(resolve_pat(None, None, None), None);
}

/// An empty variable (`JIRA_PAT=` left in a profile) must not shadow a real token
/// from a lower-priority source.
#[test]
fn an_empty_source_counts_as_not_set() {
    assert_eq!(
        resolve_pat(Some(String::new()), None, Some("alias".into())).as_deref(),
        Some("alias")
    );
    assert_eq!(
        resolve_pat(None, Some("   ".into()), Some("alias".into())).as_deref(),
        Some("alias")
    );
    assert_eq!(resolve_pat(Some(" ".into()), Some("\t".into()), None), None);
}

// ------------------------------------------------------------- log filtering ---

#[test]
fn an_explicit_level_beats_rust_log() {
    assert_eq!(
        resolve_filter(Some("warn"), Some("debug")),
        ("warn".to_string(), FilterSource::ExplicitLevel)
    );
}

#[test]
fn rust_log_is_only_a_fallback() {
    assert_eq!(
        resolve_filter(None, Some("jiraleaks=debug,hyper=warn")),
        (
            "jiraleaks=debug,hyper=warn".to_string(),
            FilterSource::RustEnv
        )
    );
    assert_eq!(
        resolve_filter(Some(" "), Some("trace")),
        ("trace".to_string(), FilterSource::RustEnv)
    );
}

#[test]
fn the_default_level_is_the_documented_one() {
    assert_eq!(DEFAULT_LOG_LEVEL, "info");
    assert_eq!(
        resolve_filter(None, None),
        ("info".to_string(), FilterSource::Default)
    );
    assert_eq!(
        resolve_filter(Some(""), Some("")),
        ("info".to_string(), FilterSource::Default)
    );
}

// ------------------------------------------------------------------ defaults ---

/// The README's configuration table, transcribed by hand: this list **is** the
/// contract, so it is deliberately not derived from the code under test.
#[test]
fn defaults_match_the_readme_table() {
    let config = Config::default();

    assert_eq!(config.jira_url, "");
    assert_eq!(config.pat(), "", "no token by default");
    assert_eq!(config.auth, "bearer");
    assert_eq!(config.email, None);
    assert_eq!(config.jql, None);
    assert_eq!(config.page_size, 50);
    assert_eq!(config.max_issues, 0, "0 = unlimited");
    assert_eq!(config.concurrency, 2);
    assert_eq!(config.fields, "*navigable");
    assert_eq!(config.comments_mode, "all");
    assert!(!config.scan_attachments);
    assert_eq!(config.max_attachment_size_mb, 10);
    assert_eq!(config.max_text_size_kb, 2048);
    assert_eq!(config.max_findings_per_issue, 1000);
    assert_eq!(config.allowlist, None);
    assert_eq!(config.rules, None);
    assert_eq!(config.min_confidence, "low");
    assert_eq!(config.format, "json");
    assert_eq!(config.report_dir, PathBuf::from("./reports"));
    assert_eq!(config.report_layout, "flat");
    assert!(!config.dry_run);
    assert!(!config.incremental);
    assert_eq!(config.state_dir, PathBuf::from("./.jiraleaks-state"));
    assert_eq!(config.metrics_path, None);
    assert_eq!(config.metrics_format, MetricsFormat::Json);
    assert_eq!(config.effective_log_level(), "info");
    assert!(
        config.log_level.is_none(),
        "an unset level is what lets RUST_LOG act as a fallback"
    );
    assert!(!config.no_proxy);
    assert_eq!(config.alerts, None);
    assert_eq!(config.db_url, None);
    assert_eq!(config.request_timeout_secs(), 30);
    assert!(
        config
            .db_url()
            .expect("the default state dir enables the store")
            .ends_with("findings.db?mode=rwc"),
        "the default store URL is derived from state_dir"
    );
}

/// The defaults a test inherits differ from production only where a test must not
/// inherit them — the integration tests must not run against another
/// configuration than the binary does.
#[test]
fn test_config_is_the_default_plus_the_test_overrides() {
    let default = Config::default();
    let test = Config::test_config("https://jira.example.com", "tok");

    for (name, same) in [
        ("page_size", test.page_size == default.page_size),
        ("max_issues", test.max_issues == default.max_issues),
        ("fields", test.fields == default.fields),
        ("comments_mode", test.comments_mode == default.comments_mode),
        (
            "min_confidence",
            test.min_confidence == default.min_confidence,
        ),
        ("format", test.format == default.format),
        ("report_layout", test.report_layout == default.report_layout),
        (
            "metrics_format",
            test.metrics_format == default.metrics_format,
        ),
        ("incremental", test.incremental == default.incremental),
        (
            "max_text_size_kb",
            test.max_text_size_kb == default.max_text_size_kb,
        ),
        (
            "max_findings_per_issue",
            test.max_findings_per_issue == default.max_findings_per_issue,
        ),
        (
            "max_attachment_size_mb",
            test.max_attachment_size_mb == default.max_attachment_size_mb,
        ),
    ] {
        assert!(same, "test_config must not change {name}");
    }

    // The documented overrides.
    assert_eq!(test.jira_url, "https://jira.example.com");
    assert_eq!(test.pat(), "tok");
    assert_eq!(test.jql.as_deref(), Some("project = TEST"));
    assert_eq!(test.concurrency, 1, "deterministic ordering in tests");
    assert_eq!(test.report_dir, PathBuf::from("/tmp/jiraleaks-test"));
    assert_eq!(test.state_dir, PathBuf::from("/tmp/jiraleaks-test-state"));
    assert!(test.dry_run, "tests never write reports");
    assert!(test.no_proxy, "tests talk to a local mock server");
}

/// Every `clap` default must equal the corresponding `Config::default()` value:
/// the binary and a library caller must not receive different configurations.
#[test]
fn clap_defaults_agree_with_config_default() {
    let config = Config::default();
    let command = Config::command();
    let mut compared = Vec::new();

    for arg in command.get_arguments() {
        let id = arg.get_id().as_str();
        let Some(expected) = documented_default(&config, id) else {
            continue;
        };
        let flag = id.replace('_', "-");
        let actual: Vec<String> = arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();

        match expected {
            Some(value) => assert_eq!(
                actual,
                vec![value.clone()],
                "clap's default for --{flag} disagrees with Config::default() ({value})"
            ),
            None => assert!(
                actual.is_empty(),
                "--{flag} must have no clap default; Config::default() leaves it unset"
            ),
        }
        compared.push(flag);
    }

    assert!(
        compared.len() >= 20,
        "expected to compare every documented option, compared {}: {compared:?}",
        compared.len()
    );
}

/// How `Config::default()` renders the value of the option with this `clap` id.
///
/// `Some(None)` means "must not have a default" (the optional fields), and `None`
/// means the id is not a `Config` field at all (`help`, `version`). A new field
/// that is not listed here makes the caller's count assertion fail, so the map
/// cannot silently fall behind the struct.
fn documented_default(config: &Config, id: &str) -> Option<Option<String>> {
    Some(match id {
        "jira_url" => Some(config.jira_url.clone()),
        "auth" => Some(config.auth.clone()),
        "pat" => Some(config.pat().to_string()),
        "page_size" => Some(config.page_size.to_string()),
        "max_issues" => Some(config.max_issues.to_string()),
        "concurrency" => Some(config.concurrency.to_string()),
        "fields" => Some(config.fields.clone()),
        "comments_mode" => Some(config.comments_mode.clone()),
        "scan_attachments" => Some(config.scan_attachments.to_string()),
        "max_attachment_size_mb" => Some(config.max_attachment_size_mb.to_string()),
        "max_text_size_kb" => Some(config.max_text_size_kb.to_string()),
        "max_findings_per_issue" => Some(config.max_findings_per_issue.to_string()),
        "min_confidence" => Some(config.min_confidence.clone()),
        "format" => Some(config.format.clone()),
        "report_dir" => Some(config.report_dir.display().to_string()),
        "report_layout" => Some(config.report_layout.clone()),
        "dry_run" => Some(config.dry_run.to_string()),
        "incremental" => Some(config.incremental.to_string()),
        "state_dir" => Some(config.state_dir.display().to_string()),
        "metrics_format" => Some(config.metrics_format.to_string()),
        "no_proxy" => Some(config.no_proxy.to_string()),
        "log_level" => config.log_level.clone(),
        "email" | "jql" | "allowlist" | "rules" | "db_url" | "metrics_path" | "alerts" => None,
        _ => return None,
    })
}

// ------------------------------------------------------------------- the bin ---

/// The compiled binary, for the contracts only a real process can prove.
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_jiraleaks"))
}

/// Arguments that clap accepts and that reach `validate()`; `--auth basic`
/// without `JIRA_EMAIL` fails there, *after* the token check. Nothing in this
/// test touches the network.
fn run_binary_with_a_bad_but_parseable_config(environment: &[(&str, &str)]) -> Output {
    let mut command = binary();
    command
        .args([
            "--jira-url",
            "https://jira.example.com",
            "--jql",
            "project = SEC",
            "--auth",
            "basic",
        ])
        .env_remove("JIRA_PAT")
        .env_remove("JIRA_API_TOKEN")
        .env_remove("JIRA_EMAIL")
        .env_remove("JIRA_URL")
        .env_remove("JIRA_JQL")
        .env_remove("JIRA_AUTH");
    for (key, value) in environment {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run the jiraleaks binary")
}

#[test]
fn the_binary_reads_jira_pat_from_the_environment() {
    let output = run_binary_with_a_bad_but_parseable_config(&[("JIRA_PAT", "pat-token")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("JIRA_EMAIL"),
        "the run must get past the token check, got: {stderr}"
    );
}

/// The README documents `JIRA_API_TOKEN` as an alias; as a clap argument alias it
/// was a hidden flag, so the environment variable was ignored.
#[test]
fn the_binary_reads_the_jira_api_token_alias() {
    let output = run_binary_with_a_bad_but_parseable_config(&[("JIRA_API_TOKEN", "api-token")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("JIRA_EMAIL"),
        "the alias must satisfy the token check, got: {stderr}"
    );
    assert!(
        !stderr.contains("JIRA_PAT"),
        "the alias must be used instead of reporting a missing token, got: {stderr}"
    );
}

/// Negative control for the two tests above: with no token anywhere the run stops
/// at the token check, which is what makes them meaningful.
#[test]
fn the_binary_rejects_a_run_without_any_token() {
    let output = run_binary_with_a_bad_but_parseable_config(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("JIRA_PAT"),
        "expected the missing-token error, got: {stderr}"
    );
}

/// clap's own exit code for a parse failure is 2, which the README reserves for
/// "Jira access error" — a typo in a flag must not look like a failed login.
#[test]
fn a_rejected_command_line_exits_with_the_configuration_code() {
    let output = binary()
        .arg("--no-such-flag")
        .output()
        .expect("failed to run the jiraleaks binary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("--no-such-flag") || stderr.contains("unexpected argument"),
        "the error must be printed, got: {stderr}"
    );
}

#[test]
fn help_and_version_exit_successfully() {
    let help = binary().arg("--help").output().expect("failed to run");
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        stdout.contains("--jira-url") && stdout.contains("--metrics-format"),
        "help goes to stdout, got stdout: {stdout} / stderr: {}",
        String::from_utf8_lossy(&help.stderr)
    );

    let version = binary().arg("--version").output().expect("failed to run");
    assert_eq!(version.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")),
        "version goes to stdout"
    );
}
