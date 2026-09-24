use std::process::ExitCode;

use clap::Parser;
use jiraleaks::config::Config;
use jiraleaks::error::ScannerError;

fn main() -> ExitCode {
    let mut config = match Config::try_parse() {
        Ok(c) => c,
        Err(e) => return report_cli_error(e),
    };

    // clap fills the token from `--pat` only: the environment fallbacks
    // (`JIRA_PAT`, then the legacy `JIRA_API_TOKEN`) are applied here, before
    // anything validates the token.
    config.resolve_pat_from_env();

    // Shell completion script generation
    if let Some(shell) = config.completions() {
        use clap::CommandFactory;
        let mut cmd = Config::command();
        clap_complete::generate(shell, &mut cmd, "jiraleaks", &mut std::io::stdout());
        return ExitCode::SUCCESS;
    }

    if let Err(e) = config.validate() {
        eprintln!("{e}");
        return ExitCode::from(e.exit_code());
    }

    if let Err(e) = jiraleaks::log::init(&config) {
        eprintln!("Failed to initialize logging: {e}");
        return ExitCode::from(e.exit_code());
    }

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Starting jiraleaks");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    let exit_code = rt.block_on(async_main(config));

    tracing::info!(?exit_code, "Scanner finished");
    rt.shutdown_background();
    exit_code
}

/// Print a command-line error and map it to the process exit code.
///
/// clap's `Err` covers two very different outcomes, and `clap::Error::exit` would
/// use its own code (2) for both:
///
/// - the user asked for `--help` or `--version` (`use_stderr()` is false): the
///   text is the requested output, so it goes to stdout and the process succeeds;
/// - the command line is wrong — an unknown flag, a rejected value, a missing
///   argument (`use_stderr()` is true): a configuration error, exit code
///   [`ScannerError::CLI_PARSE_EXIT_CODE`]. It must not be 2, which the README
///   and [`ScannerError::exit_code`] reserve for "Jira access error": a typo in a
///   flag used to be indistinguishable from a failed authentication.
fn report_cli_error(error: clap::Error) -> ExitCode {
    // A closed stdout/stderr must not change the outcome of the process.
    let _ = error.print();

    if error.use_stderr() {
        ExitCode::from(ScannerError::CLI_PARSE_EXIT_CODE)
    } else {
        ExitCode::SUCCESS
    }
}

async fn async_main(config: Config) -> ExitCode {
    use jiraleaks::jira::client::JiraClient;
    use jiraleaks::pipeline;

    let client = match JiraClient::new(&config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create Jira client");
            return ExitCode::from(e.exit_code());
        }
    };

    match client.server_info().await {
        Ok(info) => {
            tracing::info!(
                base_url = %info.base_url,
                version = %info.version,
                deployment_type = %info.deployment_type,
                "Connected to Jira"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to connect to Jira");
            return ExitCode::from(e.exit_code());
        }
    }

    match pipeline::run(config, client).await {
        Ok(exit_code) => exit_code,
        Err(e) => {
            tracing::error!(error = %e, "Pipeline failed");
            ExitCode::from(e.exit_code())
        }
    }
}
