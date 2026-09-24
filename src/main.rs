use std::process::ExitCode;

use clap::Parser;
use jiraleaks::config::Config;

fn main() -> ExitCode {
    let config = match Config::try_parse() {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    // Shell completion script generation
    if let Some(shell) = config.completions() {
        use clap::CommandFactory;
        let mut cmd = Config::command();
        clap_complete::generate(shell, &mut cmd, "jiraleaks", &mut std::io::stdout());
        return ExitCode::SUCCESS;
    }

    if let Err(e) = config.validate() {
        eprintln!("{e}");
        return e.exit_code();
    }

    if let Err(e) = jiraleaks::log::init(&config) {
        eprintln!("Failed to initialize logging: {e}");
        return ExitCode::from(1);
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

async fn async_main(config: Config) -> ExitCode {
    use jiraleaks::jira::client::JiraClient;
    use jiraleaks::pipeline;

    let client = match JiraClient::new(&config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create Jira client");
            return e.exit_code();
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
            return e.exit_code();
        }
    }

    match pipeline::run(config, client).await {
        Ok(exit_code) => exit_code,
        Err(e) => {
            tracing::error!(error = %e, "Pipeline failed");
            e.exit_code()
        }
    }
}
