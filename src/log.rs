use tracing_subscriber::EnvFilter;

use crate::config::Config;

/// Initialize tracing/logging with the configured log level.
pub fn init(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|e| format!("tracing subscriber init failed: {e}").into())
}
