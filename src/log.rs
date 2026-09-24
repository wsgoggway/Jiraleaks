use tracing_subscriber::EnvFilter;

use crate::config::{Config, DEFAULT_LOG_LEVEL};
use crate::error::ScannerError;

/// Which source the effective tracing filter came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterSource {
    /// `--log-level` or `LOG_LEVEL` was given explicitly.
    ExplicitLevel,
    /// Nothing was configured; `RUST_LOG` supplied the filter.
    RustEnv,
    /// Neither was given; [`DEFAULT_LOG_LEVEL`] applies.
    Default,
}

/// Decide the effective log filter from the configured level and `RUST_LOG`.
///
/// Priority: an explicitly configured level wins; `RUST_LOG` is only a
/// **fallback**, consulted when no level was configured. That is the documented
/// CLI contract — `--log-level` / `LOG_LEVEL` are the flags in `--help` and in
/// the README — and the alternative (letting `RUST_LOG` win) silently overrides
/// the operator: `RUST_LOG` is inherited from developer shells, CI images and
/// systemd units, so a service started with `--log-level warn` in an environment
/// that happens to export `RUST_LOG=debug` produced debug output and nobody could
/// tell why.
///
/// `None`, an empty string and a whitespace-only string all count as "not set".
/// The level is returned as a filter *directive string*, so `RUST_LOG`-style
/// values (`jiraleaks=debug,hyper=warn`) keep working.
pub fn resolve_filter(level: Option<&str>, rust_log: Option<&str>) -> (String, FilterSource) {
    fn present(value: Option<&str>) -> Option<&str> {
        value.filter(|v| !v.trim().is_empty())
    }

    if let Some(level) = present(level) {
        (level.to_string(), FilterSource::ExplicitLevel)
    } else if let Some(rust_log) = present(rust_log) {
        (rust_log.to_string(), FilterSource::RustEnv)
    } else {
        (DEFAULT_LOG_LEVEL.to_string(), FilterSource::Default)
    }
}

/// Initialize tracing/logging with the configured log level.
///
/// The only way this fails is a subscriber that is already installed (a second
/// call in the same process), which is a startup error and not something a scan
/// can continue past — hence [`ScannerError`] rather than a printable string, so
/// the process exits with the code belonging to the failure instead of a
/// hardcoded one.
pub fn init(config: &Config) -> Result<(), ScannerError> {
    let (effective, source) = resolve_filter(
        config.log_level.as_deref(),
        std::env::var("RUST_LOG").ok().as_deref(),
    );

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&effective))
        .with_target(false)
        .try_init()
        .map_err(|e| ScannerError::Other(format!("tracing subscriber init failed: {e}")))?;

    if source == FilterSource::ExplicitLevel {
        if let Ok(rust_log) = std::env::var("RUST_LOG") {
            tracing::debug!(
                rust_log = %rust_log,
                effective = %effective,
                "RUST_LOG ignored: --log-level/LOG_LEVEL was set explicitly"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_level_beats_rust_log() {
        assert_eq!(
            resolve_filter(Some("warn"), Some("debug")),
            ("warn".to_string(), FilterSource::ExplicitLevel)
        );
    }

    #[test]
    fn rust_log_is_the_fallback() {
        assert_eq!(
            resolve_filter(None, Some("jiraleaks=debug,hyper=warn")),
            (
                "jiraleaks=debug,hyper=warn".to_string(),
                FilterSource::RustEnv
            )
        );
        assert_eq!(
            resolve_filter(Some("  "), Some("trace")),
            ("trace".to_string(), FilterSource::RustEnv)
        );
        assert_eq!(
            resolve_filter(Some(""), None),
            (DEFAULT_LOG_LEVEL.to_string(), FilterSource::Default)
        );
    }

    #[test]
    fn nothing_set_falls_back_to_the_documented_default() {
        assert_eq!(
            resolve_filter(None, None),
            (DEFAULT_LOG_LEVEL.to_string(), FilterSource::Default)
        );
        assert_eq!(DEFAULT_LOG_LEVEL, "info");
    }
}
