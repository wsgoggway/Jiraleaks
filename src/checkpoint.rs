use std::fs;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::config::Config;
use crate::error::ScannerError;
use crate::finding::ScanRun;

/// Checkpoint state for incremental scanning (spec §10.16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub last_run_at: String,
    pub last_updated_issue_time: String,
    pub last_issue_key: String,
    pub status: String,
}

/// Read the checkpoint file. Returns None if the file doesn't exist.
pub fn read_checkpoint(config: &Config) -> Option<Checkpoint> {
    let path = checkpoint_path(config);
    if !path.exists() {
        tracing::info!("No checkpoint file found, performing full scan");
        return None;
    }

    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<Checkpoint>(&content) {
            Ok(cp) => {
                tracing::info!(
                    last_run = %cp.last_run_at,
                    "Loaded checkpoint"
                );
                Some(cp)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse checkpoint, performing full scan");
                None
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read checkpoint, performing full scan");
            None
        }
    }
}

/// Write a checkpoint after a successful scan.
pub fn write_checkpoint(
    config: &Config,
    scan_run: &ScanRun,
) -> Result<(), ScannerError> {
    let state_dir = &config.state_dir;
    fs::create_dir_all(state_dir).map_err(|e| {
        ScannerError::ReportWrite(format!(
            "Failed to create state dir {}: {e}",
            state_dir.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700)).ok();
    }

    let now = OffsetDateTime::now_utc();
    let cp = Checkpoint {
        last_run_at: now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        last_updated_issue_time: scan_run.finished_at.clone(),
        last_issue_key: String::new(),
        status: "success".to_string(),
    };

    let json = serde_json::to_string_pretty(&cp).map_err(|e| {
        ScannerError::ReportWrite(format!("Checkpoint serialization error: {e}"))
    })?;

    let path = checkpoint_path(config);
    fs::write(&path, json).map_err(|e| {
        ScannerError::ReportWrite(format!("Failed to write checkpoint: {e}"))
    })?;

    tracing::info!(path = %path.display(), "Checkpoint written");
    Ok(())
}

fn checkpoint_path(config: &Config) -> std::path::PathBuf {
    config.state_dir.join("checkpoint.json")
}
