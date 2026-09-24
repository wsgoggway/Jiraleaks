pub mod csv;
pub mod defectdojo;
pub mod json;
pub mod ndjson;
pub mod sarif;
pub mod summary;

use crate::config::Config;
use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Write reports in all configured formats.
pub fn write_reports(
    config: &Config,
    scan_run: &ScanRun,
    findings: &[Finding],
) -> Result<(), ScannerError> {
    let now = time::OffsetDateTime::now_utc();
    let date_part = now
        .format(&time::format_description::parse_borrowed::<1>("[year]-[month]-[day]").unwrap())
        .unwrap_or_else(|_| "unknown".into());
    let time_part = now
        .format(&time::format_description::parse_borrowed::<1>("[hour]-[minute]-[second]").unwrap())
        .unwrap_or_else(|_| "unknown".into());

    let nested = config.report_layout == "nested";
    // `flat` (default) lays reports directly under report_dir; `nested` groups
    // them by Jira project and scan date: report_dir/<project>/<date>/<time>_report.ext
    let base: std::path::PathBuf = if nested {
        let project = project_segment(config.jql().unwrap_or(""));
        config.report_dir.join(project).join(&date_part)
    } else {
        config.report_dir.clone()
    };

    // Create report dir (and parent segments for nested) with 0700 permissions
    std::fs::create_dir_all(&base).map_err(|e| {
        ScannerError::ReportWrite(format!(
            "Failed to create report dir {}: {e}",
            base.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).ok();
    }

    let formats: Vec<&str> = if config.format == "all" {
        vec!["json", "ndjson", "csv", "sarif", "summary", "defectdojo"]
    } else {
        config.format.split(',').map(|s| s.trim()).collect()
    };

    for fmt in &formats {
        let ext = match *fmt {
            "json" => "json",
            "ndjson" => "ndjson",
            "csv" => "csv",
            "sarif" => "sarif",
            "summary" => "txt",
            "defectdojo" => "defectdojo.json",
            _ => continue,
        };

        let filename = if nested {
            // Date already encoded in the path; time keeps same-day scans unique.
            format!("{time_part}_report.{ext}")
        } else {
            format!("{date_part}T{time_part}_report.{ext}")
        };
        let path = base.join(&filename);

        match *fmt {
            "json" => json::write(&path, scan_run, findings)?,
            "ndjson" => ndjson::write(&path, findings)?,
            "csv" => csv::write(&path, findings)?,
            "sarif" => sarif::write(&path, scan_run, findings)?,
            "summary" => summary::write(&path, scan_run, findings)?,
            "defectdojo" => defectdojo::write(&path, findings)?,
            _ => {}
        }

        tracing::info!(format = fmt, path = %path.display(), "Report written");
    }

    Ok(())
}

/// Extract a path-safe project segment from a JQL query.
///
/// Examples:
///   `project = SEC`         -> "SEC"
///   `project = "SEC"`       -> "SEC"
///   `project in (SEC)`      -> "SEC"
///   `project in (SEC, PROJ)` -> "_multi"
///   (no single project)     -> "_default"
///
/// Only the `[A-Za-z0-9_-]` characters of a single project token are kept; all
/// fallback names are literal and path-safe.
fn project_segment(jql: &str) -> String {
    let lower = jql.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find("project") {
        let start = from + rel;
        let end = start + "project".len();
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end == lower.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return classify_after_project(&jql[end..]);
        }
        from = end;
    }
    "_default".to_string()
}

/// Inspect the JQL substring following the `project` keyword.
///
/// Handles `= <token>` and `in (<tok>, ...)` forms; anything else yields
/// `_default`.
fn classify_after_project(rest: &str) -> String {
    let trimmed = rest.trim_start();
    if let Some(after_eq) = trimmed.strip_prefix('=') {
        return read_token(after_eq.trim_start()).unwrap_or_else(|| "_default".to_string());
    }
    // `in` operator, matched case-insensitively: JQL keywords are case-insensitive,
    // but the project value is re-sliced from the original string to keep its casing.
    let lower = trimmed.to_ascii_lowercase();
    if let Some(after_in) = lower.strip_prefix("in") {
        // "in" must be a whole word: the following byte must not be alphanumeric.
        let boundary_ok = after_in
            .as_bytes()
            .first()
            .map(|b| !b.is_ascii_alphanumeric())
            .unwrap_or(true);
        if boundary_ok {
            let r = trimmed[2..].trim_start();
            if r.starts_with('(') {
                let inner = r.trim_start_matches('(').split(')').next().unwrap_or("");
                let tokens: Vec<String> = inner
                    .split(',')
                    .map(|t| t.trim().trim_matches('"').to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                return match tokens.len() {
                    0 => "_default".to_string(),
                    1 => tokens.into_iter().next().unwrap(),
                    _ => "_multi".to_string(),
                };
            }
        }
    }
    "_default".to_string()
}

/// Read one `[A-Za-z0-9_-]+` token, stripping a leading quote if present.
fn read_token(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches('"');
    let token: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::finding::{ScanRun, ScanStatus};

    fn sample_scan_run() -> ScanRun {
        ScanRun {
            scan_id: "test-scan".into(),
            status: ScanStatus::Success,
            started_at: "2026-01-01T00:00:00Z".into(),
            finished_at: "2026-01-01T00:00:01Z".into(),
            jira_url: "https://jira.example.com".into(),
            jql: "project = SEC".into(),
            issues_scanned: 0,
            issues_total: 0,
            findings_total: 0,
            findings_critical: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
            findings_info: 0,
            errors_total: 0,
            comments_scanned: 0,
            attachments_scanned: 0,
            scanner_version: "test".into(),
            duration_secs: 0.0,
        }
    }

    fn report_files(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("report dir readable")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with("_report.json"))
            .collect()
    }

    #[test]
    fn project_segment_single() {
        assert_eq!(project_segment("project = SEC"), "SEC");
        assert_eq!(project_segment("project=SEC"), "SEC");
        assert_eq!(project_segment("Project = \"SEC\""), "SEC");
        assert_eq!(project_segment("PROJECT IN (SEC)"), "SEC");
        assert_eq!(project_segment("project in ( SEC )"), "SEC");
    }

    #[test]
    fn project_segment_multi() {
        assert_eq!(project_segment("project in (SEC)"), "SEC");
        assert_eq!(project_segment("project in (SEC, PROJ)"), "_multi");
        assert_eq!(project_segment("project in(SEC, PROJ)"), "_multi");
    }

    #[test]
    fn project_segment_default() {
        assert_eq!(project_segment("text ~ \"foo\""), "_default");
        assert_eq!(project_segment(""), "_default");
        assert_eq!(project_segment("projectName = X"), "_default");
        assert_eq!(project_segment("status = Open"), "_default");
    }

    #[test]
    fn write_reports_nested_layout_single_project() {
        let dir =
            std::env::temp_dir().join(format!("jiraleaks-report-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::test_config("https://jira.example.com", "tok");
        cfg.report_layout = "nested".into();
        cfg.jql = Some("project = SEC".into());
        cfg.report_dir = dir.clone();

        write_reports(&cfg, &sample_scan_run(), &[]).unwrap();

        // Layout: report_dir/<project>/<date>/<time>_report.json
        let project_dir = dir.join("SEC");
        assert!(project_dir.is_dir(), "project segment dir should exist");
        let date_dirs: Vec<_> = std::fs::read_dir(&project_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();
        assert_eq!(date_dirs.len(), 1, "exactly one date directory");
        let files = report_files(&date_dirs[0].path());
        assert_eq!(files.len(), 1, "one json report in nested layout");
        assert!(
            !files[0].contains('T'),
            "nested filename is time-only (no date/T): got {}",
            files[0]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_reports_nested_layout_other_segments() {
        for (jql, expected) in [
            ("project in (SEC, PROJ)", "_multi"),
            ("text ~ \"foo\"", "_default"),
        ] {
            let dir = std::env::temp_dir().join(format!(
                "jiraleaks-report-nested-{expected}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let mut cfg = Config::test_config("https://jira.example.com", "tok");
            cfg.report_layout = "nested".into();
            cfg.jql = Some(jql.into());
            cfg.report_dir = dir.clone();

            write_reports(&cfg, &sample_scan_run(), &[]).unwrap();

            assert!(
                dir.join(expected).is_dir(),
                "{expected} segment dir should exist for JQL `{jql}`"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn write_reports_flat_layout() {
        let dir =
            std::env::temp_dir().join(format!("jiraleaks-report-flat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::test_config("https://jira.example.com", "tok");
        cfg.report_layout = "flat".into();
        cfg.report_dir = dir.clone();

        write_reports(&cfg, &sample_scan_run(), &[]).unwrap();

        // Layout: report_dir/<date>T<time>_report.json (byte-identical to pre-change)
        let files = report_files(&dir);
        assert_eq!(files.len(), 1, "one json report in flat layout");
        assert!(
            files[0].contains('T'),
            "flat filename embeds date and time: got {}",
            files[0]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
