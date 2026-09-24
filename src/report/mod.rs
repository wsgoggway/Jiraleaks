pub mod csv;
pub mod defectdojo;
pub mod json;
pub mod ndjson;
pub mod sarif;
pub mod summary;

use std::path::{Component, Path, PathBuf};

use crate::config::Config;
use crate::error::ScannerError;
use crate::finding::{Finding, ScanRun};

/// Everything a report writer is given: the scan it belongs to and the findings
/// to report.
///
/// Every writer has the signature `fn(&Path, &ReportInput) -> Result<(), ScannerError>`,
/// so the [`CATALOGUE`] can hold them all as one function-pointer type. A writer
/// ignores the parts it does not use (CSV reads only `findings`, for instance)
/// instead of carrying a second arity that the dispatch would have to remember.
pub struct ReportInput<'a> {
    /// Metadata of the scan that produced the findings.
    pub scan_run: &'a ScanRun,
    /// Findings to report, in scan order.
    pub findings: &'a [Finding],
}

/// One report format: the name `--format` accepts, the file extension it writes,
/// and the writer itself.
#[derive(Debug)]
pub struct ReportFormat {
    /// Name accepted by `--format`.
    pub name: &'static str,
    /// Extension of the written file (`summary` writes `.txt`, DefectDojo writes
    /// `.defectdojo.json`).
    pub ext: &'static str,
    /// The writer.
    pub write: fn(&Path, &ReportInput<'_>) -> Result<(), ScannerError>,
}

/// The single source of truth about report formats.
///
/// `--format` validation ([`FORMAT_NAMES`]), `all` expansion, the output
/// extension and the dispatch all read this one table, so a format can no longer
/// be half-added: a name without an extension or a writer does not compile, and a
/// writer without a name is unreachable. Previously the name list, the
/// name-to-extension map and the dispatch were three separate matches, and a
/// format present in the first but missing from the third was logged as written
/// while nothing was written at all.
pub const CATALOGUE: &[ReportFormat] = &[
    ReportFormat {
        name: "json",
        ext: "json",
        write: json::write,
    },
    ReportFormat {
        name: "ndjson",
        ext: "ndjson",
        write: ndjson::write,
    },
    ReportFormat {
        name: "csv",
        ext: "csv",
        write: csv::write,
    },
    ReportFormat {
        name: "sarif",
        ext: "sarif",
        write: sarif::write,
    },
    ReportFormat {
        name: "summary",
        ext: "txt",
        write: summary::write,
    },
    ReportFormat {
        name: "defectdojo",
        ext: "defectdojo.json",
        write: defectdojo::write,
    },
];

/// Every format name, in catalogue order: what `--format` validates against and
/// what `all` expands to.
///
/// Kept in step with [`CATALOGUE`] by `format_names_match_the_catalogue`, which
/// fails the test suite rather than letting the two drift apart.
pub const FORMAT_NAMES: &[&str] = &["json", "ndjson", "csv", "sarif", "summary", "defectdojo"];

/// Resolve a `--format` value into the formats to write.
///
/// * `all` — anywhere in the list, so `json,all` behaves like `all` — expands to
///   every format in the catalogue;
/// * an unknown or empty name is a [`ScannerError::Config`], never a silent
///   no-op that leaves the operator without the report they asked for;
/// * duplicates collapse, so no report is ever written twice.
pub fn resolve_formats(spec: &str) -> Result<Vec<&'static ReportFormat>, ScannerError> {
    let unknown = |name: &str| {
        ScannerError::Config(format!(
            "unknown report format '{name}', expected one of: {}, all",
            FORMAT_NAMES.join(", ")
        ))
    };

    let mut selected: Vec<&'static ReportFormat> = Vec::new();
    for raw in spec.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            return Err(unknown(name));
        }
        if name == "all" {
            for format in CATALOGUE {
                if !selected.iter().any(|s| s.name == format.name) {
                    selected.push(format);
                }
            }
            continue;
        }
        let format = CATALOGUE
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| unknown(name))?;
        if !selected.iter().any(|s| s.name == format.name) {
            selected.push(format);
        }
    }

    Ok(selected)
}

/// Write reports in all configured formats.
pub fn write_reports(
    config: &Config,
    scan_run: &ScanRun,
    findings: &[Finding],
) -> Result<(), ScannerError> {
    // Resolve first: a bad `--format` must fail before any directory is created.
    let formats = resolve_formats(&config.format)?;

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
    let base: PathBuf = if nested {
        let project = project_segment(config.jql().unwrap_or(""));
        secure_join(&config.report_dir, &[&project, &date_part])?
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

    let input = ReportInput { scan_run, findings };
    for format in formats {
        let filename = if nested {
            // Date already encoded in the path; time keeps same-day scans unique.
            format!("{time_part}_report.{}", format.ext)
        } else {
            format!("{date_part}T{time_part}_report.{}", format.ext)
        };
        let path = base.join(&filename);

        (format.write)(&path, &input)?;
        // Logged only after the writer returned Ok, so the log cannot claim a
        // report was written when its writer failed.
        tracing::info!(format = format.name, path = %path.display(), "Report written");
    }

    Ok(())
}

/// Join `segments` under `root`, rejecting any segment that could escape it.
///
/// Pure — it touches no filesystem — and deliberately strict: a segment must be
/// exactly one normal path component. `..`, `.`, an absolute path, an empty
/// segment, a Windows drive prefix and a segment containing a path separator are
/// all rejected. [`project_segment`] already filters the project name down to
/// `[A-Za-z0-9_-]`; this is the second line of defence, so a future change to that
/// filter cannot quietly start writing reports outside `root`.
fn secure_join(root: &Path, segments: &[&str]) -> Result<PathBuf, ScannerError> {
    let mut path = root.to_path_buf();
    for segment in segments {
        let mut components = Path::new(segment).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(part)), None) => path.push(part),
            _ => {
                return Err(ScannerError::Config(format!(
                    "refusing to write a report outside {}: path segment {segment:?} is not a plain directory name",
                    root.display()
                )))
            }
        }
    }
    Ok(path)
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
/// Only the `[A-Za-z0-9_-]` characters of a single project token are kept; a token
/// that filters down to nothing is not a project at all. Both fallback names are
/// literals. This holds for every form of the JQL — `=` and `in (...)` alike — so
/// `project in (../../../../tmp/pwned)` lands under `_default` inside the report
/// directory rather than next to `/tmp`.
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
/// `_default`. The project tokens of both forms are read by [`read_token`], so no
/// token reaches the path builder unfiltered.
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
                // Every token goes through the same `[A-Za-z0-9_-]` filter as the
                // `=` form: a token that filters down to nothing — a relative path,
                // a string with separators, an operator — is not a project and does
                // not count towards the token count.
                let mut tokens: Vec<String> = inner.split(',').filter_map(read_token).collect();
                return match tokens.len() {
                    0 => "_default".to_string(),
                    1 => tokens.remove(0),
                    _ => "_multi".to_string(),
                };
            }
        }
    }
    "_default".to_string()
}

/// Read one `[A-Za-z0-9_-]+` token, stripping a leading quote if present.
///
/// The only way a JQL-derived string enters a path: everything outside
/// `[A-Za-z0-9_-]` — `/`, `\`, `.`, `..`, quotes beyond a leading one — is cut
/// off, and a token with nothing left is `None`.
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

    /// The project segment is the one JQL-derived string that reaches a path, so a
    /// hostile query must never get past `[A-Za-z0-9_-]`.
    #[test]
    fn project_segment_rejects_paths() {
        assert_eq!(
            project_segment("project in (../../../../tmp/pwned)"),
            "_default"
        );
        assert_eq!(project_segment("project in (..)"), "_default");
        assert_eq!(project_segment("project in (.., ../..)"), "_default");
        assert_eq!(project_segment("project = ../../tmp/pwned"), "_default");
        assert_eq!(project_segment("project = /etc"), "_default");
        assert_eq!(project_segment("project = \"./x\""), "_default");
        // Quotes are still stripped, and a path prefix is cut off at the separator.
        assert_eq!(project_segment("project in (\"SEC\")"), "SEC");
        assert_eq!(project_segment("project in (SEC/../../x)"), "SEC");
        // Junk tokens do not count as extra projects.
        assert_eq!(project_segment("project in (SEC, ../../x)"), "SEC");
        assert_eq!(project_segment("project in (../../x, SEC)"), "SEC");
    }

    #[test]
    fn secure_join_accepts_plain_segments() {
        let root = Path::new("/var/reports");
        assert_eq!(
            secure_join(root, &["SEC", "2026-01-01"]).unwrap(),
            Path::new("/var/reports/SEC/2026-01-01")
        );
        assert_eq!(secure_join(root, &[]).unwrap(), root);
    }

    #[test]
    fn secure_join_rejects_escaping_segments() {
        let root = Path::new("/var/reports");
        for segment in ["..", ".", "", "/etc", "/", "SEC/../../etc", "a/b", "./x"] {
            let err = secure_join(root, &["SEC", segment])
                .expect_err("segment {segment} must be rejected");
            assert!(
                matches!(err, ScannerError::Config(_)),
                "{segment} produced {err:?}"
            );
        }
        // A single hostile segment is enough, whatever the other ones are.
        assert!(secure_join(root, &["../SEC"]).is_err());
    }

    #[test]
    fn format_names_match_the_catalogue() {
        let from_catalogue: Vec<&str> = CATALOGUE.iter().map(|f| f.name).collect();
        assert_eq!(FORMAT_NAMES, from_catalogue.as_slice());
        // Names are unique: a duplicate would make `--format` ambiguous and write
        // one file twice.
        let mut sorted = from_catalogue.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), from_catalogue.len());
    }

    #[test]
    fn catalogue_extensions_are_plain_file_names() {
        for format in CATALOGUE {
            assert!(!format.ext.is_empty(), "{} has no extension", format.name);
            let mut components = Path::new(format.ext).components();
            match (components.next(), components.next()) {
                (Some(Component::Normal(_)), None) => {}
                other => panic!("{} has an unsafe extension: {other:?}", format.name),
            }
        }
    }

    #[test]
    fn resolve_formats_expands_all_and_deduplicates() {
        let all = resolve_formats("all").unwrap();
        assert_eq!(
            all.iter().map(|f| f.name).collect::<Vec<_>>(),
            vec!["json", "ndjson", "csv", "sarif", "summary", "defectdojo"]
        );

        // `all` inside a list behaves like `all`, and nothing is selected twice.
        let mixed = resolve_formats("json,all").unwrap();
        assert_eq!(mixed.len(), FORMAT_NAMES.len());
        assert_eq!(mixed[0].name, "json");

        let duplicated = resolve_formats("json, json ,json").unwrap();
        assert_eq!(duplicated.len(), 1);
        assert_eq!(duplicated[0].name, "json");

        let single = resolve_formats("sarif").unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].ext, "sarif");
    }

    #[test]
    fn resolve_formats_rejects_unknown_names() {
        for spec in ["bogus", "json,bogus", "", " ", "json,", "json,,csv"] {
            let err = resolve_formats(spec).expect_err("{spec} must be rejected");
            assert!(
                matches!(err, ScannerError::Config(_)),
                "{spec} produced {err:?}"
            );
        }
    }

    #[test]
    fn write_reports_rejects_unknown_format_before_writing_anything() {
        let dir =
            std::env::temp_dir().join(format!("jiraleaks-report-badfmt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::test_config("https://jira.example.com", "tok");
        cfg.report_dir = dir.clone();
        cfg.format = "json,bogus".into();

        let err = write_reports(&cfg, &sample_scan_run(), &[]).expect_err("bad format");
        assert!(matches!(err, ScannerError::Config(_)), "got {err:?}");
        assert!(
            !dir.exists(),
            "a rejected format must not create the report directory"
        );
    }

    #[test]
    fn write_reports_writes_each_selected_format_once() {
        let dir =
            std::env::temp_dir().join(format!("jiraleaks-report-catalogue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::test_config("https://jira.example.com", "tok");
        cfg.report_dir = dir.clone();
        cfg.format = "all".into();

        write_reports(&cfg, &sample_scan_run(), &[]).unwrap();

        let files: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            files.len(),
            FORMAT_NAMES.len(),
            "one file per catalogue format, got {files:?}"
        );
        for format in CATALOGUE {
            let suffix = format!("_report.{}", format.ext);
            let matching = files.iter().filter(|n| n.ends_with(&suffix)).count();
            assert_eq!(matching, 1, "{} -> {files:?}", format.name);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The nested layout groups reports by JQL project, i.e. by a string a scan
    /// operator copies from anywhere. A traversal there would write outside
    /// `report_dir`.
    #[test]
    fn write_reports_nested_layout_never_escapes_report_dir() {
        let pid = std::process::id();
        let traversal = format!("../../../../tmp/jiraleaks-escape-{pid}");
        for (jql, expected) in [
            (format!("project in ({traversal})"), "_default"),
            ("project in (..)".to_string(), "_default"),
            ("project in (\"SEC\")".to_string(), "SEC"),
            ("project = SEC".to_string(), "SEC"),
            ("project in (SEC, PROJ)".to_string(), "_multi"),
        ] {
            let dir =
                std::env::temp_dir().join(format!("jiraleaks-report-escape-{expected}-{pid}"));
            let _ = std::fs::remove_dir_all(&dir);
            let escape_target = normalize(&dir.join(&traversal));
            let _ = std::fs::remove_dir_all(&escape_target);

            let mut cfg = Config::test_config("https://jira.example.com", "tok");
            cfg.report_layout = "nested".into();
            cfg.jql = Some(jql.clone());
            cfg.report_dir = dir.clone();

            write_reports(&cfg, &sample_scan_run(), &[]).unwrap();

            assert!(
                dir.join(expected).is_dir(),
                "JQL `{jql}` should group under {expected}"
            );
            assert!(
                !walk_files(&dir).is_empty(),
                "no report written under {} for `{jql}`",
                dir.display()
            );
            assert!(
                !escape_target.exists(),
                "JQL `{jql}` wrote outside the report dir: {}",
                escape_target.display()
            );

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Every file under `root`, recursively.
    fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    /// Lexically normalize `path` — collapse `.` and `..` — without touching the
    /// filesystem, so a test can name the path a traversal would have reached.
    fn normalize(path: &std::path::Path) -> std::path::PathBuf {
        let mut out = std::path::PathBuf::new();
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other.as_os_str()),
            }
        }
        out
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
