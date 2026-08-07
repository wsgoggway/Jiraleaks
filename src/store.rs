//! Persistent findings store with cross-scan status reconciliation and
//! live-validation join (spec §24 extension).
//!
//! Backed by `sqlx::Any` so the same code targets SQLite (local) and
//! PostgreSQL (deployment). Identity of a stored finding is the deterministic
//! `fingerprint(secret_hash, rule_id, issue_key)`; per-issue granularity lets
//! the reconciler close secrets that vanish from a re-scanned issue while
//! leaving unscanned issues untouched.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use sqlx::any::{Any, AnyPoolOptions, AnyRow};
use sqlx::Pool;
use sqlx::Row;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::ScannerError;
use crate::finding::{
    Confidence, ExternalValidation, Finding, FindingStatus, Location, ScanRun, ScanStatus,
    Severity, SourceType,
};

pub struct FindingsStore {
    pool: Pool<Any>,
    /// Whether the backing database is PostgreSQL (drives placeholder style).
    is_postgres: bool,
}

/// One row of the `findings` table as read back during reconciliation.
struct StoredRow {
    fp: String,
    secret_hash: String,
    rule_id: String,
    issue_key: String,
    issue_url: String,
    severity: String,
    confidence: String,
    status: String,
    field_path: String,
    source_type: String,
    redacted_secret: String,
    snippet: String,
    locations_json: String,
    references_json: String,
    username: Option<String>,
    first_seen: String,
    last_seen: String,
    times_seen: i64,
}

/// Deterministic primary key for a finding per (secret_hash, rule_id, issue_key).
///
/// `finding_id` (UUID v4) is regenerated each scan and is NOT a stable key.
fn fingerprint(secret_hash: &str, rule_id: &str, issue_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret_hash.as_bytes());
    h.update(b"\x1f");
    h.update(rule_id.as_bytes());
    h.update(b"\x1f");
    h.update(issue_key.as_bytes());
    format!("fp:{:x}", h.finalize())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

// --- enum <-> DB string round-tripping (DB-internal representation) ---

fn severity_to_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn str_to_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn confidence_to_str(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

fn str_to_confidence(s: &str) -> Confidence {
    match s {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        _ => Confidence::Low,
    }
}

fn source_type_to_str(st: SourceType) -> &'static str {
    match st {
        SourceType::Description => "description",
        SourceType::Comment => "comment",
        SourceType::Attachment => "attachment",
        SourceType::CustomField => "customfield",
    }
}

fn str_to_source_type(s: &str) -> SourceType {
    match s {
        "comment" => SourceType::Comment,
        "attachment" => SourceType::Attachment,
        "customfield" => SourceType::CustomField,
        _ => SourceType::Description,
    }
}

fn scan_status_to_str(s: ScanStatus) -> &'static str {
    match s {
        ScanStatus::Success => "success",
        ScanStatus::Failed => "failed",
        ScanStatus::Partial => "partial",
    }
}

/// A per-issue expansion of a current-scan finding, ready for INSERT.
struct Exp {
    fp: String,
    secret_hash: String,
    rule_id: String,
    issue_key: String,
    issue_url: String,
    field_path: String,
    source_type: &'static str,
    severity: &'static str,
    confidence: &'static str,
    redacted_secret: String,
    snippet: String,
    locations_json: String,
    references_json: String,
    username: Option<String>,
}

/// Ensure the parent directory of a file-backed SQLite database exists so that
/// opening with `mode=rwc` does not fail with `SQLITE_CANTOPEN` (code 14).
/// SQLite creates the database file but not its parent directories. No-op for
/// in-memory databases, non-SQLite URLs, or paths without a parent directory.
fn ensure_sqlite_parent_dir(db_url: &str) -> Result<(), ScannerError> {
    let rest = match db_url.strip_prefix("sqlite:") {
        Some(r) => r,
        None => return Ok(()), // Postgres or any other backend.
    };
    // In-memory databases carry no filesystem path.
    if rest.contains("memory") {
        return Ok(());
    }
    // Drop the `//` authority separator and any query/fragment, keeping the
    // leading slash for absolute paths (`sqlite:///abs/...` -> `/abs/...`).
    let path_str = rest
        .trim_start_matches("//")
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    if path_str.is_empty() {
        return Ok(());
    }
    if let Some(parent) = std::path::Path::new(path_str).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ScannerError::Store(format!("create state dir {}: {e}", parent.display()))
            })?;
        }
    }
    Ok(())
}

impl FindingsStore {
    /// Open/create the database.
    ///
    /// `db_url` examples:
    /// - `sqlite://./.jiraleaks-state/findings.db?mode=rwc`
    /// - `postgres://user:pass@host/db`
    pub async fn open(db_url: &str) -> Result<Self, ScannerError> {
        sqlx::any::install_default_drivers();
        ensure_sqlite_parent_dir(db_url)?;
        let is_postgres = db_url.starts_with("postgres");
        // In-memory SQLite (`:memory:`, `sqlite::memory:`) gives each pooled
        // connection its own private database; force a single connection so
        // migrations and reconcile share the same in-memory state. File and
        // Postgres URLs keep a small pool.
        let max_conn = if db_url.contains("memory") { 1 } else { 5 };
        let pool = AnyPoolOptions::new()
            .max_connections(max_conn)
            .connect(db_url)
            .await
            .map_err(|e| ScannerError::Store(format!("open {db_url}: {e}")))?;
        Ok(Self { pool, is_postgres })
    }

    /// Placeholder token for the 1-based bind position, backend-appropriate.
    /// SQLite expects `?`, PostgreSQL expects `$n`.
    fn ph(&self, i: usize) -> String {
        if self.is_postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    }

    /// Apply the schema migration. The DDL is idempotent (`IF NOT EXISTS`) and
    /// portable; statements are split and executed individually (SQLite only
    /// runs one statement per prepare).
    pub async fn migrate(&self) -> Result<(), ScannerError> {
        let sql = include_str!("../migrations/0001_init.sql");
        for raw in sql.split(';') {
            let cleaned: String = raw
                .lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let cleaned = cleaned.trim();
            if cleaned.is_empty() {
                continue;
            }
            sqlx::query(cleaned)
                .execute(&self.pool)
                .await
                .map_err(|e| ScannerError::Store(format!("migrate: {e}")))?;
        }
        Ok(())
    }

    /// Reconcile current-scan findings against stored state and return the
    /// enriched findings for reporting.
    ///
    /// - `scanned_issue_keys` = issues actually fetched this run (only these
    ///   are eligible for `Closed`).
    /// - `scan_started_at` = RFC3339 start of this scan; a finding whose
    ///   `first_seen` predates it is `Recurring`, otherwise `New`.
    pub async fn reconcile(
        &self,
        current: &[Finding],
        scanned_issue_keys: &HashSet<String>,
        scan_id: &str,
        scan_started_at: &str,
    ) -> Result<Vec<Finding>, ScannerError> {
        let now = now_rfc3339();

        // --- Expand current findings to per-(hash, rule, issue) rows ---
        let mut exps: Vec<Exp> = Vec::new();
        for f in current {
            let locs: Vec<Location> = if f.locations.is_empty() {
                vec![Location {
                    issue_key: f.issue_key.clone(),
                    field_path: f.field_path.clone(),
                    source_type: f.source_type,
                }]
            } else {
                f.locations.clone()
            };
            for loc in &locs {
                let loc_json =
                    serde_json::to_string(&vec![loc.clone()]).unwrap_or_else(|_| "[]".into());
                let refs_json =
                    serde_json::to_string(&f.references).unwrap_or_else(|_| "[]".into());
                exps.push(Exp {
                    fp: fingerprint(&f.secret_hash, &f.rule_id, &loc.issue_key),
                    secret_hash: f.secret_hash.clone(),
                    rule_id: f.rule_id.clone(),
                    issue_key: loc.issue_key.clone(),
                    issue_url: f.issue_url.clone(),
                    field_path: loc.field_path.clone(),
                    source_type: source_type_to_str(loc.source_type),
                    severity: severity_to_str(f.severity),
                    confidence: confidence_to_str(f.confidence),
                    redacted_secret: f.redacted_secret.clone(),
                    snippet: f.snippet.clone(),
                    locations_json: loc_json,
                    references_json: refs_json,
                    username: f.username.clone(),
                });
            }
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ScannerError::Store(format!("begin tx: {e}")))?;

        // --- Read stored rows for the scanned issues ---
        let mut stored_by_fp: HashMap<String, StoredRow> = HashMap::new();
        if !scanned_issue_keys.is_empty() {
            let keys: Vec<&String> = scanned_issue_keys.iter().collect();
            let placeholders = (1..=keys.len())
                .map(|i| self.ph(i))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT fingerprint, secret_hash, rule_id, issue_key, issue_url, \
                 severity, confidence, status, field_path, source_type, \
                 redacted_secret, snippet, locations_json, references_json, \
                 username, first_seen, last_seen, closed_at, times_seen \
                 FROM findings WHERE issue_key IN ({placeholders})"
            );
            let mut q = sqlx::query(&sql);
            for k in &keys {
                q = q.bind(*k);
            }
            let rows = q
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| ScannerError::Store(format!("read findings: {e}")))?;
            for row in &rows {
                let s = parse_stored(row)?;
                stored_by_fp.insert(s.fp.clone(), s);
            }
        }

        let current_fps: HashSet<&str> = exps.iter().map(|e| e.fp.as_str()).collect();

        // --- Close: stored rows in scanned issues absent from current ---
        let close_sql = format!(
            "UPDATE findings SET status = 'closed', closed_at = {p1}, last_seen = {p2}, \
             scan_id_last = {p3} WHERE fingerprint = {p4}",
            p1 = self.ph(1),
            p2 = self.ph(2),
            p3 = self.ph(3),
            p4 = self.ph(4)
        );
        for s in stored_by_fp.values() {
            if scanned_issue_keys.contains(&s.issue_key)
                && !current_fps.contains(s.fp.as_str())
                && s.status != "closed"
            {
                sqlx::query(&close_sql)
                    .bind(&now)
                    .bind(&now)
                    .bind(scan_id)
                    .bind(&s.fp)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| ScannerError::Store(format!("close finding: {e}")))?;
            }
        }

        // --- Upsert current rows (portable ON CONFLICT) ---
        let cols = [
            "fingerprint",
            "secret_hash",
            "rule_id",
            "issue_key",
            "issue_url",
            "severity",
            "confidence",
            "status",
            "field_path",
            "source_type",
            "redacted_secret",
            "snippet",
            "locations_json",
            "references_json",
            "username",
            "first_seen",
            "last_seen",
            "closed_at",
            "times_seen",
            "scan_id_last",
        ];
        let values = (1..=cols.len())
            .map(|i| self.ph(i))
            .collect::<Vec<_>>()
            .join(",");
        let col_list = cols.join(",");
        // On conflict: reopen as recurring, keep first_seen, clear closed_at,
        // increment times_seen. Both SQLite and PostgreSQL support EXCLUDED and
        // referencing the target table by name.
        let upsert_sql = format!(
            "INSERT INTO findings ({col_list}) VALUES ({values}) \
             ON CONFLICT(fingerprint) DO UPDATE SET \
             issue_url = EXCLUDED.issue_url, \
             severity = EXCLUDED.severity, \
             confidence = EXCLUDED.confidence, \
             status = 'recurring', \
             field_path = EXCLUDED.field_path, \
             source_type = EXCLUDED.source_type, \
             redacted_secret = EXCLUDED.redacted_secret, \
             snippet = EXCLUDED.snippet, \
             locations_json = EXCLUDED.locations_json, \
             references_json = EXCLUDED.references_json, \
             username = EXCLUDED.username, \
             last_seen = EXCLUDED.last_seen, \
             closed_at = NULL, \
             times_seen = findings.times_seen + 1, \
             scan_id_last = EXCLUDED.scan_id_last"
        );
        for e in &exps {
            sqlx::query(&upsert_sql)
                .bind(&e.fp)
                .bind(&e.secret_hash)
                .bind(&e.rule_id)
                .bind(&e.issue_key)
                .bind(&e.issue_url)
                .bind(e.severity)
                .bind(e.confidence)
                .bind("new")
                .bind(&e.field_path)
                .bind(e.source_type)
                .bind(&e.redacted_secret)
                .bind(&e.snippet)
                .bind(&e.locations_json)
                .bind(&e.references_json)
                .bind(&e.username)
                .bind(&now)
                .bind(&now)
                .bind(None::<&str>)
                .bind(1i64)
                .bind(scan_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| ScannerError::Store(format!("upsert finding: {e}")))?;
        }

        // --- Live-validation join (read-only) ---
        let hashes: Vec<&str> = current.iter().map(|f| f.secret_hash.as_str()).collect();
        let mut live_map: HashMap<String, ExternalValidation> = HashMap::new();
        if !hashes.is_empty() {
            let placeholders = (1..=hashes.len())
                .map(|i| self.ph(i))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT secret_hash, CAST(valid AS INTEGER) AS valid, checked_at, source \
                 FROM live_validations WHERE secret_hash IN ({placeholders})"
            );
            let mut q = sqlx::query(&sql);
            for h in &hashes {
                q = q.bind(*h);
            }
            let rows = q
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| ScannerError::Store(format!("read live_validations: {e}")))?;
            for row in &rows {
                let hash = get_str(row, "secret_hash")?;
                let valid: i64 = row
                    .try_get::<i64, _>("valid")
                    .map_err(|e| ScannerError::Store(format!("read valid: {e}")))?;
                let valid = valid != 0;
                let checked_at = get_str(row, "checked_at")?;
                let source = get_str(row, "source")?;
                live_map.insert(
                    hash,
                    ExternalValidation {
                        valid,
                        source,
                        checked_at,
                    },
                );
            }
        }

        tx.commit()
            .await
            .map_err(|e| ScannerError::Store(format!("commit: {e}")))?;

        // --- Build enriched findings for reports ---
        let mut result: Vec<Finding> = Vec::new();
        for f in current {
            let mut nf = f.clone();
            let mut first_seen_min: Option<String> = None;
            let mut times_sum: u32 = 0;
            for loc in &f.locations {
                let fp = fingerprint(&f.secret_hash, &f.rule_id, &loc.issue_key);
                let first_seen = match stored_by_fp.get(&fp) {
                    Some(s) => {
                        times_sum += (s.times_seen + 1) as u32;
                        s.first_seen.clone()
                    }
                    None => {
                        times_sum += 1;
                        now.clone()
                    }
                };
                match &first_seen_min {
                    None => first_seen_min = Some(first_seen),
                    Some(cur) if first_seen.as_str() < cur.as_str() => {
                        first_seen_min = Some(first_seen);
                    }
                    _ => {}
                }
            }
            let first_seen = first_seen_min.unwrap_or_else(|| now.clone());
            nf.status = if first_seen.as_str() < scan_started_at {
                FindingStatus::Recurring
            } else {
                FindingStatus::New
            };
            nf.first_seen = Some(first_seen);
            nf.times_seen = Some(times_sum);
            if let Some(ev) = live_map.get(&f.secret_hash) {
                let ev = ev.clone();
                if ev.valid {
                    nf.severity = Severity::Critical;
                    nf.confidence = Confidence::High;
                }
                nf.external_validation = Some(ev);
            }
            result.push(nf);
        }

        // --- Report newly-closed findings (in scanned issues, now absent) ---
        for s in stored_by_fp.values() {
            if scanned_issue_keys.contains(&s.issue_key)
                && !current_fps.contains(s.fp.as_str())
                && s.status != "closed"
            {
                let locations: Vec<Location> =
                    serde_json::from_str(&s.locations_json).unwrap_or_default();
                let references: Vec<String> =
                    serde_json::from_str(&s.references_json).unwrap_or_default();
                result.push(Finding {
                    finding_id: uuid::Uuid::new_v4().to_string(),
                    issue_key: s.issue_key.clone(),
                    issue_url: s.issue_url.clone(),
                    field_path: s.field_path.clone(),
                    rule_id: s.rule_id.clone(),
                    severity: str_to_severity(&s.severity),
                    confidence: str_to_confidence(&s.confidence),
                    redacted_secret: s.redacted_secret.clone(),
                    secret_hash: s.secret_hash.clone(),
                    snippet: s.snippet.clone(),
                    detected_at: s.last_seen.clone(),
                    scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                    locations,
                    source_type: str_to_source_type(&s.source_type),
                    status: FindingStatus::Closed,
                    username: s.username.clone(),
                    references,
                    first_seen: Some(s.first_seen.clone()),
                    times_seen: Some(s.times_seen as u32),
                    external_validation: live_map.get(&s.secret_hash).cloned(),
                });
            }
        }

        Ok(result)
    }

    /// Record a finished scan into the `scans` audit table.
    pub async fn record_scan(&self, scan: &ScanRun) -> Result<(), ScannerError> {
        let values = (1..=8).map(|i| self.ph(i)).collect::<Vec<_>>().join(",");
        let sql = format!(
            "INSERT INTO scans \
             (scan_id, started_at, finished_at, status, jira_url, jql, \
              issues_scanned, findings_total) \
             VALUES ({values}) \
             ON CONFLICT(scan_id) DO UPDATE SET \
             started_at = EXCLUDED.started_at, \
             finished_at = EXCLUDED.finished_at, \
             status = EXCLUDED.status, \
             issues_scanned = EXCLUDED.issues_scanned, \
             findings_total = EXCLUDED.findings_total"
        );
        sqlx::query(&sql)
            .bind(&scan.scan_id)
            .bind(&scan.started_at)
            .bind(&scan.finished_at)
            .bind(scan_status_to_str(scan.status))
            .bind(&scan.jira_url)
            .bind(&scan.jql)
            .bind(scan.issues_scanned as i64)
            .bind(scan.findings_total as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| ScannerError::Store(format!("record_scan: {e}")))?;
        Ok(())
    }
}

/// Read a NOT-NULL text column.
fn get_str(row: &AnyRow, name: &str) -> Result<String, ScannerError> {
    row.try_get::<String, _>(name)
        .map_err(|e| ScannerError::Store(format!("read col {name}: {e}")))
}

/// Parse a stored row. Nullable columns use `Option<String>`; NOT NULL use `String`.
fn parse_stored(row: &AnyRow) -> Result<StoredRow, ScannerError> {
    Ok(StoredRow {
        fp: get_str(row, "fingerprint")?,
        secret_hash: get_str(row, "secret_hash")?,
        rule_id: get_str(row, "rule_id")?,
        issue_key: get_str(row, "issue_key")?,
        issue_url: get_str(row, "issue_url")?,
        severity: get_str(row, "severity")?,
        confidence: get_str(row, "confidence")?,
        status: get_str(row, "status")?,
        field_path: get_str(row, "field_path")?,
        source_type: get_str(row, "source_type")?,
        redacted_secret: get_str(row, "redacted_secret")?,
        snippet: get_str(row, "snippet")?,
        locations_json: get_str(row, "locations_json")?,
        references_json: get_str(row, "references_json")?,
        username: row
            .try_get::<Option<String>, _>("username")
            .map_err(|e| ScannerError::Store(format!("read username: {e}")))?,
        first_seen: get_str(row, "first_seen")?,
        last_seen: get_str(row, "last_seen")?,
        times_seen: row
            .try_get::<i64, _>("times_seen")
            .map_err(|e| ScannerError::Store(format!("read times_seen: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Location, Severity, SourceType};
    use crate::hash::secret_hash;

    async fn fresh_store() -> FindingsStore {
        let store = FindingsStore::open("sqlite::memory:").await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    #[tokio::test]
    async fn open_creates_missing_parent_dir() {
        let base =
            std::env::temp_dir().join(format!("jiraleaks-store-cantopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let db = base.join("nested/deep/findings.db");
        let url = format!("sqlite://{}?mode=rwc", db.display());
        // Parent directories do not exist yet; this previously failed with
        // SQLITE_CANTOPEN (code 14).
        let store = FindingsStore::open(&url).await.expect("open creates parent dir");
        store.migrate().await.expect("migrate succeeds");
        assert!(db.is_file(), "database file should be created");
        let _ = std::fs::remove_dir_all(&base);
    }

    fn make_finding(value: &str, rule_id: &str, issue_key: &str) -> Finding {
        Finding {
            finding_id: uuid::Uuid::new_v4().to_string(),
            issue_key: issue_key.into(),
            issue_url: format!("https://jira/browse/{issue_key}"),
            field_path: "fields.description".into(),
            rule_id: rule_id.into(),
            severity: Severity::High,
            confidence: Confidence::High,
            redacted_secret: crate::redact::redact(value),
            secret_hash: secret_hash(value),
            snippet: format!("[REDACTED:{rule_id}]"),
            detected_at: "2026-08-07T00:00:00Z".into(),
            scanner_version: "0.1.0".into(),
            locations: vec![Location {
                issue_key: issue_key.into(),
                field_path: "fields.description".into(),
                source_type: SourceType::Description,
            }],
            source_type: SourceType::Description,
            status: FindingStatus::New,
            username: None,
            references: Vec::new(),
            first_seen: None,
            times_seen: None,
            external_validation: None,
        }
    }

    fn keys(ks: &[&str]) -> HashSet<String> {
        ks.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn migrate_creates_tables() {
        let store = fresh_store().await;
        // Count tables; tables exist after migrate.
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let nv: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM live_validations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(nv, 0);
    }

    #[tokio::test]
    async fn reconcile_new() {
        let store = fresh_store().await;
        let finding = make_finding("ghp_new_secret_1", "github_token", "SEC-1");
        let scanned = keys(&["SEC-1"]);
        let out = store
            .reconcile(&[finding], &scanned, "scan-1", "2026-08-07T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, FindingStatus::New);
        assert!(out[0].first_seen.is_some());
        assert_eq!(out[0].times_seen, Some(1));

        // Row stored with status 'new'.
        let status: String =
            sqlx::query_scalar("SELECT status FROM findings WHERE issue_key = 'SEC-1'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(status, "new");
    }

    #[tokio::test]
    async fn reconcile_recurring() {
        let store = fresh_store().await;
        let finding = make_finding("ghp_rec_secret_2", "github_token", "SEC-1");
        let scanned = keys(&["SEC-1"]);
        // First run → new.
        let out1 = store
            .reconcile(std::slice::from_ref(&finding), &scanned, "scan-1", "2026-08-07T00:00:00Z")
            .await
            .unwrap();
        // Second run (later started_at) → recurring, times_seen=2.
        let out = store
            .reconcile(&[finding], &scanned, "scan-2", "2026-08-08T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, FindingStatus::Recurring);
        assert_eq!(out[0].times_seen, Some(2));
        // first_seen preserved from the first run.
        assert_eq!(out1[0].first_seen, out[0].first_seen);

        let (status, times): (String, i64) =
            sqlx::query_as("SELECT status, times_seen FROM findings WHERE issue_key = 'SEC-1'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(status, "recurring");
        assert_eq!(times, 2);
    }

    #[tokio::test]
    async fn reconcile_closed() {
        let store = fresh_store().await;
        // Seed: secret present in SEC-1.
        let finding = make_finding("ghp_close_3", "github_token", "SEC-1");
        let scanned = keys(&["SEC-1"]);
        store
            .reconcile(&[finding], &scanned, "scan-1", "2026-08-07T00:00:00Z")
            .await
            .unwrap();
        // Second run: secret gone from SEC-1 (current empty), but SEC-1 was rescanned.
        let out = store
            .reconcile(&[], &scanned, "scan-2", "2026-08-08T00:00:00Z")
            .await
            .unwrap();
        // One closed finding reported.
        let closed = out
            .iter()
            .find(|f| f.status == FindingStatus::Closed)
            .expect("a closed finding");
        assert_eq!(closed.issue_key, "SEC-1");
        assert!(closed.first_seen.is_some());
        assert_eq!(closed.times_seen, Some(1));

        let status: String =
            sqlx::query_scalar("SELECT status FROM findings WHERE issue_key = 'SEC-1'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(status, "closed");
    }

    #[tokio::test]
    async fn reconcile_not_scanned_untouched() {
        let store = fresh_store().await;
        // Seed SEC-9.
        let finding9 = make_finding("ghp_keep_9", "github_token", "SEC-9");
        store
            .reconcile(
                &[finding9],
                &keys(&["SEC-9"]),
                "scan-1",
                "2026-08-07T00:00:00Z",
            )
            .await
            .unwrap();

        // New run scans only SEC-1 (different JQL); SEC-9 not rescanned.
        let out = store
            .reconcile(&[], &keys(&["SEC-1"]), "scan-2", "2026-08-08T00:00:00Z")
            .await
            .unwrap();
        // SEC-9 not reported (not in current, not in scanned set).
        assert!(out.is_empty());

        // SEC-9 row untouched (still 'new', not closed).
        let status: String =
            sqlx::query_scalar("SELECT status FROM findings WHERE issue_key = 'SEC-9'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(status, "new");
    }

    #[tokio::test]
    async fn reconcile_live_validation_join() {
        let store = fresh_store().await;
        let finding = make_finding("ghp_live_valid", "github_token", "SEC-1");
        let hash = finding.secret_hash.clone();
        // External system marks the token valid.
        let p1 = "?".to_string();
        let sql = format!(
            "INSERT INTO live_validations (secret_hash, valid, checked_at, source, details) \
             VALUES ({p1}, {p1}, {p1}, {p1}, {p1})"
        );
        sqlx::query(&sql)
            .bind(&hash)
            .bind(true)
            .bind("2026-08-07T00:00:00Z")
            .bind("ext-sys")
            .bind(None::<&str>)
            .execute(&store.pool)
            .await
            .unwrap();

        let out = store
            .reconcile(&[finding], &keys(&["SEC-1"]), "scan-1", "2026-08-07T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
        assert_eq!(out[0].confidence, Confidence::High);
        let ev = out[0].external_validation.as_ref().expect("external validation");
        assert!(ev.valid);
        assert_eq!(ev.source, "ext-sys");

        // DB severity stays the detected value (not overridden).
        let sev: String =
            sqlx::query_scalar("SELECT severity FROM findings WHERE issue_key = 'SEC-1'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(sev, "high");
    }

    #[tokio::test]
    async fn reconcile_live_validation_invalid_keeps_severity() {
        let store = fresh_store().await;
        let finding = make_finding("ghp_live_invalid", "github_token", "SEC-1");
        let hash = finding.secret_hash.clone();
        let p1 = "?".to_string();
        let sql = format!(
            "INSERT INTO live_validations (secret_hash, valid, checked_at, source, details) \
             VALUES ({p1}, {p1}, {p1}, {p1}, {p1})"
        );
        sqlx::query(&sql)
            .bind(&hash)
            .bind(false)
            .bind("2026-08-07T00:00:00Z")
            .bind("ext-sys")
            .bind(None::<&str>)
            .execute(&store.pool)
            .await
            .unwrap();

        let out = store
            .reconcile(&[finding], &keys(&["SEC-1"]), "scan-1", "2026-08-07T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].external_validation.is_some());
        assert!(!out[0].external_validation.as_ref().unwrap().valid);
    }

    #[tokio::test]
    async fn record_scan_writes_audit() {
        let store = fresh_store().await;
        let scan = ScanRun {
            scan_id: "scan-audit".into(),
            status: ScanStatus::Success,
            started_at: "2026-08-07T00:00:00Z".into(),
            finished_at: "2026-08-07T00:01:00Z".into(),
            jira_url: "https://jira".into(),
            jql: "project = TEST".into(),
            issues_scanned: 5,
            issues_total: 5,
            findings_total: 2,
            findings_critical: 1,
            findings_high: 1,
            findings_medium: 0,
            findings_low: 0,
            findings_info: 0,
            errors_total: 0,
            comments_scanned: 0,
            attachments_scanned: 0,
            scanner_version: "0.1.0".into(),
            duration_secs: 60.0,
        };
        store.record_scan(&scan).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
