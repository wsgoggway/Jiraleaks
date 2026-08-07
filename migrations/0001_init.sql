-- Portable DDL: works on both SQLite and PostgreSQL.
CREATE TABLE IF NOT EXISTS findings (
    fingerprint  TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    issue_key    TEXT NOT NULL,
    issue_url    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    confidence   TEXT NOT NULL,
    status       TEXT NOT NULL,
    field_path   TEXT NOT NULL,
    source_type  TEXT NOT NULL,
    redacted_secret TEXT NOT NULL,
    snippet      TEXT NOT NULL,
    locations_json  TEXT NOT NULL,
    references_json TEXT NOT NULL,
    username     TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    closed_at    TEXT,
    times_seen   BIGINT NOT NULL DEFAULT 1,
    scan_id_last TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_issue  ON findings(issue_key);
CREATE INDEX IF NOT EXISTS idx_findings_hash   ON findings(secret_hash);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Written by an external validation system (by secret_hash).
CREATE TABLE IF NOT EXISTS live_validations (
    secret_hash TEXT PRIMARY KEY,
    valid       BOOLEAN NOT NULL,
    checked_at  TEXT NOT NULL,
    source      TEXT NOT NULL,
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_live_valid ON live_validations(valid);

-- Audit log of completed scans.
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    finished_at  TEXT NOT NULL,
    status       TEXT NOT NULL,
    jira_url     TEXT NOT NULL,
    jql          TEXT NOT NULL,
    issues_scanned BIGINT NOT NULL,
    findings_total BIGINT NOT NULL
);
