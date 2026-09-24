//! Cross-cutting tests for finding identity.
//!
//! Three identities used to coexist without a shared definition: the
//! deduplicator's `"{secret_hash}:{rule_id}"` map key, the store's
//! `fp:`-prefixed primary key over `(secret_hash, rule_id, issue_key)`, and a
//! freshly minted UUID `finding_id` that DefectDojo used as its stable handle.
//! They are now named types — [`MergeKey`], [`FindingKey`] and
//! [`Finding::key`] — and this file pins their contract from the outside:
//! which one survives a re-scan, which one collapses several issues into one
//! finding, and which one DefectDojo may rely on.
//!
//! The golden constants below were captured from the pre-refactor code and
//! cross-checked with an independent SHA-256 implementation; they are the
//! values already stored in existing databases, so they must never change.

use std::collections::HashSet;

use jiraleaks::dedup::Deduplicator;
use jiraleaks::finding::{
    Confidence, Finding, FindingKey, FindingStatus, Location, MergeKey, ScanRun, ScanStatus,
    Severity, SourceType,
};
use jiraleaks::hash::secret_hash;
use jiraleaks::report::{defectdojo, ReportInput};
use jiraleaks::store::FindingsStore;

/// The DefectDojo writer reads only its findings; the scan metadata is there because
/// every report writer shares one signature.
fn scan_run() -> ScanRun {
    ScanRun {
        scan_id: "scan-1".into(),
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
        scanner_version: "0.1.0".into(),
        duration_secs: 0.0,
    }
}

fn write_defectdojo(
    path: &std::path::Path,
    findings: &[Finding],
) -> Result<(), jiraleaks::error::ScannerError> {
    let run = scan_run();
    defectdojo::write(
        path,
        &ReportInput {
            scan_run: &run,
            findings,
        },
    )
}

/// Secret value whose whole identity chain is pinned below.
const GOLDEN_SECRET: &str = "ghp_golden_secret";
const GOLDEN_SECRET_HASH: &str =
    "sha256:648d7b9b7547f6aab35c9f9f16712e4c11a0dc0bdec6848e95fad4f062505b19";
const GOLDEN_FINGERPRINT: &str =
    "fp:c2417f473b660bfe3cdbff88e4131773893acb00086712a0e7842638d71eae81";

fn finding(secret: &str, rule_id: &str, issue_key: &str) -> Finding {
    Finding {
        // A fresh UUID every scan, exactly like the pipeline: any identity that
        // depends on this value is broken by design.
        finding_id: uuid::Uuid::new_v4().to_string(),
        issue_key: issue_key.into(),
        issue_url: format!("https://jira.example.com/browse/{issue_key}"),
        field_path: "fields.description".into(),
        rule_id: rule_id.into(),
        severity: Severity::High,
        confidence: Confidence::High,
        redacted_secret: "[REDACTED]".into(),
        secret_hash: secret_hash(secret),
        snippet: "[REDACTED]".into(),
        detected_at: "2026-01-01T00:00:00Z".into(),
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

fn scanned(issues: &[&str]) -> HashSet<String> {
    issues.iter().map(|s| s.to_string()).collect()
}

/// Scan window relative to the wall clock: `first_seen` is stamped from the
/// real clock during reconcile, so a hardcoded date would silently flip
/// `Recurring` back to `New` (see `store::tests`).
fn scan_start_in(secs: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::seconds(secs))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

async fn fresh_store() -> FindingsStore {
    let store = FindingsStore::open("sqlite::memory:").await.unwrap();
    store.migrate().await.unwrap();
    store
}

#[test]
fn secret_hash_and_fingerprint_chain_matches_golden_values() {
    assert_eq!(secret_hash(GOLDEN_SECRET), GOLDEN_SECRET_HASH);
    let key = FindingKey::new(GOLDEN_SECRET_HASH, "github_token", "SEC-1");
    assert_eq!(key.fingerprint(), GOLDEN_FINGERPRINT);
    // Same inputs → same fingerprint, whatever the finding_id.
    let a = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    let b = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    assert_ne!(a.finding_id, b.finding_id);
    assert_eq!(a.key().fingerprint(), GOLDEN_FINGERPRINT);
    assert_eq!(b.key().fingerprint(), GOLDEN_FINGERPRINT);
}

#[test]
fn fingerprint_is_per_issue_while_the_merge_key_is_not() {
    let first = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    let second = finding(GOLDEN_SECRET, "github_token", "SEC-2");

    // Cross-issue merge identity: identical, so dedup collapses the two hits...
    assert_eq!(first.merge_key(), second.merge_key());
    assert_eq!(
        first.merge_key().to_string(),
        format!("{GOLDEN_SECRET_HASH}:github_token")
    );
    assert_eq!(
        first.merge_key(),
        MergeKey {
            secret_hash: GOLDEN_SECRET_HASH.into(),
            rule_id: "github_token".into(),
        }
    );

    // ...while the persisted identity stays per location.
    assert_ne!(first.key().fingerprint(), second.key().fingerprint());
}

#[test]
fn location_keys_cover_every_location_and_fall_back_to_the_finding_issue() {
    let single = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    assert_eq!(single.location_keys(), vec![single.key()]);

    let mut multi = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    multi.locations = vec![
        Location {
            issue_key: "SEC-1".into(),
            field_path: "fields.description".into(),
            source_type: SourceType::Description,
        },
        Location {
            issue_key: "SEC-7".into(),
            field_path: "comment[4].body".into(),
            source_type: SourceType::Comment,
        },
    ];
    let keys = multi.location_keys();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].issue_key, "SEC-1");
    assert_eq!(keys[1].issue_key, "SEC-7");
    assert_ne!(keys[0].fingerprint(), keys[1].fingerprint());

    // No explicit locations: the finding's own issue is the one location it is
    // persisted under.
    let mut bare = finding(GOLDEN_SECRET, "github_token", "SEC-9");
    bare.locations.clear();
    let keys = bare.location_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].issue_key, "SEC-9");
    assert_eq!(keys[0].fingerprint(), bare.key().fingerprint());
}

#[tokio::test]
async fn store_identity_is_the_fingerprint_not_the_random_finding_id() {
    let store = fresh_store().await;

    let first_scan = finding("ghp_store_identity", "github_token", "SEC-5");
    let out1 = store
        .reconcile(
            std::slice::from_ref(&first_scan),
            &scanned(&["SEC-5"]),
            "scan-1",
            &scan_start_in(-86_400),
        )
        .await
        .unwrap();
    assert_eq!(out1.len(), 1);
    assert_eq!(out1[0].times_seen, Some(1));
    assert_eq!(out1[0].status, FindingStatus::New);
    let first_seen = out1[0].first_seen.clone();

    // Next scan mints a new finding_id for the very same secret and location.
    let second_scan = finding("ghp_store_identity", "github_token", "SEC-5");
    assert_ne!(first_scan.finding_id, second_scan.finding_id);
    let out2 = store
        .reconcile(
            &[second_scan],
            &scanned(&["SEC-5"]),
            "scan-2",
            &scan_start_in(60),
        )
        .await
        .unwrap();
    assert_eq!(out2.len(), 1);
    assert_eq!(out2[0].status, FindingStatus::Recurring);
    assert_eq!(out2[0].times_seen, Some(2));
    assert_eq!(out2[0].first_seen, first_seen);
}

#[tokio::test]
async fn dedup_merges_across_issues_but_the_store_closes_per_issue() {
    let store = fresh_store().await;

    // Scan 1: the same secret leaks into two issues. Dedup reports ONE finding
    // with two locations (spec §10.12.3).
    let mut dedup = Deduplicator::new();
    dedup.insert(finding(GOLDEN_SECRET, "github_token", "SEC-1"));
    dedup.insert(finding(GOLDEN_SECRET, "github_token", "SEC-2"));
    let merged = dedup.into_findings();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].location_keys().len(), 2);

    let first = store
        .reconcile(
            &merged,
            &scanned(&["SEC-1", "SEC-2"]),
            "scan-1",
            &scan_start_in(-86_400),
        )
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].status, FindingStatus::New);
    assert_eq!(first[0].times_seen, Some(2));

    // Scan 2: the secret is gone from SEC-2 but still present in SEC-1.
    let remaining = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    let second = store
        .reconcile(
            &[remaining],
            &scanned(&["SEC-1", "SEC-2"]),
            "scan-2",
            &scan_start_in(60),
        )
        .await
        .unwrap();

    let recurring: Vec<&Finding> = second
        .iter()
        .filter(|f| f.status == FindingStatus::Recurring)
        .collect();
    let closed: Vec<&Finding> = second
        .iter()
        .filter(|f| f.status == FindingStatus::Closed)
        .collect();
    // Per-issue persistence: SEC-1 recurs, SEC-2 alone is closed. Keying
    // persistence on the issue-independent merge key would have closed both.
    assert_eq!(recurring.len(), 1);
    assert_eq!(recurring[0].issue_key, "SEC-1");
    assert_eq!(recurring[0].times_seen, Some(2));
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].issue_key, "SEC-2");
}

#[test]
fn defectdojo_id_survives_rescans_and_separates_locations() {
    let dir = std::env::temp_dir().join(format!("jiraleaks-identity-dd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let read_id = |path: &std::path::Path| -> String {
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        doc["findings"][0]["unique_id_from_tool"]
            .as_str()
            .expect("unique_id_from_tool")
            .to_string()
    };

    // Two scans of the same state, two different UUIDs: one DefectDojo record.
    let scan1 = dir.join("scan1.json");
    let scan2 = dir.join("scan2.json");
    let report = finding(GOLDEN_SECRET, "github_token", "SEC-1");
    let expected = format!("{GOLDEN_FINGERPRINT}#0");
    write_defectdojo(&scan1, std::slice::from_ref(&report)).unwrap();
    write_defectdojo(&scan2, &[finding(GOLDEN_SECRET, "github_token", "SEC-1")]).unwrap();
    assert_eq!(read_id(&scan1), expected);
    assert_eq!(read_id(&scan2), expected);

    // A different location is a different record.
    let elsewhere = dir.join("scan3.json");
    write_defectdojo(
        &elsewhere,
        &[finding(GOLDEN_SECRET, "github_token", "SEC-3")],
    )
    .unwrap();
    assert_ne!(read_id(&elsewhere), expected);

    let _ = std::fs::remove_dir_all(&dir);
}
