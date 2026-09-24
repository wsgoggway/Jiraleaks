use std::collections::HashSet;
use std::io::IsTerminal;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::allowlist::AllowlistFilter;
use crate::config::Config;
use crate::credpair::CredentialPairDetector;
use crate::dedup::Deduplicator;
use crate::error::ScannerError;
use crate::extract::TextExtractor;
use crate::fetcher::Fetcher;
use crate::finding::{
    self, Confidence, Finding, FindingStatus, Location, ScanRun, ScanStatus, Severity,
};
use crate::hash::secret_hash;
use crate::jira::client::JiraClient;
use crate::jira::models::Issue;
use crate::progress::ScanProgress;
use crate::redact;
use crate::report;
use crate::rules::RulesEngine;

/// Run the full scanning pipeline (spec §11.2).
pub async fn run(
    config: Config,
    client: JiraClient,
) -> Result<std::process::ExitCode, ScannerError> {
    let started_at = time::OffsetDateTime::now_utc();
    let scan_id = uuid::Uuid::new_v4().to_string();

    // Load rules
    let rules_engine = RulesEngine::new(config.rules.as_deref())?;

    // Load allowlist
    let allowlist = match &config.allowlist {
        Some(path) => AllowlistFilter::from_file(path)?,
        None => AllowlistFilter::empty(),
    };

    // Build pipeline components
    let client = Arc::new(client);
    let fetcher = Arc::new(Fetcher::new(client.clone(), config.clone()));
    let extractor = TextExtractor::new(config.max_text_size_kb);
    // Startup check: the credential-pair patterns are compiled once here rather
    // than silently skipped at detection time.
    let credpair_detector = CredentialPairDetector::new()?;
    let dedup = Deduplicator::new();

    let cancel = CancellationToken::new();

    // Spawn graceful shutdown handler
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received SIGINT, initiating graceful shutdown...");
        cancel_clone.cancel();
    });

    #[cfg(unix)]
    {
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
            sigterm.recv().await;
            info!("Received SIGTERM, initiating graceful shutdown...");
            cancel_clone.cancel();
        });
    }

    // Fetch issues (streaming) and process them concurrently as pages arrive
    let jql = config.jql().unwrap_or("");
    let bar = if std::io::stderr().is_terminal() {
        ProgressBar::new(0)
    } else {
        ProgressBar::hidden()
    };
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{wide_bar:.cyan/blue}] {pos}/{len} issues · {msg} · {elapsed_precise} · ETA {eta}",
        )
        .expect("valid indicatif template"),
    );
    let progress = Arc::new(ScanProgress::with_bar(bar));
    let (mut issue_rx, fetch_handle) = fetcher
        .fetch_issues_stream(jql, cancel.clone(), progress.clone())
        .await;

    // Periodic ticker keeps the bar's spinner/ETA fresh during quiet periods
    let progress_tick = tokio::spawn({
        let progress = progress.clone();
        let cancel = cancel.clone();
        async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            interval.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => progress.tick(),
                    _ = cancel.cancelled() => break,
                }
            }
        }
    });

    // Process issues concurrently, bounded by JoinSet backpressure
    let mut errors_total = 0u64;
    let mut dedup = dedup;
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut join_set: JoinSet<Result<Vec<Finding>, ScannerError>> = JoinSet::new();
    let mut scanned_issue_keys: HashSet<String> = HashSet::new();

    while let Some(issue) = issue_rx.recv().await {
        if cancel.is_cancelled() {
            info!("Scan cancelled, processing partial results");
            break;
        }
        // backpressure: keep at most concurrency*2 tasks in flight
        while join_set.len() >= config.concurrency * 2 {
            collect_one(
                &mut join_set,
                &mut all_findings,
                &mut errors_total,
                &progress,
            )
            .await;
        }
        scanned_issue_keys.insert(issue.key.clone());
        let client = client.clone();
        let extractor = extractor.clone();
        let rules_engine = rules_engine.clone();
        let allowlist = allowlist.clone();
        let config = config.clone();
        join_set.spawn(async move {
            process_issue(
                &client,
                &extractor,
                &rules_engine,
                &credpair_detector,
                &allowlist,
                &config,
                issue,
            )
            .await
        });
    }

    // Drain all remaining tasks
    while collect_one(
        &mut join_set,
        &mut all_findings,
        &mut errors_total,
        &progress,
    )
    .await
    {}

    progress_tick.abort();

    // Check the fetch task for errors (JoinError -> ScannerError, then inner)
    fetch_handle
        .await
        .map_err(|e| ScannerError::ScanCritical(format!("Fetch task join error: {e}")))??;
    progress.finish(); // finalize the bar ([done/total])

    // Dedup all findings
    for finding in all_findings {
        dedup.insert(finding);
    }
    let mut findings = dedup.into_findings();

    // Reconcile against the persistent findings store (status history +
    // live-validation) when a database URL is configured.
    let started_at_rfc3339 = started_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let store = if let Some(db_url) = config.db_url() {
        let store = crate::store::FindingsStore::open(&db_url).await?;
        store.migrate().await?;
        Some(store)
    } else {
        None
    };
    if let Some(ref store) = store {
        findings = store
            .reconcile(
                &findings,
                &scanned_issue_keys,
                &scan_id,
                &started_at_rfc3339,
            )
            .await?;
    }

    // Count findings by severity
    let mut findings_critical = 0u64;
    let mut findings_high = 0u64;
    let mut findings_medium = 0u64;
    let mut findings_low = 0u64;
    let mut findings_info = 0u64;

    for f in &findings {
        match f.severity {
            Severity::Critical => findings_critical += 1,
            Severity::High => findings_high += 1,
            Severity::Medium => findings_medium += 1,
            Severity::Low => findings_low += 1,
            Severity::Info => findings_info += 1,
        }
    }

    let finished_at = time::OffsetDateTime::now_utc();
    let duration = (finished_at - started_at).as_seconds_f64();

    let scan_status = if cancel.is_cancelled() || errors_total > 0 {
        ScanStatus::Partial
    } else {
        ScanStatus::Success
    };

    let scan_run = ScanRun {
        scan_id: scan_id.clone(),
        status: scan_status,
        started_at: started_at_rfc3339.clone(),
        finished_at: finished_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        jira_url: config.jira_url.clone(),
        jql: jql.to_string(),
        // `issues_done` counts finished attempts: an issue whose processing
        // failed is counted here too (and again in `errors_total`), so
        // `issues_scanned` is "issues attempted", not "issues scanned
        // successfully". See `progress.rs` for the counter semantics.
        issues_scanned: progress.issues_done.load(Ordering::Relaxed),
        issues_total: progress.issues_total.load(Ordering::Relaxed),
        findings_total: findings.len() as u64,
        findings_critical,
        findings_high,
        findings_medium,
        findings_low,
        findings_info,
        errors_total,
        comments_scanned: 0,
        attachments_scanned: 0,
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        duration_secs: duration,
    };

    // Write reports
    if !config.dry_run {
        report::write_reports(&config, &scan_run, &findings)?;
    }

    // Write metrics if configured
    if let Some(ref metrics_path) = config.metrics_path {
        crate::metrics::write_metrics(metrics_path, config.metrics_format, &scan_run)?;
    }

    // Send alerts if configured
    if let Some(ref alerts_path) = config.alerts {
        crate::alert::send_alerts(alerts_path, &scan_run, &findings)?;
    }

    // Write checkpoint on success
    if config.incremental && matches!(scan_run.status, ScanStatus::Success) {
        crate::checkpoint::write_checkpoint(&config, &scan_run)?;
    }

    info!(
        findings_total = scan_run.findings_total,
        issues_scanned = scan_run.issues_scanned,
        duration_secs = duration,
        status = ?scan_run.status,
        "Scan complete"
    );

    // Record the scan into the findings store audit table.
    if let Some(ref store) = store {
        store.record_scan(&scan_run).await?;
    }

    Ok(std::process::ExitCode::from(0))
}

/// Collect one finished task from the JoinSet. Returns true if a task was
/// collected, false if the set is empty.
async fn collect_one(
    join_set: &mut JoinSet<Result<Vec<Finding>, ScannerError>>,
    all_findings: &mut Vec<Finding>,
    errors_total: &mut u64,
    progress: &ScanProgress,
) -> bool {
    let Some(res) = join_set.join_next().await else {
        return false;
    };
    match res {
        Ok(Ok(fs)) => {
            let found = fs.len() as u64;
            all_findings.extend(fs);
            progress.finish_issue(found);
        }
        Ok(Err(e)) => {
            warn!(error = %e, "Issue processing error (non-critical)");
            *errors_total += 1;
            progress.finish_issue_error();
        }
        Err(e) => {
            warn!(error = %e, "Task join error");
            *errors_total += 1;
            progress.finish_issue_error();
        }
    }
    true
}

/// Process a single issue: extract text, scan with rules, detect credpairs,
/// apply allowlist, adjust confidence, and return findings.
async fn process_issue(
    client: &JiraClient,
    extractor: &TextExtractor,
    rules_engine: &RulesEngine,
    credpair_detector: &CredentialPairDetector,
    allowlist: &AllowlistFilter,
    config: &Config,
    issue: Issue,
) -> Result<Vec<Finding>, ScannerError> {
    let issue_key = issue.key.clone();
    let issue_url = format!("{}/browse/{issue_key}", config.jira_url);

    // Extract text segments
    let segments = extractor.extract(&issue_key, &issue.fields);

    // Fetch additional comments if needed (paginated)
    let mut extra_comments = Vec::new();
    if config.comments_mode != "none" {
        if let Some(comment_field) = issue.fields.get("comment") {
            let total = comment_field
                .get("total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let existing_count = comment_field
                .get("comments")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(0);
            if total > existing_count {
                match client
                    .get_comments_paginated(&issue_key, existing_count, 50)
                    .await
                {
                    Ok(mut page) => extra_comments.append(&mut page.comments),
                    Err(e) => {
                        warn!(issue = %issue_key, error = %e, "Failed to fetch extra comments");
                    }
                }
            }
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut issue_findings_count = 0usize;

    for segment in &segments {
        if issue_findings_count >= config.max_findings_per_issue {
            warn!(
                issue = %issue_key,
                limit = config.max_findings_per_issue,
                "Max findings per issue reached"
            );
            break;
        }

        // 1. Regex rule scanning
        let hits = rules_engine.scan(&segment.text, &segment.field_path);
        for hit in hits.iter() {
            if issue_findings_count >= config.max_findings_per_issue {
                break;
            }

            let secret_hash = secret_hash(&hit.matched_value);

            // Allowlist check
            if allowlist.is_allowed(
                &hit.matched_value,
                &hit.rule_id,
                &issue_key,
                &hit.field_path,
            ) {
                debug!(
                    rule_id = %hit.rule_id,
                    issue = %issue_key,
                    "Finding excluded by allowlist"
                );
                continue;
            }

            // Placeholder check
            let is_placeholder = crate::credpair::is_placeholder_static(&hit.matched_value);

            // Context keyword check: look for secret-related words around the match
            const CONTEXT_WORDS: &[&str] = &[
                "secret",
                "key",
                "token",
                "password",
                "passwd",
                "pwd",
                "credential",
                "api_key",
                "apikey",
                "access_key",
                "private_key",
            ];
            let win_start = segment
                .text
                .floor_char_boundary(hit.match_span.start.saturating_sub(50));
            let win_end = segment
                .text
                .ceil_char_boundary((hit.match_span.end + 50).min(segment.text.len()));
            let window = &segment.text[win_start..win_end].to_lowercase();
            let has_context = CONTEXT_WORDS.iter().any(|w| window.contains(w));

            // Confidence adjustment
            let confidence = finding::adjust_confidence(
                Confidence::parse(&hit.confidence),
                has_context,
                crate::entropy::shannon(&hit.matched_value) > 3.5,
                is_placeholder,
            );

            // Filter by min-confidence
            if confidence < Confidence::parse(&config.min_confidence) {
                continue;
            }

            // A snippet is a ±50 byte window, so it can carry the secrets of the
            // neighbouring findings of the same segment: the hit masks those too.
            let redacted = redact::redact(&hit.matched_value);
            let redacted_snippet = hit.redacted_snippet(&hits);

            findings.push(Finding {
                finding_id: uuid::Uuid::new_v4().to_string(),
                issue_key: issue_key.clone(),
                issue_url: issue_url.clone(),
                field_path: hit.field_path.clone(),
                rule_id: hit.rule_id.clone(),
                severity: Severity::parse(&hit.severity),
                confidence,
                redacted_secret: redacted,
                secret_hash,
                snippet: redacted_snippet,
                detected_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                locations: vec![Location {
                    issue_key: issue_key.clone(),
                    field_path: hit.field_path.clone(),
                    source_type: segment.source_type.into(),
                }],
                source_type: segment.source_type.into(),
                status: FindingStatus::New,
                username: None,
                references: hit.references.clone(),
                first_seen: None,
                times_seen: None,
                external_validation: None,
            });

            issue_findings_count += 1;
        }

        // 2. Credential pair detection
        let cred_hits = credpair_detector.detect(&segment.text, &segment.field_path);
        for ch in cred_hits {
            if issue_findings_count >= config.max_findings_per_issue {
                break;
            }

            let confidence = Confidence::parse("high");
            if confidence < Confidence::parse(&config.min_confidence) {
                continue;
            }

            findings.push(Finding {
                finding_id: uuid::Uuid::new_v4().to_string(),
                issue_key: issue_key.clone(),
                issue_url: issue_url.clone(),
                field_path: ch.field_path.clone(),
                rule_id: "credential_pair".to_string(),
                severity: Severity::High,
                confidence,
                redacted_secret: ch.redacted_password.clone(),
                secret_hash: ch.password_hash.clone(),
                snippet: format!(
                    "username={} password=[REDACTED:credential_pair]",
                    ch.username
                ),
                detected_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                locations: vec![Location {
                    issue_key: issue_key.clone(),
                    field_path: ch.field_path.clone(),
                    source_type: segment.source_type.into(),
                }],
                source_type: segment.source_type.into(),
                status: FindingStatus::New,
                username: Some(ch.username.clone()),
                references: Vec::new(),
                first_seen: None,
                times_seen: None,
                external_validation: None,
            });

            issue_findings_count += 1;
        }
    }

    debug!(issue = %issue_key, findings = findings.len(), "Issue processed");

    Ok(findings)
}

/// Legacy shim — use [`Severity::parse`] or `Severity::from_str` from
/// [`crate::finding`] instead.
///
/// Kept only while the call sites outside this module migrate; it delegates
/// verbatim, so behaviour is identical. No `#[deprecated]` attribute on purpose:
/// emitting a warning from another team's code during a parallel migration is
/// noise, not a signal.
pub fn parse_severity(s: &str) -> Severity {
    Severity::parse(s)
}

/// Legacy shim — use [`Confidence::parse`] or `Confidence::from_str` from
/// [`crate::finding`] instead.
///
/// Same delegation and same deliberate absence of `#[deprecated]` as
/// [`parse_severity`].
pub fn parse_confidence(s: &str) -> Confidence {
    Confidence::parse(s)
}
