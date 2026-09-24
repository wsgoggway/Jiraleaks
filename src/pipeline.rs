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
use crate::attachments::{self, AttachmentPolicy};
use crate::candidate::{Candidate, Judge, Verdict};
use crate::config::Config;
use crate::credpair::CredentialPairDetector;
use crate::dedup::Deduplicator;
use crate::error::ScannerError;
use crate::extract::{SourceType, TextExtractor, TextSegment};
use crate::fetcher::{FetchOptions, Fetcher};
use crate::finding::{Confidence, Finding, FindingStatus, Location, ScanRun, ScanStatus, Severity};
use crate::hash::secret_hash;
use crate::jira::client::JiraClient;
use crate::jira::models::Issue;
use crate::progress::ScanProgress;
use crate::redact;
use crate::report;
use crate::rules::RulesEngine;

/// What one issue contributed to the scan.
///
/// The counters travel with the findings instead of being pushed into
/// [`ScanProgress`] from inside the task, so they are recorded at exactly the
/// point the issue's findings are (see [`collect_one`]): an issue either
/// contributes everything it found or is counted as failed, never half of each.
struct IssueOutcome {
    findings: Vec<Finding>,
    /// Comment bodies scanned for this issue — see
    /// [`ScanProgress::comments_scanned`] for what the number counts.
    comments_scanned: u64,
    attachments_scanned: u64,
}

/// Run the full scanning pipeline (spec §11.2).
pub async fn run(
    config: Config,
    client: JiraClient,
) -> Result<std::process::ExitCode, ScannerError> {
    let started_at = time::OffsetDateTime::now_utc();
    let scan_id = uuid::Uuid::new_v4().to_string();

    // Shared, not cloned per issue: every spawned task needs to read the
    // configuration, and a deep `Config` clone per issue was pure allocation.
    let config = Arc::new(config);

    // Load rules
    let rules_engine = RulesEngine::new(config.rules.as_deref())?;

    // Load allowlist
    let allowlist = match &config.allowlist {
        Some(path) => AllowlistFilter::from_file(path)?,
        None => AllowlistFilter::empty(),
    };

    // Build pipeline components
    let client = Arc::new(client);
    // The fetcher gets the four values it reads, not a whole configuration.
    let fetcher = Arc::new(Fetcher::new(
        client.clone(),
        FetchOptions::from_config(&config),
    ));
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

    // Fetch issues (streaming) and process them concurrently as pages arrive.
    //
    // `--incremental` narrows the query to the issues that changed since the
    // previous *successful* scan. The decision — and every reason it may decline
    // to narrow, from a missing checkpoint to a different JQL — lives in
    // `checkpoint::plan_incremental_scan`, which logs the window it chose.
    let configured_jql = config.jql().unwrap_or("");
    let incremental_plan = crate::checkpoint::plan_incremental_scan(&config, configured_jql);
    let jql = incremental_plan
        .as_ref()
        .map(|plan| plan.jql.as_str())
        .unwrap_or(configured_jql);
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
    let mut join_set: JoinSet<Result<IssueOutcome, ScannerError>> = JoinSet::new();
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
        let config = Arc::clone(&config);
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
    //
    // A store that cannot be opened, migrated or reconciled is *remembered*, not
    // propagated here, and the run continues on the findings it already has. The
    // store is a side channel — it enriches each finding with its history
    // (`status`, `times_seen`, `first_seen`, live validation) and keeps the audit
    // row of the run — while the findings themselves are collected without it. So
    // a failure here costs the enrichment, and losing the enrichment of a scan
    // that already found secrets is strictly better than losing the whole report:
    // the reports, metrics, alerts and checkpoint are written regardless, and the
    // remembered error is returned at the very end, so the exit code still says
    // "store" (5) and the failure is never swallowed.
    //
    // The findings that reach the emission below therefore carry `status: New`
    // and no history when the store was unavailable — an understatement of what
    // the database knows, never a false claim: a finding is reported, and whether
    // it is new is what the missing database cannot answer.
    let started_at_rfc3339 = started_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let mut store_error: Option<ScannerError> = None;
    let store = match open_store(&config).await {
        Ok(store) => store,
        Err(e) => {
            warn!(
                error = %e,
                "Findings store unavailable: continuing without status history and live validation"
            );
            store_error = Some(e);
            None
        }
    };
    if let Some(ref store) = store {
        match store
            .reconcile(
                &findings,
                &scanned_issue_keys,
                &scan_id,
                &started_at_rfc3339,
            )
            .await
        {
            Ok(reconciled) => findings = reconciled,
            Err(e) => {
                warn!(
                    error = %e,
                    "Findings store reconcile failed: reporting the findings without their history"
                );
                store_error = Some(e);
            }
        }
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
        // The query that actually ran, narrowed when `--incremental` applied it:
        // the report has to describe the scan that produced the findings, and the
        // baseline for the *next* run is stored separately (`checkpoint` keeps
        // the configured query, not this one).
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
        // Counted while the issues were processed: comment bodies scanned and
        // attachments whose text was fetched. See `progress.rs` for exactly
        // what each one counts.
        comments_scanned: progress.comments_scanned.load(Ordering::Relaxed),
        attachments_scanned: progress.attachments_scanned.load(Ordering::Relaxed),
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

    // Advance the incremental baseline. Only a fully successful scan may do so:
    // the gate (and the reason it declines) lives in `checkpoint`.
    crate::checkpoint::maybe_write_checkpoint(&config, &scan_run)?;

    info!(
        findings_total = scan_run.findings_total,
        issues_scanned = scan_run.issues_scanned,
        duration_secs = duration,
        status = ?scan_run.status,
        "Scan complete"
    );

    // Record the scan into the findings store audit table. The reports are on
    // disk by now, so a failure here is remembered like the ones above instead of
    // taking the run down mid-way.
    if let Some(ref store) = store {
        if let Err(e) = store.record_scan(&scan_run).await {
            warn!(error = %e, "Failed to record the scan in the findings store");
            if store_error.is_none() {
                store_error = Some(e);
            }
        }
    }

    // Everything the scan produced has been written. Only now does a store
    // failure become the exit code (5): the operator still sees that the database
    // was unavailable, and the reports of the run are not the price of it.
    if let Some(e) = store_error {
        return Err(e);
    }

    Ok(std::process::ExitCode::from(0))
}

/// Open and migrate the findings store, if one is configured.
///
/// `Ok(None)` means "the store is disabled" (no `--db-url` and no state
/// directory) and is not a failure; any `Err` is a store that was asked for and
/// could not be prepared. The caller decides what a failure costs — see the
/// comment at the call site: the pipeline keeps going without the store and
/// returns the error at the end.
async fn open_store(config: &Config) -> Result<Option<crate::store::FindingsStore>, ScannerError> {
    let Some(db_url) = config.db_url() else {
        return Ok(None);
    };
    let store = crate::store::FindingsStore::open(&db_url).await?;
    store.migrate().await?;
    Ok(Some(store))
}

/// Collect one finished task from the JoinSet. Returns true if a task was
/// collected, false if the set is empty.
async fn collect_one(
    join_set: &mut JoinSet<Result<IssueOutcome, ScannerError>>,
    all_findings: &mut Vec<Finding>,
    errors_total: &mut u64,
    progress: &ScanProgress,
) -> bool {
    let Some(res) = join_set.join_next().await else {
        return false;
    };
    match res {
        Ok(Ok(outcome)) => {
            let found = outcome.findings.len() as u64;
            progress.record_comments(outcome.comments_scanned);
            progress.record_attachments(outcome.attachments_scanned);
            all_findings.extend(outcome.findings);
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
///
/// Every text the issue carries reaches the scanning loop below as a
/// [`crate::extract::TextSegment`], whatever its source: the payload's fields,
/// the comment pages after the first, and the attachment bodies. There is one
/// scanning loop, one rules engine and one credential-pair detector, so a secret
/// in an attachment is found by exactly the code that finds one in a description.
async fn process_issue(
    client: &JiraClient,
    extractor: &TextExtractor,
    rules_engine: &RulesEngine,
    credpair_detector: &CredentialPairDetector,
    allowlist: &AllowlistFilter,
    config: &Config,
    issue: Issue,
) -> Result<IssueOutcome, ScannerError> {
    let issue_key = issue.key.clone();
    let issue_url = format!("{}/browse/{issue_key}", config.jira_url);

    // Extract text segments from the payload. This includes the *first page* of
    // the issue's comments: Jira embeds `comment.maxResults` of them in the
    // issue itself.
    let mut segments = extractor.extract(&issue_key, &issue.fields);

    // Comments after the first page are not in the payload, and are lost unless
    // they are fetched — `comments_mode = all`, the default, promises them.
    if config.comments_mode != "none" {
        let (total, offset) = comment_paging(&issue.fields);
        if total > offset {
            match client.get_comments_after(&issue_key, offset).await {
                Ok(fetched) => {
                    let fetched_count = fetched.len();
                    for (i, comment) in fetched.into_iter().enumerate() {
                        // Numbered by their position in the whole thread, not
                        // by their position in the page, so a comment's path is
                        // the same shape as the first page's
                        // (`comment.comments[<n>].body`) and does not collide
                        // with it.
                        let path = format!(
                            "comment.comments[{}].body",
                            (offset as usize).saturating_add(i)
                        );
                        segments.extend(extractor.extract_at(&path, &comment.body));
                    }
                    debug!(
                        issue = %issue_key,
                        fetched = fetched_count,
                        total,
                        "Fetched the comment pages after the first"
                    );
                }
                Err(e) => {
                    // Non-fatal by design: the issue's other findings are still
                    // reported, and the missing pages are logged.
                    warn!(issue = %issue_key, error = %e, "Failed to fetch extra comments");
                }
            }
        }
    }

    // Attachments are off unless `--scan-attachments` is set, and nothing here
    // issues a request when it is not.
    let attachment_policy = AttachmentPolicy::from_config(config);
    let attachment_outcome = if attachment_policy.enabled {
        let (attachment_segments, outcome) = attachments::collect_segments(
            client,
            extractor,
            &issue_key,
            &issue.fields,
            &attachment_policy,
        )
        .await;
        segments.extend(attachment_segments);
        outcome
    } else {
        attachments::AttachmentOutcome::default()
    };

    let comments_scanned = comment_bodies_scanned(&segments);

    let mut findings: Vec<Finding> = Vec::new();
    let mut issue_findings_count = 0usize;

    // The judge holds no state, so one value serves every hit of the issue.
    let judge = Judge::new();

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

            // Allowlist, the placeholder check, the context boost, the confidence
            // adjustment and the min-confidence floor are one call into
            // `candidate::Judge`: that chain used to be inline here, and a
            // rejected candidate was dropped without a trace. The judge logs the
            // reason of every drop it decides.
            let candidate = Candidate {
                value: &hit.matched_value,
                text: &segment.text,
                value_span: hit.match_span.clone(),
                field_path: &hit.field_path,
                issue_key: &issue_key,
            };

            // `check` reports *which* entry suppressed the value, so the entry's
            // audit `reason` travels into the verdict (`DropReason::Allowlisted`)
            // and into the debug log of the drop instead of being lost.
            let allowlisted = allowlist
                .check(
                    &hit.matched_value,
                    &hit.rule_id,
                    &issue_key,
                    &hit.field_path,
                )
                .map(|matched| matched.reason.map(str::to_string));

            let confidence = match judge.finalize(
                &hit.rule_id,
                Confidence::parse(&hit.confidence),
                &candidate,
                allowlisted,
                Confidence::parse(&config.min_confidence),
            ) {
                Verdict::Keep { confidence, .. } => confidence,
                Verdict::Drop(_) => continue,
            };

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

    debug!(
        issue = %issue_key,
        findings = findings.len(),
        comments_scanned,
        attachments_scanned = attachment_outcome.scanned,
        "Issue processed"
    );

    Ok(IssueOutcome {
        findings,
        comments_scanned,
        attachments_scanned: attachment_outcome.scanned,
    })
}

/// Comment counts carried by an issue payload: `(total, offset)`.
///
/// Jira puts only the first page of an issue's comments into the issue's
/// `comment` field — `maxResults` entries of `total`, starting at `startAt` — so
/// `offset` is where the next page starts and what the fetch must not re-read.
/// Both values are `0` when the payload carries no comment field at all (a
/// `--fields` list without `comment`), and nothing is fetched then.
fn comment_paging(fields: &serde_json::Value) -> (u64, u64) {
    let Some(comment) = fields.get("comment") else {
        return (0, 0);
    };

    let total = comment
        .get("total")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let start_at = comment
        .get("startAt")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let in_payload = comment
        .get("comments")
        .and_then(serde_json::Value::as_array)
        .map(|comments| comments.len() as u64)
        .unwrap_or(0);

    (total, start_at + in_payload)
}

/// How many comment bodies `segments` covers — the number
/// [`ScanProgress::comments_scanned`] reports.
///
/// Counting segments would not be the same number: a comment body is walked
/// leaf by leaf (an ADF body is one segment per text node) while the comment's
/// other fields — its id, its author's name — are text segments too. The
/// counter is about comments, so the bodies are grouped by their path up to
/// `.body` and counted once each.
fn comment_bodies_scanned(segments: &[TextSegment]) -> u64 {
    const BODY: &str = ".body";

    let mut bodies: HashSet<&str> = HashSet::new();
    for segment in segments {
        if segment.source_type != SourceType::Comment {
            continue;
        }
        if let Some(at) = segment.field_path.find(BODY) {
            bodies.insert(&segment.field_path[..at + BODY.len()]);
        }
    }

    bodies.len() as u64
}

/// Legacy shim — use [`Severity::parse`] or [`Severity::from_str`] from
/// [`crate::finding`] instead.
///
/// Retained for one remaining caller, `tests/config_cli.rs`, which reaches for it
/// through `jiraleaks::pipeline`. Nothing in `src/` uses it any more; the two
/// `src/` call sites were migrated, and this pair can go as soon as that test
/// calls `Severity::parse` itself (CHANGE REQUEST to the QA owner).
///
/// No `#[deprecated]` attribute on purpose: emitting a warning from another
/// team's code during a parallel migration is noise, not a signal.
pub fn parse_severity(s: &str) -> Severity {
    Severity::parse(s)
}

/// Legacy shim — use [`Confidence::parse`] or [`Confidence::from_str`] from
/// [`crate::finding`] instead.
///
/// Same delegation, same single remaining caller and same deliberate absence of
/// `#[deprecated]` as [`parse_severity`].
pub fn parse_confidence(s: &str) -> Confidence {
    Confidence::parse(s)
}
