use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use indicatif::ProgressBar;

/// Shared scan progress counters plus an optional terminal progress bar.
/// The bar (if any) stays in sync with the counters.
///
/// Counter semantics (the fields are public and read by the report writers, so
/// they are a contract, not an implementation detail):
///
/// - `issues_total` — the total the scan expects: the Jira-reported total capped
///   by `--max-issues`, filled in as pages arrive and therefore still growing
///   while the first pages are processed. It can stay above `issues_done` when a
///   scan is cancelled or a page fetch fails.
/// - `issues_done` — issues that finished processing, **successful or not**: a
///   failed issue increments this counter *and* `errors_count`. This is the
///   counter that `ScanRun::issues_scanned` mirrors, so `issues_scanned` means
///   "issues attempted". Subtract `errors_count` for the fully-processed count —
///   dividing the two directly would understate the failure rate.
/// - `findings_found` — findings found before deduplication, i.e. the sum over
///   issues of the findings each issue reported; `ScanRun::findings_total` is
///   the post-dedup number and is normally smaller.
/// - `comments_scanned` — comment bodies whose text was handed to the
///   detectors, each counted once however many segments its body was walked
///   into. It includes the first page that arrives inside the issue payload,
///   which is scanned whatever `--comments-mode` says: the mode only decides
///   whether the pages after the first are fetched.
/// - `attachments_scanned` — attachments whose text was fetched and handed to
///   the detectors, i.e. exactly the size of the `attachment[<name>]` segment
///   set. Attachments skipped (not text, over a limit, foreign URL) and
///   attachments that failed to download are not counted here.
/// - `errors_count` — issues whose processing failed (a subset of
///   `issues_done`).
pub struct ScanProgress {
    pub issues_total: AtomicU64, // Jira-total (or max_issues), grows with pages
    pub issues_done: AtomicU64,  // issues processed, including failed ones
    pub findings_found: AtomicU64, // findings found (pre-dedup)
    pub comments_scanned: AtomicU64,
    pub attachments_scanned: AtomicU64,
    pub errors_count: AtomicU64,
    pub started_at: Instant,
    bar: Option<ProgressBar>,
}

impl ScanProgress {
    /// Counters only: no terminal progress bar is attached.
    pub fn new() -> Self {
        Self {
            issues_total: AtomicU64::new(0),
            issues_done: AtomicU64::new(0),
            findings_found: AtomicU64::new(0),
            comments_scanned: AtomicU64::new(0),
            attachments_scanned: AtomicU64::new(0),
            errors_count: AtomicU64::new(0),
            started_at: Instant::now(),
            bar: None,
        }
    }

    /// Counters plus a progress bar kept in sync with them.
    ///
    /// The bar is attached here, at construction, so the type is shared as
    /// `Arc<ScanProgress>` from its first moment — there is no window in which
    /// the counters are live but the bar is not.
    pub fn with_bar(bar: ProgressBar) -> Self {
        Self {
            bar: Some(bar),
            ..Self::new()
        }
    }

    /// Update the known issue total (Jira total or max_issues).
    pub fn set_total(&self, total: u64) {
        self.issues_total.store(total, Ordering::Relaxed);
        if let Some(bar) = &self.bar {
            bar.set_length(total);
        }
    }

    /// Record one finished issue with its pre-dedup finding count.
    pub fn finish_issue(&self, findings_delta: u64) {
        self.issues_done.fetch_add(1, Ordering::Relaxed);
        self.findings_found
            .fetch_add(findings_delta, Ordering::Relaxed);
        if let Some(bar) = &self.bar {
            bar.inc(1);
            bar.set_message(self.summary());
        }
    }

    /// Record the comment bodies of one finished issue. See the type-level
    /// note on `comments_scanned`.
    pub fn record_comments(&self, comments: u64) {
        self.comments_scanned.fetch_add(comments, Ordering::Relaxed);
    }

    /// Record the attachments of one finished issue. See the type-level note on
    /// `attachments_scanned`.
    pub fn record_attachments(&self, attachments: u64) {
        self.attachments_scanned
            .fetch_add(attachments, Ordering::Relaxed);
    }

    /// Record one finished issue that errored out.
    ///
    /// Counts as a finished issue as well: see the type-level note on
    /// `issues_done` / `ScanRun::issues_scanned`.
    pub fn finish_issue_error(&self) {
        self.issues_done.fetch_add(1, Ordering::Relaxed);
        self.errors_count.fetch_add(1, Ordering::Relaxed);
        if let Some(bar) = &self.bar {
            bar.inc(1);
            bar.set_message(self.summary());
        }
    }

    /// Refresh the progress bar (spinner/ETA) without changing counters.
    pub fn tick(&self) {
        if let Some(bar) = &self.bar {
            bar.tick();
        }
    }

    /// Finalize the bar with a completion message.
    pub fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_with_message(self.summary());
        }
    }

    fn summary(&self) -> String {
        let findings = self.findings_found.load(Ordering::Relaxed);
        let errors = self.errors_count.load(Ordering::Relaxed);
        format!("{findings} findings · {errors} errors")
    }
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bar-less constructor and the bar-carrying one must start from the same
    /// counters, and `with_bar` must not lose the zero state.
    #[test]
    fn with_bar_starts_from_zeroed_counters() {
        let progress = ScanProgress::with_bar(ProgressBar::hidden());
        assert_eq!(progress.issues_total.load(Ordering::Relaxed), 0);
        assert_eq!(progress.issues_done.load(Ordering::Relaxed), 0);
        assert_eq!(progress.findings_found.load(Ordering::Relaxed), 0);
        assert_eq!(progress.comments_scanned.load(Ordering::Relaxed), 0);
        assert_eq!(progress.attachments_scanned.load(Ordering::Relaxed), 0);
        assert_eq!(progress.errors_count.load(Ordering::Relaxed), 0);
    }

    /// The content counters accumulate across issues, which is what makes
    /// `ScanRun::comments_scanned` / `attachments_scanned` a scan total.
    #[test]
    fn content_counters_accumulate() {
        let progress = ScanProgress::new();
        progress.record_comments(2);
        progress.record_comments(1);
        progress.record_attachments(3);
        assert_eq!(progress.comments_scanned.load(Ordering::Relaxed), 3);
        assert_eq!(progress.attachments_scanned.load(Ordering::Relaxed), 3);
    }

    /// Documented contract: a failed issue counts as a finished issue.
    #[test]
    fn error_counts_as_done() {
        let progress = ScanProgress::new();
        progress.finish_issue(3);
        progress.finish_issue_error();
        assert_eq!(progress.issues_done.load(Ordering::Relaxed), 2);
        assert_eq!(progress.errors_count.load(Ordering::Relaxed), 1);
        assert_eq!(progress.findings_found.load(Ordering::Relaxed), 3);
    }
}
