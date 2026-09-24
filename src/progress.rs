use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use indicatif::ProgressBar;

/// Shared scan progress counters plus an optional terminal progress bar.
/// The bar (if any) stays in sync with the counters.
pub struct ScanProgress {
    pub issues_total: AtomicU64, // Jira-total (or max_issues), grows with pages
    pub issues_done: AtomicU64,  // issues processed
    pub findings_found: AtomicU64, // findings found (pre-dedup)
    pub errors_count: AtomicU64,
    pub started_at: Instant,
    bar: Option<ProgressBar>,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            issues_total: AtomicU64::new(0),
            issues_done: AtomicU64::new(0),
            findings_found: AtomicU64::new(0),
            errors_count: AtomicU64::new(0),
            started_at: Instant::now(),
            bar: None,
        }
    }

    pub fn set_bar(&mut self, bar: ProgressBar) {
        self.bar = Some(bar);
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

    /// Record one finished issue that errored out.
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
