use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::error::ScannerError;
use crate::jira::client::JiraClient;
use crate::jira::models::Issue;
use crate::progress::ScanProgress;

/// Everything [`Fetcher`] needs from the configuration — and nothing else.
///
/// The fetcher used to take a whole `Config` and read four values out of it, so
/// every caller had to have a complete configuration and the type could not say
/// which parts of it mattered. The four are named here once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOptions {
    /// Issues per search page (`--page-size`).
    pub page_size: u32,
    /// Maximum issues to scan; 0 = no limit (`--max-issues`).
    pub max_issues: u32,
    /// Concurrent issue processing tasks (`--concurrency`); it sizes the
    /// channel the fetcher streams into.
    pub concurrency: usize,
    /// Fields to request per issue (`--fields`), already split on commas.
    pub fields: Vec<String>,
}

impl FetchOptions {
    /// Read the fetcher's options out of a configuration.
    ///
    /// The `--fields` value is a comma-separated CLI string; it is split here,
    /// so the fetcher deals in field names and not in the CLI's spelling of
    /// them.
    pub fn from_config(config: &Config) -> Self {
        Self {
            page_size: config.page_size,
            max_issues: config.max_issues,
            concurrency: config.concurrency,
            fields: config
                .fields
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }
}

/// Coordinates data fetching from Jira: issue search pagination.
///
/// Comments and attachments are *not* fetched here: comment pagination lives in
/// [`JiraClient::get_comments_after`] and attachment fetching in
/// [`crate::attachments`], each next to the limit it enforces. A third copy of
/// comment pagination used to live here as `fetch_comments` and was never
/// called from anywhere.
pub struct Fetcher {
    client: Arc<JiraClient>,
    options: FetchOptions,
}

impl Fetcher {
    pub fn new(client: Arc<JiraClient>, options: FetchOptions) -> Self {
        Self { client, options }
    }

    /// Stream issues matching the JQL with pagination. Runs pagination in a
    /// spawned task and sends issues through an mpsc channel as pages arrive,
    /// so the consumer can start processing before all issues are fetched.
    /// Returns the receiver and a join handle yielding the number of issues
    /// fetched (or a ScannerError on fetch failure).
    pub async fn fetch_issues_stream(
        self: Arc<Self>,
        jql: &str,
        cancel: CancellationToken,
        progress: Arc<ScanProgress>,
    ) -> (
        mpsc::Receiver<Issue>,
        tokio::task::JoinHandle<Result<u64, ScannerError>>,
    ) {
        let cap = self.options.concurrency.max(1) * 2;
        let (tx, rx) = mpsc::channel(cap);
        let fields = self.options.fields.clone();
        let jql = jql.to_string();

        let handle = tokio::spawn(async move {
            let mut start_at = 0u32;
            let page_size = self.options.page_size;
            let mut fetched: u64 = 0;
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let page = self
                    .client
                    .search(&jql, start_at, page_size, &fields)
                    .await?;
                // issues_total = min(Jira-total, max_issues); max_issues==0 -> no limit
                let total_disp = if self.options.max_issues > 0 {
                    page.total.min(self.options.max_issues as u64)
                } else {
                    page.total
                };
                progress.set_total(total_disp);
                for issue in page.issues {
                    if cancel.is_cancelled() {
                        break;
                    }
                    if self.options.max_issues > 0 && fetched >= self.options.max_issues as u64 {
                        break;
                    }
                    if tx.send(issue).await.is_err() {
                        break; // consumer dropped -> exit
                    }
                    fetched += 1;
                }
                if self.options.max_issues > 0 && fetched >= self.options.max_issues as u64 {
                    break;
                }
                start_at += page_size;
                if start_at as u64 >= page.total {
                    break;
                }
            }
            // drop(tx) closes the channel -> recv() on the consumer returns None
            Ok(fetched)
        });
        (rx, handle)
    }
}
