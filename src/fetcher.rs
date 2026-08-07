use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::error::ScannerError;
use crate::jira::client::JiraClient;
use crate::jira::models::Issue;
use crate::progress::ScanProgress;

/// Coordinates data fetching from Jira: search pagination, comments, attachments.
pub struct Fetcher {
    client: Arc<JiraClient>,
    config: Config,
}

impl Fetcher {
    pub fn new(client: Arc<JiraClient>, config: Config) -> Self {
        Self { client, config }
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
        let cap = self.config.concurrency.max(1) * 2;
        let (tx, rx) = mpsc::channel(cap);
        let fields: Vec<String> = self
            .config
            .fields
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let jql = jql.to_string();

        let handle = tokio::spawn(async move {
            let mut start_at = 0u32;
            let page_size = self.config.page_size;
            let mut fetched: u64 = 0;
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let page = self.client.search(&jql, start_at, page_size, &fields).await?;
                // issues_total = min(Jira-total, max_issues); max_issues==0 -> no limit
                let total_disp = if self.config.max_issues > 0 {
                    page.total.min(self.config.max_issues as u64)
                } else {
                    page.total
                };
                progress.set_total(total_disp);
                for issue in page.issues {
                    if cancel.is_cancelled() {
                        break;
                    }
                    if self.config.max_issues > 0 && fetched >= self.config.max_issues as u64 {
                        break;
                    }
                    if tx.send(issue).await.is_err() {
                        break; // consumer dropped -> exit
                    }
                    fetched += 1;
                }
                if self.config.max_issues > 0 && fetched >= self.config.max_issues as u64 {
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

    /// Fetch all comments for a single issue, handling pagination.
    pub async fn fetch_comments(
        &self,
        client: &JiraClient,
        issue_key: &str,
        existing_count: u64,
    ) -> Result<Vec<crate::jira::models::Comment>, ScannerError> {
        let mut all_comments = Vec::new();
        let mut start_at = existing_count;

        loop {
            let page = client.get_comments_paginated(issue_key, start_at, 50).await?;
            let count = page.comments.len();
            all_comments.extend(page.comments);

            start_at += 50;
            if all_comments.len() as u64 >= page.total || count == 0 {
                break;
            }
        }

        Ok(all_comments)
    }
}
