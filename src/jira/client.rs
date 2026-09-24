use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::config::Config;
use crate::error::ScannerError;
use crate::jira::models::{AttachmentMeta, CommentPage, SearchPage, ServerInfo};

/// HTTP client for Jira REST API with rate limiting, retries, and auth.
pub struct JiraClient {
    http: Client,
    base_url: String,
    auth_header: String,
    semaphore: Arc<Semaphore>,
    pub concurrency: usize,
}

impl JiraClient {
    /// Build a new JiraClient from the scanner config.
    pub fn new(config: &Config) -> Result<Self, ScannerError> {
        let base_url = config.jira_url.trim_end_matches('/').to_string();

        let auth_header = match config.auth.as_str() {
            "bearer" => format!("Bearer {}", config.pat()),
            "basic" => {
                let email = config.email.as_deref().unwrap_or("");
                let creds = format!("{}:{}", email, config.pat());
                format!("Basic {}", base64_encode(&creds))
            }
            "none" => String::new(),
            other => {
                return Err(ScannerError::Config(format!("Unknown auth mode: {other}")));
            }
        };

        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs()))
            .user_agent(concat!("jiraleaks/", env!("CARGO_PKG_VERSION")))
            .gzip(true);

        if config.no_proxy {
            builder = builder.no_proxy();
        }

        let http = builder
            .build()
            .map_err(|e| ScannerError::Config(format!("Failed to build HTTP client: {e}")))?;

        let concurrency = config.concurrency.max(1);

        Ok(Self {
            http,
            base_url,
            auth_header,
            semaphore: Arc::new(Semaphore::new(concurrency)),
            concurrency,
        })
    }

    /// Verify connectivity and log server info.
    pub async fn server_info(&self) -> Result<ServerInfo, ScannerError> {
        let url = format!("{}/rest/api/2/serverInfo", self.base_url);
        let resp = self.send(self.http.get(&url)).await?;
        let info: ServerInfo = resp
            .json()
            .await
            .map_err(|e| ScannerError::JiraAccess(format!("Failed to parse serverInfo: {e}")))?;
        Ok(info)
    }

    /// Search issues by JQL with pagination.
    pub async fn search(
        &self,
        jql: &str,
        start_at: u32,
        page_size: u32,
        fields: &[String],
    ) -> Result<SearchPage, ScannerError> {
        let url = format!("{}/rest/api/2/search", self.base_url);
        let fields_param = fields.join(",");

        debug!(jql, start_at, page_size, fields = %fields_param, "Searching Jira");

        let resp = self
            .send(self.http.get(&url).query(&[
                ("jql", jql),
                ("startAt", &start_at.to_string()),
                ("maxResults", &page_size.to_string()),
                ("fields", &fields_param),
            ]))
            .await?;

        let page: SearchPage = resp.json().await.map_err(|e| {
            ScannerError::ScanCritical(format!("Failed to parse search results: {e}"))
        })?;

        Ok(page)
    }

    /// Get a single issue by key.
    pub async fn get_issue(
        &self,
        key: &str,
        fields: &[String],
    ) -> Result<serde_json::Value, ScannerError> {
        let url = format!("{}/rest/api/2/issue/{}", self.base_url, key);
        let fields_param = fields.join(",");

        let resp = self
            .send(self.http.get(&url).query(&[("fields", &fields_param)]))
            .await?;

        resp.json()
            .await
            .map_err(|e| ScannerError::JiraAccess(format!("Failed to get issue {key}: {e}")))
    }

    /// Get paginated comments for an issue.
    pub async fn get_comments_paginated(
        &self,
        key: &str,
        start_at: u64,
        max_results: u64,
    ) -> Result<CommentPage, ScannerError> {
        let url = format!("{}/rest/api/2/issue/{}/comment", self.base_url, key);

        let resp = self
            .send(self.http.get(&url).query(&[
                ("startAt", &start_at.to_string()),
                ("maxResults", &max_results.to_string()),
            ]))
            .await?;

        resp.json()
            .await
            .map_err(|e| ScannerError::JiraAccess(format!("Failed to get comments for {key}: {e}")))
    }

    /// Download an attachment into memory.
    pub async fn download_attachment(
        &self,
        meta: &AttachmentMeta,
    ) -> Result<Vec<u8>, ScannerError> {
        let url = format!("{}{}", self.base_url, meta.content);
        let resp = self.send(self.http.get(&url)).await?;

        let max_size = 10 * 1024 * 1024; // 10 MB default safety limit
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ScannerError::ScanCritical(format!("Attachment download failed: {e}")))?;

        if bytes.len() > max_size {
            warn!(
                filename = %meta.filename,
                size = bytes.len(),
                "Attachment exceeds size limit, truncating"
            );
            return Ok(bytes[..max_size].to_vec());
        }

        Ok(bytes.to_vec())
    }

    /// Send an HTTP request with retry logic, rate limiting, and error handling.
    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Response, ScannerError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| ScannerError::ScanCritical(format!("Semaphore closed: {e}")))?;

        // Clone the partially-built request to add headers
        let req = req
            .header("Authorization", &self.auth_header)
            .header("Accept", "application/json");

        let mut attempt = 0u32;
        let max_retries = 3u32;
        let mut backoff = Duration::from_millis(500);

        loop {
            attempt += 1;
            let req = req
                .try_clone()
                .expect("Request must be cloneable for retry");

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp);
                    }

                    match status {
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                            return Err(ScannerError::JiraAccess(format!(
                                "Auth failure: HTTP {status}"
                            )));
                        }
                        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                            if attempt < max_retries {
                                let delay = parse_retry_after(&resp).unwrap_or(backoff);
                                warn!(
                                    status = status.as_u16(),
                                    delay_ms = delay.as_millis(),
                                    attempt,
                                    "Rate limited, retrying"
                                );
                                tokio::time::sleep(delay).await;
                                backoff = (backoff * 2).min(Duration::from_secs(60));
                                continue;
                            }
                            return Err(ScannerError::JiraAccess(format!(
                                "Rate limit exhausted after {max_retries} retries (HTTP {status})"
                            )));
                        }
                        s if s.is_server_error() => {
                            if attempt < max_retries {
                                warn!(status = s.as_u16(), attempt, "Server error, retrying");
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(Duration::from_secs(30));
                                continue;
                            }
                            return Err(ScannerError::JiraAccess(format!(
                                "Server error after {max_retries} retries: HTTP {s}"
                            )));
                        }
                        other => {
                            return Err(ScannerError::JiraAccess(format!(
                                "Unexpected HTTP {other}"
                            )));
                        }
                    }
                }
                Err(e) => {
                    if e.is_timeout() || e.is_connect() {
                        if attempt < max_retries {
                            warn!(
                                error = %e,
                                attempt,
                                "Network error, retrying"
                            );
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                            continue;
                        }
                        return Err(ScannerError::JiraAccess(format!(
                            "Network error after {max_retries} retries: {e}"
                        )));
                    }
                    return Err(ScannerError::JiraAccess(format!("Request error: {e}")));
                }
            }
        }
    }
}

/// Parse Retry-After header: supports seconds (integer) and HTTP-date.
fn parse_retry_after(resp: &Response) -> Option<Duration> {
    let header = resp.headers().get("Retry-After")?.to_str().ok()?;
    // Try integer seconds first
    if let Ok(secs) = header.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // Try HTTP-date
    if let Ok(date) = httpdate::parse_http_date(header) {
        let now = std::time::SystemTime::now();
        if let Ok(dur) = date.duration_since(now) {
            return Some(dur);
        }
    }
    None
}

/// Minimal base64 encoder without external crate dependency.
fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}
