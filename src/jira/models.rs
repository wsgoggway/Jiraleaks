use serde::{Deserialize, Serialize};

/// Represents a paginated search result from Jira REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPage {
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    #[serde(alias = "startAt")]
    pub start_at: u64,
    #[serde(default)]
    #[serde(alias = "maxResults")]
    pub max_results: u64,
    #[serde(default)]
    pub issues: Vec<Issue>,
}

/// A Jira issue with its key and all fields as a dynamic JSON value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub fields: serde_json::Value,
}

/// Attachment metadata from the Jira API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub size: u64,
    #[serde(alias = "mimeType", default)]
    pub mime_type: String,
    #[serde(default)]
    pub author: Option<UserRef>,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub content: String,
}

/// Lightweight user reference (author, assignee, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRef {
    #[serde(alias = "displayName", default)]
    pub display_name: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email_address: Option<String>,
}

/// Paginated comments result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentPage {
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub comments: Vec<Comment>,
}

/// A single comment on a Jira issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub author: Option<UserRef>,
    /// Comment body — string for wiki markup, object for ADF.
    #[serde(default)]
    pub body: serde_json::Value,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub updated: String,
}

/// Server info response from `/rest/api/2/serverInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    #[serde(alias = "baseUrl", default)]
    pub base_url: String,
    #[serde(default)]
    pub version: String,
    #[serde(alias = "deploymentType", default)]
    pub deployment_type: String,
    #[serde(alias = "serverTitle", default)]
    pub server_title: String,
}
