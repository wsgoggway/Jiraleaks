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

/// Attachment metadata as it appears in an issue's `attachment` field.
///
/// Only the fields the scanner acts on are modelled; the payload carries more
/// (`author`, `created`, `thumbnail`, `self`, …) and serde ignores unknown
/// fields, which is why this struct stays compatible with both Jira Server and
/// Cloud payloads. Unknown fields staying out of the model is deliberate: every
/// field here has a reader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// Jira's attachment id. Deserialised leniently because the wire type
    /// varies: Jira Server/DC sends a string (`"10001"`), some Cloud endpoints a
    /// number, and a strict `u64` would fail the whole array — every attachment
    /// of the issue silently skipped — on the more common of the two.
    #[serde(default, deserialize_with = "string_or_number")]
    pub id: String,
    #[serde(default)]
    pub filename: String,
    /// Size the issue payload declares. Used to skip an oversized attachment
    /// before any request is made, never trusted as the actual body size.
    #[serde(default)]
    pub size: u64,
    #[serde(alias = "mimeType", default)]
    pub mime_type: String,
    /// URL the body is fetched from. Attacker-controlled: it is validated
    /// against the configured Jira origin before any request
    /// (see [`crate::attachments::resolve_content_url`]).
    #[serde(default)]
    pub content: String,
}

/// Accept a JSON string or a JSON number for a field modelled as a string.
fn string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Str(String),
        Num(u64),
    }

    Ok(match Id::deserialize(deserializer)? {
        Id::Str(s) => s,
        Id::Num(n) => n.to_string(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload Jira Server really sends: a string id and a pile of fields
    /// the scanner does not model. Both must be tolerated — a strict model here
    /// means "no attachment is ever scanned", silently.
    #[test]
    fn attachment_meta_accepts_a_server_payload() {
        let raw = serde_json::json!({
            "id": "10001",
            "filename": "prod.env",
            "size": 512,
            "mimeType": "text/plain",
            "content": "https://jira.example.com/secure/attachment/10001/prod.env",
            "author": {"displayName": "Someone", "name": "someone"},
            "created": "2024-01-01T10:00:00.000+0000",
            "self": "https://jira.example.com/rest/api/2/attachment/10001",
            "thumbnail": "https://jira.example.com/secure/thumbnail/10001/_thumb_10001.png"
        });

        let meta: AttachmentMeta = serde_json::from_value(raw).expect("server payload parses");
        assert_eq!(meta.id, "10001");
        assert_eq!(meta.filename, "prod.env");
        assert_eq!(meta.size, 512);
        assert_eq!(meta.mime_type, "text/plain");
        assert!(meta.content.ends_with("/secure/attachment/10001/prod.env"));
    }

    /// A numeric id (some Cloud endpoints) is accepted too, and a missing id
    /// does not fail the parse.
    #[test]
    fn attachment_meta_accepts_a_numeric_or_missing_id() {
        let numeric: AttachmentMeta =
            serde_json::from_value(serde_json::json!({"id": 10001, "filename": "a.txt"}))
                .expect("numeric id parses");
        assert_eq!(numeric.id, "10001");

        let absent: AttachmentMeta =
            serde_json::from_value(serde_json::json!({"filename": "a.txt"}))
                .expect("missing id parses");
        assert_eq!(absent.id, "");
    }
}
