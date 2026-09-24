//! Attachment scanning: which attachments of an issue are worth a request, how
//! their `content` URL is validated before one is made, and how a fetched body
//! becomes a segment for the shared scanning loop.
//!
//! Three policies live here, and each is separately testable because each is
//! separately dangerous:
//!
//! * **Which attachments.** Only text can be scanned, and decoding a binary
//!   format is not what a regex engine can do with it — see
//!   [`TEXT_EXTENSIONS`] and [`BINARY_EXTENSIONS`] for what is fetched and why
//!   the rest is not.
//! * **Where from.** The `content` URL is written by whoever attached the file,
//!   so it is attacker-controlled input on its way into an outbound request.
//!   [`resolve_content_url`] is the single place that decides which URLs are
//!   ours; a URL that fails it is never fetched.
//! * **How much.** Every download is streamed with a byte limit
//!   ([`JiraClient::download_attachment`]) and every issue has a byte budget and
//!   an attachment count ([`MAX_ATTACHMENTS_PER_ISSUE`],
//!   [`MAX_ATTACHMENT_BYTES_PER_ISSUE`]), so a single issue cannot make the
//!   scanner allocate without bound.
//!
//! This module never fails an issue: an attachment that cannot be fetched,
//! decoded or trusted is warned about and counted, and the issue's other
//! findings are reported. See [`collect_segments`].

use serde_json::Value;
use tracing::{debug, warn};
use url::Url;

use crate::config::Config;
use crate::extract::{SourceType, TextExtractor, TextSegment};
use crate::jira::client::JiraClient;
use crate::jira::models::AttachmentMeta;
use crate::sanitize;

/// Extensions whose content is text a regex engine can read.
///
/// Deliberately an allowlist rather than a denylist: a new binary format is then
/// skipped by default instead of being decoded as if it were text. The list is
/// credentials-and-config oriented — what leaks in a Jira ticket is a `.env`, a
/// `.pem`, a `.log`, a CI config — not source code in general, though a few
/// common source extensions are included because tokens do get pasted into
/// `.py` and `.sh` files.
pub const TEXT_EXTENSIONS: &[&str] = &[
    "txt",
    "log",
    "env",
    "ini",
    "conf",
    "cfg",
    "properties",
    "pem",
    "key",
    "crt",
    "cer",
    "pub",
    "json",
    "yaml",
    "yml",
    "toml",
    "xml",
    "csv",
    "sql",
    "md",
    "sh",
    "ps1",
    "py",
    "rb",
    "js",
    "ts",
    "go",
    "rs",
    "java",
    "tf",
    "tfvars",
    "dockerfile",
    "gitconfig",
    "npmrc",
];

/// Extensions that are never scanned, checked *before* the allowlist so a
/// misleading MIME type cannot get them fetched.
///
/// Archives are skipped because the byte limit is enforced on the bytes that
/// arrive: a 1 MB `.zip` is well under any per-attachment limit and can still
/// expand to gigabytes, so scanning an archive means either unpacking
/// attacker-chosen amounts of memory or bounding it by a limit that is checked
/// after the fact — and the archived text would need a format-specific reader
/// anyway. Executables, images and PDFs are skipped because lossy UTF-8 decoding
/// of compressed or structured binary produces noise, not secrets, and every
/// finding it did produce would be unreviewable. Office documents are zip
/// containers, so the same expansion argument applies.
pub const BINARY_EXTENSIONS: &[&str] = &[
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "exe", "dll", "so", "dylib", "bin", "iso",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "odt", "ods", "odp",
];

/// Extensionless filenames that are still text, matched case-insensitively on
/// the whole basename (`Dockerfile` has no extension to match on).
const TEXT_FILENAMES: &[&str] = &["dockerfile", "makefile", "gemfile"];

/// Attachments fetched per issue, at most.
///
/// A cap on requests, not on bytes: 20 text attachments is already far more
/// than a ticket that leaked a credential carries, and an issue with hundreds is
/// a bulk upload whose tail can wait for a targeted re-scan.
pub const MAX_ATTACHMENTS_PER_ISSUE: usize = 20;

/// Bytes fetched per issue, across all of its attachments.
///
/// With the default 10 MB per-attachment limit this is "three full-size
/// attachments, or twenty ordinary ones". It exists because the per-attachment
/// limit alone allows `MAX_ATTACHMENTS_PER_ISSUE * limit` — 200 MB at the
/// defaults — to be pulled in for one issue, and issues are processed
/// concurrently: the budget is what bounds the scanner's memory to
/// `concurrency * 32 MB` at the defaults, which is a number an operator can
/// reason about.
pub const MAX_ATTACHMENT_BYTES_PER_ISSUE: u64 = 32 * 1024 * 1024;

/// Longest attachment name kept in a `field_path`.
///
/// The name comes from the issue and is repeated in every finding of that
/// attachment, in every report; an unbounded label is a report-size multiplier.
const MAX_FIELD_NAME_CHARS: usize = 128;

/// Attachment-scanning policy: the values this module reads out of [`Config`].
///
/// Carved out of the full configuration so that the attachment path can be
/// exercised without one, and so that `pipeline.rs` passes exactly what this
/// module is allowed to look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentPolicy {
    /// `--scan-attachments`. When false nothing in this module runs and no
    /// attachment request is made.
    pub enabled: bool,
    /// `--max-attachment-size-mb`, in bytes: the limit for one attachment body.
    pub max_bytes_per_attachment: u64,
    /// See [`MAX_ATTACHMENTS_PER_ISSUE`].
    pub max_attachments_per_issue: usize,
    /// See [`MAX_ATTACHMENT_BYTES_PER_ISSUE`].
    pub max_bytes_per_issue: u64,
}

impl AttachmentPolicy {
    /// Read the policy out of a configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.scan_attachments,
            // `saturating_mul`: the flag is validated to be non-zero, but a
            // library caller can set any u64, and an overflow here would wrap to
            // a tiny limit and silently skip every attachment.
            max_bytes_per_attachment: config.max_attachment_size_mb.saturating_mul(1024 * 1024),
            max_attachments_per_issue: MAX_ATTACHMENTS_PER_ISSUE,
            max_bytes_per_issue: MAX_ATTACHMENT_BYTES_PER_ISSUE,
        }
    }
}

impl Default for AttachmentPolicy {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

/// What one issue's `attachment` field contributed to its scan.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentOutcome {
    /// Attachments whose text became a segment — the number
    /// `ScanRun::attachments_scanned` reports.
    pub scanned: u64,
    /// Attachments deliberately not fetched: not a text candidate, over a size
    /// limit, or a `content` URL we refuse to follow.
    pub skipped: u64,
    /// Attachments that were worth fetching but could not be read. Never fatal
    /// for the issue.
    pub failed: u64,
    /// Bytes actually read from Jira's attachment endpoint.
    pub bytes_downloaded: u64,
}

/// An attachment body as it was read from Jira.
///
/// `truncated` is not derivable from `bytes` alone (a body that fits exactly
/// would be indistinguishable from one cut at the limit), and the caller wants
/// to warn about it, so it travels with the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentBody {
    pub bytes: Vec<u8>,
    /// True when the size limit cut the body short.
    pub truncated: bool,
}

/// Why an attachment will not be fetched, or `None` when it is a text candidate
/// worth a request.
pub fn skip_reason(meta: &AttachmentMeta) -> Option<&'static str> {
    if meta.filename.trim().is_empty() {
        return Some("no filename");
    }

    let extension = extension_of(basename(&meta.filename));
    if BINARY_EXTENSIONS.contains(&extension.as_str()) {
        return Some("binary, archive or office format");
    }
    if TEXT_EXTENSIONS.contains(&extension.as_str())
        || TEXT_FILENAMES.contains(&basename(&meta.filename).to_ascii_lowercase().as_str())
    {
        return None;
    }
    if mime_is_text(&meta.mime_type) {
        return None;
    }
    Some("not a text extension and not a text MIME type")
}

/// Whether [`skip_reason`] says this attachment can be scanned.
pub fn is_text_candidate(meta: &AttachmentMeta) -> bool {
    skip_reason(meta).is_none()
}

/// Resolve an attachment `content` value into a URL we are willing to fetch.
///
/// `content` is one of two things: a path relative to the configured Jira base
/// URL (what Jira Server/DC sends, `/secure/attachment/10001/prod.env`) or an
/// absolute URL (Jira Cloud). Anything else — a foreign host, a scheme that is
/// not the configured one, a different port, a protocol-relative
/// `//host/path` — yields `None`, and the caller logs a warning and skips the
/// attachment without a request.
///
/// This is the SSRF guard, and it is an origin comparison rather than a
/// prefix check on purpose: a prefix check passes
/// `http://jira.example.com.evil.tld/x` for the base `http://jira.example.com`,
/// which is exactly the trick a hostile issue would use. The returned URL is the
/// parsed-and-reserialized form, so what is fetched is what was checked.
pub fn resolve_content_url(base_url: &str, content: &str) -> Option<String> {
    let base = Url::parse(base_url).ok()?;
    let content = content.trim();
    if content.is_empty() {
        return None;
    }
    // `Url::join` follows the RFC 3986 reference resolution rules, in which
    // "//host/path" is protocol-relative: it would *replace* the authority and
    // leave this origin. Refuse it before the join can reinterpret it.
    if content.starts_with("//") {
        return None;
    }

    let candidate = match Url::parse(content) {
        Ok(url) => url,
        // Not an absolute URL: a relative path is resolved against the base.
        Err(_) => base.join(content).ok()?,
    };

    if same_origin(&base, &candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Same scheme, host and effective port. The effective port matters: a base of
/// `https://jira.example.com` (443) and a content of `https://jira.example.com:8443/x`
/// are different origins, and a URL that names no port is not the same as one
/// that names a different one.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Fetch the text attachments of one issue and return their segments.
///
/// The segments are scanned by the caller's ordinary loop — same rules engine,
/// same credential-pair detector, same allowlist — because an attachment is
/// another place a secret can sit, not another kind of scan.
///
/// Never returns an error: an attachment that is malformed, unfetchable or
/// untrustworthy is counted in the [`AttachmentOutcome`] and warned about, and
/// the issue keeps its other findings, exactly as a failed extra-comment fetch
/// does.
pub async fn collect_segments(
    client: &JiraClient,
    extractor: &TextExtractor,
    issue_key: &str,
    fields: &Value,
    policy: &AttachmentPolicy,
) -> (Vec<TextSegment>, AttachmentOutcome) {
    let mut outcome = AttachmentOutcome::default();
    if !policy.enabled {
        return (Vec::new(), outcome);
    }

    let Some(attachments) = fields.get("attachment").and_then(Value::as_array) else {
        return (Vec::new(), outcome);
    };

    let mut segments = Vec::new();
    let mut budget = policy.max_bytes_per_issue;

    for raw in attachments {
        if outcome.scanned >= policy.max_attachments_per_issue as u64 {
            warn!(
                issue = %issue_key,
                limit = policy.max_attachments_per_issue,
                "Attachment count limit for this issue reached"
            );
            break;
        }

        let Some(meta) = parse_meta(raw) else {
            outcome.failed += 1;
            // A malformed entry is skipped on its own: parsing the whole array
            // as one `Vec<AttachmentMeta>` would drop every attachment of the
            // issue because one of them surprised the model.
            warn!(issue = %issue_key, "Malformed attachment entry skipped");
            continue;
        };
        let name = field_name(&meta.filename);

        if let Some(reason) = skip_reason(&meta) {
            debug!(issue = %issue_key, attachment = %name, reason, "Attachment skipped");
            outcome.skipped += 1;
            continue;
        }

        let Some(url) = resolve_content_url(client.base_url(), &meta.content) else {
            outcome.skipped += 1;
            warn!(
                issue = %issue_key,
                attachment = %name,
                content = %sanitize::terminal(&meta.content),
                "Attachment content URL is outside the configured Jira origin, not downloaded"
            );
            continue;
        };

        // Both size limits are checked against the size the issue *claims*
        // before a request is made, so an oversized attachment costs nothing.
        // The claim is not trusted — `download_attachment` enforces the same
        // limit on the response itself.
        if meta.size > policy.max_bytes_per_attachment {
            outcome.skipped += 1;
            warn!(
                issue = %issue_key,
                attachment = %name,
                attachment_id = %meta.id,
                declared_size = meta.size,
                limit = policy.max_bytes_per_attachment,
                "Attachment exceeds the size limit, not downloaded"
            );
            continue;
        }
        if budget == 0 {
            outcome.skipped += 1;
            warn!(
                issue = %issue_key,
                attachment = %name,
                "Attachment budget for this issue is exhausted, not downloaded"
            );
            continue;
        }

        let limit = policy.max_bytes_per_attachment.min(budget);
        match client.download_attachment(&url, limit).await {
            Ok(body) => {
                budget = budget.saturating_sub(body.bytes.len() as u64);
                if body.truncated {
                    warn!(
                        issue = %issue_key,
                        attachment = %name,
                        limit,
                        "Attachment truncated at the size limit"
                    );
                }
                // `from_utf8_lossy`, not a UTF-8 check: a text file with a
                // stray binary byte is still worth scanning, and rejecting it
                // would lose the secrets around that byte.
                let text = String::from_utf8_lossy(&body.bytes);
                segments.push(extractor.segment(
                    format!("attachment[{name}]"),
                    &text,
                    SourceType::Attachment,
                ));
                outcome.scanned += 1;
                outcome.bytes_downloaded += body.bytes.len() as u64;
            }
            Err(error) => {
                outcome.failed += 1;
                warn!(
                    issue = %issue_key,
                    attachment = %name,
                    error = %error,
                    "Attachment download failed"
                );
            }
        }
    }

    (segments, outcome)
}

/// Parse one entry of the `attachment` array.
fn parse_meta(raw: &Value) -> Option<AttachmentMeta> {
    serde_json::from_value(raw.clone()).ok()
}

/// Basename of a filename, in case a payload carries a path.
fn basename(filename: &str) -> &str {
    filename.rsplit(['/', '\\']).next().unwrap_or(filename)
}

/// Lowercased extension of a basename, empty when there is none.
fn extension_of(basename: &str) -> String {
    basename
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Whether a MIME type names text. Parameters (`; charset=utf-8`) are ignored.
fn mime_is_text(mime_type: &str) -> bool {
    let mime = mime_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
        || matches!(
            mime.as_str(),
            "application/json" | "application/xml" | "application/x-yaml"
        )
}

/// Attachment name as it appears in a `field_path`.
///
/// The name is written by whoever uploaded the file, and every report prints the
/// field path, so it is neutralised with the same helper the rest of the scanner
/// uses: terminal escape sequences removed, newlines and tabs flattened so one
/// attachment cannot forge a line in a report, and the label capped so it cannot
/// dominate a report.
fn field_name(filename: &str) -> String {
    let flattened: String = sanitize::terminal(filename)
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            other => other,
        })
        .take(MAX_FIELD_NAME_CHARS)
        .collect();

    if flattened.trim().is_empty() {
        "unnamed".to_string()
    } else {
        flattened
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(filename: &str, mime_type: &str) -> AttachmentMeta {
        AttachmentMeta {
            id: "1".to_string(),
            filename: filename.to_string(),
            size: 10,
            mime_type: mime_type.to_string(),
            content: "/secure/attachment/1/file".to_string(),
        }
    }

    #[test]
    fn text_attachments_are_candidates() {
        for (filename, mime) in [
            ("prod.env", "text/plain"),
            (".env", "application/octet-stream"),
            ("keys.pem", ""),
            ("app.log", "text/plain"),
            ("settings.yaml", "text/yaml"),
            ("Dockerfile", ""),
            ("docker-compose.yml", ""),
            ("tokens.txt", ""),
            ("query.sql", ""),
            // A misleading MIME type must not disqualify a text extension.
            ("notes.md", "application/octet-stream"),
        ] {
            assert!(
                is_text_candidate(&meta(filename, mime)),
                "{filename} should be scanned"
            );
        }
    }

    #[test]
    fn binary_attachments_are_not_candidates() {
        for (filename, mime) in [
            ("dump.zip", "application/zip"),
            ("image.png", "image/png"),
            ("photo.jpeg", "image/jpeg"),
            ("report.pdf", "application/pdf"),
            ("sheet.xlsx", "application/vnd.ms-excel"),
            ("slides.pptx", "application/octet-stream"),
            ("lib.so", "application/octet-stream"),
            ("backup.tar.gz", "application/gzip"),
            // A text MIME type must not rescue an archive: the limit is
            // enforced on compressed bytes, so this is the shape of a bomb.
            ("dump.zip", "text/plain"),
        ] {
            assert!(
                !is_text_candidate(&meta(filename, mime)),
                "{filename} ({mime}) should be skipped"
            );
        }
    }

    #[test]
    fn text_mime_type_wins_over_an_unknown_extension() {
        assert!(is_text_candidate(&meta("notes.unknownext", "text/plain")));
        assert!(is_text_candidate(&meta("payload", "application/json")));
        assert!(is_text_candidate(&meta("payload", "application/x-yaml")));
        assert!(is_text_candidate(&meta(
            "payload",
            "text/plain; charset=utf-8"
        )));
        assert!(!is_text_candidate(&meta(
            "payload",
            "application/octet-stream"
        )));
        assert!(!is_text_candidate(&meta("", "text/plain")));
    }

    #[test]
    fn resolve_accepts_a_relative_path_and_a_same_origin_url() {
        let base = "https://jira.example.com";
        assert_eq!(
            resolve_content_url(base, "/secure/attachment/1/prod.env").as_deref(),
            Some("https://jira.example.com/secure/attachment/1/prod.env")
        );
        assert_eq!(
            resolve_content_url(
                base,
                "https://jira.example.com/secure/attachment/1/prod.env"
            )
            .as_deref(),
            Some("https://jira.example.com/secure/attachment/1/prod.env")
        );
        // A base URL with a path and a port is compared on its origin, not on
        // its full text.
        assert_eq!(
            resolve_content_url("http://127.0.0.1:8080/jira", "/rest/x").as_deref(),
            Some("http://127.0.0.1:8080/rest/x")
        );
    }

    #[test]
    fn resolve_rejects_foreign_origins() {
        let base = "https://jira.example.com";
        for content in [
            // Another host entirely.
            "https://evil.example.com/secure/attachment/1/prod.env",
            // The classic prefix trick: same prefix, different host.
            "https://jira.example.com.evil.tld/secure/attachment/1/prod.env",
            // Protocol-relative: would replace the authority on join.
            "//evil.example.com/secure/attachment/1/prod.env",
            // Scheme downgrade.
            "http://jira.example.com/secure/attachment/1/prod.env",
            // Same host, another port.
            "https://jira.example.com:8443/secure/attachment/1/prod.env",
            // Same origin but not HTTP at all.
            "file:///etc/passwd",
            "javascript:alert(1)",
            // Nothing to resolve.
            "",
            "   ",
        ] {
            assert_eq!(
                resolve_content_url(base, content),
                None,
                "{content} must not be fetched"
            );
        }
    }

    /// The name is attacker-controlled and reaches every report; it must not be
    /// able to carry a terminal escape sequence or forge a report line.
    #[test]
    fn field_name_is_neutralised() {
        assert_eq!(field_name("prod.env"), "prod.env");
        assert_eq!(field_name("a\nb\tc"), "a b c");
        // A CSI erase sequence is stripped, not passed on to the terminal.
        assert_eq!(field_name("\u{1b}[2Kclean"), "clean");
        // An OSC 52 clipboard write is consumed whole, payload included.
        let clipboard = field_name("\u{1b}]52;c;aGFjaw==\u{7}prod.env");
        assert!(!clipboard.contains('\u{1b}'));
        assert!(!clipboard.contains('\u{7}'));
        assert!(clipboard.ends_with("prod.env"), "got {clipboard:?}");
        assert_eq!(field_name("   "), "unnamed");
        assert_eq!(field_name(""), "unnamed");
        assert!(field_name(&"x".repeat(500)).chars().count() <= MAX_FIELD_NAME_CHARS);
    }
}
