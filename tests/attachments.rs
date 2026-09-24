//! Comment and attachment scanning, end to end through `pipeline::run`.
//!
//! Both features these tests cover were documented and did not work, so the
//! tests are written against the observable result of a whole scan rather than
//! against the internals: a report is written by the same path an operator uses,
//! and what it says — the findings, the counters in `scan_run` — is the
//! assertion.
//!
//! Four of them are regressions on silent false negatives:
//!
//! * comments after the first page were fetched and then dropped, so a token in
//!   comment 21 of an issue was never found;
//! * `--scan-attachments` was read into the configuration and used nowhere, so
//!   the flag scanned nothing while the README promised it did;
//! * a download read the whole body before checking its size, so the size limit
//!   was applied after the allocation it was meant to prevent;
//! * an attachment `content` URL is written by whoever attached the file, and
//!   was concatenated onto the Jira base URL — an arbitrary outbound request
//!   (and a credential leak) waiting for a hostile issue.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use jiraleaks::config::Config;
use jiraleaks::hash::secret_hash;
use jiraleaks::jira::client::JiraClient;
use jiraleaks::pipeline;

// ── fixtures ──────────────────────────────────────────────────────────────

/// A token the built-in `github_token` rule matches: `ghp_` plus 36
/// alphanumerics. Distinct per call site, so a finding can be attributed to
/// exactly one place in the fixture.
fn token(tag: &str) -> String {
    assert!(
        tag.len() <= 36 && tag.chars().all(|c| c.is_ascii_alphanumeric()),
        "token tags are lowercase alphanumerics"
    );
    format!("ghp_{tag}{}", "q".repeat(36 - tag.len()))
}

/// An issue as the search endpoint returns it.
fn issue(fields: Value) -> Value {
    json!({"id": "1", "key": "TEST-1", "fields": fields})
}

/// One entry of an issue's `attachment` array.
fn attachment(
    id: &str,
    filename: &str,
    mime_type: &str,
    size: u64,
    content: impl Into<String>,
) -> Value {
    json!({
        "id": id,
        "filename": filename,
        "size": size,
        "mimeType": mime_type,
        "content": content.into(),
    })
}

/// Mount `/rest/api/2/search`, answering every page request with one issue
/// (`total: 1`), which is what stops the fetcher after the first page.
async fn mount_search(server: &MockServer, fields: Value) {
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
            "issues": [issue(fields)],
        })))
        .mount(server)
        .await;
}

/// Mount one page of the comment endpoint.
async fn mount_comments(server: &MockServer, start_at: u64, total: u64, comments: Value) {
    Mock::given(method("GET"))
        .and(path("/rest/api/2/issue/TEST-1/comment"))
        .and(query_param("startAt", start_at.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "startAt": start_at,
            "total": total,
            "comments": comments,
        })))
        .mount(server)
        .await;
}

/// Requests the mock server received whose path starts with `prefix`.
async fn requests_to(server: &MockServer, prefix: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| request.url.path().starts_with(prefix))
        .count()
}

// ── running a scan ────────────────────────────────────────────────────────

/// One scan's result, read back from the JSON report it wrote.
struct ScanReport {
    scan_run: Value,
    findings: Vec<Value>,
    /// Everything the scan logged, so a test can assert that a skip was
    /// reported and not swallowed.
    logs: String,
}

impl ScanReport {
    /// A finding for `field_path` produced by `rule_id`, if there is one.
    fn finding(&self, field_path: &str, rule_id: &str) -> Option<&Value> {
        self.findings
            .iter()
            .find(|finding| finding["field_path"] == field_path && finding["rule_id"] == rule_id)
    }

    /// Whether any finding names this `field_path`, whatever the rule.
    fn has_path(&self, field_path: &str) -> bool {
        self.findings
            .iter()
            .any(|finding| finding["field_path"] == field_path)
    }

    /// A `ScanRun` counter.
    fn counter(&self, name: &str) -> u64 {
        self.scan_run[name].as_u64().unwrap_or(0)
    }

    /// Whether any finding carries `secret` — used to prove a secret that was
    /// never scanned is absent, without matching on a rendered snippet.
    fn contains_secret(&self, secret: &str) -> bool {
        let hash = secret_hash(secret);
        self.findings
            .iter()
            .any(|finding| finding["secret_hash"] == hash)
    }
}

/// Run a whole scan against `jira_url` and read the report back.
///
/// `tune` adjusts the configuration before the scan; everything the test does
/// not care about stays at its production default, so a test that forgets a
/// flag gets the default behaviour rather than a test-shaped one.
async fn run_scan(jira_url: &str, tune: impl FnOnce(&mut Config)) -> ScanReport {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    let dir = std::env::temp_dir().join(format!(
        "jiraleaks-attachments-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));

    let mut config = Config::test_config(jira_url, "test-token");
    config.report_dir = dir.clone();
    config.format = "json".to_string();
    config.dry_run = false;
    // No findings store: these tests assert on the report, and a store would
    // add a database file per test for nothing.
    config.state_dir = PathBuf::new();
    tune(&mut config);

    let client = JiraClient::new(&config).expect("Jira client");
    let (_, logs) = capturing_logs(async {
        pipeline::run(config, client).await.expect("pipeline run");
    })
    .await;

    let report_path = std::fs::read_dir(&dir)
        .expect("report directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("a JSON report was written");
    let document: Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).expect("report is readable"))
            .expect("report is JSON");
    let _ = std::fs::remove_dir_all(&dir);

    ScanReport {
        scan_run: document["scan_run"].clone(),
        findings: document["findings"].as_array().cloned().unwrap_or_default(),
        logs,
    }
}

/// Collect everything logged while `body` runs.
///
/// A skipped attachment is a *reported* skip: the whole point of the fix is that
/// the operator can tell "nothing suspicious" from "not looked at". The
/// subscriber is installed on the test's own thread, and `#[tokio::test]`'s
/// current-thread runtime keeps every task of the scan there.
async fn capturing_logs<T>(body: impl Future<Output = T>) -> (T, String) {
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Captured(Arc::clone(&buffer)))
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    let guard = tracing::subscriber::set_default(subscriber);
    let output = body.await;
    drop(guard);

    let logs = String::from_utf8_lossy(&buffer.lock().expect("log buffer")).into_owned();
    (output, logs)
}

// ── 1. comments ───────────────────────────────────────────────────────────

/// Regression: the pages after the first were fetched and then dropped, so a
/// secret in comment 21 of an issue was never reported.
#[tokio::test]
async fn comments_after_the_first_page_are_scanned() {
    let server = MockServer::start().await;
    let second_page = token("secondpage");

    // Jira's `comment` field carries the first page (here: one entry) and says
    // how many there are in total.
    mount_search(
        &server,
        json!({
            "summary": "key rotation",
            "comment": {
                "startAt": 0,
                "maxResults": 1,
                "total": 2,
                "comments": [{"id": "1", "body": "nothing to see here"}],
            },
        }),
    )
    .await;
    mount_comments(
        &server,
        1,
        2,
        json!([{"id": "2", "body": format!("GITHUB_TOKEN={second_page}")}]),
    )
    .await;

    let report = run_scan(&server.uri(), |config| {
        config.comments_mode = "all".to_string();
    })
    .await;

    let finding = report
        .finding("comment.comments[1].body", "github_token")
        .expect("the second page's comment must be scanned");
    assert_eq!(finding["source_type"], "comment");
    assert_eq!(report.counter("comments_scanned"), 2);
    assert_eq!(report.counter("errors_total"), 0);

    // The first page is scanned once, not twice: it arrives inside the issue
    // payload, so the paginated fetch must start *after* it, never at 0.
    let requests = server.received_requests().await.unwrap_or_default();
    let comment_requests: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path().ends_with("/comment"))
        .collect();
    assert_eq!(
        comment_requests.len(),
        1,
        "exactly one extra page is needed"
    );
    assert!(comment_requests[0]
        .url
        .query()
        .unwrap_or("")
        .contains("startAt=1"));
}

/// `--comments-mode none` must cost no request, and the first page — which
/// arrives with the issue — must still be counted as scanned.
#[tokio::test]
async fn comments_mode_none_fetches_no_page() {
    let server = MockServer::start().await;
    mount_search(
        &server,
        json!({
            "comment": {
                "startAt": 0,
                "maxResults": 1,
                "total": 5,
                "comments": [{"id": "1", "body": "first page only"}],
            },
        }),
    )
    .await;
    mount_comments(&server, 1, 5, json!([{"id": "2", "body": "never fetched"}])).await;

    let report = run_scan(&server.uri(), |config| {
        config.comments_mode = "none".to_string();
    })
    .await;

    assert_eq!(requests_to(&server, "/rest/api/2/issue").await, 0);
    assert_eq!(report.counter("comments_scanned"), 1);
    assert_eq!(report.counter("errors_total"), 0);
}

// ── 2. attachments ────────────────────────────────────────────────────────

/// Regression: `--scan-attachments` was a no-op flag.
#[tokio::test]
async fn a_text_attachment_is_downloaded_and_scanned() {
    let server = MockServer::start().await;
    let secret = token("envfile");
    let body = format!("AWS_REGION=eu-central-1\nGITHUB_TOKEN={secret}\n");

    mount_search(
        &server,
        json!({
            "attachment": [attachment(
                "10001",
                "prod.env",
                "text/plain",
                body.len() as u64,
                "/secure/attachment/10001/prod.env",
            )],
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/secure/attachment/10001/prod.env"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let report = run_scan(&server.uri(), |config| {
        config.scan_attachments = true;
        config.comments_mode = "none".to_string();
    })
    .await;

    let finding = report
        .finding("attachment[prod.env]", "github_token")
        .expect("the attachment body must be scanned");
    assert_eq!(finding["source_type"], "attachment");
    assert_eq!(report.counter("attachments_scanned"), 1);
    assert_eq!(report.counter("errors_total"), 0);
    assert_eq!(requests_to(&server, "/secure/attachment").await, 1);
}

/// Archives and images are never fetched: an archive's size limit would apply
/// to compressed bytes, and lossy text decoding of a binary produces noise.
#[tokio::test]
async fn archives_and_images_are_not_fetched_at_all() {
    let server = MockServer::start().await;

    mount_search(
        &server,
        json!({
            "attachment": [
                attachment("1", "dump.zip", "application/zip", 1024, "/secure/attachment/1/dump.zip"),
                attachment("2", "image.png", "image/png", 1024, "/secure/attachment/2/image.png"),
                // A text MIME type must not rescue an archive.
                attachment("3", "bundle.tar.gz", "text/plain", 1024, "/secure/attachment/3/bundle.tar.gz"),
            ],
        }),
    )
    .await;

    let report = run_scan(&server.uri(), |config| {
        config.scan_attachments = true;
        config.comments_mode = "none".to_string();
    })
    .await;

    assert_eq!(requests_to(&server, "/secure/attachment").await, 0);
    assert_eq!(report.counter("attachments_scanned"), 0);
    assert!(
        report.findings.is_empty(),
        "no findings from unfetched files"
    );
    assert_eq!(report.counter("errors_total"), 0);
}

/// Regression: the old download read the whole body before checking the size,
/// so a limit of 10 MB allocated 10 MB plus a full copy before truncating.
///
/// A secret at the *start* of an oversized body proves the body was never read:
/// the header check rejects the response before a single byte of it is taken, so
/// a streaming implementation would have reported that secret and this one must
/// not.
#[tokio::test]
async fn a_body_over_the_content_length_limit_is_not_read() {
    let server = MockServer::start().await;
    let secret = token("toobig");
    let mut body = format!("GITHUB_TOKEN={secret}\n").into_bytes();
    body.resize(2 * 1024 * 1024, b'#');

    mount_search(
        &server,
        json!({
            "attachment": [attachment(
                "1",
                "huge.env",
                "text/plain",
                // The payload's declared size lies low, so the download starts
                // and only the response header can stop it.
                1024,
                "/secure/attachment/1/huge.env",
            )],
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/secure/attachment/1/huge.env"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let report = run_scan(&server.uri(), |config| {
        config.scan_attachments = true;
        config.max_attachment_size_mb = 1;
        config.comments_mode = "none".to_string();
    })
    .await;

    assert_eq!(requests_to(&server, "/secure/attachment").await, 1);
    assert!(
        !report.contains_secret(&secret),
        "the body must not be read"
    );
    assert_eq!(report.counter("attachments_scanned"), 0);
    // A refused attachment is not a failed issue.
    assert_eq!(report.counter("errors_total"), 0);
    assert!(
        report.logs.contains("over the"),
        "the refusal must be logged, not swallowed: {}",
        report.logs
    );
}

/// A body that declares no length at all: the limit must cut the read, the head
/// must still be scanned, and the tail must not be reached.
#[tokio::test]
async fn a_chunked_body_is_cut_at_the_limit() {
    let head_secret = token("headsecret");
    let tail_secret = token("tailsecret");

    let mut body = format!("GITHUB_TOKEN={head_secret}\n").into_bytes();
    body.resize(1_500_000, b'#');
    body.extend_from_slice(format!("\nGITHUB_TOKEN={tail_secret}\n").as_bytes());
    body.resize(3 * 1024 * 1024, b'#');

    // The attachment URL is absolute here, and must still be the Jira origin —
    // which is why the payload is built from the address the server actually
    // bound.
    let jira = ChunkedJira::start(body, |uri| {
        json!({
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
            "issues": [issue(json!({
                "attachment": [attachment(
                    "1",
                    "big.log",
                    "text/plain",
                    // The declared size is what the payload claims and stays
                    // under the limit, so the download starts; the body is
                    // what is really 3 MiB, with no length announced.
                    1024,
                    format!("{uri}/secure/attachment/1/big.log"),
                )],
            }))],
        })
    })
    .await;

    let report = run_scan(&jira.uri, |config| {
        config.scan_attachments = true;
        config.max_attachment_size_mb = 1;
        config.comments_mode = "none".to_string();
    })
    .await;

    assert!(
        report
            .finding("attachment[big.log]", "github_token")
            .is_some(),
        "the head of the body is within the limit and must be scanned"
    );
    assert!(
        !report.contains_secret(&tail_secret),
        "the tail is past the limit and must never be read"
    );
    assert_eq!(report.counter("attachments_scanned"), 1);
    assert_eq!(report.counter("errors_total"), 0);
    assert!(
        report.logs.contains("truncated at the size limit"),
        "a cut body must be reported: {}",
        report.logs
    );
}

/// A `content` URL is attacker-controlled. One that leaves the Jira origin must
/// cost a warning, never a request — and never the issue's other findings.
#[tokio::test]
async fn a_foreign_content_url_is_skipped_with_a_warning() {
    let server = MockServer::start().await;
    let secret = token("realattach");

    mount_search(
        &server,
        json!({
            "attachment": [
                // Absolute URL on another host.
                attachment("1", "steal.env", "text/plain", 32, "http://evil.invalid/steal.env"),
                // Protocol-relative: `Url::join` would replace the authority.
                attachment("2", "proto.env", "text/plain", 32, "//evil.invalid/proto.env"),
                // The one attachment that is really ours.
                attachment("3", "real.env", "text/plain", 64, "/secure/attachment/3/real.env"),
            ],
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/secure/attachment/3/real.env"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("GITHUB_TOKEN={secret}\n")),
        )
        .mount(&server)
        .await;

    let report = run_scan(&server.uri(), |config| {
        config.scan_attachments = true;
        config.comments_mode = "none".to_string();
    })
    .await;

    assert!(report
        .finding("attachment[real.env]", "github_token")
        .is_some());
    assert!(!report.has_path("attachment[steal.env]"));
    assert!(!report.has_path("attachment[proto.env]"));
    assert_eq!(requests_to(&server, "/secure/attachment").await, 1);
    assert_eq!(report.counter("attachments_scanned"), 1);
    // The hostile URLs must not fail the issue they arrived in.
    assert_eq!(report.counter("errors_total"), 0);
    assert!(
        report.logs.contains("outside the configured Jira origin"),
        "the skip must be visible in the log: {}",
        report.logs
    );
}

/// `--scan-attachments` is off by default: then nothing is requested, whatever
/// the issue carries.
#[tokio::test]
async fn attachments_disabled_make_no_request() {
    let server = MockServer::start().await;

    mount_search(
        &server,
        json!({
            "attachment": [attachment(
                "1",
                "prod.env",
                "text/plain",
                64,
                "/secure/attachment/1/prod.env",
            )],
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/secure/attachment/1/prod.env"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("GITHUB_TOKEN=ghp_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"),
        )
        .mount(&server)
        .await;

    let report = run_scan(&server.uri(), |config| {
        // The default, spelled out: this test is about the default being off.
        config.scan_attachments = false;
        config.comments_mode = "none".to_string();
    })
    .await;

    assert_eq!(requests_to(&server, "/secure/attachment").await, 0);
    assert_eq!(report.counter("attachments_scanned"), 0);
    assert!(report.findings.is_empty());
}

/// The counters are the scan's claim about its own coverage, so they are read
/// back from the report a scan wrote: one comment from the payload, one from the
/// second page, one attachment.
#[tokio::test]
async fn counters_report_what_was_scanned() {
    let server = MockServer::start().await;
    let attachment_secret = token("countattach");
    let comment_secret = token("countcomment");
    let body = format!("GITHUB_TOKEN={attachment_secret}\n");

    mount_search(
        &server,
        json!({
            "comment": {
                "startAt": 0,
                "maxResults": 1,
                "total": 2,
                "comments": [{"id": "1", "body": "first page"}],
            },
            "attachment": [attachment(
                "1",
                "counts.env",
                "text/plain",
                body.len() as u64,
                "/secure/attachment/1/counts.env",
            )],
        }),
    )
    .await;
    mount_comments(
        &server,
        1,
        2,
        json!([{"id": "2", "body": format!("GITHUB_TOKEN={comment_secret}")}]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/secure/attachment/1/counts.env"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let report = run_scan(&server.uri(), |config| {
        config.scan_attachments = true;
        config.comments_mode = "all".to_string();
    })
    .await;

    assert_eq!(report.counter("comments_scanned"), 2);
    assert_eq!(report.counter("attachments_scanned"), 1);
    assert_eq!(report.counter("issues_scanned"), 1);
    assert_eq!(report.counter("errors_total"), 0);
    assert!(report.contains_secret(&attachment_secret));
    assert!(report.contains_secret(&comment_secret));
}

// ── the one response shape wiremock cannot produce ────────────────────────

/// A Jira that answers with `Transfer-Encoding: chunked` and no
/// `Content-Length`, which is what a reverse proxy in front of a large
/// attachment produces. `wiremock` cannot express it — it always knows its
/// body's length and sends it — and without it the streaming limit is untested:
/// the header check alone would pass every wiremock case.
///
/// One request per connection (`Connection: close`), so dispatching on the
/// request line is all the parsing this needs.
struct ChunkedJira {
    uri: String,
}

impl ChunkedJira {
    /// Serve `search(uri)` at `/rest/api/2/search` and `attachment` at every
    /// other path.
    async fn start(attachment: Vec<u8>, search: impl FnOnce(&str) -> Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind a port");
        let uri = format!(
            "http://{}",
            listener.local_addr().expect("the bound address")
        );
        let search = search(&uri).to_string();

        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let search = search.clone();
                let attachment = attachment.clone();
                tokio::spawn(async move {
                    // A client that stops reading at its limit closes the
                    // connection under us; that is the expected outcome here,
                    // not a failure.
                    let _ = answer(socket, &search, &attachment).await;
                });
            }
        });

        Self { uri }
    }
}

/// Answer one request on `socket`: the search payload, or the chunked body.
async fn answer(mut socket: TcpStream, search: &str, attachment: &[u8]) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 64 * 1024 {
            return Ok(()); // not a request head we understand
        }
    }

    let head = String::from_utf8_lossy(&request);
    let target = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();

    if target.starts_with("/rest/api/2/search") {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{search}",
            search.len()
        );
        socket.write_all(response.as_bytes()).await?;
    } else {
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await?;
        for chunk in attachment.chunks(64 * 1024) {
            socket
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await?;
            socket.write_all(chunk).await?;
            socket.write_all(b"\r\n").await?;
        }
        socket.write_all(b"0\r\n\r\n").await?;
    }

    Ok(())
}
