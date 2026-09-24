//! Jira client contract: connectivity, pagination, auth failures and the retry
//! policy — asserted against a mocked Jira over real HTTP.
//!
//! Two properties here are not observable from a report and would otherwise be
//! taken on faith:
//!
//! * an authentication failure is **not** retried — a wrong token must fail
//!   fast, not after three attempts and a backoff;
//! * a `429` **is** retried, exactly once here, and the `Retry-After` the server
//!   asked for is what the client waits — asserted on the virtual clock and on
//!   the number of requests the mock actually received, not on the fact that the
//!   call eventually succeeded.
//!
//! The time is real, and no test sleeps: the retry delay comes from the mock's
//! `Retry-After: 0`, so the whole suite finishes in milliseconds while still
//! proving how many attempts each path took. Pausing the clock — the usual way
//! to make a retry test instant — is not an option here, because it advances
//! past the client's own request timeout and turns every round trip into a
//! network error.

use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use jiraleaks::config::Config;
use jiraleaks::error::ScannerError;
use jiraleaks::jira::client::JiraClient;

/// The statuses that mean "your credentials are wrong". Both are permanent for
/// a given token, so neither may be retried.
const AUTH_FAILURES: &[u16] = &[401, 403];

#[tokio::test]
async fn test_server_info_ok() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "baseUrl": server.uri(),
            "version": "9.12.37",
            "deploymentType": "Server",
            "serverTitle": "Test Jira"
        })))
        .mount(&server)
        .await;

    let config = Config::test_config(&server.uri(), "test-token");
    let client =
        jiraleaks::jira::client::JiraClient::new(&config).expect("Failed to create client");
    let info = client.server_info().await.expect("server_info failed");

    assert_eq!(info.version, "9.12.37");
    assert_eq!(info.deployment_type, "Server");
}

#[tokio::test]
async fn test_search_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .and(query_param("startAt", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "total": 3,
            "startAt": 0,
            "maxResults": 50,
            "issues": [
                {"id": "1", "key": "TEST-1", "fields": {}},
                {"id": "2", "key": "TEST-2", "fields": {}}
            ]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .and(query_param("startAt", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "total": 3,
            "startAt": 50,
            "maxResults": 50,
            "issues": [
                {"id": "3", "key": "TEST-3", "fields": {}}
            ]
        })))
        .mount(&server)
        .await;

    let config = Config::test_config(&server.uri(), "test-token");
    let client =
        jiraleaks::jira::client::JiraClient::new(&config).expect("Failed to create client");

    let page1 = client
        .search("project = TEST", 0, 50, &["summary".into()])
        .await
        .expect("search page 1 failed");
    assert_eq!(page1.issues.len(), 2);
    assert_eq!(page1.total, 3);

    let page2 = client
        .search("project = TEST", 50, 50, &["summary".into()])
        .await
        .expect("search page 2 failed");
    assert_eq!(page2.issues.len(), 1);
}

/// An auth failure is reported as [`ScannerError::JiraAccess`] — the variant the
/// process maps to exit code 2 — with the status in the message, and it is asked
/// for exactly once.
#[tokio::test]
async fn auth_failures_are_jira_access_errors_and_are_not_retried() {
    for status in AUTH_FAILURES {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/2/serverInfo"))
            .respond_with(ResponseTemplate::new(*status))
            .mount(&server)
            .await;

        let config = Config::test_config(&server.uri(), "test-token");
        let client = JiraClient::new(&config).expect("Failed to create client");
        let error = client
            .server_info()
            .await
            .expect_err("a {status} response must not succeed");

        assert!(
            matches!(error, ScannerError::JiraAccess(_)),
            "HTTP {status} produced {error:?}, expected JiraAccess"
        );
        assert_eq!(error.exit_code(), 2, "HTTP {status}");
        assert!(
            error.to_string().contains("Auth failure"),
            "the message must say what failed: {error}"
        );
        assert!(
            error.to_string().contains(&status.to_string()),
            "the message must carry the status: {error}"
        );

        // No retry: a wrong token is not transient, and retrying it only delays
        // the diagnosis.
        let requests = received_requests(&server).await;
        assert_eq!(
            requests.len(),
            1,
            "HTTP {status} was requested {} times, expected exactly one",
            requests.len()
        );
    }
}

/// A `429` is retried, and the wait is the server's `Retry-After`, not the
/// client's own 500 ms backoff.
///
/// The mock answers `Retry-After: 0` on purpose. A real one-second header would
/// make this test sleep for a second, and pausing the clock — the usual cure for
/// that — is not available here: it breaks the real HTTP round trip by advancing
/// past the client's own request timeout. A zero delay keeps the test instant
/// *and* keeps the assertion exact: if the client ignored the header and used
/// its backoff, the run below would take at least 500 ms.
#[tokio::test]
async fn a_rate_limited_request_is_retried_after_the_declared_delay() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "baseUrl": server.uri(),
            "version": "9.0.0",
            "deploymentType": "Server",
            "serverTitle": "OK"
        })))
        .mount(&server)
        .await;

    let config = Config::test_config(&server.uri(), "test-token");
    let client = JiraClient::new(&config).expect("Failed to create client");

    let started = std::time::Instant::now();
    let result = client.server_info().await;
    let elapsed = started.elapsed();

    assert!(result.is_ok(), "Expected success after retry: {result:?}");
    // The retry happened: the mock was asked twice, and the second answer is the
    // one the client returned.
    let requests = received_requests(&server).await;
    assert_eq!(
        requests.len(),
        2,
        "the client must retry a 429 exactly once here, got {} requests",
        requests.len()
    );
    assert_eq!(
        result.expect("checked above").version,
        "9.0.0",
        "the retried response is not the one that was returned"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(400),
        "the client waited {elapsed:?}: the mock asked for no delay, so this is the \
         client's own backoff, not the Retry-After header"
    );
}

/// The retry budget is finite. A server that stays rate limited must not keep
/// the scan going: after the third attempt the client gives up with a
/// [`ScannerError::JiraAccess`] naming the rate limit, so the process exits with
/// code 2 instead of waiting forever.
///
/// `Retry-After: 0` keeps the three attempts instant; the mock's request log is
/// what proves there were exactly three.
#[tokio::test]
async fn an_endless_rate_limit_stops_after_three_attempts() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .mount(&server)
        .await;

    let config = Config::test_config(&server.uri(), "test-token");
    let client = JiraClient::new(&config).expect("Failed to create client");

    let error = client
        .server_info()
        .await
        .expect_err("a permanent 429 must fail");

    assert!(
        matches!(error, ScannerError::JiraAccess(_)),
        "expected JiraAccess, got {error:?}"
    );
    assert_eq!(error.exit_code(), 2, "the rate limit maps to the Jira code");
    assert!(
        error.to_string().contains("Rate limit exhausted"),
        "the message must say the rate limit was exhausted: {error}"
    );
    let requests = received_requests(&server).await;
    assert_eq!(
        requests.len(),
        3,
        "the retry budget is three attempts, got {} requests",
        requests.len()
    );
}

/// Every request the mock received, in order.
async fn received_requests(server: &MockServer) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .expect("the mock server records what it receives")
}
