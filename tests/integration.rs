use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use jiraleaks::config::Config;

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

#[tokio::test]
async fn test_401_returns_jira_access_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let config = Config::test_config(&server.uri(), "test-token");
    let client =
        jiraleaks::jira::client::JiraClient::new(&config).expect("Failed to create client");
    let result = client.server_info().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_429_with_retry_after() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/api/2/serverInfo"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
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
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let config = Config::test_config(&server.uri(), "test-token");
    let client =
        jiraleaks::jira::client::JiraClient::new(&config).expect("Failed to create client");
    let result = client.server_info().await;

    assert!(result.is_ok(), "Expected success after retry: {result:?}");
}
