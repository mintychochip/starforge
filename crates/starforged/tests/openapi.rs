//! The OpenAPI 3.1 document: served at `GET /api/v1/openapi.json`,
//! it documents every route registered in `starforged_api::router`
//! (enumerated from `lib.rs` below), references the shared error
//! envelope, and declares bearer-token security.

mod common;

use common::*;
use serde_json::Value;

const ROUTES: &[(&str, &str)] = &[
    ("get", "/api/v1/openapi.json"),
    ("get", "/api/v1/admin/audit"),
    ("get", "/api/v1/user"),
    ("post", "/api/v1/user/repos"),
    ("get", "/api/v1/user/keys"),
    ("post", "/api/v1/user/keys"),
    ("delete", "/api/v1/user/keys/{id}"),
    ("post", "/api/v1/orgs"),
    ("get", "/api/v1/orgs/{org}"),
    ("patch", "/api/v1/orgs/{org}"),
    ("delete", "/api/v1/orgs/{org}"),
    ("get", "/api/v1/orgs/{org}/repos"),
    ("post", "/api/v1/orgs/{org}/repos"),
    ("get", "/api/v1/orgs/{org}/teams"),
    ("post", "/api/v1/orgs/{org}/teams"),
    ("get", "/api/v1/orgs/{org}/teams/{team}"),
    ("patch", "/api/v1/orgs/{org}/teams/{team}"),
    ("delete", "/api/v1/orgs/{org}/teams/{team}"),
    ("get", "/api/v1/orgs/{org}/teams/{team}/members"),
    ("put", "/api/v1/orgs/{org}/teams/{team}/members/{handle}"),
    ("delete", "/api/v1/orgs/{org}/teams/{team}/members/{handle}"),
    ("get", "/api/v1/orgs/{org}/teams/{team}/repos"),
    ("put", "/api/v1/orgs/{org}/teams/{team}/repos/{repo}"),
    ("delete", "/api/v1/orgs/{org}/teams/{team}/repos/{repo}"),
    ("get", "/api/v1/orgs/{org}/members"),
    ("put", "/api/v1/orgs/{org}/members/{handle}"),
    ("delete", "/api/v1/orgs/{org}/members/{handle}"),
    ("get", "/api/v1/search/trails"),
    ("get", "/api/v1/search/sessions"),
    ("get", "/api/v1/repos/{owner}/{repo}/search/code"),
    ("post", "/api/v1/oauth/device/code"),
    ("post", "/api/v1/oauth/token"),
    ("get", "/api/v1/repos/{owner}/{repo}"),
    ("patch", "/api/v1/repos/{owner}/{repo}"),
    ("get", "/api/v1/repos/{owner}/{repo}/collaborators"),
    ("put", "/api/v1/repos/{owner}/{repo}/collaborators/{handle}"),
    (
        "delete",
        "/api/v1/repos/{owner}/{repo}/collaborators/{handle}",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/keys"),
    ("post", "/api/v1/repos/{owner}/{repo}/keys"),
    ("delete", "/api/v1/repos/{owner}/{repo}/keys/{id}"),
    ("post", "/api/v1/repos/{owner}/{repo}/transfer"),
    ("get", "/api/v1/repos/{owner}/{repo}/import"),
    ("delete", "/api/v1/repos/{owner}/{repo}/import"),
    ("post", "/api/v1/repos/{owner}/{repo}/import/start"),
    ("post", "/api/v1/repos/{owner}/{repo}/import/github"),
    ("get", "/api/v1/repos/{owner}/{repo}/import/github"),
    ("put", "/api/v1/repos/{owner}/{repo}/mirror/pull"),
    ("get", "/api/v1/repos/{owner}/{repo}/mirror/pull"),
    ("delete", "/api/v1/repos/{owner}/{repo}/mirror/pull"),
    ("post", "/api/v1/repos/{owner}/{repo}/mirror/pull/sync"),
    ("post", "/api/v1/repos/{owner}/{repo}/mirror/push"),
    ("get", "/api/v1/repos/{owner}/{repo}/mirror/push"),
    ("delete", "/api/v1/repos/{owner}/{repo}/mirror/push/{id}"),
    ("post", "/api/v1/repos/{owner}/{repo}/mirror/push/{id}/sync"),
    ("post", "/api/v1/repos/{owner}/{repo}/mirror/pull/enabled"),
    ("put", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}"),
    ("get", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}"),
    ("delete", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}"),
    ("get", "/api/v1/repos/{owner}/{repo}/sessions"),
    (
        "put",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/complete",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/events"),
    ("post", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/links"),
    ("get", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/links"),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/release",
    ),
    ("post", "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/purge"),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/publish",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/unpublish",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/rescan",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/trails"),
    ("post", "/api/v1/repos/{owner}/{repo}/trails"),
    ("get", "/api/v1/repos/{owner}/{repo}/trails/{n}"),
    ("patch", "/api/v1/repos/{owner}/{repo}/trails/{n}"),
    ("get", "/api/v1/repos/{owner}/{repo}/trails/{n}/comments"),
    ("post", "/api/v1/repos/{owner}/{repo}/trails/{n}/comments"),
    (
        "patch",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/comments/{id}",
    ),
    ("post", "/api/v1/repos/{owner}/{repo}/trails/{n}/labels"),
    ("delete", "/api/v1/repos/{owner}/{repo}/trails/{n}/labels"),
    ("post", "/api/v1/repos/{owner}/{repo}/trails/{n}/assignees"),
    (
        "delete",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/assignees",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/review-requests",
    ),
    (
        "delete",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/review-requests",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/trails/{n}/sessions"),
    ("post", "/api/v1/repos/{owner}/{repo}/trails/{n}/sessions"),
    (
        "delete",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/sessions/{ulid}",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/changes"),
    ("get", "/api/v1/repos/{owner}/{repo}/trails/{n}/changes"),
    ("post", "/api/v1/repos/{owner}/{repo}/trails/{n}/changes"),
    ("get", "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}"),
    (
        "patch",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/state",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/diff",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/revisions",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/revisions/{r}",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews/pending",
    ),
    (
        "delete",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews/pending",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/reviews/{id}/dismiss",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/resolve",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/threads/{t}/comments",
    ),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/gates",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/trails/{n}/changes/{k}/merge",
    ),
    ("post", "/api/v1/repos/{owner}/{repo}/statuses/{sha}"),
    ("get", "/api/v1/repos/{owner}/{repo}/statuses/{sha}"),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/commits/{reference}/status",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/hooks"),
    ("post", "/api/v1/repos/{owner}/{repo}/hooks"),
    ("patch", "/api/v1/repos/{owner}/{repo}/hooks/{id}"),
    ("delete", "/api/v1/repos/{owner}/{repo}/hooks/{id}"),
    ("get", "/api/v1/repos/{owner}/{repo}/hooks/{id}/deliveries"),
    (
        "get",
        "/api/v1/repos/{owner}/{repo}/hooks/{id}/deliveries/{row}",
    ),
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/hooks/{id}/deliveries/{row}/redeliver",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/gate-rules"),
    ("post", "/api/v1/repos/{owner}/{repo}/gate-rules"),
    ("patch", "/api/v1/repos/{owner}/{repo}/gate-rules/{id}"),
    ("delete", "/api/v1/repos/{owner}/{repo}/gate-rules/{id}"),
    ("get", "/api/v1/repos/{owner}/{repo}/tag-protections"),
    ("post", "/api/v1/repos/{owner}/{repo}/tag-protections"),
    (
        "delete",
        "/api/v1/repos/{owner}/{repo}/tag-protections/{id}",
    ),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openapi_document_is_valid_complete_and_stable() {
    let s = TestServer::start().await;
    let client = s.browser();
    let url = s.url("/api/v1/openapi.json");

    // Served unauthenticated (the document reveals no data).
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();

    // Valid JSON with the OpenAPI 3.1 structural fields.
    let doc: Value = serde_json::from_str(&body).expect("spec is JSON");
    assert!(
        doc["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.1.")),
        "openapi version must be 3.1.x: {}",
        doc["openapi"]
    );
    assert_eq!(doc["info"]["title"], "Starforge API");
    assert!(doc["info"]["version"].is_string());
    let paths = doc["paths"].as_object().expect("paths object");
    let schemas = doc["components"]["schemas"]
        .as_object()
        .expect("schemas object");

    // Stable across requests (generated at startup and cached).
    let again = client.get(&url).send().await.unwrap().text().await.unwrap();
    assert_eq!(body, again, "spec must be stable across requests");

    // Every registered method+path appears in `paths`.
    for (method, path) in ROUTES {
        let op = &paths[*path];

        assert!(
            op[method].is_object(),
            "{method} {path} missing from the spec"
        );
    }
    // No speculative extras: every spec path is a registered route.
    for path in paths.keys() {
        assert!(
            ROUTES.iter().any(|(_, p)| p == path),
            "spec path {path} is not a registered route"
        );
    }

    // The shared error envelope is defined and referenced by error responses.
    assert!(
        schemas.contains_key("ApiErrorBody"),
        "ApiErrorBody in components"
    );
    assert!(
        schemas.contains_key("ApiErrorDetail"),
        "ApiErrorDetail in components"
    );
    let envelope = &schemas["ApiErrorDetail"]["properties"]["error"];
    assert!(
        schemas["ApiErrorBody"]["properties"]["error"].is_object(),
        "error envelope exposed: {envelope}"
    );
    let unauthenticated = &paths["/api/v1/user"]["get"]["responses"]["401"]["content"]["application/json"]
        ["schema"]["$ref"];
    assert_eq!(unauthenticated, "#/components/schemas/ApiErrorBody");

    // Bearer auth is declared: the scheme is HTTP bearer and authenticated
    // operations carry it.
    let scheme = &doc["components"]["securitySchemes"]["bearer_auth"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");
    let security = paths["/api/v1/user"]["get"]["security"]
        .as_array()
        .expect("security requirements");
    assert!(
        security.iter().any(|r| r["bearer_auth"].is_array()),
        "GET /api/v1/user requires bearer_auth: {security:?}"
    );

    // DTO schemas are present (one named schema per DTO).
    for name in [
        "UserJson",
        "RepoJson",
        "CreateRepoBody",
        "OrgJson",
        "TeamJson",
        "TrailJson",
        "TrailDetailJson",
        "ChangeJson",
        "CreateChangeBody",
        "SubmitReviewBody",
        "StatusJson",
        "WebhookJson",
        "CreateHookBody",
        "GateRuleJson",
        "TagProtectionJson",
        "GithubImportJson",
        "KeyJson",
        "ImportJson",
        "PullMirrorJson",
        "PushMirrorJson",
    ] {
        assert!(schemas.contains_key(name), "schema {name} in components");
    }
}
