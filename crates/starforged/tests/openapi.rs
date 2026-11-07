//! The OpenAPI 3.1 document: served at `GET /api/v1/openapi.json`,
//! it documents every route registered in `starforged_api::router`
//! (enumerated from `lib.rs` below), references the shared error
//! envelope, and declares bearer-token security.

mod common;

use common::*;
use serde_json::Value;
use std::collections::HashSet;

/// The (method, full `/api/v1` path) pairs registered in
/// `starforged_api::router`, mechanically scanned out of `lib.rs` so the
/// spec and `ROUTES` are both checked against the router itself. Scans
/// each `.route("<path>", <method>(handler)…)` registration and collects
/// the method calls chained onto its path.
fn router_routes() -> Vec<(&'static str, String)> {
    let src = include_str!("../../starforged-api/src/lib.rs");
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(start) = rest.find(".route(") {
        let after = &rest[start + ".route(".len()..];
        let q1 = after.find('"').expect("route path literal");
        let q2 = after[q1 + 1..].find('"').expect("route path literal end");
        let path = &after[q1 + 1..q1 + 1 + q2];
        let next = after.find(".route(").unwrap_or(usize::MAX);
        let fallback = after.find(".fallback(").unwrap_or(usize::MAX);
        let region = &after[..next.min(fallback).min(after.len())];
        for method in ["get", "post", "put", "patch", "delete"] {
            let mut found = false;
            let mut hay = region;
            while let Some(i) = hay.find(method) {
                let before_ok = i == 0 || {
                    let b = hay.as_bytes()[i - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                let after_ok = hay[i + method.len()..].starts_with('(');
                if before_ok && after_ok {
                    found = true;
                    break;
                }
                hay = &hay[i + 1..];
            }
            if found {
                out.push((method, format!("/api/v1{path}")));
            }
        }
        rest = &after[region.len()..];
    }
    out
}

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
    ("post", "/api/v1/oauth/revoke"),
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
    (
        "post",
        "/api/v1/repos/{owner}/{repo}/runners/registration-token",
    ),
    ("get", "/api/v1/repos/{owner}/{repo}/runners"),
    ("post", "/api/v1/runners/register"),
    ("delete", "/api/v1/runners/{id}"),
    ("post", "/api/v1/runners/jobs/request"),
    ("patch", "/api/v1/runners/jobs/{id}/trace"),
    ("post", "/api/v1/runners/jobs/{id}/heartbeat"),
    ("put", "/api/v1/runners/jobs/{id}"),
    ("post", "/api/v1/ci/jobs/{id}/git-credential"),
    ("post", "/api/v1/repos/{owner}/{repo}/ci/runs/{id}/cancel"),
    ("get", "/api/v1/repos/{owner}/{repo}/ci/runs"),
    ("post", "/api/v1/repos/{owner}/{repo}/ci/runs"),
    ("get", "/api/v1/repos/{owner}/{repo}/ci/runs/{id}"),
    ("post", "/api/v1/runners/jobs/{id}/artifacts/authorize"),
    ("put", "/api/v1/runners/jobs/{id}/artifacts/{*name}"),
    ("get", "/api/v1/runners/jobs/{id}/artifacts/{*name}"),
    ("post", "/api/v1/runners/jobs/{id}/secrets"),
    ("get", "/api/v1/repos/{owner}/{repo}/ci/secrets"),
    ("post", "/api/v1/repos/{owner}/{repo}/ci/secrets"),
    ("delete", "/api/v1/repos/{owner}/{repo}/ci/secrets/{name}"),
    ("post", "/api/v1/sandboxes"),
    ("get", "/api/v1/sandboxes/runtimes"),
    ("get", "/api/v1/sandboxes/{id}"),
    ("delete", "/api/v1/sandboxes/{id}"),
    ("post", "/api/v1/sandboxes/{id}/pause"),
    ("post", "/api/v1/sandboxes/{id}/resume"),
    ("post", "/api/v1/sandboxes/{id}/timeout"),
    ("post", "/api/v1/sandboxes/{id}/exec"),
    ("get", "/api/v1/sandboxes/{id}/files"),
    ("put", "/api/v1/sandboxes/{id}/files"),
    ("delete", "/api/v1/sandboxes/{id}/files"),
    ("get", "/api/v1/sandboxes/{id}/ports/{port}/url"),
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
    // The maintained list equals the router's registrations, and the spec
    // has no speculative extras either.
    let from_router: HashSet<(&str, String)> = router_routes().into_iter().collect();
    assert_eq!(
        from_router.len(),
        router_routes().len(),
        "duplicate router registrations"
    );
    let from_list: HashSet<(&str, String)> =
        ROUTES.iter().map(|(m, p)| (*m, (*p).to_string())).collect();
    assert_eq!(
        from_list, from_router,
        "ROUTES must match the router's registrations in lib.rs"
    );
    for path in paths.keys() {
        assert!(
            from_router.iter().any(|(_, p)| p == path),
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

    // Anonymous callers are allowed where the handler uses `reader()`
    // (`search` routes): an empty security requirement alongside bearer_auth.
    let optional = paths["/api/v1/search/trails"]["get"]["security"]
        .as_array()
        .expect("security requirements");
    assert!(
        optional
            .iter()
            .any(|r| r.as_object().is_some_and(|o| o.is_empty())),
        "GET /api/v1/search/trails allows anonymous callers: {optional:?}"
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

/// Routes whose handler authenticates with `auth.reader()` (anonymous
/// callers allowed) must declare optional security (`security((), …)`);
/// every other authenticated route must require the bearer token.
/// Mechanically scanned from the handler bodies and their `#[utoipa::path]`
/// annotations in `starforged-api`'s sources.
#[test]
fn security_optionality_matches_auth() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../starforged-api/src");
    let mut checked = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("api sources") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        if !src.contains("utoipa::path") {
            continue;
        }
        let file = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        let fns: Vec<usize> = src.match_indices("pub async fn ").map(|(i, _)| i).collect();
        for (k, &start) in fns.iter().enumerate() {
            let body_end = fns
                .get(k + 1)
                .copied()
                .or_else(|| {
                    ["\nfn ", "\nasync fn "]
                        .iter()
                        .filter_map(|m| src[start + 1..].find(m).map(|i| start + 1 + i))
                        .min()
                })
                .unwrap_or(src.len());
            let name = src[start + "pub async fn ".len()..]
                .split('(')
                .next()
                .expect("handler name");
            let region_start = if k == 0 { 0 } else { fns[k - 1] };
            let annotation = src[region_start..start].rfind("#[utoipa::path(");
            let Some(attr) = annotation else {
                panic!("{file}::{name} has no #[utoipa::path]");
            };
            let annotation = &src[region_start + attr..start];
            let optional = annotation.contains("security((),");
            let required = annotation.contains("security((\"bearer_auth\"");
            let uses_reader = src[start..body_end].contains(".reader()");
            // Public endpoints (OAuth device flow, the spec itself) declare
            // no security requirement at all.
            if !optional && !required {
                assert!(
                    matches!(
                        name,
                        "device_code" | "token" | "revoke" | "openapi_json" | "register_runner"
                    ),
                    "{file}::{name} declares no security requirement"
                );
                assert!(
                    !uses_reader,
                    "{file}::{name} uses reader() but declares no security"
                );
                continue;
            }
            assert_eq!(
                optional, uses_reader,
                "{file}::{name}: reader()={uses_reader} must match optional={optional}"
            );
            checked.push((file.clone(), name.to_string()));
        }
    }
    assert!(!checked.is_empty(), "sweep checked handlers");
}
