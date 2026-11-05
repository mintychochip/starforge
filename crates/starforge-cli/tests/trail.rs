//! J3: `trail list/show/create/comment` against an in-process stub.
//!
//! The stub asserts exact paths, query strings, request bodies, and the
//! `Authorization: Bearer` header; the CLI handlers are called in-process
//! through the library seam.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde_json::{Value, json};

use starforge_cli::api::ApiClient;
use starforge_cli::commands::trail::read::{ListArgs, list, show};
use starforge_cli::commands::trail::write::{comment, create};
use starforge_cli::commands::trail::{Format, TrailCtx};

const TOKEN: &str = "test-token";

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
    auth: Option<String>,
}

struct App {
    recorded: Mutex<Vec<Recorded>>,
    /// (method, path) -> (status, body).
    routes: HashMap<(String, String), (u16, Value)>,
}

async fn handle(
    axum::extract::State(app): axum::extract::State<Arc<App>>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let method = req.method().to_string();
    let uri: Uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let headers: &HeaderMap = req.headers();
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default()
        .to_vec();
    app.recorded.lock().unwrap().push(Recorded {
        method: method.clone(),
        path: path.clone(),
        query,
        body,
        auth,
    });
    match app.routes.get(&(method, path)) {
        Some((status, value)) => (
            StatusCode::from_u16(*status).unwrap(),
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string(value).unwrap(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": {"code": "not_found", "message": "not found", "details": null}})),
        )
            .into_response(),
    }
}

async fn start(routes: Vec<(&str, &str, u16, Value)>) -> (String, Arc<App>) {
    let app = Arc::new(App {
        recorded: Mutex::new(Vec::new()),
        routes: routes
            .into_iter()
            .map(|(m, p, s, v)| ((m.to_string(), p.to_string()), (s, v)))
            .collect(),
    });
    let router = Router::new().fallback(handle).with_state(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{addr}"), app)
}

fn ctx_for(base: &str) -> TrailCtx {
    let api = ApiClient::new(base, "o/r", TOKEN).unwrap();
    TrailCtx::new(
        api,
        std::path::Path::new("/tmp/cli-trail-stub"),
        Some("origin"),
        Vec::new(),
    )
}

fn query_pairs(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn trail_detail() -> Value {
    json!({
        "number": 12,
        "title": "Fix the thing",
        "intent": "Make it work.",
        "state": "open",
        "ready": true,
        "author": "alice",
        "author_id": 1,
        "labels": ["bug"],
        "assignees": ["bob"],
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-02T00:00:00Z",
        "closed_at": null,
        "merged_at": null,
        "comments": [
            {"id": 7, "author": "alice", "author_id": 1, "body": "Looks good.",
             "created_at": "2026-10-03T00:00:00Z", "edited_at": null}
        ],
        "timeline": []
    })
}

fn change_row() -> Value {
    json!({
        "trail": 12, "k": 1, "kind": "branch",
        "head_branch": "feature/x", "base_branch": "main",
        "current_revision": 2, "state": "open", "creator": "alice",
        "mergeability": "mergeable", "conflict_paths": [],
        "allowed_methods": ["merge"],
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-02T00:00:00Z"
    })
}

const HEAD_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn change_detail() -> Value {
    json!({
        "change": change_row(),
        "revisions": [
            {"r": 2, "head_sha": HEAD_SHA, "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "merge_base": null, "pusher": "alice",
             "created_at": "2026-10-02T00:00:00Z",
             "mergeability": "mergeable", "conflict_paths": []}
        ],
        "selected": {"r": 2, "head_sha": HEAD_SHA, "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             "merge_base": null, "pusher": "alice",
             "created_at": "2026-10-02T00:00:00Z",
             "mergeability": "mergeable", "conflict_paths": []},
        "files": [],
        "truncated": false,
        "reviews": [],
        "threads": [],
        "gates": {"passed": false, "results": [
            {"rule": "approval", "passed": false, "reason": "needs 1 more approval"}
        ]},
        "can_review": true,
        "can_triage": false,
        "can_close": false
    })
}

fn combined_status() -> Value {
    json!({
        "sha": HEAD_SHA,
        "state": "success",
        "total_count": 1,
        "statuses": [
            {"sha": HEAD_SHA, "context": "ci", "state": "success",
             "target_url": null, "description": null, "creator": "alice",
             "created_at": "2026-10-02T00:00:00Z", "updated_at": "2026-10-02T00:00:00Z"}
        ]
    })
}

fn default_list_args() -> ListArgs {
    ListArgs {
        state: "open".to_string(),
        label: None,
        assignee: None,
        author: None,
        limit: 30,
        after: None,
    }
}

#[tokio::test]
async fn list_renders_rows_and_more() {
    let (base, app) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        200,
        json!({
            "trails": [
                {"number": 1, "title": "First", "state": "open", "author": "alice",
                 "updated_at": "2026-10-02T00:00:00Z"},
                {"number": 2, "title": "Second", "state": "closed", "author": "bob",
                 "updated_at": "2026-10-03T00:00:00Z"}
            ],
            "next_after": 7
        }),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = list(&ctx, &default_list_args(), Format::Text).await;
    assert_eq!(code, 0);
    assert!(
        out.contains("#1  open  2026-10-02T00:00:00Z  alice  First"),
        "rows: {out}"
    );
    assert!(
        out.contains("#2  closed  2026-10-03T00:00:00Z  bob  Second"),
        "rows: {out}"
    );
    assert!(out.contains("more: --after 7"), "more line: {out}");

    let reqs = app.recorded.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/api/v1/repos/o/r/trails");
    assert_eq!(reqs[0].auth.as_deref(), Some("Bearer test-token"));
    let q = query_pairs(&reqs[0].query);
    assert_eq!(q.get("state").map(String::as_str), Some("open"));
    assert_eq!(q.get("limit").map(String::as_str), Some("30"));
}

#[tokio::test]
async fn list_empty_prints_no_trails() {
    let (base, _) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        200,
        json!({"trails": [], "next_after": null}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = list(&ctx, &default_list_args(), Format::Text).await;
    assert_eq!(code, 0);
    assert_eq!(out, "(no trails)");
}

#[tokio::test]
async fn list_state_all_omits_param() {
    let (base, app) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        200,
        json!({"trails": [], "next_after": null}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let mut args = default_list_args();
    args.state = "all".to_string();
    let (_, code) = list(&ctx, &args, Format::Text).await;
    assert_eq!(code, 0);
    let reqs = app.recorded.lock().unwrap();
    let q = query_pairs(&reqs[0].query);
    assert!(
        !q.contains_key("state"),
        "all must omit state: {:?}",
        reqs[0].query
    );
}

#[tokio::test]
async fn list_filters_are_sent_as_is() {
    let (base, app) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        200,
        json!({"trails": [], "next_after": null}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let mut args = default_list_args();
    args.state = "merged".to_string();
    args.label = Some("bug".to_string());
    args.assignee = Some("bob".to_string());
    args.author = Some("alice".to_string());
    args.limit = 5;
    args.after = Some(9);
    let (_, code) = list(&ctx, &args, Format::Text).await;
    assert_eq!(code, 0);
    let reqs = app.recorded.lock().unwrap();
    let q = query_pairs(&reqs[0].query);
    assert_eq!(q.get("state").map(String::as_str), Some("merged"));
    assert_eq!(q.get("label").map(String::as_str), Some("bug"));
    assert_eq!(q.get("assignee").map(String::as_str), Some("bob"));
    assert_eq!(q.get("author").map(String::as_str), Some("alice"));
    assert_eq!(q.get("limit").map(String::as_str), Some("5"));
    assert_eq!(q.get("after").map(String::as_str), Some("9"));
}

#[tokio::test]
async fn show_renders_full_text() {
    let (base, app) = start(vec![
        ("GET", "/api/v1/repos/o/r/trails/12", 200, trail_detail()),
        (
            "GET",
            "/api/v1/repos/o/r/trails/12/changes",
            200,
            json!({"changes": [change_row()]}),
        ),
        (
            "GET",
            "/api/v1/repos/o/r/trails/12/changes/1",
            200,
            change_detail(),
        ),
        (
            "GET",
            &format!("/api/v1/repos/o/r/commits/{HEAD_SHA}/status"),
            200,
            combined_status(),
        ),
    ])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = show(&ctx, 12, Format::Text).await;
    assert_eq!(code, 0);
    assert!(
        out.contains("#12 Fix the thing  [open, ready]"),
        "header: {out}"
    );
    assert!(out.contains("author: alice"), "author: {out}");
    assert!(
        out.contains("created: 2026-10-01T00:00:00Z"),
        "created: {out}"
    );
    assert!(
        out.contains("updated: 2026-10-02T00:00:00Z"),
        "updated: {out}"
    );
    assert!(out.contains("labels: bug"), "labels: {out}");
    assert!(out.contains("assignees: bob"), "assignees: {out}");
    assert!(
        out.contains(&format!("url: {base}/o/r/trails/12")),
        "url: {out}"
    );
    assert!(out.contains("Make it work."), "intent: {out}");
    assert!(out.contains("changes:"), "changes: {out}");
    assert!(
        out.contains("1  branch  main \u{2190} feature/x  open  rev 2  mergeable  gates: failing (needs 1 more approval)  checks: success"),
        "change line: {out}"
    );
    assert!(out.contains("comments (1):"), "comments: {out}");
    assert!(out.contains("Looks good."), "comment body: {out}");

    {
        let reqs = app.recorded.lock().unwrap();
        let paths: Vec<&str> = reqs.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/api/v1/repos/o/r/trails/12",
                "/api/v1/repos/o/r/trails/12/changes",
                "/api/v1/repos/o/r/trails/12/changes/1",
                &format!("/api/v1/repos/o/r/commits/{HEAD_SHA}/status"),
            ]
        );
        for r in reqs.iter() {
            assert_eq!(r.auth.as_deref(), Some("Bearer test-token"), "auth: {r:?}");
        }
    }
    let (out, code) = show(&ctx, 12, Format::Json).await;
    assert_eq!(code, 0);
    let body: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(body["trail"]["number"], 12);
    assert_eq!(
        body["changes"][0]["status"]["state"], "success",
        "status: {out}"
    );
    assert!(
        body["changes"][0]["change"].get("files").is_none(),
        "files stripped: {out}"
    );
}

#[tokio::test]
async fn show_without_revisions_omits_checks() {
    let mut detail = change_detail();
    detail.as_object_mut().unwrap().remove("selected");
    let (base, _) = start(vec![
        ("GET", "/api/v1/repos/o/r/trails/12", 200, trail_detail()),
        (
            "GET",
            "/api/v1/repos/o/r/trails/12/changes",
            200,
            json!({"changes": [change_row()]}),
        ),
        ("GET", "/api/v1/repos/o/r/trails/12/changes/1", 200, detail),
    ])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = show(&ctx, 12, Format::Text).await;
    assert_eq!(code, 0);
    assert!(
        !out.contains("checks:"),
        "no checks without head sha: {out}"
    );
    assert!(
        out.contains("gates: failing (needs 1 more approval)"),
        "gates: {out}"
    );
    let (out, code) = show(&ctx, 12, Format::Json).await;
    assert_eq!(code, 0);
    let body: Value = serde_json::from_str(&out).unwrap();
    assert!(
        body["changes"][0]["status"].is_null(),
        "status is null: {out}"
    );
    assert!(
        body["changes"][0]["change"].get("files").is_none(),
        "files stripped: {out}"
    );
    assert!(
        body["changes"][0]["change"].get("threads").is_none(),
        "threads stripped: {out}"
    );
}

#[tokio::test]
async fn create_posts_and_prints_url() {
    let (base, app) = start(vec![(
        "POST",
        "/api/v1/repos/o/r/trails",
        201,
        json!({"number": 3, "title": "T"}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = create(&ctx, "T", "I", Format::Text).await;
    assert_eq!(code, 0);
    assert_eq!(out, format!("created trail #3: {base}/o/r/trails/3"));
    let reqs = app.recorded.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/repos/o/r/trails");
    assert_eq!(reqs[0].auth.as_deref(), Some("Bearer test-token"));
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(body, json!({"title": "T", "intent": "I"}));
}

#[tokio::test]
async fn comment_posts_and_prints_url() {
    let (base, app) = start(vec![(
        "POST",
        "/api/v1/repos/o/r/trails/12/comments",
        201,
        json!({"id": 8}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = comment(&ctx, 12, "Nice.", Format::Text).await;
    assert_eq!(code, 0);
    assert_eq!(out, format!("commented on trail #12: {base}/o/r/trails/12"));
    let reqs = app.recorded.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/repos/o/r/trails/12/comments");
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(body, json!({"body": "Nice."}));
}

#[tokio::test]
async fn not_found_maps_to_error() {
    let (base, _) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        404,
        json!({"error": {"code": "not_found", "message": "not found", "details": null}}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = list(&ctx, &default_list_args(), Format::Text).await;
    assert_eq!(code, 1);
    assert_eq!(out, "error: not found (not_found)");
}

#[tokio::test]
async fn unauthorized_hints_login() {
    let (base, _) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        401,
        json!({"error": {"code": "unauthenticated", "message": "a valid token is required", "details": null}}),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = list(&ctx, &default_list_args(), Format::Text).await;
    assert_eq!(code, 1);
    assert!(
        out.contains("authentication failed") && out.contains("starforge auth login"),
        "login hint: {out}"
    );
    assert!(!out.contains(TOKEN), "token must never appear");
}

#[tokio::test]
async fn json_format_passes_response_through() {
    let list_body = json!({"trails": [{"number": 1}], "next_after": null});
    let (base, _) = start(vec![(
        "GET",
        "/api/v1/repos/o/r/trails",
        200,
        list_body.clone(),
    )])
    .await;
    let ctx = ctx_for(&base);
    let (out, code) = list(&ctx, &default_list_args(), Format::Json).await;
    assert_eq!(code, 0);
    assert_eq!(out, serde_json::to_string_pretty(&list_body).unwrap());
}

// ---------------------------------------------------------------------------
// Clap surface: `--format agent` only on `show`, `--limit` bounded 1–100.
// ---------------------------------------------------------------------------

use clap::Parser;
use starforge_cli::cli::{Cli, TrailCmd};

fn parse<const N: usize>(argv: [&str; N]) -> Result<Cli, clap::error::Error> {
    Cli::try_parse_from(argv)
}

#[test]
fn agent_format_rejected_outside_show() {
    let err = parse(["starforge", "trail", "list", "--format", "agent"]).unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    let err = parse([
        "starforge",
        "trail",
        "create",
        "--title",
        "t",
        "--format",
        "agent",
    ])
    .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    let argv = [
        "starforge",
        "trail",
        "comment",
        "1",
        "--body",
        "b",
        "--format",
        "agent",
    ];
    let err = parse(argv).unwrap_err();
    assert_eq!(err.exit_code(), 2, "{argv:?}: {err}");
    let cli = parse(["starforge", "trail", "show", "1", "--format", "agent"]).unwrap();
    assert!(matches!(
        cli.cmd,
        starforge_cli::cli::Cmd::Trail {
            cmd: TrailCmd::Show { .. }
        }
    ));
}

#[test]
fn limit_bounded_with_default_30() {
    for bad in ["0", "101"] {
        let err = parse(["starforge", "trail", "list", "--limit", bad]).unwrap_err();
        assert_eq!(err.exit_code(), 2, "limit {bad}: {err}");
    }
    let cli = parse(["starforge", "trail", "list"]).unwrap();
    assert!(matches!(
        cli.cmd,
        starforge_cli::cli::Cmd::Trail {
            cmd: TrailCmd::List { limit: 30, .. }
        }
    ));
}

#[test]
fn comment_requires_one_body_source() {
    let err = parse(["starforge", "trail", "comment", "1"]).unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    let err = parse([
        "starforge",
        "trail",
        "comment",
        "1",
        "--body",
        "b",
        "--body-file",
        "-",
    ])
    .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
}
