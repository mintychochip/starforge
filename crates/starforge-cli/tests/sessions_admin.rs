//! `sessions publish`/`unpublish`/`delete` against an in-process stub.
//!
//! The stub asserts exact paths and the `Authorization: Bearer` header; the
//! handlers are called in-process through the library seam. Argument
//! parsing is pinned via [`Cli::try_parse_from`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{StatusCode, Uri, header};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde_json::{Value, json};

use clap::Parser;
use starforge_cli::api::ApiClient;
use starforge_cli::cli::{Cli, Cmd, SessionsCmd};
use starforge_cli::commands::session_admin::{delete, publish, unpublish};

const TOKEN: &str = "test-token";
const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
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
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    app.recorded.lock().unwrap().push(Recorded {
        method: method.clone(),
        path: path.clone(),
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

fn api_for(base: &str) -> ApiClient {
    ApiClient::new(base, "o/r", TOKEN).unwrap()
}

fn session_path(suffix: &str) -> String {
    format!("/api/v1/repos/o/r/sessions/{ULID}{suffix}")
}

#[tokio::test]
async fn publish_posts_to_publish_endpoint() {
    let (base, app) = start(vec![(
        "POST",
        &session_path("/publish"),
        200,
        json!({"ulid": ULID, "visibility": "published"}),
    )])
    .await;
    let (out, code) = publish(&api_for(&base), ULID).await;
    assert_eq!(code, 0);
    assert_eq!(out, format!("published {ULID}"));
    let recorded = app.recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[0].path, session_path("/publish"));
    assert_eq!(recorded[0].auth.as_deref(), Some("Bearer test-token"));
}

#[tokio::test]
async fn unpublish_posts_to_unpublish_endpoint() {
    let (base, app) = start(vec![(
        "POST",
        &session_path("/unpublish"),
        200,
        json!({"ulid": ULID, "visibility": "inherit"}),
    )])
    .await;
    let (out, code) = unpublish(&api_for(&base), ULID).await;
    assert_eq!(code, 0);
    assert_eq!(out, format!("unpublished {ULID}"));
    let recorded = app.recorded.lock().unwrap();
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[0].path, session_path("/unpublish"));
}

#[tokio::test]
async fn delete_confirmed_deletes_session() {
    let (base, app) = start(vec![("DELETE", &session_path(""), 204, Value::Null)]).await;
    let (out, code) = delete(&api_for(&base), ULID, true).await;
    assert_eq!(code, 0);
    assert_eq!(out, format!("deleted {ULID}"));
    let recorded = app.recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].method, "DELETE");
    assert_eq!(recorded[0].path, session_path(""));
}

#[tokio::test]
async fn delete_without_yes_refuses_before_any_request() {
    let (base, app) = start(vec![("DELETE", &session_path(""), 204, Value::Null)]).await;
    let (out, code) = delete(&api_for(&base), ULID, false).await;
    assert_eq!(code, 1);
    assert_eq!(
        out,
        format!("error: refusing to delete session {ULID} without --yes")
    );
    assert!(app.recorded.lock().unwrap().is_empty(), "no request");
}

#[tokio::test]
async fn publish_401_renders_auth_error_with_login_hint() {
    let (base, _) = start(vec![(
        "POST",
        &session_path("/publish"),
        401,
        json!({"error": {"code": "unauthenticated", "message": "a valid token is required", "details": null}}),
    )])
    .await;
    let (out, code) = publish(&api_for(&base), ULID).await;
    assert_eq!(code, 1);
    assert!(
        out.contains("authentication failed") && out.contains("auth login"),
        "out: {out}"
    );
}

#[tokio::test]
async fn publish_403_renders_auth_error() {
    let (base, _) = start(vec![(
        "POST",
        &session_path("/publish"),
        403,
        json!({"error": {"code": "forbidden", "message": "this token lacks the session:upload scope", "details": null}}),
    )])
    .await;
    let (out, code) = publish(&api_for(&base), ULID).await;
    assert_eq!(code, 1);
    assert!(out.contains("authentication failed"), "out: {out}");
}

#[tokio::test]
async fn publish_404_renders_status_error() {
    let (base, _) = start(vec![]).await;
    let (out, code) = publish(&api_for(&base), ULID).await;
    assert_eq!(code, 1);
    assert_eq!(out, "error: not found (not_found)");
}

#[tokio::test]
async fn delete_404_renders_status_error() {
    let (base, _) = start(vec![]).await;
    let (out, code) = delete(&api_for(&base), ULID, true).await;
    assert_eq!(code, 1);
    assert_eq!(out, "error: not found (not_found)");
}

#[test]
fn sessions_admin_arguments_parse() {
    let cli =
        Cli::try_parse_from(["starforge", "sessions", "publish", ULID, "--repo", "o/r"]).unwrap();
    assert!(matches!(
        cli.cmd,
        Cmd::Sessions {
            cmd: SessionsCmd::Publish { ref ulid, ref repo }
        } if ulid == ULID && repo.as_deref() == Some("o/r")
    ));
    let cli = Cli::try_parse_from([
        "starforge",
        "sessions",
        "delete",
        ULID,
        "--yes",
        "--repo",
        "o/r",
    ])
    .unwrap();
    assert!(matches!(
        cli.cmd,
        Cmd::Sessions {
            cmd: SessionsCmd::Delete { ref ulid, yes: true, .. }
        } if ulid == ULID
    ));
    let cli = Cli::try_parse_from(["starforge", "sessions", "unpublish", ULID]).unwrap();
    assert!(matches!(
        cli.cmd,
        Cmd::Sessions {
            cmd: SessionsCmd::Unpublish { .. }
        }
    ));
}
