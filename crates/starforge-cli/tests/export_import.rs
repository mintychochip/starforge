//! `export`/`import` bundle round-trips against an in-process stub.
//!
//! The stub is query-aware (event pages) and byte-capable (segment
//! downloads/uploads), and records every request so the import's upload
//! sequence (meta, segments, complete, links) is pinned exactly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::{StatusCode, Uri, header};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde_json::{Value, json};

use clap::Parser;
use starforge_cli::api::ApiClient;
use starforge_cli::cli::{Cli, Cmd};
use starforge_cli::commands::bundle::{BundleCtx, discover_session_dirs, export, import};

const TOKEN: &str = "test-token";
const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ULID2: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
    auth: Option<String>,
}

/// (method, path, query) key into the stub's route table.
type RouteKey = (String, String, String);
/// (status, content-type, body) stub response.
type RouteResponse = (u16, String, Vec<u8>);
/// One stub route: (method, path, query, status, content-type, body).
type RouteSpec = (String, String, String, u16, String, Vec<u8>);

struct Stub {
    recorded: Mutex<Vec<Recorded>>,
    routes: HashMap<RouteKey, RouteResponse>,
}

async fn handle(
    axum::extract::State(app): axum::extract::State<Arc<Stub>>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let method = req.method().to_string();
    let uri: Uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap_or_default()
        .to_vec();
    app.recorded.lock().unwrap().push(Recorded {
        method: method.clone(),
        path: path.clone(),
        query: query.clone(),
        body,
        auth,
    });
    match app.routes.get(&(method, path, query)) {
        Some((status, content_type, body)) => (
            StatusCode::from_u16(*status).unwrap(),
            [(header::CONTENT_TYPE, content_type.clone())],
            body.clone(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": {"code": "not_found", "message": "not found", "details": null}})),
        )
            .into_response(),
    }
}

async fn start(routes: Vec<RouteSpec>) -> (String, Arc<Stub>) {
    let app = Arc::new(Stub {
        recorded: Mutex::new(Vec::new()),
        routes: routes
            .into_iter()
            .map(|(m, p, q, s, ct, b)| ((m, p, q), (s, ct, b)))
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

fn route(method: &str, path: &str, query: &str, status: u16, body: Value) -> RouteSpec {
    (
        method.to_string(),
        path.to_string(),
        query.to_string(),
        status,
        "application/json".to_string(),
        serde_json::to_vec(&body).unwrap(),
    )
}

fn raw_route(method: &str, path: &str, query: &str, status: u16, body: Vec<u8>) -> RouteSpec {
    (
        method.to_string(),
        path.to_string(),
        query.to_string(),
        status,
        "application/octet-stream".to_string(),
        body,
    )
}
fn api_for(base: &str) -> ApiClient {
    ApiClient::new(base, "o/r", TOKEN).unwrap()
}

fn ctx_for(base: &str) -> BundleCtx {
    BundleCtx::new(api_for(base), base, "o/r", TOKEN)
}

fn sessions_path(suffix: &str) -> String {
    format!("/api/v1/repos/o/r/sessions{suffix}")
}

fn session_meta(ulid: &str) -> Value {
    json!({
        "ulid": ulid,
        "agent": {"name": "pi", "version": "0.5.2"},
        "adapter_version_verified": true,
        "models": ["pi-model-x"],
        "title": "export me",
        "branch": "feature/widget",
        "head": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "started_at": 1762214400,
        "ended_at": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "visibility": "inherit",
        "quarantine": {"state": "none", "reason": null, "detail": null},
        "redaction": {"fingerprint": "fp-test", "counts": {"known-token": 2}},
        "capture": {"mode": "discovery", "cli_version": "0.1.0"},
        "links": [],
    })
}

fn events() -> Vec<Value> {
    vec![
        json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z", "kind": "user_message", "text": "hello"}),
        json!({"v": 1, "seq": 1, "ts": "2026-11-04T00:01:00Z", "kind": "tool_call",
               "tool": {"name": "Edit", "input": {"file_path": "src/a.rs"}}}),
        json!({"v": 1, "seq": 2, "ts": "2026-11-04T00:02:00Z", "kind": "assistant_message", "text": "done"}),
    ]
}

fn links() -> Value {
    json!([{"sha": SHA, "confidence": "exact", "seq_start": 0, "seq_end": 1}])
}

/// One session's read routes: metadata, two event pages (2 + 1 events), the
/// links list, and one raw segment (segment 1 answers 404 by absence).
fn session_routes(ulid: &str, segment_bytes: &[u8]) -> Vec<RouteSpec> {
    let meta = session_meta(ulid);
    let ev = events();
    vec![
        route("GET", &sessions_path(&format!("/{ulid}")), "", 200, meta),
        route(
            "GET",
            &sessions_path(&format!("/{ulid}/events")),
            "page=1",
            200,
            json!({"events": [ev[0].clone(), ev[1].clone()], "page": 1, "pages": 2, "total": 3}),
        ),
        route(
            "GET",
            &sessions_path(&format!("/{ulid}/events")),
            "page=2",
            200,
            json!({"events": [ev[2].clone()], "page": 2, "pages": 2, "total": 3}),
        ),
        route(
            "GET",
            &sessions_path(&format!("/{ulid}/links")),
            "",
            200,
            json!({"links": links()}),
        ),
        raw_route(
            "GET",
            &sessions_path(&format!("/{ulid}/segments/0")),
            "",
            200,
            segment_bytes.to_vec(),
        ),
    ]
}

#[tokio::test]
async fn export_writes_full_bundle() {
    let segment_bytes = starforge_format::compress(b"raw segment bytes\n");
    let (base, app) = start(session_routes(ULID, &segment_bytes)).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    let (out, code) = export(&ctx_for(&base), &[ULID.to_string()], &dir).await;
    assert_eq!(code, 0, "out: {out}");
    let recorded = app.recorded.lock().unwrap();
    let event_queries: Vec<&str> = recorded
        .iter()
        .filter(|r| r.path.ends_with("/events"))
        .map(|r| r.query.as_str())
        .collect();
    assert_eq!(
        event_queries,
        vec!["page=1", "page=2"],
        "events paginate 1-based"
    );
    assert!(out.contains(&format!("exported {ULID}")), "out: {out}");
    assert!(
        out.contains(&format!("exported 1 session(s) to {}", dir.display())),
        "out: {out}"
    );

    let session_dir = dir.join("o__r").join(ULID);
    let stored_meta: Value =
        serde_json::from_str(&std::fs::read_to_string(session_dir.join("session.json")).unwrap())
            .unwrap();
    assert_eq!(stored_meta, session_meta(ULID));
    let events_text = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap();
    let lines: Vec<Value> = events_text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines, events(), "events must survive page by page");
    assert_eq!(events_text.lines().count(), 3);
    let stored_links: Value =
        serde_json::from_str(&std::fs::read_to_string(session_dir.join("links.json")).unwrap())
            .unwrap();
    assert_eq!(stored_links, links());
    assert_eq!(
        std::fs::read(session_dir.join("segments").join("0.raw.zst")).unwrap(),
        segment_bytes,
        "segment bytes must be byte-faithful"
    );
    let bundle: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["format_version"], 1);
    assert_eq!(bundle["server"], base);
    assert!(bundle["exported_at"].as_str().is_some());
}

#[tokio::test]
async fn export_without_raw_serves_redacted_segments() {
    // The server guards stored bytes behind the raw-storage gate, so with no
    // segment route the bundle's segments must be the re-segmentation of the
    // redacted `/events` stream — not stored bytes.
    let mut routes = session_routes(ULID, b"unused");
    routes.retain(|(_, path, _, _, _, _)| !path.contains("/segments/"));
    let (base, _app) = start(routes).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    let (_out, code) = export(&ctx_for(&base), &[ULID.to_string()], &dir).await;
    assert_eq!(code, 0);
    let exported = std::fs::read(
        dir.join("o__r")
            .join(ULID)
            .join("segments")
            .join("0.raw.zst"),
    )
    .unwrap();
    let text = String::from_utf8(starforge_format::decompress(&exported).unwrap()).unwrap();
    let body: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(body, events(), "segments carry the redacted stream");
}

#[tokio::test]
async fn export_without_session_lists_all_readable() {
    let segment_bytes = starforge_format::compress(b"x");
    let mut routes = session_routes(ULID, &segment_bytes);
    routes.extend(session_routes(ULID2, &segment_bytes));
    routes.push(route(
        "GET",
        &sessions_path(""),
        "",
        200,
        json!({"sessions": [{"ulid": ULID}, {"ulid": ULID2}]}),
    ));
    let (base, _app) = start(routes).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    let (out, code) = export(&ctx_for(&base), &[], &dir).await;
    assert_eq!(code, 0, "out: {out}");
    assert!(
        out.contains(&format!("exported {ULID}")) && out.contains(&format!("exported {ULID2}")),
        "out: {out}"
    );
    assert!(dir.join("o__r").join(ULID).join("session.json").is_file());
    assert!(dir.join("o__r").join(ULID2).join("session.json").is_file());
}

#[tokio::test]
async fn export_unreadable_session_is_a_clear_error() {
    let (base, _app) = start(vec![]).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    let (out, code) = export(&ctx_for(&base), &[ULID.to_string()], &dir).await;
    assert_eq!(code, 1);
    assert_eq!(
        out,
        format!("error: cannot export session {ULID}: session not found or not readable")
    );
}

/// Write a one-session bundle by hand (the shape `export` produces).
fn write_bundle(dir: &Path, ulid: &str, events_text: &str, links: Value) {
    let session_dir = dir.join("o__r").join(ulid);
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        dir.join("bundle.json"),
        r#"{"format_version": 1, "server": "http://example.test", "exported_at": "2026-11-04T00:00:00Z"}"#,
    )
    .unwrap();
    std::fs::write(
        session_dir.join("session.json"),
        serde_json::to_string_pretty(&session_meta(ulid)).unwrap(),
    )
    .unwrap();
    std::fs::write(session_dir.join("events.jsonl"), events_text).unwrap();
    std::fs::write(
        session_dir.join("links.json"),
        serde_json::to_string_pretty(&links).unwrap(),
    )
    .unwrap();
}

fn events_text() -> String {
    events()
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[tokio::test]
async fn import_uploads_meta_segments_complete_and_links() {
    let text = events_text();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    write_bundle(&dir, ULID, &text, links());
    let (base, app) = start(vec![
        route(
            "PUT",
            &sessions_path(&format!("/{ULID}")),
            "",
            201,
            json!({"ulid": ULID}),
        ),
        route(
            "PUT",
            &sessions_path(&format!("/{ULID}/segments/0")),
            "",
            200,
            json!({"ulid": ULID}),
        ),
        route(
            "POST",
            &sessions_path(&format!("/{ULID}/complete")),
            "",
            200,
            json!({"ulid": ULID}),
        ),
        route(
            "POST",
            &sessions_path(&format!("/{ULID}/links")),
            "",
            200,
            json!({"accepted": 1}),
        ),
    ])
    .await;
    let (out, code) = import(&ctx_for(&base), &dir).await;
    assert_eq!(code, 0, "out: {out}");
    assert_eq!(
        out,
        format!("{ULID}: imported\nimported 1 session(s), 0 already present")
    );

    let recorded = app.recorded.lock().unwrap();
    let sequence: Vec<(&str, &str)> = recorded
        .iter()
        .map(|r| (r.method.as_str(), r.path.as_str()))
        .collect();
    assert_eq!(
        sequence,
        vec![
            ("PUT", sessions_path(&format!("/{ULID}")).as_str()),
            (
                "PUT",
                sessions_path(&format!("/{ULID}/segments/0")).as_str()
            ),
            ("POST", sessions_path(&format!("/{ULID}/complete")).as_str()),
            ("POST", sessions_path(&format!("/{ULID}/links")).as_str()),
        ]
    );
    let meta: Value = serde_json::from_slice(&recorded[0].body).unwrap();
    assert_eq!(meta["id"], ULID, "ULID preserved: {meta}");
    assert_eq!(meta["format"], "starforge.session/v1");
    assert_eq!(meta["agent"]["name"], "pi");
    assert!(
        meta["started_at"].as_str().is_some_and(|s| s.contains('T')),
        "started_at converted: {meta}"
    );
    assert_eq!(meta["repo"]["branch"], "feature/widget");
    assert_eq!(
        meta["files_touched"],
        json!(["src/a.rs"]),
        "files derived: {meta}"
    );
    assert_eq!(meta["usage"]["input"], 10);
    assert_eq!(
        recorded[1].body,
        starforge_format::compress(text.as_bytes()),
        "segment bytes are the re-segmented events"
    );
    let links_body: Value = serde_json::from_slice(&recorded[3].body).unwrap();
    assert_eq!(links_body["links"], links());
    assert!(
        recorded
            .iter()
            .all(|r| r.auth.as_deref() == Some("Bearer test-token"))
    );
}

#[tokio::test]
async fn import_existing_ulid_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    write_bundle(&dir, ULID, &events_text(), links());
    let (base, app) = start(vec![route(
        "PUT",
        &sessions_path(&format!("/{ULID}")),
        "",
        200,
        json!({"ulid": ULID}),
    )])
    .await;
    let (out, code) = import(&ctx_for(&base), &dir).await;
    assert_eq!(code, 0, "out: {out}");
    assert_eq!(
        out,
        format!("{ULID}: exists, skipped\nimported 0 session(s), 1 already present")
    );
    let recorded = app.recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1, "only the meta PUT");
    assert_eq!(recorded[0].method, "PUT");
}

#[tokio::test]
async fn import_first_403_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    write_bundle(&dir, ULID, &events_text(), links());
    let (base, _app) = start(vec![route(
        "PUT",
        &sessions_path(&format!("/{ULID}")),
        "",
        403,
        json!({"error": {"code": "forbidden", "message": "permission denied", "details": null}}),
    )])
    .await;
    let (out, code) = import(&ctx_for(&base), &dir).await;
    assert_eq!(code, 1);
    assert!(out.contains("importing"), "out: {out}");
}

#[tokio::test]
async fn import_403_after_successful_write_is_exists_skip() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    write_bundle(&dir, ULID, &events_text(), links());
    write_bundle(&dir, ULID2, &events_text(), links());
    let (base, _app) = start(vec![
        route("PUT", &sessions_path(&format!("/{ULID}")), "", 201, json!({"ulid": ULID})),
        route("PUT", &sessions_path(&format!("/{ULID}/segments/0")), "", 200, json!({"ulid": ULID})),
        route("POST", &sessions_path(&format!("/{ULID}/complete")), "", 200, json!({"ulid": ULID})),
        route("POST", &sessions_path(&format!("/{ULID}/links")), "", 200, json!({"accepted": 1})),
        route(
            "PUT",
            &sessions_path(&format!("/{ULID2}")),
            "",
            403,
            json!({"error": {"code": "forbidden", "message": "permission denied", "details": null}}),
        ),
    ])
    .await;
    let (out, code) = import(&ctx_for(&base), &dir).await;
    assert_eq!(code, 0, "out: {out}");
    assert_eq!(
        out,
        format!(
            "{ULID}: imported\n{ULID2}: exists, skipped\nimported 1 session(s), 1 already present"
        )
    );
}

#[tokio::test]
async fn import_rejects_unknown_bundle_version() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    write_bundle(&dir, ULID, &events_text(), links());
    std::fs::write(
        dir.join("bundle.json"),
        r#"{"format_version": 2, "server": "http://example.test", "exported_at": "2026-11-04T00:00:00Z"}"#,
    )
    .unwrap();
    let (base, _app) = start(vec![]).await;
    let (out, code) = import(&ctx_for(&base), &dir).await;
    assert_eq!(code, 1);
    assert_eq!(out, "error: unsupported bundle format version 2 (want 1)");
}

#[tokio::test]
async fn import_rejects_non_bundle_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("nowhere");
    std::fs::create_dir_all(&dir).unwrap();
    let (base, _app) = start(vec![]).await;
    let (out, code) = import(&ctx_for(&base), &dir).await;
    assert_eq!(code, 1);
    assert!(out.contains("not a starforge export bundle"), "out: {out}");
}

#[test]
fn discover_rejects_ulid_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bundle");
    write_bundle(&dir, ULID, &events_text(), links());
    // Hand-flip one session.json to claim the other ULID.
    let path: PathBuf = dir.join("o__r").join(ULID).join("session.json");
    let mut meta: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    meta["ulid"] = json!(ULID2);
    std::fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
    let err = discover_session_dirs(&dir).unwrap_err();
    assert!(err.contains("does not match"), "err: {err}");
}

#[test]
fn export_import_arguments_parse() {
    let cli = Cli::try_parse_from([
        "starforge",
        "export",
        "--repo",
        "o/r",
        "--session",
        ULID,
        "--session",
        ULID2,
        "out",
    ])
    .unwrap();
    assert!(matches!(
        cli.cmd,
        Cmd::Export { ref repo, ref session, ref dir }
            if repo == "o/r" && session == &vec![ULID.to_string(), ULID2.to_string()]
                && dir == &std::path::PathBuf::from("out")
    ));
    let cli = Cli::try_parse_from(["starforge", "import", "out", "--repo", "o/r"]).unwrap();
    assert!(matches!(
        cli.cmd,
        Cmd::Import { ref repo, .. } if repo == "o/r"
    ));
    // --repo is required for both commands.
    assert!(Cli::try_parse_from(["starforge", "export", "out"]).is_err());
    assert!(Cli::try_parse_from(["starforge", "import", "out"]).is_err());
}
