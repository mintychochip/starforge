//! D3 hermetic sandbox fixture: `starforge sync` inside a sandbox.
//!
//! A temp repo with `starforge.server` / `starforge.repo` git config and
//! **no remote**, a fake agent store (the synthesized Pi fixture under a
//! temp `$HOME`), and an in-process axum stub server. The real
//! `starforge` binary's `sync` ingests the fake store, uploads the
//! session, and completes it — authenticated only by the `STARFORGE_TOKEN`
//! environment variable (the per-job token), with no credentials file and
//! no interactive login. Network is loopback-only; no real `$HOME`.
//!
//! The fixture transcript is dated 2026-10-01, more than the 24 h idle
//! rule before the test clock, so ingest ends the session and `sync`
//! uploads metadata → segment → complete.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod common;

use common::hermetic_command;

use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post, put},
};
use starforge_cli::git::common_dir;
use starforge_cli::spool::Spool;
use tempfile::TempDir;

const TOKEN: &str = "per-job-token";
const OWNER_REPO: &str = "o/r";

fn git(repo: &Path, args: &[&str], home: &Path, path: &str) -> std::process::Output {
    hermetic_command("git", home)
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("PATH", path)
        .output()
        .expect("git runs")
}

fn git_ok(repo: &Path, args: &[&str], home: &Path, path: &str) -> String {
    let out = git(repo, args, home, path);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn bin_path() -> String {
    let exe = env!("CARGO_BIN_EXE_starforge");
    let dir = Path::new(exe).parent().unwrap().to_path_buf();
    format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

fn fixture_body(repo: &Path) -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi-session.jsonl");
    std::fs::read_to_string(&src)
        .unwrap()
        .replace("/work/repo", &repo.to_string_lossy())
}

// ---------------------------------------------------------------------------
// Stub server: well-known + the four upload endpoints, Bearer-checked.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    auth: Option<String>,
    body: Vec<u8>,
}

struct Stub {
    state: Arc<Mutex<Vec<Recorded>>>,
    base_url: String,
}

impl Stub {
    fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().clone()
    }
}

fn record(
    state: &Arc<Mutex<Vec<Recorded>>>,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    state.lock().unwrap().push(Recorded {
        method: method.to_string(),
        path: uri.path().to_string(),
        auth,
        body: body.to_vec(),
    });
}

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(format!("Bearer {TOKEN}").as_str())
}

async fn put_meta(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, "PUT", &uri, &headers, &body);
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::CREATED, "created").into_response()
}

async fn put_segment(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    AxPath((_owner, _repo, _ulid, _n)): AxPath<(String, String, String, u64)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, "PUT", &uri, &headers, &body);
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

async fn post_complete(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, "POST", &uri, &headers, &body);
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

async fn post_links(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, "POST", &uri, &headers, &body);
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

async fn start_stub() -> Stub {
    let state: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let well_known_body = serde_json::json!({
        "starforge": "test",
        "api_url": base_url,
        "ssh_url": "ssh://git@example.com:2222",
    });
    let app = Router::new()
        .route(
            "/.well-known/starforge.json",
            get({
                let body = well_known_body.clone();
                move || {
                    let body = body.clone();
                    async move { axum::Json(body) }
                }
            }),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}",
            put(put_meta),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}",
            put(put_segment),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/complete",
            post(post_complete),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/links",
            post(post_links),
        )
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Stub { state, base_url }
}

// ---------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_in_sandbox_uploads_and_completes_with_env_token_only() {
    let home_dir = TempDir::new().unwrap();
    let home = home_dir.path().to_path_buf();
    let path = bin_path();

    // Temp repo: local only, no remote is ever added.
    let dir = TempDir::new().unwrap();
    let repo: PathBuf = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init"], &home, &path);
    git_ok(&repo, &["config", "user.email", "t@t.t"], &home, &path);
    git_ok(&repo, &["config", "user.name", "t"], &home, &path);
    git_ok(&repo, &["config", "commit.gpgsign", "false"], &home, &path);
    std::fs::write(repo.join("file.txt"), "hello\n").unwrap();
    git_ok(&repo, &["add", "file.txt"], &home, &path);
    git_ok(&repo, &["commit", "-m", "init"], &home, &path);
    assert!(
        git_ok(&repo, &["remote", "-v"], &home, &path)
            .trim()
            .is_empty(),
        "fixture repo must have no remotes"
    );

    // Fake agent store: the synthesized Pi transcript, cwd in this repo.
    let store = home.join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("pi-sandbox.jsonl"), fixture_body(&repo)).unwrap();

    // Sandbox wiring: server + repo from git config, token from the env.
    let stub = start_stub().await;
    git_ok(
        &repo,
        &["config", "starforge.server", &stub.base_url],
        &home,
        &path,
    );
    git_ok(
        &repo,
        &["config", "starforge.repo", OWNER_REPO],
        &home,
        &path,
    );

    // No credentials file exists: nothing to log in with interactively.
    assert!(
        !home.join(".starforge").exists(),
        "no stored credentials may exist before sync"
    );

    let sync = hermetic_command("starforge", &home)
        .current_dir(&repo)
        .args(["sync"])
        .env("PATH", &path)
        .env("STARFORGE_TOKEN", TOKEN)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("starforge runs");
    assert!(
        sync.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&sync.stderr)
    );
    assert!(
        String::from_utf8_lossy(&sync.stdout).contains("sync:"),
        "sync prints its summary: {}",
        String::from_utf8_lossy(&sync.stdout)
    );

    // Uploads went to the configured repo with the env token as Bearer.
    let reqs = stub.requests();
    let uploads: Vec<&Recorded> = reqs
        .iter()
        .filter(|r| r.path.starts_with("/api/v1/repos/o/r/sessions/"))
        .collect();
    assert!(
        !uploads.is_empty(),
        "sync must upload to the configured repo; got {reqs:?}"
    );
    for r in &uploads {
        assert!(
            r.method == "PUT" || r.method == "POST",
            "upload uses PUT/POST, got {}",
            r.method
        );
        assert_eq!(
            r.auth.as_deref(),
            Some(format!("Bearer {TOKEN}").as_str()),
            "every upload carries the per-job env token"
        );
    }

    // Metadata, segment(s), then complete — in canonical order.
    let meta = serde_json::from_slice::<serde_json::Value>(&uploads[0].body).unwrap();
    let ulid = meta["id"].as_str().unwrap().to_string();
    let session = format!("/api/v1/repos/o/r/sessions/{ulid}");
    let paths: Vec<&str> = uploads.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths.first(), Some(&session.as_str()), "metadata PUT first");
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with(&format!("{session}/segments/"))),
        "at least one segment: {paths:?}"
    );
    assert!(
        paths.contains(&format!("{session}/complete").as_str()),
        "sync completes the session: {paths:?}"
    );
    let complete_pos = paths
        .iter()
        .position(|p| *p == format!("{session}/complete").as_str())
        .unwrap();
    let last_segment_pos = paths
        .iter()
        .rposition(|p| p.starts_with(&format!("{session}/segments/")))
        .unwrap();
    assert!(
        complete_pos > last_segment_pos,
        "complete comes after the last segment: {paths:?}"
    );

    // The spool recorded the completion: a second sync is quiet.
    let spool = Spool::open(&common_dir(&repo).unwrap());
    let state = spool.read_upload(&ulid).unwrap();
    assert!(state.meta_hash.is_some(), "metadata PUT recorded");
    assert!(state.complete, "complete recorded");

    let before = stub.requests().len();
    let sync2 = hermetic_command("starforge", &home)
        .current_dir(&repo)
        .args(["sync"])
        .env("PATH", &path)
        .env("STARFORGE_TOKEN", TOKEN)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("second starforge runs");
    assert!(
        sync2.status.success(),
        "second sync failed: {}",
        String::from_utf8_lossy(&sync2.stderr)
    );
    assert_eq!(
        stub.requests().len(),
        before,
        "second sync makes zero requests"
    );
}
