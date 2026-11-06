//! GAP B §13 e2e: the real `starforge` binary plus a real `git commit`.
//!
//! A temp repo with its own `STARFORGE_HOME` runs `starforge enable` as a
//! process (binary dir prepended to `PATH` so the installed dispatchers find
//! it), a real `git commit` (asserting exactly one `Starforge-Session:`
//! trailer comes out of the installed `prepare-commit-msg` dispatcher), then
//! `starforge sync` as a process against an in-process axum stub. Assertions:
//! metadata carried `redaction.fingerprint`; the segment body decompresses to
//! JSONL with no `ghp_…` and with `[redacted:known-token]`; links carried the
//! commit SHA; a second `sync` makes zero requests. No network beyond
//! `127.0.0.1`, no real `$HOME`.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;
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

const TOKEN: &str = "test-token";

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

fn init_repo(home: &Path, path: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init"], home, path);
    git_ok(&repo, &["config", "user.email", "t@t.t"], home, path);
    git_ok(&repo, &["config", "user.name", "t"], home, path);
    git_ok(&repo, &["config", "commit.gpgsign", "false"], home, path);
    git_ok(
        &repo,
        &["commit", "--allow-empty", "-m", "init"],
        home,
        path,
    );
    (dir, repo)
}

fn starforge(repo: &Path, home: &Path, path: &str, args: &[&str]) -> std::process::Output {
    hermetic_command("starforge", home)
        .current_dir(repo)
        .args(args)
        .env("PATH", path)
        .env("STARFORGE_TOKEN", TOKEN)
        .output()
        .expect("starforge runs")
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
// Stub server: well-known + the four §7.5 endpoints, recording requests.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Recorded {
    path: String,
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

fn record(state: &Arc<Mutex<Vec<Recorded>>>, uri: &Uri, body: &[u8]) {
    state.lock().unwrap().push(Recorded {
        path: uri.path().to_string(),
        body: body.to_vec(),
    });
}

async fn put_meta(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::CREATED, "created").into_response()
}

async fn put_segment(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    AxPath((_owner, _repo, _ulid, _n)): AxPath<(String, String, String, u64)>,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::OK, "ok").into_response()
}

async fn post_complete(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::OK, "ok").into_response()
}

async fn post_links(
    State(state): State<Arc<Mutex<Vec<Recorded>>>>,
    uri: Uri,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, &uri, &body);
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
async fn real_binary_enable_commit_sync() {
    let home_dir = TempDir::new().unwrap();
    let home = home_dir.path().to_path_buf();
    let path = bin_path();
    let (_dir, repo) = init_repo(&home, &path);

    // `starforge enable` as a process.
    let out = starforge(&repo, &home, &path, &["enable"]);
    assert!(
        out.status.success(),
        "enable failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Native Pi session whose cwd and touched file live in this repo: ingest
    // (run by the hooks) discovers it without any manual spool seeding.
    let store = home.join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("pi-e2e.jsonl"), fixture_body(&repo)).unwrap();

    // Commit a file the session touched, through the installed dispatcher.
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git_ok(&repo, &["add", "src/lib.rs"], &home, &path);
    let commit = git(&repo, &["commit", "-m", "touch lib"], &home, &path);
    assert!(
        commit.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // Exactly one trailer, from the real commit message.
    let body = git_ok(&repo, &["log", "-1", "--format=%B"], &home, &path);
    let trailers: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("Starforge-Session:"))
        .collect();
    assert_eq!(trailers.len(), 1, "exactly one trailer; body:\n{body}");
    let ulid = trailers[0]
        .strip_prefix("Starforge-Session: ")
        .unwrap()
        .to_string();
    ulid::Ulid::from_str(&ulid).expect("trailer carries a ULID");
    let sha = git_ok(&repo, &["rev-parse", "HEAD"], &home, &path);
    let sha = sha.trim().to_string();

    // Point the repo at the stub, then `starforge sync` as a process.
    let stub = start_stub().await;
    git_ok(
        &repo,
        &["config", "starforge.server", &stub.base_url],
        &home,
        &path,
    );
    git_ok(&repo, &["config", "starforge.repo", "o/r"], &home, &path);
    let sync = starforge(&repo, &home, &path, &["sync"]);
    assert!(
        sync.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&sync.stderr)
    );

    // Fingerprint, redaction, link assertions against what the stub saw.
    let (rules, _) = Spool::load_rules(&repo).unwrap();
    let expected_fp = starforge_redact::fingerprint(&rules);
    let session = format!("/api/v1/repos/o/r/sessions/{ulid}");
    let reqs = stub.requests();
    assert_eq!(
        reqs.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec![
            session.as_str(),
            format!("{session}/segments/0").as_str(),
            format!("{session}/complete").as_str(),
            format!("{session}/links").as_str(),
        ],
        "canonical upload order"
    );
    let meta: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(meta["id"], ulid);
    assert_eq!(meta["redaction"]["fingerprint"], expected_fp);
    let seg_text = String::from_utf8(starforge_format::decompress(&reqs[1].body).unwrap()).unwrap();
    assert!(!seg_text.contains("ghp_"), "segment must be redacted");
    assert!(
        seg_text.contains("[redacted:known-token]"),
        "segment must carry the marker: {seg_text:?}"
    );
    let links: serde_json::Value = serde_json::from_slice(&reqs[3].body).unwrap();
    let commits: Vec<&str> = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["commit"].as_str().unwrap())
        .collect();
    assert_eq!(commits, vec![sha.as_str()], "links carried the commit SHA");

    // Spool recorded everything: a second sync is quiet.
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    let state = spool.read_upload(&ulid).unwrap();
    assert!(state.meta_hash.is_some(), "metadata PUT recorded");
    assert!(state.complete, "complete recorded");
    assert_eq!(state.sent_links.len(), 1, "links POST recorded");

    let before = stub.requests().len();
    let sync2 = starforge(&repo, &home, &path, &["sync"]);
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

// ---------------------------------------------------------------------------
// Trail smoke (M2d J6): the real binary lists its eight subcommands and fails
// closed outside any repository. No network beyond process spawn.
// ---------------------------------------------------------------------------

#[test]
fn trail_help_lists_eight_subcommands() {
    let home = TempDir::new().unwrap();
    let path = bin_path();
    let dir = TempDir::new().unwrap();
    let out = starforge(dir.path(), home.path(), &path, &["trail", "--help"]);
    assert!(out.status.success(), "trail --help exits 0");
    let text = String::from_utf8(out.stdout).unwrap();
    for cmd in [
        "list", "show", "create", "comment", "push", "checkout", "review", "merge",
    ] {
        assert!(text.contains(cmd), "help lists `{cmd}`: {text}");
    }
}

#[test]
fn trail_list_outside_repo_exits_1() {
    let home = TempDir::new().unwrap();
    let path = bin_path();
    // A bare directory: not a git repository, so discovery finds no server.
    let dir = TempDir::new().unwrap();
    let out = starforge(dir.path(), home.path(), &path, &["trail", "list"]);
    assert_eq!(out.status.code(), Some(1), "trail list exits 1");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("no server configured"),
        "discovery names the missing server: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_list_without_token_hints_login() {
    // Minimal stub: only the well-known document. Discovery resolves the
    // server from `git config starforge.server`; then the missing token
    // fails with the login hint. Empty home, no `STARFORGE_TOKEN`.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let body = serde_json::json!({
        "starforge": "test",
        "api_url": base_url,
        "ssh_url": "ssh://git@example.com:2222",
    });
    let app = Router::new().route(
        "/.well-known/starforge.json",
        get({
            let body = body.clone();
            move || {
                let body = body.clone();
                async move { axum::Json(body) }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let home = TempDir::new().unwrap();
    let path = bin_path();
    let (_dir, repo) = init_repo(home.path(), &path);
    git_ok(
        &repo,
        &["config", "starforge.server", &base_url],
        home.path(),
        &path,
    );

    let out = hermetic_command("starforge", home.path())
        .current_dir(&repo)
        .args(["trail", "list"])
        .env("PATH", &path)
        .output()
        .expect("starforge runs");
    assert_eq!(out.status.code(), Some(1), "trail list exits 1");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("starforge auth login"),
        "login hint: {combined}"
    );
    assert!(
        !combined.contains(TOKEN),
        "no token-shaped text: {combined}"
    );
}
