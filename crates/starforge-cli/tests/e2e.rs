//! C7 end-to-end + carry-in tests (TDD RED first).
//!
//! - `heuristic_link_expires_after_first_link`: session links once, then a
//!   second unrelated commit gets NO trailer (carry-in fix 1: per-session
//!   link watermark).
//! - `enable_disable_wire_agent_hooks`: `enable` installs agent adapter hooks
//!   under `<home>/.config`, `disable` removes them (carry-in fix 2).
//! - `enable_commit_sync_end_to_end`: temp repo + temp `STARFORGE_HOME`,
//!   fixture Pi session, `enable`, commit a touched file (exactly one trailer),
//!   `sync` against an in-process stub (metadata fingerprint, redacted
//!   segment, links carrying the commit SHA).
//! - `pre_push_best_effort_*`: the `_hook-pre-push` body uploads when the
//!   server is reachable and still exits 0 with the queue intact when it is
//!   not (carry-in fix 3).
//!
//! No network beyond `127.0.0.1`, no real `$HOME` (every path is injected via
//! tempdirs and explicit `CliPaths`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post, put},
};
use starforge_capture::{Adapter, Candidate, Cursor, agents::pi::PiAdapter};
use starforge_cli::commands::hooks::{self, hook_post_commit, hook_prepare};
use starforge_cli::config::CliPaths;
use starforge_cli::discovery::ServerInfo;
use starforge_cli::git::common_dir;
use starforge_cli::queue::{QueueEntry, QueueOp, Sleeper, enqueue, read_queue};
use starforge_cli::spool::Spool;
use tempfile::TempDir;

mod common;

use common::hermetic_command;

const TOKEN: &str = "test-token";
const PAST: &str = "2026-01-01T00:00:00Z";
const NOW: &str = "2026-11-04T00:00:00Z";

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git runs")
}

fn git_ok(repo: &Path, args: &[&str]) -> String {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn init_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init"]);
    git_ok(&repo, &["config", "user.email", "t@t.t"]);
    git_ok(&repo, &["config", "user.name", "t"]);
    git_ok(&repo, &["commit", "--allow-empty", "-m", "init"]);
    (dir, repo)
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi-session.jsonl")
}

/// Seed one spool session from the real Pi fixture, redacted with the repo
/// rules. Returns the ULID plus the expected redaction fingerprint.
fn seed_spool_from_fixture(spool: &Spool, repo: &Path) -> (String, String) {
    let native = fixture_path();
    let candidate = Candidate {
        session_key: "pi-e2e".to_string(),
        native_path: native.clone(),
        agent_version: String::new(),
        workdir: PathBuf::from("/work/repo"),
        parent_session_key: None,
    };
    let out = PiAdapter
        .read(&candidate, &Cursor::start(), "2026-10-01T12:03:00Z")
        .unwrap();
    assert!(out.events.len() >= 3, "fixture must yield 3+ events");

    let (rules, compiled) = Spool::load_rules(repo).unwrap();
    let expected_fp = starforge_redact::fingerprint(&rules);

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut lines = Vec::new();
    for event in &out.events {
        let (redacted, c) = starforge_redact::redact_event(&compiled, event);
        for (k, v) in c {
            *counts.entry(k).or_insert(0) += v;
        }
        lines.push(serde_json::to_string(&redacted).unwrap());
    }
    let jsonl = lines.join("\n") + "\n";
    assert!(!jsonl.contains("ghp_"), "seeded JSONL must be redacted");

    let mut meta = out.header;
    meta.id = ulid::Ulid::new();
    meta.repo = starforge_format::RepoInfo {
        remote_urls: vec!["https://example.com/o/r".to_string()],
        branch: "main".to_string(),
        head_at_start: "abc".to_string(),
    };
    meta.files_touched = vec!["src/lib.rs".to_string()];
    meta.redaction = starforge_format::RedactionSummary {
        fingerprint: expected_fp.clone(),
        counts: counts.clone(),
    };
    let ulid = meta.id.to_string();
    spool.put_session(&meta).unwrap();
    let nums = spool
        .append_events(
            &ulid,
            &jsonl,
            starforge_format::DEFAULT_SEGMENT_CAP,
            &counts,
        )
        .unwrap();
    assert_eq!(nums, vec![0], "one segment expected");
    (ulid, expected_fp)
}

#[derive(Default)]
struct FakeSleeper;

impl Sleeper for FakeSleeper {
    async fn sleep(&self, _dur: std::time::Duration) {}
}

// ---------------------------------------------------------------------------
// Stub server: well-known + the four §7.5 endpoints, recording requests.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Recorded {
    path: String,
    body: Vec<u8>,
}

struct StubInner {
    requests: Vec<Recorded>,
}

type Shared = Arc<Mutex<StubInner>>;

struct Stub {
    state: Shared,
    base_url: String,
}

impl Stub {
    fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            api_url: self.base_url.clone(),
            ssh_url: "ssh://git@example.com:2222".to_string(),
            version: "test".to_string(),
        }
    }
}

fn record(state: &Shared, uri: &Uri, body: &[u8]) {
    state.lock().unwrap().requests.push(Recorded {
        path: uri.path().to_string(),
        body: body.to_vec(),
    });
}

async fn put_meta(
    State(state): State<Shared>,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::CREATED, "created").into_response()
}

async fn put_segment(
    State(state): State<Shared>,
    uri: Uri,
    AxPath((_owner, _repo, _ulid, _n)): AxPath<(String, String, String, u64)>,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::OK, "ok").into_response()
}

async fn post_complete(State(state): State<Shared>, uri: Uri, body: Bytes) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::OK, "ok").into_response()
}

async fn post_links(State(state): State<Shared>, uri: Uri, body: Bytes) -> impl IntoResponse {
    record(&state, &uri, &body);
    (StatusCode::OK, "ok").into_response()
}

async fn start_stub() -> Stub {
    let state: Shared = Arc::new(Mutex::new(StubInner {
        requests: Vec::new(),
    }));
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
// Carry-in fix 1: heuristic linking expires after the first link.
// ---------------------------------------------------------------------------

#[test]
fn heuristic_link_expires_after_first_link() {
    let (_dir, repo) = init_repo();
    // Isolated home: ingest finds no native stores, so the seeded spool is
    // the only session source.
    let home = TempDir::new().unwrap();
    let paths = CliPaths::from_home(home.path().to_path_buf());
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let (ulid, _fp) = seed_spool_from_fixture(&spool, &repo);

    // First commit touches a file the session touched: exactly one trailer.
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git_ok(&repo, &["add", "src/lib.rs"]);
    let msg1 = repo.join(".git/MSG1");
    std::fs::write(&msg1, "first\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg1, &paths), 0);
    let body = std::fs::read_to_string(&msg1).unwrap();
    assert_eq!(
        body.lines()
            .filter(|l| l.starts_with("Starforge-Session:"))
            .count(),
        1,
        "first commit must carry exactly one trailer: {body:?}"
    );
    git_ok(
        &repo,
        &["commit", "--no-verify", "-F", msg1.to_str().unwrap()],
    );
    assert_eq!(hook_post_commit(&repo, &paths), 0);

    // The link watermark records what the link covered.
    let watermark = spool.read_link_watermark(&ulid).unwrap();
    assert!(
        watermark.is_some(),
        "post-commit must write sessions/<ulid>/link-watermark.json"
    );
    assert_eq!(spool.links().unwrap().len(), 1);

    // Second, unrelated commit: no new session activity -> NO trailer.
    std::fs::write(repo.join("UNRELATED.txt"), "unrelated\n").unwrap();
    git_ok(&repo, &["add", "UNRELATED.txt"]);
    let msg2 = repo.join(".git/MSG2");
    std::fs::write(&msg2, "second\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg2, &paths), 0);
    let body2 = std::fs::read_to_string(&msg2).unwrap();
    assert!(
        !body2.contains("Starforge-Session:"),
        "unrelated commit must not gain a trailer after the watermark: {body2:?}"
    );
}

// ---------------------------------------------------------------------------
// Carry-in fix 2: enable/disable wire agent adapter hooks.
// ---------------------------------------------------------------------------

#[test]
fn enable_disable_wire_agent_hooks() {
    let (_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let paths = CliPaths::from_home(home.path().to_path_buf());
    // `enable` only writes agent config for detected agents; give Claude a
    // store marker so its hooks are wired.
    std::fs::create_dir_all(home.path().join(".claude").join("projects").join("proj")).unwrap();

    let (out, code) = hooks::enable(&repo, &paths, false);
    assert_eq!(code, 0, "enable output: {out}");
    let claude_hook = home.path().join(".claude/settings.json");
    assert!(
        claude_hook.is_file(),
        "enable must install .claude/settings.json: {out}"
    );
    assert!(
        out.contains(&claude_hook.display().to_string()),
        "enable must print every touched path: {out}"
    );
    let body = std::fs::read_to_string(&claude_hook).unwrap();
    assert!(
        body.contains("starforge hook session-end"),
        "enable must install the SessionEnd command: {body:?}"
    );

    let (out, code) = hooks::disable(&repo, &paths, false);
    assert_eq!(code, 0, "disable output: {out}");
    let body = std::fs::read_to_string(&claude_hook).unwrap_or_default();
    assert!(
        !body.contains("starforge"),
        "disable must remove the starforge hook command: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// End to end: enable -> commit -> sync.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enable_commit_sync_end_to_end() {
    let (_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let paths = CliPaths::from_home(home.path().to_path_buf());

    // The spool session is seeded directly below; no native fixture is placed
    // under the fake home, so ingest stays a no-op and cannot double-seed.
    // (The ingest-driven path is covered by tests/ingest.rs and the
    // real-binary e2e.)

    let (out, code) = hooks::enable(&repo, &paths, false);
    assert_eq!(code, 0, "enable output: {out}");

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    let (ulid, expected_fp) = seed_spool_from_fixture(&spool, &repo);

    // Commit a file the session touched through the prepare hook.
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git_ok(&repo, &["add", "src/lib.rs"]);
    let msg = repo.join(".git/COMMIT_MSG");
    std::fs::write(&msg, "touch lib\n").unwrap();
    assert_eq!(hook_prepare(&repo, &msg, &paths), 0);
    let body = std::fs::read_to_string(&msg).unwrap();
    let trailers: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("Starforge-Session:"))
        .collect();
    assert_eq!(
        trailers,
        vec![format!("Starforge-Session: {ulid}")],
        "body: {body:?}"
    );
    // `--no-verify` still runs `prepare-commit-msg`; keep its ingest on the
    // test home instead of the real one.
    let out = hermetic_command("git", home.path())
        .arg("-C")
        .arg(&repo)
        .args(["commit", "--no-verify", "-F", msg.to_str().unwrap()])
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sha = git_ok(&repo, &["rev-parse", "HEAD"]);
    let sha = sha.trim().to_string();
    assert_eq!(hook_post_commit(&repo, &paths), 0);

    // Point the repo at the stub and sync: `sync` derives Meta/Segment/Links
    // from spool state (no pre-seeded queue).
    let stub = start_stub().await;
    git_ok(
        &repo,
        &["remote", "add", "origin", &format!("{}/o/r", stub.base_url)],
    );
    let server = stub.server_info();
    let owner_repo = "o/r".to_string();

    let summary = starforge_cli::commands::sync::sync(
        &spool,
        &server,
        &owner_repo,
        TOKEN,
        &FakeSleeper,
        NOW,
        false,
    )
    .await
    .unwrap();
    assert_eq!(summary.exit_code(), 0, "sync must drain");
    assert!(read_queue(&spool).unwrap().is_empty());

    let reqs = stub.requests();
    assert_eq!(reqs.len(), 3, "meta + segment + links: {reqs:?}");

    let meta: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(meta["id"], ulid);
    assert_eq!(meta["redaction"]["fingerprint"], expected_fp);

    let seg_bytes = &reqs[1].body;
    let seg_text = String::from_utf8(starforge_format::decompress(seg_bytes).unwrap()).unwrap();
    assert!(!seg_text.contains("ghp_"), "segment must be redacted");
    assert!(
        seg_text.contains("[redacted:known-token]"),
        "segment must carry the marker: {seg_text:?}"
    );

    let links: serde_json::Value = serde_json::from_slice(&reqs[2].body).unwrap();
    let commits: Vec<&str> = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["commit"].as_str().unwrap())
        .collect();
    assert_eq!(
        commits,
        vec![sha.as_str()],
        "links must carry the commit SHA"
    );
}

// ---------------------------------------------------------------------------
// Carry-in fix 3: pre-push attempts the upload without blocking the push.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pre_push_best_effort_uploads_when_reachable() {
    let (_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let paths = CliPaths::from_home(home.path().to_path_buf());
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let (ulid, _fp) = seed_spool_from_fixture(&spool, &repo);

    let stub = start_stub().await;
    git_ok(&repo, &["config", "starforge.server", &stub.base_url]);
    git_ok(&repo, &["config", "starforge.repo", "o/r"]);
    enqueue(
        &spool,
        QueueEntry {
            op: QueueOp::Segment,
            ulid: ulid.clone(),
            repo: "o/r".to_string(),
            segment: Some(0),
            attempts: 0,
            not_before: PAST.to_string(),
        },
    )
    .unwrap();

    let code = hooks::hook_pre_push_full(&repo, &paths, |_| Some(TOKEN.to_string())).await;
    assert_eq!(code, 0, "pre-push always exits 0");
    assert!(
        stub.requests()
            .iter()
            .any(|r| r.path.contains("/segments/0")),
        "reachable pre-push must attempt the segment upload: {:?}",
        stub.requests()
    );
    assert!(
        read_queue(&spool).unwrap().is_empty(),
        "uploaded entry must drain"
    );
}

#[tokio::test]
async fn pre_push_unreachable_leaves_queue_and_exits_zero() {
    let (_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let paths = CliPaths::from_home(home.path().to_path_buf());
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let (ulid, _fp) = seed_spool_from_fixture(&spool, &repo);

    // A port on localhost that is (almost surely) closed.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    git_ok(
        &repo,
        &[
            "config",
            "starforge.server",
            &format!("http://127.0.0.1:{closed}"),
        ],
    );
    git_ok(&repo, &["config", "starforge.repo", "o/r"]);
    enqueue(
        &spool,
        QueueEntry {
            op: QueueOp::Segment,
            ulid: ulid.clone(),
            repo: "o/r".to_string(),
            segment: Some(0),
            attempts: 0,
            not_before: PAST.to_string(),
        },
    )
    .unwrap();

    let code = hooks::hook_pre_push_full(&repo, &paths, |_| Some(TOKEN.to_string())).await;
    assert_eq!(code, 0, "pre-push never fails the push");
    assert_eq!(
        read_queue(&spool).unwrap().len(),
        1,
        "failed best-effort entry stays queued"
    );
}

// Finding 3: `--dry-run` resolves the ULID prefix first, so a typo'd prefix
// fails the same way in both modes (still writing nothing).

#[test]
fn sessions_link_unlink_dry_run_rejects_unknown_prefix() {
    let (_dir, repo) = init_repo();
    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();

    let (out, code) = starforge_cli::commands::sessions::link(&repo, "deadbeef", None, true);
    assert_eq!(code, 1, "dry-run link with unknown prefix fails: {out}");
    let (out, code) = starforge_cli::commands::sessions::unlink(&repo, "deadbeef", "abc", true);
    assert_eq!(code, 1, "dry-run unlink with unknown prefix fails: {out}");

    // And an ambiguous prefix names the candidates.
    let (out, code) = starforge_cli::commands::sessions::link(&repo, "", None, true);
    assert_eq!(
        code, 1,
        "empty spool resolves to unknown, not a link: {out}"
    );
}
