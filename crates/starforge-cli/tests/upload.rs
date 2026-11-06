//! C6 upload client + `sync` tests (TDD RED first).
//!
//! An in-process axum stub implements the four wire endpoints (`PUT`
//! sessions, `PUT` segments, `POST` complete, `POST` links) and records every
//! request (method/path/headers/body). Tempdir spools are pre-seeded via the
//! spool API; segment bytes are never re-derived from native transcripts.
//! Backoff uses an injected fake [`Sleeper`]: no real sleeps.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    routing::{post, put},
};
use tempfile::TempDir;

use starforge_cli::discovery::ServerInfo;
use starforge_cli::queue::{QueueEntry, QueueOp, Sleeper, enqueue, read_queue};
use starforge_cli::spool::{LinkConfidence, LinkEntry, LinkSource, Spool};
use starforge_cli::upload::UploadError;

const NOW: &str = "2026-11-04T00:00:00Z";
const PAST: &str = "2026-01-01T00:00:00Z";
const OWNER_REPO: &str = "o/r";
const TOKEN: &str = "test-token";
const COMMIT: &str = "abc123def456abc123def456abc123def456abc1";

fn open_spool() -> (TempDir, Spool) {
    let dir = TempDir::new().unwrap();
    let spool = Spool::open(dir.path());
    spool.ensure_layout().unwrap();
    (dir, spool)
}

fn test_meta(ended: bool) -> starforge_format::SessionMeta {
    starforge_format::SessionMeta {
        format: starforge_format::FORMAT_TAG.to_string(),
        id: ulid::Ulid::new(),
        agent: starforge_format::Agent {
            name: starforge_format::AgentName::Pi,
            version: "test".to_string(),
        },
        models: Vec::new(),
        title: None,
        started_at: "2026-11-01T00:00:00Z".to_string(),
        ended_at: ended.then(|| "2026-11-02T00:00:00Z".to_string()),
        repo: starforge_format::RepoInfo {
            remote_urls: vec!["https://example.com/o/r".to_string()],
            branch: "main".to_string(),
            head_at_start: "abc".to_string(),
        },
        parent_id: None,
        usage: starforge_format::Usage::default(),
        files_touched: Vec::new(),
        redaction: starforge_format::RedactionSummary {
            fingerprint: "fp-test".to_string(),
            counts: BTreeMap::new(),
        },
        capture: starforge_format::CaptureInfo::default(),
    }
}

/// Seed one session with `n_segments` single-event segments. Returns the meta
/// plus the exact compressed segment bytes.
fn seed_session(
    spool: &Spool,
    ended: bool,
    n_segments: u64,
) -> (starforge_format::SessionMeta, Vec<Vec<u8>>) {
    let meta = test_meta(ended);
    spool.put_session(&meta).unwrap();
    let ulid = meta.id.to_string();
    for i in 0..n_segments {
        let jsonl = format!("{{\"seq\":{i},\"kind\":\"assistant\",\"text\":\"hello {i}\"}}\n");
        let nums = spool
            .append_events(&ulid, &jsonl, usize::MAX, &BTreeMap::new())
            .unwrap();
        assert_eq!(nums, vec![i], "one segment per append");
    }
    let mut blobs = Vec::new();
    for n in 0..n_segments {
        blobs.push(spool.segment_bytes(&ulid, n).unwrap());
    }
    (meta, blobs)
}

fn seed_link(spool: &Spool, ulid: &str) {
    spool
        .record_link(&LinkEntry {
            ulid: ulid.to_string(),
            commit: COMMIT.to_string(),
            source: LinkSource::Trailer,
            confidence: LinkConfidence::Exact,
            seq_start: 0,
            seq_end: 1,
        })
        .unwrap();
}

fn seed_entry(spool: &Spool, op: QueueOp, ulid: &str, segment: Option<u64>) {
    enqueue(
        spool,
        QueueEntry {
            op,
            ulid: ulid.to_string(),
            repo: OWNER_REPO.to_string(),
            segment,
            attempts: 0,
            not_before: PAST.to_string(),
        },
    )
    .unwrap();
}

/// Fake sleeper: records every requested duration, never sleeps.
#[derive(Default)]
struct FakeSleeper {
    sleeps: Mutex<Vec<Duration>>,
}

impl Sleeper for FakeSleeper {
    async fn sleep(&self, dur: Duration) {
        self.sleeps.lock().unwrap().push(dur);
    }
}

impl FakeSleeper {
    fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Stub server.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StubConfig {
    require_token: String,
    /// Fail the first segment PUT with 500, then succeed.
    fail_first_segment_500: bool,
    /// Answer segment `n` with 409.
    conflict_segment: Option<u64>,
    /// When true the 409 body carries the request's own hash (idempotent
    /// re-upload); otherwise it carries a different hash (real conflict).
    conflict_same_hash: bool,
}

impl StubConfig {
    fn ok() -> Self {
        Self {
            require_token: TOKEN.to_string(),
            fail_first_segment_500: false,
            conflict_segment: None,
            conflict_same_hash: false,
        }
    }
}

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    auth: Option<String>,
    blake3: Option<String>,
    body: Vec<u8>,
}

struct StubInner {
    requests: Vec<Recorded>,
    config: StubConfig,
    segment_puts: usize,
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

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn record(
    state: &Shared,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> StubConfig {
    let mut inner = state.lock().unwrap();
    inner.requests.push(Recorded {
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        auth: header(headers, "authorization"),
        blake3: header(headers, "x-starforge-blake3"),
        body: body.to_vec(),
    });
    inner.config.clone()
}

fn authorized(config: &StubConfig, headers: &HeaderMap) -> bool {
    header(headers, "authorization").as_deref() == Some(&format!("Bearer {}", config.require_token))
}

async fn put_meta(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let config = record(&state, &method, &uri, &headers, &body);
    if !authorized(&config, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::CREATED, "created").into_response()
}

async fn put_segment(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    Path((_owner, _repo, _ulid, n)): Path<(String, String, String, u64)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let config = record(&state, &method, &uri, &headers, &body);
    if !authorized(&config, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if config.conflict_segment == Some(n) {
        let stored = if config.conflict_same_hash {
            starforge_format::blake3_hex(&body)
        } else {
            "0".repeat(64)
        };
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({ "hash": stored })),
        )
            .into_response();
    }
    let mut inner = state.lock().unwrap();
    if config.fail_first_segment_500 && inner.segment_puts == 0 {
        inner.segment_puts += 1;
        return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }
    inner.segment_puts += 1;
    (StatusCode::OK, "ok").into_response()
}

async fn post_complete(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let config = record(&state, &method, &uri, &headers, &body);
    if !authorized(&config, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

async fn post_links(
    State(state): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let config = record(&state, &method, &uri, &headers, &body);
    if !authorized(&config, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

async fn start_stub(config: StubConfig) -> Stub {
    let state = Arc::new(Mutex::new(StubInner {
        requests: Vec::new(),
        config,
        segment_puts: 0,
    }));
    let app = Router::new()
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Stub {
        state,
        base_url: format!("http://{addr}"),
    }
}

/// A port on localhost that is (almost surely) closed, for the down-stub case.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn run_sync(
    spool: &Spool,
    server: &ServerInfo,
    token: &str,
    sleeper: &FakeSleeper,
    dry_run: bool,
) -> Result<starforge_cli::commands::sync::SyncSummary, UploadError> {
    starforge_cli::commands::sync::sync(spool, server, OWNER_REPO, token, sleeper, NOW, dry_run)
        .await
}

// ---------------------------------------------------------------------------
// (a) Full drain: queue empties, hashes pinned, request order + bodies.
// (f) Segment requests carry X-Starforge-Blake3 == blake3(body).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_drain_empties_queue_records_hashes_and_orders_requests() {
    let (_tmp, spool) = open_spool();
    let (meta, blobs) = seed_session(&spool, true, 2);
    let ulid = meta.id.to_string();
    seed_link(&spool, &ulid);
    seed_entry(&spool, QueueOp::Meta, &ulid, None);
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(1));
    seed_entry(&spool, QueueOp::Complete, &ulid, None);
    seed_entry(&spool, QueueOp::Links, &ulid, None);

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();

    assert_eq!(summary.uploaded, 5, "every op uploaded");
    assert_eq!(summary.exit_code(), 0, "drained");
    assert!(read_queue(&spool).unwrap().is_empty(), "queue drained");
    assert!(sleeper.sleeps().is_empty(), "no backoff on success");

    let state = spool.read_upload(&ulid).unwrap();
    assert_eq!(
        state.uploaded_segments.get(&0).unwrap(),
        &starforge_format::blake3_hex(&blobs[0]),
        "segment 0 hash pinned"
    );
    assert_eq!(
        state.uploaded_segments.get(&1).unwrap(),
        &starforge_format::blake3_hex(&blobs[1]),
        "segment 1 hash pinned"
    );
    assert!(state.complete, "complete recorded");

    let reqs = stub.requests();
    assert_eq!(reqs.len(), 5, "exactly one call per op");
    let session = format!("/api/v1/repos/{OWNER_REPO}/sessions/{ulid}");
    assert_eq!(
        reqs.iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("PUT", session.as_str()),
            ("PUT", format!("{session}/segments/0").as_str()),
            ("PUT", format!("{session}/segments/1").as_str()),
            ("POST", format!("{session}/complete").as_str()),
            ("POST", format!("{session}/links").as_str()),
        ],
        "request order is metadata -> segments -> complete -> links"
    );

    let meta_body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(meta_body["id"], ulid, "metadata body carries the id");
    assert_eq!(
        meta_body["agent"]["name"], "pi",
        "metadata body carries agent.name"
    );
    assert_eq!(
        meta_body["redaction"]["fingerprint"], "fp-test",
        "metadata body carries redaction.fingerprint"
    );

    for (req, blob) in [&reqs[1], &reqs[2]].iter().zip(blobs.iter()) {
        assert_eq!(&req.body, blob, "segment body equals the spool bytes");
        assert_eq!(
            req.blake3.as_deref().unwrap(),
            &starforge_format::blake3_hex(blob),
            "X-Starforge-Blake3 equals blake3 of the body bytes"
        );
    }

    let complete_body: serde_json::Value = serde_json::from_slice(&reqs[3].body).unwrap();
    assert_eq!(
        complete_body,
        serde_json::json!({}),
        "complete body is {{}}"
    );

    let links_body: serde_json::Value = serde_json::from_slice(&reqs[4].body).unwrap();
    let links = links_body["links"].as_array().unwrap();
    assert!(
        links.iter().any(|l| l["commit"] == COMMIT),
        "links body carries the commit SHA"
    );

    for req in &reqs {
        assert_eq!(
            req.auth.as_deref().unwrap(),
            format!("Bearer {TOKEN}"),
            "bearer auth on every call"
        );
    }
}

// ---------------------------------------------------------------------------
// (b) A second sync after a full drain performs zero HTTP calls.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_sync_after_drain_performs_zero_calls() {
    let (_tmp, spool) = open_spool();
    let (meta, _blobs) = seed_session(&spool, true, 1);
    let ulid = meta.id.to_string();
    seed_entry(&spool, QueueOp::Meta, &ulid, None);
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));
    seed_entry(&spool, QueueOp::Complete, &ulid, None);

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let first = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();
    assert_eq!(first.exit_code(), 0);
    let calls_after_first = stub.requests().len();
    assert!(calls_after_first > 0);

    let sleeper2 = FakeSleeper::default();
    let second = starforge_cli::commands::sync::sync(
        &spool, &server, OWNER_REPO, TOKEN, &sleeper2, NOW, false,
    )
    .await
    .unwrap();
    assert_eq!(second.uploaded, 0, "nothing left to upload");
    assert_eq!(second.exit_code(), 0);
    assert_eq!(
        stub.requests().len(),
        calls_after_first,
        "second sync performs zero HTTP calls"
    );
    assert!(sleeper2.sleeps().is_empty());
}

// ---------------------------------------------------------------------------
// (c) 409 with a different hash: Conflict, entry queued with bumped attempts.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn conflict_with_different_hash_keeps_entry_queued() {
    let (_tmp, spool) = open_spool();
    let (meta, _blobs) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    // Open session with metadata already recorded: only the segment op runs.
    let meta_hash = starforge_format::blake3_hex(&serde_json::to_vec(&meta).unwrap());
    spool.mark_meta_uploaded(&ulid, meta_hash).unwrap();
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));

    let stub = start_stub(StubConfig {
        conflict_segment: Some(0),
        ..StubConfig::ok()
    })
    .await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();

    assert!(summary.conflict, "conflict surfaces");
    assert_eq!(summary.exit_code(), 2, "remainder stays queued");
    assert_eq!(stub.requests().len(), 1, "no blind retry on conflict");
    let queued = read_queue(&spool).unwrap();
    assert_eq!(queued.len(), 1, "entry stays queued");
    assert_eq!(queued[0].attempts, 1, "attempts bumped");
    assert_eq!(
        queued[0].not_before, "2026-11-04T00:00:02Z",
        "not_before = now + 2^1"
    );
    let state = spool.read_upload(&ulid).unwrap();
    assert!(
        !state.uploaded_segments.contains_key(&0),
        "conflicted segment is not marked uploaded"
    );
}

// ---------------------------------------------------------------------------
// (d) 500 then success: exactly one retry with the expected backoff.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transient_500_retries_once_with_backoff_then_drains() {
    let (_tmp, spool) = open_spool();
    let (meta, blobs) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    // Open session with metadata already recorded: `sync` derives nothing, so
    // this test exercises exactly one segment op (500 then success).
    let meta_hash = starforge_format::blake3_hex(&serde_json::to_vec(&meta).unwrap());
    spool.mark_meta_uploaded(&ulid, meta_hash).unwrap();
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));
    let stub = start_stub(StubConfig {
        fail_first_segment_500: true,
        ..StubConfig::ok()
    })
    .await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();

    assert_eq!(summary.exit_code(), 0, "retry succeeds");
    assert!(read_queue(&spool).unwrap().is_empty());
    assert_eq!(
        sleeper.sleeps(),
        vec![Duration::from_secs(2)],
        "exactly one backoff sleep of 2^1 seconds"
    );
    assert_eq!(stub.requests().len(), 2, "one failure plus one retry");
    let state = spool.read_upload(&ulid).unwrap();
    assert_eq!(
        state.uploaded_segments.get(&0).unwrap(),
        &starforge_format::blake3_hex(&blobs[0])
    );
}

// ---------------------------------------------------------------------------
// (e) 401: clear auth message, entry still queued.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_failure_reports_login_and_keeps_entry_queued() {
    let (_tmp, spool) = open_spool();
    let (meta, _blobs) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    // Segment already recorded: only the Meta op runs (and fails auth).
    spool.mark_segment_uploaded(&ulid, 0).unwrap();
    seed_entry(&spool, QueueOp::Meta, &ulid, None);
    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let err = run_sync(&spool, &server, "wrong-token", &sleeper, false)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("starforge auth login"),
        "clear auth message, got: {err}"
    );
    assert!(
        matches!(err, UploadError::Auth { .. }),
        "auth variant, got: {err:?}"
    );
    let queued = read_queue(&spool).unwrap();
    assert_eq!(queued.len(), 1, "entry still queued");
    assert_eq!(queued[0].attempts, 0, "auth failure does not bump attempts");
}

// ---------------------------------------------------------------------------
// 409 carrying the request's own hash is an idempotent success.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn conflict_with_identical_hash_counts_as_success() {
    let (_tmp, spool) = open_spool();
    let (meta, blobs) = seed_session(&spool, true, 1);
    let ulid = meta.id.to_string();
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));

    let stub = start_stub(StubConfig {
        conflict_segment: Some(0),
        conflict_same_hash: true,
        ..StubConfig::ok()
    })
    .await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();

    assert!(!summary.conflict);
    assert_eq!(summary.exit_code(), 0);
    assert!(read_queue(&spool).unwrap().is_empty());
    let state = spool.read_upload(&ulid).unwrap();
    assert_eq!(
        state.uploaded_segments.get(&0).unwrap(),
        &starforge_format::blake3_hex(&blobs[0]),
        "identical-hash 409 marks the segment uploaded"
    );
}

// ---------------------------------------------------------------------------
// `--dry-run`: lists ops, performs zero calls, writes nothing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dry_run_lists_ops_without_calls_or_writes() {
    let (_tmp, spool) = open_spool();
    let (meta, _blobs) = seed_session(&spool, true, 1);
    let ulid = meta.id.to_string();
    seed_entry(&spool, QueueOp::Meta, &ulid, None);
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));
    seed_entry(&spool, QueueOp::Complete, &ulid, None);

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, true)
        .await
        .unwrap();

    assert_eq!(stub.requests().len(), 0, "dry run performs zero calls");
    assert_eq!(read_queue(&spool).unwrap().len(), 3, "queue untouched");
    assert!(
        spool
            .read_upload(&ulid)
            .unwrap()
            .uploaded_segments
            .is_empty(),
        "upload.json untouched"
    );
    assert_eq!(summary.planned.len(), 3, "dry run lists every due op");
    assert!(sleeper.sleeps().is_empty());
}

// ---------------------------------------------------------------------------
// Best-effort wrapper (pre-push path): returns even when the stub is down.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn best_effort_returns_with_stub_down() {
    let (_tmp, spool) = open_spool();
    let (meta, _blobs) = seed_session(&spool, true, 1);
    let ulid = meta.id.to_string();
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));

    let server = ServerInfo {
        api_url: format!("http://127.0.0.1:{}", closed_port()),
        ssh_url: "ssh://git@example.com:2222".to_string(),
        version: "test".to_string(),
    };
    let sleeper = FakeSleeper::default();
    let summary = starforge_cli::commands::sync::sync_best_effort(
        &spool, &server, OWNER_REPO, TOKEN, &sleeper, NOW,
    )
    .await;

    // The best-effort pass reconciles before draining, so every unsent
    // operation for the ended session is queued and survives the failure:
    // meta, the one segment, and complete (nothing is lost, nothing extra).
    let mut queued: Vec<(QueueOp, Option<u64>)> = read_queue(&spool)
        .unwrap()
        .into_iter()
        .map(|e| {
            assert_eq!(e.ulid, ulid, "only the seeded session is queued");
            (e.op, e.segment)
        })
        .collect();
    queued.sort_by_key(|(op, seg)| (format!("{op:?}"), *seg));
    assert_eq!(
        queued,
        vec![
            (QueueOp::Complete, None),
            (QueueOp::Meta, None),
            (QueueOp::Segment, Some(0)),
        ],
        "every unsent op stays queued after a swallowed failure"
    );
    assert!(sleeper.sleeps().is_empty(), "best effort never backs off");
    let _ = summary;
}

// ---------------------------------------------------------------------------
// Already-uploaded segments (same hash in upload.json) are skipped quietly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn already_uploaded_segment_is_skipped_without_http() {
    let (_tmp, spool) = open_spool();
    let (meta, blobs) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    // Everything already recorded: `sync` derives nothing, zero HTTP.
    let meta_hash = starforge_format::blake3_hex(&serde_json::to_vec(&meta).unwrap());
    spool.mark_meta_uploaded(&ulid, meta_hash).unwrap();
    spool.mark_segment_uploaded(&ulid, 0).unwrap();
    assert_eq!(
        spool.read_upload(&ulid).unwrap().uploaded_segments[&0],
        starforge_format::blake3_hex(&blobs[0])
    );
    seed_entry(&spool, QueueOp::Segment, &ulid, Some(0));

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();

    assert_eq!(summary.exit_code(), 0);
    assert_eq!(summary.skipped, 1);
    assert!(read_queue(&spool).unwrap().is_empty());
    assert_eq!(stub.requests().len(), 0, "no HTTP for recorded segments");
}
// ---------------------------------------------------------------------------
// Fix round 1: `sync` derives work from spool state. A session with meta + two
// segments + one link and an EMPTY queue still uploads everything in canonical
// order, records it in `upload.json`, and goes quiet on the second run.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_derives_missing_work_from_spool_state() {
    let (_tmp, spool) = open_spool();
    let (meta, blobs) = seed_session(&spool, true, 2);
    let ulid = meta.id.to_string();
    seed_link(&spool, &ulid);
    assert!(
        read_queue(&spool).unwrap().is_empty(),
        "no queue entries seeded"
    );

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();

    assert_eq!(summary.uploaded, 5, "meta + 2 segments + complete + links");
    assert_eq!(summary.exit_code(), 0, "drained");
    assert!(read_queue(&spool).unwrap().is_empty(), "queue drained");

    let session = format!("/api/v1/repos/{OWNER_REPO}/sessions/{ulid}");
    let reqs = stub.requests();
    assert_eq!(
        reqs.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec![
            session.as_str(),
            format!("{session}/segments/0").as_str(),
            format!("{session}/segments/1").as_str(),
            format!("{session}/complete").as_str(),
            format!("{session}/links").as_str(),
        ],
        "canonical order without any pre-seeded queue"
    );

    let state = spool.read_upload(&ulid).unwrap();
    let expected_meta = starforge_format::blake3_hex(
        &serde_json::to_vec(&spool.read_meta(&ulid).unwrap()).unwrap(),
    );
    assert_eq!(state.meta_hash.as_deref(), Some(expected_meta.as_str()));
    assert_eq!(
        state.uploaded_segments.get(&0).unwrap(),
        &starforge_format::blake3_hex(&blobs[0])
    );
    assert_eq!(
        state.uploaded_segments.get(&1).unwrap(),
        &starforge_format::blake3_hex(&blobs[1])
    );
    assert!(state.complete, "complete recorded");
    assert_eq!(state.sent_links.len(), 1, "one links line recorded as sent");

    let before = stub.requests().len();
    let summary2 = run_sync(&spool, &server, TOKEN, &sleeper, false)
        .await
        .unwrap();
    assert_eq!(summary2.uploaded, 0, "nothing left to upload");
    assert_eq!(summary2.exit_code(), 0);
    assert_eq!(
        stub.requests().len(),
        before,
        "second sync makes zero requests"
    );
}
// ---------------------------------------------------------------------------
// Fix round 2: `sync_best_effort` reconciles first. A session whose `upload.json`
// records meta + segments as uploaded but whose meta then changed (ended_at set)
// with one unsent link line and an EMPTY queue still uploads PUT meta, POST
// complete, and POST links — the hook path must not need an explicit `sync`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn best_effort_reconciles_changed_meta_complete_and_links() {
    let (_tmp, spool) = open_spool();
    let (meta, _blobs) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    // Mark meta + segment as uploaded, then change the meta (ended_at set).
    let old_hash = starforge_format::blake3_hex(
        &serde_json::to_vec(&spool.read_meta(&ulid).unwrap()).unwrap(),
    );
    spool.mark_meta_uploaded(&ulid, old_hash).unwrap();
    spool.mark_segment_uploaded(&ulid, 0).unwrap();
    let mut ended = spool.read_meta(&ulid).unwrap();
    ended.ended_at = Some("2026-11-02T00:00:00Z".to_string());
    spool.put_session(&ended).unwrap();
    seed_link(&spool, &ulid);
    assert!(
        read_queue(&spool).unwrap().is_empty(),
        "no queue entries seeded"
    );

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = starforge_cli::commands::sync::sync_best_effort(
        &spool, &server, OWNER_REPO, TOKEN, &sleeper, NOW,
    )
    .await;

    let session = format!("/api/v1/repos/{OWNER_REPO}/sessions/{ulid}");
    let reqs = stub.requests();
    assert_eq!(
        reqs.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec![
            session.as_str(),
            format!("{session}/complete").as_str(),
            format!("{session}/links").as_str(),
        ],
        "no segment PUT (already uploaded); PUT meta, POST complete, POST links"
    );
    assert_eq!(summary.exit_code(), 0, "drained");
    assert!(read_queue(&spool).unwrap().is_empty(), "queue drained");

    let state = spool.read_upload(&ulid).unwrap();
    let new_hash = starforge_format::blake3_hex(
        &serde_json::to_vec(&spool.read_meta(&ulid).unwrap()).unwrap(),
    );
    assert_eq!(state.meta_hash.as_deref(), Some(new_hash.as_str()));
    assert!(state.complete, "complete recorded");
    assert_eq!(state.sent_links.len(), 1, "one links line recorded as sent");
}
// ---------------------------------------------------------------------------
// Trust depth: the hook pass trusts a recorded segment number without
// reading the file, even if the bytes on disk have since changed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn best_effort_trusts_recorded_segment_without_reading_it() {
    let (_tmp, spool) = open_spool();
    let (meta, bytes) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    let old_hash = starforge_format::blake3_hex(
        &serde_json::to_vec(&spool.read_meta(&ulid).unwrap()).unwrap(),
    );
    spool.mark_meta_uploaded(&ulid, old_hash).unwrap();
    spool.mark_segment_uploaded(&ulid, 0).unwrap();
    assert_eq!(
        spool.read_upload(&ulid).unwrap().uploaded_segments[&0],
        starforge_format::blake3_hex(&bytes[0])
    );
    let mut ended = spool.read_meta(&ulid).unwrap();
    ended.ended_at = Some("2026-11-02T00:00:00Z".to_string());
    spool.put_session(&ended).unwrap();
    seed_link(&spool, &ulid);
    // Corrupt the recorded segment file: trust must not notice or upload it.
    let seg_path = spool
        .root
        .join("sessions")
        .join(&ulid)
        .join("segments")
        .join("0.jsonl.zst");
    std::fs::write(&seg_path, b"completely different bytes").unwrap();
    assert!(
        read_queue(&spool).unwrap().is_empty(),
        "no queue entries seeded"
    );

    let stub = start_stub(StubConfig::ok()).await;
    let server = stub.server_info();
    let sleeper = FakeSleeper::default();
    let summary = starforge_cli::commands::sync::sync_best_effort(
        &spool, &server, OWNER_REPO, TOKEN, &sleeper, NOW,
    )
    .await;

    let session = format!("/api/v1/repos/{OWNER_REPO}/sessions/{ulid}");
    let reqs = stub.requests();
    assert!(
        reqs.iter().all(|r| !r.path.contains("/segments/")),
        "no segment PUT in the hook pass: {reqs:?}"
    );
    assert_eq!(
        reqs.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec![
            session.as_str(),
            format!("{session}/complete").as_str(),
            format!("{session}/links").as_str(),
        ],
        "PUT meta, POST complete, POST links: no segment read or upload"
    );
    assert_eq!(summary.exit_code(), 0, "drained");
    assert!(read_queue(&spool).unwrap().is_empty(), "queue drained");
}

// ---------------------------------------------------------------------------
// Contrast: a deep (`sync`) reconcile verifies recorded segments and
// re-enqueues the one whose bytes changed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deep_reconcile_reenqueues_recorded_segment_with_changed_bytes() {
    let (_tmp, spool) = open_spool();
    let (meta, bytes) = seed_session(&spool, false, 1);
    let ulid = meta.id.to_string();
    let meta_hash = starforge_format::blake3_hex(&serde_json::to_vec(&meta).unwrap());
    spool.mark_meta_uploaded(&ulid, meta_hash).unwrap();
    spool.mark_segment_uploaded(&ulid, 0).unwrap();
    assert_eq!(
        spool.read_upload(&ulid).unwrap().uploaded_segments[&0],
        starforge_format::blake3_hex(&bytes[0])
    );
    let seg_path = spool
        .root
        .join("sessions")
        .join(&ulid)
        .join("segments")
        .join("0.jsonl.zst");
    std::fs::write(&seg_path, b"completely different bytes").unwrap();
    assert!(
        read_queue(&spool).unwrap().is_empty(),
        "no queue entries seeded"
    );

    let added = starforge_cli::commands::sync::reconcile_queue(&spool, NOW).unwrap();
    assert_eq!(added, 1, "only the changed segment is re-enqueued");
    let queued = read_queue(&spool).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].op, QueueOp::Segment);
    assert_eq!(queued[0].ulid, ulid);
    assert_eq!(queued[0].segment, Some(0));
}

// ---------------------------------------------------------------------------
// Links grouping: `links.jsonl` is parsed once per reconcile. With link
// lines for two sessions (one already recorded as sent), only the session
// with an unsent line gets a `Links` entry.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconcile_enqueues_links_only_for_session_with_unsent_line() {
    let (_tmp, spool) = open_spool();
    let (meta_a, bytes_a) = seed_session(&spool, false, 1);
    let ulid_a = meta_a.id.to_string();
    let (meta_b, bytes_b) = seed_session(&spool, false, 1);
    let ulid_b = meta_b.id.to_string();
    for (ulid, meta, bytes) in [(&ulid_a, &meta_a, &bytes_a), (&ulid_b, &meta_b, &bytes_b)] {
        let meta_hash = starforge_format::blake3_hex(&serde_json::to_vec(meta).unwrap());
        spool.mark_meta_uploaded(ulid, meta_hash).unwrap();
        spool.mark_segment_uploaded(ulid, 0).unwrap();
        assert_eq!(
            spool.read_upload(ulid).unwrap().uploaded_segments[&0],
            starforge_format::blake3_hex(&bytes[0])
        );
    }
    seed_link(&spool, &ulid_a);
    seed_link(&spool, &ulid_b);
    // B's link line is already recorded as sent; A's is not.
    let sent = spool.link_line_hashes(&ulid_b).unwrap();
    assert_eq!(sent.len(), 1, "one links line for B");
    let hashes: Vec<String> = sent.iter().map(|(hash, _)| hash.clone()).collect();
    spool.mark_links_sent(&ulid_b, &hashes).unwrap();
    assert!(
        read_queue(&spool).unwrap().is_empty(),
        "no queue entries seeded"
    );

    let added = starforge_cli::commands::sync::reconcile_queue(&spool, NOW).unwrap();
    assert_eq!(added, 1, "only the session with an unsent link line");
    let queued = read_queue(&spool).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].op, QueueOp::Links);
    assert_eq!(queued[0].ulid, ulid_a);
}
