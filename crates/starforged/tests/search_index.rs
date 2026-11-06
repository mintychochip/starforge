//! M4a S1/S2: `starforged index rebuild` over a file-backed data dir, plus the
//! incremental indexing pipeline (plan D5): every mutation enqueues an index
//! job, and `run_due_jobs` makes the change observable through `search_*`.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TestServer, commit_files, get_text, git_ok, work_repo};
use serde_json::{Value, json};
use starforged::admin::open_core;
use starforged::config::Config;
use starforged_core::Core;
use starforged_core::accounts::CreateUser;
use starforged_core::ingest::IngestAuth;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::{Scope, TokenAuth};
use starforged_index::{EventQuery, Scope as IndexScope, SearchIndex, TrailQuery};

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC1";

/// Writes a minimal `starforged.toml` rooted at `data_dir` and returns it.
fn write_config(dir: &Path, data_dir: &Path) -> PathBuf {
    std::fs::create_dir_all(data_dir).unwrap();
    let config = dir.join("starforged.toml");
    let text = format!(
        "[server]\n\
         http_addr = \"127.0.0.1:0\"\n\
         base_url = \"http://127.0.0.1:0\"\n\
         [security]\n\
         secret_key = \"{secret}\"\n\
         [storage]\n\
         data_dir = \"{data}\"\n\
         [database]\n\
         url = \"sqlite://{data}/starforge.db?mode=rwc\"\n\
         auto_migrate = true\n",
        secret = "0".repeat(64),
        data = data_dir.display(),
    );
    std::fs::write(&config, text).unwrap();
    config
}

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "rebuild fixture",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 1, "output": 2, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": ["src/plumbline.rs"],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

fn event(seq: u64, kind: &str, payload: Value) -> String {
    let mut line = json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": kind});
    for (k, v) in payload.as_object().unwrap() {
        line[k] = v.clone();
    }
    line.to_string()
}

/// Opens a `Core` over `config_path`, seeding one public repository, one
/// Trail with a comment, and one completed session whose segment carries
/// searchable text, a tool name, a file path, plus reasoning and a tool
/// result that must never be indexed.
async fn seed(config_path: &Path) -> Core {
    let config = Config::load(config_path).unwrap();
    let core = open_core(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
        .await
        .unwrap();
    let alice = core
        .create_user(CreateUser {
            handle: "alice".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    core.create_repo(
        &alice,
        "alice",
        CreateRepo {
            name: "proj".into(),
            description: String::new(),
            visibility: Visibility::Public,
            readme: false,
        },
    )
    .await
    .unwrap();
    core.create_trail(
        &alice,
        "alice",
        "proj",
        "Quyx plumbline repair",
        "Fix the qux handle",
    )
    .await
    .unwrap();
    core.add_comment(&alice, "alice", "proj", 1, "plumbline follow-up with quux")
        .await
        .unwrap();

    let token = TokenAuth {
        user: alice.clone(),
        scopes: vec![Scope::SessionUpload],
        token_id: 0,
    };
    let auth: IngestAuth = core
        .authorize_upload(&token, "alice", "proj")
        .await
        .unwrap();
    core.upsert_session_meta(&auth, ULID, &meta_body(ULID))
        .await
        .unwrap();
    let lines = [
        event(0, "user_message", json!({"text": "quyx rebuild plumbline"})),
        event(
            1,
            "tool_call",
            json!({"tool": {"name": "bash", "input": {"cmd": "echo quietly"}}}),
        ),
        event(
            2,
            "file_change",
            json!({"path": "src/plumbline.rs", "change": "modify"}),
        ),
        event(3, "reasoning", json!({"text": "subway shortcuts"})),
        event(
            4,
            "tool_result",
            json!({"result": {"output": "outputword", "is_error": false}}),
        ),
    ];
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    core.put_segment(&auth, ULID, 0, &bytes, Some(hash))
        .await
        .unwrap();
    core.complete_session(&auth, ULID).await.unwrap();
    core.publish_session(&alice, &auth.access, ULID)
        .await
        .unwrap();
    core
}

fn rebuild(config_path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_starforged"))
        .arg("--config")
        .arg(config_path)
        .arg("index")
        .arg("rebuild")
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuild_fails_while_the_writer_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write_config(dir.path(), &dir.path().join("data"));
    // The seeding `Core` holds the tantivy writer for its whole lifetime.
    let core = seed(&config_path).await;

    let out = rebuild(&config_path);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "rebuild must fail while the writer is held: {combined}"
    );
    assert!(
        combined.contains("stop the server"),
        "the failure must say to stop the server: {combined}"
    );

    drop(core);
    let out = rebuild(&config_path);
    assert!(
        out.status.success(),
        "rebuild succeeds once the writer is released: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuild_produces_the_expected_counts() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_path = write_config(dir.path(), &data_dir);
    drop(seed(&config_path).await);

    let out = rebuild(&config_path);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "rebuild failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("1 trail") && stdout.contains("3 event"),
        "rebuild prints the counts: {stdout}"
    );

    let index = SearchIndex::open_or_create(&data_dir.join("index")).unwrap();
    assert_eq!(
        index.stats().unwrap(),
        starforged_index::IndexStats {
            trails: 1,
            events: 3
        },
        "one Trail and the three searchable events (reasoning and tool results produce no documents)"
    );
    let scope = IndexScope {
        signed_in: true,
        readable: Vec::new(),
        member: Vec::new(),
        admin: Vec::new(),
        viewer_id: Some(1),
    };
    let search = |q: &str| {
        index
            .search_events(
                &EventQuery {
                    q: q.to_owned(),
                    ..Default::default()
                },
                &scope,
                0,
                20,
            )
            .unwrap()
            .len()
    };
    assert_eq!(search("plumbline"), 2, "user text and the file path");
    assert_eq!(search("bash"), 1, "the tool name");
    assert_eq!(search("subway"), 0, "reasoning is never indexed");
    assert_eq!(search("outputword"), 0, "tool outputs are never indexed");
    assert_eq!(search("quietly"), 0, "tool inputs are never indexed");
}

// ── S2: the indexing pipeline ──────────────────────────────────────────────

fn admin_scope(repo_id: i64, viewer: i64) -> IndexScope {
    IndexScope {
        signed_in: true,
        readable: vec![repo_id],
        member: vec![repo_id],
        admin: vec![repo_id],
        viewer_id: Some(viewer),
    }
}

fn anon_scope() -> IndexScope {
    IndexScope::default()
}

fn trail_hits(server: &TestServer, q: &str, scope: &IndexScope) -> Vec<starforged_index::TrailHit> {
    server
        .core
        .search_index()
        .search_trails(
            &TrailQuery {
                q: q.to_owned(),
                ..Default::default()
            },
            scope,
            0,
            20,
        )
        .unwrap()
}

fn event_hits(server: &TestServer, q: &str, scope: &IndexScope) -> Vec<starforged_index::EventHit> {
    server
        .core
        .search_index()
        .search_events(
            &EventQuery {
                q: q.to_owned(),
                ..Default::default()
            },
            scope,
            0,
            20,
        )
        .unwrap()
}

async fn drain(server: &TestServer) {
    server.core.run_due_jobs().await.unwrap();
}

/// Uploads one completed session whose single user message carries `text`.
async fn upload_completed(
    server: &TestServer,
    alice: &starforged_core::accounts::User,
    ulid: &str,
    text: &str,
) {
    let secret = server.token(alice, &[Scope::SessionUpload]).await;
    let token = server.core.authenticate_token(&secret).await.unwrap();
    let auth: IngestAuth = server
        .core
        .authorize_upload(&token, "alice", "proj")
        .await
        .unwrap();
    server
        .core
        .upsert_session_meta(&auth, ulid, &meta_body(ulid))
        .await
        .unwrap();
    let line = event(0, "user_message", json!({"text": text}));
    let bytes = starforge_format::compress(format!("{line}\n").as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    server
        .core
        .put_segment(&auth, ulid, 0, &bytes, Some(hash))
        .await
        .unwrap();
    server.core.complete_session(&auth, ulid).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_create_edit_comment_state_are_indexed() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let scope = admin_scope(repo.id, alice.id);

    s.core
        .create_trail(&alice, "alice", "proj", "Zebra alpha", "intentword")
        .await
        .unwrap();
    drain(&s).await;
    let hits = trail_hits(&s, "zebra", &scope);
    assert_eq!(hits.len(), 1, "create indexes the trail");
    assert_eq!(hits[0].state, "open");

    s.core
        .update_trail(
            &alice,
            "alice",
            "proj",
            1,
            Some("Zebra charlie"),
            None,
            None,
        )
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "charlie", &scope).len(),
        1,
        "edit re-indexes title"
    );
    assert_eq!(
        trail_hits(&s, "alpha", &scope).len(),
        0,
        "old title is replaced"
    );

    let comment = s
        .core
        .add_comment(&alice, "alice", "proj", 1, "delta comment")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "delta", &scope).len(),
        1,
        "comment body is indexed"
    );

    s.core
        .edit_comment(&alice, "alice", "proj", 1, comment.id, "echo edited")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "echo", &scope).len(),
        1,
        "comment edit re-indexes"
    );
    assert_eq!(
        trail_hits(&s, "delta", &scope).len(),
        0,
        "old comment text is replaced"
    );

    s.core
        .set_trail_state(&alice, "alice", "proj", 1, "closed")
        .await
        .unwrap();
    drain(&s).await;
    let hits = trail_hits(&s, "zebra", &scope);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].state, "closed", "state change re-indexes state");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_complete_publish_unpublish_indexed() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let scope = admin_scope(repo.id, alice.id);
    let access = s
        .core
        .require_repo(Some(&alice), "alice", "proj", Permission::Admin)
        .await
        .unwrap();

    upload_completed(
        &s,
        &alice,
        "01ARZ3NDEKTSV4RRFFQ69G5FC2",
        "publishword hello",
    )
    .await;
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "publishword", &scope).len(),
        1,
        "complete indexes events"
    );
    assert_eq!(
        event_hits(&s, "publishword", &anon_scope()).len(),
        0,
        "unpublished public event is hidden from anonymous"
    );

    s.core
        .publish_session(&alice, &access, "01ARZ3NDEKTSV4RRFFQ69G5FC2")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "publishword", &anon_scope()).len(),
        1,
        "publish re-indexes published flag"
    );

    s.core
        .unpublish_session(&alice, &access, "01ARZ3NDEKTSV4RRFFQ69G5FC2")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "publishword", &anon_scope()).len(),
        0,
        "unpublish re-indexes published flag"
    );
    assert_eq!(
        event_hits(&s, "publishword", &scope).len(),
        1,
        "admin scope still sees unpublished"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_quarantine_and_release_are_indexed() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let scope = admin_scope(repo.id, alice.id);
    let access = s
        .core
        .require_repo(Some(&alice), "alice", "proj", Permission::Admin)
        .await
        .unwrap();

    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FC3";
    let secret_text = "quarantineword -----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY----- done";
    upload_completed(&s, &alice, ulid, secret_text).await;
    s.core.publish_session(&alice, &access, ulid).await.unwrap();
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "quarantineword", &scope).len(),
        1,
        "quarantined session is indexed for admins"
    );
    assert_eq!(
        event_hits(&s, "quarantineword", &anon_scope()).len(),
        0,
        "quarantined session is hidden from anonymous"
    );

    s.core.release_session(&alice, &access, ulid).await.unwrap();
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "quarantineword", &anon_scope()).len(),
        1,
        "release re-indexes quarantine flag"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_delete_and_purge_drop_docs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let scope = admin_scope(repo.id, alice.id);
    let access = s
        .core
        .require_repo(Some(&alice), "alice", "proj", Permission::Admin)
        .await
        .unwrap();

    upload_completed(&s, &alice, "01ARZ3NDEKTSV4RRFFQ69G5FC4", "deleteword one").await;
    drain(&s).await;
    assert_eq!(event_hits(&s, "deleteword", &scope).len(), 1);
    s.core
        .delete_session(&alice, &access, "01ARZ3NDEKTSV4RRFFQ69G5FC4")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "deleteword", &scope).len(),
        0,
        "delete drops session docs"
    );

    upload_completed(&s, &alice, "01ARZ3NDEKTSV4RRFFQ69G5FC5", "purgeword two").await;
    drain(&s).await;
    assert_eq!(event_hits(&s, "purgeword", &scope).len(), 1);
    s.core
        .purge_session(&alice, &access, "01ARZ3NDEKTSV4RRFFQ69G5FC5")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        event_hits(&s, "purgeword", &scope).len(),
        0,
        "purge drops session docs"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_visibility_change_updates_docs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let scope = admin_scope(repo.id, alice.id);

    s.core
        .create_trail(&alice, "alice", "proj", "Visibilityword title", "intent")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "visibilityword", &anon_scope()).len(),
        1,
        "public trail visible to anonymous"
    );

    s.core
        .set_visibility(&alice, "alice", "proj", Visibility::Private)
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "visibilityword", &anon_scope()).len(),
        0,
        "private trail hidden from anonymous"
    );
    assert_eq!(
        trail_hits(&s, "visibilityword", &scope).len(),
        1,
        "readable scope still sees private trail"
    );

    s.core
        .set_visibility(&alice, "alice", "proj", Visibility::Public)
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "visibilityword", &anon_scope()).len(),
        1,
        "public again visible to anonymous"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_delete_restore_and_purge_drop_docs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let scope = admin_scope(repo.id, alice.id);

    s.core
        .create_trail(&alice, "alice", "proj", "Repoword title", "intent")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(trail_hits(&s, "repoword", &scope).len(), 1);

    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "repoword", &scope).len(),
        0,
        "delete drops repo docs"
    );

    s.core.restore_repo(&alice, repo.id).await.unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "repoword", &scope).len(),
        1,
        "restore re-indexes repo docs"
    );

    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    s.core.purge_repo_now(&root, repo.id).await.unwrap();
    drain(&s).await;
    assert_eq!(
        trail_hits(&s, "repoword", &scope).len(),
        0,
        "purge drops repo docs"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_index_at_startup_is_recreated_and_rebuild_enqueued() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_path = write_config(dir.path(), &data_dir);
    // A corrupt index: a directory that is not a readable tantivy index.
    let index_dir = data_dir.join("index");
    std::fs::create_dir_all(&index_dir).unwrap();
    std::fs::write(index_dir.join("garbage.txt"), "not an index").unwrap();

    let config = Config::load(&config_path).unwrap();
    let app = starforged::serve::build(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
        .await
        .unwrap();
    assert!(
        app.core.search_index_was_recreated(),
        "corrupt index was recreated"
    );
    starforged::serve::recover_search_index(&app.core)
        .await
        .unwrap();
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'rebuild_index' AND state = 'queued'",
    )
    .fetch_one(app.core.db().pool())
    .await
    .unwrap();
    assert_eq!(queued, 1, "startup recovery enqueues RebuildIndex");
    app.core.run_due_jobs().await.unwrap();
    assert!(
        index_dir.join("meta.json").exists(),
        "recreated index is a real index"
    );
    drop(app);

    // A healthy index opens without a rebuild job.
    let config = Config::load(&config_path).unwrap();
    let app = starforged::serve::build(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
        .await
        .unwrap();
    assert!(
        !app.core.search_index_was_recreated(),
        "healthy index opens as-is"
    );
    starforged::serve::recover_search_index(&app.core)
        .await
        .unwrap();
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'rebuild_index' AND state = 'queued'",
    )
    .fetch_one(app.core.db().pool())
    .await
    .unwrap();
    assert_eq!(queued, 0, "no rebuild for a healthy index");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_rebuild_action_enqueues_rebuild_index() {
    let s = TestServer::start().await;
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let (admin_client, csrf) = s.login("root").await;

    let page = get_text(&admin_client, &s.url("/admin/jobs")).await;
    assert!(page.contains("Rebuild search index"), "{page}");
    assert!(page.contains("/admin/jobs/rebuild-index"), "{page}");

    // A bad CSRF token is refused first and enqueues nothing.
    let bad = admin_client
        .post(s.url("/admin/jobs/rebuild-index"))
        .form(&[("_csrf", "wrong")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403, "bad CSRF is refused");

    let res = admin_client
        .post(s.url("/admin/jobs/rebuild-index"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert_eq!(res.headers()["location"], "/admin/jobs");
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'rebuild_index' AND state = 'queued'",
    )
    .fetch_one(s.core.db().pool())
    .await
    .unwrap();
    assert_eq!(queued, 1, "rebuild action enqueues RebuildIndex");

    // Non-admins get 404.
    let _ = root;
    let alice = s.user("alice").await;
    let _ = alice;
    let (owner, _) = s.login("alice").await;
    assert_eq!(
        owner
            .post(s.url("/admin/jobs/rebuild-index"))
            .form(&[("_csrf", "x")])
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let anon = s.browser();
    assert_eq!(
        anon.post(s.url("/admin/jobs/rebuild-index"))
            .form(&[("_csrf", "x")])
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_created_trail_is_indexed() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let scope = admin_scope(repo.id, alice.id);
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    commit_files(
        &work,
        &[("feature.txt", b"feature\n")],
        "pushtestword feature",
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main"]).await;

    // The post-receive scan is async: poll (bounded) until the index job runs.
    let start = std::time::Instant::now();
    loop {
        s.core.run_due_jobs().await.unwrap();
        if !trail_hits(&s, "pushtestword", &scope).is_empty() {
            break;
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "pushed trail was not indexed within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
