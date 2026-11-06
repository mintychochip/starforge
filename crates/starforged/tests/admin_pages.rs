//! L3: the quarantine queue and health pages (M5a D4, D5).
mod common;

use common::{TestServer, get_text};
use starforged_core::accounts::{CreateUser, User};
use starforged_core::permission::Visibility;
use starforged_db::jobs as db_jobs;
use starforged_db::sessions::{self as sessions_db, NewSession};

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G6A0";
const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G6A1";
const DETAIL_MARKER: &str = "detail-marker-never-render-quarantine-detail";

async fn admin(s: &TestServer) -> User {
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Inserts one quarantined session with the detail hidden from the page.
async fn quarantined_session(s: &TestServer, repo_id: i64, uploader_id: i64, ulid: &str) -> i64 {
    sessions_db::insert_session(
        s.core.db(),
        &NewSession {
            repo_id,
            ulid,
            uploader_id,
            agent_name: "test-agent",
            agent_version: "1.0.0",
            models: "model",
            title: "title",
            branch: "main",
            head_sha: "",
            started_at: 1_700_000_000,
            ended_at: Some(1_700_000_100),
            parent_ulid: None,
            usage_input: 0,
            usage_output: 0,
            usage_cache_read: 0,
            usage_cache_write: 0,
            usage_reasoning: 0,
            files_touched: "[]",
            turn_count: 0,
            tool_call_count: 0,
            lifecycle: "complete",
            quarantine: "quarantined",
            quarantine_reason: "secret detected",
            quarantine_detail: DETAIL_MARKER,
            visibility: "inherit",
            raw_enabled: 0,
            redaction_fingerprint: "fp",
            redaction_counts: "{}",
            capture_mode: "cli",
            cli_version: "1.0.0",
            adapter_verified: 0,
        },
    )
    .await
    .unwrap()
}

async fn session_quarantine(s: &TestServer, id: i64) -> Option<String> {
    sessions_db::session_by_id(s.core.db(), id)
        .await
        .unwrap()
        .map(|row| row.quarantine)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_queue_lists_and_acts_on_sessions_from_two_repositories() {
    let s = TestServer::start().await;
    let _root = admin(&s).await;
    let alice = s.user("alice").await;
    let proj = s.repo(&alice, "proj", Visibility::Private).await;
    let other = s.repo(&alice, "other", Visibility::Private).await;
    let id_a = quarantined_session(&s, proj.id, alice.id, ULID_A).await;
    let id_b = quarantined_session(&s, other.id, alice.id, ULID_B).await;

    let (client, csrf) = s.login("root").await;
    let page = get_text(&client, &s.url("/admin/quarantine")).await;
    for needle in [
        ULID_A,
        ULID_B,
        "alice/proj",
        "alice/other",
        "alice",
        "secret detected",
    ] {
        assert!(page.contains(needle), "missing {needle}:\n{page}");
    }
    // The quarantine detail (and, by construction, session content) never renders.
    assert!(
        !page.contains(DETAIL_MARKER),
        "detail leaked onto the page:\n{page}"
    );

    // Release works with CSRF.
    let released = client
        .post(s.url(&format!("/admin/quarantine/{id_a}/release")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), 303, "release redirect");
    assert_eq!(
        session_quarantine(&s, id_a).await.as_deref(),
        Some("released")
    );
    let after_release = get_text(&client, &s.url("/admin/quarantine")).await;
    assert!(
        !after_release.contains(ULID_A),
        "released session still listed:\n{after_release}"
    );
    assert!(after_release.contains(ULID_B));

    // Purge works with CSRF.
    let purged = client
        .post(s.url(&format!("/admin/quarantine/{id_b}/purge")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(purged.status(), 303, "purge redirect");
    assert_eq!(
        session_quarantine(&s, id_b).await,
        None,
        "purged session row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_actions_require_csrf() {
    let s = TestServer::start().await;
    let _root = admin(&s).await;
    let alice = s.user("alice").await;
    let proj = s.repo(&alice, "proj", Visibility::Private).await;
    let id = quarantined_session(&s, proj.id, alice.id, ULID_A).await;

    let (client, _csrf) = s.login("root").await;
    let bad = client
        .post(s.url(&format!("/admin/quarantine/{id}/release")))
        .form(&[("_csrf", "wrong")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403, "bad CSRF");
    assert_eq!(
        session_quarantine(&s, id).await.as_deref(),
        Some("quarantined")
    );

    // Releasing a missing session is 404, not a silent success.
    let csrf = get_text(&client, &s.url("/")).await;
    let csrf = common::extract_input(&csrf, "_csrf");
    let missing = client
        .post(s.url("/admin/quarantine/999999/release"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404, "missing session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_shows_version_engine_git_and_job_aggregates() {
    // A free port, not the default 2222: a real Starforge (or another test
    // run) on this machine may already hold 2222.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listen = format!("127.0.0.1:{port}");
    let configured = listen.clone();
    let s = TestServer::start_with(move |c| c.ssh.listen = configured).await;
    let _root = admin(&s).await;

    // One failed job and one queued job, so the aggregates name both states.
    let db = s.core.db();
    let failed_id = db_jobs::insert(
        db,
        &db_jobs::NewJob {
            kind: "test-health-kind",
            payload: "{}",
            dedupe_key: None,
            run_at: 1_700_000_000,
        },
    )
    .await
    .unwrap()
    .expect("first insert");
    db_jobs::fail(db, failed_id, "boom", None).await.unwrap();
    db_jobs::insert(
        db,
        &db_jobs::NewJob {
            kind: "test-health-kind",
            payload: "{}",
            dedupe_key: None,
            run_at: 1_700_000_000,
        },
    )
    .await
    .unwrap();

    let (client, _csrf) = s.login("root").await;
    let page = get_text(&client, &s.url("/admin/health")).await;
    let engine = match s.core.db().backend() {
        starforged_db::Backend::Sqlite => "sqlite",
        starforged_db::Backend::Postgres => "postgres",
    };
    let ssh_line = format!("enabled on {listen}");
    for needle in [
        "Starforge version",
        "Database engine",
        engine,
        "Schema version",
        "Git version",
        "Data directory free space",
        "SSH listener",
        ssh_line.as_str(),
        "Search index trails",
        "Oldest pending job",
        "test-health-kind",
        "failed",
        "queued",
    ] {
        assert!(page.contains(needle), "missing {needle}:\n{page}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_disabled_ssh_listener() {
    let s = TestServer::start_with(|c| c.ssh.enabled = false).await;
    let _root = admin(&s).await;
    let (client, _csrf) = s.login("root").await;
    let page = get_text(&client, &s.url("/admin/health")).await;
    assert!(page.contains("SSH listener"), "missing label:\n{page}");
    assert!(page.contains("disabled"), "expected disabled:\n{page}");
    assert!(
        !page.contains("enabled on"),
        "disabled listener shown enabled:\n{page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_pages_hide_from_non_admins() {
    let s = TestServer::start().await;
    let _root = admin(&s).await;
    let alice = s.user("alice").await;
    let proj = s.repo(&alice, "proj", Visibility::Private).await;
    let id = quarantined_session(&s, proj.id, alice.id, ULID_A).await;

    let (alice_client, alice_csrf) = s.login("alice").await;
    let anon = s.browser();
    for path in ["/admin/quarantine", "/admin/health"] {
        assert_eq!(
            anon.get(s.url(path)).send().await.unwrap().status(),
            404,
            "anonymous {path}"
        );
        assert_eq!(
            alice_client.get(s.url(path)).send().await.unwrap().status(),
            404,
            "non-admin {path}"
        );
    }
    let post = alice_client
        .post(s.url(&format!("/admin/quarantine/{id}/release")))
        .form(&[("_csrf", alice_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 404, "non-admin release");
}
