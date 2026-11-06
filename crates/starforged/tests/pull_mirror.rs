//! Pull-mirror tests (M4b D4): configuration, scheduled and on-demand
//! syncs, prune, revisions for branch changes backed by mirrored branches,
//! `push` webhooks with `sender: null`, push/merge refusals, `refs/for`
//! still working, disable restoring pushes, failure backoff with scrubbed
//! errors, and the maintain+/reader access matrix. Sources are `file://`
//! work repositories (the test-only URL-policy flag admits them).
mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

type SinkHits = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let req = match method {
        "PUT" => client.put(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };
    let r = req.bearer_auth(token);
    let r = match body {
        Some(b) => r.json(b),
        None => r,
    };
    let res = r.send().await.unwrap();
    let status = res.status().as_u16();
    let text = res.text().await.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, v)
}

async fn make_source(dir: &Path, name: &str) -> (String, PathBuf) {
    let work = work_repo(dir, name, &[("README.md", "# src\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&work, &[("feature.txt", b"feature\n")], "on feature").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    git_ok(&work, &["tag", "v1"]).await;
    (format!("file://{}", work.display()), work)
}

/// Runs due jobs until the mirror's `last_success_at` (or `last_error`) is
/// set, bounded at 10 s. Mirrors the import test's polling convention.
async fn poll_mirror(s: &TestServer, token: &str, owner: &str, name: &str) -> Value {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let (_, v) = api(
            &client,
            "GET",
            &s.url(&format!("/api/v1/repos/{owner}/{name}/mirror/pull")),
            token,
            None,
        )
        .await;
        if v["last_success_at"].is_number()
            || !v["last_error"].as_str().unwrap_or("").is_empty()
            || Instant::now() > deadline
        {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn audit_count(s: &TestServer, action: &str, target: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
        .bind(action)
        .bind(target)
        .fetch_one(s.core.db().pool())
        .await
        .unwrap()
}

async fn server_refs(s: &TestServer, repo_id: i64) -> String {
    git_ok(
        &s.core.repo_path(repo_id),
        &["for-each-ref", "--format=%(refname)"],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_mirror_configures_syncs_and_prunes() {
    let s = TestServer::start_with(|c| c.remotes.allow_file_urls = true).await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let (url, src) = make_source(dir.path(), "src").await;

    let client = reqwest::Client::new();
    let (status, v) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": url, "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["url"], url);
    assert_eq!(v["interval_secs"], 300);
    assert_eq!(v["enabled"], true);

    // The repository now reports itself as a mirror.
    let (_, shown) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj"),
        &rw,
        None,
    )
    .await;
    assert_eq!(shown["mirror"], true);

    let done = poll_mirror(&s, &rw, "alice", "proj").await;
    assert!(done["last_success_at"].is_number(), "{done}");
    assert_eq!(done["last_error"], "");
    // Credentials never come back.
    assert!(done.get("sealed_secret").is_none(), "{done}");
    assert!(done.get("password").is_none(), "{done}");

    let refs = server_refs(&s, repo.id).await;
    assert!(refs.contains("refs/heads/main"), "{refs}");
    assert!(refs.contains("refs/heads/feature"), "{refs}");
    assert!(refs.contains("refs/tags/v1"), "{refs}");

    // Upstream: advance main, add a branch, delete feature.
    commit_files(&src, &[("more.txt", b"more\n")], "advance main").await;
    git_ok(&src, &["branch", "topic"]).await;
    git_ok(&src, &["branch", "-D", "feature"]).await;
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/pull/sync"),
        &rw,
        None,
    )
    .await;
    assert_eq!(status, 200);
    // The second sync must run; `last_success_at` alone would pass stale,
    // so poll on the new branch appearing instead.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let refs = server_refs(&s, repo.id).await;
        if refs.contains("refs/heads/topic") || Instant::now() > deadline {
            assert!(refs.contains("refs/heads/topic"), "{refs}");
            assert!(!refs.contains("refs/heads/feature"), "pruned: {refs}");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(audit_count(&s, "mirror.create", "repo:alice/proj").await >= 1);

    // Re-PUT updates in place (no second row) and audits mirror.update.
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": url, "interval_secs": 600})),
    )
    .await;
    assert_eq!(status, 200);
    let rows: Vec<_> = starforged_db::remotes::list_by_repo(s.core.db(), repo.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.role == "pull")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].interval_secs, 600);
    assert!(audit_count(&s, "mirror.update", "repo:alice/proj").await >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_mirror_revisions_and_webhook_sender_null() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
        c.webhooks.allow_loopback = true;
    })
    .await;
    let alice = s.user("alice").await;
    let rw = s
        .token(
            &alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let (url, src) = make_source(dir.path(), "src").await;

    // Webhook sink.
    let hits: SinkHits = Arc::new(Mutex::new(Vec::new()));
    let sink_hits = hits.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let sink_hits = sink_hits.clone();
                async move {
                    let event = headers
                        .get("x-starforge-event")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("?")
                        .to_owned();
                    sink_hits.lock().unwrap().push((event, body.to_vec()));
                    (axum::http::StatusCode::OK, "ok")
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    let hook_url = format!("http://{addr}/hook");

    let client = reqwest::Client::new();
    let (status, hook) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/hooks"),
        &rw,
        Some(&json!({"url": hook_url, "events": ["push"]})),
    )
    .await;
    assert_eq!(status, 201, "{hook}");

    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": url, "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200);
    let done = poll_mirror(&s, &rw, "alice", "proj").await;
    assert!(done["last_success_at"].is_number(), "{done}");

    // Open a trail + branch change on the mirrored `feature` branch.
    let (status, trail) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/trails"),
        &rw,
        Some(&json!({"title": "feature work", "intent": "ship it"})),
    )
    .await;
    assert_eq!(status, 201, "{trail}");
    let n = trail["number"].as_i64().unwrap();
    s.core
        .create_branch_change(&alice, "alice", "proj", n, "feature", "main")
        .await
        .unwrap();
    let trail_row = starforged_db::trails::trail_by_number(s.core.db(), repo.id, n)
        .await
        .unwrap()
        .unwrap();
    let change = starforged_db::changes::change_by_trail_number(s.core.db(), trail_row.id, 1)
        .await
        .unwrap()
        .unwrap();
    let before = starforged_db::changes::revisions_of_change(s.core.db(), change.id)
        .await
        .unwrap();
    assert_eq!(before.len(), 1);

    // Drain the initial sync's push events so later assertions only see
    // the advance's event.
    s.core.run_due_jobs().await.unwrap();
    hits.lock().unwrap().clear();

    // Upstream commits on `feature`; sync again.
    git_ok(&src, &["checkout", "-q", "feature"]).await;
    commit_files(&src, &[("more.txt", b"m\n")], "more feature").await;
    git_ok(&src, &["checkout", "-q", "main"]).await;
    api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/pull/sync"),
        &rw,
        None,
    )
    .await;

    // The branch change gained a revision.
    let deadline = Instant::now() + Duration::from_secs(10);
    let after = loop {
        s.core.run_due_jobs().await.unwrap();
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change.id)
            .await
            .unwrap();
        if revs.len() >= 2 || Instant::now() > deadline {
            break revs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(after.len(), 2, "upstream commit must append a revision");

    // A `push` webhook fired with `sender: null`.
    let deadline = Instant::now() + Duration::from_secs(10);
    let body = loop {
        s.core.run_due_jobs().await.unwrap();
        let found = hits.lock().unwrap().iter().find_map(|(event, body)| {
            if event == "push" {
                let v: Value = serde_json::from_slice(body).unwrap();
                if v["sender"].is_null() && v["push"]["ref"] == "refs/heads/feature" {
                    return Some(v);
                }
            }
            None
        });
        if let Some(v) = found {
            break v;
        }
        assert!(
            Instant::now() <= deadline,
            "no sender-null push event arrived"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(body["sender"].is_null(), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_mirror_refusals_merge_and_for() {
    let s = TestServer::start_with(|c| c.remotes.allow_file_urls = true).await;
    let alice = s.user("alice").await;
    let rw = s
        .token(
            &alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    let _repo = s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let (url, src) = make_source(dir.path(), "src").await;

    let client = reqwest::Client::new();
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": url, "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200);
    let done = poll_mirror(&s, &rw, "alice", "proj").await;
    assert!(done["last_success_at"].is_number(), "{done}");

    // A direct push is refused with the mirror message.
    let pusher = work_repo(dir.path(), "pusher", &[("x.txt", "x\n")]).await;
    let push = git(
        &pusher,
        &[
            "push",
            &s.git_url("alice", "proj", Some(&rw)),
            "main:pusher-branch",
        ],
    )
    .await;
    let stderr = String::from_utf8_lossy(&push.stderr).to_string();
    assert!(stderr.contains("pull mirror"), "{stderr}");

    // Merging a Trail change is refused (422, like archived).
    let (status, trail) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/trails"),
        &rw,
        Some(&json!({"title": "merge me", "intent": "try to merge"})),
    )
    .await;
    assert_eq!(status, 201, "{trail}");
    let n = trail["number"].as_i64().unwrap();
    s.core
        .create_branch_change(&alice, "alice", "proj", n, "feature", "main")
        .await
        .unwrap();
    let (status, body) = api(
        &client,
        "POST",
        &s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/1/merge"
        )),
        &rw,
        Some(&json!({"method": "merge"})),
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert!(body.to_string().contains("pull mirror"), "{body}");

    // `refs/for` still works: a discussion proposal lands.
    let for_push = git(
        &src,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&rw)),
            "HEAD:refs/for/main/proposal",
        ],
    )
    .await;
    assert!(
        for_push.status.success(),
        "refs/for must work on a mirror: {}",
        String::from_utf8_lossy(&for_push.stderr)
    );

    // Disabling the mirror restores pushes.
    let (status, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/pull/enabled"),
        &rw,
        Some(&json!({"enabled": false})),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["enabled"], false);
    let ok = git(
        &pusher,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&rw)),
            "main:pusher-branch",
        ],
    )
    .await;
    assert!(
        ok.status.success(),
        "push after disabling must work: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_mirror_schedule_access_and_failure() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
        c.webhooks.allow_loopback = true;
    })
    .await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let dave = s.user("dave").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let bob_rw = s.token(&bob, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let carol_r = s.token(&carol, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let dave_r = s.token(&dave, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let dir = tempfile::tempdir().unwrap();
    let (url, _src) = make_source(dir.path(), "src").await;

    let client = reqwest::Client::new();
    // Write-but-not-maintain cannot configure (403); a reader cannot either.
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &bob_rw,
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 403, "writer must not configure mirrors");
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &carol_r,
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 403, "reader must not configure mirrors");
    // A stranger gets 404 everywhere.
    let (status, _) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &dave_r,
        None,
    )
    .await;
    assert_eq!(status, 404, "non-reader must 404");
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &dave_r,
        Some(&json!({"url": url})),
    )
    .await;
    assert_eq!(status, 404);

    // Interval below 300 is 422.
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": url, "interval_secs": 60})),
    )
    .await;
    assert_eq!(status, 422);

    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": url, "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200);
    let done = poll_mirror(&s, &rw, "alice", "proj").await;
    assert!(done["last_success_at"].is_number(), "{done}");

    // Scheduling: the run re-enqueued the mirror at now + interval.
    let now = starforged_db::now();
    let run_at: Option<i64> = sqlx::query_scalar(
        "SELECT run_at FROM jobs WHERE kind = 'pull_mirror' AND state = 'queued' ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_optional(s.core.db().pool())
    .await
    .unwrap();
    let run_at = run_at.expect("a re-enqueued pull_mirror job must exist");
    assert!(
        run_at > now,
        "re-enqueued run_at {run_at} not in the future (now {now})"
    );
    assert!(
        run_at <= now + 310,
        "re-enqueued run_at {run_at} beyond the interval"
    );

    // A dead upstream: the failure is recorded (never a credential) and
    // the retry is backoff-scheduled, not immediate.
    let (status, _) = api(
        &client,
        "PUT",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        Some(&json!({"url": "file:///nonexistent/upstream.git", "interval_secs": 300})),
    )
    .await;
    assert_eq!(status, 200);
    api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/pull/sync"),
        &rw,
        None,
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let failed = loop {
        s.core.run_due_jobs().await.unwrap();
        let (_, v) = api(
            &client,
            "GET",
            &s.url("/api/v1/repos/alice/proj/mirror/pull"),
            &rw,
            None,
        )
        .await;
        if !v["last_error"].as_str().unwrap_or("").is_empty() || Instant::now() > deadline {
            break v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        !failed["last_error"].as_str().unwrap().is_empty(),
        "{failed}"
    );
    let now = starforged_db::now();
    let run_at: Option<i64> = sqlx::query_scalar(
        "SELECT run_at FROM jobs WHERE kind = 'pull_mirror' AND state = 'queued' ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_optional(s.core.db().pool())
    .await
    .unwrap();
    let run_at = run_at.expect("a backoff re-enqueue must exist");
    assert!(
        run_at > now && run_at <= now + 310,
        "backoff run_at {run_at} (now {now})"
    );

    // Read-only scopes cannot disable; deleting restores pushes and audits.
    let (status, _) = api(
        &client,
        "DELETE",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &bob_rw,
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = api(
        &client,
        "DELETE",
        &s.url("/api/v1/repos/alice/proj/mirror/pull"),
        &rw,
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(audit_count(&s, "mirror.delete", "repo:alice/proj").await >= 1);
    let (_, shown) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj"),
        &rw,
        None,
    )
    .await;
    assert_eq!(shown["mirror"], false);

    // The web page renders for maintainers (CSRF-bearing forms) and the
    // save action is CSRF-gated.
    let (browser, csrf) = s.login("alice").await;
    let page = get_text(&browser, &s.url("/alice/proj/settings/mirrors")).await;
    assert!(page.contains("Pull mirror"), "{page}");
    assert!(page.contains(&csrf), "page must carry the CSRF token");
    let denied = browser
        .post(s.url("/alice/proj/settings/mirrors"))
        .form(&[
            ("url", url.as_str()),
            ("auth", "none"),
            ("interval_secs", "300"),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        denied.status().is_client_error(),
        "POST without CSRF must fail: {}",
        denied.status()
    );
}
