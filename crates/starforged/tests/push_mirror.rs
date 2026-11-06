//! Push-mirror tests (M4b D5): configuration against a `file://` bare
//! target, the 30 s debounce dedupe (two pushes coalesce into one run),
//! branch/tag mirroring with prune on branch deletion, `refs/trails/*`
//! never leaving the repository, a failing target's scrubbed `last_error`
//! with backoff rescheduling, the cap of 10, maintain+/reader access, and
//! audit rows.
mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

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

/// A bare `file://` target; returns its URL and path.
fn make_target(dir: &Path, name: &str) -> (String, PathBuf) {
    let dest = dir.join(name);
    std::process::Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&dest)
        .status()
        .unwrap();
    (format!("file://{}", dest.display()), dest)
}

async fn target_refs(target: &Path) -> String {
    git_ok(target, &["for-each-ref", "--format=%(refname)"]).await
}

/// Makes queued `push_mirror` jobs due by moving their `run_at` into the
/// past (no sleeping: time travel in the table).
async fn make_due(s: &TestServer) {
    sqlx::query("UPDATE jobs SET run_at = $1 WHERE kind = 'push_mirror' AND state = 'queued'")
        .bind(starforged_db::now() - 1)
        .execute(s.core.db().pool())
        .await
        .unwrap();
}

async fn push_mirrors(s: &TestServer, token: &str) -> Value {
    let client = reqwest::Client::new();
    let (_, v) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        token,
        None,
    )
    .await;
    v
}

/// Runs due jobs (making debounced jobs due first) until the first push
/// mirror reports success or an error, bounded at 10 s.
async fn poll_push(s: &TestServer, token: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        make_due(s).await;
        s.core.run_due_jobs().await.unwrap();
        let v = push_mirrors(s, token).await;
        let first = v.as_array().and_then(|a| a.first());
        match first {
            Some(m) if m["last_success_at"].is_number() => return v,
            Some(m) if !m["last_error"].as_str().unwrap_or("").is_empty() => return v,
            _ => {}
        }
        if Instant::now() > deadline {
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

async fn done_push_jobs(s: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE kind = 'push_mirror' AND state = 'done'")
        .fetch_one(s.core.db().pool())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_mirror_debounces_and_mirrors() {
    let s = TestServer::start_with(|c| c.remotes.allow_file_urls = true).await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let (target_url, target) = make_target(dir.path(), "target.git");

    let client = reqwest::Client::new();
    let (status, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &rw,
        Some(&json!({"url": target_url})),
    )
    .await;
    assert_eq!(status, 201, "{v}");
    assert_eq!(v["url"], target_url);
    assert_eq!(v["enabled"], true);
    let remote_id = v["id"].as_i64().unwrap();

    // Two pushes inside the debounce window: the scan enqueues at now + 30 s
    // after each, deduped to exactly one queued job.
    let work = work_repo(dir.path(), "pusher", &[("README.md", "# proj\n")]).await;
    let url = s.git_url("alice", "proj", Some(&rw));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    // A real fast-forward follow-up: the second push builds on the first.
    commit_files(&work, &[("second.txt", b"second\n")], "second commit").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE kind = 'push_mirror' AND state = 'queued'",
    )
    .fetch_one(s.core.db().pool())
    .await
    .unwrap();
    assert_eq!(queued, 1, "two pushes must coalesce into one debounced job");

    // The job is debounced: nothing reached the target before time moves.
    assert!(target_refs(&target).await.is_empty());

    let done = poll_push(&s, &rw).await;
    assert!(done[0]["last_success_at"].is_number(), "{done}");
    assert_eq!(done[0]["last_error"], "");
    // Credentials never come back.
    assert!(done[0].get("sealed_secret").is_none(), "{done}");
    assert!(done[0].get("password").is_none(), "{done}");

    let refs = target_refs(&target).await;
    assert!(refs.contains("refs/heads/main"), "{refs}");

    // Exactly one push-mirror job ran (the debounced coalesced one).
    assert_eq!(
        done_push_jobs(&s).await,
        1,
        "exactly one push-mirror job must run"
    );

    assert!(audit_count(&s, "mirror.create", "repo:alice/proj").await >= 1);

    // "Sync now" expedites a fresh run the same way.
    let (status, _) = api(
        &client,
        "POST",
        &s.url(&format!(
            "/api/v1/repos/alice/proj/mirror/push/{remote_id}/sync"
        )),
        &rw,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let ran = done_push_jobs(&s).await;
        if ran >= 2 || Instant::now() > deadline {
            assert!(ran >= 2, "sync now must run a second job");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Deleting the mirror audits and stops future debounces.
    let (status, _) = api(
        &client,
        "DELETE",
        &s.url(&format!("/api/v1/repos/alice/proj/mirror/push/{remote_id}")),
        &rw,
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(audit_count(&s, "mirror.delete", "repo:alice/proj").await >= 1);
    let listed = push_mirrors(&s, &rw).await;
    assert_eq!(listed.as_array().unwrap().len(), 0, "{listed}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_mirror_prunes_tags_and_hides_trail_refs() {
    let s = TestServer::start_with(|c| c.remotes.allow_file_urls = true).await;
    let alice = s.user("alice").await;
    let rw = s
        .token(
            &alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let (target_url, target) = make_target(dir.path(), "target.git");

    let client = reqwest::Client::new();
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &rw,
        Some(&json!({"url": target_url})),
    )
    .await;
    assert_eq!(status, 201);

    // Push main, a topic branch, and a tag.
    let url = s.git_url("alice", "proj", Some(&rw));
    let work = work_repo(dir.path(), "pusher", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "topic"]).await;
    commit_files(&work, &[("topic.txt", b"topic\n")], "on topic").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    git_ok(&work, &["tag", "v1"]).await;
    git_ok(&work, &["push", "-q", &url, "main", "topic", "v1"]).await;

    // A `refs/for` proposal creates server-side `refs/trails/*` (and must
    // not leak through the mirror).
    let for_push = git(&work, &["push", "-q", &url, "HEAD:refs/for/main/proposal"]).await;
    assert!(
        for_push.status.success(),
        "refs/for must work: {}",
        String::from_utf8_lossy(&for_push.stderr)
    );

    poll_push(&s, &rw).await;
    let refs = target_refs(&target).await;
    assert!(refs.contains("refs/heads/main"), "{refs}");
    assert!(refs.contains("refs/heads/topic"), "{refs}");
    assert!(refs.contains("refs/tags/v1"), "{refs}");
    assert!(
        !refs.contains("refs/trails"),
        "trail refs never mirror: {refs}"
    );
    assert!(!refs.contains("refs/for"), "refs/for never mirrors: {refs}");

    // Delete the topic branch and the tag on the server: prune propagates.
    git_ok(&work, &["push", "-q", &url, ":topic", ":v1"]).await;
    poll_push(&s, &rw).await;
    let refs = target_refs(&target).await;
    assert!(refs.contains("refs/heads/main"), "{refs}");
    assert!(
        !refs.contains("refs/heads/topic"),
        "branch delete pruned: {refs}"
    );
    assert!(!refs.contains("refs/tags/v1"), "tag delete pruned: {refs}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_mirror_failure_scrubs_and_backs_off() {
    let s = TestServer::start_with(|c| c.remotes.allow_file_urls = true).await;
    let alice = s.user("alice").await;
    let rw = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();

    // A URL whose userinfo carries a secret: no response ever echoes it.
    let secret = "s3cr3t-token-value";
    let missing = dir.path().join("missing.git");
    let url_with_secret = format!("file://user:{secret}@{}", missing.display());
    let client = reqwest::Client::new();
    let (status, v) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &rw,
        Some(&json!({"url": url_with_secret})),
    )
    .await;
    assert_ne!(status, 500, "{v}");
    assert!(!v.to_string().contains(secret), "secret leaked: {v}");

    // The plain failing target: `last_error` is recorded, scrubbed, and the
    // retry is backoff-scheduled, not immediate.
    let dead_url = format!("file://{}", dir.path().join("dead.git").display());
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &rw,
        Some(&json!({"url": dead_url})),
    )
    .await;
    assert_eq!(status, 201);
    let failed = poll_push(&s, &rw).await;
    let err = failed[0]["last_error"].as_str().unwrap_or("");
    assert!(!err.is_empty(), "{failed}");
    assert!(!err.contains(secret), "secret in stored error: {err}");

    let now = starforged_db::now();
    let run_at: Option<i64> = sqlx::query_scalar(
        "SELECT run_at FROM jobs WHERE kind = 'push_mirror' AND state = 'queued' ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_optional(s.core.db().pool())
    .await
    .unwrap();
    let run_at = run_at.expect("a backoff re-enqueue must exist");
    assert!(
        run_at > now && run_at <= now + 310,
        "backoff run_at {run_at} (now {now})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_mirror_cap_and_access() {
    let s = TestServer::start_with(|c| c.remotes.allow_file_urls = true).await;
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
    let (target_url, _target) = make_target(dir.path(), "target.git");

    let client = reqwest::Client::new();
    // Write-but-not-maintain cannot add (403); a reader cannot either.
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &bob_rw,
        Some(&json!({"url": target_url})),
    )
    .await;
    assert_eq!(status, 403, "writer must not add push mirrors");
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &carol_r,
        Some(&json!({"url": target_url})),
    )
    .await;
    assert_eq!(status, 403, "reader must not add push mirrors");
    // A stranger gets 404 everywhere.
    let (status, _) = api(
        &client,
        "GET",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &dave_r,
        None,
    )
    .await;
    assert_eq!(status, 404, "non-reader must 404");
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &dave_r,
        Some(&json!({"url": target_url})),
    )
    .await;
    assert_eq!(status, 404);

    // A policy-refused URL is 422 at configure time (SSRF gate).
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &rw,
        Some(&json!({"url": "ext::sh -c echo pwned"})),
    )
    .await;
    assert_eq!(status, 422, "ext:: must be refused at configure time");

    // The cap: 10 mirrors fit, the 11th is 422.
    for i in 0..10 {
        let (status, v) = api(
            &client,
            "POST",
            &s.url("/api/v1/repos/alice/proj/mirror/push"),
            &rw,
            Some(&json!({"url": target_url})),
        )
        .await;
        assert_eq!(status, 201, "mirror {i}: {v}");
    }
    let (status, _) = api(
        &client,
        "POST",
        &s.url("/api/v1/repos/alice/proj/mirror/push"),
        &rw,
        Some(&json!({"url": target_url})),
    )
    .await;
    assert_eq!(status, 422, "the 11th push mirror must be refused");

    let listed = push_mirrors(&s, &rw).await;
    assert_eq!(listed.as_array().unwrap().len(), 10, "{listed}");

    // Deleting a nonexistent id is 404.
    let (status, _) = api(
        &client,
        "DELETE",
        &s.url("/api/v1/repos/alice/proj/mirror/push/999999"),
        &rw,
        None,
    )
    .await;
    assert_eq!(status, 404);

    // The web page renders for maintainers (CSRF-bearing forms) and the add
    // action is CSRF-gated.
    let (browser, csrf) = s.login("alice").await;
    let page = get_text(&browser, &s.url("/alice/proj/settings/mirrors")).await;
    assert!(page.contains("Push mirrors"), "{page}");
    assert!(page.contains(&csrf), "page must carry the CSRF token");
    let denied = browser
        .post(s.url("/alice/proj/settings/mirrors/push"))
        .form(&[("url", target_url.as_str()), ("auth", "none")])
        .send()
        .await
        .unwrap();
    assert!(
        denied.status().is_client_error(),
        "POST without CSRF must fail: {}",
        denied.status()
    );
}
