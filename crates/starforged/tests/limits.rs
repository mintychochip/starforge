//! M5a abuse controls (spec §11.6): login attempts per IP and per account,
//! API requests per token, and new `refs/for` changes per user, all with
//! low limits configured through `[limits]`; `0` disables each limit.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::User;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use tokio::time::sleep;

const ULID_Q: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";

/// Wrong-password attempts past the per-IP limit are refused with a 429 and
/// the generic page message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_per_ip_limit_refuses_third_attempt() {
    let s = TestServer::start_with(|config| {
        config.limits.login_per_ip_per_minute = 2;
        config.limits.login_per_account_per_hour = 0;
    })
    .await;
    s.user("alice").await;

    let first = s.try_login("alice", "wrong password!").await.1;
    assert_eq!(first.status(), 401);
    let second = s.try_login("alice", "wrong password!").await.1;
    assert_eq!(second.status(), 401);
    let third = s.try_login("alice", "wrong password!").await.1;
    assert_eq!(third.status(), 429);
    let body = third.text().await.unwrap();
    assert!(body.contains("Too many login attempts"), "{body}");
}

/// After `login_per_account_per_hour` failures, even the correct password is
/// refused until the failures age out of the hour window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_per_account_limit_blocks_even_correct_password() {
    let s = TestServer::start_with(|config| {
        config.limits.login_per_ip_per_minute = 0;
        config.limits.login_per_account_per_hour = 3;
    })
    .await;
    s.user("alice").await;

    for _ in 0..3 {
        let response = s.try_login("alice", "wrong password!").await.1;
        assert_eq!(response.status(), 401);
    }
    let refused = s.try_login("alice", PASSWORD).await.1;
    assert_eq!(refused.status(), 429);

    // Age the failure rows out of the window; the correct password works.
    sqlx::query(
        "UPDATE audit_log SET created_at = created_at - 7200 \
         WHERE action = 'auth.login_failed' AND target = 'login:alice'",
    )
    .execute(s.core.db().pool())
    .await
    .unwrap();
    let accepted = s.try_login("alice", PASSWORD).await.1;
    assert_eq!(accepted.status(), 303);
}

/// Unknown login names are limited identically to known ones: the failures
/// are audited under the normalized name, and the 4th attempt is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_per_account_limit_covers_unknown_names() {
    let s = TestServer::start_with(|config| {
        config.limits.login_per_ip_per_minute = 0;
        config.limits.login_per_account_per_hour = 3;
    })
    .await;

    for _ in 0..3 {
        let response = s.try_login("nobody", "wrong password!").await.1;
        assert_eq!(response.status(), 401);
    }
    let refused = s.try_login("nobody", "wrong password!").await.1;
    assert_eq!(refused.status(), 429);

    let failures = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_log \
         WHERE action = 'auth.login_failed' AND target = 'login:nobody'",
    )
    .fetch_one(s.core.db().pool())
    .await
    .unwrap();
    assert_eq!(failures, 3);
    let limited = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_log \
         WHERE action = 'auth.login_rate_limited' AND target = 'login:nobody'",
    )
    .fetch_one(s.core.db().pool())
    .await
    .unwrap();
    assert_eq!(limited, 1);
}

/// The 4th request with a token past the hourly budget gets a 429 with
/// `Retry-After`; every token response carries the `X-RateLimit-*` headers,
/// and another token is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_per_token_limit_returns_429_with_headers() {
    let s = TestServer::start_with(|config| {
        config.limits.api_per_token_per_hour = 3;
    })
    .await;
    let alice = s.user("alice").await;
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let other = s.token(&alice, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    let url = s.url("/api/v1/user");

    for want_remaining in ["2", "1", "0"] {
        let response = client.get(&url).bearer_auth(&token).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-ratelimit-limit"], "3");
        assert_eq!(response.headers()["x-ratelimit-remaining"], want_remaining);
        assert!(
            response.headers()["x-ratelimit-reset"]
                .to_str()
                .unwrap()
                .parse::<i64>()
                .is_ok()
        );
        assert!(response.headers().get("retry-after").is_none());
    }

    let refused = client.get(&url).bearer_auth(&token).send().await.unwrap();
    assert_eq!(refused.status(), 429);
    assert!(refused.headers().get("retry-after").is_some());
    assert_eq!(refused.headers()["x-ratelimit-limit"], "3");
    assert_eq!(refused.headers()["x-ratelimit-remaining"], "0");
    let body: Value = refused.json().await.unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");

    let unaffected = client.get(&url).bearer_auth(&other).send().await.unwrap();
    assert_eq!(unaffected.status(), 200);

    let anonymous = client.get(&url).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
    assert!(anonymous.headers().get("x-ratelimit-limit").is_none());
}

/// Pushes `refs/for/main/<topic>` from the cloned work repo; returns the raw
/// command output so refusals can be inspected.
async fn push_topic(work: &Path, url: &str, topic: &str) -> std::process::Output {
    git(work, &["push", url, &format!("HEAD:refs/for/main/{topic}")]).await
}

async fn wait_for_change(
    s: &TestServer,
    repo_id: i64,
    user_id: i64,
    topic: &str,
) -> starforged_db::changes::ChangeRow {
    let start = Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            user_id,
            "main",
            topic,
            None,
        )
        .await
        .unwrap();
        if let Some(change) = found {
            return change;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for change for topic {topic}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_revision_count(s: &TestServer, change_id: i64, expected: usize) {
    let start = Instant::now();
    loop {
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change_id)
            .await
            .unwrap();
        if revs.len() == expected {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {expected} revisions (have {})",
            revs.len()
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn setup_git_repo(s: &TestServer, alice: &User, name: &str) -> (i64, String, PathBuf) {
    s.repo(alice, name, Visibility::Private).await;
    let repo_id = s
        .core
        .repo_for(Some(alice), "alice", name)
        .await
        .unwrap()
        .repo
        .id;
    let token = s.token(alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", name, Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    (repo_id, url, work)
}

/// Past the hourly budget, a NEW `refs/for` change is refused with the
/// sideband message; pushing a revision to an existing topic still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refs_for_budget_refuses_new_changes_only() {
    let s = TestServer::start_with(|config| {
        config.limits.refs_for_new_changes_per_hour = 2;
    })
    .await;
    let alice = s.user("alice").await;
    let (repo_id, url, work) = setup_git_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "alpha").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/alpha"]).await;
    wait_for_change(&s, repo_id, alice.id, "alpha").await;

    commit_files(&work, &[("b.txt", b"b\n")], "beta").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/beta"]).await;
    wait_for_change(&s, repo_id, alice.id, "beta").await;

    commit_files(&work, &[("c.txt", b"c\n")], "gamma").await;
    let refused = push_topic(&work, &url, "gamma").await;
    assert!(
        !refused.status.success(),
        "third new change must be refused"
    );
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(output.contains("new-change"), "{output}");
    assert!(
        starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            alice.id,
            "main",
            "gamma",
            None
        )
        .await
        .unwrap()
        .is_none(),
        "refused topic must not create a change"
    );

    // An update push to the existing `alpha` topic is still accepted.
    commit_files(&work, &[("d.txt", b"d\n")], "alpha again").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/alpha"]).await;
    let alpha = wait_for_change(&s, repo_id, alice.id, "alpha").await;
    wait_for_revision_count(&s, alpha.id, 2).await;
}

/// Two new refs in one push that exceed the remaining budget are refused
/// together (pre-receive rejects the whole push).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refs_for_budget_refuses_two_new_refs_in_one_push() {
    let s = TestServer::start_with(|config| {
        config.limits.refs_for_new_changes_per_hour = 1;
    })
    .await;
    let alice = s.user("alice").await;
    let (repo_id, url, work) = setup_git_repo(&s, &alice, "proj").await;

    commit_files(&work, &[("a.txt", b"a\n")], "first").await;
    git_ok(&work, &["push", "-q", &url, "HEAD:refs/for/main/first"]).await;
    wait_for_change(&s, repo_id, alice.id, "first").await;

    commit_files(&work, &[("b.txt", b"b\n")], "batch").await;
    let refused = git(
        &work,
        &[
            "push",
            &url,
            "HEAD:refs/for/main/one",
            "HEAD:refs/for/main/two",
        ],
    )
    .await;
    assert!(
        !refused.status.success(),
        "over-budget pair must be refused"
    );
    for topic in ["one", "two"] {
        assert!(
            starforged_db::changes::open_agit_change(
                s.core.db(),
                repo_id,
                alice.id,
                "main",
                topic,
                None
            )
            .await
            .unwrap()
            .is_none(),
            "topic {topic} must not create a change"
        );
    }
}

/// Every limit set to `0` is disabled: logins, API requests, and new
/// `refs/for` changes proceed past what the limits would have refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_disables_every_limit() {
    let s = TestServer::start_with(|config| {
        config.limits.login_per_ip_per_minute = 0;
        config.limits.login_per_account_per_hour = 0;
        config.limits.api_per_token_per_hour = 0;
        config.limits.refs_for_new_changes_per_hour = 0;
    })
    .await;
    let alice = s.user("alice").await;

    for _ in 0..4 {
        let response = s.try_login("alice", "wrong password!").await.1;
        assert_eq!(response.status(), 401);
    }

    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();
    for _ in 0..5 {
        let response = client
            .get(s.url("/api/v1/user"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    let (repo_id, url, work) = setup_git_repo(&s, &alice, "proj").await;
    for topic in ["one", "two", "three"] {
        let file = format!("{topic}.txt");
        commit_files(&work, &[(file.as_str(), b"x\n".as_slice())], topic).await;
        git_ok(
            &work,
            &["push", "-q", &url, &format!("HEAD:refs/for/main/{topic}")],
        )
        .await;
        wait_for_change(&s, repo_id, alice.id, topic).await;
    }
}

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "test session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

/// The existing upload storage quota still rejects segments with its own
/// error (regression: rate limits did not disturb the session quotas).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_storage_quota_still_rejects_segments() {
    let s = TestServer::start_with(|config| {
        config.sessions.max_repo_bytes = 10;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let created = client
        .put(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID_Q}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_Q))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let rejected = client
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID_Q}/segments/0"
        )))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", "dd")
        .body(vec![9u8; 64])
        .send()
        .await
        .unwrap();
    assert!(rejected.status().is_client_error());
    let body: Value = rejected.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("quota"),
        "quota rejection must say so: {body}"
    );
}
