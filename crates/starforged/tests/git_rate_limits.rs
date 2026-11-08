//! Git rate limit (Phase 5): one per-IP fixed window shared by git smart
//! HTTP and SSH public-key auth attempts, set by
//! `limits.git_per_ip_per_minute`; `0` disables it.

mod common;

use common::*;
use starforged_core::permission::Visibility;

/// With a budget of 3, three `info/refs` requests succeed and the fourth
/// answers 429 with `Retry-After` and a plain-text body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_http_rate_limit_answers_429_with_retry_after() {
    let s = TestServer::start_with(|config| {
        config.limits.git_per_ip_per_minute = 3;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let client = reqwest::Client::new();
    let url = s.url("/alice/proj.git/info/refs?service=git-upload-pack");
    for _ in 0..3 {
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 200, "within the budget");
    }
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 429, "past the budget");
    assert!(
        response.headers().contains_key("retry-after"),
        "429 carries Retry-After"
    );
    let body = response.text().await.unwrap();
    assert_eq!(body.trim(), "rate limit exceeded");
}

/// With the limit disabled (`0`), no burst is ever refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_http_rate_limit_disabled_allows_burst() {
    let s = TestServer::start_with(|config| {
        config.limits.git_per_ip_per_minute = 0;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let client = reqwest::Client::new();
    let url = s.url("/alice/proj.git/info/refs?service=git-upload-pack");
    for _ in 0..5 {
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 200, "unlimited");
    }
}

/// SSH shares the window: three auth attempts succeed, the fourth is
/// rejected before any key lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_auth_rate_limit_rejects_attempts_past_the_budget() {
    let s = TestServer::start_with(|config| {
        config.limits.git_per_ip_per_minute = 3;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let tmp = tempfile::tempdir().unwrap();
    let (priv_key, publine) = gen_key(tmp.path(), "id", "ed25519", None);
    s.add_key(&alice, &publine).await;
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    let url = s.ssh_url("alice", "proj");
    for _ in 0..3 {
        let out = s.ssh_git(&work, &priv_key, &["ls-remote", &url]).await;
        assert!(
            out.status.success(),
            "within the budget: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = s.ssh_git(&work, &priv_key, &["ls-remote", &url]).await;
    assert!(!out.status.success(), "past the budget");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Permission denied"),
        "auth rejected: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
