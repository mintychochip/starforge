//! Push-size and repository-size limits (P5 hardening): `receive.maxInputSize`
//! over HTTP and SSH, and the pre-receive hook's repository-size refusal.

mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

/// The current `refs/heads/main` tip of the hosted bare repository.
async fn main_tip(s: &TestServer, repo_id: i64) -> String {
    git_ok(
        &s.core.repo_path(repo_id),
        &["rev-parse", "refs/heads/main"],
    )
    .await
    .trim()
    .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_push_size_limit_refuses_large_push_and_keeps_ref() {
    let s = TestServer::start_with(|c| {
        c.limits.max_push_bytes = 4096;
    })
    .await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    // A small push succeeds under the limit.
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
    let before = main_tip(&s, repo.id).await;

    // A push whose pack exceeds the limit is refused and the ref stays put.
    commit_files(&work, &[("data/blob.bin", &noise(64 * 1024))], "add blob").await;
    let out = git(
        &work,
        &["push", &s.git_url("alice", "proj", Some(&token)), "main"],
    )
    .await;
    assert!(
        !out.status.success(),
        "large push must fail: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(main_tip(&s, repo.id).await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_push_size_limit_disabled_allows_large_push() {
    // Default configuration: `max_push_bytes` is 0 (disabled).
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    commit_files(&work, &[("data/blob.bin", &noise(64 * 1024))], "add blob").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_repo_size_limit_refuses_push_at_limit() {
    let s = TestServer::start_with(|c| {
        c.limits.max_repo_bytes = 1;
    })
    .await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    // The empty repository is below the limit, so the first push lands.
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
    let before = main_tip(&s, repo.id).await;

    // The repository is now above the limit: every push is refused.
    commit_files(&work, &[("b.txt", b"b")], "more").await;
    let out = git(
        &work,
        &["push", &s.git_url("alice", "proj", Some(&token)), "main"],
    )
    .await;
    assert!(
        !out.status.success(),
        "push at the limit must fail: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("repository size limit reached"),
        "push must report the size limit: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(main_tip(&s, repo.id).await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_repo_size_limit_large_limit_allows_push() {
    let s = TestServer::start_with(|c| {
        c.limits.max_repo_bytes = 1 << 40;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    commit_files(&work, &[("data/blob.bin", &noise(64 * 1024))], "add blob").await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_push_size_limit_refuses_large_push() {
    let s = TestServer::start_with(|c| {
        c.limits.max_push_bytes = 4096;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let dir = tempfile::tempdir().unwrap();
    let (priv_key, publine) = gen_key(dir.path(), "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    // A small push over SSH succeeds under the limit.
    s.ssh_git_ok(
        &work,
        &priv_key,
        &["push", "-q", &s.ssh_url("alice", "proj"), "main"],
    )
    .await;

    // A push whose pack exceeds the limit is refused.
    commit_files(&work, &[("data/blob.bin", &noise(64 * 1024))], "add blob").await;
    let out = s
        .ssh_git(
            &work,
            &priv_key,
            &["push", &s.ssh_url("alice", "proj"), "main"],
        )
        .await;
    assert!(
        !out.status.success(),
        "large SSH push must fail: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
