mod common;

use std::time::Duration;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushes_queue_git_maintenance() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    // The push response ends before the server reaps git, so the job appears shortly after.
    let key = format!("git_maintenance:{}", repo.id);
    let mut queued = 0_i64;
    for _ in 0..100 {
        queued = sqlx::query_scalar(
            "SELECT COUNT(*) FROM jobs WHERE dedupe_key = $1 AND state = 'queued'",
        )
        .bind(key.as_str())
        .fetch_one(s.core.db().pool())
        .await
        .unwrap();
        if queued == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(queued, 1, "the push queued maintenance");
    s.core.run_due_jobs().await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE dedupe_key = $1")
        .bind(key.as_str())
        .fetch_one(s.core.db().pool())
        .await
        .unwrap();
    assert_eq!(state, "done");
}
