//! Cross-repository Trail changes: object import, source metadata, refresh,
//! merge, and the private-source leak rule.

mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    alice_rw: String,
    alice_repo: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let rw = &[Scope::RepoRead, Scope::TrailWrite];
        let repo = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
        Ctx {
            alice_rw: s.token(&alice, rw).await,
            alice_repo: s.token(&alice, repo).await,
            s,
            alice,
        }
    }

    fn api(&self, path: &str) -> String {
        self.s.url(&format!("/api/v1/repos/alice/target{path}"))
    }

    async fn push_target_main(&self) -> String {
        let url = self.s.git_url(
            "alice",
            "target",
            Some(&self.s.token(&self.alice, &[Scope::RepoWrite]).await),
        );
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let work = work_repo(&tmp_path, "target", &[("a.txt", "one\n")]).await;
        git_ok(&work, &["push", "-q", &url, "main"]).await;
        url
    }

    async fn push_source_feature(&self, target_url: &str) -> (String, std::path::PathBuf) {
        let url = self.s.git_url(
            "alice",
            "source",
            Some(&self.s.token(&self.alice, &[Scope::RepoWrite]).await),
        );
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        // Clone the target so the source shares its initial commit. Separate
        // initial commits would make the histories unrelated, and the merge
        // would correctly refuse with 409.
        git_ok(&tmp_path, &["clone", "-q", target_url, "source"]).await;
        let work = tmp_path.join("source");
        git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
        commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
        commit_files(&work, &[("b.txt", b"bee\n")], "add bee").await;
        git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
        (url, work)
    }

    async fn trail(&self) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.s.url("/api/v1/repos/alice/target/trails"))
            .bearer_auth(&self.alice_rw)
            .json(&json!({"title": "cross repo work", "intent": "ship it"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }

    async fn open_change(&self, n: i64, source: &str, branch: &str) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.api(&format!("/trails/{n}/changes")))
            .bearer_auth(&self.alice_rw)
            .json(&json!({
                "kind": "cross_repo",
                "source_repo": source,
                "source_branch": branch,
                "base_branch": "main",
            }))
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }

    async fn target_repo(&self) -> std::path::PathBuf {
        let repo = self
            .s
            .core
            .repo_for(Some(&self.alice), "alice", "target")
            .await
            .unwrap();
        self.s.core.repo_path(repo.repo.id)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_repo_change_imports_objects_and_merges() {
    let c = Ctx::start().await;
    c.s.repo(&c.alice, "target", Visibility::Private).await;
    c.s.repo(&c.alice, "source", Visibility::Private).await;
    let target_url = c.push_target_main().await;
    c.push_source_feature(&target_url).await;
    let n = c.trail().await;
    let (status, body) = c.open_change(n, "alice/source", "feature/x").await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["kind"], "branch");
    assert_eq!(body["head_branch"], "feature/x");
    assert_eq!(body["source"]["owner"], "alice");
    assert_eq!(body["source"]["repo"], "source");
    assert_eq!(body["source"]["branch"], "feature/x");
    let k = body["k"].as_i64().unwrap();
    assert_eq!(body["current_revision"], 1);

    // The head objects are present in the target repository.
    let server = c.target_repo().await;
    let gd = format!("--git-dir={}", server.display());
    let work = tempfile::tempdir().unwrap();
    let trail_ref = format!("refs/trails/{n}/changes/{k}/head");
    let sha = git_ok(work.path(), &[&gd, "rev-parse", &trail_ref])
        .await
        .trim()
        .to_owned();
    git_ok(
        work.path(),
        &[&gd, "cat-file", "-e", &format!("{sha}^{{commit}}")],
    )
    .await;
    assert_eq!(
        git_ok(work.path(), &[&gd, "show", &format!("{sha}:a.txt")]).await,
        "one\ntwo\n"
    );

    // Merge the cross-repository change into the target's main.
    let client = reqwest::Client::new();
    let res = client
        .post(c.api(&format!("/trails/{n}/changes/{k}/merge")))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let merged: Value = res.json().await.unwrap();
    assert_eq!(merged["method"], "merge");
    let main_sha = git_ok(work.path(), &[&gd, "rev-parse", "refs/heads/main"])
        .await
        .trim()
        .to_owned();
    assert_eq!(merged["sha"], main_sha);
    assert_eq!(
        git_ok(work.path(), &[&gd, "show", "refs/heads/main:a.txt"]).await,
        "one\ntwo\n"
    );
    assert_eq!(
        git_ok(work.path(), &[&gd, "show", "refs/heads/main:b.txt"]).await,
        "bee\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_repo_refresh_appends_a_revision() {
    let c = Ctx::start().await;
    c.s.repo(&c.alice, "target", Visibility::Private).await;
    c.s.repo(&c.alice, "source", Visibility::Private).await;
    let target_url = c.push_target_main().await;
    let (source_url, work) = c.push_source_feature(&target_url).await;
    let n = c.trail().await;
    let (status, body) = c.open_change(n, "alice/source", "feature/x").await;
    assert_eq!(status, 201, "{body}");
    let k = body["k"].as_i64().unwrap();
    assert_eq!(body["current_revision"], 1);

    // Move the source branch in the same working copy.
    commit_files(&work, &[("c.txt", b"see\n")], "add see").await;
    git_ok(&work, &["push", "-q", &source_url, "feature/x"]).await;

    let client = reqwest::Client::new();
    let res = client
        .post(c.api(&format!("/trails/{n}/changes/{k}/refresh")))
        .bearer_auth(&c.alice_rw)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let refreshed: Value = res.json().await.unwrap();
    assert_eq!(refreshed["current_revision"], 2);
    assert_eq!(refreshed["state"], "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_repo_refuses_private_sources_and_missing_branches() {
    let c = Ctx::start().await;
    let bob = c.s.user("bob").await;
    c.s.repo(&c.alice, "target", Visibility::Public).await;
    c.s.repo(&bob, "secret", Visibility::Private).await;
    c.s.repo(&c.alice, "source", Visibility::Public).await;
    c.push_target_main().await;
    c.s.core
        .set_collaborator(&bob, "bob", "secret", "alice", Permission::Read)
        .await
        .unwrap();
    let n = c.trail().await;

    let (status, body) = c.open_change(n, "bob/secret", "main").await;
    assert_eq!(status, 403, "{body}");

    let (status, body) = c.open_change(n, "alice/source", "no-such-branch").await;
    assert_eq!(status, 422, "{body}");
    let text = serde_json::to_string(&body).unwrap();
    assert!(text.contains("cannot fetch source branch"), "{text}");
}
