//! H4: server-side merge + Trail merged transition. Real git over HTTP,
//! in-process server (follows `api_changes.rs` / `web_changes.rs`).
mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use starforged_db::checks::GateRuleUpdate;

use common::*;
use serde_json::{Value, json};
use starforged_core::merge::PreCasHook;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    alice_rw: String,
    alice_repo: String,
    carol_rw: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let carol = s.user("carol").await;
        s.repo(&alice, "proj", Visibility::Private).await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        let rw = &[Scope::RepoRead, Scope::TrailWrite];
        Ctx {
            alice_rw: s.token(&alice, rw).await,
            alice_repo: s
                .token(
                    &alice,
                    &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
                )
                .await,
            carol_rw: s.token(&carol, rw).await,
            s,
            alice,
        }
    }

    async fn repo_id(&self) -> i64 {
        self.s
            .core
            .repo_for(Some(&self.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id
    }

    async fn server(&self) -> PathBuf {
        self.s.core.repo_path(self.repo_id().await)
    }

    fn trails(&self) -> String {
        self.s.url("/api/v1/repos/alice/proj/trails")
    }

    fn merge(&self, n: i64, k: i64) -> String {
        self.s.url(&format!(
            "/api/v1/repos/alice/proj/trails/{n}/changes/{k}/merge"
        ))
    }

    fn change(&self, n: i64, k: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes/{k}"))
    }

    async fn trail(&self) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.trails())
            .bearer_auth(&self.alice_rw)
            .json(&json!({"title": "feature work", "intent": "ship it"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }

    /// Pushes `main` plus a two-commit `feature/x`; returns the working copy.
    async fn push_basic(&self) -> (PathBuf, String) {
        let url = self.s.git_url(
            "alice",
            "proj",
            Some(&self.s.token(&self.alice, &[Scope::RepoWrite]).await),
        );
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
        git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
        commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
        commit_files(&work, &[("b.txt", b"bee\n")], "add bee").await;
        git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
        (work, url)
    }

    /// Pushes `main` and `feature/x` whose commits carry session trailers.
    async fn push_trailered(&self) -> (PathBuf, String) {
        let url = self.s.git_url(
            "alice",
            "proj",
            Some(&self.s.token(&self.alice, &[Scope::RepoWrite]).await),
        );
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
        git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
        commit_files(
            &work,
            &[("a.txt", b"one\ntwo\n")],
            &format!("feat one\n\nStarforge-Session: {ULID_A}\n"),
        )
        .await;
        commit_files(
            &work,
            &[("b.txt", b"bee\n")],
            &format!("feat two\n\nStarforge-Session: {ULID_A}\n"),
        )
        .await;
        git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
        (work, url)
    }

    async fn create_branch_change(&self, n: i64, head: &str, base: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(
                self.s
                    .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes")),
            )
            .bearer_auth(&self.alice_rw)
            .json(&json!({"kind": "branch", "head_branch": head, "base_branch": base}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create branch change");
        res.json::<Value>().await.unwrap()
    }

    async fn post_merge(&self, n: i64, k: i64, token: &str, method: &str) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.merge(n, k))
            .bearer_auth(token)
            .json(&json!({"method": method}))
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn trail_state(&self, n: i64) -> String {
        starforged_db::trails::trail_by_number(self.s.core.db(), self.repo_id().await, n)
            .await
            .unwrap()
            .unwrap()
            .state
    }

    async fn timeline_kinds(&self, n: i64) -> Vec<String> {
        let trail =
            starforged_db::trails::trail_by_number(self.s.core.db(), self.repo_id().await, n)
                .await
                .unwrap()
                .unwrap();
        starforged_db::trails::timeline_of_trail(self.s.core.db(), trail.id)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    async fn audit_count(&self, action: &str, target: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
            .bind(action)
            .bind(target)
            .fetch_one(self.s.core.db().pool())
            .await
            .unwrap()
    }
}

fn git_dir_arg(server: &Path) -> String {
    format!("--git-dir={}", server.display())
}

async fn server_rev(work: &Path, server: &Path, r: &str) -> String {
    let gd = git_dir_arg(server);
    git_ok(work, &[&gd, "rev-parse", "--verify", r])
        .await
        .trim()
        .to_owned()
}

async fn server_message(work: &Path, server: &Path, rev: &str) -> String {
    let gd = git_dir_arg(server);
    let out = git_ok(work, &[&gd, "log", "--format=%B", "-n", "1", rev]).await;
    out.trim_end_matches('\n').to_owned()
}

async fn server_parents(work: &Path, server: &Path, rev: &str) -> Vec<String> {
    let gd = git_dir_arg(server);
    let out = git_ok(work, &[&gd, "rev-list", "--parents", "-n", "1", rev]).await;
    let mut parts: Vec<String> = out.split_whitespace().map(str::to_owned).collect();
    parts.remove(0);
    parts
}

/// Moves the base ref forward on every firing (fresh commit each time, so a
/// second firing races a retry too). Synchronous: the merge path runs it on a
/// blocking thread.
fn advancing_hook(server: PathBuf, base: &str) -> PreCasHook {
    let counter = Arc::new(AtomicU64::new(0));
    let base = base.to_owned();
    PreCasHook::new(move || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_AUTHOR_NAME", "hook")
                .env("GIT_AUTHOR_EMAIL", "hook@test")
                .env("GIT_COMMITTER_NAME", "hook")
                .env("GIT_COMMITTER_EMAIL", "hook@test")
                .arg(format!("--git-dir={}", server.display()))
                .args(args)
                .output()
                .expect("hook git runs");
            assert!(out.status.success(), "hook git failed: {args:?}");
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let tip = run(&["rev-parse", "--verify", &base]);
        let tree = run(&["rev-parse", &format!("{tip}^{{tree}}")]);
        let new = run(&[
            "commit-tree",
            &tree,
            "-p",
            &tip,
            "-m",
            &format!("hook advance {n}"),
        ]);
        run(&["update-ref", &base, &new, &tip]);
    })
}

/// Moves the base ref forward only on the first firing; later firings are a
/// no-op, so the merge retry converges.
fn once_hook(server: PathBuf, base: &str) -> PreCasHook {
    let fired = Arc::new(AtomicBool::new(false));
    let base = base.to_owned();
    PreCasHook::new(move || {
        if fired.swap(true, Ordering::SeqCst) {
            return;
        };
        let run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_AUTHOR_NAME", "hook")
                .env("GIT_AUTHOR_EMAIL", "hook@test")
                .env("GIT_COMMITTER_NAME", "hook")
                .env("GIT_COMMITTER_EMAIL", "hook@test")
                .arg(format!("--git-dir={}", server.display()))
                .args(args)
                .output()
                .expect("hook git runs");
            assert!(out.status.success(), "hook git failed: {args:?}");
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let tip = run(&["rev-parse", "--verify", &base]);
        let tree = run(&["rev-parse", &format!("{tip}^{{tree}}")]);
        let new = run(&["commit-tree", &tree, "-p", &tip, "-m", "hook advance"]);
        run(&["update-ref", &base, &new, &tip]);
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_moves_base_with_two_parents_and_trailer() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let base = server_rev(&work, &server, "refs/heads/main").await;
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["method"], "merge");
    let sha = body["sha"].as_str().unwrap().to_owned();

    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, sha);
    assert_eq!(server_parents(&work, &server, &sha).await, vec![base, head]);
    let message = server_message(&work, &server, &sha).await;
    assert!(message.starts_with("feature work (#1)\n"), "{message}");
    assert!(
        message.contains("Starforge-Trail: alice/proj#1"),
        "{message}"
    );

    let client = reqwest::Client::new();
    let detail: Value = client
        .get(c.change(n, 1))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["change"]["state"], "merged");
    assert_eq!(c.trail_state(n).await, "merged");

    let kinds = c.timeline_kinds(n).await;
    assert!(kinds.contains(&"change.merge".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"trail.merged".to_owned()), "{kinds:?}");
    assert_eq!(
        c.audit_count("change.merge", "change:alice/proj#1/1").await,
        1
    );
    assert_eq!(c.audit_count("trail.merged", "trail:alice/proj#1").await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn squash_composes_message_with_subjects_and_distinct_trailers() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_trailered().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let base = server_rev(&work, &server, "refs/heads/main").await;
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "squash").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["method"], "squash");
    let sha = body["sha"].as_str().unwrap().to_owned();

    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, sha);
    // One parent (the base tip): a linear, fast-forwardable history.
    assert_eq!(
        server_parents(&work, &server, &sha).await,
        vec![base.clone()]
    );
    // The squashed tree equals the head tree.
    let gd = git_dir_arg(&server);
    let squash_tree = git_ok(&work, &[&gd, "rev-parse", &format!("{sha}^{{tree}}")]).await;
    let head_tree = git_ok(&work, &[&gd, "rev-parse", &format!("{head}^{{tree}}")]).await;
    assert_eq!(squash_tree, head_tree);

    let expected = format!(
        "feature work (#1)\n\nfeat one\nfeat two\n\nStarforge-Session: {ULID_A}\n\
         Change: alice/proj#1/1\n\nStarforge-Trail: alice/proj#1\n"
    );
    let message = server_message(&work, &server, &sha).await;
    assert_eq!(message, expected.trim_end_matches('\n'));
    // No duplicate session trailer.
    assert_eq!(
        message
            .matches(&format!("Starforge-Session: {ULID_A}"))
            .count(),
        1,
        "{message}"
    );
    // Fast-forwardable: the old base is an ancestor of the new tip.
    let gd = git_dir_arg(&server);
    let out = git(&work, &[&gd, "merge-base", "--is-ancestor", &base, &sha]).await;
    assert!(out.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_forward_moves_ref_without_new_commit() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "fast_forward").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["sha"], head);
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, head);
    assert_eq!(c.trail_state(n).await, "merged");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_forward_refuses_when_head_lacks_base() {
    let c = Ctx::start().await;
    let (work, url) = c.push_basic().await;
    let server = c.server().await;
    // Advance main past the branch point: the head no longer contains base.
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit_files(&work, &[("a.txt", b"one\nmain-two\n")], "main two").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let before = server_rev(&work, &server, "refs/heads/main").await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "fast_forward").await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflict_is_409_with_paths_and_base_unchanged() {
    let c = Ctx::start().await;
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\nfeature\n")], "feature edit").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit_files(&work, &[("a.txt", b"one\nmainline\n")], "main edit").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let server = c.server().await;

    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let before = server_rev(&work, &server, "refs/heads/main").await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 409, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("a.txt"), "{body}");
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gates_rechecked_at_merge_time_stale_report_refuses() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;

    // The client saw a passing report (no rules yet)…
    let client = reqwest::Client::new();
    let gates: Value = client
        .get(format!("{}/gates", c.change(n, 1)))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(gates["passed"].as_bool().unwrap());

    // …then a rule landed. The merge still refuses: it never trusts the report.
    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        c.repo_id().await,
        None,
        1,
        false,
        false,
        "[]",
        false,
        false,
        false,
        "[]",
        false,
        false,
        false,
        starforged_db::now(),
    )
    .await
    .unwrap();
    let before = server_rev(&work, &server, "refs/heads/main").await;
    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 422, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("needs 1 more approval"), "{body}");
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_plus_status_satisfies_gate_then_merge() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;

    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        c.repo_id().await,
        None,
        1,
        false,
        false,
        "[\"ci/unit\"]",
        false,
        false,
        false,
        "[]",
        false,
        false,
        false,
        starforged_db::now(),
    )
    .await
    .unwrap();
    let client = reqwest::Client::new();
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/alice/proj/statuses/{head}")))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"state": "success", "context": "ci/unit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let res = client
        .post(format!("{}/reviews", c.change(n, 1)))
        .bearer_auth(&c.alice_repo)
        .json(&json!({"verdict": "approve", "body": "ship it"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 200, "{body}");
    let sha = body["sha"].as_str().unwrap().to_owned();
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, sha);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cas_race_retries_once_then_409s_with_new_state() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    c.s.core
        .set_merge_cas_hook(Some(advancing_hook(server.clone(), "refs/heads/main")));

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    c.s.core.set_merge_cas_hook(None);
    assert_eq!(status, 409, "{body}");
    // The report carries the fresh base tip, not the stale one.
    let tip = server_rev(&work, &server, "refs/heads/main").await;
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains(&tip), "{body}");

    // Nothing merged: the change is still open.
    let client = reqwest::Client::new();
    let detail: Value = client
        .get(c.change(n, 1))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["change"]["state"], "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_base_move_retries_to_success() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;
    c.s.core
        .set_merge_cas_hook(Some(once_hook(server.clone(), "refs/heads/main")));

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    c.s.core.set_merge_cas_hook(None);
    assert_eq!(status, 200, "{body}");
    let sha = body["sha"].as_str().unwrap().to_owned();
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, sha);
    // Two parents: the moved base tip and the change head.
    let parents = server_parents(&work, &server, &sha).await;
    assert_eq!(parents.len(), 2);
    assert_eq!(parents[1], head);
    let hook_subject = server_message(&work, &server, &parents[0]).await;
    assert!(hook_subject.starts_with("hook advance"), "{hook_subject}");
}

/// The CAS retry re-checks the allowed methods: a rule edit landing between
/// the two CAS attempts that disallows the in-flight method refuses with
/// 422, leaving the base at the racer's tip and the change open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cas_retry_rechecks_allowed_methods() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let repo_id = c.repo_id().await;
    let rule = starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        repo_id,
        None,
        0,
        false,
        false,
        "[]",
        false,
        false,
        false,
        "[\"merge\"]",
        false,
        false,
        false,
        starforged_db::now(),
    )
    .await
    .unwrap();
    // Rendezvous: the hook moves the base once (forcing the retry), signals
    // the test, and waits until the test has edited the rule, so the edit
    // deterministically lands between the two CAS attempts.
    let (fired_tx, fired_rx) = std::sync::mpsc::channel::<()>();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel::<()>();
    let proceed_rx = Arc::new(std::sync::Mutex::new(proceed_rx));
    let hook_server = server.clone();
    let moved = Arc::new(AtomicBool::new(false));
    let hook = PreCasHook::new(move || {
        if moved.swap(true, Ordering::SeqCst) {
            return;
        }
        let run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_AUTHOR_NAME", "hook")
                .env("GIT_AUTHOR_EMAIL", "hook@test")
                .env("GIT_COMMITTER_NAME", "hook")
                .env("GIT_COMMITTER_EMAIL", "hook@test")
                .arg(format!("--git-dir={}", hook_server.display()))
                .args(args)
                .output()
                .expect("hook git runs");
            assert!(out.status.success(), "hook git failed: {args:?}");
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let tip = run(&["rev-parse", "--verify", "refs/heads/main"]);
        let tree = run(&["rev-parse", &format!("{tip}^{{tree}}")]);
        let new = run(&["commit-tree", &tree, "-p", &tip, "-m", "hook advance"]);
        run(&["update-ref", "refs/heads/main", &new, &tip]);
        fired_tx.send(()).expect("test waits for the hook");
        proceed_rx
            .lock()
            .expect("proceed channel")
            .recv_timeout(Duration::from_secs(30))
            .expect("test edits the rule, then releases the hook");
    });
    c.s.core.set_merge_cas_hook(Some(hook));
    let merge_url = c.merge(n, 1);
    let token = c.alice_repo.clone();
    let merge_task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        let res = client
            .post(merge_url)
            .bearer_auth(token)
            .json(&json!({"method": "merge"}))
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        (status, body)
    });
    tokio::task::spawn_blocking(move || {
        fired_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("hook fires before the first CAS")
    })
    .await
    .unwrap();
    starforged_db::checks::update_gate_rule(
        c.s.core.db(),
        rule.id,
        repo_id,
        &GateRuleUpdate {
            methods: Some("[\"squash\"]"),
            ..Default::default()
        },
        starforged_db::now(),
    )
    .await
    .unwrap();
    proceed_tx.send(()).unwrap();
    let (status, body) = merge_task.await.unwrap();
    c.s.core.set_merge_cas_hook(None);
    assert_eq!(status, 422, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("merge"), "{body}");
    // The base stays at the racer's tip: the merge moved nothing.
    let tip = server_rev(&work, &server, "refs/heads/main").await;
    let subject = server_message(&work, &server, &tip).await;
    assert!(subject.starts_with("hook advance"), "{subject}");
    // Nothing merged: the change is still open.
    let client = reqwest::Client::new();
    let detail: Value = client
        .get(c.change(n, 1))
        .bearer_auth(&c.alice_repo)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["change"]["state"], "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_forward_retry_refuses_rewind_after_base_moves() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    let base_before = server_rev(&work, &server, "refs/heads/main").await;
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;
    // The hook advances the base once past the head's history; the retry
    // must refuse rather than drag the branch back to the head.
    c.s.core
        .set_merge_cas_hook(Some(once_hook(server.clone(), "refs/heads/main")));
    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "fast_forward").await;
    c.s.core.set_merge_cas_hook(None);
    assert_eq!(status, 409, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("no longer an ancestor"), "{body}");
    // The base was NOT rewound: the racer's commit is still the tip, still
    // built on the old base.
    let tip = server_rev(&work, &server, "refs/heads/main").await;
    assert_ne!(tip, head);
    let subject = server_message(&work, &server, &tip).await;
    assert!(subject.starts_with("hook advance"), "{subject}");
    let gd = git_dir_arg(&server);
    assert!(
        git(
            &work,
            &[&gd, "merge-base", "--is-ancestor", &base_before, &tip],
        )
        .await
        .status
        .success()
    );
    // Nothing merged: the change is still open.
    let client = reqwest::Client::new();
    let detail: Value = client
        .get(c.change(n, 1))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["change"]["state"], "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_merges_only_after_last_open_change_merges() {
    let c = Ctx::start().await;
    let url = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
    for (branch, file) in [("feature/x", "x.txt"), ("feature/y", "y.txt")] {
        git_ok(&work, &["checkout", "-q", "-b", branch, "main"]).await;
        commit_files(&work, &[(file, format!("{branch}\n").as_bytes())], branch).await;
    }
    git_ok(
        &work,
        &["push", "-q", &url, "main", "feature/x", "feature/y"],
    )
    .await;

    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    c.create_branch_change(n, "feature/y", "main").await;

    let (status, _) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 200);
    assert_eq!(c.trail_state(n).await, "open");
    let kinds = c.timeline_kinds(n).await;
    assert!(!kinds.contains(&"trail.merged".to_owned()), "{kinds:?}");

    let (status, _) = c.post_merge(n, 2, &c.alice_repo, "merge").await;
    assert_eq!(status, 200);
    assert_eq!(c.trail_state(n).await, "merged");
    assert!(
        c.timeline_kinds(n)
            .await
            .contains(&"trail.merged".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_rejects_archived_unknown_method_and_non_writers() {
    let c = Ctx::start().await;
    let (_work, _url) = c.push_basic().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;

    // Unknown method.
    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "octopus").await;
    assert_eq!(status, 422, "{body}");

    // A reader cannot merge (403); anonymous callers cannot either (401).
    let (status, _) = c.post_merge(n, 1, &c.carol_rw, "merge").await;
    assert_eq!(status, 403);
    let client = reqwest::Client::new();
    let res = client
        .post(c.merge(n, 1))
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // An archived repository refuses merges.
    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();
    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 422, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_merge_form_merges_on_post() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;

    let (browser, _jar) = c.s.login("alice").await;
    let page_url = c.s.url(&format!("/alice/proj/trails/{n}/changes/1"));
    let head = server_rev(&work, &server, "refs/heads/feature/x").await;

    // No rules: gates pass, every method is offered, the button is live.
    let page = get_text(&browser, &page_url).await;
    assert!(page.contains("gates pass"), "{page}");
    assert!(page.contains(r#"name="method""#), "{page}");
    assert!(
        page.contains(r#"<button type="submit">Merge</button>"#),
        "{page}"
    );

    // A failing rule disables the button (the server re-checks on POST anyway).
    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        c.repo_id().await,
        None,
        1,
        false,
        false,
        "[]",
        false,
        false,
        false,
        "[]",
        false,
        false,
        false,
        starforged_db::now(),
    )
    .await
    .unwrap();
    let page = get_text(&browser, &page_url).await;
    assert!(page.contains("Gates failing"), "{page}");
    assert!(
        !page.contains(r#"<button type="submit">Merge</button>"#),
        "{page}"
    );

    // …so a direct POST still refuses.
    let csrf = extract_input(&page, "_csrf");
    let res = browser
        .post(c.s.url(&format!("/alice/proj/trails/{n}/changes/1/merge")))
        .form(&[("_csrf", csrf.as_str()), ("method", "merge")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // An approval re-enables the merge; posting merges the base.
    c.s.core
        .submit_review(
            &c.alice,
            "alice",
            "proj",
            n,
            1,
            None,
            "approve",
            "lgtm",
            None,
            &[],
        )
        .await
        .unwrap();
    let page = get_text(&browser, &page_url).await;
    assert!(
        page.contains(r#"<button type="submit">Merge</button>"#),
        "{page}"
    );
    let csrf = extract_input(&page, "_csrf");
    let res = browser
        .post(c.s.url(&format!("/alice/proj/trails/{n}/changes/1/merge")))
        .form(&[("_csrf", csrf.as_str()), ("method", "fast_forward")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{res:?}");
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, head);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_authors_two_approvals_count_once() {
    // D10: approval de-duplication is one voice per author — the latest
    // decisive review. Two `approve` reviews from alice satisfy one of two
    // required approvals, never both.
    let c = Ctx::start().await;
    let (_work, _url) = c.push_basic().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;
    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        c.repo_id().await,
        None,
        2,
        false,
        false,
        "[]",
        false,
        false,
        false,
        "[]",
        false,
        false,
        false,
        starforged_db::now(),
    )
    .await
    .unwrap();

    let client = reqwest::Client::new();
    for body in ["first look", "second look"] {
        let res = client
            .post(format!("{}/reviews", c.change(n, 1)))
            .bearer_auth(&c.alice_repo)
            .json(&json!({"verdict": "approve", "body": body}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "submit {body}");
    }

    let gates: Value = client
        .get(format!("{}/gates", c.change(n, 1)))
        .bearer_auth(&c.alice_rw)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!gates["passed"].as_bool().unwrap(), "{gates}");
    let text = serde_json::to_string(&gates).unwrap();
    assert!(
        text.contains("needs 1 more approval"),
        "two approvals from one author count once: {gates}"
    );
    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "merge").await;
    assert_eq!(status, 422, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebase_replays_commits_onto_base_with_authors_and_trailer() {
    let c = Ctx::start().await;
    let (work, _url) = c.push_basic().await;
    let server = c.server().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "rebase").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["method"], "rebase");
    let sha = body["sha"].as_str().unwrap().to_owned();
    assert_eq!(server_rev(&work, &server, "refs/heads/main").await, sha);

    // The base now has the original commit plus the two replayed commits.
    let gd = git_dir_arg(&server);
    let count = git_ok(&work, &[&gd, "rev-list", "--count", "refs/heads/main"]).await;
    assert_eq!(count.trim(), "3");
    assert_eq!(server_parents(&work, &server, &sha).await.len(), 1);
    let subjects = git_ok(&work, &[&gd, "log", "--format=%s", "refs/heads/main"]).await;
    let subjects: Vec<&str> = subjects.lines().collect();
    assert_eq!(subjects, vec!["add bee", "add two", "initial commit"]);
    let bodies = git_ok(&work, &[&gd, "log", "--format=%B", "refs/heads/main"]).await;
    assert!(
        bodies.matches("Starforge-Trail: alice/proj#1").count() >= 2,
        "{bodies}"
    );
    assert_eq!(
        git_ok(&work, &[&gd, "show", "refs/heads/main:a.txt"]).await,
        "one\ntwo\n"
    );
    assert_eq!(
        git_ok(&work, &[&gd, "show", "refs/heads/main:b.txt"]).await,
        "bee\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebase_refuses_conflicts_and_non_linear_histories() {
    let c = Ctx::start().await;
    let (work, url) = c.push_basic().await;
    let n = c.trail().await;
    c.create_branch_change(n, "feature/x", "main").await;

    // Move main under the change with a conflicting edit.
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit_files(&work, &[("a.txt", b"main side\n")], "main side").await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "feature/x"]).await;

    let (status, body) = c.post_merge(n, 1, &c.alice_repo, "rebase").await;
    assert_eq!(status, 409, "{body}");
    let text = serde_json::to_string(&body).unwrap();
    assert!(text.contains("rebase conflict"), "{text}");
    assert!(text.contains("a.txt"), "{text}");

    // A merge commit in the change range is refused before any replay.
    let c2 = Ctx::start().await;
    let (work2, url2) = c2.push_basic().await;
    let n2 = c2.trail().await;
    c2.create_branch_change(n2, "feature/x", "main").await;
    git_ok(&work2, &["checkout", "-q", "-b", "side", "main"]).await;
    commit_files(&work2, &[("side.txt", b"side\n")], "side commit").await;
    git_ok(&work2, &["checkout", "-q", "feature/x"]).await;
    git_ok(
        &work2,
        &["merge", "-q", "--no-ff", "side", "-m", "merge side"],
    )
    .await;
    git_ok(&work2, &["push", "-q", &url2, "feature/x"]).await;
    let (status, body) = c2.post_merge(n2, 1, &c2.alice_repo, "rebase").await;
    assert_eq!(status, 422, "{body}");
    let text = serde_json::to_string(&body).unwrap();
    assert!(text.contains("linear history"), "{text}");
}
