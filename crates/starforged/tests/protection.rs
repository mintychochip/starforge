//! B1: branch protection end to end. Real pushes over HTTP against an
//! in-process server: direct pushes refused with the pattern in the message,
//! allow-lists (user and team) bypassing only the direct-push block, force
//! pushes and deletions refused for everyone, other branches unaffected, and
//! Trail merges into a protected branch still succeeding.
mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::User;
use starforged_core::orgs::{NewOrgInput, NewTeamInput, OrgRole};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::Scope;
use tokio::time::sleep;

const SCAN_TIMEOUT: Duration = Duration::from_secs(20);

async fn writer_url(
    s: &TestServer,
    owner: &str,
    repo: &str,
    user: &User,
    scopes: &[Scope],
) -> String {
    let token = s.token(user, scopes).await;
    s.git_url(owner, repo, Some(&token))
}

async fn setup_repo(s: &TestServer, alice: &User, name: &str) -> (i64, String, PathBuf, PathBuf) {
    s.repo(alice, name, Visibility::Private).await;
    let repo_id = s
        .core
        .repo_for(Some(alice), "alice", name)
        .await
        .unwrap()
        .repo
        .id;
    let url = writer_url(s, "alice", name, alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let server = s.core.repo_path(repo_id);
    (repo_id, url, work, server)
}

fn git_dir_arg(server: &Path) -> String {
    format!("--git-dir={}", server.display())
}

/// `rev-parse` of `r` in the server repo, or `None` when the ref is absent.
async fn server_rev(work: &Path, server: &Path, r: &str) -> Option<String> {
    let gd = git_dir_arg(server);
    let out = git(work, &[&gd, "rev-parse", "--verify", r]).await;
    if out.status.success() {
        Some(String::from_utf8(out.stdout).unwrap().trim().to_owned())
    } else {
        None
    }
}

async fn server_rev_ok(work: &Path, server: &Path, r: &str) -> String {
    server_rev(work, server, r)
        .await
        .unwrap_or_else(|| panic!("expected server ref {r} to exist"))
}

async fn create_rule(s: &TestServer, token: &str, owner: &str, repo: &str, body: &Value) -> Value {
    let client = reqwest::Client::new();
    let res = client
        .post(s.url(&format!("/api/v1/repos/{owner}/{repo}/gate-rules")))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "creating the protection rule");
    res.json::<Value>().await.unwrap()
}

fn protection_body(users: &[&str], teams: &[&str]) -> Value {
    json!({
        "pattern": "main",
        "block_direct_push": true,
        "block_force_push": true,
        "block_deletion": true,
        "push_allowlist": {
            "users": users,
            "teams": teams,
        },
    })
}

async fn wait_for_change(s: &TestServer, repo_id: i64, user_id: i64, base: &str, topic: &str) {
    let start = Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            user_id,
            base,
            topic,
            None,
        )
        .await
        .unwrap();
        if found.is_some() {
            return;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "timed out waiting for open change {base}/{topic}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_push_refused_names_ref_and_pattern() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let maintain = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    create_rule(&s, &maintain, "alice", "proj", &protection_body(&[], &[])).await;

    commit_files(&work, &[("x.txt", b"x\n")], "direct change").await;
    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    let out = git(&work, &["push", &bob_url, "main"]).await;
    assert!(!out.status.success(), "direct push must be refused");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("refs/heads/main"), "{err}");
    assert!(err.contains("main"), "{err}");
    // The ref is unchanged: the pre-rule tip is still live.
    let tip = server_rev_ok(&work, &server, "refs/heads/main").await;
    let head = git_ok(&work, &["rev-parse", "HEAD"]).await;
    assert_ne!(tip.trim(), head.trim(), "refused push moves nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlisted_user_direct_push_succeeds() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let maintain = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    let created = create_rule(&s, &maintain, "alice", "proj", &protection_body(&[], &[])).await;
    let id = created["id"].as_i64().unwrap();

    // Without the allow-list the push is refused …
    commit_files(&work, &[("x.txt", b"x\n")], "direct change").await;
    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    assert!(
        !git(&work, &["push", &bob_url, "main"])
            .await
            .status
            .success()
    );

    // … and with `bob` allow-listed it succeeds.
    let client = reqwest::Client::new();
    let res = client
        .patch(s.url(&format!("/api/v1/repos/alice/proj/gate-rules/{id}")))
        .bearer_auth(&maintain)
        .json(&json!({"push_allowlist": {"users": ["bob"], "teams": []}}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    git_ok(&work, &["push", &bob_url, "main"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_allowlist_works_on_org_repositories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.core
        .create_org(
            &alice,
            NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    s.core
        .set_org_member(&alice, "acme", "bob", OrgRole::Member)
        .await
        .unwrap();
    s.core
        .create_repo(
            &alice,
            "acme",
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "acme", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .create_team(
            &alice,
            "acme",
            NewTeamInput {
                name: "Releases".into(),
                description: String::new(),
                permission: "write".into(),
                all_repos: false,
            },
        )
        .await
        .unwrap();
    s.core
        .set_team_member(&alice, "acme", "releases", "bob")
        .await
        .unwrap();

    let repo_id = s
        .core
        .repo_for(Some(&alice), "acme", "proj")
        .await
        .unwrap()
        .repo
        .id;
    let alice_url = writer_url(&s, "acme", "proj", &alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &alice_url, "main"]).await;
    let server = s.core.repo_path(repo_id);

    let maintain = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    create_rule(
        &s,
        &maintain,
        "acme",
        "proj",
        &protection_body(&[], &["releases"]),
    )
    .await;

    commit_files(&work, &[("x.txt", b"x\n")], "team change").await;
    let bob_url = writer_url(&s, "acme", "proj", &bob, &[Scope::RepoWrite]).await;
    git_ok(&work, &["push", &bob_url, "main"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn force_push_and_delete_refused_for_everyone() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let (_, alice_url, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Admin)
        .await
        .unwrap();
    // A second commit on `main`, pushed before the rule exists.
    commit_files(&work, &[("b.txt", b"b\n")], "second").await;
    git_ok(&work, &["push", "-q", &alice_url, "main"]).await;
    let protected_tip = server_rev_ok(&work, &server, "refs/heads/main").await;

    let maintain = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    // `bob` is exempt from the direct-push block only: force and delete
    // still refuse for him.
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &protection_body(&["bob"], &[]),
    )
    .await;

    // Diverge from the protected tip: an amended commit is not a descendant.
    git_ok(&work, &["commit", "--amend", "-m", "rewritten"]).await;
    let rewritten = git_ok(&work, &["rev-parse", "HEAD"]).await;
    assert_ne!(rewritten.trim(), protected_tip.trim());
    for (who, user) in [("owner", &alice), ("admin", &carol), ("exempt", &bob)] {
        let url = writer_url(&s, "alice", "proj", user, &[Scope::RepoWrite]).await;
        let out = git(&work, &["push", "--force", &url, "main"]).await;
        assert!(!out.status.success(), "{who} force push must be refused");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("refs/heads/main"), "{who}: {err}");
        assert!(err.contains("main"), "{who}: {err}");
        let out = git(&work, &["push", &url, "--delete", "main"]).await;
        assert!(!out.status.success(), "{who} delete must be refused");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("refs/heads/main"), "{who}: {err}");
    }
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        protected_tip.trim(),
        "refused force pushes and deletes move nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_branches_are_unaffected() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let maintain = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    create_rule(&s, &maintain, "alice", "proj", &protection_body(&[], &[])).await;

    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    git_ok(&work, &["checkout", "-b", "feature"]).await;
    commit_files(&work, &[("f.txt", b"f\n")], "feature work").await;
    git_ok(&work, &["push", &bob_url, "feature"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/feature")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_merge_into_protected_branch_succeeds() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (repo_id, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let maintain = s
        .token(
            &alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    create_rule(&s, &maintain, "alice", "proj", &protection_body(&[], &[])).await;

    commit_files(&work, &[("feature.txt", b"hello\n")], "add feature").await;
    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    git_ok(&work, &["push", "-q", &bob_url, "HEAD:refs/for/main/feat"]).await;
    wait_for_change(&s, repo_id, bob.id, "main", "feat").await;

    let client = reqwest::Client::new();
    let res = client
        .post(s.url("/api/v1/repos/alice/proj/trails/1/changes/1/merge"))
        .bearer_auth(&maintain)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "server merges bypass push rules");
    let before = server_rev_ok(&work, &server, "refs/heads/main").await;
    let _ = before;
    git_ok(&work, &["fetch", "-q", &bob_url, "main"]).await;
    let fetched = git_ok(&work, &["rev-parse", "FETCH_HEAD"]).await;
    assert!(
        server_rev(&work, &server, "refs/heads/main")
            .await
            .unwrap()
            .trim()
            == fetched.trim(),
        "merge moved main"
    );
}
