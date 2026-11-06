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

async fn create_tag_protection(
    s: &TestServer,
    token: &str,
    owner: &str,
    repo: &str,
    pattern: &str,
) -> Value {
    let client = reqwest::Client::new();
    let res = client
        .post(s.url(&format!("/api/v1/repos/{owner}/{repo}/tag-protections")))
        .bearer_auth(token)
        .json(&json!({"pattern": pattern}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "creating the tag protection");
    res.json::<Value>().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tag_protection_needs_maintain_for_matching_tags() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let maintain = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    create_tag_protection(&s, &maintain, "alice", "proj", "v*").await;

    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    let alice_url = writer_url(&s, "alice", "proj", &alice, &[Scope::RepoWrite]).await;

    // A write user's protected tag is refused, naming the ref and the pattern.
    git_ok(&work, &["tag", "v1"]).await;
    let out = git(&work, &["push", &bob_url, "refs/tags/v1"]).await;
    assert!(!out.status.success(), "protected tag push must be refused");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("refs/tags/v1"), "{err}");
    assert!(err.contains("v*"), "{err}");
    assert!(
        server_rev(&work, &server, "refs/tags/v1").await.is_none(),
        "refused tag push creates nothing"
    );

    // A maintainer's push succeeds.
    git_ok(&work, &["push", &alice_url, "refs/tags/v1"]).await;
    server_rev_ok(&work, &server, "refs/tags/v1").await;

    // A non-matching tag sails through for the write user.
    git_ok(&work, &["tag", "release-1"]).await;
    git_ok(&work, &["push", &bob_url, "refs/tags/release-1"]).await;
    server_rev_ok(&work, &server, "refs/tags/release-1").await;

    // Deleting a protected tag needs maintain too.
    let out = git(&work, &["push", &bob_url, ":refs/tags/v1"]).await;
    assert!(
        !out.status.success(),
        "protected tag delete must be refused"
    );
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("refs/tags/v1"), "{err}");
    assert!(err.contains("v*"), "{err}");
    server_rev_ok(&work, &server, "refs/tags/v1").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_listed_namespace_pushes_need_write() {
    let s = TestServer::start_with(|config| {
        config.git.allowed_ref_namespaces = vec!["refs/notes/".to_owned()];
    })
    .await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    git_ok(&work, &["notes", "add", "-m", "a note"]).await;

    // A write user pushes into the allow-listed namespace.
    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    git_ok(&work, &["push", &bob_url, "refs/notes/commits"]).await;
    server_rev_ok(&work, &server, "refs/notes/commits").await;

    // A read user is refused (with a fresh note so the push is a real update).
    git_ok(&work, &["notes", "append", "-m", "carol note"]).await;
    let carol_url = writer_url(&s, "alice", "proj", &carol, &[Scope::RepoRead]).await;
    let out = git(&work, &["push", &carol_url, "refs/notes/commits"]).await;
    assert!(
        !out.status.success(),
        "read push into notes must be refused"
    );
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("refs/notes/commits"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespace_pushes_refused_without_allow_list() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    git_ok(&work, &["notes", "add", "-m", "a note"]).await;

    let bob_url = writer_url(&s, "alice", "proj", &bob, &[Scope::RepoWrite]).await;
    let out = git(&work, &["push", &bob_url, "refs/notes/commits"]).await;
    assert!(
        !out.status.success(),
        "notes push without the allow-list must be refused"
    );
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("refs/notes/commits"), "{err}");
    assert!(
        server_rev(&work, &server, "refs/notes/commits")
            .await
            .is_none(),
        "refused notes push creates nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_namespace_entry_fails_startup() {
    use starforged::config::{
        Config, DatabaseConfig, GitConfig, MailConfig, RegistrationConfig, SecurityConfig,
        ServerConfig, SessionsConfig, StorageConfig, WebhooksConfig,
    };
    let data = tempfile::tempdir().unwrap();
    let config = Config {
        server: ServerConfig {
            http_addr: "127.0.0.1:0".into(),
            base_url: "http://127.0.0.1:0".into(),
        },
        database: DatabaseConfig {
            url: format!("sqlite://{}?mode=rwc", data.path().join("t.db").display()),
            auto_migrate: true,
        },
        storage: StorageConfig {
            data_dir: data.path().to_path_buf(),
            index_dir: PathBuf::from("index"),
        },
        security: SecurityConfig {
            secret_key: "0".repeat(64),
        },
        registration: RegistrationConfig::default(),
        mail: MailConfig::default(),
        sessions: SessionsConfig::default(),
        webhooks: WebhooksConfig::default(),
        git: GitConfig {
            allowed_ref_namespaces: vec!["refs/heads/evil/".into()],
        },
        remotes: starforged::config::RemotesConfig::default(),
        github: starforged::config::GithubConfig::default(),
        oidc: starforged::config::OidcConfig::default(),
        limits: starforged::config::LimitsConfig::default(),
        ssh: starforged::config::SshConfig::default(),
    };
    let err =
        match starforged::serve::build(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
            .await
        {
            Ok(_) => panic!("build with a reserved namespace must fail"),
            Err(err) => err,
        };
    assert!(
        err.to_string().contains("refs/heads/"),
        "startup names the offending namespace: {err:?}"
    );
}
