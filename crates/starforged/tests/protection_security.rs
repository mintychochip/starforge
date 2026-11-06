//! B4: protection sweep. End-to-end pinning of the branch/tag protection
//! shapes over real HTTP pushes: a role × operation matrix asserting every
//! refusal by EFFECT (the server-side ref is unchanged, read back both via
//! the object store and via `ls-remote`) plus the `remote: starforge: …`
//! message naming the ref and the blocking pattern; rule combinations;
//! concurrency (a rule change between two pushes takes effect on the
//! second); server-side paths (Trail merges, `refs/for`, `refs/trails`);
//! and the 404/403 access matrix on both management APIs.
//!
//! Tag-protection list readability currently needs maintain+ (unlike the
//! gate-rule list, which any reader may list); that shape is pinned in one
//! helper ([`assert_tag_list_requires_maintain`]) so a later read-shape
//! change stays small.
mod common;

use std::path::{Path, PathBuf};
use std::process::Output;
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
const WRITE_SCOPES: &[Scope] = &[Scope::RepoRead, Scope::RepoWrite];

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

/// The ref as the server advertises it over HTTP, or `None` when absent.
async fn remote_rev(work: &Path, url: &str, r: &str) -> Option<String> {
    let out = git(work, &["ls-remote", url, r]).await;
    assert!(
        out.status.success(),
        "ls-remote {r} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .map(str::to_owned)
}

/// Refusal by message: the push fails and git shows `remote: starforge: …`
/// naming the ref and (when given) the blocking pattern.
fn assert_refused(out: &Output, want_ref: &str, want_pattern: Option<&str>) {
    assert!(!out.status.success(), "push must be refused");
    let err = String::from_utf8(out.stderr.clone()).unwrap();
    assert!(
        err.contains("starforge:"),
        "refusal reaches the pusher as `remote: starforge: …`: {err}"
    );
    assert!(err.contains(want_ref), "refusal names {want_ref}: {err}");
    if let Some(pattern) = want_pattern {
        assert!(
            err.contains(pattern),
            "refusal names the pattern {pattern}: {err}"
        );
    }
}

/// Refusal by effect: the server-side ref still reads as `before`, both in
/// the object store and over `ls-remote`.
async fn assert_ref_unchanged(
    work: &Path,
    server: &Path,
    url: &str,
    r: &str,
    before: Option<&str>,
) {
    assert_eq!(
        server_rev(work, server, r).await.as_deref(),
        before,
        "refused push moves nothing in the object store"
    );
    assert_eq!(
        remote_rev(work, url, r).await.as_deref(),
        before,
        "refused push moves nothing over ls-remote"
    );
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

fn branch_rule(pattern: Value, users: &[&str], teams: &[&str]) -> Value {
    json!({
        "pattern": pattern,
        "block_direct_push": true,
        "block_force_push": true,
        "block_deletion": true,
        "push_allowlist": {"users": users, "teams": teams},
    })
}

async fn create_tag(s: &TestServer, token: &str, owner: &str, repo: &str, pattern: &str) -> Value {
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

struct Role {
    name: &'static str,
    user: User,
}

/// Seven push identities: every collaborator tier, the owner, and a site admin.
async fn push_roles(s: &TestServer, alice: &User, repo: &str) -> Vec<Role> {
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let dave = s.user("dave").await;
    let erin = s.user("erin").await;
    let grace = s.user("grace").await;
    s.core
        .create_user(starforged_core::accounts::CreateUser {
            handle: "frank".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let frank = s.core.user_by_handle("frank").await.unwrap().unwrap();
    for (handle, level) in [
        ("bob", Permission::Maintain),
        ("carol", Permission::Read),
        ("dave", Permission::Triage),
        ("erin", Permission::Write),
        ("grace", Permission::Admin),
    ] {
        s.core
            .set_collaborator(alice, "alice", repo, handle, level)
            .await
            .unwrap();
    }
    vec![
        Role {
            name: "read",
            user: carol,
        },
        Role {
            name: "triage",
            user: dave,
        },
        Role {
            name: "write",
            user: erin,
        },
        Role {
            name: "maintain",
            user: bob,
        },
        Role {
            name: "admin",
            user: grace,
        },
        Role {
            name: "owner",
            user: alice.clone(),
        },
        Role {
            name: "site admin",
            user: frank,
        },
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_push_role_matrix() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    let maintain = s.token(&alice, WRITE_SCOPES).await;
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(json!("main"), &[], &[]),
    )
    .await;

    // Every role's direct push to a fully protected branch is refused, by
    // message and by effect. Below-write roles fail the write tier; write
    // and above fail the protection snapshot; admins get no bypass.
    for role in push_roles(&s, &alice, "proj").await {
        commit_files(
            &work,
            &[(&format!("{}.txt", role.name), b"x\n")],
            &format!("direct change by {}", role.name),
        )
        .await;
        let before = server_rev(&work, &server, "refs/heads/main").await;
        let probe_url = writer_url(&s, "alice", "proj", &role.user, WRITE_SCOPES).await;
        let out = git(&work, &["push", &probe_url, "main"]).await;
        assert_refused(&out, "refs/heads/main", Some("main"));
        assert_ref_unchanged(
            &work,
            &server,
            &probe_url,
            "refs/heads/main",
            before.as_deref(),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branch_operation_matrix() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let erin = s.user("erin").await;
    let grace = s.user("grace").await;
    s.core
        .create_user(starforged_core::accounts::CreateUser {
            handle: "frank".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let frank = s.core.user_by_handle("frank").await.unwrap().unwrap();
    let (_, _, work, server) = setup_repo(&s, &alice, "proj2").await;
    for (handle, level) in [
        ("bob", Permission::Maintain),
        ("erin", Permission::Write),
        ("grace", Permission::Admin),
    ] {
        s.core
            .set_collaborator(&alice, "alice", "proj2", handle, level)
            .await
            .unwrap();
    }
    let maintain = s.token(&alice, WRITE_SCOPES).await;
    // A null pattern covers every branch; only `erin` bypasses direct pushes.
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj2",
        &branch_rule(Value::Null, &["erin"], &[]),
    )
    .await;
    let bob_url = writer_url(&s, "alice", "proj2", &bob, WRITE_SCOPES).await;
    let erin_url = writer_url(&s, "alice", "proj2", &erin, WRITE_SCOPES).await;
    let grace_url = writer_url(&s, "alice", "proj2", &grace, WRITE_SCOPES).await;
    let frank_url = writer_url(&s, "alice", "proj2", &frank, WRITE_SCOPES).await;

    // Create: a non-exempt maintainer cannot create a branch …
    git_ok(&work, &["checkout", "-b", "fresh"]).await;
    commit_files(&work, &[("fresh.txt", b"fresh\n")], "fresh work").await;
    let out = git(&work, &["push", &bob_url, "fresh"]).await;
    assert_refused(&out, "refs/heads/fresh", Some("all branches"));
    assert_ref_unchanged(&work, &server, &bob_url, "refs/heads/fresh", None).await;
    // … while the allow-listed writer can.
    git_ok(&work, &["push", &erin_url, "fresh"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/fresh")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
    git_ok(&work, &["checkout", "-q", "main"]).await;

    // Fast-forward: refused for the maintainer, allowed for the exempt writer.
    commit_files(&work, &[("ff.txt", b"ff\n")], "ff change").await;
    let before = server_rev(&work, &server, "refs/heads/main").await;
    let out = git(&work, &["push", &bob_url, "main"]).await;
    assert_refused(&out, "refs/heads/main", Some("all branches"));
    assert_ref_unchanged(
        &work,
        &server,
        &bob_url,
        "refs/heads/main",
        before.as_deref(),
    )
    .await;
    git_ok(&work, &["push", &erin_url, "main"]).await;
    let tip = server_rev_ok(&work, &server, "refs/heads/main").await;
    assert_eq!(
        tip.trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );

    // Force: refused for everyone, including the exempt writer, an admin,
    // and a site admin; the message names the force-push block.
    git_ok(&work, &["commit", "-q", "--amend", "-m", "rewritten"]).await;
    for url in [&erin_url, &grace_url, &frank_url] {
        let out = git(&work, &["push", "--force", url, "main"]).await;
        assert_refused(&out, "refs/heads/main", Some("blocks force pushes"));
        assert_ref_unchanged(&work, &server, url, "refs/heads/main", Some(tip.trim())).await;
    }
    let fresh = server_rev_ok(&work, &server, "refs/heads/fresh").await;
    // Delete: refused for everyone too; the ref survives.
    for url in [&erin_url, &grace_url, &frank_url] {
        let out = git(&work, &["push", url, "--delete", "fresh"]).await;
        assert_refused(&out, "refs/heads/fresh", Some("blocks deletion"));
        assert_ref_unchanged(&work, &server, url, "refs/heads/fresh", Some(fresh.trim())).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_combinations_all_matching_rules_apply() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let erin = s.user("erin").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "erin", Permission::Write)
        .await
        .unwrap();
    let maintain = s.token(&alice, WRITE_SCOPES).await;
    // Two rules covering `main`: only the first exempts `erin`. (One rule
    // per pattern, so the second uses the null pattern, which also matches.)
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(json!("main"), &["erin"], &[]),
    )
    .await;
    let second = create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(Value::Null, &[], &[]),
    )
    .await;
    let second_id = second["id"].as_i64().unwrap();

    // One blocking rule without the exemption still refuses the push.
    commit_files(&work, &[("x.txt", b"x\n")], "direct change").await;
    let erin_url = writer_url(&s, "alice", "proj", &erin, WRITE_SCOPES).await;
    let before = server_rev(&work, &server, "refs/heads/main").await;
    let out = git(&work, &["push", &erin_url, "main"]).await;
    assert_refused(&out, "refs/heads/main", Some("main"));
    assert_ref_unchanged(
        &work,
        &server,
        &erin_url,
        "refs/heads/main",
        before.as_deref(),
    )
    .await;

    // Exempting `erin` on the second rule too lets the push through.
    let client = reqwest::Client::new();
    let res = client
        .patch(s.url(&format!("/api/v1/repos/alice/proj/gate-rules/{second_id}")))
        .bearer_auth(&maintain)
        .json(&json!({"push_allowlist": {"users": ["erin"], "teams": []}}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    git_ok(&work, &["push", &erin_url, "main"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );

    // A rule on another pattern leaves other branches alone.
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(json!("feature/*"), &[], &[]),
    )
    .await;
    git_ok(&work, &["checkout", "-qb", "other"]).await;
    commit_files(&work, &[("o.txt", b"o\n")], "other work").await;
    git_ok(&work, &["push", &erin_url, "other"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/other")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
    git_ok(&work, &["checkout", "-qb", "feature/x"]).await;
    commit_files(&work, &[("f.txt", b"f\n")], "feature work").await;
    let before = server_rev(&work, &server, "refs/heads/feature/x").await;
    let out = git(&work, &["push", &erin_url, "feature/x"]).await;
    assert_refused(&out, "refs/heads/feature/x", Some("feature/*"));
    assert_ref_unchanged(
        &work,
        &server,
        &erin_url,
        "refs/heads/feature/x",
        before.as_deref(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_team_allowlist_matrix() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let erin = s.user("erin").await;
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
    for (handle, role) in [("bob", OrgRole::Member), ("erin", OrgRole::Member)] {
        s.core
            .set_org_member(&alice, "acme", handle, role)
            .await
            .unwrap();
    }
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
    for (handle, level) in [("bob", Permission::Write), ("erin", Permission::Write)] {
        s.core
            .set_collaborator(&alice, "acme", "proj", handle, level)
            .await
            .unwrap();
    }
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

    let maintain = s.token(&alice, WRITE_SCOPES).await;
    create_rule(
        &s,
        &maintain,
        "acme",
        "proj",
        &branch_rule(json!("main"), &[], &["releases"]),
    )
    .await;

    // The team member pushes straight through …
    commit_files(&work, &[("team.txt", b"team\n")], "team change").await;
    let bob_url = writer_url(&s, "acme", "proj", &bob, WRITE_SCOPES).await;
    git_ok(&work, &["push", &bob_url, "main"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
    // … while a write collaborator outside the team is refused, by message
    // and by effect.
    commit_files(&work, &[("outsider.txt", b"no\n")], "outsider change").await;
    let erin_url = writer_url(&s, "acme", "proj", &erin, WRITE_SCOPES).await;
    let before = server_rev(&work, &server, "refs/heads/main").await;
    let out = git(&work, &["push", &erin_url, "main"]).await;
    assert_refused(&out, "refs/heads/main", Some("main"));
    assert_ref_unchanged(
        &work,
        &server,
        &erin_url,
        "refs/heads/main",
        before.as_deref(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tag_operation_role_matrix() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    let roles = push_roles(&s, &alice, "proj").await;
    let user = |name: &str| {
        roles
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("no role {name}"))
            .user
            .clone()
    };
    let maintain = s.token(&alice, WRITE_SCOPES).await;
    create_tag(&s, &maintain, "alice", "proj", "v*").await;
    // The maintainer seeds a tag the move/delete probes will target.
    let alice_url = writer_url(&s, "alice", "proj", &alice, WRITE_SCOPES).await;
    git_ok(&work, &["tag", "v2"]).await;
    git_ok(&work, &["push", "-q", &alice_url, "refs/tags/v2"]).await;
    let v2 = server_rev_ok(&work, &server, "refs/tags/v2").await;

    // Create: below-write roles fail the write tier (no pattern in the
    // message); a writer fails the tag-protection snapshot, which names
    // the pattern. All three leave the ref absent.
    let erin_url = writer_url(&s, "alice", "proj", &user("write"), WRITE_SCOPES).await;
    for name in ["read", "triage"] {
        git_ok(&work, &["tag", &format!("v-{name}")]).await;
        let url = writer_url(&s, "alice", "proj", &user(name), WRITE_SCOPES).await;
        let out = git(&work, &["push", &url, &format!("refs/tags/v-{name}")]).await;
        assert_refused(&out, &format!("refs/tags/v-{name}"), None);
        assert_ref_unchanged(&work, &server, &url, &format!("refs/tags/v-{name}"), None).await;
    }
    git_ok(&work, &["tag", "v-write"]).await;
    let out = git(&work, &["push", &erin_url, "refs/tags/v-write"]).await;
    assert_refused(&out, "refs/tags/v-write", Some("v*"));
    assert_ref_unchanged(&work, &server, &erin_url, "refs/tags/v-write", None).await;
    // … maintain and above succeed.
    for (name, suffix) in [
        ("maintain", "maintain"),
        ("admin", "admin"),
        ("owner", "owner"),
        ("site admin", "siteadmin"),
    ] {
        git_ok(&work, &["tag", &format!("v-{suffix}")]).await;
        let url = writer_url(&s, "alice", "proj", &user(name), WRITE_SCOPES).await;
        git_ok(&work, &["push", &url, &format!("refs/tags/v-{suffix}")]).await;
        server_rev_ok(&work, &server, &format!("refs/tags/v-{suffix}")).await;
    }
    // Non-matching tags still need only write.
    git_ok(&work, &["tag", "release-1"]).await;
    git_ok(&work, &["push", &erin_url, "refs/tags/release-1"]).await;
    server_rev_ok(&work, &server, "refs/tags/release-1").await;

    // Move: a writer cannot force-move a protected tag; the ref is unchanged.
    commit_files(&work, &[("move.txt", b"move\n")], "move target").await;
    git_ok(&work, &["tag", "-f", "v2"]).await;
    let out = git(&work, &["push", "--force", &erin_url, "refs/tags/v2"]).await;
    assert_refused(&out, "refs/tags/v2", Some("v*"));
    assert_ref_unchanged(&work, &server, &erin_url, "refs/tags/v2", Some(v2.trim())).await;

    // Delete: refused for the writer (the tag survives), allowed for an admin.
    let out = git(&work, &["push", &erin_url, ":refs/tags/v2"]).await;
    assert_refused(&out, "refs/tags/v2", Some("v*"));
    assert_ref_unchanged(&work, &server, &erin_url, "refs/tags/v2", Some(v2.trim())).await;
    let admin_url = writer_url(&s, "alice", "proj", &user("admin"), WRITE_SCOPES).await;
    git_ok(&work, &["push", &admin_url, ":refs/tags/v2"]).await;
    assert_ref_unchanged(&work, &server, &admin_url, "refs/tags/v2", None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notes_namespace_matrix() {
    // With `refs/notes/` allow-listed, branch protection never touches it.
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
    let maintain = s.token(&alice, WRITE_SCOPES).await;
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(Value::Null, &[], &[]),
    )
    .await;

    git_ok(&work, &["notes", "add", "-m", "a note"]).await;
    let bob_url = writer_url(&s, "alice", "proj", &bob, WRITE_SCOPES).await;
    git_ok(&work, &["push", &bob_url, "refs/notes/commits"]).await;
    server_rev_ok(&work, &server, "refs/notes/commits").await;

    // A read user cannot push notes: refused by message and by effect.
    git_ok(&work, &["notes", "append", "-m", "carol note"]).await;
    let before = server_rev(&work, &server, "refs/notes/commits").await;
    let carol_url = writer_url(&s, "alice", "proj", &carol, WRITE_SCOPES).await;
    let out = git(&work, &["push", &carol_url, "refs/notes/commits"]).await;
    assert_refused(&out, "refs/notes/commits", None);
    assert_ref_unchanged(
        &work,
        &server,
        &carol_url,
        "refs/notes/commits",
        before.as_deref(),
    )
    .await;

    // Without the allow-list the same push is refused and creates nothing.
    let plain = TestServer::start().await;
    let palice = plain.user("alice").await;
    let pbob = plain.user("pbob").await;
    let (_, _, pwork, pserver) = setup_repo(&plain, &palice, "proj").await;
    plain
        .core
        .set_collaborator(&palice, "alice", "proj", "pbob", Permission::Write)
        .await
        .unwrap();
    git_ok(&pwork, &["notes", "add", "-m", "a note"]).await;
    let pbob_url = writer_url(&plain, "alice", "proj", &pbob, WRITE_SCOPES).await;
    let out = git(&pwork, &["push", &pbob_url, "refs/notes/commits"]).await;
    assert_refused(&out, "refs/notes/commits", None);
    assert_ref_unchanged(&pwork, &pserver, &pbob_url, "refs/notes/commits", None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_change_between_pushes_takes_effect() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let erin = s.user("erin").await;
    let (_, _, work, server) = setup_repo(&s, &alice, "proj").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "erin", Permission::Write)
        .await
        .unwrap();
    let maintain = s.token(&alice, WRITE_SCOPES).await;
    let created = create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(json!("main"), &[], &[]),
    )
    .await;
    let id = created["id"].as_i64().unwrap();

    commit_files(&work, &[("x.txt", b"x\n")], "direct change").await;
    let erin_url = writer_url(&s, "alice", "proj", &erin, WRITE_SCOPES).await;
    let before = server_rev(&work, &server, "refs/heads/main").await;
    let out = git(&work, &["push", &erin_url, "main"]).await;
    assert_refused(&out, "refs/heads/main", Some("main"));
    assert_ref_unchanged(
        &work,
        &server,
        &erin_url,
        "refs/heads/main",
        before.as_deref(),
    )
    .await;

    // The second push runs under the new snapshot: allow-listing takes
    // effect without the pusher changing anything.
    let client = reqwest::Client::new();
    let res = client
        .patch(s.url(&format!("/api/v1/repos/alice/proj/gate-rules/{id}")))
        .bearer_auth(&maintain)
        .json(&json!({"push_allowlist": {"users": ["erin"], "teams": []}}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    git_ok(&work, &["push", &erin_url, "main"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "HEAD"]).await.trim()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_paths_and_trail_refs_unaffected() {
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
    create_rule(
        &s,
        &maintain,
        "alice",
        "proj",
        &branch_rule(json!("main"), &[], &[]),
    )
    .await;

    // `refs/for` proposals sail through under full protection …
    commit_files(&work, &[("feature.txt", b"hello\n")], "add feature").await;
    let bob_url = writer_url(&s, "alice", "proj", &bob, WRITE_SCOPES).await;
    git_ok(&work, &["push", "-q", &bob_url, "HEAD:refs/for/main/feat"]).await;
    wait_for_change(&s, repo_id, bob.id, "main", "feat").await;
    // … the server merge moves the protected branch …
    let client = reqwest::Client::new();
    let res = client
        .post(s.url("/api/v1/repos/alice/proj/trails/1/changes/1/merge"))
        .bearer_auth(&maintain)
        .json(&json!({"method": "merge"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "server merges bypass push rules");
    git_ok(&work, &["fetch", "-q", &bob_url, "main"]).await;
    assert_eq!(
        server_rev_ok(&work, &server, "refs/heads/main")
            .await
            .trim(),
        git_ok(&work, &["rev-parse", "FETCH_HEAD"]).await.trim(),
        "merge moved main"
    );
    // … and the merge wrote the server-only trail refs clients can never push.
    server_rev_ok(&work, &server, "refs/trails/1/changes/1/head").await;
    let out = git(
        &work,
        &["push", &bob_url, "HEAD:refs/trails/1/changes/1/head"],
    )
    .await;
    assert!(
        !out.status.success(),
        "refs/trails/* stays server-only under protection"
    );
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("refs/trails/1/changes/1/head"), "{err}");
    let advertised = git_ok(&work, &["ls-remote", &bob_url]).await;
    assert!(!advertised.contains("refs/trails"), "{advertised}");
    assert!(!advertised.contains("refs/for"), "{advertised}");
}

/// Pins the CURRENT tag-protection list shape: reads need maintain+,
/// unlike the gate-rule list, which any repository reader may list.
async fn assert_tag_list_requires_maintain(
    client: &reqwest::Client,
    tags_url: &str,
    reader_token: &str,
    role: &str,
    maintainer_token: &str,
) {
    let res = client
        .get(tags_url)
        .bearer_auth(reader_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        403,
        "{role} readers cannot list tag protections"
    );
    let res = client
        .get(tags_url)
        .bearer_auth(maintainer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "maintain+ lists tag protections");
    assert!(
        res.json::<Value>()
            .await
            .unwrap()
            .get("tag_protections")
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_access_matrix() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let dave = s.user("dave").await;
    let erin = s.user("erin").await;
    let grace = s.user("grace").await;
    let gus = s.user("gus").await;
    s.core
        .create_user(starforged_core::accounts::CreateUser {
            handle: "frank".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let frank = s.core.user_by_handle("frank").await.unwrap().unwrap();
    s.repo(&alice, "proj", Visibility::Private).await;
    for (handle, level) in [
        ("bob", Permission::Maintain),
        ("carol", Permission::Read),
        ("dave", Permission::Triage),
        ("erin", Permission::Write),
        ("grace", Permission::Admin),
    ] {
        s.core
            .set_collaborator(&alice, "alice", "proj", handle, level)
            .await
            .unwrap();
    }
    let read = &[Scope::RepoRead];
    let trail = &[Scope::RepoRead, Scope::TrailWrite];
    let full = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
    let (
        carol_read,
        dave_trail,
        erin_trail,
        bob_full,
        bob_read,
        grace_full,
        alice_full,
        frank_full,
        gus_full,
        gus_repo,
    ) = (
        s.token(&carol, read).await,
        s.token(&dave, trail).await,
        s.token(&erin, trail).await,
        s.token(&bob, full).await,
        s.token(&bob, read).await,
        s.token(&grace, full).await,
        s.token(&alice, full).await,
        s.token(&frank, full).await,
        s.token(&gus, full).await,
        s.token(&gus, &[Scope::RepoRead, Scope::RepoWrite]).await,
    );
    let client = reqwest::Client::new();
    let rules = s.url("/api/v1/repos/alice/proj/gate-rules");
    let tags = s.url("/api/v1/repos/alice/proj/tag-protections");
    let rule_body = || {
        json!({
            "pattern": "matrix",
            "required_approvals": 0,
            "dismiss_on_push": false,
            "block_on_request_changes": false,
            "required_contexts": [],
            "require_up_to_date": false,
            "require_threads_resolved": false,
            "require_session_evidence": false,
            "allowed_methods": [],
        })
    };

    // Gate-rule lists: anonymous 404, outsiders 404, every reader 200.
    assert_eq!(client.get(&rules).send().await.unwrap().status(), 404);
    for (token, role) in [(&gus_full, "outsider"), (&gus_repo, "scoped outsider")] {
        let res = client.get(&rules).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 404, "{role} sees no repository");
    }
    for (token, role) in [
        (&carol_read, "read"),
        (&dave_trail, "triage"),
        (&erin_trail, "write"),
        (&bob_full, "maintain"),
        (&grace_full, "admin"),
        (&alice_full, "owner"),
        (&frank_full, "site admin"),
    ] {
        let res = client.get(&rules).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 200, "{role} lists gate rules");
    }

    // Gate-rule mutations: anonymous 401, outsiders 404, below maintain 403.
    assert_eq!(
        client
            .post(&rules)
            .json(&rule_body())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for (token, role) in [(&gus_full, "outsider"), (&gus_repo, "scoped outsider")] {
        let res = client
            .post(&rules)
            .bearer_auth(token)
            .json(&rule_body())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404, "{role} sees no repository");
    }
    for (token, role) in [
        (&carol_read, "read"),
        (&dave_trail, "triage"),
        (&erin_trail, "write"),
    ] {
        let res = client
            .post(&rules)
            .bearer_auth(token)
            .json(&rule_body())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{role} cannot mutate gate rules");
    }
    // A maintainer holding only `repo:read` lists but cannot mutate.
    assert_eq!(
        client
            .get(&rules)
            .bearer_auth(&bob_read)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let res = client
        .post(&rules)
        .bearer_auth(&bob_read)
        .json(&rule_body())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "mutations need the repo:write scope");

    // Maintain, admin, owner, and site admin can create, patch, and delete.
    for (token, role) in [
        (&bob_full, "maintain"),
        (&grace_full, "admin"),
        (&alice_full, "owner"),
        (&frank_full, "site admin"),
    ] {
        let res = client
            .post(&rules)
            .bearer_auth(token)
            .json(&rule_body())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "{role} creates gate rules");
        let id = res.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
        let rule = s.url(&format!("/api/v1/repos/alice/proj/gate-rules/{id}"));
        let res = client
            .patch(&rule)
            .bearer_auth(&erin_trail)
            .json(&json!({"required_approvals": 1}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "write cannot patch");
        let res = client
            .patch(&rule)
            .bearer_auth(token)
            .json(&json!({"required_approvals": 1}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{role} patches gate rules");
        let res = client
            .delete(&rule)
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204, "{role} deletes gate rules");
    }
    // Unknown gate-rule ids are 404 for readers, and for scoped outsiders.
    let missing = s.url("/api/v1/repos/alice/proj/gate-rules/999999");
    for (token, role) in [(&bob_full, "maintain"), (&gus_repo, "scoped outsider")] {
        let res = client
            .delete(&missing)
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404, "{role} sees 404 for unknown ids");
    }

    // Tag-protection lists: anonymous 404, outsiders 404, and (unlike gate
    // rules) below-maintain readers 403 — pinned in one helper.
    assert_eq!(client.get(&tags).send().await.unwrap().status(), 404);
    for (token, role) in [(&gus_full, "outsider"), (&gus_repo, "scoped outsider")] {
        let res = client.get(&tags).bearer_auth(token).send().await.unwrap();
        assert_eq!(res.status(), 404, "{role} sees no repository");
    }
    for (token, role) in [
        (&carol_read, "read"),
        (&dave_trail, "triage"),
        (&erin_trail, "write"),
    ] {
        assert_tag_list_requires_maintain(&client, &tags, token, role, &bob_full).await;
    }

    // Tag-protection mutations: below maintain 403, maintain+ 201/204.
    let res = client
        .post(&tags)
        .bearer_auth(&erin_trail)
        .json(&json!({"pattern": "v*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "write cannot create tag protections");
    let res = client
        .post(&tags)
        .bearer_auth(&bob_read)
        .json(&json!({"pattern": "v*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "tag mutations need the repo:write scope");
    for (token, role) in [
        (&bob_full, "maintain"),
        (&grace_full, "admin"),
        (&alice_full, "owner"),
        (&frank_full, "site admin"),
    ] {
        // `v*` already exists after the first pass; both shapes are maintain+ ok.
        let res = client
            .post(&tags)
            .bearer_auth(token)
            .json(&json!({"pattern": "v*"}))
            .send()
            .await
            .unwrap();
        assert!(
            res.status() == 201 || res.status() == 409,
            "{role}: {}",
            res.status()
        );
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        let id = body["id"].as_i64().unwrap_or(0);
        if id != 0 {
            let tag = s.url(&format!("/api/v1/repos/alice/proj/tag-protections/{id}"));
            let res = client
                .delete(&tag)
                .bearer_auth(&erin_trail)
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 403, "write cannot delete tag protections");
            let res = client.delete(&tag).bearer_auth(token).send().await.unwrap();
            assert_eq!(res.status(), 204, "{role} deletes tag protections");
        }
    }
    // Unknown tag-protection ids are 404 for API readers and outsiders alike.
    let missing = s.url("/api/v1/repos/alice/proj/tag-protections/999999");
    for (token, role) in [(&bob_full, "maintain"), (&gus_full, "outsider")] {
        let res = client
            .delete(&missing)
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404, "{role} sees 404 for unknown ids");
    }
}
