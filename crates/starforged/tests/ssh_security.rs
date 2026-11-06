//! SSH vs HTTP security sweep (M3c, plan Task C3). Real `ssh` + `git`
//! against the in-process server: the SSH outcome must equal the HTTP
//! outcome for every cell of the matrix (roles × visibility × operation).
//! Deploy keys have no HTTP twin, so the plan's expected outcome (D5) is
//! asserted directly for them. Revocation and audit-leak checks close the
//! sweep. Table-driven: one `TestServer` per visibility, minimal pushes.

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::*;
use serde_json::json;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::orgs::{NewOrgInput, NewTeamInput, OrgPatch, OrgRole};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

fn keydir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

struct Row {
    label: &'static str,
    owner: &'static str,
    repo: &'static str,
    token: String,
    key: PathBuf,
    readable: bool,
    writable: bool,
    member: bool,
    tag_ok: bool,
}

async fn add_user_key(s: &TestServer, u: &User, dir: &Path, name: &str) -> PathBuf {
    let (priv_key, publine) = gen_key(dir, &format!("id_{name}"), "ed25519", None);
    s.add_key(u, &publine).await;
    priv_key
}

async fn protect(s: &TestServer, tok: &str, owner: &str, repo: &str) {
    let client = reqwest::Client::new();
    let res = client
        .post(s.url(&format!("/api/v1/repos/{owner}/{repo}/gate-rules")))
        .bearer_auth(tok)
        .json(&json!({
            "pattern": "main",
            "block_direct_push": false,
            "block_force_push": true,
            "block_deletion": true,
            "push_allowlist": {"users": [], "teams": []},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "gate rule {owner}/{repo}");
    let res = client
        .post(s.url(&format!("/api/v1/repos/{owner}/{repo}/tag-protections")))
        .bearer_auth(tok)
        .json(&json!({"pattern": "v*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "tag protection {owner}/{repo}");
}

/// One full visibility sweep. `visibility` is the visibility for every repo
/// in this server, so the implicit-read cells differ by it.
async fn sweep(visibility: Visibility, tag: &str) {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let pub_vis = visibility == Visibility::Public;

    // Org 1 (base `none`): team-grant cell. Org 2 (base `write`): base cell.
    // Collaborator cells sit on Alice's user-owned repo, where deploy keys live.
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
        .create_org(
            &alice,
            NewOrgInput {
                handle: "baseorg".into(),
                display_name: "Base".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    let uteam = s.user("uteam").await;
    let ubase = s.user("ubase").await;
    s.core
        .set_org_member(&alice, "acme", "uteam", OrgRole::Member)
        .await
        .unwrap();
    s.core
        .set_org_member(&alice, "baseorg", "ubase", OrgRole::Member)
        .await
        .unwrap();
    s.core
        .create_team(
            &alice,
            "acme",
            NewTeamInput {
                name: "readers".into(),
                description: String::new(),
                permission: "read".into(),
                all_repos: true,
            },
        )
        .await
        .unwrap();
    s.core
        .set_team_member(&alice, "acme", "readers", "uteam")
        .await
        .unwrap();
    s.core
        .update_org(
            &alice,
            "baseorg",
            OrgPatch {
                display_name: None,
                description: None,
                base_permission: Some("write".into()),
            },
        )
        .await
        .unwrap();

    let uread = s.user("uread").await;
    let utriage = s.user("utriage").await;
    let uwrite = s.user("uwrite").await;
    let umaintain = s.user("umaintain").await;
    let uadmin = s.user("uadmin").await;
    let uout = s.user("uout").await;

    s.repo(&alice, "proj", visibility).await;
    for (owner, repo) in [("acme", "teamrepo"), ("baseorg", "baserepo")] {
        s.core
            .create_repo(
                &alice,
                owner,
                starforged_core::repos::CreateRepo {
                    name: repo.into(),
                    description: String::new(),
                    visibility,
                    readme: false,
                },
            )
            .await
            .unwrap();
    }
    for (handle, perm) in [
        ("uread", Permission::Read),
        ("utriage", Permission::Triage),
        ("uwrite", Permission::Write),
        ("umaintain", Permission::Maintain),
        ("uadmin", Permission::Admin),
    ] {
        s.core
            .set_collaborator(&alice, "alice", "proj", handle, perm)
            .await
            .unwrap();
    }
    // `refs/for` = members, so the member/non-member split is observable.
    for (owner, repo) in [
        ("alice", "proj"),
        ("acme", "teamrepo"),
        ("baseorg", "baserepo"),
    ] {
        s.core
            .set_refs_for_access(&alice, owner, repo, "members")
            .await
            .unwrap();
    }

    let full = &[Scope::RepoRead, Scope::RepoWrite];
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    let seed = work_repo(&tmp_path, "seed", &[("README.md", "# sweep\n")]).await;
    let alice_tok = s.token(&alice, full).await;
    for (owner, repo) in [
        ("alice", "proj"),
        ("acme", "teamrepo"),
        ("baseorg", "baserepo"),
    ] {
        git_ok(
            &seed,
            &[
                "push",
                "-q",
                &s.git_url(owner, repo, Some(&alice_tok)),
                "main",
            ],
        )
        .await;
    }
    commit_files(&seed, &[("second.txt", b"2\n")], "second").await;
    for (owner, repo) in [
        ("alice", "proj"),
        ("acme", "teamrepo"),
        ("baseorg", "baserepo"),
    ] {
        git_ok(
            &seed,
            &[
                "push",
                "-q",
                &s.git_url(owner, repo, Some(&alice_tok)),
                "main",
            ],
        )
        .await;
    }

    for (owner, repo) in [
        ("alice", "proj"),
        ("acme", "teamrepo"),
        ("baseorg", "baserepo"),
    ] {
        protect(&s, &alice_tok, owner, repo).await;
    }
    // The protected tip is the pre-amend SHA; diverge before the sweep.
    let tip = git_ok(&seed, &["rev-parse", "HEAD"]).await;
    git_ok(&seed, &["commit", "--amend", "-m", "rewritten"]).await;

    let kdir = keydir();
    let kdir = kdir.path().to_path_buf();
    let mut rows: Vec<Row> = Vec::new();
    // label, user, readable, writable, member, tag_ok (maintain+ only).
    let cells: Vec<(&'static str, &User, bool, bool, bool, bool)> = vec![
        ("uread", &uread, true, false, true, false),
        ("utriage", &utriage, true, false, true, false),
        ("uwrite", &uwrite, true, true, true, false),
        ("umaintain", &umaintain, true, true, true, true),
        ("uadmin", &uadmin, true, true, true, true),
        // Stranger: implicit read on public, nothing on private. Never a member.
        ("uout", &uout, pub_vis, false, false, false),
    ];
    for (label, user, readable, writable, member, tag_ok) in cells {
        let key = add_user_key(&s, user, &kdir, label).await;
        rows.push(Row {
            label,
            owner: "alice",
            repo: "proj",
            token: s.token(user, full).await,
            key,
            readable,
            writable,
            member,
            tag_ok,
        });
    }
    {
        let key = add_user_key(&s, &uteam, &kdir, "uteam").await;
        rows.push(Row {
            label: "uteam",
            owner: "acme",
            repo: "teamrepo",
            token: s.token(&uteam, full).await,
            key,
            readable: true,
            writable: false,
            member: true,
            tag_ok: false,
        });
    }
    {
        let key = add_user_key(&s, &ubase, &kdir, "ubase").await;
        rows.push(Row {
            label: "ubase",
            owner: "baseorg",
            repo: "baserepo",
            token: s.token(&ubase, full).await,
            key,
            readable: true,
            writable: true,
            member: true,
            tag_ok: false,
        });
    }
    let (ro_priv, ro_pub) = gen_key(&kdir, "id_deploy_ro", "ed25519", None);
    s.add_deploy(&alice, "proj", &ro_pub, false).await;
    rows.push(Row {
        label: "deploy_ro",
        owner: "alice",
        repo: "proj",
        token: String::new(),
        key: ro_priv,
        readable: true,
        writable: false,
        member: false,
        tag_ok: false,
    });
    let (rw_priv, rw_pub) = gen_key(&kdir, "id_deploy_rw", "ed25519", None);
    s.add_deploy(&alice, "proj", &rw_pub, true).await;
    rows.push(Row {
        label: "deploy_rw",
        owner: "alice",
        repo: "proj",
        token: String::new(),
        key: rw_priv,
        readable: true,
        writable: true,
        member: false,
        tag_ok: false,
    });

    // ---- matrix loop ----
    for row in &rows {
        let cell = format!("{} on {}/{} ({tag})", row.label, row.owner, row.repo);
        let is_deploy = row.label.starts_with("deploy");
        let http_url = s.git_url(
            row.owner,
            row.repo,
            if is_deploy { None } else { Some(&row.token) },
        );
        let ssh_url = s.ssh_url(row.owner, row.repo);

        // Clone (read).
        let http_clone = if is_deploy {
            row.readable
        } else {
            let dir = tmp_path.join(format!("clone-http-{}", row.label));
            git(
                &tmp_path,
                &["clone", "-q", &http_url, dir.to_str().unwrap()],
            )
            .await
            .status
            .success()
        };
        let clone_dir = tmp_path.join(format!("clone-ssh-{}", row.label));
        let ssh_clone = s
            .ssh_git(
                &tmp_path,
                &row.key,
                &["clone", "-q", &ssh_url, clone_dir.to_str().unwrap()],
            )
            .await;
        let ssh_clone_ok = ssh_clone.status.success();
        assert_eq!(
            ssh_clone_ok,
            row.readable,
            "{cell}: ssh clone {}",
            stderr(&ssh_clone)
        );
        if is_deploy {
            assert!(ssh_clone_ok, "{cell}: deploy clone (D5)");
        } else {
            assert_eq!(http_clone, row.readable, "{cell}: http clone");
            assert_eq!(ssh_clone_ok, http_clone, "{cell}: clone equality");
        }

        // Branch push (write). Distinct branches per transport: the same
        // refspec twice would let the second push succeed as an up-to-date
        // no-op without exercising its write authorization.
        let branch_ssh = format!("sweep/{tag}-{}-ssh", row.label);
        let branch_http = format!("sweep/{tag}-{}-http", row.label);
        let refspec_ssh = format!("HEAD:refs/heads/{branch_ssh}");
        let refspec_http = format!("HEAD:refs/heads/{branch_http}");
        let ssh_branch = s
            .ssh_git(&seed, &row.key, &["push", "-q", &ssh_url, &refspec_ssh])
            .await;
        let ssh_branch_ok = ssh_branch.status.success();
        assert_eq!(
            ssh_branch_ok,
            row.writable,
            "{cell}: ssh branch push {}",
            stderr(&ssh_branch)
        );
        if is_deploy {
            assert_eq!(
                ssh_branch_ok, row.writable,
                "{cell}: deploy branch push (D5)"
            );
        } else {
            let http_branch = git(&seed, &["push", "-q", &http_url, &refspec_http])
                .await
                .status
                .success();
            assert_eq!(http_branch, row.writable, "{cell}: http branch push");
            assert_eq!(ssh_branch_ok, http_branch, "{cell}: branch equality");
            for (branch, who) in [(&branch_ssh, "ssh"), (&branch_http, "http")] {
                let probe = git(
                    &tmp_path,
                    &[
                        "ls-remote",
                        &s.git_url(row.owner, row.repo, Some(&alice_tok)),
                        &format!("refs/heads/{branch}"),
                    ],
                )
                .await;
                assert!(probe.status.success(), "{cell}: ls-remote {who}");
                assert_eq!(
                    String::from_utf8(probe.stdout)
                        .unwrap()
                        .contains(&format!("refs/heads/{branch}")),
                    row.writable,
                    "{cell}: {who} pushed branch present"
                );
            }
        }

        // refs/for push (read tier for readers, write tier for writers; deploy never).
        let topic_http = format!("{tag}-{}-http", row.label);
        let topic_ssh = format!("{tag}-{}-ssh", row.label);
        let refs_ssh = s
            .ssh_git(
                &seed,
                &row.key,
                &[
                    "push",
                    "-q",
                    &ssh_url,
                    &format!("HEAD:refs/for/main/{topic_ssh}"),
                ],
            )
            .await;
        let refs_ssh_ok = refs_ssh.status.success();
        let refs_expect = row.member && row.readable;
        assert_eq!(
            refs_ssh_ok,
            refs_expect,
            "{cell}: ssh refs/for {}",
            stderr(&refs_ssh)
        );
        if is_deploy {
            assert!(!refs_ssh_ok, "{cell}: deploy refs/for refused (D5)");
        } else {
            let refs_http = git(
                &seed,
                &[
                    "push",
                    "-q",
                    &http_url,
                    &format!("HEAD:refs/for/main/{topic_http}"),
                ],
            )
            .await
            .status
            .success();
            assert_eq!(refs_http, refs_expect, "{cell}: http refs/for");
            assert_eq!(refs_ssh_ok, refs_http, "{cell}: refs/for equality");
        }

        // Tag push under `v*` protection (maintain+ only).
        let tag_http_name = format!("v-{}-http", row.label);
        let tag_ssh_name = format!("v-{}-ssh", row.label);
        git_ok(&seed, &["tag", &tag_http_name]).await;
        git_ok(&seed, &["tag", &tag_ssh_name]).await;
        let tag_ssh = s
            .ssh_git(
                &seed,
                &row.key,
                &["push", "-q", &ssh_url, &format!("refs/tags/{tag_ssh_name}")],
            )
            .await;
        let tag_ssh_ok = tag_ssh.status.success();
        assert_eq!(
            tag_ssh_ok,
            row.tag_ok,
            "{cell}: ssh tag push {}",
            stderr(&tag_ssh)
        );
        if is_deploy {
            assert!(!tag_ssh_ok, "{cell}: deploy tag refused (D5)");
        } else {
            let tag_http = git(
                &seed,
                &[
                    "push",
                    "-q",
                    &http_url,
                    &format!("refs/tags/{tag_http_name}"),
                ],
            )
            .await
            .status
            .success();
            assert_eq!(tag_http, row.tag_ok, "{cell}: http tag push");
            assert_eq!(tag_ssh_ok, tag_http, "{cell}: tag equality");
        }

        // Force push under branch protection (refused for everyone).
        let force_ssh = s
            .ssh_git(
                &seed,
                &row.key,
                &["push", "--force", "-q", &ssh_url, "main"],
            )
            .await;
        let force_ssh_ok = force_ssh.status.success();
        assert!(
            !force_ssh_ok,
            "{cell}: ssh force push refused {}",
            stderr(&force_ssh)
        );
        if !is_deploy {
            let force_http = git(&seed, &["push", "--force", "-q", &http_url, "main"])
                .await
                .status
                .success();
            assert!(!force_http, "{cell}: http force push refused");
        }
        let probe = git(
            &tmp_path,
            &[
                "ls-remote",
                &s.git_url(row.owner, row.repo, Some(&alice_tok)),
                "refs/heads/main",
            ],
        )
        .await;
        assert!(probe.status.success(), "{cell}: ls-remote main");
        assert!(
            String::from_utf8(probe.stdout)
                .unwrap()
                .contains(tip.trim()),
            "{cell}: protected tip unmoved"
        );
    }

    // Pin one refs/for ingestion over SSH (change with the pusher's author).
    let repo_id = starforged_db::repos::by_owner_and_name(s.core.db(), "alice", "proj")
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut ingested = false;
    for _ in 0..100 {
        if starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            uwrite.id,
            "main",
            &format!("{tag}-uwrite-ssh"),
            None,
        )
        .await
        .unwrap()
        .is_some()
        {
            ingested = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ingested, "ssh refs/for ingestion created a change");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_public() {
    sweep(Visibility::Public, "pub").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_private() {
    sweep(Visibility::Private, "priv").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_takes_effect_on_next_connection() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let tok = s.token(&alice, &[Scope::RepoRead, Scope::RepoWrite]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&tok)),
            "main",
        ],
    )
    .await;

    // Key removal.
    let kdir = keydir();
    let kdir = kdir.path();
    let (priv_key, publine) = gen_key(kdir, "id_a", "ed25519", None);
    let view = s.add_key(&alice, &publine).await;
    let alive = s
        .ssh_git(kdir, &priv_key, &["ls-remote", &s.ssh_url("alice", "proj")])
        .await;
    assert!(alive.status.success(), "before removal: {}", stderr(&alive));
    s.core.remove_ssh_key(&alice, view.id).await.unwrap();
    let dead = s
        .ssh_git(kdir, &priv_key, &["ls-remote", &s.ssh_url("alice", "proj")])
        .await;
    assert!(
        !dead.status.success(),
        "removed key must stop authenticating"
    );

    // Suspension.
    let (priv2, pub2) = gen_key(kdir, "id_b", "ed25519", None);
    s.add_key(&alice, &pub2).await;
    let admin = s
        .core
        .create_user(CreateUser {
            handle: "sysop".into(),
            display_name: String::new(),
            email: None,
            email_verified: true,
            password: Some("correct horse battery".into()),
            is_admin: true,
        })
        .await
        .unwrap();
    s.core.suspend_user(&admin, alice.id).await.unwrap();
    let out = s
        .ssh_git(kdir, &priv2, &["ls-remote", &s.ssh_url("alice", "proj")])
        .await;
    assert!(
        !out.status.success(),
        "suspended user must not authenticate"
    );
    s.core.unsuspend_user(&admin, alice.id).await.unwrap();
    let out = s
        .ssh_git(kdir, &priv2, &["ls-remote", &s.ssh_url("alice", "proj")])
        .await;
    assert!(
        out.status.success(),
        "unsuspended user authenticates again: {}",
        stderr(&out)
    );

    // Deploy-key deletion.
    let (dpriv, dpub) = gen_key(kdir, "id_d", "ed25519", None);
    let dview = s.add_deploy(&alice, "proj", &dpub, false).await;
    let out = s
        .ssh_git(kdir, &dpriv, &["ls-remote", &s.ssh_url("alice", "proj")])
        .await;
    assert!(
        out.status.success(),
        "before deploy delete: {}",
        stderr(&out)
    );
    s.core
        .remove_deploy_key(&alice, "alice", "proj", dview.id)
        .await
        .unwrap();
    let out = s
        .ssh_git(kdir, &dpriv, &["ls-remote", &s.ssh_url("alice", "proj")])
        .await;
    assert!(
        !out.status.success(),
        "deleted deploy key must stop authenticating"
    );

    // Repository transfer: the old org's team grant drops.
    let orguser = s.user("orguser").await;
    s.core
        .create_org(
            &orguser,
            NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    s.core
        .set_org_member(&orguser, "acme", "bob", OrgRole::Member)
        .await
        .unwrap();
    s.core
        .create_team(
            &orguser,
            "acme",
            NewTeamInput {
                name: "readers".into(),
                description: String::new(),
                permission: "read".into(),
                all_repos: true,
            },
        )
        .await
        .unwrap();
    s.core
        .set_team_member(&orguser, "acme", "readers", "bob")
        .await
        .unwrap();
    s.core
        .create_repo(
            &orguser,
            "acme",
            starforged_core::repos::CreateRepo {
                name: "shut".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
    let org_tok = s
        .token(&orguser, &[Scope::RepoRead, Scope::RepoWrite])
        .await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("acme", "shut", Some(&org_tok)),
            "main",
        ],
    )
    .await;
    let (bpriv, bpub) = gen_key(kdir, "id_bob", "ed25519", None);
    s.add_key(&bob, &bpub).await;
    let out = s
        .ssh_git(kdir, &bpriv, &["ls-remote", &s.ssh_url("acme", "shut")])
        .await;
    assert!(
        out.status.success(),
        "team read before transfer: {}",
        stderr(&out)
    );
    // Org owner (a user) transfers to themselves as a user: team links drop.
    s.core
        .transfer_repo(&orguser, "acme", "shut", "orguser")
        .await
        .unwrap();
    let out = s
        .ssh_git(kdir, &bpriv, &["ls-remote", &s.ssh_url("acme", "shut")])
        .await;
    assert!(!out.status.success(), "old path dead after transfer");
    let out = s
        .ssh_git(kdir, &bpriv, &["ls-remote", &s.ssh_url("orguser", "shut")])
        .await;
    assert!(
        !out.status.success(),
        "team grant gone after transfer: {}",
        stderr(&out)
    );
    let out = s
        .ssh_git(kdir, &bpriv, &["ls-remote", &s.ssh_url("orguser", "shut")])
        .await;
    assert!(
        !out.status.success(),
        "bob has no grant on transferred repo"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_rows_hold_no_key_material() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let kdir = keydir();
    let kdir = kdir.path();
    let (priv_key, publine) = gen_key(kdir, "id_a", "ed25519", None);
    let blob = publine.split_whitespace().nth(1).unwrap().to_owned();
    let private_material = std::fs::read_to_string(&priv_key).unwrap();
    assert!(private_material.contains("PRIVATE"), "priv file sanity");
    let view = s.add_key(&alice, &publine).await;
    let (dpriv, dpub) = gen_key(kdir, "id_d", "ed25519", None);
    let _ = dpriv;
    let dblob = dpub.split_whitespace().nth(1).unwrap().to_owned();
    s.add_deploy(&alice, "proj", &dpub, false).await;
    s.core.remove_ssh_key(&alice, view.id).await.unwrap();
    let rows = starforged_db::audit::recent(s.core.db(), 50).await.unwrap();
    let add: Vec<_> = rows.iter().filter(|r| r.action == "ssh_key.add").collect();
    assert_eq!(add.len(), 1, "{rows:?}");
    assert_eq!(
        add[0].detail, view.fingerprint,
        "add row carries fingerprint only"
    );
    let rem: Vec<_> = rows
        .iter()
        .filter(|r| r.action == "ssh_key.remove")
        .collect();
    assert_eq!(rem.len(), 1, "{rows:?}");
    for row in &rows {
        for field in [&row.action, &row.target, &row.detail] {
            assert!(
                !field.contains(&blob),
                "audit must never hold the key blob: {row:?}"
            );
            assert!(
                !field.contains(&dblob),
                "audit must never hold the key blob: {row:?}"
            );
            assert!(
                !field.contains("PRIVATE"),
                "audit must never hold private material: {row:?}"
            );
            assert!(
                !field.contains(&publine),
                "audit must never hold the public line: {row:?}"
            );
        }
    }
    let dadd: Vec<_> = rows
        .iter()
        .filter(|r| r.action == "deploy_key.add")
        .collect();
    assert_eq!(dadd.len(), 1, "{rows:?}");
    assert_eq!(dadd[0].detail, "repo:alice/proj");
    let drem: Vec<_> = rows
        .iter()
        .filter(|r| r.action == "deploy_key.remove")
        .collect();
    assert!(drem.is_empty(), "no deploy removal in this test: {rows:?}");
}
