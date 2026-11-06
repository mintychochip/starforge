//! Git over SSH (M3c, spec §8.1): real `ssh` + `git` against the in-process
//! server. User keys, deploy keys, refusals, request restrictions, limits,
//! and the repository page's SSH clone URL (plan D5/D6).

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::permission::Visibility;

fn keydir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Bounded poll (10 s) for observable state; never a sleep.
async fn wait_for_tip(s: &TestServer, owner: &str, repo: &str) -> String {
    for _ in 0..100 {
        if let Some(tip) = repo_tip(s, owner, repo, "main").await {
            return tip;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for tip");
}

async fn repo_tip(server: &TestServer, owner: &str, repo: &str, branch: &str) -> Option<String> {
    let row = starforged_db::repos::by_owner_and_name(server.core.db(), owner, repo)
        .await
        .ok()??;
    let path = server.core.repo_path(row.id);
    let branch_ref = format!("refs/heads/{branch}");
    let out = tokio::task::spawn_blocking(move || {
        Command::new("git")
            .args([
                "-C",
                path.to_str().unwrap(),
                "rev-parse",
                "--verify",
                "-q",
                &branch_ref,
            ])
            .output()
    })
    .await
    .ok()?;
    let out = out.ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        None
    }
}

async fn waiter_tip(s: &TestServer, owner: &str, repo: &str) -> String {
    wait_for_tip(s, owner, repo).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_clone_fetch_and_push_branch() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let dir = keydir();
    let dir = dir.path();
    let (priv_key, publine) = gen_key(dir, "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;

    // Push over HTTP first so the clone has content, then clone over SSH.
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let token = s
        .token(
            &alice,
            &[
                starforged_core::tokens::Scope::RepoRead,
                starforged_core::tokens::Scope::RepoWrite,
            ],
        )
        .await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    let tip = waiter_tip(&s, "alice", "proj").await;

    let clone_dir = tempfile::tempdir().unwrap();
    s.ssh_git_ok(
        clone_dir.path(),
        &priv_key,
        &["clone", "-q", &s.ssh_url("alice", "proj"), "clone"],
    )
    .await;
    let cloned = clone_dir.path().join("clone");
    let head = git_ok(&cloned, &["rev-parse", "HEAD"]).await;
    assert_eq!(head.trim(), tip);

    // Fetch a new commit pushed over HTTP, then push a branch over SSH.
    commit_files(&work, &[("a.txt", b"a")], "more").await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    s.ssh_git_ok(&cloned, &priv_key, &["fetch", "-q", "origin"])
        .await;
    let fetched = git_ok(&cloned, &["rev-parse", "FETCH_HEAD"]).await;
    let new_tip = waiter_tip(&s, "alice", "proj").await;
    assert_eq!(fetched.trim(), new_tip);

    commit_files(&cloned, &[("b.txt", b"b")], "branch").await;
    git_ok(&cloned, &["checkout", "-q", "-b", "feature"]).await;
    s.ssh_git_ok(&cloned, &priv_key, &["push", "-q", "origin", "feature"])
        .await;
    let branch_tip = git_ok(&cloned, &["rev-parse", "feature"]).await;
    // The branch lands as a stored ref.
    assert!(repo_tip(&s, "alice", "proj", "feature").await.is_some());
    assert_eq!(
        repo_tip(&s, "alice", "proj", "feature").await.unwrap(),
        branch_tip.trim()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_refs_for_push_creates_change_and_v2_and_rename() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let dir = keydir();
    let dir = dir.path();
    let (priv_key, publine) = gen_key(dir, "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let token = s
        .token(
            &alice,
            &[
                starforged_core::tokens::Scope::RepoRead,
                starforged_core::tokens::Scope::RepoWrite,
            ],
        )
        .await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    waiter_tip(&s, "alice", "proj").await;

    let clone_dir = tempfile::tempdir().unwrap();
    // Protocol v2: ls-remote advertises a v2 capability line through the SSH transport.
    let out = s
        .ssh_git(
            clone_dir.path(),
            &priv_key,
            &["clone", "-q", &s.ssh_url("alice", "proj"), "clone"],
        )
        .await;
    assert!(out.status.success(), "clone: {}", stderr(&out));
    // GIT_TRACE_PACKET shows the protocol version negotiation.
    let out = {
        let ssh = format!(
            "ssh -i {} -p {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityAgent=none",
            priv_key.display(),
            s.ssh_addr.port()
        );
        git_with_env(
            clone_dir.path(),
            &["ls-remote", &s.ssh_url("alice", "proj")],
            &[("GIT_SSH_COMMAND", &ssh), ("GIT_TRACE_PACKET", "1")],
        )
        .await
    };
    let trace = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        trace.contains("version 2") || trace.contains("version=2"),
        "expected v2: {trace}"
    );

    let cloned = clone_dir.path().join("clone");
    s.ssh_git_ok(
        &cloned,
        &priv_key,
        &["push", "-q", "origin", "HEAD:refs/for/main/topic"],
    )
    .await;
    // The change is ingested by the post-receive scan (bounded poll).
    let repo_id = starforged_db::repos::by_owner_and_name(s.core.db(), "alice", "proj")
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut found = false;
    for _ in 0..100 {
        if starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            alice.id,
            "main",
            "topic",
            None,
        )
        .await
        .unwrap()
        .is_some()
        {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(found, "refs/for change never ingested");

    // Renamed repository's old path works over SSH.
    s.core
        .rename_repo(&alice, "alice", "proj", "renamed")
        .await
        .unwrap();
    let old_url = s.ssh_url("alice", "proj");
    let out = s
        .ssh_git(clone_dir.path(), &priv_key, &["ls-remote", &old_url])
        .await;
    assert!(out.status.success(), "old path ls-remote: {}", stderr(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&waiter_tip(&s, "alice", "renamed").await)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deploy_key_on_deleted_repo_gets_not_found() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let token = s
        .token(
            &alice,
            &[
                starforged_core::tokens::Scope::RepoRead,
                starforged_core::tokens::Scope::RepoWrite,
            ],
        )
        .await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    waiter_tip(&s, "alice", "proj").await;
    let dir = keydir();
    let dir = dir.path();
    let (ro_priv, ro_pub) = gen_key(dir, "id_ro", "ed25519", None);
    s.add_deploy(&alice, "proj", &ro_pub, false).await;
    s.core
        .rename_repo(&alice, "alice", "proj", "renamed")
        .await
        .unwrap();
    s.core
        .delete_repo(&alice, "alice", "renamed", "alice/renamed")
        .await
        .unwrap();
    for path in ["proj", "renamed"] {
        let out = s
            .ssh_git(dir, &ro_priv, &["ls-remote", &s.ssh_url("alice", path)])
            .await;
        assert!(!out.status.success(), "deleted deploy repo {path}");
        assert!(
            stderr(&out).contains("repository not found"),
            "{}",
            stderr(&out)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deploy_keys_round_trip() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.repo(&alice, "other", Visibility::Private).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let token = s
        .token(
            &alice,
            &[
                starforged_core::tokens::Scope::RepoRead,
                starforged_core::tokens::Scope::RepoWrite,
            ],
        )
        .await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    waiter_tip(&s, "alice", "proj").await;

    let dir = keydir();
    let dir = dir.path();
    // Read-only deploy key: clones, cannot push.
    let (ro_priv, ro_pub) = gen_key(dir, "id_ro", "ed25519", None);
    s.add_deploy(&alice, "proj", &ro_pub, false).await;
    let clone_dir = tempfile::tempdir().unwrap();
    s.ssh_git_ok(
        clone_dir.path(),
        &ro_priv,
        &["clone", "-q", &s.ssh_url("alice", "proj"), "clone"],
    )
    .await;
    let cloned = clone_dir.path().join("clone");
    commit_files(&cloned, &[("c.txt", b"c")], "ro push").await;
    let out = s
        .ssh_git(&cloned, &ro_priv, &["push", "-q", "origin", "main"])
        .await;
    assert!(
        !out.status.success(),
        "read-only deploy key must not push: {}",
        stderr(&out)
    );

    // Read-write deploy key: pushes a branch, cannot push refs/for.
    let (rw_priv, rw_pub) = gen_key(dir, "id_rw", "ed25519", None);
    s.add_deploy(&alice, "proj", &rw_pub, true).await;
    commit_files(&cloned, &[("d.txt", b"d")], "rw push").await;
    git_ok(&cloned, &["checkout", "-q", "-b", "deployed"]).await;
    s.ssh_git_ok(&cloned, &rw_priv, &["push", "-q", "origin", "deployed"])
        .await;
    assert!(repo_tip(&s, "alice", "proj", "deployed").await.is_some());
    let out = s
        .ssh_git(
            &cloned,
            &rw_priv,
            &["push", "-q", "origin", "HEAD:refs/for/main/x"],
        )
        .await;
    assert!(
        !out.status.success(),
        "deploy key must not push refs/for: {}",
        stderr(&out)
    );

    // A deploy key cannot reach another repository.
    let out = s
        .ssh_git(
            clone_dir.path(),
            &rw_priv,
            &["ls-remote", &s.ssh_url("alice", "other")],
        )
        .await;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("repository not found"),
        "{}",
        stderr(&out)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let token = s
        .token(
            &alice,
            &[
                starforged_core::tokens::Scope::RepoRead,
                starforged_core::tokens::Scope::RepoWrite,
            ],
        )
        .await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    waiter_tip(&s, "alice", "proj").await;

    let dir = keydir();
    let dir = dir.path();
    // Unknown key.
    let (unknown_priv, _unknown_pub) = gen_key(dir, "id_unknown", "ed25519", None);
    let out = s
        .ssh_git(
            tmp.path(),
            &unknown_priv,
            &["ls-remote", &s.ssh_url("alice", "proj")],
        )
        .await;
    assert!(!out.status.success());

    // Suspended user.
    let (alice_priv, alice_pub) = gen_key(dir, "id_alice", "ed25519", None);
    s.add_key(&alice, &alice_pub).await;
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
        .ssh_git(
            tmp.path(),
            &alice_priv,
            &["ls-remote", &s.ssh_url("alice", "proj")],
        )
        .await;
    assert!(
        !out.status.success(),
        "suspended user must not authenticate"
    );
    s.core.unsuspend_user(&admin, alice.id).await.unwrap();

    // Wrong user name.
    let out = Command::new("ssh")
        .args([
            "-i",
            unknown_priv.to_str().unwrap(),
            "-p",
            &s.ssh_addr.port().to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "bob@127.0.0.1",
            "git-upload-pack '/alice/proj.git'",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // Private repository the user cannot read: "not found".
    let clone_dir = tempfile::tempdir().unwrap();
    let (bob_priv, bob_pub) = gen_key(dir, "id_bob", "ed25519", None);
    s.add_key(&bob, &bob_pub).await;
    let out = s
        .ssh_git(
            clone_dir.path(),
            &bob_priv,
            &["ls-remote", &s.ssh_url("alice", "proj")],
        )
        .await;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("repository not found"),
        "{}",
        stderr(&out)
    );

    // Write push by a read user.
    s.core
        .set_collaborator(
            &alice,
            "alice",
            "proj",
            "bob",
            starforged_core::permission::Permission::Read,
        )
        .await
        .unwrap();
    let work2 = work_repo(tmp.path(), "work2", &[("README.md", "# hi\n")]).await;
    let _ = work2;
    // Bob clones (read), commits, and tries to push: refused.
    s.ssh_git_ok(
        clone_dir.path(),
        &bob_priv,
        &["clone", "-q", &s.ssh_url("alice", "proj"), "clone"],
    )
    .await;
    let bob_work = clone_dir.path().join("clone");
    commit_files(&bob_work, &[("e.txt", b"e")], "bob push").await;
    let out = s
        .ssh_git(&bob_work, &bob_priv, &["push", "-q", "origin", "main"])
        .await;
    assert!(
        !out.status.success(),
        "reader must not push: {}",
        stderr(&out)
    );

    // Push to an archived repository.
    s.core.archive_repo(&alice, "alice", "proj").await.unwrap();
    let out = s
        .ssh_git(
            &bob_work,
            &alice_priv,
            &["push", "-q", &s.ssh_url("alice", "proj"), "main"],
        )
        .await;
    assert!(
        !out.status.success(),
        "archived repo must refuse pushes: {}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("archived"), "{}", stderr(&out));
}

fn ssh_raw(s: &TestServer, priv_key: &Path, user: &str, args: &[&str], extra: &[&str]) -> Output {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-i",
        priv_key.to_str().unwrap(),
        "-p",
        &s.ssh_addr.port().to_string(),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
    ]);
    cmd.args(extra);
    cmd.arg(format!("{user}@127.0.0.1"));
    cmd.args(args);
    cmd.output().unwrap()
}

async fn ssh_raw_bounded(
    s: &TestServer,
    priv_key: &Path,
    user: &str,
    args: &[&str],
    extra: &[&str],
) -> Output {
    let s = s.ssh_addr.port();
    let priv_key = priv_key.to_path_buf();
    let user = user.to_owned();
    let args = args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    let extra = extra.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    let handle = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("ssh");
        cmd.args([
            "-i",
            priv_key.to_str().unwrap(),
            "-p",
            &s.to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
        ]);
        cmd.args(&extra);
        cmd.arg(format!("{user}@127.0.0.1"));
        cmd.args(&args);
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            match child.try_wait().unwrap() {
                Some(_) => return child.wait_with_output().unwrap(),
                None => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return child.wait_with_output().unwrap();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), handle)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restrictions() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let dir = keydir();
    let dir = dir.path();
    let (priv_key, publine) = gen_key(dir, "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;

    // Shell is refused.
    let out = ssh_raw(&s, &priv_key, "git", &[], &[]);
    assert!(!out.status.success(), "shell: {}", stderr(&out));
    // Unknown commands are refused.
    let out = ssh_raw(&s, &priv_key, "git", &["ls"], &[]);
    assert!(!out.status.success());
    // Port forwarding is refused, immediately and bounded.
    let out = ssh_raw_bounded(
        &s,
        &priv_key,
        "git",
        &[],
        &[
            "-N",
            "-R",
            "0:127.0.0.1:80",
            "-o",
            "ExitOnForwardFailure=yes",
        ],
    )
    .await;
    assert!(!out.status.success(), "remote forward must be refused");
    let out = ssh_raw_bounded(&s, &priv_key, "git", &[], &["-W", "127.0.0.1:80"]).await;
    assert!(!out.status.success(), "direct-tcpip must be refused");
    // A non-GIT_PROTOCOL env request is ignored: a real git op succeeds.
    let out = s
        .ssh_git_with_opts(
            dir,
            &priv_key,
            &["ls-remote", &s.ssh_url("alice", "proj")],
            &["SetEnv=FOO=bar"],
        )
        .await;
    assert!(
        out.status.success(),
        "bogus env must not break the git command: {}",
        stderr(&out)
    );
}

fn hold_ssh_n(
    s: &TestServer,
    priv_key: &Path,
    extra: &[&str],
    keepalive: bool,
    wait_auth: bool,
) -> std::process::Child {
    use std::io::{BufRead, Read};
    let mut cmd = Command::new("ssh");
    if wait_auth {
        cmd.arg("-v");
    }
    cmd.args([
        "-i",
        priv_key.to_str().unwrap(),
        "-p",
        &s.ssh_addr.port().to_string(),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-N",
    ]);
    if keepalive {
        cmd.args(["-o", "ServerAliveInterval=1"]);
    }
    cmd.args(extra);
    cmd.arg("git@127.0.0.1");
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    if !wait_auth {
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = stderr.read_to_end(&mut sink);
        });
        return child;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut collected = String::new();
    loop {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("ssh -N did not authenticate in 10s; stderr:\n{collected}");
        }
        let mut line = String::new();
        match stderr.read_line(&mut line) {
            Ok(0) => {
                let status = child.wait().unwrap();
                panic!("ssh -N exited early ({status}); stderr:\n{collected}");
            }
            Ok(_) => {
                collected.push_str(&line);
                if line.contains("Authenticated to") {
                    break;
                }
            }
            Err(_) => {
                let _ = child.kill();
                panic!("ssh -N stderr read failed; collected:\n{collected}");
            }
        }
    }
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = stderr.read_to_end(&mut sink);
    });
    child
}

// Helpers run in spawn_blocking: `tokio::process` child waiting cannot be slept on with blocking sleep.
fn wait_exited(child: &mut std::process::Child, bound: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + bound;
    loop {
        match child.try_wait().unwrap() {
            Some(status) => return !status.success(),
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limits_concurrent_connection_refused() {
    let s = TestServer::start_with(|c| {
        c.ssh.idle_timeout_secs = 60;
        c.ssh.max_connection_secs = 600;
        c.ssh.max_connections_per_user = 1;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let dir = keydir();
    let dir = dir.path();
    let (priv_key, publine) = gen_key(dir, "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;
    let mut held = hold_ssh_n(&s, &priv_key, &[], false, true);
    // Poll a second connection until it is refused (slot held by `held`).
    let refused = {
        let mut ok = false;
        for _ in 0..100 {
            let out = s
                .ssh_git(dir, &priv_key, &["ls-remote", &s.ssh_url("alice", "proj")])
                .await;
            if !out.status.success() && stderr(&out).contains("Permission denied") {
                ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        ok
    };
    assert!(refused, "second concurrent connection must be refused");
    let _ = held.kill();
    let _ = held.wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limits_idle_connection_closes() {
    let s = TestServer::start_with(|c| {
        c.ssh.idle_timeout_secs = 1;
        c.ssh.max_connection_secs = 600;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let dir = keydir();
    let dir = dir.path();
    let (priv_key, publine) = gen_key(dir, "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;
    let mut held = hold_ssh_n(&s, &priv_key, &[], false, false);
    let closed = tokio::task::spawn_blocking(move || {
        wait_exited(&mut held, std::time::Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(closed, "idle connection must close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limits_total_connection_closes() {
    let s = TestServer::start_with(|c| {
        c.ssh.idle_timeout_secs = 600;
        c.ssh.max_connection_secs = 3;
    })
    .await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let dir = keydir();
    let dir = dir.path();
    let (priv_key, publine) = gen_key(dir, "id_ed", "ed25519", None);
    s.add_key(&alice, &publine).await;
    let mut held = hold_ssh_n(&s, &priv_key, &[], true, true);
    let closed = tokio::task::spawn_blocking(move || {
        wait_exited(&mut held, std::time::Duration::from_secs(10))
    })
    .await
    .unwrap();
    assert!(closed, "total timeout must close the connection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_page_shows_ssh_clone_url() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let page = get_text(&s.browser(), &s.url("/alice/proj")).await;
    assert!(
        page.contains(&format!("{}&#47;alice&#47;proj.git", s.ssh_base))
            || page.contains(&format!("{}/alice/proj.git", s.ssh_base)),
        "ssh clone url missing:\n{page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deploy_write_push_webhook_sender_null() {
    use std::sync::{Arc, Mutex};
    let s = TestServer::start_with(|c| c.webhooks.allow_loopback = true).await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let token = s
        .token(
            &alice,
            &[
                starforged_core::tokens::Scope::RepoRead,
                starforged_core::tokens::Scope::RepoWrite,
            ],
        )
        .await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", "origin", "main"]).await;
    waiter_tip(&s, "alice", "proj").await;
    let dir = keydir();
    let dir = dir.path();
    let (rw_priv, rw_pub) = gen_key(dir, "id_rw", "ed25519", None);
    s.add_deploy(&alice, "proj", &rw_pub, true).await;
    let hits: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let inner = hits.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |body: axum::body::Bytes| {
            let inner = inner.clone();
            async move {
                inner
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice::<serde_json::Value>(&body).unwrap());
                (axum::http::StatusCode::OK, "ok".to_string())
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    let client = reqwest::Client::new();
    let res = client
        .post(s.url("/api/v1/repos/alice/proj/hooks"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"url": format!("http://{addr}/hook"), "events": ["push"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::CREATED);
    let clone_dir = tempfile::tempdir().unwrap();
    s.ssh_git_ok(
        clone_dir.path(),
        &rw_priv,
        &["clone", "-q", &s.ssh_url("alice", "proj"), "clone"],
    )
    .await;
    let cloned = clone_dir.path().join("clone");
    commit_files(&cloned, &[("d.txt", b"d")], "rw push").await;
    git_ok(&cloned, &["checkout", "-q", "-b", "deployed"]).await;
    s.ssh_git_ok(&cloned, &rw_priv, &["push", "-q", "origin", "deployed"])
        .await;
    let mut sender: Option<serde_json::Value> = None;
    for _ in 0..100 {
        s.core.run_due_jobs().await.unwrap();
        // Match the deploy-key push itself: the earlier HTTP push of `main`
        // by alice is processed asynchronously and may also reach the hook
        // if its fan-out runs after the hook is registered.
        let found = hits
            .lock()
            .unwrap()
            .iter()
            .find(|b| {
                b.get("event").is_some_and(|v| v == "push")
                    && b["push"]["ref"] == "refs/heads/deployed"
            })
            .cloned();
        if let Some(body) = found {
            sender = body.get("sender").cloned();
            if sender.is_some() {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        sender,
        Some(serde_json::Value::Null),
        "deploy push webhook sender must be null: {sender:?}"
    );
}
