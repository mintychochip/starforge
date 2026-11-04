mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_and_clone_over_protocol_v0_and_v2() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    // Larger than axum's 2 MB default body limit: the push must stream.
    commit_files(
        &work,
        &[("data/blob.bin", &noise(3 * 1024 * 1024))],
        "add binary data",
    )
    .await;
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
    for version in ["0", "2"] {
        let dest = format!("clone-v{version}");
        let protocol = format!("protocol.version={version}");
        git_ok(
            tmp.path(),
            &[
                "-c",
                &protocol,
                "clone",
                "-q",
                &s.git_url("alice", "proj", Some(&token)),
                &dest,
            ],
        )
        .await;
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(&dest).join("README.md")).unwrap(),
            "# proj\n"
        );
        assert_eq!(
            std::fs::metadata(tmp.path().join(&dest).join("data/blob.bin"))
                .unwrap()
                .len(),
            3 * 1024 * 1024
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_access_follows_visibility_permissions_and_scopes() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "private", Visibility::Private).await;
    s.repo(&alice, "public", Visibility::Public).await;
    let alice_write = s.token(&alice, &[Scope::RepoWrite]).await;
    let alice_read = s.token(&alice, &[Scope::RepoRead]).await;
    let bob_write = s.token(&bob, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "public", Some(&alice_write)),
            "main",
        ],
    )
    .await;

    // Anyone can clone a public repository; nobody pushes anonymously.
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "public", None),
            "anonymous",
        ],
    )
    .await;
    assert!(
        !git(
            &work,
            &["push", &s.git_url("alice", "public", None), "main"]
        )
        .await
        .status
        .success()
    );

    // A private repository is invisible to anonymous users and to strangers.
    assert!(
        !git(
            tmp.path(),
            &["clone", &s.git_url("alice", "private", None), "x1"]
        )
        .await
        .status
        .success()
    );
    let stranger = git(
        tmp.path(),
        &[
            "clone",
            &s.git_url("alice", "private", Some(&bob_write)),
            "x2",
        ],
    )
    .await;
    assert!(
        String::from_utf8_lossy(&stranger.stderr).contains("not found"),
        "{}",
        String::from_utf8_lossy(&stranger.stderr)
    );

    // A read collaborator can clone but not push; a read-only token cannot push either.
    s.core
        .set_collaborator(&alice, "alice", "private", "bob", Permission::Read)
        .await
        .unwrap();
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "private", Some(&bob_write)),
            "bob-clone",
        ],
    )
    .await;
    // A read collaborator enters receive-pack (for refs/for) but the hook
    // rejects the branch push with a clear message and moves nothing.
    let bob_url = s.git_url("alice", "private", Some(&bob_write));
    let tip_before = git_ok(&work, &["ls-remote", &bob_url, "refs/heads/main"]).await;
    let denied = git(&work, &["push", &bob_url, "main"]).await;
    assert!(!denied.status.success());
    let denied_stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_stderr.contains("need write permission"),
        "{denied_stderr}"
    );
    let tip_after = git_ok(&work, &["ls-remote", &bob_url, "refs/heads/main"]).await;
    assert_eq!(tip_before, tip_after, "rejected push moved the branch");
    // A read-only token is likewise rejected at the hook (scope tier).
    let alice_url = s.git_url("alice", "private", Some(&alice_read));
    let read_only = git(&work, &["push", &alice_url, "main"]).await;
    assert!(!read_only.status.success());
    let read_only_stderr = String::from_utf8_lossy(&read_only.stderr);
    assert!(
        read_only_stderr.contains("repo:write scope"),
        "{read_only_stderr}"
    );
    let tip_still = git_ok(&work, &["ls-remote", &alice_url, "refs/heads/main"]).await;
    assert_eq!(tip_before, tip_still, "rejected push moved the branch");

    // A write collaborator can push.
    s.core
        .set_collaborator(&alice, "alice", "private", "bob", Permission::Write)
        .await
        .unwrap();
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "private", Some(&bob_write)),
            "main",
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushes_outside_branches_and_tags_are_rejected() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    let rejected = git(&work, &["push", &url, "HEAD:refs/entire/checkpoints/ab/x"]).await;
    assert!(!rejected.status.success());
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("refs/entire/checkpoints/ab/x is not allowed"),
        "{stderr}"
    );
    git_ok(&work, &["push", "-q", &url, "main", "HEAD:refs/tags/v1"]).await;
    let refs = git_ok(&work, &["ls-remote", &url]).await;
    assert!(
        refs.contains("refs/heads/main") && refs.contains("refs/tags/v1"),
        "{refs}"
    );
    assert!(!refs.contains("refs/entire"), "{refs}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dumb_http_is_refused_and_challenges_use_basic_auth() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.repo(&alice, "closed", Visibility::Private).await;
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(s.url("/alice/open.git/info/refs"))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let challenge = client
        .get(s.url("/alice/closed.git/info/refs?service=git-upload-pack"))
        .send()
        .await
        .unwrap();
    assert_eq!(challenge.status(), 401);
    assert_eq!(
        challenge.headers()["www-authenticate"],
        "Basic realm=\"Starforge\""
    );
    let without_suffix = client
        .get(s.url("/alice/open/info/refs?service=git-upload-pack"))
        .send()
        .await
        .unwrap();
    assert_eq!(without_suffix.status(), 200, "the .git suffix is optional");
    assert_eq!(
        without_suffix.headers()["content-type"],
        "application/x-git-upload-pack-advertisement"
    );
    assert_eq!(
        client
            .get(s.url("/healthz"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limited_scope_tokens_cannot_push_refs_for() {
    use std::time::{Duration, Instant};

    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    let owner_url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    git_ok(&work, &["push", "-q", &owner_url, "main"]).await;
    commit_files(&work, &[("b.txt", b"b\n")], "proposal").await;

    // A read-permission user with a `trail:write`-only token is rejected at
    // the RPC read tier (403) and creates nothing.
    let trail_write = s.token(&bob, &[Scope::TrailWrite]).await;
    let denied = git(
        &work,
        &[
            "push",
            &s.git_url("alice", "proj", Some(&trail_write)),
            "HEAD:refs/for/main/x",
        ],
    )
    .await;
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("403"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    // A `session:upload`-only token is rejected the same way.
    let upload = s.token(&bob, &[Scope::SessionUpload]).await;
    let denied = git(
        &work,
        &[
            "push",
            &s.git_url("alice", "proj", Some(&upload)),
            "HEAD:refs/for/main/y",
        ],
    )
    .await;
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("403"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    // Rejections happen synchronously at the RPC: no scan ever runs, so no
    // change rows may exist for bob's topics.
    for topic in ["x", "y"] {
        assert!(
            starforged_db::changes::open_agit_change(
                s.core.db(),
                repo_id,
                bob.id,
                "main",
                topic,
                None
            )
            .await
            .unwrap()
            .is_none(),
            "limited-scope push created a change for topic {topic}"
        );
    }

    // The same user with `repo:read` is accepted and lands a change.
    let read = s.token(&bob, &[Scope::RepoRead]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&read)),
            "HEAD:refs/for/main/z",
        ],
    )
    .await;
    let start = Instant::now();
    loop {
        if let Some(change) = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            bob.id,
            "main",
            "z",
            None,
        )
        .await
        .unwrap()
        {
            assert_eq!(change.creator_id, Some(bob.id));
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "repo:read refs/for push never ingested"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
