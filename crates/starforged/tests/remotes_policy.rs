mod common;

use std::time::Duration;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_git::remote::{self, RemoteCreds};

const REFSPECS: &[&str] = &["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"];

fn refspecs() -> Vec<String> {
    REFSPECS.iter().map(|s| s.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_fetch_brings_only_heads_and_tags() {
    let server = TestServer::start_with(|config| {
        config.remotes.allow_file_urls = true;
    })
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "src", &[("README.md", "# src\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&work, &[("feature.txt", b"feature\n")], "on feature").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    git_ok(&work, &["tag", "v1"]).await;
    // Refs that must never be fetched.
    git_ok(&work, &["update-ref", "refs/notes/commits", "HEAD"]).await;
    git_ok(&work, &["update-ref", "refs/pull/1/head", "HEAD"]).await;

    let url = format!("file://{}", work.display());
    let pinned = server
        .core
        .check_remote_url(&url)
        .expect("file:// is allowed under the test flag");
    let dest = tmp.path().join("dest.git");
    git_ok(
        tmp.path(),
        &["init", "-q", "--bare", dest.to_str().unwrap()],
    )
    .await;
    remote::fetch(
        &dest,
        &pinned,
        &RemoteCreds::None,
        &refspecs(),
        Duration::from_secs(30),
        tmp.path(),
    )
    .await
    .expect("file fetch succeeds");
    let refs = git_ok(&dest, &["for-each-ref", "--format=%(refname)"]).await;
    for expected in ["refs/heads/main", "refs/heads/feature", "refs/tags/v1"] {
        assert!(refs.contains(expected), "missing {expected} in:\n{refs}");
    }
    for forbidden in ["refs/notes/", "refs/pull/"] {
        assert!(
            !refs.contains(forbidden),
            "fetched forbidden {forbidden} in:\n{refs}"
        );
    }
    // ls-remote reports the default branch.
    let head = remote::ls_remote_head(
        &dest,
        &pinned,
        &RemoteCreds::None,
        Duration::from_secs(30),
        tmp.path(),
    )
    .await
    .expect("ls-remote succeeds");
    assert_eq!(head.symref.as_deref(), Some("refs/heads/main"));
    assert!(head.oid.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_fetch_uses_a_token_from_the_environment_only() {
    let client = TestServer::start_with(|config| {
        config.remotes.allow_file_urls = true;
    })
    .await;
    let upstream = TestServer::start_with(|config| {
        config.remotes.allow_file_urls = true;
    })
    .await;
    let alice = upstream.user("alice").await;
    upstream.repo(&alice, "proj", Visibility::Private).await;
    let token = upstream.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &upstream.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;

    // The URL handed to git carries no token; the token goes via the
    // GIT_CONFIG_* environment as an http.extraHeader.
    let url = upstream.git_url("alice", "proj", None);
    assert!(!url.contains(&token));
    let pinned = client
        .core
        .check_remote_url(&url)
        .expect("http to loopback is allowed under the test flag");
    let creds = RemoteCreds::Basic {
        username: "git".to_owned(),
        password: token.clone(),
    };
    for args in [
        remote::fetch_args(&pinned, &refspecs()),
        remote::push_args(&pinned, &refspecs()),
        remote::ls_remote_args(&pinned),
    ] {
        assert!(
            !args.iter().any(|a| a.contains(&token)),
            "argv leaks the token: {args:?}"
        );
    }
    let dest = tmp.path().join("dest.git");
    git_ok(
        tmp.path(),
        &["init", "-q", "--bare", dest.to_str().unwrap()],
    )
    .await;
    remote::fetch(
        &dest,
        &pinned,
        &creds,
        &refspecs(),
        Duration::from_secs(30),
        tmp.path(),
    )
    .await
    .expect("fetch with a token succeeds");
    let refs = git_ok(&dest, &["for-each-ref", "--format=%(refname)"]).await;
    assert!(refs.contains("refs/heads/main"), "refs:\n{refs}");

    // A wrong token fails, and the scrubbed error never contains it.
    let wrong = "wrong-token-value-12345";
    let dest2 = tmp.path().join("dest2.git");
    git_ok(
        tmp.path(),
        &["init", "-q", "--bare", dest2.to_str().unwrap()],
    )
    .await;
    let err = remote::fetch(
        &dest2,
        &pinned,
        &RemoteCreds::Basic {
            username: "git".to_owned(),
            password: wrong.to_owned(),
        },
        &refspecs(),
        Duration::from_secs(30),
        tmp.path(),
    )
    .await
    .expect_err("fetch with a wrong token must fail");
    let text = format!("{err}");
    assert!(!text.contains(wrong), "error leaks the token: {text}");
    assert!(!text.contains(&token), "error leaks the token: {text}");
    // scrub() directly: a stderr echoing the URL with userinfo is cleaned.
    let with_pw = format!("https://git:{wrong}@127.0.0.1/x.git");
    let scrubbed = remote::scrub(
        &format!("fatal: unable to access '{with_pw}': 401"),
        &with_pw,
    );
    assert!(!scrubbed.contains(wrong), "{scrubbed}");
}
