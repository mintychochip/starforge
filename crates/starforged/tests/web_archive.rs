//! Archive downloads: zip/tar.gz streaming, format 404s, and private-repo
//! visibility, plus the download links on the repository home page.
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
}
async fn push(s: &TestServer, alice: &starforged_core::accounts::User, repo: &str) {
    let url = s.git_url(
        "alice",
        repo,
        Some(&s.token(alice, &[Scope::RepoWrite]).await),
    );
    let work = work_repo(
        s.data.path(),
        &format!("work-{repo}"),
        &[("a.txt", "hello\n")],
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
}

async fn start() -> Ctx {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    s.repo(&alice, "secret", Visibility::Private).await;
    push(&s, &alice, "proj").await;
    push(&s, &alice, "secret").await;
    Ctx { s }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zip_and_tar_gz_downloads_stream_archive_bytes() {
    let c = start().await;
    let anon = c.s.browser();

    let zip = anon
        .get(c.s.url("/alice/proj/archive/main.zip"))
        .send()
        .await
        .unwrap();
    assert_eq!(zip.status().as_u16(), 200);
    assert_eq!(
        zip.headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"proj-main.zip\"")
    );
    let bytes = zip.bytes().await.unwrap();
    assert!(
        bytes.starts_with(b"PK\x03\x04"),
        "zip body must start with the PK local-file header"
    );

    let tar = anon
        .get(c.s.url("/alice/proj/archive/main.tar.gz"))
        .send()
        .await
        .unwrap();
    assert_eq!(tar.status().as_u16(), 200);
    let bytes = tar.bytes().await.unwrap();
    assert!(
        bytes.starts_with(&[0x1f, 0x8b]),
        "tar.gz body must start with the gzip magic"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_rev_and_unknown_format_are_404() {
    let c = start().await;
    let anon = c.s.browser();
    for path in [
        "/alice/proj/archive/nope.zip",
        "/alice/proj/archive/main.rar",
    ] {
        let res = anon.get(c.s.url(path)).send().await.unwrap();
        assert_eq!(res.status().as_u16(), 404, "{path}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_repo_archive_404s_anonymously_and_serves_owner() {
    let c = start().await;

    let anon = c.s.browser();
    let res = anon
        .get(c.s.url("/alice/secret/archive/main.zip"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);

    let (owner, _csrf) = c.s.login("alice").await;
    let res = owner
        .get(c.s.url("/alice/secret/archive/main.zip"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_home_links_both_archive_formats() {
    let c = start().await;
    let body = get_text(&c.s.browser(), &c.s.url("/alice/proj")).await;
    assert!(
        body.contains(r#"<a href="/alice/proj/archive/main.zip">Download ZIP</a>"#),
        "home page must link the zip archive"
    );
    assert!(
        body.contains(r#"<a href="/alice/proj/archive/main.tar.gz">Download tar.gz</a>"#),
        "home page must link the tar.gz archive"
    );
}
