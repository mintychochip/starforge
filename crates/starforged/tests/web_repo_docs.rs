//! README-relative links, wrong-kind redirects, and blame reachability.

mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readme_links_images_blame_and_wrong_kind_redirects() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[
            (
                "README.md",
                "# Home\n\n[guide](docs/guide.md)\n\n[docsdir](docs/)\n\n[docsbare](docs)\n\n![logo](img/logo.png)\n",
            ),
            ("docs/guide.md", "# Guide\n"),
            ("docs/README.md", "# Docs\n\n[guide](guide.md)\n\n[root](../README.md)\n"),
            ("img/logo.png", "pngdata\n"),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let (client, _) = s.login("alice").await;

    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(
        home.contains(r#"href="/alice/proj/blob/main/docs/guide.md""#),
        "{home}"
    );
    assert!(
        home.contains(r#"href="/alice/proj/tree/main/docs""#),
        "{home}"
    );
    assert!(
        home.contains(r#"href="/alice/proj/blob/main/docs""#),
        "{home}"
    );
    assert!(
        home.contains(r#"src="/alice/proj/raw/main/img/logo.png""#),
        "{home}"
    );

    let docs = get_text(&client, &s.url("/alice/proj/tree/main/docs")).await;
    assert!(
        docs.contains(r#"href="/alice/proj/blob/main/docs/guide.md""#),
        "{docs}"
    );
    assert!(
        docs.contains(r#"href="/alice/proj/blob/main/README.md""#),
        "{docs}"
    );

    for path in [
        "/alice/proj/blob/main/docs/guide.md",
        "/alice/proj/tree/main/docs",
        "/alice/proj/blob/main/README.md",
        "/alice/proj/raw/main/img/logo.png",
    ] {
        let resp = client.get(s.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
    }

    let bare = client
        .get(s.url("/alice/proj/blob/main/docs"))
        .send()
        .await
        .unwrap();
    assert_eq!(bare.status(), 303);
    assert_eq!(bare.headers()["location"], "/alice/proj/tree/main/docs");
    let followed = client
        .get(s.url("/alice/proj/tree/main/docs"))
        .send()
        .await
        .unwrap();
    assert_eq!(followed.status(), 200);

    let blob = get_text(&client, &s.url("/alice/proj/blob/main/docs/guide.md")).await;
    assert!(blob.contains(">Blame</a>"), "{blob}");
    assert!(
        blob.contains(r#"href="/alice/proj/blame/docs/guide.md?at=main""#),
        "{blob}"
    );
    let blame_resp = client
        .get(s.url("/alice/proj/blame/docs/guide.md?at=main"))
        .send()
        .await
        .unwrap();
    assert_eq!(blame_resp.status(), 200);
    let blame = blame_resp.text().await.unwrap();
    assert!(
        blame.contains(r#"/alice/proj/blob/main/docs/guide.md"#),
        "{blame}"
    );

    let blob_dir = client
        .get(s.url("/alice/proj/blob/main/docs"))
        .send()
        .await
        .unwrap();
    assert_eq!(blob_dir.status(), 303);
    assert_eq!(blob_dir.headers()["location"], "/alice/proj/tree/main/docs");

    let tree_file = client
        .get(s.url("/alice/proj/tree/main/README.md"))
        .send()
        .await
        .unwrap();
    assert_eq!(tree_file.status(), 303);
    assert_eq!(
        tree_file.headers()["location"],
        "/alice/proj/blob/main/README.md"
    );

    for missing in [
        "/alice/proj/blob/main/missing.md",
        "/alice/proj/tree/main/missing",
    ] {
        assert_eq!(
            client.get(s.url(missing)).send().await.unwrap().status(),
            404,
            "{missing}"
        );
    }
}
