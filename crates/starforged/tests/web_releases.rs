//! Release web UI: creating a release through the form, uploading and
//! downloading an asset, the tags page links, reader restrictions, and the
//! delete-keeps-the-tag rule. Assertions read state back from Core or
//! compare response bytes, not bare page text.
mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    _tmp: tempfile::TempDir,
}

async fn start() -> Ctx {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    Ctx {
        s,
        alice,
        _tmp: tmp,
    }
}

/// Builds a hand-rolled `multipart/form-data` body (the workspace reqwest
/// has no `multipart` feature): one text field and one file field.
fn multipart_body(boundary: &str, csrf: &str, filename: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{csrf}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"asset\"; filename=\"{filename}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_upload_download_and_delete_a_release() {
    let c = start().await;
    let (alice, _) = c.s.login("alice").await;

    let form = get_text(&alice, &c.s.url("/alice/proj/releases/new")).await;
    let csrf = extract_input(&form, "_csrf");

    let res = alice
        .post(c.s.url("/alice/proj/releases/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("tag", "v1.0"),
            ("target", "main"),
            ("title", "First release"),
            ("notes", "Shipped **great** things."),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, "/alice/proj/releases/tag/v1.0");

    let view =
        c.s.core
            .release(Some(&c.alice), "alice", "proj", "v1.0")
            .await
            .unwrap();
    assert_eq!(view.title, "First release");

    let page = get_text(&alice, &c.s.url("/alice/proj/releases/tag/v1.0")).await;
    assert!(page.contains("First release"), "{page}");
    assert!(page.contains("/alice/proj/archive/v1.0.zip"), "{page}");
    assert!(page.contains("/alice/proj/archive/v1.0.tar.gz"), "{page}");

    // Upload one asset through the multipart form.
    let asset_bytes = noise(64);
    let boundary = "----starforge-test-boundary";
    let body = multipart_body(boundary, &csrf, "blob.bin", &asset_bytes);
    let res = alice
        .post(c.s.url("/alice/proj/releases/assets/v1.0"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, "/alice/proj/releases/tag/v1.0");

    let page = get_text(&alice, &c.s.url("/alice/proj/releases/tag/v1.0")).await;
    assert!(page.contains("blob.bin"), "{page}");
    assert!(
        page.contains("/alice/proj/releases/download/v1.0/blob.bin"),
        "{page}"
    );

    // The download returns the identical bytes.
    let res = alice
        .get(c.s.url("/alice/proj/releases/download/v1.0/blob.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()["content-disposition"],
        r#"attachment; filename="blob.bin""#
    );
    let downloaded = res.bytes().await.unwrap();
    assert_eq!(&downloaded[..], &asset_bytes[..]);

    // The tags page links the tag's archive and its release.
    let tags = get_text(&alice, &c.s.url("/alice/proj/tags")).await;
    assert!(tags.contains("/alice/proj/archive/v1.0.zip"), "{tags}");
    assert!(
        tags.contains(r#"href="/alice/proj/releases/tag/v1.0">Release</a>"#),
        "{tags}"
    );

    // Deleting the release keeps the git tag on the tags page.
    let page = get_text(&alice, &c.s.url("/alice/proj/releases/tag/v1.0")).await;
    let csrf = extract_input(&page, "_csrf");
    let res = alice
        .post(c.s.url("/alice/proj/releases/delete/v1.0"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, "/alice/proj/releases");

    let tags = get_text(&alice, &c.s.url("/alice/proj/tags")).await;
    assert!(tags.contains("v1.0"), "the tag survives: {tags}");
    assert!(
        !tags.contains(r#"href="/alice/proj/releases/tag/v1.0">Release</a>"#),
        "the release link goes with the release: {tags}"
    );

    let res = alice
        .get(c.s.url("/alice/proj/releases/tag/v1.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_collaborator_cannot_create_a_release() {
    let c = start().await;
    let _bob = c.s.user("bob").await;
    c.s.core
        .set_collaborator(&c.alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let (bob, _) = c.s.login("bob").await;

    let page = get_text(&bob, &c.s.url("/alice/proj/releases")).await;
    assert!(
        !page.contains("/alice/proj/releases/new"),
        "a read-only collaborator must not see New release: {page}"
    );

    let form = get_text(&bob, &c.s.url("/alice/proj/releases/new")).await;
    let csrf = extract_input(&form, "_csrf");
    let res = bob
        .post(c.s.url("/alice/proj/releases/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("tag", "v2.0"),
            ("target", "main"),
            ("title", "reader release"),
            ("notes", "nope"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "creating a release needs write");
    assert!(
        c.s.core
            .release(Some(&c.alice), "alice", "proj", "v2.0")
            .await
            .is_err(),
        "a refused create writes no release"
    );
}
