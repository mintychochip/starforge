//! API releases and archives (Phase 3): create → get → list → patch →
//! assets → delete round-trip, scope checks, draft visibility, and the
//! archive download. Real HTTP against an in-process server.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::Scope;

struct Ctx {
    s: TestServer,
    alice_full: String,
    alice_read_only: String,
    carol_read: String,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let carol = s.user("carol").await;
        s.core
            .create_user(CreateUser {
                handle: "bob".into(),
                password: Some(PASSWORD.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        s.core
            .create_repo(
                &alice,
                "alice",
                CreateRepo {
                    name: "proj".into(),
                    description: String::new(),
                    visibility: Visibility::Private,
                    readme: true,
                },
            )
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
            .await
            .unwrap();
        let full = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
        Ctx {
            alice_full: s.token(&alice, full).await,
            alice_read_only: s.token(&alice, &[Scope::RepoRead]).await,
            carol_read: s.token(&carol, full).await,
            s,
        }
    }

    fn url(&self, path: &str) -> String {
        self.s.url(path)
    }

    async fn post_json(&self, token: &str, path: &str, body: &Value) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .post(self.url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        (status, body)
    }

    async fn patch_json(&self, token: &str, path: &str, body: &Value) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .patch(self.url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        (status, body)
    }

    async fn get_json(&self, token: &str, path: &str) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        (status, body)
    }

    async fn delete_status(&self, token: &str, path: &str) -> u16 {
        let client = reqwest::Client::new();
        client
            .delete(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn put_asset(
        &self,
        token: &str,
        tag: &str,
        name: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> (u16, Value) {
        let client = reqwest::Client::new();
        let res = client
            .put(self.url(&format!(
                "/api/v1/repos/alice/proj/release-assets/{tag}/{name}"
            )))
            .bearer_auth(token)
            .header("content-type", content_type)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(json!({}));
        (status, body)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_download_and_release_round_trip() {
    let c = Ctx::start().await;
    let list_path = "/api/v1/repos/alice/proj/releases";
    let tag_path = "/api/v1/repos/alice/proj/releases/v1.0";

    // Archive: zip bytes with a valid token.
    let client = reqwest::Client::new();
    let res = client
        .get(c.url("/api/v1/repos/alice/proj/archive/main.zip"))
        .bearer_auth(&c.alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let content_type = res.headers().get("content-type").unwrap().to_owned();
    let disposition = res.headers().get("content-disposition").unwrap().to_owned();
    let bytes = res.bytes().await.unwrap();
    assert_eq!(content_type, "application/zip");
    assert!(bytes.len() >= 2 && &bytes[0..4] == b"PK\x03\x04");
    assert!(
        disposition.to_str().unwrap().contains("proj-main.zip"),
        "filename header: {disposition:?}"
    );

    // Archive: 404 without access (non-reader token).
    let res = client
        .get(c.url("/api/v1/repos/alice/proj/archive/main.zip"))
        .bearer_auth("no-such-token")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Alice owns proj (private); carol is a Read collaborator — she can
    // download the archive...
    let res = client
        .get(c.url("/api/v1/repos/alice/proj/archive/main.zip"))
        .bearer_auth(&c.carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // ...but a stranger (valid token, no repo access) gets 404 through
    // repo_for.
    let dave = c.s.user("dave").await;
    let stranger = c.s.token(&dave, &[Scope::RepoRead]).await;
    let res = client
        .get(c.url("/api/v1/repos/alice/proj/archive/main.zip"))
        .bearer_auth(&stranger)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Create a draft release for a new tag with target main.
    let (status, body) = c
        .post_json(
            &c.alice_full,
            list_path,
            &json!({
                "tag": "v1.0",
                "target": "main",
                "title": "First",
                "notes": "notes **here**",
                "draft": true,
                "prerelease": true,
            }),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["tag"], "v1.0");
    assert_eq!(body["title"], "First");
    assert_eq!(body["draft"], true);
    assert_eq!(body["prerelease"], true);
    assert!(!body["commit_id"].as_str().unwrap().is_empty());
    assert_eq!(body["author"], json!("alice"));
    assert!(body["published_at"].is_null());

    // GET returns the same release.
    let (status, got) = c.get_json(&c.alice_full, tag_path).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["id"], body["id"]);
    assert_eq!(got["notes"], "notes **here**");

    // List returns it.
    let (status, list) = c.get_json(&c.alice_full, list_path).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["releases"].as_array().unwrap().len(), 1);
    assert_eq!(list["releases"][0]["tag"], "v1.0");

    // Duplicate create is a conflict.
    let (status, _) = c
        .post_json(
            &c.alice_full,
            list_path,
            &json!({"tag": "v1.0", "target": "main", "title": "x", "notes": "", "draft": false, "prerelease": false}),
        )
        .await;
    assert_eq!(status, 409);

    // Draft hidden from a reader (carol is Read-only on the repo).
    let (status, _) = c.get_json(&c.carol_read, tag_path).await;
    assert_eq!(status, 404);
    let (status, list) = c.get_json(&c.carol_read, list_path).await;
    assert_eq!(status, 200);
    assert_eq!(list["releases"].as_array().unwrap().len(), 0);

    // PATCH title and publish the draft → published_at set.
    let (status, patched) = c
        .patch_json(
            &c.alice_full,
            tag_path,
            &json!({"title": "Renamed", "draft": false}),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["title"], "Renamed");
    assert_eq!(patched["draft"], false);
    assert!(patched["published_at"].is_string());

    // Now the reader can see it.
    let (status, _) = c.get_json(&c.carol_read, tag_path).await;
    assert_eq!(status, 200);

    // Upload an asset, download it byte-identical.
    let payload: Vec<u8> = (0u8..255).collect();
    let (status, asset) = c
        .put_asset(
            &c.alice_full,
            "v1.0",
            "blob.bin",
            "application/octet-stream",
            &payload,
        )
        .await;
    assert_eq!(status, 201, "{asset}");
    assert_eq!(asset["name"], "blob.bin");
    assert_eq!(asset["size"], payload.len() as u64);
    assert_eq!(asset["content_type"], "application/octet-stream");
    assert!(
        asset["download_url"]
            .as_str()
            .unwrap()
            .ends_with("/release-assets/v1.0/blob.bin"),
        "{asset}"
    );

    let client = reqwest::Client::new();
    let res = client
        .get(c.url("/api/v1/repos/alice/proj/release-assets/v1.0/blob.bin"))
        .bearer_auth(&c.carol_read)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("blob.bin")
    );
    assert_eq!(res.bytes().await.unwrap().to_vec(), payload);

    // Duplicate asset name is a conflict.
    let (status, _) = c
        .put_asset(&c.alice_full, "v1.0", "blob.bin", "text/plain", b"other")
        .await;
    assert_eq!(status, 409);

    // Read-only token cannot create (403).
    let (status, _) = c
        .post_json(
            &c.alice_read_only,
            list_path,
            &json!({"tag": "v2.0", "target": "main", "title": "", "notes": "", "draft": false, "prerelease": false}),
        )
        .await;
    assert_eq!(status, 403);

    // Delete the asset, then its GET is 404.
    let status = c
        .delete_status(
            &c.alice_full,
            "/api/v1/repos/alice/proj/release-assets/v1.0/blob.bin",
        )
        .await;
    assert_eq!(status, 204);
    let res = client
        .get(c.url("/api/v1/repos/alice/proj/release-assets/v1.0/blob.bin"))
        .bearer_auth(&c.alice_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Delete the release; it disappears from GET.
    let status = c.delete_status(&c.alice_full, tag_path).await;
    assert_eq!(status, 204);
    let (status, _) = c.get_json(&c.alice_full, tag_path).await;
    assert_eq!(status, 404);
}
