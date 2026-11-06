//! SSH key and deploy key API tests (D2–D4). Real `ssh-keygen` keys in temp
//! dirs; fingerprints compared with `ssh-keygen -lf -E sha256`.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

/// Generates a key of `kind` in `dir/<name>`; returns `(publine, fingerprint)`.
fn gen_key(dir: &Path, name: &str, kind: &str, bits: Option<&str>) -> (String, String) {
    let keypath = dir.join(name);
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(["-q", "-t", kind, "-N", ""]);
    if let Some(bits) = bits {
        cmd.args(["-b", bits]);
    }
    cmd.args(["-f"]);
    cmd.arg(&keypath);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "ssh-keygen: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let publine = std::fs::read_to_string(keypath.with_extension("pub"))
        .unwrap()
        .trim()
        .to_owned();
    let out = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(&keypath)
        .arg("-E")
        .arg("sha256")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let fingerprint = text.split_whitespace().nth(1).unwrap().to_owned();
    (publine, fingerprint)
}

fn keydir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

async fn api(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => unreachable!(),
    };
    let resp = req
        .bearer_auth(token)
        .json(&body.unwrap_or(json!({})))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    let value = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_keys_round_trip_and_duplicate_is_422() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let dir = keydir();
    let dirpath: PathBuf = dir.path().to_path_buf();
    let (publine, fingerprint) = gen_key(&dirpath, "id_ed", "ed25519", None);
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let (status, body) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/user/keys"),
        &token,
        Some(json!({ "title": "laptop", "key": publine })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["fingerprint"], fingerprint);
    assert_eq!(body["title"], "laptop");

    let (status, body) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/user/keys"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);

    // Another user cannot remove alice's key (404), and a duplicate is 422.
    let bob_token = s.token(&bob, &[Scope::RepoRead]).await;
    let id = body["keys"][0]["id"].as_i64().unwrap();
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/user/keys/{id}")),
        &bob_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/user/keys"),
        &bob_token,
        Some(json!({ "title": "copy", "key": publine })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Owner removes it; list empties.
    let (status, _) = api(
        &s.browser(),
        "DELETE",
        &s.url(&format!("/api/v1/user/keys/{id}")),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/user/keys"),
        &token,
        None,
    )
    .await;
    assert!(body["keys"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parser_rejects_and_key_types_parse() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let dir = keydir();
    let dirpath: PathBuf = dir.path().to_path_buf();

    // ed25519, ecdsa-256, rsa-3072 parse; fingerprint matches ssh-keygen.
    for (name, kind, bits) in [
        ("id1", "ed25519", None),
        ("id2", "ecdsa", Some("-P256")),
        ("id3", "rsa", Some("3072")),
    ] {
        let (publine, fp) = match bits {
            Some("-P256") => {
                // `-b` is not used for ecdsa; curve via -P.
                let keypath = dirpath.join(name);
                let out = Command::new("ssh-keygen")
                    .args(["-q", "-t", "ecdsa", "-P256", "-N", "", "-f"])
                    .arg(&keypath)
                    .output()
                    .unwrap();
                assert!(out.status.success());
                let publine = std::fs::read_to_string(keypath.with_extension("pub"))
                    .unwrap()
                    .trim()
                    .to_owned();
                let out = Command::new("ssh-keygen")
                    .args(["-lf"])
                    .arg(&keypath)
                    .arg("-E")
                    .arg("sha256")
                    .output()
                    .unwrap();
                let text = String::from_utf8_lossy(&out.stdout);
                (publine, text.split_whitespace().nth(1).unwrap().to_owned())
            }
            Some(b) => gen_key(&dirpath, name, kind, Some(b)),
            None => gen_key(&dirpath, name, kind, None),
        };
        let (status, body) = api(
            &s.browser(),
            "POST",
            &s.url("/api/v1/user/keys"),
            &token,
            Some(json!({ "title": name, "key": publine })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "key {name}: {body}");
        assert_eq!(body["fingerprint"], fp);
        let id = body["id"].as_i64().unwrap();
        let (status, _) = api(
            &s.browser(),
            "DELETE",
            &s.url(&format!("/api/v1/user/keys/{id}")),
            &token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    // rsa-1024 refused.
    let (publine, _) = gen_key(&dirpath, "weak", "rsa", Some("1024"));
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/user/keys"),
        &token,
        Some(json!({ "title": "weak", "key": publine })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Garbage, options prefix, mismatched blob refused.
    let (good, _) = gen_key(&dirpath, "good", "ed25519", None);
    for bad in ["garbage".to_owned(), format!("restrict {good}"), {
        let mut parts = good.split_whitespace();
        let _algo = parts.next().unwrap();
        let b64 = parts.next().unwrap();
        // Flip the algorithm prefix while keeping the blob.
        format!("ssh-rsa {b64}")
    }] {
        let (status, _) = api(
            &s.browser(),
            "POST",
            &s.url("/api/v1/user/keys"),
            &token,
            Some(json!({ "title": "bad", "key": bad })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deploy_keys_admin_only_archived_refused_and_audited() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let mia = s.user("mia").await;
    s.user("outsider").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    // mia is a maintainer: enough to read/push, not to manage keys.
    s.core
        .set_collaborator(
            &alice,
            "alice",
            "proj",
            "mia",
            starforged_core::permission::Permission::Maintain,
        )
        .await
        .unwrap();

    let dir = keydir();
    let dirpath: PathBuf = dir.path().to_path_buf();
    let (publine, fp) = gen_key(&dirpath, "deploy", "ed25519", None);
    let alice_token = s.token(&alice, &[Scope::RepoWrite]).await;
    let mia_token = s.token(&mia, &[Scope::RepoWrite]).await;

    // Maintainer gets 403 on list/create; anon outsider (valid token, no repo access) gets 404.
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/keys"),
        &mia_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/keys"),
        &mia_token,
        Some(json!({ "title": "d", "key": publine, "read_write": false })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let outsider = s.core.user_by_handle("outsider").await.unwrap().unwrap();
    let outsider_token = s.token(&outsider, &[Scope::RepoWrite]).await;
    let (status, _) = api(
        &s.browser(),
        "GET",
        &s.url("/api/v1/repos/alice/proj/keys"),
        &outsider_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Admin adds a read key and a read-write key.
    let (status, body) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/keys"),
        &alice_token,
        Some(json!({ "title": "ro", "key": publine, "read_write": false })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["fingerprint"], fp);
    assert_eq!(body["read_write"], false);
    let ro_id = body["id"].as_i64().unwrap();

    let (publine2, _) = gen_key(&dirpath, "deploy2", "ed25519", None);
    let (status, body) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/keys"),
        &alice_token,
        Some(json!({ "title": "rw", "key": publine2, "read_write": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["read_write"], true);
    let rw_id = body["id"].as_i64().unwrap();

    // Duplicate of a deploy key as a user key is 422.
    let ro_token = s.token(&alice, &[Scope::RepoRead]).await;
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/user/keys"),
        &ro_token,
        Some(json!({ "title": "copy", "key": publine })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Archive: adds refused.
    s.core.archive_repo(&alice, "alice", "proj").await.unwrap();
    let (publine3, _) = gen_key(&dirpath, "deploy3", "ed25519", None);
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/keys"),
        &alice_token,
        Some(json!({ "title": "late", "key": publine3, "read_write": false })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    s.core
        .unarchive_repo(&alice, "alice", "proj")
        .await
        .unwrap();

    // Remove both; list empties.
    for id in [ro_id, rw_id] {
        let (status, _) = api(
            &s.browser(),
            "DELETE",
            &s.url(&format!("/api/v1/repos/alice/proj/keys/{id}")),
            &alice_token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    // Audit: exactly one add and one remove row per key.
    let rows = starforged_db::audit::recent(s.core.db(), 50).await.unwrap();
    for action in ["deploy_key.add", "deploy_key.remove"] {
        let count = rows.iter().filter(|r| r.action == action).count();
        assert_eq!(count, 2, "{action}: {rows:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_key_cap_holds() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    // Fill the cap through Core to keep the test fast; one more via API is 422.
    let dir = keydir();
    let dirpath: PathBuf = dir.path().to_path_buf();
    let (publine, _) = gen_key(&dirpath, "seed", "ed25519", None);
    // Use distinct keys: mutate the comment so each key differs? The blob must
    // differ; generate 100 ed25519 keys is heavy, so insert via Core with the
    // same helper in a loop of generated keys.
    for i in 0..100 {
        let (line, _) = gen_key(&dirpath, &format!("k{i}"), "ed25519", None);
        s.core
            .add_ssh_key(&alice, &format!("k{i}"), &line)
            .await
            .unwrap();
    }
    let (status, _) = api(
        &s.browser(),
        "POST",
        &s.url("/api/v1/user/keys"),
        &token,
        Some(json!({ "title": "over", "key": publine })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
