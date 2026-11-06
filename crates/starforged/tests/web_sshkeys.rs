//! SSH key and deploy key web tests: page round-trips, CSRF, escaping.
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use starforged_core::permission::{Permission, Visibility};

fn gen_key(dir: &Path, name: &str) -> (String, String) {
    let keypath = dir.join(name);
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&keypath)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
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
    let text = String::from_utf8_lossy(&out.stdout);
    (publine, text.split_whitespace().nth(1).unwrap().to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_keys_page_round_trip_csrf_and_escaping() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let dir = tempfile::tempdir().unwrap();
    let dirpath: PathBuf = dir.path().to_path_buf();
    let (publine, fp) = gen_key(&dirpath, "id1");

    let (client, csrf) = s.login("alice").await;
    let page = get_text(&client, &s.url("/settings/keys")).await;
    assert!(page.contains("SSH keys"));

    // Forged CSRF: 403 and no state change.
    let forged = client
        .post(s.url("/settings/keys"))
        .form(&[
            ("_csrf", "forged"),
            ("title", "x"),
            ("key", publine.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    assert!(
        s.core
            .ssh_keys(&s.core.user_by_handle("alice").await.unwrap().unwrap())
            .await
            .unwrap()
            .is_empty()
    );

    // Hostile title renders escaped.
    let added = client
        .post(s.url("/settings/keys"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "<script>alert(1)</script>"),
            ("key", publine.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let page = get_text(&client, &s.url("/settings/keys")).await;
    assert!(page.contains(fp.as_str()), "fingerprint missing");
    assert!(page.contains("&#60;script&#62;"), "title must be escaped");
    assert!(!page.contains("<script>alert(1)</script>"));

    // Extract the id and remove it.
    let alice = s.core.user_by_handle("alice").await.unwrap().unwrap();
    let keys = s.core.ssh_keys(&alice).await.unwrap();
    assert_eq!(keys.len(), 1);
    let removed = client
        .post(s.url(&format!("/settings/keys/{}/remove", keys[0].id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 303);
    assert!(s.core.ssh_keys(&alice).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deploy_keys_page_round_trip_csrf_and_permissions() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let dirpath: PathBuf = dir.path().to_path_buf();
    let (publine, fp) = gen_key(&dirpath, "deploy");

    let (bob_client, _bob_csrf) = s.login("bob").await;
    let denied = bob_client
        .get(s.url("/alice/proj/settings/keys"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    let (client, csrf) = s.login("alice").await;
    let page = get_text(&client, &s.url("/alice/proj/settings/keys")).await;
    assert!(page.contains("Deploy keys"));

    let forged = client
        .post(s.url("/alice/proj/settings/keys"))
        .form(&[
            ("_csrf", "forged"),
            ("title", "d"),
            ("key", publine.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    assert!(
        s.core
            .deploy_keys(&alice, "alice", "proj")
            .await
            .unwrap()
            .is_empty()
    );

    let added = client
        .post(s.url("/alice/proj/settings/keys"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "<b>ci</b>"),
            ("key", publine.as_str()),
            ("read_write", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let page = get_text(&client, &s.url("/alice/proj/settings/keys")).await;
    assert!(page.contains(fp.as_str()));
    assert!(page.contains("read-write"));
    assert!(page.contains("&#60;b&#62;ci&#60;/b&#62;"));

    let keys = s.core.deploy_keys(&alice, "alice", "proj").await.unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].read_write);
    let removed = client
        .post(s.url(&format!("/alice/proj/settings/keys/{}/remove", keys[0].id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 303);
    assert!(
        s.core
            .deploy_keys(&alice, "alice", "proj")
            .await
            .unwrap()
            .is_empty()
    );
}
