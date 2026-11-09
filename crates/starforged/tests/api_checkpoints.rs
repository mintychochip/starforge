//! Session checkpoint API: ref verification, metadata, privacy, and the
//! checkpoint ref policy.

mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "checkpoint session",
        "started_at": "2026-11-08T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 1, "output": 2, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": ["a.txt"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

async fn create_session(s: &TestServer, owner: &str, repo: &str, token: &str, ulid: &str) {
    let res = reqwest::Client::new()
        .put(s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}")))
        .bearer_auth(token)
        .json(&meta_body(ulid))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checkpoint_upload_list_and_verification() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s
        .token(&alice, &[Scope::RepoRead, Scope::SessionUpload])
        .await;
    create_session(&s, "alice", "proj", &upload, ULID).await;

    // A work commit whose objects are pushed as a checkpoint ref.
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let tree = git_ok(&work, &["rev-parse", "HEAD^{tree}"])
        .await
        .trim()
        .to_owned();
    let url = s.git_url("alice", "proj", Some(&upload));
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            &format!("{head}:refs/starforge/checkpoints/{ULID}/1"),
        ],
    )
    .await;

    let client = reqwest::Client::new();
    let put = |n: u64, body: Value| {
        client
            .put(s.url(&format!(
                "/api/v1/repos/alice/proj/sessions/{ULID}/checkpoints/{n}"
            )))
            .bearer_auth(&upload)
            .json(&body)
            .send()
    };
    let body = json!({
        "commit": head,
        "tree": tree,
        "parent": null,
        "label": "turn 1",
        "source": "manual",
        "created_at": 1_700_000_000,
    });
    let res = put(1, body.clone()).await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    let list: Value = client
        .get(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/checkpoints"
        )))
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["n"], 1);
    assert_eq!(list[0]["commit"], head);
    assert_eq!(list[0]["label"], "turn 1");

    let one: Value = client
        .get(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/checkpoints/1"
        )))
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(one["tree"], tree);

    // A tree that does not match the commit is refused.
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            &format!("{head}:refs/starforge/checkpoints/{ULID}/2"),
        ],
    )
    .await;
    let mut bad = body.clone();
    bad["tree"] = json!("1".repeat(40));
    let res = put(2, bad).await.unwrap();
    assert_eq!(res.status(), 409, "{}", res.text().await.unwrap());

    // A commit the ref does not point at is refused.
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            &format!("{head}:refs/starforge/checkpoints/{ULID}/3"),
        ],
    )
    .await;
    let mut bad = body;
    bad["commit"] = json!("2".repeat(40));
    let res = put(3, bad).await.unwrap();
    assert_eq!(res.status(), 409, "{}", res.text().await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checkpoint_ref_policy_and_public_privacy() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.repo(&alice, "pub", Visibility::Public).await;
    let upload = s
        .token(&alice, &[Scope::RepoRead, Scope::SessionUpload])
        .await;
    let read_only = s.token(&alice, &[Scope::RepoRead]).await;
    create_session(&s, "alice", "proj", &upload, ULID).await;

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let tree = git_ok(&work, &["rev-parse", "HEAD^{tree}"])
        .await
        .trim()
        .to_owned();

    // A read-only token cannot push a checkpoint ref.
    let read_url = s.git_url("alice", "proj", Some(&read_only));
    let out = git(
        &work,
        &[
            "push",
            &read_url,
            &format!("{head}:refs/starforge/checkpoints/{ULID}/1"),
        ],
    )
    .await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("checkpoint pushes need"), "{stderr}");

    // A malformed checkpoint ref is refused even with the upload scope.
    let upload_url = s.git_url("alice", "proj", Some(&upload));
    let out = git(
        &work,
        &[
            "push",
            &upload_url,
            &format!("{head}:refs/starforge/checkpoints/not-a-ulid/1"),
        ],
    )
    .await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("must be <ulid>/<n>"), "{stderr}");

    // On a public repository, checkpoint refs are refused entirely: every
    // reader could fetch an unpublished session's tree.
    create_session(&s, "alice", "pub", &upload, ULID).await;
    let pub_url = s.git_url("alice", "pub", Some(&upload));
    let out = git(
        &work,
        &[
            "push",
            &pub_url,
            &format!("{head}:refs/starforge/checkpoints/{ULID}/1"),
        ],
    )
    .await;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("checkpoints are not accepted on public repositories"),
        "{stderr}"
    );

    // The metadata route also refuses an unpublished session on a public
    // repository, before it looks for the ref.
    let res = reqwest::Client::new()
        .put(s.url(&format!(
            "/api/v1/repos/alice/pub/sessions/{ULID}/checkpoints/1"
        )))
        .bearer_auth(&upload)
        .json(&json!({"commit": head, "tree": tree}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "{}", res.text().await.unwrap());
    let text = res.text().await.unwrap();
    assert!(text.contains("publish the session"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_session_page_lists_checkpoints() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s
        .token(&alice, &[Scope::RepoRead, Scope::SessionUpload])
        .await;
    create_session(&s, "alice", "proj", &upload, ULID).await;
    let session = starforged_db::sessions::session_by_ulid(s.core.db(), repo.id, ULID)
        .await
        .unwrap()
        .unwrap();
    let commit = "a".repeat(40);
    let tree = "b".repeat(40);
    starforged_db::sessions::upsert_checkpoint(
        s.core.db(),
        repo.id,
        session.id,
        1,
        &commit,
        &tree,
        None,
        "turn 1",
        "manual",
        starforged_db::now(),
    )
    .await
    .unwrap();

    let (browser, _csrf) = s.login("alice").await;
    let page = get_text(&browser, &s.url(&format!("/alice/proj/sessions/{ULID}"))).await;
    assert!(page.contains("Checkpoints (1)"), "{page}");
    assert!(page.contains("turn 1"), "{page}");
    assert!(page.contains("starforge rewind"), "{page}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantined_session_refuses_checkpoint_metadata() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s
        .token(&alice, &[Scope::RepoRead, Scope::SessionUpload])
        .await;
    create_session(&s, "alice", "proj", &upload, ULID).await;
    let session = starforged_db::sessions::session_by_ulid(s.core.db(), repo.id, ULID)
        .await
        .unwrap()
        .unwrap();
    starforged_db::sessions::set_quarantine(
        s.core.db(),
        session.id,
        "quarantined",
        "secret",
        "rule xyz",
    )
    .await
    .unwrap();
    let res = reqwest::Client::new()
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/checkpoints/1"
        )))
        .bearer_auth(&upload)
        .json(&json!({"commit": "a".repeat(40), "tree": "b".repeat(40)}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422, "{}", res.text().await.unwrap());
    let text = res.text().await.unwrap();
    assert!(text.contains("quarantined"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_session_removes_its_checkpoint_refs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s
        .token(&alice, &[Scope::RepoRead, Scope::SessionUpload])
        .await;
    create_session(&s, "alice", "proj", &upload, ULID).await;

    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    let tree = git_ok(&work, &["rev-parse", "HEAD^{tree}"])
        .await
        .trim()
        .to_owned();
    let url = s.git_url("alice", "proj", Some(&upload));
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &url,
            &format!("{head}:refs/starforge/checkpoints/{ULID}/1"),
        ],
    )
    .await;
    let res = reqwest::Client::new()
        .put(s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/checkpoints/1"
        )))
        .bearer_auth(&upload)
        .json(&json!({"commit": head, "tree": tree}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    let res = reqwest::Client::new()
        .delete(s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}")))
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());

    let server = s.core.repo_path(repo.id);
    let gd = format!("--git-dir={}", server.display());
    let ref_name = format!("refs/starforge/checkpoints/{ULID}/1");
    let out = git(&work, &[&gd, "rev-parse", "--verify", &ref_name]).await;
    assert!(
        !out.status.success(),
        "checkpoint ref survived session delete"
    );
}
