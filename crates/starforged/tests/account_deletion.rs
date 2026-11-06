//! Task V3: account deletion removes the user's uploaded sessions through
//! the session-delete path (D4) — blob refcounts, commit links, and search
//! index documents go with them — and the sole-owner rule keeps an org from
//! losing its last owner, atomically (a concurrent owner removal and an
//! account deletion cannot both succeed).
mod common;

use common::TestServer;
use serde_json::{Value, json};
use starforged_core::CoreError;
use starforged_core::account::AccountDeleteHook;
use starforged_core::ingest::IngestAuth;
use starforged_core::orgs::{NewOrgInput, OrgRole};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_index::{EventQuery, Scope as IndexScope};

const ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA1";
const ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA2";

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "account deletion fixture",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 1, "output": 2, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

/// Uploads one completed session with a single user message carrying `text`;
/// returns the stored blob hash. `owner` is the repository owner; alice
/// (the deleting account) uploads as a write collaborator.
async fn upload_completed(
    server: &TestServer,
    owner: &str,
    repo: &str,
    ulid: &str,
    text: &str,
) -> String {
    let alice = server.core.user_by_handle("alice").await.unwrap().unwrap();
    let secret = server.token(&alice, &[Scope::SessionUpload]).await;
    let token = server.core.authenticate_token(&secret).await.unwrap();
    let auth: IngestAuth = server
        .core
        .authorize_upload(&token, owner, repo)
        .await
        .unwrap();
    server
        .core
        .upsert_session_meta(&auth, ulid, &meta_body(ulid))
        .await
        .unwrap();
    let line = serde_json::json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z", "kind": "user_message", "text": text}).to_string();
    let bytes = starforge_format::compress(format!("{line}\n").as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    server
        .core
        .put_segment(&auth, ulid, 0, &bytes, Some(hash.clone()))
        .await
        .unwrap();
    server.core.complete_session(&auth, ulid).await.unwrap();
    hash
}

/// Bob owns two public repositories and grants alice write on both, so alice
/// can upload to them while owning no repositories herself (the deletion
/// rule requires owned repositories to be deleted first).
async fn two_repos_with_alice_write(
    server: &TestServer,
) -> (starforged_core::repos::Repo, starforged_core::repos::Repo) {
    let bob = server.user("bob").await;
    let one = server.repo(&bob, "one", Visibility::Public).await;
    let two = server.repo(&bob, "two", Visibility::Public).await;
    for name in ["one", "two"] {
        server
            .core
            .set_collaborator(
                &bob,
                "bob",
                name,
                "alice",
                starforged_core::permission::Permission::Write,
            )
            .await
            .unwrap();
    }
    (one, two)
}

fn scope_for(repo_id: i64, viewer: i64) -> IndexScope {
    IndexScope {
        signed_in: true,
        readable: vec![repo_id],
        member: vec![repo_id],
        admin: vec![repo_id],
        viewer_id: Some(viewer),
    }
}

fn event_hits(server: &TestServer, q: &str, scope: &IndexScope) -> Vec<starforged_index::EventHit> {
    server
        .core
        .search_index()
        .search_events(
            &EventQuery {
                q: q.to_owned(),
                ..Default::default()
            },
            scope,
            0,
            20,
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_deletion_removes_sessions_blobs_and_index_docs() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (one, two) = two_repos_with_alice_write(&s).await;
    let hash_a = upload_completed(&s, "bob", "one", ULID_A, "plumbline").await;
    let hash_b = upload_completed(&s, "bob", "two", ULID_B, "timetable").await;
    s.core.run_due_jobs().await.unwrap();
    assert_eq!(
        event_hits(&s, "plumbline", &scope_for(one.id, alice.id)).len(),
        1,
        "session A indexed"
    );
    assert_eq!(
        event_hits(&s, "timetable", &scope_for(two.id, alice.id)).len(),
        1,
        "session B indexed"
    );
    let blob_dir = s.core.config().blob_dir.clone();
    for hash in [&hash_a, &hash_b] {
        let blob = starforged_db::sessions::blob_by_hash(s.db(), hash)
            .await
            .unwrap()
            .expect("blob row before deletion");
        assert_eq!(blob.refcount, 1);
        assert!(starforged_blob::blob_file_path(&blob_dir, hash).exists());
    }

    s.core.delete_account(&alice, "alice").await.unwrap();

    assert!(
        s.core.user_by_handle("alice").await.unwrap().is_none(),
        "account gone"
    );
    assert!(
        starforged_db::sessions::sessions_uploaded_by(s.db(), alice.id, 100)
            .await
            .unwrap()
            .is_empty(),
        "uploaded sessions gone"
    );
    for hash in [&hash_a, &hash_b] {
        let blob = starforged_db::sessions::blob_by_hash(s.db(), hash)
            .await
            .unwrap()
            .expect("blob row before the GC sweep");
        assert_eq!(blob.refcount, 0, "refcount decremented");
    }
    // No orphan commit links for the removed sessions.
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM commit_links")
        .fetch_one(s.db().pool())
        .await
        .unwrap();
    assert_eq!(links, 0);
    // The hourly GC removes the zero-ref rows and files.
    s.core
        .enqueue(&starforged_core::jobs::Job::HourlyCleanup)
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();
    for hash in [&hash_a, &hash_b] {
        assert!(
            starforged_db::sessions::blob_by_hash(s.db(), hash)
                .await
                .unwrap()
                .is_none(),
            "zero-ref blob row swept"
        );
        assert!(!starforged_blob::blob_file_path(&blob_dir, hash).exists());
    }
    // The index has no documents for the deleted sessions.
    assert!(
        event_hits(&s, "plumbline", &IndexScope::default()).is_empty(),
        "session A docs dropped"
    );
    assert!(
        event_hits(&s, "timetable", &IndexScope::default()).is_empty(),
        "session B docs dropped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_account_deletion_completes_on_rerun() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    two_repos_with_alice_write(&s).await;
    let _ = upload_completed(&s, "bob", "one", ULID_A, "plumbline").await;
    let _ = upload_completed(&s, "bob", "two", ULID_B, "timetable").await;
    s.core.run_due_jobs().await.unwrap();

    // Fail the deletion after the first session removal.
    s.core
        .set_account_delete_hook(Some(AccountDeleteHook::new(|| {
            Err(CoreError::Internal("boom".into()))
        })));
    let interrupted = s.core.delete_account(&alice, "alice").await;
    assert!(interrupted.is_err(), "deletion aborted: {interrupted:?}");
    assert!(
        s.core.user_by_handle("alice").await.unwrap().is_some(),
        "account survives the interruption"
    );
    let remaining = starforged_db::sessions::sessions_uploaded_by(s.db(), alice.id, 100)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1, "first session removed, second remains");

    s.core.set_account_delete_hook(None);
    s.core.delete_account(&alice, "alice").await.unwrap();
    assert!(s.core.user_by_handle("alice").await.unwrap().is_none());
    assert!(
        starforged_db::sessions::sessions_uploaded_by(s.db(), alice.id, 100)
            .await
            .unwrap()
            .is_empty(),
        "rerun finishes the job"
    );
    s.core
        .enqueue(&starforged_core::jobs::Job::HourlyCleanup)
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();
    assert!(
        starforged_db::sessions::zero_ref_blobs(s.db(), 100)
            .await
            .unwrap()
            .is_empty(),
        "no zero-ref blobs left"
    );
    assert!(
        event_hits(&s, "plumbline", &IndexScope::default()).is_empty()
            && event_hits(&s, "timetable", &IndexScope::default()).is_empty(),
        "index docs dropped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sole_owner_account_deletion_is_refused_and_org_keeps_an_owner() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.core
        .create_org(
            &alice,
            NewOrgInput {
                handle: "acme".into(),
                display_name: String::new(),
                description: String::new(),
            },
        )
        .await
        .unwrap();

    let refused = s.core.delete_account(&alice, "alice").await;
    assert!(
        matches!(&refused, Err(CoreError::Invalid(m)) if m.contains("acme")),
        "{refused:?}"
    );
    assert!(s.core.user_by_handle("alice").await.unwrap().is_some());
    let members = s.core.org_members(&alice, "acme").await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].handle, "alice");

    // With a second owner, the account (and its membership) goes cleanly.
    let bob = s.user("bob").await;
    s.core
        .set_org_member(&alice, "acme", "bob", OrgRole::Owner)
        .await
        .unwrap();
    s.core.delete_account(&alice, "alice").await.unwrap();
    assert!(s.core.user_by_handle("alice").await.unwrap().is_none());
    let members = s.core.org_members(&bob, "acme").await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(
        (members[0].handle.as_str(), members[0].role),
        ("bob", OrgRole::Owner)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_removal_and_account_deletion_race_keeps_an_owner() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.core
        .create_org(
            &alice,
            NewOrgInput {
                handle: "acme".into(),
                display_name: String::new(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    s.core
        .set_org_member(&alice, "acme", "bob", OrgRole::Owner)
        .await
        .unwrap();

    // Race: alice deletes her account while alice removes bob (the other
    // owner). Serialized per org: exactly one may succeed, and the org must
    // keep at least one owner.
    let core_a = s.core.clone();
    let alice_a = alice.clone();
    let core_b = s.core.clone();
    let alice_b = alice.clone();
    let (deleted, removed) = tokio::join!(
        async move { core_a.delete_account(&alice_a, "alice").await },
        async move { core_b.remove_org_member(&alice_b, "acme", "bob").await },
    );
    assert_ne!(
        deleted.is_ok(),
        removed.is_ok(),
        "exactly one wins: deleted={deleted:?} removed={removed:?}"
    );
    // The org always has an owner.
    let row = starforged_db::orgs::by_handle(s.db(), "acme")
        .await
        .unwrap()
        .expect("org survives");
    let owners: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner'")
            .bind(row.id)
            .fetch_one(s.db().pool())
            .await
            .unwrap();
    assert_eq!(owners, 1, "org keeps exactly one owner");
    if deleted.is_ok() {
        assert!(s.core.user_by_handle("alice").await.unwrap().is_none());
        let members = s.core.org_members(&bob, "acme").await.unwrap();
        assert_eq!((members.len(), members[0].handle.as_str()), (1, "bob"));
    } else {
        assert!(s.core.user_by_handle("alice").await.unwrap().is_some());
        let members = s.core.org_members(&alice, "acme").await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].handle, "alice");
    }
}
