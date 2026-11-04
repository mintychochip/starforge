//! D7: end-to-end server session ingest over HTTP, exactly as the CLI drives it.
//!
//! One `#[tokio::test]` walks the whole M1d wire: user + repo + a
//! `session:upload` PAT, metadata PUT, two segment PUTs (zstd bytes with
//! `X-Starforge-Blake3`), quarantine via the server re-scan, complete, a real
//! `git push` carrying a `Starforge-Session` trailer plus a CLI-style links
//! claim, admin queue listing, release, idempotent re-sync, a secret-leak
//! sweep, and purge. No stubbing: [`TestServer`] boots the real router.
mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

/// The session under test.
const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC0";

/// A realistic `ghp_` classic token (38 alphanumerics, over the 36 minimum
/// for `known-token`): what the CLI spool would carry before client-side
/// redaction. It travels only inside segment bytes; the leak sweep below
/// proves it never escapes into responses, rows, or audit entries.
const PLANTED_TOKEN: &str = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12";

/// PEM block tripping the `private-key` detector.
const PLANTED_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----";
fn meta_body() -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ULID,
        "agent": {"name": "pi", "version": "1.0"},
        "models": ["e2e-model"],
        "title": "e2e widget session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {},
        "parent_id": null,
        "usage": {},
        "files_touched": [],
        "redaction": {},
        "capture": {"mode": "discovery"},
    })
}

fn event(seq: u64, kind: &str, payload: Value) -> String {
    let mut line = json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": kind});
    for (k, v) in payload.as_object().unwrap() {
        line[k] = v.clone();
    }
    line.to_string()
}

/// Compresses JSONL `lines` (newline-joined plus trailing newline) and returns
/// the bytes with their BLAKE3 hex, exactly like the CLI spool upload.
fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}

/// `(sha, confidence, trailer_seen, claim_seen, session_id)` for every link
/// filed under `ulid`.
async fn link_rows(
    core: &starforged_core::Core,
    repo_id: i64,
) -> Vec<(String, String, i64, i64, Option<i64>)> {
    sqlx::query_as::<_, (String, String, i64, i64, Option<i64>)>(
        "SELECT sha, confidence, trailer_seen, claim_seen, session_id FROM commit_links \
         WHERE repo_id = $1 AND session_ulid = $2 ORDER BY sha",
    )
    .bind(repo_id)
    .bind(ULID)
    .fetch_all(core.db().pool())
    .await
    .unwrap()
}

/// The post-push scan runs in a spawned task after the push response, so poll.
async fn wait_for_link(core: &starforged_core::Core, repo_id: i64, sha: &str) {
    for _ in 0..200 {
        if link_rows(core, repo_id)
            .await
            .iter()
            .any(|row| row.0 == sha)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("link row for {ULID} {sha} never appeared");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_shaped_ingest_quarantine_links_release_purge() {
    assert!(
        PLANTED_TOKEN.len() - 4 >= 36,
        "planted token must trip known-token"
    );
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let upload = s.token(&alice, &[Scope::SessionUpload]).await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;
    let client = reqwest::Client::new();
    let meta_url = s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}"));
    let seg_url = |n: u64| {
        s.url(&format!(
            "/api/v1/repos/alice/proj/sessions/{ULID}/segments/{n}"
        ))
    };
    let complete_url = s.url(&format!(
        "/api/v1/repos/alice/proj/sessions/{ULID}/complete"
    ));
    let links_url = s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}/links"));
    let release_url = s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}/release"));
    let purge_url = s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}/purge"));
    let queue_url = s.url("/api/v1/repos/alice/proj/sessions?quarantined=true");

    // Every response body, for the leak sweep at the end.
    let mut bodies: Vec<String> = Vec::new();

    // 1. Metadata PUT, as the CLI sends it: 201 with quarantine "none".
    let created = client
        .put(&meta_url)
        .bearer_auth(&upload)
        .json(&meta_body())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let text = created.text().await.unwrap();
    bodies.push(text.clone());
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["ulid"], ULID);
    assert_eq!(body["quarantine"], "none");

    // 2. Segment 0: a clean turn (prompt, answer, tool call). Stored verbatim
    // on disk, refcounted once, session stays clean.
    let seg0 = vec![
        event(0, "user_message", json!({"text": "implement the widget"})),
        event(
            1,
            "assistant_message",
            json!({"text": "working on it", "model": "e2e-model"}),
        ),
        event(
            2,
            "tool_call",
            json!({"tool": {"name": "bash", "input": {}}}),
        ),
    ];
    let (bytes0, hash0) = segment_payload(&seg0);
    let put0 = client
        .put(seg_url(0))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash0)
        .body(bytes0.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put0.status(), 200);
    bodies.push(put0.text().await.unwrap());

    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .expect("session row");
    let session_id = session.id;
    assert_eq!(session.quarantine, "none");
    let segments = db_sessions::segments_of(s.core.db(), session_id)
        .await
        .unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].n, 0);
    assert_eq!(segments[0].blob_hash, hash0);
    assert_eq!(segments[0].byte_size, bytes0.len() as i64);
    // Blob bytes on disk equal the sent bytes.
    let blob_path = s
        .data
        .path()
        .join("data")
        .join("blobs")
        .join(&hash0[..2])
        .join(&hash0);
    assert_eq!(std::fs::read(&blob_path).unwrap(), bytes0);
    let blob_row = |hash: &str| {
        let pool = s.core.db().pool().clone();
        let owned = hash.to_owned();
        async move {
            sqlx::query_as::<_, (i64,)>("SELECT refcount FROM blobs WHERE hash = $1")
                .bind(owned.clone())
                .fetch_optional(&pool)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("missing blob row for {owned}"))
                .0
        }
    };
    assert_eq!(blob_row(&hash0).await, 1);

    // 3. Segment 1: the private-key block lands on line 1, so rule-priority
    // order attributes the quarantine to `private-key` even though line 2
    // also trips `known-token` with the planted ghp_ token.
    let seg1 = vec![
        event(
            3,
            "user_message",
            json!({"text": format!("key block:\n{PLANTED_KEY}\nrotated")}),
        ),
        event(
            4,
            "tool_result",
            json!({"result": {"output": format!("fetched credential {PLANTED_TOKEN} from env")}}),
        ),
    ];
    let (bytes1, hash1) = segment_payload(&seg1);
    let put1 = client
        .put(seg_url(1))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash1)
        .body(bytes1.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put1.status(), 200);
    bodies.push(put1.text().await.unwrap());

    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.quarantine, "quarantined");
    assert_eq!(session.quarantine_reason, "private-key");
    assert_eq!(session.quarantine_detail, "segment 1 line 1");
    // Quarantine is a state, never a rejection: the segment is stored.
    assert_eq!(
        db_sessions::segments_of(s.core.db(), session_id)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(blob_row(&hash1).await, 1);
    let audit: Vec<String> = starforged_db::audit::recent(s.core.db(), 100)
        .await
        .unwrap()
        .into_iter()
        .map(|row| format!("{} {} {}", row.action, row.target, row.detail))
        .collect();
    assert!(
        audit
            .iter()
            .any(|a| a.contains("session.quarantine") && a.contains(&format!("session:{ULID}"))),
        "{audit:?}"
    );

    // 4. Complete, as the CLI's final flush sends it.
    let done = client
        .post(&complete_url)
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    bodies.push(done.text().await.unwrap());

    // 5. A real push carrying the session trailer, then the CLI claim merges
    // into the same row.
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    commit_files(
        &work,
        &[("feature.txt", b"feature\n")],
        &format!("implement feature\n\nStarforge-Session: {ULID}\n"),
    )
    .await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "proj", Some(&write)),
            "main",
        ],
    )
    .await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    wait_for_link(&s.core, repo_id, &sha).await;
    assert_eq!(
        link_rows(&s.core, repo_id).await,
        vec![(sha.clone(), "heuristic".to_owned(), 1, 0, None)]
    );
    let claimed = client
        .post(&links_url)
        .bearer_auth(&upload)
        .json(
            &json!({"links": [{"sha": sha, "confidence": "exact", "seq_start": 0, "seq_end": 4}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(claimed.status(), 200);
    bodies.push(claimed.text().await.unwrap());
    assert_eq!(
        link_rows(&s.core, repo_id).await,
        vec![(sha.clone(), "exact".to_owned(), 1, 1, Some(session_id))]
    );

    // 6. The admin quarantine queue lists the session before release.
    let queued = client
        .get(&queue_url)
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(queued.status(), 200);
    let text = queued.text().await.unwrap();
    bodies.push(text.clone());
    let queued_body: Value = serde_json::from_str(&text).unwrap();
    let entry = queued_body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["ulid"] == ULID)
        .unwrap_or_else(|| panic!("session missing from queue: {queued_body}"))
        .clone();
    assert_eq!(entry["quarantine"], "quarantined");
    assert_eq!(entry["reason"], "private-key");

    // 7. Release clears the flag; the queue drops it.
    let released = client
        .post(&release_url)
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), 200);
    bodies.push(released.text().await.unwrap());
    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.quarantine, "released");
    let queued = client
        .get(&queue_url)
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(queued.status(), 200);
    let queued_body: Value = serde_json::from_str::<Value>(&queued.text().await.unwrap()).unwrap();
    assert!(
        !queued_body["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["ulid"] == ULID),
        "{queued_body}"
    );

    // 8. Re-uploading the identical segment is a 200 no-op: no new rows, no
    // refcount or verdict movement.
    let counts_before = db_sessions::segments_of(s.core.db(), session_id)
        .await
        .unwrap()
        .len();
    let redaction_before = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .unwrap()
        .redaction_counts;
    let retry = client
        .put(seg_url(1))
        .bearer_auth(&upload)
        .header("X-Starforge-Blake3", &hash1)
        .body(bytes1.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), 200);
    bodies.push(retry.text().await.unwrap());
    assert_eq!(
        db_sessions::segments_of(s.core.db(), session_id)
            .await
            .unwrap()
            .len(),
        counts_before
    );
    assert_eq!(blob_row(&hash1).await, 1);
    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.quarantine, "released");
    assert_eq!(session.redaction_counts, redaction_before);

    // 9. A second sync-equivalent — re-send everything recorded — changes
    // nothing: meta re-PUT, both segments, complete, and the same claim.
    let re_meta = client
        .put(&meta_url)
        .bearer_auth(&upload)
        .json(&meta_body())
        .send()
        .await
        .unwrap();
    assert_eq!(re_meta.status(), 200);
    bodies.push(re_meta.text().await.unwrap());
    for (n, bytes, hash) in [(0u64, &bytes0, &hash0), (1u64, &bytes1, &hash1)] {
        let redo = client
            .put(seg_url(n))
            .bearer_auth(&upload)
            .header("X-Starforge-Blake3", hash)
            .body(bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(redo.status(), 200);
        bodies.push(redo.text().await.unwrap());
    }
    let re_done = client
        .post(&complete_url)
        .bearer_auth(&upload)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(re_done.status(), 200);
    bodies.push(re_done.text().await.unwrap());
    let re_claim = client
        .post(&links_url)
        .bearer_auth(&upload)
        .json(
            &json!({"links": [{"sha": sha, "confidence": "exact", "seq_start": 0, "seq_end": 4}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(re_claim.status(), 200);
    bodies.push(re_claim.text().await.unwrap());
    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.lifecycle, "complete");
    assert_eq!(session.quarantine, "released");
    assert_eq!(
        db_sessions::segments_of(s.core.db(), session_id)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(blob_row(&hash0).await, 1);
    assert_eq!(blob_row(&hash1).await, 1);
    assert_eq!(link_rows(&s.core, repo_id).await.len(), 1);

    // 10. No response body, session/segment/link row, or audit row carries
    // the planted token. (The segment blobs on disk do — that is the stored
    // evidence quarantine exists to flag.)
    let mut haystacks = bodies;
    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
        .await
        .unwrap()
        .unwrap();
    haystacks.push(format!("{session:?}"));
    for segment in db_sessions::segments_of(s.core.db(), session_id)
        .await
        .unwrap()
    {
        haystacks.push(format!("{segment:?}"));
    }
    for link in db_sessions::links_of_session(s.core.db(), session_id)
        .await
        .unwrap()
    {
        haystacks.push(format!("{link:?}"));
    }
    for row in starforged_db::audit::recent(s.core.db(), 200)
        .await
        .unwrap()
    {
        haystacks.push(format!("{} {} {}", row.action, row.target, row.detail));
    }
    for hay in &haystacks {
        assert!(!hay.contains(PLANTED_TOKEN), "planted token leaked: {hay}");
    }

    // 11. Purge removes the session, its segment rows and links, and drops
    // both blob refcounts to zero; purging again is 404.
    let purged = client
        .post(&purge_url)
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(purged.status(), 204);
    assert!(
        db_sessions::session_by_ulid(s.core.db(), repo_id, ULID)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db_sessions::segments_of(s.core.db(), session_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db_sessions::links_of_session(s.core.db(), session_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(link_rows(&s.core, repo_id).await.len(), 0);
    assert_eq!(blob_row(&hash0).await, 0);
    assert_eq!(blob_row(&hash1).await, 0);
    let again = client
        .post(&purge_url)
        .bearer_auth(&upload)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 404);
}
