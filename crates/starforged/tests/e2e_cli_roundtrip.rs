//! M1 closeout: real `starforge-cli` ingest + sync against the real server.
//!
//! Unlike `e2e_sessions.rs` (which hand-builds the wire with `reqwest`), this
//! test moves real bytes with real CLI code: a fixture Pi JSONL session is
//! ingested with [`starforge_cli::ingest::ingest`] and uploaded with
//! [`starforge_cli::commands::sync::sync`] against the in-process
//! [`TestServer`]. It proves the CLI's spool/redaction/upload path speaks the
//! same contract the server enforces.
//!
//! The fixture plants one `ghp_…` token twice: once in a user message (the
//! CLI redacts it out of the stored segment bytes) and once in an `Edit`
//! `file_path` (the CLI redacts it client-side before the spool, so the
//! server-side meta-scan holds no token and quarantines nothing).
mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::TestServer;
use starforge_capture::Roots;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

/// A realistic `ghp_` classic token (38 alphanumerics, over the 36 minimum
/// for `known-token`).
const PLANTED_TOKEN: &str = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12";

/// [`starforge_cli::queue::Sleeper`] that never sleeps: the happy path issues
/// no retries, so no sleeping is needed.
struct NoSleep;

impl starforge_cli::queue::Sleeper for NoSleep {
    async fn sleep(&self, _dur: Duration) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_cli_ingest_sync_round_trip() {
    assert!(
        PLANTED_TOKEN.len() - 4 >= 36,
        "planted token must trip known-token"
    );
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let repo_id = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap()
        .repo
        .id;

    // Temp `STARFORGE_HOME`-equivalent layout: the worktree doubles as the
    // ingest repo root, `data/.pi/agent/sessions/--x--` is the Pi store.
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let data = tmp.path().join("data");
    let config = tmp.path().join("config");
    let spool_parent = tmp.path().join("spool");
    for dir in [&work, &data, &config, &spool_parent] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::create_dir_all(data.join(".pi/agent/sessions/--x--")).unwrap();

    let work_str = work.to_string_lossy().into_owned();
    // Spaces delimit the token from the path: the high-entropy alphabet
    // includes `/ . _ = + -`, so a glued token loses the overlap to the
    // low-confidence detector and the client-side redaction would miss it.
    let file_with_token = format!("{work_str}/notes {PLANTED_TOKEN} rotated.md");
    let records = [
        serde_json::json!({
            "type": "session",
            "version": 3,
            "id": "roundtrip-1",
            "timestamp": "2026-09-01T12:00:00Z",
            "cwd": work_str,
            "runtime": { "version": "0.5.2" },
        }),
        serde_json::json!({
            "type": "message",
            "id": "m1",
            "parentId": null,
            "timestamp": "2026-09-01T12:00:00Z",
            "runtime": { "version": "0.5.2" },
            "message": {
                "role": "user",
                "content": [{ "type": "text", "text": format!("deploy failed; the rotated credential {PLANTED_TOKEN} from env did not help") }],
            },
        }),
        serde_json::json!({
            "type": "message",
            "id": "m2",
            "parentId": "m1",
            "timestamp": "2026-09-01T12:01:00Z",
            "runtime": { "version": "0.5.2" },
            "message": {
                "role": "assistant",
                "model": "pi-model-x",
                "provider": "anthropic",
                "usage": {"input": 10, "output": 20, "cacheRead": 0, "cacheWrite": 0},
                "content": [{ "type": "text", "text": "rotating it now" }],
            },
        }),
        serde_json::json!({
            "type": "message",
            "id": "m3",
            "parentId": "m2",
            "timestamp": "2026-09-01T12:02:00Z",
            "runtime": { "version": "0.5.2" },
            "message": {
                "role": "assistant",
                "model": "pi-model-x",
                "provider": "anthropic",
                "usage": {"input": 11, "output": 21, "cacheRead": 0, "cacheWrite": 0},
                "content": [{ "type": "toolCall", "id": "tool-1", "name": "Edit", "arguments": {"file_path": file_with_token, "edits": 1} }],
            },
        }),
    ];
    let native = records
        .iter()
        .map(|record| serde_json::to_string(record).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(
        data.join(".pi/agent/sessions/--x--/roundtrip.jsonl"),
        &native,
    )
    .unwrap();

    // Real CLI ingest: discover → redact → spool. September timestamps are
    // older than the 24 h idle rule, so the session is also marked ended and
    // the sync below exercises the complete path.
    let roots = std::collections::BTreeMap::from([(
        "pi".to_string(),
        Roots {
            config_dir: config,
            data_dir: data,
            worktree: work.clone(),
        },
    )]);
    let spool = starforge_cli::spool::Spool::open(&spool_parent);
    spool.ensure_layout().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let stats = starforge_cli::ingest::ingest(&spool, &roots, &work, now).unwrap();
    assert_eq!(stats.new_events, 3, "fixture must yield 3 events");
    assert_eq!(stats.new_segments, 1, "fixture must fit one segment");

    let sessions_dir = spool_parent.join("starforge").join("sessions");
    let mut ulids: Vec<String> = std::fs::read_dir(&sessions_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(ulids.len(), 1, "ingest must spool exactly one session");
    let ulid = ulids.pop().unwrap();
    let meta = spool.read_meta(&ulid).unwrap();
    assert!(
        meta.ended_at.is_some(),
        "idle rule must mark the session ended"
    );
    assert!(
        meta.redaction
            .counts
            .get("known-token")
            .copied()
            .unwrap_or(0)
            >= 2,
        "client counts must record the planted token: {:?}",
        meta.redaction.counts
    );

    // Real CLI sync: the narrowest public seam that moves bytes is
    // `commands::sync::sync` itself (no CLI paths are hard-wired: server,
    // owner/repo, and token are all injected).
    let server = starforge_cli::discovery::ServerInfo {
        api_url: s.base.clone(),
        ssh_url: "ssh://git@example.test:2222".to_string(),
        version: "test".to_string(),
    };
    let now_str = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let summary = starforge_cli::commands::sync::sync(
        &spool,
        &server,
        "alice/proj",
        &token,
        &NoSleep,
        &now_str,
        false,
    )
    .await
    .unwrap();
    assert_eq!(summary.exit_code(), 0, "sync must drain");
    assert_eq!(summary.uploaded, 3, "meta + segment + complete expected");
    assert!(
        starforge_cli::queue::read_queue(&spool).unwrap().is_empty(),
        "queue must drain"
    );

    // The server has the session row under the ULID the spool recorded.
    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, &ulid)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.lifecycle, "complete");
    // The token was redacted client-side before upload, so the server
    // meta-scan finds nothing and quarantines nothing.
    assert_eq!(session.quarantine, "none");
    assert_eq!(session.quarantine_reason, "");
    assert_eq!(session.quarantine_detail, "");
    // Stored files_touched carries no token (the client redacts first).
    assert!(
        !session.files_touched.contains(PLANTED_TOKEN),
        "stored files_touched must not hold the raw token: {}",
        session.files_touched
    );
    assert!(
        session.files_touched.contains("[redacted:known-token]"),
        "stored files_touched must hold the redaction marker: {}",
        session.files_touched
    );

    // Every segment row's hash equals the spool's `upload.json` hash.
    let segments = db_sessions::segments_of(s.core.db(), session.id)
        .await
        .unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].n, 0);
    let upload = spool.read_upload(&ulid).unwrap();
    assert_eq!(
        upload.uploaded_segments.get(&0),
        Some(&segments[0].blob_hash)
    );
    assert!(upload.meta_hash.is_some());
    assert!(upload.complete);

    // The uploaded segment decompresses to the same events the spool holds.
    let spool_bytes = spool.segment_bytes(&ulid, 0).unwrap();
    let server_bytes = s
        .core
        .config()
        .blob_store
        .get_by_hash(&segments[0].blob_hash)
        .await
        .unwrap();
    assert_eq!(
        spool_bytes, server_bytes,
        "server must store exact spool bytes"
    );
    let text = String::from_utf8(starforge_format::decompress(&server_bytes).unwrap()).unwrap();
    let spool_text =
        String::from_utf8(starforge_format::decompress(&spool_bytes).unwrap()).unwrap();
    assert_eq!(text, spool_text);
    assert_eq!(text.lines().count(), 3, "all events must survive");
    assert!(
        text.contains("[redacted:known-token]"),
        "segment must carry the redaction marker"
    );

    // The planted token never reaches the server's stored bytes: neither the
    // segment blob nor the stored (server-redacted) metadata strings.
    assert!(
        !server_bytes
            .windows(PLANTED_TOKEN.len())
            .any(|window| window == PLANTED_TOKEN.as_bytes()),
        "raw token must not be in the stored blob"
    );
    assert!(!text.contains(PLANTED_TOKEN));
    assert!(
        !session.files_touched.contains(PLANTED_TOKEN),
        "stored files_touched must hold the redacted value"
    );
    assert!(
        session.files_touched.contains("[redacted:known-token]"),
        "stored files_touched must hold the redacted value: {}",
        session.files_touched
    );
    let stored_counts: BTreeMap<String, u64> =
        serde_json::from_str(&session.redaction_counts).unwrap();
    assert!(
        stored_counts.get("known-token").copied().unwrap_or(0) >= 1,
        "server counts must preserve the evidence: {}",
        session.redaction_counts
    );

    // A second sync issues no new requests: nothing re-uploads, no new
    // segment rows, no new audit rows.
    let audits_before = starforged_db::audit::recent(s.core.db(), 100)
        .await
        .unwrap()
        .len();
    let segments_before = db_sessions::segments_of(s.core.db(), session.id)
        .await
        .unwrap()
        .len();
    let upload_before = spool.read_upload(&ulid).unwrap();
    let second = starforge_cli::commands::sync::sync(
        &spool,
        &server,
        "alice/proj",
        &token,
        &NoSleep,
        &now_str,
        false,
    )
    .await
    .unwrap();
    assert_eq!(second.uploaded, 0, "nothing left to upload");
    assert_eq!(second.exit_code(), 0);
    assert_eq!(spool.read_upload(&ulid).unwrap(), upload_before);
    assert_eq!(
        db_sessions::segments_of(s.core.db(), session.id)
            .await
            .unwrap()
            .len(),
        segments_before
    );
    assert_eq!(
        starforged_db::audit::recent(s.core.db(), 100)
            .await
            .unwrap()
            .len(),
        audits_before
    );
}
