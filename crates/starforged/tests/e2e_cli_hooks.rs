//! Post-release regression: hooks upload commit claims without an explicit
//! `starforge sync`.
//!
//! The real CLI hook handlers (`hook_prepare` / `hook_post_commit` /
//! `hook_pre_push_full`) run against a temp git work repo whose `origin` is
//! the TestServer repo URL and a Pi native session under a temp
//! `STARFORGE_HOME`-equivalent home. NO `sync` call happens anywhere: after
//! one `hook_pre_push_full` pass the server must hold the session plus a
//! `cli_claim` link for the commit SHA (confidence `exact`, seq range), the
//! spool queue must be empty, and `upload.json` must record the links as
//! sent. Marking the spooled session ended and calling `hook_pre_push_full`
//! again must complete the server row and set its `ended_at`.
mod common;

use common::{TestServer, git_dated, git_ok};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_upload_links_and_changed_meta_without_sync() {
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

    // Temp git work repo: initial commit dated 2020, origin = server URL.
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    git_ok(&work, &["init", "-q"]).await;
    git_ok(
        &work,
        &[
            "remote",
            "add",
            "origin",
            &s.git_url("alice", "proj", Some(&token)),
        ],
    )
    .await;
    std::fs::write(work.join("README.md"), "# proj\n").unwrap();
    git_ok(&work, &["add", "README.md"]).await;
    git_dated(
        &work,
        &["commit", "-q", "-m", "initial commit"],
        1_577_836_800,
    )
    .await;

    // Pi native session: events an hour ago (after the 2020 initial commit,
    // inside the 24 h idle window so ingest does NOT mark it ended), with an
    // Edit tool call on notes.txt so the link is `exact`.
    let now = time::OffsetDateTime::now_utc();
    let fmt = |off: i64| {
        (now - time::Duration::seconds(off))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let work_str = work.to_string_lossy().into_owned();
    let notes = format!("{work_str}/notes.txt");
    let records = [
        serde_json::json!({
            "type": "session",
            "version": 3,
            "id": "hooks-1",
            "timestamp": fmt(3600),
            "cwd": work_str,
            "runtime": { "version": "0.5.2" },
        }),
        serde_json::json!({
            "type": "message",
            "id": "m1",
            "parentId": null,
            "timestamp": fmt(3600),
            "runtime": { "version": "0.5.2" },
            "message": {
                "role": "user",
                "content": [{ "type": "text", "text": "edit the notes" }],
            },
        }),
        serde_json::json!({
            "type": "message",
            "id": "m2",
            "parentId": "m1",
            "timestamp": fmt(1800),
            "runtime": { "version": "0.5.2" },
            "message": {
                "role": "assistant",
                "model": "pi-model-x",
                "provider": "anthropic",
                "usage": {"input": 10, "output": 20, "cacheRead": 0, "cacheWrite": 0},
                "content": [{ "type": "text", "text": "on it" }],
            },
        }),
        serde_json::json!({
            "type": "message",
            "id": "m3",
            "parentId": "m2",
            "timestamp": fmt(60),
            "runtime": { "version": "0.5.2" },
            "message": {
                "role": "assistant",
                "model": "pi-model-x",
                "provider": "anthropic",
                "usage": {"input": 11, "output": 21, "cacheRead": 0, "cacheWrite": 0},
                "content": [{ "type": "toolCall", "id": "tool-1", "name": "Edit", "arguments": {"file_path": notes, "edits": 1} }],
            },
        }),
    ];
    let native = records
        .iter()
        .map(|record| serde_json::to_string(record).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let store = home.join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("s.jsonl"), &native).unwrap();

    let paths = starforge_cli::config::CliPaths::from_home(home.clone());

    // Write + stage notes.txt, run prepare/commit/post-commit like git would.
    std::fs::write(work.join("notes.txt"), "notes\n").unwrap();
    git_ok(&work, &["add", "notes.txt"]).await;
    let msg_file = work.join("COMMIT_MSG");
    std::fs::write(&msg_file, "subject\n").unwrap();
    assert_eq!(
        starforge_cli::commands::hooks::hook_prepare(&work, &msg_file, &paths),
        0
    );
    let body = std::fs::read_to_string(&msg_file).unwrap();
    assert!(
        body.contains("Starforge-Session:"),
        "prepare must add a trailer; body:\n{body}"
    );
    let msg_str = msg_file.to_string_lossy().into_owned();
    git_ok(&work, &["commit", "--no-verify", "-F", msg_str.as_str()]).await;
    let sha = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_string();
    assert_eq!(
        starforge_cli::commands::hooks::hook_post_commit(&work, &paths),
        0
    );

    // ONE pre-push pass: enqueue + best-effort upload (which now reconciles).
    // No `sync` call anywhere.
    let lookup = |key: &str| {
        if key == "STARFORGE_TOKEN" {
            Some(token.clone())
        } else {
            None
        }
    };
    assert_eq!(
        starforge_cli::commands::hooks::hook_pre_push_full(&work, &paths, lookup).await,
        0
    );

    let spool = starforge_cli::spool::Spool::open(
        &starforge_cli::git::common_dir(&work).expect("common dir"),
    );
    let links = spool.links().unwrap();
    assert_eq!(links.len(), 1, "post-commit must record one link");
    let ulid = links[0].ulid.clone();

    // Through the server DB: session exists, cli_claim link is exact + ranged.
    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, &ulid)
        .await
        .unwrap()
        .expect("session row exists after pre-push");
    let rows = db_sessions::links_of_session(s.core.db(), session.id)
        .await
        .unwrap();
    let link = rows
        .iter()
        .find(|row| row.sha == sha)
        .unwrap_or_else(|| panic!("claim link for {sha} missing: {rows:?}"));
    assert_eq!(link.source, "cli_claim");
    assert_eq!(link.confidence, "exact");
    assert!(
        link.seq_start.is_some() && link.seq_end.is_some(),
        "seq range: {link:?}"
    );
    assert_eq!(link.claim_seen, 1);

    assert!(
        starforge_cli::queue::read_queue(&spool).unwrap().is_empty(),
        "spool queue must be empty after pre-push"
    );
    let upload = spool.read_upload(&ulid).unwrap();
    assert!(upload.meta_hash.is_some());
    assert_eq!(upload.sent_links.len(), 1, "links recorded as sent");
    assert!(!upload.complete, "session not ended yet");

    // Mark the spooled session ended through the Spool API, then pre-push again.
    let mut meta = spool.read_meta(&ulid).unwrap();
    meta.ended_at = Some(fmt(0));
    spool.put_session(&meta).unwrap();
    let lookup = |key: &str| {
        if key == "STARFORGE_TOKEN" {
            Some(token.clone())
        } else {
            None
        }
    };
    assert_eq!(
        starforge_cli::commands::hooks::hook_pre_push_full(&work, &paths, lookup).await,
        0
    );

    let session = db_sessions::session_by_ulid(s.core.db(), repo_id, &ulid)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.lifecycle, "complete");
    assert!(session.ended_at.is_some(), "ended_at set on server row");
    assert!(spool.read_upload(&ulid).unwrap().complete);
}
