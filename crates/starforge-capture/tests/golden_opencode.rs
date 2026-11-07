//! Golden tests for the OpenCode capture adapter.
//!
//! Drives tempdirs only (never `$HOME`): the fixture SQL is executed into
//! `<tmp>/data/opencode.db` with `rusqlite` (no committed binaries).
//! `Roots` points at the tempdirs with `worktree` set to the fixture's
//! own worktree (`/repo`, lexical only).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use starforge_capture::Cursor;
use starforge_capture::agents::OpencodeAdapter;
use starforge_capture::{Adapter, Roots};
use starforge_format::{SessionMeta, kind_name};

const FALLBACK_TS: &str = "2026-11-04T12:00:00Z";
const SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";

fn fixture_dir(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/opencode")
        .join(version)
}

/// Execute the fixture `transcript.sql` into `<tmp>/data/opencode.db` and
/// build `Roots` whose worktree is the fixture's own worktree.
fn setup_db(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let sql = std::fs::read_to_string(fixture_dir(version).join("transcript.sql")).unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("opencode.db");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(&sql)
        .unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: data,
        worktree: PathBuf::from("/repo"),
    };
    (tmp, roots, db)
}

fn event_lines(header_events: &[starforge_format::Event]) -> Vec<String> {
    header_events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect()
}

#[test]
fn opencode_golden_pinned_version() {
    let (_tmp, roots, _db) = setup_db("2.0.29");
    let a = OpencodeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].session_key, SESSION_ID);
    assert_eq!(found[0].agent_version, "2.0.29");
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("2.0.29").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Opencode);
    assert_eq!(out.header.agent.version, "2.0.29");
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            "user_message",
            "assistant_message",
            "reasoning",
            "tool_call",
            "tool_result",
            "system",
            "compaction",
            "system",
            "system",
            "system",
            "tool_call",
            "tool_result",
            "tool_call",
            "tool_result",
        ]
    );
    assert!(out.header.capture.adapter_version_verified);

    // The unknown future part is never dropped: it maps to `system`
    // whose text carries the raw part JSON.
    let system = out
        .events
        .iter()
        .find(|e| matches!(&e.kind, starforge_format::EventKind::System(s) if s.text.contains("future-part")))
        .expect("fixture must contain a system fallback event");
    let starforge_format::EventKind::System(body) = &system.kind else {
        unreachable!("find already matched system with future-part");
    };
    assert!(
        body.text.contains("future-part"),
        "system text must carry the raw part JSON: {}",
        body.text
    );

    // Real message types map readably, never as raw-JSON system events:
    // `synthetic`/`system` carry their text (description-prefixed when
    // present), `agent-switched` names both agents, and `idle` yields
    // nothing (there is no idle event; total events stay 14).
    let system_texts: Vec<&str> = out
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            starforge_format::EventKind::System(s) => Some(s.text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        system_texts,
        vec![
            "{\"type\":\"future-part\",\"weird\":true}",
            "Retry: Synthetic retry hint.",
            "Notice: Engine restarted.",
            "Agent switched from build to plan",
        ]
    );
    for text in &system_texts[1..] {
        assert!(
            !text.trim_start().starts_with('{'),
            "mapped message type must not be raw JSON: {text}"
        );
    }
    assert_eq!(out.events.len(), 14, "idle must produce no event");

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("2.0.29").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 1200);
    assert_eq!(out.header.usage.output, 60);
    assert_eq!(
        out.header.files_touched,
        vec!["src/auth.rs", "src/modern.rs", "src/legacy.rs"]
    );
}

/// File-modifying tools' paths go through the same normalization as the Pi
/// adapter: absolute inside the workdir becomes repo-relative, absolute
/// outside is dropped (never stored verbatim — it could name e.g.
/// `/home/<user>/.ssh/…`), relative stays as-is.
#[test]
fn opencode_files_touched_drops_absolute_paths_outside_workdir() {
    let (_tmp, roots, db) = setup_db("2.0.29");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
         VALUES('msg_paths', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'assistant', 8, 1793793650000, 1793793655000,
                '{\"agent\":\"build\",\"model\":{\"id\":\"claude-sonnet-4-5\",\"providerID\":\"anthropic\"},\"content\":[],\"tokens\":{\"input\":0,\"output\":0,\"reasoning\":0,\"cache\":{\"read\":0,\"write\":0}},\"cost\":0,\"time\":{\"created\":1793793650000}}');
         INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
         VALUES('msg_paths', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 0, 'tool', 'call_inside', 1793793650000, 1793793655000,
                '{\"type\":\"tool\",\"id\":\"call_inside\",\"name\":\"edit\",\"state\":{\"status\":\"completed\",\"input\":{\"path\":\"/repo/src/inside.rs\"},\"content\":[]}}');
         INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
         VALUES('msg_paths', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 1, 'tool', 'call_outside', 1793793650000, 1793793655000,
                '{\"type\":\"tool\",\"id\":\"call_outside\",\"name\":\"edit\",\"state\":{\"status\":\"completed\",\"input\":{\"path\":\"/home/jlo/.ssh/id_rsa\"},\"content\":[]}}');
         INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
         VALUES('msg_paths', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 2, 'tool', 'call_rel', 1793793650000, 1793793655000,
                '{\"type\":\"tool\",\"id\":\"call_rel\",\"name\":\"write\",\"state\":{\"status\":\"completed\",\"input\":{\"path\":\"src/rel.rs\"},\"content\":[]}}');",
    )
    .unwrap();
    drop(conn);
    let a = OpencodeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(
        out.header.files_touched,
        vec![
            "src/auth.rs",
            "src/modern.rs",
            "src/legacy.rs",
            "src/inside.rs",
            "src/rel.rs",
        ]
    );
    assert!(
        !out.header.files_touched.iter().any(|f| f.contains(".ssh")),
        "{:?}",
        out.header.files_touched
    );
}

#[test]
fn opencode_unknown_version_parses_unverified() {
    let (_tmp, roots, _db) = setup_db("unknown");
    let a = OpencodeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_version, "9.9.9");
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    // Identical event bytes to the pinned fixture; only the header differs.
    let expected = std::fs::read_to_string(fixture_dir("2.0.29").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn opencode_read_is_read_only() {
    let (_tmp, roots, db) = setup_db("2.0.29");
    let a = OpencodeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let before = std::fs::metadata(&db).unwrap();
    let (mtime, size) = (before.modified().unwrap(), before.len());
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(out.events.len(), 14);
    let after = std::fs::metadata(&db).unwrap();
    assert_eq!(after.modified().unwrap(), mtime);
    assert_eq!(after.len(), size);
}

#[test]
fn opencode_missing_v2_table_is_not_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("opencode.db");
    // An unrelated SQLite database: the v2 tables are absent.
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("CREATE TABLE unrelated(x TEXT); INSERT INTO unrelated VALUES('nope');")
        .unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: data,
        worktree: PathBuf::from("/repo"),
    };
    let a = OpencodeAdapter;
    assert!(!a.detect(&roots));
    assert!(a.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn opencode_hooks_are_noops() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = OpencodeAdapter;
    // No pinned plugin-event story: discovery of the store is the only
    // capture path, so both directions report nothing.
    assert!(a.install_hooks(&roots).unwrap().is_empty());
    assert!(a.remove_hooks(&roots).unwrap().is_empty());
}

#[test]
fn opencode_incremental_read_resumes() {
    let (_tmp, roots, db) = setup_db("2.0.29");
    let a = OpencodeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 14);
    let next = first.next;
    // 8 messages consumed; the last seq consumed is 7.
    assert_eq!(next.lines, 8);
    assert_eq!(next.offset, 7);
    assert_eq!(next.events, 14);

    // Empty growth: same cursor back.
    let again = a.read(&found[0], &next, FALLBACK_TS).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next, next);

    // Partial resume across the multi-part assistant message (seq 1
    // emits 5 events): a cursor after the first message holds 1 event,
    // so the tail continues at seq 1 with no reuse, skip, or reorder,
    // and head-plus-tail equals the fresh full read.
    let mid = Cursor {
        offset: 0,
        lines: 1,
        events: 1,
    };
    let tail = a.read(&found[0], &mid, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 13);
    assert_eq!(tail.events[0].seq, 1);
    assert_eq!(tail.next.lines, 8);
    assert_eq!(tail.next.offset, 7);
    let mut concat: Vec<starforge_format::Event> = first.events.iter().take(1).cloned().collect();
    concat.extend(tail.events.iter().cloned());
    assert_eq!(concat, first.events);
    let mut seqs: Vec<u64> = concat.iter().map(|e| e.seq).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);

    // Growth: a new message (seq 8) is a new candidate, and reading from
    // the old cursor yields only the new event with continuing seq.
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
             VALUES('msg_user_2', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'user', 8, 1793793620000, 1793793620000,
             '{\"text\":\"Thanks.\",\"files\":[],\"agents\":[],\"skills\":[],\"time\":{\"created\":1793793620000}}');",
        )
        .unwrap();
    let mut known = HashMap::new();
    known.insert(found[0].session_key.clone(), next);
    let grown = a.discover(&roots, &known);
    assert_eq!(grown.len(), 1);
    let delta = a.read(&grown[0], &next, FALLBACK_TS).unwrap();
    assert_eq!(delta.events.len(), 1);
    assert_eq!(delta.events[0].seq, 14);
    assert_eq!(delta.next.offset, 8);
    assert_eq!(delta.next.lines, 9);
    assert_eq!(delta.next.events, 15);
    let fresh = a.read(&grown[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 15);
    let mut concat2 = first.events.clone();
    concat2.extend(delta.events.iter().cloned());
    assert_eq!(concat2, fresh.events);

    // discover with the post-growth cursor reports nothing new.
    let mut known2 = HashMap::new();
    known2.insert(found[0].session_key.clone(), delta.next);
    assert!(a.discover(&roots, &known2).is_empty());

    // Cursor past the last seq is rejected.
    let bad = Cursor {
        offset: 9999,
        lines: 99,
        events: 99,
    };
    let err = a.read(&found[0], &bad, FALLBACK_TS).unwrap_err();
    assert!(
        matches!(err, starforge_capture::CaptureError::CursorBeyondEnd(_, _)),
        "unexpected error: {err:?}"
    );

    // Bad fallback timestamp is rejected.
    let err = a
        .read(&found[0], &Cursor::start(), "not-a-timestamp")
        .unwrap_err();
    assert!(
        matches!(err, starforge_capture::CaptureError::BadTimestamp(_)),
        "unexpected error: {err:?}"
    );
}

/// `detect` stays false when the store does not exist.
#[test]
fn opencode_detect_false_without_store() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = OpencodeAdapter;
    assert!(!a.detect(&roots));
    assert!(a.discover(&roots, &HashMap::new()).is_empty());
}

/// Unknown-cwd sessions are skipped, never attributed to the worktree under
/// commit: empty `directory` plus an empty/missing project worktree must not
/// discover.
#[test]
fn opencode_session_with_unknown_workdir_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("opencode.db");
    let sql = "CREATE TABLE project(id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL);\
        CREATE TABLE session_v2(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', parent_id TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, time_archived INTEGER);\
        CREATE TABLE session_message(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, type TEXT NOT NULL, seq INTEGER NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);\
        CREATE TABLE session_part(message_id TEXT NOT NULL, session_id TEXT NOT NULL, ordinal INTEGER NOT NULL, type TEXT NOT NULL, call_id TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);\
        INSERT INTO project(id, worktree, time_created, time_updated) VALUES('p1', '', 1, 1);\
        INSERT INTO session_v2(id, project_id, directory, version, time_created, time_updated) VALUES('sess_unknown', 'p1', '', '2.0.29', 1, 1);\
        INSERT INTO session_v2(id, project_id, directory, version, time_created, time_updated) VALUES('sess_missing_proj', 'nope', '', '2.0.29', 1, 1);\
        INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data) VALUES('m1', 'sess_unknown', 'user', 0, 1, 1, '{\"text\":\"hi\"}');\
        INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data) VALUES('m2', 'sess_missing_proj', 'user', 0, 1, 1, '{\"text\":\"hi\"}');";
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(sql)
        .unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: data,
        worktree: PathBuf::from("/repo"),
    };
    let a = OpencodeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert!(
        found.is_empty(),
        "unknown-cwd sessions must be skipped, got {found:?}"
    );
}

// `synthetic`/`system` with empty text and description must not push an
// empty `System` event.
#[test]
fn opencode_blank_synthetic_and_system_emit_no_event() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("opencode.db");
    let sql = "CREATE TABLE project(id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL);\
        CREATE TABLE session_v2(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', parent_id TEXT, title TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, time_archived INTEGER);\
        CREATE TABLE session_message(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, type TEXT NOT NULL, seq INTEGER NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);\
        CREATE TABLE session_part(message_id TEXT NOT NULL, session_id TEXT NOT NULL, ordinal INTEGER NOT NULL, type TEXT NOT NULL, call_id TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);\
        INSERT INTO project(id, worktree, time_created, time_updated) VALUES('p1', '/repo', 1, 1);\
        INSERT INTO session_v2(id, project_id, directory, version, time_created, time_updated) VALUES('sess_blank', 'p1', '/repo', '2.0.29', 1, 1);\
        INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data) VALUES('m1', 'sess_blank', 'user', 0, 1, 1, '{\"text\":\"hi\"}');\
        INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data) VALUES('m2', 'sess_blank', 'synthetic', 1, 2, 2, '{\"text\":\"\",\"description\":\"\"}');\
        INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data) VALUES('m3', 'sess_blank', 'system', 2, 3, 3, '{}');";
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(sql)
        .unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: data,
        worktree: PathBuf::from("/repo"),
    };
    let a = OpencodeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(
        out.events.len(),
        1,
        "only the user message survives: {:?}",
        out.events
    );
    assert!(matches!(
        out.events[0].kind,
        starforge_format::EventKind::UserMessage(_)
    ));
}
