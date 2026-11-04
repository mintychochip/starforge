//! Golden tests for the OpenCode capture adapter.
//!
//! Drives tempdirs only (never `$HOME`): the fixture SQL is executed into
//! `<tmp>/data/opencode.db` with `rusqlite` (no committed binaries), or the
//! file-storage fixture is copied into
//! `<tmp>/data/opencode-sessions/<session>.jsonl`. `Roots` points at the
//! tempdirs with `worktree` set to the transcript's own `cwd` (`/repo`,
//! lexical only).

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
/// build `Roots` whose worktree is the transcript's own `cwd`.
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

/// Copy the file-storage `transcript.jsonl` into
/// `<tmp>/data/opencode-sessions/` and build `Roots` as above.
fn setup_files(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixture_dir(version).join("transcript.jsonl")).unwrap();
    let store = tmp.path().join("data/opencode-sessions");
    std::fs::create_dir_all(&store).unwrap();
    let native = store.join(format!("{SESSION_ID}.jsonl"));
    std::fs::write(&native, &fixture).unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    (tmp, roots, native)
}

fn event_lines(header_events: &[starforge_format::Event]) -> Vec<String> {
    header_events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect()
}

#[test]
fn opencode_golden_pinned_version() {
    let (_tmp, roots, _db) = setup_db("0.9.0");
    let a = OpencodeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].session_key, SESSION_ID);
    assert_eq!(found[0].agent_version, "0.9.0");
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("0.9.0").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Opencode);
    assert_eq!(out.header.agent.version, "0.9.0");
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            "user_message",
            "assistant_message",
            "reasoning",
            "tool_call",
            "file_change",
            "tool_result",
            "compaction",
        ]
    );
    assert!(out.header.capture.adapter_version_verified);

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("0.9.0").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 1200);
    assert_eq!(out.header.usage.output, 60);
    assert_eq!(out.header.files_touched, vec!["src/auth.rs"]);
}

#[test]
fn opencode_unknown_version_parses_unverified() {
    let (_tmp, roots, _db) = setup_db("unknown");
    let a = OpencodeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    // Identical event bytes to the pinned fixture; only the header differs.
    let expected = std::fs::read_to_string(fixture_dir("0.9.0").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn opencode_file_storage_version_unverified_with_system_fallback() {
    let (_tmp, roots, _native) = setup_files("0.8.1");
    let a = OpencodeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_version, "0.8.1");
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("0.8.1").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Opencode);
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            "user_message",
            "assistant_message",
            "reasoning",
            "tool_call",
            "file_change",
            "tool_result",
            "system",
            "compaction",
        ]
    );
    // The file-storage-only record shape is never dropped: it maps to
    // `system` whose text carries the raw native JSON line.
    let system = out
        .events
        .iter()
        .find(|e| kind_name(&e.kind) == "system")
        .expect("file-storage fixture must contain a system fallback event");
    let starforge_format::EventKind::System(body) = &system.kind else {
        unreachable!("kind_name already matched system");
    };
    assert!(
        body.text.contains("\"plugin_event\""),
        "system text must carry the raw record JSON: {}",
        body.text
    );
    assert!(
        body.text.contains("starforge-notify"),
        "system text must preserve the unmapped payload: {}",
        body.text
    );
    // File-storage versions ship unverified.
    assert!(!out.header.capture.adapter_version_verified);

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("0.8.1").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
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
    let (_tmp, roots, db) = setup_db("0.9.0");
    let a = OpencodeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 7);
    let next = first.next;
    // 5 rows consumed; the last rowid consumed is 5.
    assert_eq!(next.lines, 5);
    assert_eq!(next.offset, 5);
    assert_eq!(next.events, 7);

    // Empty growth: same cursor back.
    let again = a.read(&found[0], &next, FALLBACK_TS).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next, next);

    // Partial resume across the multi-event file-write row (row 3 emits
    // `tool_call` + `file_change`): cursor after 2 rows holds 3 events, so
    // the tail continues at seq 3 with no reuse, skip, or reorder, and the
    // head-plus-tail concatenation equals the fresh full read.
    let mid = Cursor {
        offset: 2,
        lines: 2,
        events: 3,
    };
    let tail = a.read(&found[0], &mid, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 4);
    assert_eq!(tail.events[0].seq, 3);
    assert_eq!(tail.next.lines, 5);
    assert_eq!(tail.next.offset, 5);
    let mut concat: Vec<starforge_format::Event> = first.events.iter().take(3).cloned().collect();
    concat.extend(tail.events.iter().cloned());
    assert_eq!(concat, first.events);
    let mut seqs: Vec<u64> = concat.iter().map(|e| e.seq).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5, 6]);

    // Growth: a new row is a new candidate, and reading from the old cursor
    // yields only the new event with continuing seq.
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "INSERT INTO message(session_id, role, name, content, ts) VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'user', '', 'Thanks.', '2026-11-04T12:00:20Z');",
        )
        .unwrap();
    let mut known = HashMap::new();
    known.insert(found[0].session_key.clone(), next);
    let grown = a.discover(&roots, &known);
    assert_eq!(grown.len(), 1);
    let delta = a.read(&grown[0], &next, FALLBACK_TS).unwrap();
    assert_eq!(delta.events.len(), 1);
    assert_eq!(delta.events[0].seq, 7);
    assert_eq!(delta.next.offset, 6);
    assert_eq!(delta.next.lines, 6);
    assert_eq!(delta.next.events, 8);
    let fresh = a.read(&grown[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 8);
    let mut concat2 = first.events.clone();
    concat2.extend(delta.events.iter().cloned());
    assert_eq!(concat2, fresh.events);

    // discover with the post-growth cursor reports nothing new.
    let mut known2 = HashMap::new();
    known2.insert(found[0].session_key.clone(), delta.next);
    assert!(a.discover(&roots, &known2).is_empty());

    // Cursor past the last rowid is rejected.
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

/// `detect` stays false when neither store exists.
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
