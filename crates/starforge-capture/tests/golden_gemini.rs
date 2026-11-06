//! Golden tests for the Gemini CLI capture adapter.
//!
//! Drives tempdirs only (never `$HOME`): the fixture chat JSON is copied
//! into `<tmp>/data/tmp/<hash>/chats/` (Gemini CLI), and `Roots` points
//! at the tempdirs with `worktree` set to the transcript's own `cwd`
//! (`/repo`, lexical only).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use starforge_capture::Cursor;
use starforge_capture::agents::GeminiAdapter;
use starforge_capture::{Adapter, Roots};
use starforge_format::{SessionMeta, kind_name};

const FALLBACK_TS: &str = "2026-11-04T12:00:00Z";
const CLI_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";

fn fixture_dir(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/gemini")
        .join(version)
}

/// Copy `transcript.json` into the Gemini CLI store layout and build `Roots`
/// whose worktree is the transcript's own `cwd` (`/repo`, lexical only).
fn setup_cli(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixture_dir(version).join("transcript.json")).unwrap();
    let store = tmp.path().join("data/tmp/abc123def456/chats");
    std::fs::create_dir_all(&store).unwrap();
    let native = store.join(format!("{CLI_SESSION_ID}.json"));
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
fn gemini_golden_pinned_version() {
    let (_tmp, roots, _native) = setup_cli("0.12.0");
    let a = GeminiAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_version, "0.12.0");
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("0.12.0").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Gemini);
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            "user_message",
            "assistant_message",
            "reasoning",
            "tool_call",
            "tool_result",
            "compaction",
        ]
    );
    assert!(out.header.capture.adapter_version_verified);

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("0.12.0").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 1200);
    assert_eq!(out.header.usage.output, 60);
    assert_eq!(out.header.files_touched, vec!["src/auth.rs"]);
}

#[test]
fn gemini_unknown_version_parses_unverified() {
    let (_tmp, roots, _native) = setup_cli("unknown");
    let a = GeminiAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    // Identical event bytes to the pinned fixture; only the header differs.
    let expected = std::fs::read_to_string(fixture_dir("0.12.0").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn gemini_hooks_are_noops() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = GeminiAdapter;
    // No pinned hook story for the chat files: discovery of the chat
    // files is the only capture path, so both directions report nothing.
    assert!(a.install_hooks(&roots).unwrap().is_empty());
    assert!(a.remove_hooks(&roots).unwrap().is_empty());
}

#[test]
fn gemini_incremental_read_resumes() {
    let (_tmp, roots, native) = setup_cli("0.12.0");
    let a = GeminiAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 6);
    let next = first.next;
    let file_len = std::fs::metadata(&native).unwrap().len();
    assert_eq!(next.lines, 5);
    assert_eq!(next.offset, file_len);

    // Empty growth: same cursor back.
    let again = a.read(&found[0], &next, FALLBACK_TS).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next, next);

    // Growth across the multi-event assistant message (message index 1
    // emits two events): write a one-message prefix doc, read it for a real
    // mid cursor, then restore the full doc and resume. The tail continues
    // at seq 1 with no reuse, skip, or reorder, and head-plus-tail equals
    // the fresh full read.
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&native).unwrap()).unwrap();
    let mut prefix = doc.clone();
    let messages = prefix
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
        .expect("chat doc carries a messages array");
    messages.truncate(1);
    std::fs::write(&native, serde_json::to_string(&prefix).unwrap()).unwrap();
    let head = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(head.events.len(), 1);
    std::fs::write(&native, serde_json::to_string(&doc).unwrap()).unwrap();
    let tail = a.read(&found[0], &head.next, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 5);
    assert_eq!(tail.events[0].seq, 1);
    assert_eq!(tail.next.lines, 5);
    let mut concat = head.events.clone();
    concat.extend(tail.events.iter().cloned());
    assert_eq!(concat, first.events);
    let mut seqs: Vec<u64> = concat.iter().map(|e| e.seq).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);

    // discover with the full cursor reports nothing new.
    let mut known = HashMap::new();
    known.insert(found[0].session_key.clone(), next);
    assert!(a.discover(&roots, &known).is_empty());

    // Cursor past EOF is rejected.
    let bad = Cursor {
        offset: file_len + 1,
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

/// `detect` is true only when a store exists: false on an empty data dir,
#[test]
fn gemini_detect_matches_store_presence() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = GeminiAdapter;
    assert!(!a.detect(&roots));

    let (_tmp_cli, cli_roots, _) = setup_cli("0.12.0");
    assert!(a.detect(&cli_roots));
}
