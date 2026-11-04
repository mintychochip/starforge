//! Golden tests for the Codex CLI capture adapter.
//!
//! Drives tempdirs only (never `$HOME`): the fixture transcript bytes are
//! copied into `<tmp>/data/sessions/2026/11/04/`, and `Roots` points at the
//! tempdirs with `worktree` set to the transcript's own `cwd` (`/repo`,
//! lexical only).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use starforge_capture::Cursor;
use starforge_capture::agents::CodexAdapter;
use starforge_capture::{Adapter, Roots};
use starforge_format::{SessionMeta, kind_name};

const FALLBACK_TS: &str = "2026-11-04T12:00:00Z";
const SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn fixture_dir(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/codex")
        .join(version)
}

/// Copy `transcript.jsonl` into a temp Codex session store and build `Roots`
/// whose worktree is the transcript's own `cwd` (`/repo`, lexical only).
fn setup(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixture_dir(version).join("transcript.jsonl")).unwrap();
    let store = tmp.path().join("data/sessions/2026/11/04");
    std::fs::create_dir_all(&store).unwrap();
    let native = store.join(format!("rollout-{SESSION_ID}.jsonl"));
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
fn codex_golden_pinned_version() {
    let (_tmp, roots, _native) = setup("0.42.0");
    let a = CodexAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("0.42.0").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Codex);
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            "user_message",
            "assistant_message",
            "reasoning",
            "tool_call",
            "tool_result",
            "assistant_message",
            "compaction",
            "user_message",
        ]
    );
    assert!(out.header.capture.adapter_version_verified);

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("0.42.0").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 2600);
    assert_eq!(out.header.usage.output, 85);
    assert_eq!(out.header.files_touched, vec!["src/auth.rs".to_string()]);
}

#[test]
fn codex_unknown_version_parses_unverified() {
    let (_tmp, roots, _native) = setup("unknown");
    let a = CodexAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    // Identical event bytes to the pinned fixture; only the header differs.
    let expected = std::fs::read_to_string(fixture_dir("0.42.0").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn codex_hooks_are_unpinned() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = CodexAdapter;
    // No hook story is pinned for the covered Codex versions: both directions
    // report nothing written and nothing removed.
    assert!(a.install_hooks(&roots).unwrap().is_empty());
    assert!(a.remove_hooks(&roots).unwrap().is_empty());
    assert!(!roots.config_dir.exists());
}

#[test]
fn codex_incremental_read_resumes() {
    let (_tmp, roots, _native) = setup("0.42.0");
    let a = CodexAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 8);
    let next = first.next;
    assert_eq!(next.lines, 8);
    assert_eq!(next.events, 8);

    // Empty growth: same cursor back.
    let again = a.read(&found[0], &next, FALLBACK_TS).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next, next);

    // Partial resume: cursor after 3 records yields seq 3.. events.
    let file_len = std::fs::metadata(&found[0].native_path).unwrap().len();
    let raw = std::fs::read(&found[0].native_path).unwrap();
    let mut off = 0u64;
    for _ in 0..3 {
        let rel: usize = raw[off as usize..]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap()
            + 1;
        off += rel as u64;
    }
    assert!(off < file_len);
    let mid = Cursor {
        offset: off,
        lines: 3,
        events: 3,
    };
    let tail = a.read(&found[0], &mid, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 5);
    assert_eq!(tail.events[0].seq, 3);
    assert_eq!(tail.next.lines, 8);
    assert_eq!(tail.next.events, 8);
    assert_eq!(tail.next.offset, file_len);

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

#[test]
fn codex_append_and_multi_event_resume_keep_seq_contiguous() {
    let (_tmp, roots, _native) = setup("0.42.0");
    let a = CodexAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 8);

    // Append one record that emits TWO events (message + reasoning summary).
    let appended = serde_json::json!({
        "type": "response",
        "text": "Also updated the tests.",
        "reasoning_summary": "Decided to update tests alongside the refactor.",
        "model": "gpt-5-codex",
        "usage": { "input_tokens": 300, "output_tokens": 20 },
        "cwd": "/repo",
        "session_id": SESSION_ID,
        "version": "0.42.0",
        "timestamp": "2026-11-04T12:00:25Z"
    });
    let mut grown = std::fs::read(&found[0].native_path).unwrap();
    grown.extend_from_slice(serde_json::to_string(&appended).unwrap().as_bytes());
    grown.push(b'\n');
    std::fs::write(&found[0].native_path, &grown).unwrap();

    // The grown file is discoverable again past the old cursor …
    let mut known = HashMap::new();
    known.insert(found[0].session_key.clone(), first.next);
    let found2 = a.discover(&roots, &known);
    assert_eq!(found2.len(), 1);

    // … and the resume continues seq without reuse or gap.
    let tail = a.read(&found2[0], &first.next, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 2);
    assert_eq!(tail.events[0].seq, 8);
    assert_eq!(tail.events[1].seq, 9);
    let kinds: Vec<&str> = tail.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(kinds, vec!["assistant_message", "reasoning"]);
    assert_eq!(tail.next.lines, 9);
    assert_eq!(tail.next.events, 10);

    // Concatenation equals a fresh full read, seq contiguous and unique.
    let fresh = a.read(&found2[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 10);
    let mut joined = first.events.clone();
    joined.extend(tail.events.iter().cloned());
    assert_eq!(joined, fresh.events);
    let seqs: Vec<u64> = fresh.events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (0..10).collect::<Vec<_>>());

    // discover with the advanced cursor reports nothing new.
    let mut known2 = HashMap::new();
    known2.insert(found2[0].session_key.clone(), tail.next);
    assert!(a.discover(&roots, &known2).is_empty());
}
