//! Golden tests for the Claude Code capture adapter.
//!
//! Drives tempdirs only (never `$HOME`): the fixture transcript bytes are
//! copied into `<tmp>/data/projects/<slug>/`, and `Roots` points at the
//! tempdirs with `worktree` set to the transcript's own `cwd`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use starforge_capture::Cursor;
use starforge_capture::agents::ClaudeAdapter;
use starforge_capture::{Adapter, Roots};
use starforge_format::{SessionMeta, kind_name};

const FALLBACK_TS: &str = "2026-11-04T12:00:00Z";
const SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn fixture_dir(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/claude-code")
        .join(version)
}

/// Copy `transcript.jsonl` into a temp data store and build `Roots` whose
/// worktree is the transcript's own `cwd` (`/repo`, lexical only).
fn setup(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixture_dir(version).join("transcript.jsonl")).unwrap();
    let slug = "repo";
    let store = tmp.path().join("data/projects").join(slug);
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
fn claude_golden_pinned_version() {
    let (_tmp, roots, _native) = setup("1.2.3");
    let a = ClaudeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("1.2.3").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(
        out.header.agent.name,
        starforge_format::AgentName::ClaudeCode
    );
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
    let meta = std::fs::read_to_string(fixture_dir("1.2.3").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 5150);
    assert_eq!(out.header.usage.output, 155);
    assert_eq!(out.header.files_touched, vec!["src/auth.rs".to_string()]);
}

#[test]
fn claude_unknown_version_parses_unverified() {
    let (_tmp, roots, _native) = setup("unknown");
    let a = ClaudeAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    // Identical event bytes to the pinned fixture; only the header differs.
    let expected = std::fs::read_to_string(fixture_dir("1.2.3").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn claude_hooks_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = ClaudeAdapter;
    let written = a.install_hooks(&roots).unwrap();
    assert_eq!(written.len(), 1);
    assert!(written[0].starts_with(&roots.config_dir));
    let body = std::fs::read_to_string(&written[0]).unwrap();
    assert!(body.contains("starforge"), "hook file must carry marker");
    let removed = a.remove_hooks(&roots).unwrap();
    assert_eq!(removed, written);
    assert!(!written[0].exists());
    // Second removal removes nothing.
    let removed_again = a.remove_hooks(&roots).unwrap();
    assert!(removed_again.is_empty());
}

#[test]
fn claude_incremental_read_resumes() {
    let (_tmp, roots, _native) = setup("1.2.3");
    let a = ClaudeAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 8);
    let next = first.next;
    assert_eq!(next.lines, 8);

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
    };
    let tail = a.read(&found[0], &mid, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 5);
    assert_eq!(tail.events[0].seq, 3);
    assert_eq!(tail.next.lines, 8);
    assert_eq!(tail.next.offset, file_len);

    // discover with the full cursor reports nothing new.
    let mut known = HashMap::new();
    known.insert(found[0].session_key.clone(), next);
    assert!(a.discover(&roots, &known).is_empty());

    // Cursor past EOF is rejected.
    let bad = Cursor {
        offset: file_len + 1,
        lines: 99,
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
