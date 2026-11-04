//! Golden tests for the Pi and omp capture adapters.
//!
//! Drives tempdirs only (never `$HOME`): the fixture transcript bytes are
//! copied into `<tmp>/data/sessions/` (Pi) or
//! `<tmp>/data/omp/agent/sessions/<date>/` (omp), and `Roots` points at the
//! tempdirs with `worktree` set to the transcript's own `cwd` (`/repo`,
//! lexical only).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use starforge_capture::Cursor;
use starforge_capture::agents::PiAdapter;
use starforge_capture::{Adapter, Roots};
use starforge_format::{SessionMeta, kind_name};

const FALLBACK_TS: &str = "2026-11-04T12:00:00Z";
const PI_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const OMP_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";

fn fixture_dir(version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pi")
        .join(version)
}

/// Copy `transcript.jsonl` into the Pi store layout and build `Roots` whose
/// worktree is the transcript's own `cwd` (`/repo`, lexical only).
fn setup_pi(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixture_dir(version).join("transcript.jsonl")).unwrap();
    let store = tmp.path().join("data/sessions");
    std::fs::create_dir_all(&store).unwrap();
    let native = store.join(format!("{PI_SESSION_ID}.jsonl"));
    std::fs::write(&native, &fixture).unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    (tmp, roots, native)
}

/// Copy `transcript.jsonl` into the omp store layout and build `Roots` whose
/// worktree is the transcript's own `cwd` (`/repo`, lexical only).
fn setup_omp(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = std::fs::read_to_string(fixture_dir(version).join("transcript.jsonl")).unwrap();
    let store = tmp.path().join("data/omp/agent/sessions/2026/11/04");
    std::fs::create_dir_all(&store).unwrap();
    let native = store.join(format!("{OMP_SESSION_ID}.jsonl"));
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
fn pi_golden_pinned_version() {
    let (_tmp, roots, _native) = setup_pi("0.5.2");
    let a = PiAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected = std::fs::read_to_string(fixture_dir("0.5.2").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Pi);
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            "user_message",
            "assistant_message",
            "reasoning",
            "tool_call",
            "tool_result",
            "subagent_start",
            "subagent_end",
            "assistant_message",
            "compaction",
        ]
    );
    assert!(out.header.capture.adapter_version_verified);

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("0.5.2").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 2600);
    assert_eq!(out.header.usage.output, 85);
    assert_eq!(out.header.files_touched, vec!["src/auth.rs"]);
}

#[test]
fn omp_golden_version_unverified_with_system_fallback() {
    let (_tmp, roots, _native) = setup_omp("omp-0.9.1");
    let a = PiAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_version, "omp-0.9.1");
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let expected =
        std::fs::read_to_string(fixture_dir("omp-0.9.1").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);

    // seq is 0..n contiguous.
    for (i, e) in out.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event {i} seq");
    }
    // omp shares the Pi agent name per §7.8's five-name table.
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Pi);
    assert_eq!(out.header.agent.version, "omp-0.9.1");
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
            "subagent_start",
            "subagent_end",
            "assistant_message",
            "compaction",
        ]
    );
    // The omp-only record shape is never dropped: it maps to `system` whose
    // text carries the raw native JSON.
    let system = out
        .events
        .iter()
        .find(|e| kind_name(&e.kind) == "system")
        .expect("omp fixture must contain a system fallback event");
    let starforge_format::EventKind::System(body) = &system.kind else {
        unreachable!("kind_name already matched system");
    };
    assert!(
        body.text.contains("\"extension_state\""),
        "system text must carry the raw record JSON: {}",
        body.text
    );
    assert!(
        body.text.contains("starforge-lint"),
        "system text must preserve the unmapped payload: {}",
        body.text
    );
    // omp versions ship unverified.
    assert!(!out.header.capture.adapter_version_verified);

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("omp-0.9.1").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn pi_unknown_version_parses_unverified() {
    let (_tmp, roots, _native) = setup_pi("unknown");
    let a = PiAdapter;
    assert!(a.detect(&roots));
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let out = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    // Identical event bytes to the pinned fixture; only the header differs.
    let expected = std::fs::read_to_string(fixture_dir("0.5.2").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn pi_hooks_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = PiAdapter;
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
fn pi_incremental_read_resumes() {
    let (_tmp, roots, _native) = setup_pi("0.5.2");
    let a = PiAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 9);
    let next = first.next;
    assert_eq!(next.lines, 8);

    // Empty growth: same cursor back.
    let again = a.read(&found[0], &next, FALLBACK_TS).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next, next);

    // Partial resume across the multi-event assistant record (record index 1
    // emits two events): cursor after 2 records holds 3 events, so the tail
    // continues at seq 3 with no reuse, skip, or reorder.
    let file_len = std::fs::metadata(&found[0].native_path).unwrap().len();
    let raw = std::fs::read(&found[0].native_path).unwrap();
    let mut off = 0u64;
    for _ in 0..2 {
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
        lines: 2,
        events: 3,
    };
    let tail = a.read(&found[0], &mid, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 6);
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

/// A foreign store file without the marker is never deleted by `remove_hooks`,
/// and `detect` stays false when neither store exists.
#[test]
fn pi_hooks_never_touch_foreign_files() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = PiAdapter;
    assert!(!a.detect(&roots));
    let foreign = roots.config_dir.join("pi/starforge.json");
    std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    std::fs::write(&foreign, r#"{"hooks": []}"#).unwrap();
    let removed = a.remove_hooks(&roots).unwrap();
    assert!(removed.is_empty());
    assert!(foreign.exists());
}

/// Installing over a foreign hook file merges under the single `starforge`
/// key: unrelated keys survive, the marker is present, and removal restores
/// the foreign file (a second removal is a no-op).
#[test]
fn pi_install_merges_into_foreign_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = PiAdapter;
    let path = roots.config_dir.join("pi/starforge.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let foreign = r#"{"extensionEvents":{"sessionStart":[]},"theme":"dark"}"#;
    std::fs::write(&path, foreign).unwrap();

    let written = a.install_hooks(&roots).unwrap();
    assert_eq!(written, vec![path.clone()]);
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains("starforge"), "hook file must carry marker");
    let merged: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        merged.get("theme").and_then(|v| v.as_str()),
        Some("dark"),
        "unrelated keys preserved"
    );
    assert!(
        merged.get("extensionEvents").is_some(),
        "unrelated keys preserved"
    );
    assert!(merged.get("starforge").is_some(), "dedicated starforge key");

    // Removal drops only the `starforge` key and keeps the rest.
    let removed = a.remove_hooks(&roots).unwrap();
    assert_eq!(removed, vec![path.clone()]);
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(after.get("starforge").is_none());
    assert_eq!(after.get("theme").and_then(|v| v.as_str()), Some("dark"));
    assert!(after.get("extensionEvents").is_some());

    // Second removal touches nothing.
    let before = std::fs::read(&path).unwrap();
    let removed_again = a.remove_hooks(&roots).unwrap();
    assert!(removed_again.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

/// Installing over an unparseable (or non-object) hook file fails with
/// `InvalidData` naming the path and leaves the bytes untouched.
#[test]
fn pi_install_rejects_non_object_hook_file() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = PiAdapter;
    let path = roots.config_dir.join("pi/starforge.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    for bad in ["{not valid json", "[1, 2, 3]", "\"just a string\""] {
        std::fs::write(&path, bad).unwrap();
        let err = a.install_hooks(&roots).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "error names the path: {err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
    }
    // A foreign file with no `starforge` key is never removed.
    let removed = a.remove_hooks(&roots).unwrap();
    assert!(removed.is_empty());
    assert!(path.exists());
}
