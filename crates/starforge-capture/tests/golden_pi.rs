//! Golden tests for the Pi and omp capture adapters.
//!
//! Drives tempdirs only (never `$HOME`): the fixture transcript bytes are
//! copied into `<tmp>/data/.pi/agent/sessions/<cwd-slug>/` (Pi) or
//! `<tmp>/data/.omp/agent/sessions/<cwd-slug>/` (omp), and `Roots` points
//! at the tempdirs with `worktree` set to the transcript's own `cwd`
//! (`/repo`, lexical only).

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
    let store = tmp.path().join("data/.pi/agent/sessions/--home-u-proj--");
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
    let store = tmp.path().join("data/.omp/agent/sessions/-home-u-proj");
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

/// The fixture's event kinds in order: user, reasoning, assistant text,
/// tool call, tool result, tool-call-only assistant turn, image tool result,
/// advisor system message, compaction, unknown-record system fallback.
/// The `session_exit` record yields no event and no `ended_at` (a skipped
/// runtime marker); the skipped records (model_usage, mode_change,
/// credential_pin, tool_execution_start) emit none.
fn fixture_kinds() -> Vec<&'static str> {
    vec![
        "user_message",
        "reasoning",
        "assistant_message",
        "tool_call",
        "tool_result",
        "tool_call",
        "tool_result",
        "system",
        "compaction",
        "system",
    ]
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
    assert_eq!(kinds, fixture_kinds());
    assert!(out.header.capture.adapter_version_verified);

    // The leading `title` record (no `timestamp`) must NOT get the fallback
    // "now": no event carries FALLBACK_TS, so the 24 h idle rule can end
    // the session. The advisor message is readable system text; the unknown
    // record keeps its raw JSON.
    assert!(out.events.iter().all(|e| e.ts != FALLBACK_TS));
    let systems: Vec<&starforge_format::System> = out
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            starforge_format::EventKind::System(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(systems.len(), 2);
    assert_eq!(
        systems[0].text,
        "Consider running the test suite before finishing."
    );
    assert!(systems[1].text.contains("\"mystery_record\""));

    // `credential_pin` contents never appear anywhere in the output.
    let all = format!("{:?}", out.events) + &format!("{:?}", out.header);
    assert!(
        !all.contains("sk-secret-should-not-appear-in-output"),
        "credential_pin content must never be captured"
    );
    // The image tool result is a placeholder, never inlined data.
    assert!(
        !all.contains("aGVsbG8="),
        "image data must never be inlined"
    );

    // Header matches meta.json exactly.
    let meta = std::fs::read_to_string(fixture_dir("0.5.2").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
    assert_eq!(out.header.usage.input, 2600);
    assert_eq!(out.header.usage.output, 85);
    assert_eq!(out.header.usage.cache_read, 100);
    assert_eq!(out.header.usage.cache_write, 20);
    assert_eq!(out.header.usage.reasoning, 30);
    assert_eq!(out.header.files_touched, vec!["src/auth.rs"]);
    assert_eq!(out.header.title.as_deref(), Some("Refactor auth module"));
    assert_eq!(
        out.header.ended_at, None,
        "session_exit does not end the session"
    );
}

#[test]
fn omp_golden_version_unverified() {
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
    // omp shares the Pi agent name per §7.8's five-name table; the format
    // version (`session.version` == 3) never appears as the agent version.
    assert_eq!(out.header.agent.name, starforge_format::AgentName::Pi);
    assert_eq!(out.header.agent.version, "omp-0.9.1");
    let kinds: Vec<&str> = out.events.iter().map(|e| kind_name(&e.kind)).collect();
    assert_eq!(kinds, fixture_kinds());
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
    let expected = std::fs::read_to_string(fixture_dir("unknown").join("expected.jsonl")).unwrap();
    let got = event_lines(&out.events);
    assert_eq!(got.join("\n") + "\n", expected);
    assert!(!out.header.capture.adapter_version_verified);
    let meta = std::fs::read_to_string(fixture_dir("unknown").join("meta.json")).unwrap();
    let want = SessionMeta::parse(meta.trim()).unwrap();
    assert_eq!(out.header, want);
}

#[test]
fn pi_install_hooks_is_noop_and_remove_cleans_legacy() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = PiAdapter;
    // No verified hook surface: install writes nothing.
    assert!(a.install_hooks(&roots).unwrap().is_empty());
    // Legacy file carrying the marker is removed and reported.
    let legacy = roots.config_dir.join(".config/pi/starforge.json");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, r#"{"starforge": {"extensionEvents": {}}}"#).unwrap();
    let removed = a.remove_hooks(&roots).unwrap();
    assert_eq!(removed, vec![legacy.clone()]);
    assert!(!legacy.exists());
    // Second removal removes nothing.
    assert!(a.remove_hooks(&roots).unwrap().is_empty());
}

#[test]
fn pi_incremental_read_resumes() {
    let (_tmp, roots, _native) = setup_pi("0.5.2");
    let a = PiAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 10);
    let next = first.next;
    // 16 records in the fixture (title, session, title_change, 5 message
    // records, custom, custom_message, model_usage, mode_change,
    // credential_pin, compaction, mystery, session_exit). `session_exit`
    // is a skipped runtime marker: it yields no event and no `ended_at`.
    assert_eq!(next.lines, 16);

    // Empty growth: same cursor back.
    let again = a.read(&found[0], &next, FALLBACK_TS).unwrap();
    assert!(again.events.is_empty());
    assert_eq!(again.next, next);

    // Partial resume across the multi-event assistant record (record index 4
    // emits reasoning + assistant + tool_call): a cursor after 5 records
    // holds 4 events, so the tail continues at seq 4 with no reuse, skip,
    // or reorder.
    let file_len = std::fs::metadata(&found[0].native_path).unwrap().len();
    let raw = std::fs::read(&found[0].native_path).unwrap();
    let mut off = 0u64;
    for _ in 0..5 {
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
        lines: 5,
        events: 4,
    };
    let tail = a.read(&found[0], &mid, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 6);
    assert_eq!(tail.events[0].seq, 4);
    assert_eq!(tail.next.lines, 16);
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

/// A resumed batch starting with a record that lacks both `timestamp` and
/// `updatedAt` inherits the most recent timestamp already seen in the batch
/// — never the fallback "now".
#[test]
fn pi_incremental_timestamp_inherits_last_seen() {
    let (_tmp, roots, _native) = setup_pi("0.5.2");
    let a = PiAdapter;
    let found = a.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    let first = a.read(&found[0], &Cursor::start(), FALLBACK_TS).unwrap();
    let resume_at = first.next;
    // The last fixture record is `session_exit` (a skipped marker) at
    // 12:00:20; a later record without a timestamp inherits it.
    let last_ts = "2026-11-04T12:00:20.000Z";

    // Append a `custom_message` with no timestamp at all.
    let appended = serde_json::json!({
        "type": "custom_message",
        "id": "c9",
        "parentId": null,
        "runtime": { "version": "0.5.2" },
        "customType": "advisor",
        "content": "Late note without a timestamp.",
        "display": true,
    });
    std::fs::write(
        &found[0].native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&found[0].native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&found[0], &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(kind_name(&tail.events[0].kind), "system");
    assert_eq!(tail.events[0].ts, last_ts);
    assert_ne!(tail.events[0].ts, FALLBACK_TS);
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
    let foreign = roots.config_dir.join(".config/pi/starforge.json");
    std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    std::fs::write(&foreign, r#"{"hooks": []}"#).unwrap();
    let removed = a.remove_hooks(&roots).unwrap();
    assert!(removed.is_empty());
    assert!(foreign.exists());
}

/// Legacy removal drops only the `starforge` key, preserving unrelated keys
/// (a second removal is a no-op); install never touches the file.
#[test]
fn pi_remove_legacy_preserves_foreign_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let roots = Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    };
    let a = PiAdapter;
    let path = roots.config_dir.join(".config/pi/starforge.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let foreign = r#"{"extensionEvents":{"sessionStart":[]},"theme":"dark","starforge":{}}"#;
    std::fs::write(&path, foreign).unwrap();
    assert!(a.install_hooks(&roots).unwrap().is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), foreign);
    let removed = a.remove_hooks(&roots).unwrap();
    assert_eq!(removed, vec![path.clone()]);
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(after.get("starforge").is_none());
    assert_eq!(after.get("theme").and_then(|v| v.as_str()), Some("dark"));
    assert!(after.get("extensionEvents").is_some());
    let before = std::fs::read(&path).unwrap();
    assert!(a.remove_hooks(&roots).unwrap().is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
