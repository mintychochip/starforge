//! Cross-adapter discovery sweep + incremental cursors + unknown-version
//! conformance.
//!
//! Drives tempdirs only (never `$HOME`): each test copies the pinned
//! fixture bytes into the adapter's native store layout (same layout as the
//! golden tests), reads from [`Cursor::start`], grows the native store,
//! and asserts the resume yields only the new events with contiguous `seq`.
//! OpenCode growth is a SQL `INSERT` (seq cursor); every other adapter
//! grows by appending to (or rewriting) its transcript file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use starforge_capture::agents::{
    ClaudeAdapter, CodexAdapter, GeminiAdapter, OpencodeAdapter, PiAdapter,
};
use starforge_capture::{Adapter, Cursor, Roots};
use starforge_format::{Event, EventKind, kind_name};

const FALLBACK_TS: &str = "2026-11-04T12:00:00Z";
const CLAUDE_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const CODEX_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const PI_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const OPENCODE_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
const GEMINI_SESSION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";

const FOLLOW_UP_TEXT: &str = "Follow-up: did the tests pass?";
const COMPACTION_TEXT: &str = "Second compaction checkpoint.";
const GROWTH_TS: &str = "2026-11-04T12:00:30Z";
const COMPACTION_TS: &str = "2026-11-04T12:00:35Z";

fn fixture_bytes(agent: &str, version: &str, file: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(agent)
            .join(version)
            .join(file),
    )
    .unwrap()
}

fn fixture_str(agent: &str, version: &str, file: &str) -> String {
    String::from_utf8(fixture_bytes(agent, version, file)).unwrap()
}

fn roots_for(tmp: &tempfile::TempDir) -> Roots {
    Roots {
        config_dir: tmp.path().join("cfg"),
        data_dir: tmp.path().join("data"),
        worktree: PathBuf::from("/repo"),
    }
}

fn setup_claude(version: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("data/projects/repo");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join(format!("{CLAUDE_SESSION_ID}.jsonl")),
        fixture_bytes("claude-code", version, "transcript.jsonl"),
    )
    .unwrap();
    let roots = roots_for(&tmp);
    (tmp, roots)
}

fn setup_codex(version: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("data/sessions/2026/11/04");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join(format!("rollout-{CODEX_SESSION_ID}.jsonl")),
        fixture_bytes("codex", version, "transcript.jsonl"),
    )
    .unwrap();
    let roots = roots_for(&tmp);
    (tmp, roots)
}

fn setup_pi(version: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("data/.pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join(format!("{PI_SESSION_ID}.jsonl")),
        fixture_bytes("pi", version, "transcript.jsonl"),
    )
    .unwrap();
    let roots = roots_for(&tmp);
    (tmp, roots)
}

fn setup_opencode_db(version: &str) -> (tempfile::TempDir, Roots, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("opencode.db");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(&fixture_str("opencode", version, "transcript.sql"))
        .unwrap();
    let roots = roots_for(&tmp);
    (tmp, roots, db)
}

fn setup_gemini(version: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("data/tmp/abc123def456/chats");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join(format!("{GEMINI_SESSION_ID}.json")),
        fixture_bytes("gemini", version, "transcript.json"),
    )
    .unwrap();
    let roots = roots_for(&tmp);
    (tmp, roots)
}

/// `seq` values are unique and contiguous `0..n` over the whole history.
fn assert_seqs_contiguous(events: &[Event]) {
    let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (0..events.len() as u64).collect::<Vec<_>>());
}

fn assert_resume_continuity(first: &[Event], tail: &[Event], fresh: &[Event]) {
    assert!(!first.is_empty());
    assert!(!tail.is_empty());
    assert_eq!(tail[0].seq, first.len() as u64);
    let mut joined = first.to_vec();
    joined.extend(tail.iter().cloned());
    assert_eq!(joined, fresh);
    assert_seqs_contiguous(&joined);
    assert_seqs_contiguous(fresh);
}

fn single_candidate<A: Adapter + ?Sized>(a: &A, roots: &Roots) -> starforge_capture::Candidate {
    let found = a.discover(roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    found.into_iter().next().unwrap()
}

fn user_text(event: &Event) -> &str {
    match &event.kind {
        EventKind::UserMessage(m) => &m.text,
        other => panic!("expected user_message, got {}", kind_name(other)),
    }
}

fn compaction_summary(event: &Event) -> Option<&str> {
    match &event.kind {
        EventKind::Compaction(c) => c.summary.as_deref(),
        other => panic!("expected compaction, got {}", kind_name(other)),
    }
}

// --- Claude ---

#[test]
fn claude_growing_transcript_resume() {
    let (_tmp, roots) = setup_claude("1.2.3");
    let a = ClaudeAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 8);
    let resume_at = first.next;

    let appended = serde_json::json!({
        "type": "user",
        "message": { "role": "user", "content": [{ "type": "text", "text": FOLLOW_UP_TEXT }] },
        "cwd": "/repo",
        "sessionId": CLAUDE_SESSION_ID,
        "version": "1.2.3",
        "uuid": "88888888-8888-4888-8888-888888888888",
        "timestamp": GROWTH_TS,
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(kind_name(&tail.events[0].kind), "user_message");
    assert_eq!(user_text(&tail.events[0]), FOLLOW_UP_TEXT);

    let fresh = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 9);
    assert_resume_continuity(&first.events, &tail.events, &fresh.events);
}

#[test]
fn claude_compaction_boundary() {
    let (_tmp, roots) = setup_claude("1.2.3");
    let a = ClaudeAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    let resume_at = first.next;

    let appended = serde_json::json!({
        "type": "summary",
        "summary": COMPACTION_TEXT,
        "cwd": "/repo",
        "sessionId": CLAUDE_SESSION_ID,
        "version": "1.2.3",
        "timestamp": COMPACTION_TS,
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(compaction_summary(&tail.events[0]), Some(COMPACTION_TEXT));
    assert_eq!(tail.next.lines, resume_at.lines + 1);
    assert_eq!(tail.next.events, resume_at.events + 1);
    assert!(tail.next.offset > resume_at.offset);
}

#[test]
fn claude_discover_incremental() {
    let (_tmp, roots) = setup_claude("1.2.3");
    let a = ClaudeAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();

    let mut known = HashMap::new();
    known.insert(cand.session_key.clone(), first.next);
    assert!(a.discover(&roots, &known).is_empty());

    let appended = serde_json::json!({
        "type": "user",
        "message": { "role": "user", "content": [{ "type": "text", "text": FOLLOW_UP_TEXT }] },
        "cwd": "/repo",
        "sessionId": CLAUDE_SESSION_ID,
        "version": "1.2.3",
        "timestamp": GROWTH_TS,
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let regrown = a.discover(&roots, &known);
    assert_eq!(regrown.len(), 1);
    assert_eq!(regrown[0].session_key, cand.session_key);
}

// --- Codex ---

#[test]
fn codex_growing_transcript_resume() {
    let (_tmp, roots) = setup_codex("0.42.0");
    let a = CodexAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 8);
    let resume_at = first.next;

    let appended = serde_json::json!({
        "type": "prompt",
        "text": FOLLOW_UP_TEXT,
        "cwd": "/repo",
        "session_id": CODEX_SESSION_ID,
        "version": "0.42.0",
        "timestamp": GROWTH_TS,
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(kind_name(&tail.events[0].kind), "user_message");
    assert_eq!(user_text(&tail.events[0]), FOLLOW_UP_TEXT);

    let fresh = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 9);
    assert_resume_continuity(&first.events, &tail.events, &fresh.events);
}

#[test]
fn codex_compaction_boundary() {
    let (_tmp, roots) = setup_codex("0.42.0");
    let a = CodexAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    let resume_at = first.next;

    let appended = serde_json::json!({
        "type": "compacted",
        "summary": COMPACTION_TEXT,
        "cwd": "/repo",
        "session_id": CODEX_SESSION_ID,
        "version": "0.42.0",
        "timestamp": COMPACTION_TS,
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(compaction_summary(&tail.events[0]), Some(COMPACTION_TEXT));
    assert_eq!(tail.next.lines, resume_at.lines + 1);
    assert_eq!(tail.next.events, resume_at.events + 1);
    assert!(tail.next.offset > resume_at.offset);
}

#[test]
fn codex_discover_incremental() {
    let (_tmp, roots) = setup_codex("0.42.0");
    let a = CodexAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();

    let mut known = HashMap::new();
    known.insert(cand.session_key.clone(), first.next);
    assert!(a.discover(&roots, &known).is_empty());

    let appended = serde_json::json!({
        "type": "prompt",
        "text": FOLLOW_UP_TEXT,
        "cwd": "/repo",
        "session_id": CODEX_SESSION_ID,
        "version": "0.42.0",
        "timestamp": GROWTH_TS,
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let regrown = a.discover(&roots, &known);
    assert_eq!(regrown.len(), 1);
    assert_eq!(regrown[0].session_key, cand.session_key);
}

// --- Pi ---

#[test]
fn pi_growing_transcript_resume() {
    let (_tmp, roots) = setup_pi("0.5.2");
    let a = PiAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 11);
    let resume_at = first.next;

    let appended = serde_json::json!({
        "type": "message",
        "id": "m9",
        "parentId": null,
        "timestamp": GROWTH_TS,
        "runtime": { "version": "0.5.2" },
        "message": {
            "role": "user",
            "content": [{ "type": "text", "text": FOLLOW_UP_TEXT }],
        },
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(kind_name(&tail.events[0].kind), "user_message");
    assert_eq!(user_text(&tail.events[0]), FOLLOW_UP_TEXT);

    let fresh = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 12);
    assert_resume_continuity(&first.events, &tail.events, &fresh.events);
}

#[test]
fn pi_compaction_boundary() {
    let (_tmp, roots) = setup_pi("0.5.2");
    let a = PiAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    let resume_at = first.next;

    let appended = serde_json::json!({
        "type": "compaction",
        "id": "cp9",
        "parentId": null,
        "timestamp": COMPACTION_TS,
        "runtime": { "version": "0.5.2" },
        "summary": COMPACTION_TEXT,
        "shortSummary": "Second checkpoint",
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(compaction_summary(&tail.events[0]), Some(COMPACTION_TEXT));
    assert_eq!(tail.next.lines, resume_at.lines + 1);
    assert_eq!(tail.next.events, resume_at.events + 1);
    assert!(tail.next.offset > resume_at.offset);
}

#[test]
fn pi_discover_incremental() {
    let (_tmp, roots) = setup_pi("0.5.2");
    let a = PiAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();

    let mut known = HashMap::new();
    known.insert(cand.session_key.clone(), first.next);
    assert!(a.discover(&roots, &known).is_empty());

    let appended = serde_json::json!({
        "type": "message",
        "id": "m9",
        "parentId": null,
        "timestamp": GROWTH_TS,
        "runtime": { "version": "0.5.2" },
        "message": {
            "role": "user",
            "content": [{ "type": "text", "text": FOLLOW_UP_TEXT }],
        },
    });
    std::fs::write(
        &cand.native_path,
        format!(
            "{}{}\n",
            std::fs::read_to_string(&cand.native_path).unwrap(),
            serde_json::to_string(&appended).unwrap()
        ),
    )
    .unwrap();

    let regrown = a.discover(&roots, &known);
    assert_eq!(regrown.len(), 1);
    assert_eq!(regrown[0].session_key, cand.session_key);
}

// --- OpenCode (seq cursors) ---

fn opencode_insert_user(db: &Path, text: &str, seq: i64, time_ms: i64) {
    let data = serde_json::json!({
        "text": text,
        "files": [],
        "agents": [],
        "skills": [],
        "time": { "created": time_ms },
    });
    let id = format!("msg_growth_{seq}");
    rusqlite::Connection::open(db)
        .unwrap()
        .execute(
            "INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
             VALUES(?1, ?2, 'user', ?3, ?4, ?4, ?5)",
            rusqlite::params![id, OPENCODE_SESSION_ID, seq, time_ms, data.to_string()],
        )
        .unwrap();
}

fn opencode_insert_compaction(db: &Path, summary: &str, seq: i64, time_ms: i64) {
    let data = serde_json::json!({
        "status": "completed",
        "reason": "manual",
        "summary": summary,
        "recent": "",
        "time": { "created": time_ms },
    });
    let id = format!("msg_growth_{seq}");
    rusqlite::Connection::open(db)
        .unwrap()
        .execute(
            "INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
             VALUES(?1, ?2, 'compaction', ?3, ?4, ?4, ?5)",
            rusqlite::params![id, OPENCODE_SESSION_ID, seq, time_ms, data.to_string()],
        )
        .unwrap();
}

#[test]
fn opencode_growing_transcript_resume() {
    let (_tmp, roots, db) = setup_opencode_db("2.0.29");
    let a = OpencodeAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 7);
    let resume_at = first.next;
    // Seq cursor: offset is the last message seq consumed.
    assert_eq!(resume_at.offset, 2);
    assert_eq!(resume_at.lines, 3);

    opencode_insert_user(&db, FOLLOW_UP_TEXT, 3, 1_793_793_630_000);

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(kind_name(&tail.events[0].kind), "user_message");
    assert_eq!(user_text(&tail.events[0]), FOLLOW_UP_TEXT);
    assert_eq!(tail.next.offset, 3);
    assert_eq!(tail.next.lines, resume_at.lines + 1);

    let fresh = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 8);
    assert_resume_continuity(&first.events, &tail.events, &fresh.events);
}

#[test]
fn opencode_compaction_boundary() {
    let (_tmp, roots, db) = setup_opencode_db("2.0.29");
    let a = OpencodeAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    let resume_at = first.next;

    opencode_insert_compaction(&db, COMPACTION_TEXT, 3, 1_793_793_635_000);

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(compaction_summary(&tail.events[0]), Some(COMPACTION_TEXT));
    assert_eq!(tail.next.offset, resume_at.offset + 1);
    assert_eq!(tail.next.lines, resume_at.lines + 1);
    assert_eq!(tail.next.events, resume_at.events + 1);
}

#[test]
fn opencode_discover_incremental() {
    let (_tmp, roots, db) = setup_opencode_db("2.0.29");
    let a = OpencodeAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();

    let mut known = HashMap::new();
    known.insert(cand.session_key.clone(), first.next);
    assert!(a.discover(&roots, &known).is_empty());

    opencode_insert_user(&db, FOLLOW_UP_TEXT, 3, 1_793_793_630_000);

    let regrown = a.discover(&roots, &known);
    assert_eq!(regrown.len(), 1);
    assert_eq!(regrown[0].session_key, cand.session_key);
}

// --- Gemini (whole-document rewrite) ---

fn gemini_push(native: &Path, msg: serde_json::Value) {
    let raw = std::fs::read_to_string(native).unwrap();
    let mut doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    doc.get_mut("messages")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(msg);
    std::fs::write(native, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
}

#[test]
fn gemini_growing_transcript_resume() {
    let (_tmp, roots) = setup_gemini("0.12.0");
    let a = GeminiAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(first.events.len(), 6);
    let resume_at = first.next;

    gemini_push(
        &cand.native_path,
        serde_json::json!({
            "role": "user",
            "content": FOLLOW_UP_TEXT,
            "timestamp": GROWTH_TS,
        }),
    );

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(kind_name(&tail.events[0].kind), "user_message");
    assert_eq!(user_text(&tail.events[0]), FOLLOW_UP_TEXT);
    assert_eq!(tail.next.lines, resume_at.lines + 1);

    let fresh = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    assert_eq!(fresh.events.len(), 7);
    assert_resume_continuity(&first.events, &tail.events, &fresh.events);
}

#[test]
fn gemini_compaction_boundary() {
    let (_tmp, roots) = setup_gemini("0.12.0");
    let a = GeminiAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();
    let resume_at = first.next;

    gemini_push(
        &cand.native_path,
        serde_json::json!({
            "role": "summary",
            "summary": COMPACTION_TEXT,
            "timestamp": COMPACTION_TS,
        }),
    );

    let tail = a.read(&cand, &resume_at, FALLBACK_TS).unwrap();
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].seq, resume_at.next_seq());
    assert_eq!(compaction_summary(&tail.events[0]), Some(COMPACTION_TEXT));
    assert_eq!(tail.next.lines, resume_at.lines + 1);
    assert_eq!(tail.next.events, resume_at.events + 1);
    assert!(tail.next.offset > resume_at.offset);
}

#[test]
fn gemini_discover_incremental() {
    let (_tmp, roots) = setup_gemini("0.12.0");
    let a = GeminiAdapter;
    let cand = single_candidate(&a, &roots);
    let first = a.read(&cand, &Cursor::start(), FALLBACK_TS).unwrap();

    let mut known = HashMap::new();
    known.insert(cand.session_key.clone(), first.next);
    assert!(a.discover(&roots, &known).is_empty());

    gemini_push(
        &cand.native_path,
        serde_json::json!({
            "role": "user",
            "content": FOLLOW_UP_TEXT,
            "timestamp": GROWTH_TS,
        }),
    );

    let regrown = a.discover(&roots, &known);
    assert_eq!(regrown.len(), 1);
    assert_eq!(regrown[0].session_key, cand.session_key);
}

/// Object-safe sweep view over the five adapters.
///
/// `Adapter` itself is not `dyn`-compatible (it carries the associated
/// `const COVERED`), and the B1 contract freezes that shape, so the uniform
/// sweep goes through this local shim instead of `Box<dyn Adapter>`. The
/// blanket impl keeps every assertion below dispatched through the real
/// `Adapter` methods with no contract change.
trait SweepAdapter {
    fn agent_id(&self) -> starforge_format::AgentName;
    fn check_version(&self, version: &str) -> starforge_capture::AdapterVersion;
    fn sweep_discover(
        &self,
        roots: &Roots,
        known: &HashMap<String, Cursor>,
    ) -> Vec<starforge_capture::Candidate>;
    fn sweep_read(
        &self,
        candidate: &starforge_capture::Candidate,
        cursor: &Cursor,
        fallback_ts: &str,
    ) -> Result<starforge_capture::ReadOutput, starforge_capture::CaptureError>;
}

impl<T: Adapter> SweepAdapter for T {
    fn agent_id(&self) -> starforge_format::AgentName {
        Adapter::id(self)
    }
    fn check_version(&self, version: &str) -> starforge_capture::AdapterVersion {
        Adapter::version_status(self, version)
    }
    fn sweep_discover(
        &self,
        roots: &Roots,
        known: &HashMap<String, Cursor>,
    ) -> Vec<starforge_capture::Candidate> {
        Adapter::discover(self, roots, known)
    }
    fn sweep_read(
        &self,
        candidate: &starforge_capture::Candidate,
        cursor: &Cursor,
        fallback_ts: &str,
    ) -> Result<starforge_capture::ReadOutput, starforge_capture::CaptureError> {
        Adapter::read(self, candidate, cursor, fallback_ts)
    }
}

// --- Unknown-version conformance sweep over all five adapters ---

#[test]
fn unknown_version_conformance_sweep() {
    let adapters: Vec<Box<dyn SweepAdapter>> = vec![
        Box::new(ClaudeAdapter),
        Box::new(CodexAdapter),
        Box::new(PiAdapter),
        Box::new(OpencodeAdapter),
        Box::new(GeminiAdapter),
    ];
    assert_eq!(adapters.len(), 5);
    for a in &adapters {
        let status = a.check_version("v0.0.0-unknown");
        assert!(
            !status.covered,
            "{:?} must report v0.0.0-unknown as uncovered",
            a.agent_id()
        );
    }

    // Each `unknown/` fixture still parses with the closest known parser and
    // reports `adapter_version_verified == false`.
    fn read_unknown(a: &dyn SweepAdapter, roots: &Roots) -> Vec<Event> {
        let found = a.sweep_discover(roots, &HashMap::new());
        assert_eq!(found.len(), 1);
        let out = a
            .sweep_read(&found[0], &Cursor::start(), FALLBACK_TS)
            .unwrap();
        assert!(
            !out.header.capture.adapter_version_verified,
            "{:?} unknown fixture must parse unverified",
            a.agent_id()
        );
        out.events
    }
    fn assert_unknown_events(a: &dyn SweepAdapter, events: &[Event]) {
        assert!(
            !events.is_empty(),
            "{:?} unknown fixture parsed empty",
            a.agent_id()
        );
        assert_eq!(kind_name(&events[0].kind), "user_message");
        assert_eq!(user_text(&events[0]), "Help me refactor the auth module.");
        assert_seqs_contiguous(events);
    }

    let (_tmp, roots) = setup_claude("unknown");
    let events = read_unknown(adapters[0].as_ref(), &roots);
    assert_unknown_events(adapters[0].as_ref(), &events);

    let (_tmp, roots) = setup_codex("unknown");
    let events = read_unknown(adapters[1].as_ref(), &roots);
    assert_unknown_events(adapters[1].as_ref(), &events);

    let (_tmp, roots) = setup_pi("unknown");
    let events = read_unknown(adapters[2].as_ref(), &roots);
    assert_unknown_events(adapters[2].as_ref(), &events);

    let (_tmp, roots, _db) = setup_opencode_db("unknown");
    let events = read_unknown(adapters[3].as_ref(), &roots);
    assert_unknown_events(adapters[3].as_ref(), &events);

    let (_tmp, roots) = setup_gemini("unknown");
    let events = read_unknown(adapters[4].as_ref(), &roots);
    assert_unknown_events(adapters[4].as_ref(), &events);
}
