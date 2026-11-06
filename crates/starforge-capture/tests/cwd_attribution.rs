//! Working-directory attribution tests (privacy rule).
//!
//! A session whose `cwd` is unknown (missing or empty) must NEVER be
//! discovered for an unrelated worktree, and a session whose `cwd` lies
//! outside the worktree must not be discovered either. Gemini CLI is
//! the one exception: a `cwd`-less chat under `tmp/<project_hash>/`
//! is attributed when `<project_hash>` is the sha256 of the worktree
//! path string. Pi's `cwd` lives in the `{"type":"session"}`
//! header record (first line).
//!
//! All stores are tempdirs; nothing here touches `$HOME`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::Digest as _;
use starforge_capture::agents::{ClaudeAdapter, CodexAdapter, GeminiAdapter, PiAdapter};
use starforge_capture::{Adapter, Roots};

const WORKTREE: &str = "/repo";

fn roots_for(data_dir: &Path) -> Roots {
    Roots {
        config_dir: data_dir.join("config"),
        data_dir: data_dir.to_path_buf(),
        worktree: PathBuf::from(WORKTREE),
    }
}

fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().expect("file has parent")).unwrap();
    std::fs::write(path, body).unwrap();
}

fn worktree_hash() -> String {
    let mut h = sha2::Sha256::new();
    h.update(WORKTREE.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Claude Code: `<data>/projects/<slug>/<file>.jsonl`.
fn claude_case(body: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("data/projects/slug/session.jsonl"), body);
    let roots = roots_for(&tmp.path().join("data"));
    (tmp, roots)
}

/// Codex CLI: `<data>/sessions/<date>/rollout-<file>.jsonl` (recursive).
fn codex_case(body: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("data/sessions/2026/11/04/rollout-1.jsonl"),
        body,
    );
    let roots = roots_for(&tmp.path().join("data"));
    (tmp, roots)
}

/// Gemini CLI: `<data>/tmp/<hash>/chats/<file>.json`.
fn gemini_case(hash: &str, body: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join(format!("data/tmp/{hash}/chats/chat.json")),
        body,
    );
    let roots = roots_for(&tmp.path().join("data"));
    (tmp, roots)
}

/// Pi: `<data>/.pi/agent/sessions/<slug>/<file>.jsonl` (recursive).
fn pi_case(body: &str) -> (tempfile::TempDir, Roots) {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path()
            .join("data/.pi/agent/sessions/slug/session.jsonl"),
        body,
    );
    let roots = roots_for(&tmp.path().join("data"));
    (tmp, roots)
}

// --- Claude Code -----------------------------------------------------------

#[test]
fn claude_cwd_less_session_is_not_discovered() {
    let body = "{\"type\":\"user\",\"timestamp\":\"2026-11-04T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = claude_case(body);
    assert!(ClaudeAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn claude_empty_cwd_session_is_not_discovered() {
    let body = "{\"type\":\"user\",\"cwd\":\"\",\"timestamp\":\"2026-11-04T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = claude_case(body);
    assert!(ClaudeAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn claude_outside_cwd_session_is_not_discovered() {
    let body = "{\"type\":\"user\",\"cwd\":\"/elsewhere\",\"timestamp\":\"2026-11-04T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = claude_case(body);
    assert!(ClaudeAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn claude_inside_cwd_session_is_discovered() {
    let body = "{\"type\":\"user\",\"cwd\":\"/repo/sub\",\"timestamp\":\"2026-11-04T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = claude_case(body);
    let found = ClaudeAdapter.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].workdir, PathBuf::from("/repo/sub"));
}

// --- Codex CLI -------------------------------------------------------------

#[test]
fn codex_cwd_less_session_is_not_discovered() {
    let body = "{\"type\":\"prompt\",\"text\":\"hi\",\"timestamp\":\"2026-11-04T12:00:00Z\"}\n";
    let (_tmp, roots) = codex_case(body);
    assert!(CodexAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn codex_empty_cwd_session_is_not_discovered() {
    let body = "{\"type\":\"prompt\",\"cwd\":\"\",\"text\":\"hi\"}\n";
    let (_tmp, roots) = codex_case(body);
    assert!(CodexAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn codex_outside_cwd_session_is_not_discovered() {
    let body = "{\"type\":\"prompt\",\"cwd\":\"/elsewhere\",\"text\":\"hi\"}\n";
    let (_tmp, roots) = codex_case(body);
    assert!(CodexAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn codex_inside_cwd_session_is_discovered() {
    let body = "{\"type\":\"prompt\",\"cwd\":\"/repo\",\"text\":\"hi\"}\n";
    let (_tmp, roots) = codex_case(body);
    assert_eq!(CodexAdapter.discover(&roots, &HashMap::new()).len(), 1);
}

// --- Gemini CLI ------------------------------------------------------------

const GEMINI_NO_CWD: &str = "{\"sessionId\":\"01ARZ3NDEKTSV4RRFFQ69G5FB1\",\"version\":\"0.12.0\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\",\"timestamp\":\"2026-11-04T12:00:00Z\"}]}";

#[test]
fn gemini_cwd_less_chat_under_wrong_hash_is_not_discovered() {
    let (_tmp, roots) = gemini_case(
        "0000000000000000000000000000000000000000000000000000000000000000",
        GEMINI_NO_CWD,
    );
    assert!(GeminiAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn gemini_cwd_less_chat_under_worktree_hash_is_discovered() {
    let (_tmp, roots) = gemini_case(&worktree_hash(), GEMINI_NO_CWD);
    let found = GeminiAdapter.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].workdir, PathBuf::from(WORKTREE));
}

#[test]
fn gemini_empty_cwd_chat_under_wrong_hash_is_not_discovered() {
    let body = "{\"sessionId\":\"01ARZ3NDEKTSV4RRFFQ69G5FB1\",\"version\":\"0.12.0\",\"cwd\":\"\",\"messages\":[]}";
    let (_tmp, roots) = gemini_case(
        "0000000000000000000000000000000000000000000000000000000000000000",
        body,
    );
    assert!(GeminiAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn gemini_outside_cwd_chat_is_not_discovered() {
    let body = "{\"sessionId\":\"01ARZ3NDEKTSV4RRFFQ69G5FB1\",\"version\":\"0.12.0\",\"cwd\":\"/elsewhere\",\"messages\":[]}";
    let (_tmp, roots) = gemini_case(&worktree_hash(), body);
    assert!(GeminiAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn gemini_inside_cwd_chat_is_discovered_any_hash() {
    let body = "{\"sessionId\":\"01ARZ3NDEKTSV4RRFFQ69G5FB1\",\"version\":\"0.12.0\",\"cwd\":\"/repo/sub\",\"messages\":[]}";
    let (_tmp, roots) = gemini_case(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        body,
    );
    assert_eq!(GeminiAdapter.discover(&roots, &HashMap::new()).len(), 1);
}

// --- Pi (and omp) ----------------------------------------------------------

#[test]
fn pi_cwd_less_session_is_not_discovered() {
    let body = "{\"type\":\"message\",\"timestamp\":\"2026-11-04T12:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = pi_case(body);
    assert!(PiAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn pi_empty_header_cwd_session_is_not_discovered() {
    // Old Pi sessions carry an empty header cwd: unknown, so skipped.
    let body = "{\"type\":\"session\",\"version\":3,\"id\":\"uuid\",\"timestamp\":\"2024-12-03T14:00:00.000Z\",\"cwd\":\"\"}\n{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = pi_case(body);
    assert!(PiAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn pi_header_cwd_session_is_discovered() {
    let body = "{\"type\":\"session\",\"version\":3,\"id\":\"uuid\",\"timestamp\":\"2024-12-03T14:00:00.000Z\",\"cwd\":\"/repo\"}\n{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = pi_case(body);
    let found = PiAdapter.discover(&roots, &HashMap::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].workdir, PathBuf::from(WORKTREE));
}

#[test]
fn pi_outside_cwd_session_is_not_discovered() {
    let body = "{\"type\":\"session\",\"version\":3,\"id\":\"uuid\",\"timestamp\":\"2024-12-03T14:00:00.000Z\",\"cwd\":\"/elsewhere\"}\n{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = pi_case(body);
    assert!(PiAdapter.discover(&roots, &HashMap::new()).is_empty());
}

#[test]
fn pi_per_record_cwd_session_is_discovered() {
    // omp shape: no public spec; per-record cwd is accepted.
    let body = "{\"type\":\"message\",\"cwd\":\"/repo/sub\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n";
    let (_tmp, roots) = pi_case(body);
    assert_eq!(PiAdapter.discover(&roots, &HashMap::new()).len(), 1);
}
