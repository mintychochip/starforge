//! GAP A ingest tests: discover → read → redact → spool.
//!
//! A fixture Pi transcript is placed under a temp home; `ingest` must redact
//! secrets into the spool (segments + raw + fingerprint), a second ingest
//! with no native growth must write nothing new, and re-discovery must map to
//! the same ULID. No network, no real `$HOME`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use starforge_capture::Roots;
use starforge_cli::config::CliPaths;
use starforge_cli::git::common_dir;
use starforge_cli::ingest::ingest;
use starforge_cli::queue::{QueueOp, read_queue};
use starforge_cli::spool::Spool;
use tempfile::TempDir;

fn git_ok(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init"]);
    git_ok(&repo, &["config", "user.email", "t@t.t"]);
    git_ok(&repo, &["config", "user.name", "t"]);
    git_ok(&repo, &["commit", "--allow-empty", "-m", "init"]);
    (dir, repo)
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi-session.jsonl")
}

/// The Pi fixture with every `/work/repo` cwd/file path rewritten to the
/// test repo, so discovery (which only captures sessions whose cwd lies
/// inside the repo) sees it.
fn fixture_body(repo: &Path) -> String {
    std::fs::read_to_string(fixture_path())
        .unwrap()
        .replace("/work/repo", &repo.to_string_lossy())
}

fn write_fixture(repo: &Path, dest: &Path) {
    std::fs::write(dest, fixture_body(repo)).unwrap();
}

fn parse_now(s: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
}

#[test]
fn ingest_redacts_seed_spool_and_records_fingerprint() {
    let (_repo_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let _paths = CliPaths::from_home(home.path().to_path_buf());
    // Native Pi session under the fake home (Pi store layout).
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    write_fixture(&repo, &store.join("pi-ingest-1.jsonl"));

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = BTreeMap::from([(
        "pi".to_string(),
        Roots {
            config_dir: home.path().join(".config"),
            data_dir: home.path().to_path_buf(),
            worktree: repo.clone(),
        },
    )]);
    let now = parse_now("2026-11-04T00:00:00Z");
    let stats = ingest(&spool, &roots, &repo, now).unwrap();
    assert_eq!(stats.sessions, 1, "one native session seen");
    assert!(stats.new_events >= 3, "fixture yields 3+ events");
    assert_eq!(stats.new_segments, 1, "one segment written");
    assert!(stats.enqueued >= 2, "meta + segment queued: {stats:?}");

    // Exactly one spooled session.
    let mut ulids = Vec::new();
    for entry in std::fs::read_dir(spool.root.join("sessions")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            ulids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    assert_eq!(ulids.len(), 1, "one spool session: {ulids:?}");
    let ulid = ulids[0].clone();
    ulid::Ulid::from_str(&ulid).expect("session dir is a ULID");
    use std::str::FromStr as _;

    // Cursor record maps back to the same ULID.
    let records = spool.cursor_records().unwrap();
    assert_eq!(records.len(), 1, "one cursor record: {records:?}");
    let rec = records.values().next().unwrap();
    assert_eq!(rec.ulid, ulid, "re-discovery maps to the same ULID");

    // Segments carry redacted events, never the planted secret.
    let seg_bytes = spool.segment_bytes(&ulid, 0).unwrap();
    let seg_text = String::from_utf8(starforge_format::decompress(&seg_bytes).unwrap()).unwrap();
    assert!(!seg_text.contains("ghp_"), "segment must be redacted");
    assert!(
        seg_text.contains("[redacted:known-token]"),
        "segment must carry the marker: {seg_text:?}"
    );

    // Raw native slice is redacted too.
    let raw_bytes = spool.raw_bytes(&ulid, 0).unwrap();
    let raw_text = String::from_utf8(starforge_format::decompress(&raw_bytes).unwrap()).unwrap();
    assert!(!raw_text.contains("ghp_"), "raw slice must be redacted");

    // Fingerprint recorded on the meta.
    let (rules, _) = Spool::load_rules(&repo).unwrap();
    let expected_fp = starforge_redact::fingerprint(&rules);
    let meta = spool.read_meta(&ulid).unwrap();
    assert_eq!(meta.redaction.fingerprint, expected_fp);
    assert!(
        meta.redaction
            .counts
            .get("known-token")
            .copied()
            .unwrap_or(0)
            >= 1,
        "counts: {:?}",
        meta.redaction.counts
    );
    // The 24 h idle rule fired: fixture events are older than `now`.
    assert!(meta.ended_at.is_some(), "ended_at set by the idle rule");

    // Queue holds Meta + Segment (+ Complete, since ended).
    let queue = read_queue(&spool).unwrap();
    let ops: Vec<(QueueOp, Option<u64>)> = queue.iter().map(|e| (e.op, e.segment)).collect();
    assert!(ops.contains(&(QueueOp::Meta, None)), "meta queued: {ops:?}");
    assert!(
        ops.contains(&(QueueOp::Segment, Some(0))),
        "segment queued: {ops:?}"
    );
    assert!(
        ops.contains(&(QueueOp::Complete, None)),
        "complete queued (ended): {ops:?}"
    );

    // Second ingest with no native growth writes nothing new.
    let snapshot_meta =
        std::fs::read(spool.root.join("sessions").join(&ulid).join("meta.json")).unwrap();
    let snapshot_seg = spool.segment_bytes(&ulid, 0).unwrap();
    let snapshot_queue = read_queue(&spool).unwrap();
    let stats2 = ingest(&spool, &roots, &repo, now).unwrap();
    assert_eq!(stats2.sessions, 0, "no new activity: {stats2:?}");
    assert_eq!(stats2.new_segments, 0);
    assert_eq!(stats2.enqueued, 0, "no duplicate queue entries");
    assert_eq!(
        std::fs::read(spool.root.join("sessions").join(&ulid).join("meta.json")).unwrap(),
        snapshot_meta,
        "meta.json unchanged"
    );
    assert_eq!(spool.segment_bytes(&ulid, 0).unwrap(), snapshot_seg);
    assert_eq!(read_queue(&spool).unwrap().len(), snapshot_queue.len());
    let records2 = spool.cursor_records().unwrap();
    assert_eq!(
        records2.values().next().unwrap().ulid,
        ulid,
        "same ULID across ingests"
    );
}

// The 24 h idle rule: an ingest at now = last record + 25 h sets
// `ended_at` to the last record's timestamp. The session's records keep
// their real timestamps (never the ingest "now"), so the rule can fire.
#[test]
fn idle_rule_ends_session_25h_after_last_record() {
    let (_repo_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let cwd = repo.to_string_lossy();
    let native = format!(
        "{{\"type\":\"session\",\"version\":3,\"id\":\"idle-1\",\"timestamp\":\"2026-10-01T12:00:00Z\",\"cwd\":\"{cwd}\",\"runtime\":{{\"version\":\"0.5.2\"}}}}\n{{\"type\":\"message\",\"id\":\"m1\",\"parentId\":null,\"timestamp\":\"2026-10-01T12:00:00Z\",\"runtime\":{{\"version\":\"0.5.2\"}},\"message\":{{\"role\":\"user\",\"content\":[{{\"type\":\"text\",\"text\":\"hello\"}}]}}}}\n"
    );
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("idle-1.jsonl"), native).unwrap();

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = BTreeMap::from([(
        "pi".to_string(),
        Roots {
            config_dir: home.path().join(".config"),
            data_dir: home.path().to_path_buf(),
            worktree: repo.clone(),
        },
    )]);
    // now = last record (2026-10-01T12:00:00Z) + 25 h.
    let stats = ingest(&spool, &roots, &repo, parse_now("2026-10-02T13:00:00Z")).unwrap();
    assert_eq!(stats.sessions, 1);
    let ulid = spool_ulid(&spool);
    let meta = spool.read_meta(&ulid).unwrap();
    assert_eq!(
        meta.ended_at.as_deref(),
        Some("2026-10-01T12:00:00Z"),
        "idle rule ends the session at the last record's timestamp"
    );
}

// Finding 1: one unreadable native file for an earlier adapter must not
// starve a later adapter's valid session. The Codex file below is not valid
// JSONL, so Codex `read` fails; the Pi session must still reach the spool.

#[test]
fn unreadable_native_file_does_not_starve_later_adapters() {
    let (_repo_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join("sessions/bad")).unwrap();
    std::fs::write(
        home.path().join("sessions/bad/rollout-1.jsonl"),
        "this is not json\n",
    )
    .unwrap();
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    write_fixture(&repo, &store.join("pi-good.jsonl"));

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    // Codex roots keep the old shared layout so its unreadable rollout is
    // still discovered (and fails) before Pi runs.
    let shared = Roots {
        config_dir: home.path().join(".config"),
        data_dir: home.path().to_path_buf(),
        worktree: repo.clone(),
    };
    let roots = BTreeMap::from([
        ("codex".to_string(), shared.clone()),
        ("pi".to_string(), shared),
    ]);

    let stats = ingest(&spool, &roots, &repo, parse_now("2026-11-04T00:00:00Z")).unwrap();
    assert_eq!(
        stats.sessions, 1,
        "only the valid Pi session counts: {stats:?}"
    );
    assert!(stats.new_events >= 3, "Pi events ingested: {stats:?}");

    let mut ulids = Vec::new();
    for entry in std::fs::read_dir(spool.root.join("sessions")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            ulids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    assert_eq!(
        ulids.len(),
        1,
        "exactly the Pi session reached the spool: {ulids:?}"
    );
    assert!(
        !spool.segment_bytes(&ulids[0], 0).unwrap().is_empty(),
        "Pi segments written"
    );
}

// Finding 2: a detector hit in the `model` field (which `redact_event`
// passes through untouched) is still scrubbed and counted: once where
// `meta.models` is redacted and once in the raw native slice.

#[test]
fn model_field_detector_hit_is_redacted_and_counted() {
    let (_repo_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let cwd = repo.to_string_lossy();
    let native = format!(
        "{{\"type\":\"session\",\"version\":3,\"id\":\"raw-only-1\",\"timestamp\":\"2026-10-01T12:00:00Z\",\"cwd\":\"{cwd}\",\"runtime\":{{\"version\":\"0.5.2\"}}}}\n{{\"type\":\"message\",\"id\":\"m1\",\"parentId\":null,\"timestamp\":\"2026-10-01T12:00:00Z\",\"runtime\":{{\"version\":\"0.5.2\"}},\"message\":{{\"role\":\"user\",\"content\":[{{\"type\":\"text\",\"text\":\"hello\"}}]}}}}\n{{\"type\":\"message\",\"id\":\"m2\",\"parentId\":\"m1\",\"timestamp\":\"2026-10-01T12:01:00Z\",\"runtime\":{{\"version\":\"0.5.2\"}},\"message\":{{\"role\":\"assistant\",\"model\":\"sk-ant-abcdefghij1234567890\",\"provider\":\"anthropic\",\"usage\":{{\"input\":1,\"output\":1,\"cacheRead\":0,\"cacheWrite\":0,\"totalTokens\":2}},\"content\":[{{\"type\":\"text\",\"text\":\"all good\"}}]}}}}\n"
    );
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("raw-only-1.jsonl"), native).unwrap();

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = BTreeMap::from([(
        "pi".to_string(),
        Roots {
            config_dir: home.path().join(".config"),
            data_dir: home.path().to_path_buf(),
            worktree: repo.clone(),
        },
    )]);

    let stats = ingest(&spool, &roots, &repo, parse_now("2026-11-04T00:00:00Z")).unwrap();
    assert_eq!(stats.sessions, 1);
    let mut ulids = Vec::new();
    for entry in std::fs::read_dir(spool.root.join("sessions")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            ulids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    assert_eq!(ulids.len(), 1);
    let meta = spool.read_meta(&ulids[0]).unwrap();
    assert_eq!(
        meta.redaction
            .counts
            .get("known-token")
            .copied()
            .unwrap_or(0),
        2,
        "model hit counted in meta.models and the raw slice: {:?}",
        meta.redaction.counts
    );
    let raw = String::from_utf8(
        starforge_format::decompress(&spool.raw_bytes(&ulids[0], 0).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(!raw.contains("sk-ant-"), "raw slice redacted");
    assert!(
        raw.contains("[redacted:known-token]"),
        "raw slice carries the marker: {raw:?}"
    );
    assert!(
        !meta.models.iter().any(|m| m.contains("sk-ant-")),
        "meta.models redacted: {:?}",
        meta.models
    );
}

// I1: credentialed remote URLs never reach the spool or `sessions show`.

#[test]
fn credentialed_remote_url_never_reaches_spool_or_show() {
    let (_repo_dir, repo) = init_repo();
    git_ok(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://deploy-user:s3cr3t@example.com/o/r.git",
        ],
    );
    let home = TempDir::new().unwrap();
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    write_fixture(&repo, &store.join("pi-cred.jsonl"));

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = BTreeMap::from([(
        "pi".to_string(),
        Roots {
            config_dir: home.path().join(".config"),
            data_dir: home.path().to_path_buf(),
            worktree: repo.clone(),
        },
    )]);
    ingest(&spool, &roots, &repo, parse_now("2026-11-04T00:00:00Z")).unwrap();

    let mut ulids = Vec::new();
    for entry in std::fs::read_dir(spool.root.join("sessions")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            ulids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    assert_eq!(ulids.len(), 1);

    let meta_bytes = std::fs::read(
        spool
            .root
            .join("sessions")
            .join(&ulids[0])
            .join("meta.json"),
    )
    .unwrap();
    let meta_text = String::from_utf8(meta_bytes).unwrap();
    assert!(!meta_text.contains("s3cr3t"), "no token in meta.json");
    assert!(!meta_text.contains("deploy-user"), "no user in meta.json");
    assert!(
        meta_text.contains("https://example.com/o/r.git"),
        "sanitized host and path preserved: {meta_text:?}"
    );

    let (out, code) = starforge_cli::commands::sessions::show(&repo, &ulids[0], false);
    assert_eq!(code, 0, "show output: {out}");
    assert!(!out.contains("s3cr3t"), "no token in show output");
    assert!(!out.contains("deploy-user"), "no user in show output");
}

// Cursor advances last: if `append_events` fails, `ingest` must return the
// error with the cursor UNCHANGED, so the next sweep replays the records
// (possible duplicates across the failed boundary are acceptable; silent
// loss is not). After repair, every event appears exactly once.
#[test]
fn spool_failure_leaves_cursor_and_replays_without_loss_or_dupes() {
    let (_repo_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    let native = store.join("pi-replay-1.jsonl");
    write_fixture(&repo, &native);

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = BTreeMap::from([(
        "pi".to_string(),
        Roots {
            config_dir: home.path().join(".config"),
            data_dir: home.path().to_path_buf(),
            worktree: repo.clone(),
        },
    )]);
    let now = parse_now("2026-11-04T00:00:00Z");

    let stats = ingest(&spool, &roots, &repo, now).unwrap();
    assert!(stats.new_events >= 3, "fixture ingested: {stats:?}");
    let records = spool.cursor_records().unwrap();
    assert_eq!(records.len(), 1, "one cursor record: {records:?}");
    let (key, rec) = records.iter().next().unwrap();
    let (key, ulid, prev_cursor) = (key.clone(), rec.ulid.clone(), rec.cursor);

    // Grow the native transcript by one record so the next sweep has work.
    let mut grown = fixture_body(&repo).into_bytes();
    grown.extend_from_slice(
        format!(
            "{{\"type\":\"message\",\"id\":\"m4\",\"parentId\":\"m3\",\"timestamp\":\"2026-10-01T12:03:00Z\",\"runtime\":{{\"version\":\"0.5.2\"}},\"message\":{{\"role\":\"assistant\",\"model\":\"pi-model-x\",\"provider\":\"anthropic\",\"usage\":{{\"input\":12,\"output\":22,\"cacheRead\":0,\"cacheWrite\":0,\"totalTokens\":34}},\"content\":[{{\"type\":\"toolCall\",\"id\":\"tool-2\",\"name\":\"Edit\",\"arguments\":{{\"file_path\":\"{}/src/main.rs\",\"edits\":2}}}}]}}}}\n",
            repo.to_string_lossy()
        )
        .as_bytes(),
    );
    std::fs::write(&native, grown).unwrap();

    // Break `append_events`: the session dir exists (no `put_session` on this
    // path), but the segments dir is parked aside behind a regular file, so
    // the segment write fails. Existing segment bytes survive via rename.
    let seg_dir = spool.root.join("sessions").join(&ulid).join("segments");
    let seg_bak = spool.root.join("sessions").join(&ulid).join("segments.bak");
    std::fs::rename(&seg_dir, &seg_bak).unwrap();
    std::fs::write(&seg_dir, b"not a dir").unwrap();

    let err = ingest(&spool, &roots, &repo, now).unwrap_err();
    let _ = err.to_string();
    let rec2 = spool
        .read_cursor(&key)
        .unwrap()
        .expect("cursor record survives the failed sweep");
    assert_eq!(rec2.ulid, ulid, "same session");
    assert_eq!(
        rec2.cursor, prev_cursor,
        "cursor unchanged after the failed sweep"
    );

    // Repair and re-run: every event appears exactly once.
    std::fs::remove_file(&seg_dir).unwrap();
    std::fs::rename(&seg_bak, &seg_dir).unwrap();
    let stats3 = ingest(&spool, &roots, &repo, now).unwrap();
    assert!(stats3.new_events >= 1, "replayed growth: {stats3:?}");

    let mut seqs = Vec::new();
    for n in 0.. {
        match spool.segment_bytes(&ulid, n) {
            Ok(bytes) => {
                let text =
                    String::from_utf8(starforge_format::decompress(&bytes).unwrap()).unwrap();
                for line in text.lines() {
                    let v: serde_json::Value = serde_json::from_str(line).unwrap();
                    seqs.push(v.get("seq").and_then(|s| s.as_u64()).unwrap());
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        seqs.len() > stats.new_events,
        "all events present: {seqs:?}"
    );
    seqs.sort_unstable();
    for (i, s) in seqs.iter().enumerate() {
        assert_eq!(
            *s, i as u64,
            "seq set is the full range, no dupes: {seqs:?}"
        );
    }
}

const OPENCODE_TOKEN: &str = "ghp_0123456789abcdef0123456789abcdef0123";

/// Build a minimal OpenCode v2 store (same schema as the capture fixtures)
/// with bound parameters (JSON payloads are never formatted into the SQL).
fn build_opencode_db(
    db: &Path,
    repo: &Path,
    title: &str,
    tool_file: &str,
    model: &str,
    version: &str,
) {
    std::fs::create_dir_all(db.parent().expect("db has parent")).unwrap();
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "CREATE TABLE project(id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL);\
         CREATE TABLE session_v2(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', parent_id TEXT, title TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, time_archived INTEGER);\
         CREATE TABLE session_message(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, type TEXT NOT NULL, seq INTEGER NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);\
         CREATE TABLE session_part(message_id TEXT NOT NULL, session_id TEXT NOT NULL, ordinal INTEGER NOT NULL, type TEXT NOT NULL, call_id TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL);",
    )
    .unwrap();
    let repo_str = repo.to_string_lossy().into_owned();
    conn.execute(
        "INSERT INTO project VALUES('p1', ?1, 1, 1)",
        rusqlite::params![repo_str],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO session_v2(id, project_id, directory, version, title, time_created, time_updated) VALUES('sess1', 'p1', ?1, ?2, ?3, 1793793600000, 1793793615000)",
        rusqlite::params![repo_str, version, title],
    )
    .unwrap();
    let user_data = serde_json::json!({"text": "hello"}).to_string();
    conn.execute(
        "INSERT INTO session_message VALUES('m1', 'sess1', 'user', 0, 1793793600000, 1793793600000, ?1)",
        rusqlite::params![user_data],
    )
    .unwrap();
    let asst_data = serde_json::json!({
        "agent": "build",
        "model": {"id": model, "providerID": "anthropic"},
        "tokens": {"input": 1, "output": 1, "reasoning": 0, "cache": {"read": 0, "write": 0}},
    })
    .to_string();
    conn.execute(
        "INSERT INTO session_message VALUES('m2', 'sess1', 'assistant', 1, 1793793605000, 1793793610000, ?1)",
        rusqlite::params![asst_data],
    )
    .unwrap();
    let part_data = serde_json::json!({
        "type": "tool",
        "id": "c1",
        "name": "edit",
        "state": {
            "status": "completed",
            "input": {"file_path": tool_file},
            "content": [{"type": "text", "text": "done"}],
        },
    })
    .to_string();
    conn.execute(
        "INSERT INTO session_part VALUES('m2', 'sess1', 0, 'tool', 'c1', 1793793605000, 1793793610000, ?1)",
        rusqlite::params![part_data],
    )
    .unwrap();
}

fn opencode_spool_root(repo: &Path) -> (TempDir, BTreeMap<String, Roots>, Spool) {
    let home = TempDir::new().unwrap();
    let _paths = CliPaths::from_home(home.path().to_path_buf());
    let common = common_dir(repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = BTreeMap::from([(
        "opencode".to_string(),
        Roots {
            config_dir: home.path().join(".config"),
            data_dir: home.path().join("data"),
            worktree: repo.to_path_buf(),
        },
    )]);
    (home, roots, spool)
}

fn spool_ulid(spool: &Spool) -> String {
    for entry in std::fs::read_dir(spool.root.join("sessions")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            return entry.file_name().to_string_lossy().into_owned();
        }
    }
    panic!("one spool session");
}

#[test]
fn opencode_title_and_file_path_are_redacted_in_meta() {
    let (_repo_dir, repo) = init_repo();
    let tool_file = format!("{}/src/{}.rs", repo.to_string_lossy(), OPENCODE_TOKEN);
    let (_home, roots, spool) = opencode_spool_root(&repo);
    build_opencode_db(
        &roots["opencode"].data_dir.join("opencode.db"),
        &repo,
        &format!("deploy key {OPENCODE_TOKEN}"),
        &tool_file,
        &format!("model-{OPENCODE_TOKEN}"),
        &format!("2.0.29-{OPENCODE_TOKEN}"),
    );
    evaluate_roots(&roots, &repo, &spool);
    let ulid = spool_ulid(&spool);
    let meta_text =
        std::fs::read_to_string(spool.root.join("sessions").join(&ulid).join("meta.json")).unwrap();
    assert!(
        !meta_text.contains(OPENCODE_TOKEN),
        "meta.json must not contain the secret: {meta_text}"
    );
    let meta = spool.read_meta(&ulid).unwrap();
    let title = meta.title.expect("title present");
    assert!(title.contains("[redacted:"), "title redacted: {title}");
    for f in &meta.files_touched {
        assert!(!f.contains(OPENCODE_TOKEN), "files_touched redacted: {f}");
    }
    assert!(
        meta.files_touched.iter().any(|f| f.contains("[redacted:")),
        "file path carries the redaction marker: {:?}",
        meta.files_touched
    );
    assert!(
        meta.models.iter().any(|m| m.contains("[redacted:")),
        "model carries the redaction marker: {:?}",
        meta.models
    );
    assert!(
        meta.agent.version.contains("[redacted:"),
        "agent version carries the redaction marker: {}",
        meta.agent.version
    );
}

#[test]
fn opencode_ingest_writes_no_raw_slices() {
    let (_repo_dir, repo) = init_repo();
    let tool_file = format!("{}/src/lib.rs", repo.to_string_lossy());
    let (_home, roots, spool) = opencode_spool_root(&repo);
    build_opencode_db(
        &roots["opencode"].data_dir.join("opencode.db"),
        &repo,
        "plain title",
        &tool_file,
        "m",
        "2.0.29",
    );
    evaluate_roots(&roots, &repo, &spool);
    let ulid = spool_ulid(&spool);
    let raw_dir = spool.root.join("sessions").join(&ulid).join("raw");
    assert!(
        !raw_dir.exists() || std::fs::read_dir(&raw_dir).unwrap().count() == 0,
        "OpenCode writes no raw slices: {}",
        raw_dir.display()
    );
}

fn evaluate_roots(roots: &BTreeMap<String, Roots>, repo: &Path, spool: &Spool) {
    let now = parse_now("2026-11-04T00:00:00Z");
    let stats = ingest(spool, roots, repo, now).unwrap();
    assert_eq!(stats.sessions, 1, "one opencode session: {stats:?}");
}
