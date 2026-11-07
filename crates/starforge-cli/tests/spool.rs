//! C4 spool tests (TDD RED first): local spool with redaction + segmentation.
//!
//! Tempdirs stand in for the git common dir; events come from the real
//! `PiAdapter` reading `tests/fixtures/pi-session.jsonl`. No network.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use starforge_capture::agents::pi::PiAdapter;
use starforge_capture::{Adapter, Candidate, Cursor};
use starforge_cli::queue::{
    QueueEntry, QueueOp, backoff_due, dequeue_ready, enqueue, mark_attempt, read_queue,
};
use starforge_cli::spool::{LinkConfidence, LinkEntry, LinkSource, Spool};
use starforge_format::{DEFAULT_SEGMENT_CAP, SessionMeta, assemble};
use starforge_redact::{RuleSet, fingerprint, redact_event, redact_text};
use tempfile::TempDir;

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi-session.jsonl")
}

fn open_spool() -> (TempDir, Spool) {
    let dir = TempDir::new().unwrap();
    let spool = Spool::open(dir.path());
    spool.ensure_layout().unwrap();
    (dir, spool)
}

/// Real adapter events from the fixture plus the raw native text.
fn fixture_events() -> (Vec<starforge_format::Event>, SessionMeta, String) {
    let native = fixture_path();
    let candidate = Candidate {
        session_key: "pi-test".to_string(),
        native_path: native.clone(),
        agent_version: String::new(),
        workdir: PathBuf::from("/work/repo"),
        parent_session_key: None,
    };
    let adapter = PiAdapter;
    let out = adapter
        .read(&candidate, &Cursor::start(), "2026-10-01T12:03:00Z")
        .unwrap();
    let raw = std::fs::read_to_string(&native).unwrap();
    (out.events, out.header, raw)
}

/// Redact every event, returning the normalized JSONL plus accumulated counts.
fn redacted_jsonl(
    compiled: &starforge_redact::Compiled,
    events: &[starforge_format::Event],
) -> (String, BTreeMap<String, u64>) {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut lines = Vec::with_capacity(events.len());
    for event in events {
        let (redacted, c) = redact_event(compiled, event);
        for (k, v) in c {
            *counts.entry(k).or_insert(0) += v;
        }
        lines.push(serde_json::to_string(&redacted).unwrap());
    }
    (lines.join("\n") + "\n", counts)
}

fn test_meta(header: SessionMeta, fingerprint: &str, counts: BTreeMap<String, u64>) -> SessionMeta {
    let mut meta = header;
    meta.id = ulid::Ulid::new();
    meta.repo = starforge_format::RepoInfo {
        remote_urls: vec!["https://example.com/repo".to_string()],
        branch: "main".to_string(),
        head_at_start: "abc123".to_string(),
    };
    meta.capture.cli_version = "test".to_string();
    meta.redaction = starforge_format::RedactionSummary {
        fingerprint: fingerprint.to_string(),
        counts,
    };
    meta
}

fn queue_entry(op: QueueOp, ulid: &str, segment: Option<u64>, not_before: &str) -> QueueEntry {
    QueueEntry {
        op,
        ulid: ulid.to_string(),
        repo: "https://example.com/repo".to_string(),
        segment,
        attempts: 0,
        not_before: not_before.to_string(),
    }
}

#[test]
fn ensure_layout_creates_every_path_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let spool = Spool::open(dir.path());
    spool.ensure_layout().unwrap();

    assert!(spool.root.join("sessions").is_dir());
    assert!(spool.root.join("cursors.json").is_file());
    assert!(spool.root.join("links.jsonl").is_file());
    assert!(spool.root.join("queue.jsonl").is_file());

    let cursors: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(spool.root.join("cursors.json")).unwrap())
            .unwrap();
    assert_eq!(cursors, serde_json::json!({"sessions": {}}));

    // Idempotent: seeded state survives a second run (files are not truncated).
    enqueue(
        &spool,
        queue_entry(
            QueueOp::Meta,
            "01J9KQXF1T3NP2R8A5B6C7D9E0",
            None,
            "2026-01-01T00:00:00Z",
        ),
    )
    .unwrap();
    spool.ensure_layout().unwrap();
    assert_eq!(read_queue(&spool).unwrap().len(), 1);
}

/// Spool dirs are `0700` and files `0600` on unix; a pre-existing leaky
/// root is tightened by `ensure_layout`.
#[cfg(unix)]
#[test]
fn spool_layout_is_private_on_unix() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new().unwrap();
    // Pre-create a leaky root to prove tightening.
    let root = dir.path().join("starforge");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let spool = Spool::open(dir.path());
    spool.ensure_layout().unwrap();
    assert_eq!(
        std::fs::metadata(&spool.root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(spool.root.join("sessions"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for name in ["cursors.json", "links.jsonl", "queue.jsonl"] {
        assert_eq!(
            std::fs::metadata(spool.root.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{name}"
        );
    }
    // Session dirs and files are private too.
    let ulid = ulid::Ulid::new().to_string();
    let mut meta = test_meta(fixture_events().1, "fp", BTreeMap::new());
    meta.id = ulid.parse().unwrap();
    spool.put_session(&meta).unwrap();
    let session = spool.root.join("sessions").join(&ulid);
    assert_eq!(
        std::fs::metadata(&session).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(session.join("meta.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

/// Older per-session contents (written before the permissions fix) are
/// tightened recursively by `ensure_layout`: a `0755` session dir and a
/// `0644` segment file become `0700`/`0600`.
#[cfg(unix)]
#[test]
fn ensure_layout_tightens_legacy_session_contents() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new().unwrap();
    let spool = Spool::open(dir.path());
    let ulid = ulid::Ulid::new().to_string();
    let session = spool.root.join("sessions").join(&ulid);
    let segments = session.join("segments");
    std::fs::create_dir_all(&segments).unwrap();
    let seg = segments.join("0.jsonl.zst");
    std::fs::write(&seg, b"legacy").unwrap();
    std::fs::write(session.join("meta.json"), b"{}").unwrap();
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&segments, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(
        session.join("meta.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    spool.ensure_layout().unwrap();
    assert_eq!(
        std::fs::metadata(&session).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&segments).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&seg).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(session.join("meta.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

/// A `queue.jsonl` that was deleted and is recreated by `enqueue` is
/// created `0600` on unix.
#[cfg(unix)]
#[test]
fn enqueue_recreates_queue_private_on_unix() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, spool) = open_spool();
    std::fs::remove_file(spool.root.join("queue.jsonl")).unwrap();
    enqueue(
        &spool,
        queue_entry(
            QueueOp::Meta,
            "01J9KQXF1T3NP2R8A5B6C7D9E0",
            None,
            "2026-01-01T00:00:00Z",
        ),
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(spool.root.join("queue.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn planted_token_absent_from_segments_and_raw_with_counts_and_fingerprint() {
    let (repo_tmp, spool) = open_spool();
    let repo = repo_tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();

    // Missing repo file is fine: rules are exactly the built-ins.
    let (rules, compiled) = Spool::load_rules(&repo).unwrap();
    let expected_fp = fingerprint(&RuleSet::built_in());
    assert_eq!(fingerprint(&rules), expected_fp);

    let (events, header, raw_native) = fixture_events();
    assert!(events.len() >= 3, "fixture must yield 3+ events");
    assert_eq!(header.agent.name, starforge_format::AgentName::Pi);
    assert!(
        PiAdapter::COVERED.contains(&header.agent.version.as_str()),
        "fixture version must stay covered: {}",
        header.agent.version
    );

    let (jsonl, counts) = redacted_jsonl(&compiled, &events);
    assert!(!jsonl.contains("ghp_"), "normalized JSONL must be redacted");

    let meta = test_meta(header, &expected_fp, counts.clone());
    spool.put_session(&meta).unwrap();
    let ulid = meta.id.to_string();

    let segments = spool
        .append_events(&ulid, &jsonl, DEFAULT_SEGMENT_CAP, &counts)
        .unwrap();
    assert_eq!(segments, vec![0]);

    // Raw native slice redacted as plain text, same segment numbering.
    let mut raw_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut raw_lines = Vec::new();
    for line in raw_native.lines() {
        let (out, c) = redact_text(&compiled, line);
        for (k, v) in c {
            *raw_counts.entry(k).or_insert(0) += v;
        }
        raw_lines.push(out);
    }
    let redacted_raw = raw_lines.join("\n") + "\n";
    spool.write_raw(&ulid, 0, redacted_raw.as_bytes()).unwrap();

    // Segment bytes: decompress, then the secret must be gone.
    let seg_bytes = spool.segment_bytes(&ulid, 0).unwrap();
    let seg_text = String::from_utf8(starforge_format::decompress(&seg_bytes).unwrap()).unwrap();
    assert!(
        !seg_text.contains("ghp_"),
        "segment must not contain the token"
    );
    assert!(
        seg_text.contains("[redacted:known-token]"),
        "segment must carry the redaction marker"
    );

    // Raw bytes: same guarantee.
    let raw_bytes = spool.raw_bytes(&ulid, 0).unwrap();
    let raw_text = String::from_utf8(starforge_format::decompress(&raw_bytes).unwrap()).unwrap();
    assert!(
        !raw_text.contains("ghp_"),
        "raw slice must not contain the token"
    );

    // meta.json on disk carries the fingerprint and the known-token count.
    let stored = spool.read_meta(&ulid).unwrap();
    assert_eq!(stored.redaction.fingerprint, expected_fp);
    assert!(
        stored
            .redaction
            .counts
            .get("known-token")
            .copied()
            .unwrap_or(0)
            >= 1,
        "counts: {:?}",
        stored.redaction.counts
    );
    assert_eq!(stored.agent.name, starforge_format::AgentName::Pi);
}

#[test]
fn segments_split_at_cap_and_assemble_round_trips() {
    let (_tmp, spool) = open_spool();
    let (events, header, _) = fixture_events();
    let (_, compiled) = Spool::load_rules(Path::new("/nonexistent-repo")).unwrap();
    let (one_batch, _) = redacted_jsonl(&compiled, &events);
    let jsonl = one_batch.repeat(4);

    let meta = test_meta(header, &fingerprint(&RuleSet::built_in()), BTreeMap::new());
    spool.put_session(&meta).unwrap();
    let ulid = meta.id.to_string();

    let nums = spool
        .append_events(&ulid, &jsonl, 128, &BTreeMap::new())
        .unwrap();
    assert!(nums.len() >= 2, "cap 128 must force a split: {nums:?}");
    let expected: Vec<u64> = (0..nums.len() as u64).collect();
    assert_eq!(nums, expected);

    let blobs: Vec<Vec<u8>> = nums
        .iter()
        .map(|n| spool.segment_bytes(&ulid, *n).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    assert_eq!(assemble(&refs).unwrap(), jsonl);

    // Segment identity lands in upload.json via its blake3 hash.
    for n in &nums {
        spool.mark_segment_uploaded(&ulid, *n).unwrap();
    }
    let upload = spool.read_upload(&ulid).unwrap();
    assert!(!upload.complete);
    for (i, n) in nums.iter().enumerate() {
        assert_eq!(
            upload.uploaded_segments.get(n).unwrap(),
            &starforge_format::blake3_hex(&blobs[i])
        );
    }
}

#[test]
fn appending_twice_continues_numbering_and_preserves_prior_bytes() {
    let (_tmp, spool) = open_spool();
    let (events, header, _) = fixture_events();
    let (_, compiled) = Spool::load_rules(Path::new("/nonexistent-repo")).unwrap();
    let (jsonl, counts) = redacted_jsonl(&compiled, &events);

    let meta = test_meta(header, &fingerprint(&RuleSet::built_in()), BTreeMap::new());
    spool.put_session(&meta).unwrap();
    let ulid = meta.id.to_string();

    let first = spool
        .append_events(&ulid, &jsonl, DEFAULT_SEGMENT_CAP, &counts)
        .unwrap();
    assert_eq!(first, vec![0]);
    let snapshot = spool.segment_bytes(&ulid, 0).unwrap();

    let second = spool
        .append_events(&ulid, &jsonl, DEFAULT_SEGMENT_CAP, &counts)
        .unwrap();
    assert_eq!(second, vec![1]);
    assert_eq!(
        spool.segment_bytes(&ulid, 0).unwrap(),
        snapshot,
        "prior segments are immutable"
    );

    let all: Vec<Vec<u8>> = [0, 1]
        .iter()
        .map(|n| spool.segment_bytes(&ulid, *n).unwrap())
        .collect();
    let refs: Vec<&[u8]> = all.iter().map(Vec::as_slice).collect();
    assert_eq!(assemble(&refs).unwrap(), format!("{jsonl}{jsonl}"));

    // Counts accumulate across appends.
    let stored = spool.read_meta(&ulid).unwrap();
    for (k, v) in &counts {
        assert_eq!(stored.redaction.counts.get(k), Some(&(v * 2)));
    }
}

#[test]
fn cursors_round_trip_cursor_shape_and_unknown_key_is_absent() {
    let (_tmp, spool) = open_spool();
    let ulid = ulid::Ulid::new().to_string();
    let cursor = Cursor {
        offset: 690,
        lines: 3,
        events: 3,
    };
    spool
        .write_cursor(
            "pi/pi-test",
            &ulid,
            cursor,
            "/tmp/x/sessions/pi-test.jsonl",
            None,
            None,
        )
        .unwrap();

    let rec = spool.read_cursor("pi/pi-test").unwrap().expect("stored");
    assert_eq!(rec.cursor, cursor);
    assert_eq!(rec.ulid, ulid);
    assert!(spool.read_cursor("pi/unknown").unwrap().is_none());

    // On-disk shape nests the Cursor serde form under the agent/session key.
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(spool.root.join("cursors.json")).unwrap())
            .unwrap();
    assert_eq!(
        file["sessions"]["pi/pi-test"]["cursor"],
        serde_json::json!({"offset": 690, "lines": 3, "events": 3})
    );
}

#[test]
fn queue_survives_crash_partial_line_and_rewrite_is_atomic() {
    let (_tmp, spool) = open_spool();
    let ulid = ulid::Ulid::new().to_string();
    enqueue(
        &spool,
        queue_entry(QueueOp::Segment, &ulid, Some(0), "2026-01-01T00:00:00Z"),
    )
    .unwrap();
    enqueue(
        &spool,
        queue_entry(QueueOp::Complete, &ulid, None, "2026-01-01T00:00:00Z"),
    )
    .unwrap();

    // Crash-simulated partial file: a garbage line is skipped, not fatal.
    std::fs::write(
        spool.root.join("queue.jsonl"),
        format!(
            "{}{}",
            std::fs::read_to_string(spool.root.join("queue.jsonl")).unwrap(),
            "this is not json\n"
        ),
    )
    .unwrap();
    let entries = read_queue(&spool).unwrap();
    assert_eq!(entries.len(), 2);

    // Pure backoff predicate on RFC 3339 strings.
    assert!(backoff_due(&entries[0], "2026-01-01T00:00:01Z"));
    assert!(!backoff_due(&entries[0], "2025-12-31T23:59:59Z"));

    // Dequeue rewrites the file, dropping the garbage line too.
    let due = dequeue_ready(&spool, "2026-06-01T00:00:00Z").unwrap();
    assert_eq!(due.len(), 2);
    assert!(read_queue(&spool).unwrap().is_empty());
    assert!(
        dequeue_ready(&spool, "2026-06-01T00:00:00Z")
            .unwrap()
            .is_empty()
    );

    // mark_attempt bumps attempts and pushes not_before out by 2^attempts.
    enqueue(
        &spool,
        queue_entry(QueueOp::Segment, &ulid, Some(1), "2026-01-01T00:00:00Z"),
    )
    .unwrap();
    assert!(mark_attempt(&spool, QueueOp::Segment, &ulid, Some(1)).unwrap());
    assert!(!mark_attempt(&spool, QueueOp::Segment, &ulid, Some(9)).unwrap());
    let after = read_queue(&spool).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].attempts, 1);
    assert_eq!(after[0].not_before, "2026-01-01T00:00:02Z");
    assert!(!backoff_due(&after[0], "2026-01-01T00:00:01Z"));
    assert!(backoff_due(&after[0], "2026-01-01T00:00:02Z"));
}

#[test]
fn links_append_one_json_object_per_line() {
    let (_tmp, spool) = open_spool();
    let ulid_a = ulid::Ulid::new().to_string();
    let ulid_b = ulid::Ulid::new().to_string();
    let link = |ulid: &str| LinkEntry {
        ulid: ulid.to_string(),
        commit: "abc123".to_string(),
        source: LinkSource::Trailer,
        confidence: LinkConfidence::Exact,
        seq_start: 0,
        seq_end: 3,
    };
    spool.record_link(&link(&ulid_a)).unwrap();
    spool
        .record_link(&LinkEntry {
            ulid: ulid_b.clone(),
            commit: "def456".to_string(),
            source: LinkSource::CliClaim,
            confidence: LinkConfidence::Heuristic,
            seq_start: 3,
            seq_end: 5,
        })
        .unwrap();

    let text = std::fs::read_to_string(spool.root.join("links.jsonl")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v.is_object());
        for key in [
            "ulid",
            "commit",
            "source",
            "confidence",
            "seq_start",
            "seq_end",
        ] {
            assert!(v.get(key).is_some(), "link line missing {key}: {line}");
        }
    }
    let stored = spool.links().unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].ulid, ulid_a);
    assert_eq!(stored[1].ulid, ulid_b);
}

#[test]
fn load_rules_merges_repo_file_and_missing_file_is_builtin() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("no-repo-here");
    let (rules, _) = Spool::load_rules(&missing).unwrap();
    assert_eq!(fingerprint(&rules), fingerprint(&RuleSet::built_in()));

    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(repo.join(".starforge")).unwrap();
    std::fs::write(
        repo.join(".starforge/redact.toml"),
        "[[pattern]]\nid = \"local\"\nregex = \"s3cr3t-[a-z]+\"\n",
    )
    .unwrap();
    let (merged, compiled) = Spool::load_rules(&repo).unwrap();
    assert_ne!(fingerprint(&merged), fingerprint(&RuleSet::built_in()));
    let (out, counts) = redact_text(&compiled, "key s3cr3t-abc here");
    assert!(
        !out.contains("s3cr3t-abc"),
        "custom pattern must redact: {out}"
    );
    assert_eq!(counts.get("local"), Some(&1));
}
// ---------------------------------------------------------------------------
// spool prune: only fully uploaded, completed, old sessions lose blobs.
// ---------------------------------------------------------------------------

fn prune_now() -> time::OffsetDateTime {
    time::OffsetDateTime::parse(
        "2026-11-06T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
}

/// Seed one spooled session with segments + a raw slice; returns
/// `(ulid, cursor_key)`. When `complete` is true, `upload.json` records the
/// server's acknowledgement (segments + meta hash + `complete`).
fn seed_spool_session(spool: &Spool, ended_at: Option<&str>, complete: bool) -> (String, String) {
    let (events, header, raw) = fixture_events();
    let (rules, compiled) = Spool::load_rules(Path::new("/nonexistent-repo")).unwrap();
    let (jsonl, counts) = redacted_jsonl(&compiled, &events);
    let mut meta = test_meta(header, &fingerprint(&rules), counts);
    meta.ended_at = ended_at.map(str::to_string);
    let ulid = meta.id.to_string();
    spool.put_session(&meta).unwrap();
    let nums = spool
        .append_events(&ulid, &jsonl, DEFAULT_SEGMENT_CAP, &BTreeMap::new())
        .unwrap();
    assert!(!nums.is_empty());
    spool.write_raw(&ulid, nums[0], raw.as_bytes()).unwrap();
    for &n in &nums {
        spool.mark_segment_uploaded(&ulid, n).unwrap();
    }
    spool
        .mark_meta_uploaded(&ulid, starforge_cli::spool::meta_body_hash(&meta).unwrap())
        .unwrap();
    if complete {
        let mut state = spool.read_upload(&ulid).unwrap();
        state.complete = true;
        std::fs::write(
            spool.root.join("sessions").join(&ulid).join("upload.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
    }
    let key = format!("pi/test-{ulid}");
    spool
        .write_cursor(&key, &ulid, Cursor::start(), "/native/path", None, None)
        .unwrap();
    (ulid, key)
}

#[test]
fn prune_deletes_only_eligible_blobs_and_keeps_meta_upload_and_cursor() {
    let (_tmp, spool) = open_spool();
    let (old, old_key) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    let (recent, _) = seed_spool_session(&spool, Some("2026-11-05T00:00:00Z"), true);
    let (incomplete, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), false);

    let candidates = spool.prune_candidates(prune_now(), 30).unwrap();
    let ulids: Vec<&str> = candidates.iter().map(|c| c.ulid.as_str()).collect();
    assert_eq!(
        ulids,
        vec![old.as_str()],
        "only the old completed session: {candidates:?}"
    );
    assert!(candidates[0].bytes > 0);

    let freed = spool
        .prune_session(&old)
        .unwrap()
        .expect("eligible session prunes");
    assert_eq!(freed, candidates[0].bytes);

    let dir = spool.root.join("sessions").join(&old);
    assert!(!dir.join("segments").exists(), "segments dir pruned");
    assert!(!dir.join("raw").exists(), "raw dir pruned");
    assert!(dir.join("meta.json").is_file(), "meta survives");
    assert!(dir.join("upload.json").is_file(), "upload state survives");
    let state = spool.read_upload(&old).unwrap();
    assert!(state.complete);
    assert!(
        !state.uploaded_segments.is_empty(),
        "uploaded record survives"
    );
    assert!(spool.read_meta(&old).is_ok(), "meta still readable");
    assert!(spool.is_pruned(&old));

    // The ineligible sessions keep their blobs.
    for other in [&recent, &incomplete] {
        let dir = spool.root.join("sessions").join(other);
        assert!(dir.join("segments").is_dir(), "{other} segments kept");
        assert!(dir.join("raw").is_dir(), "{other} raw kept");
        assert!(!spool.is_pruned(other));
    }

    // Cursor record survives: re-ingest of the same native file reuses `old`.
    let rec = spool
        .read_cursor(&old_key)
        .unwrap()
        .expect("cursor survives");
    assert_eq!(rec.ulid, old, "cursor still names the pruned session");
}

#[test]
fn prune_candidates_dry_run_deletes_nothing() {
    // The command's `--dry-run` path only scans: computing candidates must
    // leave every blob on disk.
    let (_tmp, spool) = open_spool();
    let (old, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    let dir = spool.root.join("sessions").join(&old);
    let before = spool.session_data_bytes(&old);
    let candidates = spool.prune_candidates(prune_now(), 30).unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(dir.join("segments").is_dir());
    assert!(dir.join("raw").is_dir());
    assert_eq!(spool.session_data_bytes(&old), before);
    assert!(!spool.is_pruned(&old));
}

#[test]
fn prune_never_touches_unuploaded_or_queued_sessions() {
    let (_tmp, spool) = open_spool();
    // Segment never marked uploaded (meta uploaded + complete): ineligible.
    let (unuploaded, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    let mut state = spool.read_upload(&unuploaded).unwrap();
    state.uploaded_segments.clear();
    std::fs::write(
        spool
            .root
            .join("sessions")
            .join(&unuploaded)
            .join("upload.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
    // Eligible except a queue entry is still pending for it.
    let (queued, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    enqueue(
        &spool,
        queue_entry(QueueOp::Segment, &queued, Some(0), "2026-11-06T00:00:00Z"),
    )
    .unwrap();

    let candidates = spool.prune_candidates(prune_now(), 30).unwrap();
    assert!(
        candidates.is_empty(),
        "unuploaded/queued sessions are never pruned: {candidates:?}"
    );
    assert!(
        spool
            .root
            .join("sessions")
            .join(&unuploaded)
            .join("segments")
            .is_dir()
    );
    assert!(
        spool
            .root
            .join("sessions")
            .join(&queued)
            .join("segments")
            .is_dir()
    );
}

#[test]
fn prune_uses_cursor_last_event_at_without_ended_at() {
    let (_tmp, spool) = open_spool();
    // No ended_at: the cursor's last_event_at is the activity fallback.
    let (ulid, key) = seed_spool_session(&spool, None, true);
    spool
        .write_cursor(
            &key,
            &ulid,
            Cursor::start(),
            "/native/path",
            Some("2026-01-01T00:00:00Z".to_string()),
            None,
        )
        .unwrap();
    let candidates = spool.prune_candidates(prune_now(), 30).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].last_activity, "2026-01-01T00:00:00Z");
}

#[test]
fn reingest_after_prune_reuses_the_pruned_ulid() {
    use starforge_capture::Roots;
    use starforge_cli::config::CliPaths;
    use starforge_cli::git::common_dir;
    use starforge_cli::ingest::ingest;
    use starforge_cli::queue::{read_queue, rewrite_queue};

    fn git_ok(repo: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }
    fn parse_now(s: &str) -> time::OffsetDateTime {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
    }

    // Real repo + fake home with the Pi fixture as a native session.
    let repo_dir = TempDir::new().unwrap();
    let repo = repo_dir.path().to_path_buf();
    git_ok(&repo, &["init", "-q"]);
    git_ok(&repo, &["config", "user.email", "t@t.t"]);
    git_ok(&repo, &["config", "user.name", "t"]);
    git_ok(&repo, &["commit", "--allow-empty", "-q", "-m", "init"]);
    let home = TempDir::new().unwrap();
    let _paths = CliPaths::from_home(home.path().to_path_buf());
    let store = home.path().join(".pi/agent/sessions/--x--");
    std::fs::create_dir_all(&store).unwrap();
    let body = std::fs::read_to_string(fixture_path())
        .unwrap()
        .replace("/work/repo", &repo.to_string_lossy());
    std::fs::write(store.join("pi-prune-1.jsonl"), body).unwrap();

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
    // `now` long after the fixture's last event, so the session ends old.
    ingest(&spool, &roots, &repo, parse_now("2026-11-06T00:00:00Z")).unwrap();
    let ulids = spool.session_ulids().unwrap();
    assert_eq!(ulids.len(), 1, "one spool session: {ulids:?}");
    let ulid = ulids[0].clone();

    // Pretend the server acknowledged everything: every segment uploaded,
    // current meta hash uploaded, complete set, queue settled.
    for n in spool.existing_segments(&ulid).unwrap() {
        spool.mark_segment_uploaded(&ulid, n).unwrap();
    }
    let meta = spool.read_meta(&ulid).unwrap();
    spool
        .mark_meta_uploaded(&ulid, starforge_cli::spool::meta_body_hash(&meta).unwrap())
        .unwrap();
    let mut state = spool.read_upload(&ulid).unwrap();
    state.complete = true;
    std::fs::write(
        spool.root.join("sessions").join(&ulid).join("upload.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
    rewrite_queue(&spool, &[]).unwrap();
    assert!(read_queue(&spool).unwrap().is_empty());

    // Eligible, and prune_session deletes only the blobs.
    let candidates = spool
        .prune_candidates(parse_now("2026-11-06T00:00:00Z"), 30)
        .unwrap();
    assert_eq!(
        candidates.len(),
        1,
        "ingested session is eligible: {candidates:?}"
    );
    spool
        .prune_session(&candidates[0].ulid)
        .unwrap()
        .expect("eligible session prunes");
    assert!(spool.is_pruned(&ulid));

    // Re-ingest of the unchanged native file must not mint a new session.
    let stats = ingest(&spool, &roots, &repo, parse_now("2026-11-06T00:00:00Z")).unwrap();
    assert_eq!(
        stats.sessions, 0,
        "unchanged file yields no new session: {stats:?}"
    );
    let after = spool.session_ulids().unwrap();
    assert_eq!(
        after,
        vec![ulid.clone()],
        "no new session dir after prune + re-ingest"
    );
    let records = spool.cursor_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records.values().next().unwrap().ulid, ulid);
}

#[test]
fn append_after_prune_recreates_dirs_and_writes_segment_zero() {
    let (_tmp, spool) = open_spool();
    let (ulid, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    let candidates = spool.prune_candidates(prune_now(), 30).unwrap();
    assert_eq!(candidates.len(), 1);
    spool
        .prune_session(&ulid)
        .unwrap()
        .expect("eligible session prunes");
    assert!(spool.is_pruned(&ulid));

    // Re-ingest after prune: append_events/write_raw must recreate the
    // removed dirs instead of failing with ENOENT.
    let (events, _header, raw) = fixture_events();
    let (_rules, compiled) = Spool::load_rules(Path::new("/nonexistent-repo")).unwrap();
    let (jsonl, counts) = redacted_jsonl(&compiled, &events);
    let nums = spool
        .append_events(&ulid, &jsonl, DEFAULT_SEGMENT_CAP, &counts)
        .unwrap();
    assert_eq!(nums, vec![0], "segment numbering restarts at 0 after prune");
    assert_eq!(spool.existing_segments(&ulid).unwrap(), vec![0]);
    spool.write_raw(&ulid, 0, raw.as_bytes()).unwrap();
    assert!(
        spool.raw_bytes(&ulid, 0).is_ok(),
        "raw slice written post-prune"
    );
    let meta = spool.read_meta(&ulid).unwrap();
    assert!(
        meta.redaction.counts.contains_key("known-token"),
        "meta updated post-prune: {:?}",
        meta.redaction.counts
    );
}

#[test]
fn prune_session_skips_when_session_changed_since_scan() {
    let (_tmp, spool) = open_spool();
    let (ulid, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    let candidates = spool.prune_candidates(prune_now(), 30).unwrap();
    assert_eq!(candidates.len(), 1);

    // A new (unuploaded) segment appears after the scan.
    let (events, _header, _raw) = fixture_events();
    let (_rules, compiled) = Spool::load_rules(Path::new("/nonexistent-repo")).unwrap();
    let (jsonl, _counts) = redacted_jsonl(&compiled, &events);
    let nums = spool
        .append_events(&ulid, &jsonl, DEFAULT_SEGMENT_CAP, &BTreeMap::new())
        .unwrap();
    assert_eq!(nums, vec![1]);

    let result = spool.prune_session(&ulid).unwrap();
    assert_eq!(result, None, "changed session is skipped, not pruned");
    let dir = spool.root.join("sessions").join(&ulid);
    assert!(dir.join("segments").is_dir(), "nothing deleted");
    assert_eq!(spool.existing_segments(&ulid).unwrap(), vec![0, 1]);
}

#[cfg(unix)]
#[test]
fn prune_refuses_symlinked_dirs_and_session_ulids_skips_them() {
    let (_tmp, spool) = open_spool();
    let (ulid, _) = seed_spool_session(&spool, Some("2026-01-01T00:00:00Z"), true);
    let dir = spool.root.join("sessions").join(&ulid);

    // A symlinked `segments` component must be refused, target untouched.
    let target = _tmp.path().join("segments-target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep.txt"), "keep me").unwrap();
    std::fs::remove_dir_all(dir.join("segments")).unwrap();
    std::os::unix::fs::symlink(&target, dir.join("segments")).unwrap();
    assert!(
        spool.prune_session(&ulid).is_err(),
        "symlinked segments refused"
    );
    assert_eq!(
        std::fs::read_to_string(target.join("keep.txt")).unwrap(),
        "keep me",
        "prune never deletes through the symlink"
    );

    // A symlinked session dir is not listed as a session at all.
    std::fs::remove_dir_all(&target).unwrap();
    std::fs::remove_file(dir.join("segments")).unwrap();
    let real = _tmp.path().join("real-session");
    std::fs::rename(&dir, &real).unwrap();
    std::os::unix::fs::symlink(&real, &dir).unwrap();
    let ulids = spool.session_ulids().unwrap();
    assert!(
        !ulids.contains(&ulid),
        "symlinked session dir skipped: {ulids:?}"
    );
}

#[test]
fn prune_command_rejects_huge_older_than() {
    use starforge_cli::commands::spool::prune;
    let repo_dir = TempDir::new().unwrap();
    let repo = repo_dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "t@t.t"],
        vec!["config", "user.name", "t"],
        vec!["commit", "--allow-empty", "-q", "-m", "init"],
    ] {
        let status = std::process::Command::new("git")
            .args(&args)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }
    let (out, code) = prune(&repo, u64::MAX, false);
    assert_eq!(code, 1, "huge --older-than exits 1: {out}");
    assert!(out.contains("too large"), "error names the bound: {out}");
}
