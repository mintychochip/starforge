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
        .write_cursor("pi/pi-test", &ulid, cursor, "/tmp/x/sessions/pi-test.jsonl")
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
