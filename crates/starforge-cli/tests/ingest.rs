//! GAP A ingest tests: discover → read → redact → spool.
//!
//! A fixture Pi transcript is placed under a temp home; `ingest` must redact
//! secrets into the spool (segments + raw + fingerprint), a second ingest
//! with no native growth must write nothing new, and re-discovery must map to
//! the same ULID. No network, no real `$HOME`.

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

fn parse_now(s: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
}

#[test]
fn ingest_redacts_seed_spool_and_records_fingerprint() {
    let (_repo_dir, repo) = init_repo();
    let home = TempDir::new().unwrap();
    let _paths = CliPaths::from_home(home.path().to_path_buf());
    // Native Pi session under the fake home (Pi store layout).
    std::fs::create_dir_all(home.path().join("sessions")).unwrap();
    std::fs::copy(
        fixture_path(),
        home.path().join("sessions/pi-ingest-1.jsonl"),
    )
    .unwrap();

    let common = common_dir(&repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    let roots = Roots {
        config_dir: home.path().join(".config"),
        data_dir: home.path().to_path_buf(),
        worktree: PathBuf::from("/"),
    };
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
