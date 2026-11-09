//! Session checkpoints: snapshot creation, ref shape, rewind, resume.

use std::path::{Path, PathBuf};
use std::process::Command;

use starforge_cli::checkpoints;
use starforge_cli::spool::Spool;
use starforge_format::{FORMAT_TAG, SessionMeta};
use tempfile::TempDir;
use ulid::Ulid;

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn init_repo(dir: &Path) -> PathBuf {
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.name", "Test"]);
    git(&repo, &["config", "user.email", "test@example.com"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "initial"]);
    repo
}

fn new_session(spool: &Spool) -> String {
    let ulid = Ulid::new().to_string();
    let meta = SessionMeta {
        format: FORMAT_TAG.to_string(),
        id: Ulid::from_string(&ulid).unwrap(),
        agent: Default::default(),
        models: Vec::new(),
        title: Some("checkpoint test".into()),
        started_at: "2026-11-08T00:00:00Z".into(),
        ended_at: None,
        repo: Default::default(),
        parent_id: None,
        usage: Default::default(),
        files_touched: vec!["b.txt".into(), "c.txt".into()],
        redaction: Default::default(),
        capture: Default::default(),
    };
    spool.put_session(&meta).unwrap();
    ulid
}

fn open_spool(repo: &Path) -> Spool {
    let common = starforge_cli::git::common_dir(repo).unwrap();
    let spool = Spool::open(&common);
    spool.ensure_layout().unwrap();
    spool
}

#[test]
fn checkpoint_create_records_tree_and_ref() {
    let tmp = TempDir::new().unwrap();
    let repo = init_repo(tmp.path());
    let spool = open_spool(&repo);
    let ulid = new_session(&spool);

    std::fs::write(repo.join("a.txt"), "one\ntwo\n").unwrap();
    std::fs::write(repo.join("b.txt"), "bee\n").unwrap();
    let entry = checkpoints::create(&repo, &spool, &ulid, "turn 1", "manual", false).unwrap();
    assert_eq!(entry.n, 1);
    assert_eq!(entry.label, "turn 1");
    assert_eq!(entry.source, "manual");
    let ref_name = format!("refs/starforge/checkpoints/{ulid}/1");
    assert_eq!(git(&repo, &["rev-parse", &ref_name]), entry.commit);
    assert_eq!(
        git(&repo, &["show", &format!("{}:b.txt", entry.commit)]),
        "bee"
    );
    assert_eq!(
        git(&repo, &["show", &format!("{}:a.txt", entry.commit)]),
        "one\ntwo"
    );

    // An unchanged tree is a no-op.
    let again = checkpoints::create(&repo, &spool, &ulid, "turn 2", "manual", false).unwrap();
    assert_eq!(again.n, 1);
    assert_eq!(again.commit, entry.commit);
    assert_eq!(spool.read_checkpoints(&ulid).unwrap().len(), 1);
}

#[test]
fn rewind_restores_and_force_saves_dirty_state() {
    let tmp = TempDir::new().unwrap();
    let repo = init_repo(tmp.path());
    let spool = open_spool(&repo);
    let ulid = new_session(&spool);

    let first = checkpoints::create(&repo, &spool, &ulid, "first", "manual", false).unwrap();
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    std::fs::write(repo.join("c.txt"), "see\n").unwrap();
    let second = checkpoints::create(&repo, &spool, &ulid, "second", "manual", false).unwrap();
    assert_eq!(second.n, 2);

    let err = checkpoints::rewind(&repo, &spool, &ulid, 1, false).unwrap_err();
    assert!(err.contains("dirty"), "{err}");
    assert_eq!(
        std::fs::read_to_string(repo.join("a.txt")).unwrap(),
        "two\n"
    );

    checkpoints::rewind(&repo, &spool, &ulid, 1, true).unwrap();
    assert_eq!(
        std::fs::read_to_string(repo.join("a.txt")).unwrap(),
        "one\n"
    );
    assert!(!repo.join("c.txt").exists());

    // The forced rewind saved the overwritten state in a local stash.
    let stashes = git(&repo, &["stash", "list"]);
    assert!(stashes.contains("starforge pre-rewind"), "{stashes}");
    assert_eq!(git(&repo, &["show", "stash@{0}:a.txt"]), "two");
    assert_eq!(git(&repo, &["show", "stash@{0}^3:c.txt"]), "see");
    assert_eq!(first.n, 1);
}

#[test]
fn resume_writes_context_file() {
    let tmp = TempDir::new().unwrap();
    let repo = init_repo(tmp.path());
    let spool = open_spool(&repo);
    let ulid = new_session(&spool);
    checkpoints::create(&repo, &spool, &ulid, "first", "manual", false).unwrap();

    let (entry, path) = checkpoints::resume(&repo, &spool, &ulid, 1, false).unwrap();
    assert_eq!(entry.n, 1);
    assert_eq!(path, repo.join(".starforge/resume.md"));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(&ulid), "{text}");
    assert!(text.contains("Checkpoint: 1"), "{text}");
    assert!(text.contains("checkpoint test"), "{text}");
}

#[test]
fn checkpoint_excludes_unlisted_and_secret_untracked_files() {
    let tmp = TempDir::new().unwrap();
    let repo = init_repo(tmp.path());
    let spool = open_spool(&repo);
    let ulid = new_session(&spool);
    std::fs::write(repo.join("b.txt"), "bee\n").unwrap();
    std::fs::write(repo.join("other.txt"), "not touched\n").unwrap();
    std::fs::write(
        repo.join("secret.txt"),
        "token ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ12\n",
    )
    .unwrap();
    std::fs::write(repo.join(".gitignore"), "ignored.txt\n").unwrap();
    std::fs::write(repo.join("ignored.txt"), "ignored\n").unwrap();
    // The session touched b.txt, secret.txt, and ignored.txt, but not
    // other.txt.
    let mut meta = spool.read_meta(&ulid).unwrap();
    meta.files_touched = vec!["b.txt".into(), "secret.txt".into(), "ignored.txt".into()];
    spool.put_session(&meta).unwrap();

    let entry = checkpoints::create(&repo, &spool, &ulid, "scan", "manual", false).unwrap();
    assert_eq!(
        git(&repo, &["show", &format!("{}:b.txt", entry.commit)]),
        "bee"
    );
    assert!(
        !git(&repo, &["ls-tree", "-r", "--name-only", &entry.commit])
            .lines()
            .any(|line| line == "secret.txt"),
        "redaction hit must stay out of the checkpoint"
    );
    assert!(
        !git(&repo, &["ls-tree", "-r", "--name-only", &entry.commit])
            .lines()
            .any(|line| line == "other.txt"),
        "untouched untracked file must stay out of the checkpoint"
    );
    assert!(
        !git(&repo, &["ls-tree", "-r", "--name-only", &entry.commit])
            .lines()
            .any(|line| line == "ignored.txt"),
        "ignored file must stay out of the checkpoint"
    );
}

#[test]
fn spool_prune_keeps_the_newest_checkpoints() {
    let tmp = TempDir::new().unwrap();
    let repo = init_repo(tmp.path());
    let spool = open_spool(&repo);
    let ulid = new_session(&spool);
    for n in 1..=3u64 {
        spool
            .append_checkpoint(
                &ulid,
                starforge_cli::spool::CheckpointEntry {
                    n,
                    commit: format!("{n:040x}"),
                    tree: format!("{:040x}", n + 100),
                    parent: None,
                    label: format!("cp {n}"),
                    source: "manual".into(),
                    created_at: n as i64,
                    uploaded: false,
                },
            )
            .unwrap();
    }
    let removed = spool.prune_checkpoints(&ulid, 2).unwrap();
    assert_eq!(
        removed.iter().map(|entry| entry.n).collect::<Vec<_>>(),
        vec![1]
    );
    let left = spool.read_checkpoints(&ulid).unwrap();
    assert_eq!(
        left.iter().map(|entry| entry.n).collect::<Vec<_>>(),
        vec![2, 3]
    );
}
