//! Read paths over gix (spec D11): branches, ref resolution, trees, blobs, history.
//! Blocking; async callers run these on the blocking thread pool.

use std::path::Path;

use crate::command::GitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Tree,
    Blob,
    Symlink,
    Submodule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub name: String,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub id: String,
    pub summary: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    /// Unix seconds.
    pub author_time: i64,
    pub parents: Vec<String>,
}

impl CommitInfo {
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(10)]
    }
}

/// A `<ref>/<path>` URL suffix resolved to a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub ref_name: String,
    pub commit_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blob {
    Text(String),
    Binary,
}

fn gix_err(err: impl std::fmt::Display) -> GitError {
    GitError::Gix(err.to_string())
}

fn open(repo: &Path) -> Result<gix::Repository, GitError> {
    gix::open(repo).map_err(gix_err)
}

fn branch_names(repo: &gix::Repository) -> Result<Vec<String>, GitError> {
    let platform = repo.references().map_err(gix_err)?;
    let mut names = Vec::new();
    for reference in platform.local_branches().map_err(gix_err)? {
        names.push(reference.map_err(gix_err)?.name().shorten().to_string());
    }
    names.sort();
    Ok(names)
}

fn tag_names(repo: &gix::Repository) -> Result<Vec<String>, GitError> {
    let platform = repo.references().map_err(gix_err)?;
    let mut names = Vec::new();
    for reference in platform.tags().map_err(gix_err)? {
        names.push(reference.map_err(gix_err)?.name().shorten().to_string());
    }
    Ok(names)
}

fn commit_id_of(repo: &gix::Repository, spec: &str) -> Option<String> {
    let commit = repo
        .rev_parse_single(spec)
        .ok()?
        .object()
        .ok()?
        .peel_to_commit()
        .ok()?;
    Some(commit.id.to_string())
}

fn is_object_id(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Local branch names, sorted.
pub fn branches(repo: &Path) -> Result<Vec<String>, GitError> {
    branch_names(&open(repo)?)
}

/// Splits `rest` at the longest prefix naming a branch (then a tag); a full commit id also works.
pub fn resolve(repo: &Path, rest: &str) -> Result<Option<Resolved>, GitError> {
    let r = open(repo)?;
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Ok(None);
    }
    let branches = branch_names(&r)?;
    let tags = tag_names(&r)?;
    for split in (1..=parts.len()).rev() {
        let candidate = parts[..split].join("/");
        let full = if branches.contains(&candidate) {
            format!("refs/heads/{candidate}")
        } else if tags.contains(&candidate) {
            format!("refs/tags/{candidate}")
        } else {
            continue;
        };
        if let Some(commit_id) = commit_id_of(&r, &full) {
            return Ok(Some(Resolved {
                ref_name: candidate,
                commit_id,
                path: parts[split..].join("/"),
            }));
        }
    }
    if is_object_id(parts[0])
        && let Some(commit_id) = commit_id_of(&r, parts[0])
    {
        return Ok(Some(Resolved {
            ref_name: parts[0].to_owned(),
            commit_id,
            path: parts[1..].join("/"),
        }));
    }
    Ok(None)
}

/// Entries of directory `dir` (empty = root) in `commit_id`: directories first, then by name.
/// `None` when `dir` does not exist or is not a directory.
pub fn tree(repo: &Path, commit_id: &str, dir: &str) -> Result<Option<Vec<TreeEntry>>, GitError> {
    let r = open(repo)?;
    let tree = if dir.is_empty() {
        let Ok(id) = r.rev_parse_single(commit_id) else {
            return Ok(None);
        };
        id.object()
            .map_err(gix_err)?
            .peel_to_commit()
            .map_err(gix_err)?
            .tree()
            .map_err(gix_err)?
    } else {
        let Ok(id) = r.rev_parse_single(format!("{commit_id}:{dir}").as_str()) else {
            return Ok(None);
        };
        let object = id.object().map_err(gix_err)?;
        if object.kind != gix::object::Kind::Tree {
            return Ok(None);
        }
        object.into_tree()
    };
    let mut entries = Vec::new();
    for entry in tree.iter() {
        let entry = entry.map_err(gix_err)?;
        let mode = entry.mode();
        let kind = if mode.is_tree() {
            EntryKind::Tree
        } else if mode.is_link() {
            EntryKind::Symlink
        } else if mode.is_commit() {
            EntryKind::Submodule
        } else {
            EntryKind::Blob
        };
        entries.push(TreeEntry {
            name: entry.filename().to_string(),
            kind,
        });
    }
    entries.sort_by(|a, b| {
        (a.kind != EntryKind::Tree)
            .cmp(&(b.kind != EntryKind::Tree))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(Some(entries))
}

/// Identity and size of a blob without its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    /// Full lowercase hex object id of the blob.
    pub id: String,
    /// Size of the blob's content in bytes, from the object header.
    pub size: u64,
}

/// Identity and size of file `file` in `commit_id`; `None` when it is missing or not a file.
/// The blob's content is never decompressed.
pub fn blob_ref(repo: &Path, commit_id: &str, file: &str) -> Result<Option<BlobRef>, GitError> {
    if file.is_empty() {
        return Ok(None);
    }
    let r = open(repo)?;
    let Ok(id) = r.rev_parse_single(format!("{commit_id}:{file}").as_str()) else {
        return Ok(None);
    };
    let header = id.header().map_err(gix_err)?;
    if header.kind() != gix::object::Kind::Blob {
        return Ok(None);
    }
    Ok(Some(BlobRef {
        id: id.detach().to_string(),
        size: header.size(),
    }))
}

/// The stdout of `git cat-file blob <id>`, streaming the blob's content.
/// A reaped task collects the child and warns on a non-zero exit; dropping
/// stdout makes git exit on EPIPE, so a disconnected client reaps cleanly.
pub fn stream_blob(repo: &Path, id: &str) -> Result<tokio::process::ChildStdout, GitError> {
    if !is_object_id(id) {
        return Err(GitError::Failed {
            command: "cat-file".into(),
            stderr: format!("not an object id: {id}"),
        });
    }
    let mut child = crate::command::git()
        .arg("--git-dir")
        .arg(repo)
        .arg("cat-file")
        .arg("blob")
        .arg(id)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| GitError::Failed {
        command: "cat-file".into(),
        stderr: "git cat-file produced no stdout".into(),
    })?;
    tokio::spawn(async move {
        let status = child.wait().await;
        if !matches!(&status, Ok(status) if status.success()) {
            tracing::warn!(?status, "git cat-file blob finished");
        }
    });
    Ok(stdout)
}

/// Bytes of file `file` in `commit_id`; `None` when it is missing or not a file.
pub fn blob_bytes(repo: &Path, commit_id: &str, file: &str) -> Result<Option<Vec<u8>>, GitError> {
    if file.is_empty() {
        return Ok(None);
    }
    let r = open(repo)?;
    let Ok(id) = r.rev_parse_single(format!("{commit_id}:{file}").as_str()) else {
        return Ok(None);
    };
    let object = id.object().map_err(gix_err)?;
    if object.kind != gix::object::Kind::Blob {
        return Ok(None);
    }
    Ok(Some(object.detach().data))
}

/// Text when the first 8000 bytes contain no NUL and the whole blob is UTF-8.
pub fn classify(bytes: Vec<u8>) -> Blob {
    if bytes[..bytes.len().min(8000)].contains(&0) {
        return Blob::Binary;
    }
    String::from_utf8(bytes)
        .map(Blob::Text)
        .unwrap_or(Blob::Binary)
}

/// Up to `limit` commits reachable from `commit_id`, newest first (by commit time), after skipping `skip`.
pub fn log(
    repo: &Path,
    commit_id: &str,
    skip: usize,
    limit: usize,
) -> Result<Vec<CommitInfo>, GitError> {
    let r = open(repo)?;
    let start = r.rev_parse_single(commit_id).map_err(gix_err)?.detach();
    let walk = r
        .rev_walk([start])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(gix_err)?;
    let mut commits = Vec::new();
    for info in walk.skip(skip).take(limit) {
        let commit = info.map_err(gix_err)?.object().map_err(gix_err)?;
        commits.push(commit_info(&commit)?);
    }
    Ok(commits)
}

/// The commit with full object id `id`; `None` for anything else.
pub fn commit(repo: &Path, id: &str) -> Result<Option<CommitInfo>, GitError> {
    if !is_object_id(id) {
        return Ok(None);
    }
    let r = open(repo)?;
    let Ok(found) = r.rev_parse_single(id) else {
        return Ok(None);
    };
    let Ok(object) = found.object() else {
        return Ok(None);
    };
    let Ok(commit) = object.try_into_commit() else {
        return Ok(None);
    };
    Ok(Some(commit_info(&commit)?))
}

fn commit_info(commit: &gix::Commit<'_>) -> Result<CommitInfo, GitError> {
    let author = commit.author().map_err(gix_err)?;
    Ok(CommitInfo {
        id: commit.id.to_string(),
        summary: commit.message().map_err(gix_err)?.summary().to_string(),
        message: commit.message_raw().map_err(gix_err)?.to_string(),
        author_name: author.name.to_string(),
        author_email: author.email.to_string(),
        author_time: author.time().map_err(gix_err)?.seconds,
        parents: commit.parent_ids().map(|id| id.to_string()).collect(),
    })
}

/// Commits reachable from `head_id` but not from `base_id`, newest first (by commit time): at most `limit`
/// of them, and how many there are in all.
pub fn range_log(
    repo: &Path,
    base_id: &str,
    head_id: &str,
    limit: usize,
) -> Result<(Vec<CommitInfo>, usize), GitError> {
    let r = open(repo)?;
    let base = r.rev_parse_single(base_id).map_err(gix_err)?.detach();
    let head = r.rev_parse_single(head_id).map_err(gix_err)?.detach();
    let walk = r
        .rev_walk([head])
        .with_hidden([base])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(gix_err)?;
    let mut commits = Vec::new();
    let mut total = 0;
    for info in walk {
        let info = info.map_err(gix_err)?;
        total += 1;
        if commits.len() < limit {
            commits.push(commit_info(&info.object().map_err(gix_err)?)?);
        }
    }
    Ok((commits, total))
}

/// The best common ancestor of two commits; `None` when their histories are unrelated.
pub fn merge_base(repo: &Path, a: &str, b: &str) -> Result<Option<String>, GitError> {
    let r = open(repo)?;
    let a = r.rev_parse_single(a).map_err(gix_err)?.detach();
    let b = r.rev_parse_single(b).map_err(gix_err)?.detach();
    Ok(r.merge_base(a, b)
        .map_err(gix_err)?
        .map(|id| id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str], date: Option<&str>) {
        let mut cmd = Command::new("git");
        cmd.args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        if let Some(date) = date {
            cmd.env("GIT_AUTHOR_DATE", date)
                .env("GIT_COMMITTER_DATE", date);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `main`: README.md, src/lib.rs, docs/a b.txt, bin.dat. `feature/x` adds feature.txt. Tag `v1` is the first commit.
    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        git(p, &["init", "-q", "-b", "main", "."], None);
        std::fs::write(p.join("README.md"), "# Demo\n").unwrap();
        std::fs::create_dir_all(p.join("src")).unwrap();
        std::fs::write(p.join("src/lib.rs"), "pub fn x() {}\n").unwrap();
        git(p, &["add", "-A"], None);
        git(
            p,
            &["commit", "-q", "-m", "first"],
            Some("2024-01-01T00:00:00Z"),
        );
        git(p, &["tag", "v1"], None);
        std::fs::create_dir_all(p.join("docs")).unwrap();
        std::fs::write(p.join("docs/a b.txt"), "spaced\n").unwrap();
        std::fs::write(p.join("bin.dat"), [0_u8, 1, 2, 3]).unwrap();
        git(p, &["add", "-A"], None);
        git(
            p,
            &["commit", "-q", "-m", "second\n\nbody line"],
            Some("2024-01-02T00:00:00Z"),
        );
        git(p, &["checkout", "-q", "-b", "feature/x"], None);
        std::fs::write(p.join("feature.txt"), "f\n").unwrap();
        git(p, &["add", "-A"], None);
        git(
            p,
            &["commit", "-q", "-m", "feature"],
            Some("2024-01-03T00:00:00Z"),
        );
        git(p, &["checkout", "-q", "main"], None);
        dir
    }

    #[test]
    fn branches_are_sorted() {
        assert_eq!(
            branches(fixture().path()).unwrap(),
            vec!["feature/x", "main"]
        );
    }

    #[test]
    fn resolves_the_longest_ref_prefix() {
        let f = fixture();
        let p = f.path();
        let feature = resolve(p, "feature/x/src/lib.rs").unwrap().unwrap();
        assert_eq!(
            (feature.ref_name.as_str(), feature.path.as_str()),
            ("feature/x", "src/lib.rs")
        );
        let main = resolve(p, "main").unwrap().unwrap();
        assert_eq!(main.path, "");
        let tag = resolve(p, "v1/README.md").unwrap().unwrap();
        assert_eq!(
            (tag.ref_name.as_str(), tag.path.as_str()),
            ("v1", "README.md")
        );
        assert_ne!(tag.commit_id, main.commit_id);
        let by_id = resolve(p, &format!("{}/src", main.commit_id))
            .unwrap()
            .unwrap();
        assert_eq!(
            (by_id.commit_id.as_str(), by_id.path.as_str()),
            (main.commit_id.as_str(), "src")
        );
        assert!(resolve(p, "nope/README.md").unwrap().is_none());
        assert!(resolve(p, "").unwrap().is_none());
    }

    #[test]
    fn trees_list_directories_first() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap();
        let root = tree(p, &main.commit_id, "").unwrap().unwrap();
        let listed: Vec<(&str, EntryKind)> =
            root.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(
            listed,
            vec![
                ("docs", EntryKind::Tree),
                ("src", EntryKind::Tree),
                ("README.md", EntryKind::Blob),
                ("bin.dat", EntryKind::Blob)
            ]
        );
        assert_eq!(
            tree(p, &main.commit_id, "docs").unwrap().unwrap()[0].name,
            "a b.txt"
        );
        assert!(
            tree(p, &main.commit_id, "README.md").unwrap().is_none(),
            "a file is not a tree"
        );
        assert!(tree(p, &main.commit_id, "missing").unwrap().is_none());
    }

    #[test]
    fn blobs_and_their_classification() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap();
        assert_eq!(
            blob_bytes(p, &main.commit_id, "docs/a b.txt")
                .unwrap()
                .unwrap(),
            b"spaced\n"
        );
        assert_eq!(
            classify(
                blob_bytes(p, &main.commit_id, "README.md")
                    .unwrap()
                    .unwrap()
            ),
            Blob::Text("# Demo\n".into())
        );
        assert_eq!(
            classify(blob_bytes(p, &main.commit_id, "bin.dat").unwrap().unwrap()),
            Blob::Binary
        );
        assert_eq!(classify(vec![0xff, 0xfe]), Blob::Binary);
        assert!(
            blob_bytes(p, &main.commit_id, "src").unwrap().is_none(),
            "a directory is not a blob"
        );
        assert!(blob_bytes(p, &main.commit_id, "missing").unwrap().is_none());
    }

    #[test]
    fn blob_ref_reports_size_and_id_without_content() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap();
        let r = blob_ref(p, &main.commit_id, "README.md")
            .unwrap()
            .expect("README.md exists");
        let bytes = blob_bytes(p, &main.commit_id, "README.md")
            .unwrap()
            .unwrap();
        assert_eq!(r.size, bytes.len() as u64);
        assert_eq!(r.id.len(), 40);
        assert!(
            r.id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "unexpected id: {}",
            r.id
        );
        assert!(
            blob_ref(p, &main.commit_id, "src").unwrap().is_none(),
            "a directory is not a blob"
        );
        assert!(blob_ref(p, &main.commit_id, "missing").unwrap().is_none());
        assert!(blob_ref(p, &main.commit_id, "").unwrap().is_none());
    }

    #[test]
    fn stream_blob_rejects_non_hex_ids() {
        let f = fixture();
        assert!(stream_blob(f.path(), "--output=/tmp/x").is_err());
        assert!(stream_blob(f.path(), "zz").is_err());
        assert!(stream_blob(f.path(), "").is_err());
    }

    #[test]
    fn history_is_newest_first_and_pages() {
        let f = fixture();
        let p = f.path();
        let feature = resolve(p, "feature/x").unwrap().unwrap();
        let all: Vec<String> = log(p, &feature.commit_id, 0, 10)
            .unwrap()
            .into_iter()
            .map(|c| c.summary)
            .collect();
        assert_eq!(all, vec!["feature", "second", "first"]);
        let second = &log(p, &feature.commit_id, 1, 1).unwrap()[0];
        assert_eq!(second.summary, "second");
        let found = commit(p, &second.id).unwrap().unwrap();
        assert_eq!(found.author_name, "T");
        assert_eq!(found.author_email, "t@example.com");
        assert_eq!(found.author_time, 1_704_153_600);
        assert!(found.message.contains("body line"));
        assert_eq!(found.parents.len(), 1);
        assert_eq!(found.short_id().len(), 10);
        assert!(commit(p, "not-an-id").unwrap().is_none());
        assert!(commit(p, &"0".repeat(40)).unwrap().is_none());
    }
    #[test]
    fn range_logs_list_what_head_adds_to_base() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap().commit_id;
        let feature = resolve(p, "feature/x").unwrap().unwrap().commit_id;
        let v1 = resolve(p, "v1").unwrap().unwrap().commit_id;
        let (commits, total) = range_log(p, &main, &feature, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(commits[0].summary, "feature");
        assert_eq!(range_log(p, &main, &feature, 0).unwrap(), (Vec::new(), 1));
        assert_eq!(range_log(p, &feature, &main, 10).unwrap(), (Vec::new(), 0));
        let (two, total) = range_log(p, &v1, &feature, 10).unwrap();
        assert_eq!(total, 2);
        let summaries: Vec<&str> = two.iter().map(|c| c.summary.as_str()).collect();
        assert_eq!(summaries, vec!["feature", "second"], "newest first");
        assert_eq!(merge_base(p, &main, &feature).unwrap(), Some(main.clone()));
        assert_eq!(merge_base(p, &v1, &feature).unwrap(), Some(v1));
    }
}
