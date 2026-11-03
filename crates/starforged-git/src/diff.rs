//! Commit diffs via `git show` (rename detection; merges diff against their first parent) and a
//! unified-diff parser for rendering.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncReadExt;

use crate::command::{GitError, git};

/// How much of `git show` stderr is kept for error reports; the rest is drained
/// and discarded so a chatty child can never block on a full pipe.
const STDERR_KEEP_BYTES: usize = 64 * 1024;

/// Reads `reader` to EOF, keeping the first [`STDERR_KEEP_BYTES`] bytes.
async fn drain_bounded(mut reader: tokio::process::ChildStderr) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let n = match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let room = STDERR_KEEP_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..n.min(room)]);
    }
    kept
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Added,
    Deleted,
    Modified,
    Renamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Context,
    Added,
    Removed,
    NoNewline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: LineKind,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
    /// The line without its leading `+`, `-`, or space.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub header: String,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub status: FileStatus,
    pub binary: bool,
    pub hunks: Vec<Hunk>,
}

impl FileDiff {
    pub fn display_path(&self) -> &str {
        self.new_path
            .as_deref()
            .or(self.old_path.as_deref())
            .unwrap_or("")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitDiff {
    pub files: Vec<FileDiff>,
    /// More than `max_lines` diff lines existed; the rest were dropped.
    pub truncated: bool,
}

/// Diff of `commit_id` against its first parent (or the empty tree for a root commit).
/// Reads at most `max_bytes` of `git show` output; larger diffs are cut after
/// their last complete line and reported as `truncated`.
pub async fn commit_diff(
    repo: &Path,
    commit_id: &str,
    max_lines: usize,
    max_bytes: usize,
) -> Result<CommitDiff, GitError> {
    if commit_id.is_empty() || !commit_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GitError::Failed {
            command: "show".into(),
            stderr: format!("not an object id: {commit_id}"),
        });
    }
    let mut child = git()
        .args([
            OsStr::new("-c"),
            OsStr::new("core.quotePath=false"),
            OsStr::new("--git-dir"),
            repo.as_os_str(),
            OsStr::new("show"),
            OsStr::new("--format="),
            OsStr::new("--patch"),
            OsStr::new("--find-renames"),
            OsStr::new("--diff-merges=first-parent"),
            OsStr::new("--no-color"),
            OsStr::new("--no-ext-diff"),
            OsStr::new("--no-textconv"),
            OsStr::new(commit_id),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| GitError::Failed {
        command: "show".into(),
        stderr: "git show produced no stdout".into(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| GitError::Failed {
        command: "show".into(),
        stderr: "git show produced no stderr".into(),
    })?;
    let stderr_text = tokio::spawn(drain_bounded(stderr));
    let mut kept = Vec::new();
    let mut byte_truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let n = stdout.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        kept.extend_from_slice(&chunk[..n]);
        if kept.len() > max_bytes {
            byte_truncated = true;
            break;
        }
    }
    if byte_truncated {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = stderr_text.await;
        kept.truncate(max_bytes);
        // Keep only complete lines; `\n` never appears inside a multi-byte
        // UTF-8 sequence, so this also keeps a character boundary.
        let end = kept.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        kept.truncate(end);
        let mut diff = parse(&String::from_utf8_lossy(&kept), max_lines);
        diff.truncated = true;
        return Ok(diff);
    }
    let status = child.wait().await?;
    let stderr = stderr_text.await.unwrap_or_default();
    if !status.success() {
        return Err(GitError::Failed {
            command: "show".into(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
        });
    }
    Ok(parse(&String::from_utf8_lossy(&kept), max_lines))
}

/// Parses `git diff`/`git show` patch output, keeping at most `max_lines` diff lines.
pub fn parse(text: &str, max_lines: usize) -> CommitDiff {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut kept = 0_usize;
    let mut truncated = false;
    let (mut old_no, mut new_no) = (0_u32, 0_u32);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let (old, new) = split_diff_git(rest);
            files.push(FileDiff {
                old_path: Some(old),
                new_path: Some(new),
                status: FileStatus::Modified,
                binary: false,
                hunks: Vec::new(),
            });
            continue;
        }
        let Some(file) = files.last_mut() else {
            continue;
        };
        if file.hunks.is_empty() {
            if line.starts_with("new file mode") {
                file.status = FileStatus::Added;
                file.old_path = None;
                continue;
            }
            if line.starts_with("deleted file mode") {
                file.status = FileStatus::Deleted;
                file.new_path = None;
                continue;
            }
            if let Some(path) = line.strip_prefix("rename from ") {
                file.status = FileStatus::Renamed;
                file.old_path = Some(path.to_owned());
                continue;
            }
            if let Some(path) = line.strip_prefix("rename to ") {
                file.status = FileStatus::Renamed;
                file.new_path = Some(path.to_owned());
                continue;
            }
            if line.starts_with("Binary files ") {
                file.binary = true;
                continue;
            }
            if let Some(path) = line.strip_prefix("--- ") {
                if path != "/dev/null" {
                    file.old_path = Some(strip_side(path, "a/"));
                }
                continue;
            }
            if let Some(path) = line.strip_prefix("+++ ") {
                if path != "/dev/null" {
                    file.new_path = Some(strip_side(path, "b/"));
                }
                continue;
            }
        }
        if line.starts_with("@@ ") {
            (old_no, new_no) = hunk_starts(line);
            file.hunks.push(Hunk {
                header: line.to_owned(),
                lines: Vec::new(),
            });
            continue;
        }
        let Some(hunk) = file.hunks.last_mut() else {
            continue;
        };
        if kept >= max_lines {
            truncated = true;
            continue;
        }
        let (kind, old_line, new_line, body) = match line.as_bytes().first() {
            Some(b'+') => {
                new_no += 1;
                (LineKind::Added, None, Some(new_no - 1), &line[1..])
            }
            Some(b'-') => {
                old_no += 1;
                (LineKind::Removed, Some(old_no - 1), None, &line[1..])
            }
            Some(b' ') => {
                old_no += 1;
                new_no += 1;
                (
                    LineKind::Context,
                    Some(old_no - 1),
                    Some(new_no - 1),
                    &line[1..],
                )
            }
            Some(b'\\') => (LineKind::NoNewline, None, None, line),
            _ => continue,
        };
        hunk.lines.push(DiffLine {
            kind,
            old_line,
            new_line,
            text: body.to_owned(),
        });
        kept += 1;
    }
    CommitDiff { files, truncated }
}

/// `a/<old> b/<new>` → (old, new). Exact for paths without " b/"; `---`/`+++` lines refine it.
fn split_diff_git(rest: &str) -> (String, String) {
    match rest.rfind(" b/") {
        Some(at) => (strip_side(&rest[..at], "a/"), rest[at + 3..].to_owned()),
        None => (rest.to_owned(), rest.to_owned()),
    }
}

/// Drops the `a/`/`b/` prefix and the trailing tab git adds after paths containing spaces.
fn strip_side(path: &str, prefix: &str) -> String {
    path.strip_prefix(prefix)
        .unwrap_or(path)
        .trim_end_matches('\t')
        .to_owned()
}

/// First old and new line numbers from `@@ -a,b +c,d @@`.
fn hunk_starts(header: &str) -> (u32, u32) {
    let mut old = 0;
    let mut new = 0;
    for part in header.split(' ').skip(1) {
        if let Some(range) = part.strip_prefix('-') {
            old = range
                .split(',')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        } else if let Some(range) = part.strip_prefix('+') {
            new = range
                .split(',')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            break;
        }
    }
    (old, new)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,3 @@
 fn a() {}
-fn b() {}
+fn b() -> u8 { 1 }
 fn c() {}
diff --git a/docs/a b.txt b/docs/a b.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/docs/a b.txt\t
@@ -0,0 +1 @@
+hello
\\ No newline at end of file
diff --git a/old.txt b/old.txt
deleted file mode 100644
index 4444444..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
--- not a header
diff --git a/a.txt b/c.txt
similarity index 100%
rename from a.txt
rename to c.txt
diff --git a/img.png b/img.png
new file mode 100644
index 0000000..5555555
Binary files /dev/null and b/img.png differ
";

    #[test]
    fn parses_every_kind_of_file_change() {
        let diff = parse(SAMPLE, 1000);
        assert!(!diff.truncated);
        let summary: Vec<(FileStatus, &str, bool)> = diff
            .files
            .iter()
            .map(|f| (f.status, f.display_path(), f.binary))
            .collect();
        assert_eq!(
            summary,
            vec![
                (FileStatus::Modified, "src/lib.rs", false),
                (FileStatus::Added, "docs/a b.txt", false),
                (FileStatus::Deleted, "old.txt", false),
                (FileStatus::Renamed, "c.txt", false),
                (FileStatus::Added, "img.png", true),
            ]
        );
        assert_eq!(diff.files[3].old_path.as_deref(), Some("a.txt"));
        assert_eq!(diff.files[2].new_path, None);

        let lines = &diff.files[0].hunks[0].lines;
        let shape: Vec<(LineKind, Option<u32>, Option<u32>, &str)> = lines
            .iter()
            .map(|l| (l.kind, l.old_line, l.new_line, l.text.as_str()))
            .collect();
        assert_eq!(
            shape,
            vec![
                (LineKind::Context, Some(1), Some(1), "fn a() {}"),
                (LineKind::Removed, Some(2), None, "fn b() {}"),
                (LineKind::Added, None, Some(2), "fn b() -> u8 { 1 }"),
                (LineKind::Context, Some(3), Some(3), "fn c() {}"),
            ]
        );
        let added = &diff.files[1].hunks[0].lines;
        assert_eq!(
            (added[0].kind, added[0].new_line),
            (LineKind::Added, Some(1))
        );
        assert_eq!(added[1].kind, LineKind::NoNewline);
        let removed = &diff.files[2].hunks[0].lines;
        assert_eq!(
            (removed[0].kind, removed[0].text.as_str()),
            (LineKind::Removed, "-- not a header")
        );
    }

    #[test]
    fn truncates_after_max_lines() {
        let diff = parse(SAMPLE, 2);
        assert!(diff.truncated);
        let total: usize = diff
            .files
            .iter()
            .flat_map(|f| &f.hunks)
            .map(|h| h.lines.len())
            .sum();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn commit_diff_runs_git_and_refuses_non_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(p)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        git(&["init", "-q", "-b", "main", "."]);
        std::fs::write(p.join("a.txt"), "one\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "root"]);
        std::fs::write(p.join("a.txt"), "one\ntwo\n").unwrap();
        git(&["commit", "-qam", "second"]);
        let head = git(&["rev-parse", "HEAD"]).trim().to_owned();
        let root = git(&["rev-parse", "HEAD~1"]).trim().to_owned();
        let repo = p.join(".git");

        let second = commit_diff(&repo, &head, 100, 4 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(second.files[0].status, FileStatus::Modified);
        assert_eq!(second.files[0].hunks[0].lines.last().unwrap().text, "two");
        let first = commit_diff(&repo, &root, 100, 4 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(first.files[0].status, FileStatus::Added);
        assert!(
            commit_diff(&repo, "--output=/tmp/x", 100, 4 * 1024 * 1024)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn commit_diff_bounds_memory_with_max_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(p)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        git(&["init", "-q", "-b", "main", "."]);
        let numbered: Vec<String> = (1..=1000).map(|i| i.to_string()).collect();
        std::fs::write(p.join("big.txt"), numbered.join("\n") + "\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "big"]);
        let head = git(&["rev-parse", "HEAD"]).trim().to_owned();
        let repo = p.join(".git");

        let capped = commit_diff(&repo, &head, 10_000, 1024).await.unwrap();
        assert!(capped.truncated);
        let added: Vec<&str> = capped
            .files
            .iter()
            .flat_map(|f| &f.hunks)
            .flat_map(|h| &h.lines)
            .filter(|l| l.kind == LineKind::Added)
            .map(|l| l.text.as_str())
            .collect();
        assert!(
            (1..1000).contains(&added.len()),
            "expected a strict subset of the 1000 lines, got {}",
            added.len()
        );
        assert!(
            numbered
                .iter()
                .any(|n| Some(n.as_str()) == added.last().copied()),
            "the last capped line is not complete"
        );

        let full = commit_diff(&repo, &head, 10_000, 4 * 1024 * 1024)
            .await
            .unwrap();
        assert!(!full.truncated);
        let total: usize = full
            .files
            .iter()
            .flat_map(|f| &f.hunks)
            .flat_map(|h| &h.lines)
            .filter(|l| l.kind == LineKind::Added)
            .count();
        assert_eq!(total, 1000);
    }
}
