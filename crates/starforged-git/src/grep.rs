//! Code search over one commit through `git grep` (spec §10.5, plan M4a):
//! a fixed-string search (never a regex, never user-controlled options) of
//! the tree at `commit`, with output, time, and match-count caps.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::command::{GitError, git};
use crate::refpolicy;

/// How much git stderr is kept for error reports; the rest is drained and
/// discarded so a chatty child can never block on a full pipe (the
/// [`crate::diff`] pattern).
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

/// The longest query `grep` accepts, in characters (plan M4a).
pub const MAX_QUERY_CHARS: usize = 256;

/// The caps one grep run enforces: at most `max_matches` matches over at
/// most `max_files` files, line text truncated to `max_line_chars`
/// characters, no more than `max_output_bytes` read from git, and
/// `timeout` for the whole run. The plan's core limits are the defaults.
#[derive(Debug, Clone)]
pub struct GrepLimits {
    pub max_matches: usize,
    pub max_files: usize,
    pub max_line_chars: usize,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for GrepLimits {
    fn default() -> GrepLimits {
        GrepLimits {
            max_matches: 200,
            max_files: 50,
            max_line_chars: 500,
            timeout: Duration::from_secs(10),
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// One line of one file that contains the query at `commit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrepMatch {
    pub path: String,
    pub line: u32,
    /// The full line, truncated to the limits' character cap.
    pub text: String,
}

/// The result of one grep run: the matches at `commit`, plus whether any
/// cap cut the result short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrepResult {
    pub commit: String,
    pub matches: Vec<GrepMatch>,
    pub truncated: bool,
}

/// Fixed-string search of the tree at `commit` for `query`.
///
/// The query is passed as the value of `-e` after `--fixed-strings`, so a
/// query starting with `-` (for example `--open-files-in-pager`) is
/// searched literally and never read as an option; the only subsequent
/// arguments are the validated object id and `--`, which ends option
/// parsing anyway. Binary files are never reported: `-I` keeps binary
/// matches out of the output entirely. `git grep` exit `1` means "no
/// matches", not an error.
pub async fn grep(
    repo: &Path,
    commit: &str,
    query: &str,
    case_insensitive: bool,
    limits: &GrepLimits,
) -> Result<GrepResult, GitError> {
    if !refpolicy::is_oid(commit) {
        return Err(GitError::Failed {
            command: "grep".to_owned(),
            stderr: "grep needs a full object id".to_owned(),
        });
    }
    if query.is_empty() || query.chars().count() > MAX_QUERY_CHARS {
        return Err(GitError::Failed {
            command: "grep".to_owned(),
            stderr: format!("grep needs a query of 1..={MAX_QUERY_CHARS} characters"),
        });
    }
    let run = run_grep(repo, commit, query, case_insensitive, limits);
    tokio::time::timeout(limits.timeout, run)
        .await
        .map_err(|_| GitError::Failed {
            command: "grep".to_owned(),
            stderr: format!("grep timed out after {}s", limits.timeout.as_secs()),
        })?
}

async fn run_grep(
    repo: &Path,
    commit: &str,
    query: &str,
    case_insensitive: bool,
    limits: &GrepLimits,
) -> Result<GrepResult, GitError> {
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("-c"),
        OsStr::new("core.quotePath=false"),
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("grep"),
        OsStr::new("-n"),
        OsStr::new("-z"),
        OsStr::new("--no-color"),
        OsStr::new("--no-textconv"),
        // Binary files are never matches (`-I`: don't match patterns in
        // binary files), so they never reach the output at all.
        OsStr::new("-I"),
        OsStr::new("--fixed-strings"),
    ];
    if case_insensitive {
        args.push(OsStr::new("-i"));
    }
    // The query travels as the value of `-e`; with `--fixed-strings` it is a
    // literal string even when it starts with `-`. The object id is already
    // validated hex, and `--` stops any further option parsing.
    args.push(OsStr::new("-e"));
    args.push(OsStr::new(query));
    args.push(OsStr::new(commit));
    args.push(OsStr::new("--"));
    let mut child = git()
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| GitError::Failed {
        command: "grep".to_owned(),
        stderr: "git grep produced no stdout".to_owned(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| GitError::Failed {
        command: "grep".to_owned(),
        stderr: "git grep produced no stderr".to_owned(),
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
        if kept.len() > limits.max_output_bytes {
            byte_truncated = true;
            break;
        }
    }
    if byte_truncated {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = stderr_text.await;
        kept.truncate(limits.max_output_bytes);
        // Keep only complete lines; `\n` never appears inside a multi-byte
        // UTF-8 sequence, so this also keeps a character boundary.
        let end = kept.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        kept.truncate(end);
        return Ok(parse(&String::from_utf8_lossy(&kept), commit, limits, true));
    }
    let status = child.wait().await?;
    let stderr = stderr_text.await.unwrap_or_default();
    match status.code() {
        Some(0) => Ok(parse(
            &String::from_utf8_lossy(&kept),
            commit,
            limits,
            false,
        )),
        // Exit 1 is "no matches", not an error.
        Some(1) => Ok(GrepResult {
            commit: commit.to_owned(),
            matches: Vec::new(),
            truncated: false,
        }),
        _ => Err(GitError::Failed {
            command: "grep".to_owned(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
        }),
    }
}
/// Parses `git grep -n -z` output: each record is
/// `<commit>:<path>\0<line>\0<text>\n`, read structurally (never by lines,
/// since a path may itself contain a newline, which makes it
/// unparseable by lines). The commit prefix is stripped exactly, and NUL
/// delimiters keep paths containing `:` unambiguous. Applies the match,
/// file, and line-length caps. `force_truncated` marks results cut short
/// by the byte cap. A trailing `\r` stays part of the text: it is the
/// file's actual line content.
fn parse(text: &str, commit: &str, limits: &GrepLimits, force_truncated: bool) -> GrepResult {
    let mut matches: Vec<GrepMatch> = Vec::new();
    let mut files: HashSet<&str> = HashSet::new();
    let mut truncated = force_truncated;
    let mut rest = text;
    while !rest.is_empty() {
        let Some(rest_after_prefix) = rest.strip_prefix(commit).and_then(|r| r.strip_prefix(':'))
        else {
            break;
        };
        let Some(path_end) = rest_after_prefix.find('\0') else {
            break;
        };
        let path = &rest_after_prefix[..path_end];
        let after_path = &rest_after_prefix[path_end + 1..];
        let Some(line_end) = after_path.find('\0') else {
            break;
        };
        let line_field = &after_path[..line_end];
        let after_line = &after_path[line_end + 1..];
        // The text runs to the next newline; the final record may lack one.
        let (body, next) = match after_line.find('\n') {
            Some(at) => (&after_line[..at], &after_line[at + 1..]),
            None => (after_line, ""),
        };
        rest = next;
        let Ok(line_no) = line_field.parse::<u32>() else {
            continue;
        };
        if matches.len() >= limits.max_matches
            || (!files.contains(path) && files.len() >= limits.max_files)
        {
            truncated = true;
            continue;
        }
        let mut matched_text = body;
        if matched_text.chars().count() > limits.max_line_chars {
            truncated = true;
            let at = matched_text
                .char_indices()
                .nth(limits.max_line_chars)
                .map_or(matched_text.len(), |(at, _)| at);
            matched_text = &matched_text[..at];
        }
        files.insert(path);
        matches.push(GrepMatch {
            path: path.to_owned(),
            line: line_no,
            text: matched_text.to_owned(),
        });
    }
    GrepResult {
        commit: commit.to_owned(),
        matches,
        truncated,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn git_cmd(dir: &Path, args: &[&OsStr]) -> std::process::Output {
        std::process::Command::new("git")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.test")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.test")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap()
    }

    /// Builds a repo in a temp dir holding `files` at one commit; returns
    /// the temp dir (kept alive by the caller) and the commit id.
    fn repo_with(files: &[(&str, Vec<u8>)]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let out = git_cmd(
            dir.path(),
            &[
                OsStr::new("init"),
                OsStr::new("-q"),
                OsStr::new("-b"),
                OsStr::new("main"),
            ],
        );
        assert!(
            out.status.success(),
            "git init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        for (path, bytes) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, bytes).unwrap();
        }
        git_cmd(dir.path(), &[OsStr::new("add"), OsStr::new("-A")]);
        git_cmd(
            dir.path(),
            &[
                OsStr::new("commit"),
                OsStr::new("-q"),
                OsStr::new("-m"),
                OsStr::new("c"),
            ],
        );
        let out = git_cmd(dir.path(), &[OsStr::new("rev-parse"), OsStr::new("HEAD")]);
        (
            dir,
            String::from_utf8(out.stdout).unwrap().trim().to_owned(),
        )
    }

    fn git_dir(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(".git")
    }

    #[tokio::test]
    async fn finds_fixed_strings_with_line_numbers() {
        let (dir, commit) = repo_with(&[("a.txt", b"one\nneedle here\nthree\n".to_vec())]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "needle",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.commit, commit);
        assert!(!result.truncated);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].path, "a.txt");
        assert_eq!(result.matches[0].line, 2);
        assert_eq!(result.matches[0].text, "needle here");
    }

    #[tokio::test]
    async fn case_insensitive_search() {
        let (dir, commit) = repo_with(&[("a.txt", b"Needle here\n".to_vec())]);
        let gitdir = git_dir(&dir);
        let sensitive = grep(&gitdir, &commit, "needle", false, &GrepLimits::default())
            .await
            .unwrap();
        assert!(sensitive.matches.is_empty(), "case differs, no match");
        let insensitive = grep(&gitdir, &commit, "needle", true, &GrepLimits::default())
            .await
            .unwrap();
        assert_eq!(insensitive.matches.len(), 1);
    }

    #[tokio::test]
    async fn regex_metacharacters_are_literal() {
        let (dir, commit) = repo_with(&[("a.txt", b"a.c\nabc\naac\n".to_vec())]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "a.c",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.matches.len(), 1, "only the literal `a.c` line");
        assert_eq!(result.matches[0].line, 1);
    }

    #[tokio::test]
    async fn dash_queries_are_literal_not_options() {
        let (dir, commit) =
            repo_with(&[("a.txt", b"run --open-files-in-pager now\nplain\n".to_vec())]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "--open-files-in-pager",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.matches.len(),
            1,
            "the dashed query is searched, not run"
        );
        assert_eq!(result.matches[0].line, 1);
    }

    #[tokio::test]
    async fn binary_files_are_skipped() {
        let (dir, commit) =
            repo_with(&[("bin.dat", vec![0u8, b'n', b'e', b'e', b'd', b'l', b'e', 0])]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "needle",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert!(
            result.matches.is_empty(),
            "binary matches are never reported"
        );
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn limits_truncate_and_mark() {
        let (dir, commit) = repo_with(&[("a.txt", "needle\n".repeat(10).into_bytes())]);
        let limits = GrepLimits {
            max_matches: 3,
            ..GrepLimits::default()
        };
        let result = grep(&git_dir(&dir), &commit, "needle", false, &limits)
            .await
            .unwrap();
        assert_eq!(result.matches.len(), 3);
        assert!(
            result.truncated,
            "dropped matches mark the result truncated"
        );
    }

    #[tokio::test]
    async fn long_lines_are_truncated() {
        let long = format!("{} needle\n", "x".repeat(900));
        let (dir, commit) = repo_with(&[("a.txt", long.into_bytes())]);
        let limits = GrepLimits {
            max_line_chars: 100,
            ..GrepLimits::default()
        };
        let result = grep(&git_dir(&dir), &commit, "needle", false, &limits)
            .await
            .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert!(result.matches[0].text.chars().count() <= 100);
        assert!(result.truncated);
    }

    #[tokio::test]
    async fn no_match_is_an_empty_result() {
        let (dir, commit) = repo_with(&[("a.txt", b"one\n".to_vec())]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "needle",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert!(result.matches.is_empty());
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn invalid_commit_and_query_are_errors() {
        let (dir, commit) = repo_with(&[("a.txt", b"one\n".to_vec())]);
        let gitdir = git_dir(&dir);
        assert!(
            grep(
                &gitdir,
                "not-a-sha",
                "needle",
                false,
                &GrepLimits::default()
            )
            .await
            .is_err()
        );
        assert!(
            grep(&gitdir, &commit, "", false, &GrepLimits::default())
                .await
                .is_err()
        );
        let too_long = "x".repeat(257);
        assert!(
            grep(&gitdir, &commit, &too_long, false, &GrepLimits::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn paths_with_newlines_are_found() {
        let (dir, commit) = repo_with(&[("weird\nname.txt", b"needle here\n".to_vec())]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "needle",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.matches.len(), 1, "the weird-named file is found");
        assert_eq!(result.matches[0].path, "weird\nname.txt");
        assert_eq!(result.matches[0].line, 1);
    }

    #[tokio::test]
    async fn crlf_line_endings_are_kept() {
        let (dir, commit) = repo_with(&[("a.txt", b"needle here\r\nplain\r\n".to_vec())]);
        let result = grep(
            &git_dir(&dir),
            &commit,
            "needle",
            false,
            &GrepLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(
            result.matches[0].text, "needle here\r",
            "the file's actual line content is kept"
        );
    }
}
