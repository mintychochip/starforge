//! `git blame --porcelain` grouped into per-commit runs (M1e E4).
//! Blocking; async callers run this on the blocking thread pool.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;

use crate::command::GitError;

/// One contiguous run of lines attributed to a single commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameBlock {
    pub sha: String,
    pub author: String,
    pub author_time: i64,
    /// First line of the commit summary (`git log --format=%s` semantics).
    pub summary: String,
    /// 1-based number of the run's first line in the blamed file.
    pub start: usize,
    /// The run's line count (always `lines.len()`; git's advisory group
    /// count is not trusted across split headers).
    pub count: usize,
    pub lines: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BlameError {
    #[error("blame target not found")]
    NotFound,
    #[error("blame unavailable for this file")]
    Unavailable,
    #[error(transparent)]
    Git(#[from] GitError),
}

/// Groups `git blame --porcelain -l <rev> -- <path>` into [`BlameBlock`]s.
///
/// `rev` must already be resolved to a commit id and `path` validated by the
/// caller; unknown revs/paths still surface as [`BlameError::NotFound`].
/// Binary or oversized files are refused upstream (the blob pre-check), so a
/// failure here is unexpected git output.
pub fn blame(repo_dir: &Path, rev: &str, path: &str) -> Result<Vec<BlameBlock>, BlameError> {
    if rev.is_empty() || rev.starts_with('-') || path.is_empty() {
        return Err(BlameError::NotFound);
    }
    let output = std::process::Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(Stdio::null())
        .arg("--git-dir")
        .arg(repo_dir.as_os_str())
        .arg("blame")
        .arg("--porcelain")
        .arg("-l")
        .arg(OsStr::new(rev))
        .arg("--")
        .arg(OsStr::new(path))
        .output()
        .map_err(GitError::from)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let not_found = [
            "no such path",
            "exists on disk, but not in",
            "unknown revision",
        ]
        .iter()
        .any(|m| stderr.contains(m))
            || stderr.contains("bad revision")
            || stderr.contains("unknown commit");
        if not_found {
            return Err(BlameError::NotFound);
        }
        return Err(BlameError::Git(GitError::Failed {
            command: "blame".into(),
            stderr: stderr.trim().to_owned(),
        }));
    }
    parse(&String::from_utf8_lossy(&output.stdout))
}

/// Parses porcelain output: a `<sha> <orig> <final> [<count>]` line (with an
/// optional boundary `^` prefix) opens a run; `author`/`author-time`/`summary`
/// headers fill it in; tab-prefixed lines are its content.
///
/// Git splits long same-commit groups: after the full header and its first
/// content line, the remaining lines may arrive under short repeat headers
/// (`<sha> <orig> <final>`, sometimes with a count but no metadata).
/// Adjacent headers for the same sha merge into one run — a run is a maximal
/// run of consecutive lines from one commit — inheriting the metadata the
/// full header carried. Only a header for a *different* sha flushes.
fn parse(output: &str) -> Result<Vec<BlameBlock>, BlameError> {
    #[derive(Clone, Default)]
    struct Meta {
        author: String,
        author_time: i64,
        summary: String,
    }
    struct Open {
        sha: String,
        start: usize,
        meta: Meta,
        lines: Vec<String>,
    }
    // Metadata by sha: repeat groups may open with a short header carrying
    // no metadata of their own, so a new run inherits whatever an earlier
    // run of the same sha carried.
    let mut seen: std::collections::HashMap<String, Meta> = std::collections::HashMap::new();
    let mut blocks: Vec<BlameBlock> = Vec::new();
    let mut open: Option<Open> = None;

    let flush = |open: &mut Option<Open>, blocks: &mut Vec<BlameBlock>| {
        if let Some(run) = open.take() {
            blocks.push(BlameBlock {
                sha: run.sha,
                author: run.meta.author,
                author_time: run.meta.author_time,
                summary: run.meta.summary,
                start: run.start,
                count: run.lines.len(),
                lines: run.lines,
            });
        }
    };

    for line in output.lines() {
        if let Some(content) = line.strip_prefix('\t') {
            if let Some(run) = open.as_mut() {
                run.lines.push(content.to_owned());
            }
            continue;
        }
        if let Some((sha, start)) = parse_header(line) {
            let same = open.as_ref().is_some_and(|run| run.sha == sha);
            if !same {
                flush(&mut open, &mut blocks);
                let meta = seen.get(&sha).cloned().unwrap_or_default();
                open = Some(Open {
                    sha,
                    start,
                    meta,
                    lines: Vec::new(),
                });
            }
            continue;
        }
        let Some(run) = open.as_mut() else { continue };
        let dirty = if let Some(author) = line.strip_prefix("author ") {
            run.meta.author = author.to_owned();
            true
        } else if let Some(time) = line.strip_prefix("author-time ") {
            run.meta.author_time = time.trim().parse().unwrap_or(0);
            true
        } else if let Some(summary) = line.strip_prefix("summary ") {
            run.meta.summary = summary.to_owned();
            true
        } else {
            false
        };
        if dirty {
            seen.insert(run.sha.clone(), run.meta.clone());
        }
    }
    flush(&mut open, &mut blocks);
    Ok(blocks)
}

/// A block header: optional boundary `^`, a 40–64 hex sha, orig/final line,
/// and an optional group count (absent on single-line repeats). The count is
/// advisory — groups may split across short headers — so only sha and the
/// final (1-based) line number are returned.
fn parse_header(line: &str) -> Option<(String, usize)> {
    let line = line.strip_prefix('^').unwrap_or(line);
    let mut parts = line.split(' ');
    let sha = parts.next()?;
    if !((sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let _orig: usize = parts.next()?.parse().ok()?;
    let start: usize = parts.next()?.parse().ok()?;
    // An optional group count may follow; anything else is not a header.
    if let Some(rest) = parts.next()
        && rest.parse::<usize>().is_err()
    {
        return None;
    }
    if parts.next().is_some() {
        return None;
    }
    Some((sha.to_owned(), start))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "d1591d39a1942d95d782e1cf423b56525815905a";
    const SHA_B: &str = "0032d4478e0370aba1955638117ddefd636678cb";
    const SHA_C: &str = "fd572e1503cb0b1c367dce946f377f7abf006219";

    fn block(sha: &str, start: usize, count: usize, summary: &str, lines: &[&str]) -> String {
        format!(
            "{sha} {start} {start} {count}\nauthor T\nauthor-mail <t@e.com>\nauthor-time 1793808419\nauthor-tz -0800\nsummary {summary}\nfilename my file.txt\n{}",
            lines.iter().map(|l| format!("\t{l}\n")).collect::<String>()
        )
    }

    #[test]
    fn parses_multi_block_output_with_spaces_in_filename() {
        let output = [
            block(SHA_A, 1, 1, "third <script>x</script>", &["L1"]),
            format!(
                "{SHA_B} 2 2 1\nauthor T\nauthor-time 1793808419\nsummary first\nboundary\nfilename file.txt\n\tl2\n"
            ),
            format!(
                "{SHA_C} 3 3 2\nauthor T\nauthor-time 1793808419\nsummary second\nprevious {SHA_B} file.txt\nfilename file.txt\n\tl3\n\tl4\n"
            ),
        ]
        .join("");
        let blocks = parse(&output).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].sha, SHA_A);
        assert_eq!(blocks[0].start, 1);
        assert_eq!(blocks[0].count, 1);
        assert_eq!(blocks[0].lines, ["L1"]);
        assert_eq!(blocks[0].summary, "third <script>x</script>");
        assert_eq!(blocks[0].author, "T");
        assert_eq!(blocks[0].author_time, 1793808419);
        assert_eq!(blocks[1].sha, SHA_B);
        assert_eq!(blocks[1].start, 2);
        assert_eq!(blocks[1].lines, ["l2"]);
        assert_eq!(blocks[2].sha, SHA_C);
        assert_eq!(blocks[2].start, 3);
        assert_eq!(blocks[2].count, 2);
        assert_eq!(blocks[2].lines, ["l3", "l4"]);
    }

    #[test]
    fn split_groups_merge_into_one_contiguous_run() {
        // Git splits long same-commit groups across short repeat headers;
        // adjacent headers for one sha are a single run, not many blocks.
        let output = format!(
            "{SHA_A} 1 1 1\nauthor T\nauthor-time 42\nsummary one\nfilename f.txt\n\ta\n\
             {SHA_B} 2 2 1\nauthor U\nauthor-time 43\nsummary two\nfilename f.txt\n\tb\n\
             {SHA_A} 3 3 3\n\tc\n\
             {SHA_A} 4 4\n\td\n\
             {SHA_A} 5 5\n\te\n"
        );
        let blocks = parse(&output).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[2].sha, SHA_A);
        assert_eq!(blocks[2].start, 3);
        assert_eq!(blocks[2].count, 3);
        assert_eq!(blocks[2].lines, ["c", "d", "e"]);
        assert_eq!(blocks[2].author, "T");
        assert_eq!(blocks[2].author_time, 42);
        assert_eq!(blocks[2].summary, "one");
    }

    #[test]
    fn boundary_carets_are_stripped_not_dropped() {
        let output =
            format!("^{SHA_A} 1 1 1\nauthor T\nauthor-time 7\nsummary root\nfilename f.txt\n\ta\n");
        let blocks = parse(&output).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].sha, SHA_A);
        assert_eq!(blocks[0].lines, ["a"]);
        assert_eq!(blocks[0].author_time, 7);
    }

    #[test]
    fn empty_and_garbage_output_yield_no_blocks() {
        assert!(parse("").unwrap().is_empty());
        assert!(
            parse("fatal: no such path 'x' in HEAD\n")
                .unwrap()
                .is_empty()
        );
    }
}
