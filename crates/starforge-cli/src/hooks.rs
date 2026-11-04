//! Git hook install/remove with chaining + trailer selection (C5).
//!
//! Hook chaining: an existing non-managed hook file moves to
//! `<hook>.starforge-orig` (mode preserved by rename); the installed
//! dispatcher is a POSIX `sh` script carrying a `# starforge-managed`
//! marker. It runs the `.starforge-orig` file first (when present and
//! executable), then the hidden `starforge _hook-*` command.
//! `prepare-commit-msg` exits with the orig hook's status; `post-commit`
//! and `pre-push` always exit `0`. `disable` deletes only marker-bearing
//! dispatchers and restores `.starforge-orig` files byte-for-byte.
//!
//! Windows: hooks are POSIX `sh` (Git for Windows ships `sh`, which is how
//! git executes hooks on every platform). The Rust side never assumes unix:
//! executable bits are set only behind `#[cfg(unix)]`, all paths go through
//! [`std::path`], and no symlinks are used. Documented limitation: on
//! Windows the dispatcher relies on the file's extension-less `sh`
//! association via git's own hook runner, exactly like every other git hook.

use std::io;
use std::path::{Path, PathBuf};

use crate::spool::LinkConfidence;

/// Marker carried by every dispatcher this CLI installs. `disable` only
/// removes hook files containing this marker, so user hooks are never
/// deleted.
pub const MANAGED_MARKER: &str = "# starforge-managed";

/// Hooks managed by `enable`/`disable`.
pub const HOOKS: &[&str] = &["prepare-commit-msg", "post-commit", "pre-push"];

/// Trailer key appended by the `prepare-commit-msg` handler.
pub const TRAILER_KEY: &str = "Starforge-Session";

/// Suffix for the backup of a pre-existing user hook.
pub const ORIG_SUFFIX: &str = ".starforge-orig";

fn is_managed(bytes: &[u8]) -> bool {
    bytes
        .windows(MANAGED_MARKER.len())
        .any(|w| w == MANAGED_MARKER.as_bytes())
}

/// Dispatcher script for `hook`.
///
/// Runs `<hook>.starforge-orig` first (when present and executable), then
/// the matching hidden `starforge _hook-*` command. `prepare-commit-msg`
/// propagates the orig hook's exit status while the starforge step never
/// fails the commit; the other hooks always exit `0`.
pub fn dispatcher_body(hook: &str) -> String {
    let hidden = format!("_hook-{hook}");
    let header = format!(
        "#!/bin/sh\n{MANAGED_MARKER}: {hook} (installed by `starforge enable`; `starforge disable` removes this file)\n"
    );
    match hook {
        "prepare-commit-msg" => format!(
            "{header}\
             ORIG=\"$0{ORIG_SUFFIX}\"\n\
             ORIG_STATUS=0\n\
             if [ -x \"$ORIG\" ]; then\n\
             \x20 \"$ORIG\" \"$@\"\n\
             \x20 ORIG_STATUS=$?\n\
             fi\n\
             starforge {hidden} \"$1\"\n\
             exit $ORIG_STATUS\n"
        ),
        _ => format!(
            "{header}\
             ORIG=\"$0{ORIG_SUFFIX}\"\n\
             if [ -x \"$ORIG\" ]; then\n\
             \x20 \"$ORIG\" \"$@\"\n\
             fi\n\
             starforge {hidden}\n\
             exit 0\n"
        ),
    }
}

/// Install the dispatcher for `hook` (one of [`HOOKS`]) in
/// `<common_dir>/hooks`.
///
/// An existing non-managed file moves to `<hook>.starforge-orig` (an
/// already-installed dispatcher is left byte-identical). Returns the
/// dispatcher path written.
pub fn install_hook(common_dir: &Path, hook: &str) -> io::Result<PathBuf> {
    let dir = common_dir.join("hooks");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(hook);
    if path.exists() {
        let body = std::fs::read(&path)?;
        if is_managed(&body) {
            return Ok(path);
        }
        let backup = dir.join(format!("{hook}{ORIG_SUFFIX}"));
        if !backup.exists() {
            std::fs::rename(&path, &backup)?;
        } else {
            // A backup already exists (user replaced the dispatcher by
            // hand): replace the hook without clobbering the backup.
            std::fs::remove_file(&path)?;
        }
    }
    std::fs::write(&path, dispatcher_body(hook))?;
    make_executable(&path)?;
    Ok(path)
}

/// Remove the dispatcher for `hook` only when it carries the marker, and
/// restore `<hook>.starforge-orig` over it when present.
///
/// Returns every path changed (removed dispatcher, restored original).
/// A non-managed hook file is never touched; removing twice changes nothing.
pub fn remove_hook(common_dir: &Path, hook: &str) -> io::Result<Vec<PathBuf>> {
    let dir = common_dir.join("hooks");
    let path = dir.join(hook);
    let mut changed = Vec::new();
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(changed),
        Err(err) => return Err(err),
    };
    if !is_managed(&body) {
        return Ok(changed);
    }
    std::fs::remove_file(&path)?;
    changed.push(path.clone());
    let backup = dir.join(format!("{hook}{ORIG_SUFFIX}"));
    if backup.exists() {
        std::fs::rename(&backup, &path)?;
        changed.push(path);
    }
    Ok(changed)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Format one trailer line for `ulid`.
pub fn trailer_line(ulid: &str) -> String {
    format!("{TRAILER_KEY}: {ulid}")
}

/// ULIDs already claimed by `Starforge-Session:` trailers in `msg`, in order.
pub fn existing_trailer_ulids(msg: &str) -> Vec<String> {
    msg.lines()
        .filter_map(|line| line.strip_prefix("Starforge-Session:"))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Append one trailer per `ulid` (stable order of the input slice), skipping
/// ULIDs already present. Existing lines are never rewritten.
pub fn append_trailers(msg: &str, ulids: &[String]) -> String {
    let mut seen = existing_trailer_ulids(msg);
    let mut out = msg.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for ulid in ulids {
        if seen.iter().any(|u| u == ulid) {
            continue;
        }
        seen.push(ulid.clone());
        out.push_str(&trailer_line(ulid));
        out.push('\n');
    }
    out
}

/// One linkable session: its touched files plus whether it shows activity
/// (new events or recorded file touches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCandidate {
    /// Session ULID.
    pub ulid: String,
    /// Repo-relative or absolute paths the session touched.
    pub files_touched: Vec<String>,
    /// True when the session produced new events or file touches.
    pub active: bool,
}

/// A selected session link with its confidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLink {
    /// Session ULID.
    pub ulid: String,
    /// `exact` on staged-file overlap, else `heuristic`.
    pub confidence: LinkConfidence,
}

/// Link selection (§7.2): sessions whose `files_touched` overlap the staged
/// files link with `exact` confidence; sessions with activity but no overlap
/// link with `heuristic` confidence; inactive sessions with no overlap are
/// skipped. Output is deduped by ULID in stable (sorted) order.
pub fn select_links(staged: &[String], candidates: &[SessionCandidate]) -> Vec<PendingLink> {
    let mut sorted: Vec<&SessionCandidate> = candidates.iter().collect();
    sorted.sort_by(|a, b| a.ulid.cmp(&b.ulid));
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for candidate in sorted {
        if !seen.insert(candidate.ulid.clone()) {
            continue;
        }
        if overlaps(&candidate.files_touched, staged) {
            out.push(PendingLink {
                ulid: candidate.ulid.clone(),
                confidence: LinkConfidence::Exact,
            });
        } else if candidate.active {
            out.push(PendingLink {
                ulid: candidate.ulid.clone(),
                confidence: LinkConfidence::Heuristic,
            });
        }
    }
    out
}

fn overlaps(touched: &[String], staged: &[String]) -> bool {
    touched
        .iter()
        .any(|t| staged.iter().any(|s| paths_match(t, s)))
}

/// Path overlap: exact match after slash normalization, or the touched path
/// (often absolute) ending in `/<staged>` (repo-relative from git).
pub fn paths_match(touched: &str, staged: &str) -> bool {
    let touched = normalize_path(touched);
    let staged = normalize_path(staged);
    if touched.is_empty() || staged.is_empty() {
        return false;
    }
    if touched == staged {
        return true;
    }
    touched.ends_with(&format!("/{staged}"))
}

fn normalize_path(path: &str) -> String {
    path.trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_carries_marker_and_chains_orig() {
        for hook in HOOKS {
            let body = dispatcher_body(hook);
            assert!(body.contains(MANAGED_MARKER));
            assert!(body.contains(ORIG_SUFFIX));
            assert!(body.contains(&format!("_hook-{hook}")));
        }
    }

    #[test]
    fn install_is_idempotent_and_remove_restores() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("hooks")).unwrap();
        let orig = "#!/bin/sh\necho hi\n";
        std::fs::write(dir.path().join("hooks").join("prepare-commit-msg"), orig).unwrap();
        let written = install_hook(dir.path(), "prepare-commit-msg").unwrap();
        assert!(
            std::fs::read_to_string(&written)
                .unwrap()
                .contains(MANAGED_MARKER)
        );
        assert_eq!(
            std::fs::read_to_string(
                dir.path()
                    .join("hooks")
                    .join("prepare-commit-msg.starforge-orig")
            )
            .unwrap(),
            orig
        );
        let before = std::fs::read(&written).unwrap();
        install_hook(dir.path(), "prepare-commit-msg").unwrap();
        assert_eq!(std::fs::read(&written).unwrap(), before);
        let changed = remove_hook(dir.path(), "prepare-commit-msg").unwrap();
        assert_eq!(changed.len(), 2);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("hooks").join("prepare-commit-msg")).unwrap(),
            orig
        );
    }
}
