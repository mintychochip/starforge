use std::path::{Component, Path};

/// True when `workdir` lies inside `worktree`.
///
/// When both paths exist on disk they are compared on their canonicalized
/// (symlink-resolved) forms, so a symlink inside the worktree that points
/// outside never counts as inside. Paths that do not exist fall back to
/// lexical component-wise comparison (`/repo` contains `/repo/sub` but not
/// `/repo2`; `.` segments are dropped and `..` segments pop the previous
/// normal component lexically).
pub fn workdir_inside(worktree: &Path, workdir: &Path) -> bool {
    let base = canonical_or_lexical(worktree);
    let dir = canonical_or_lexical(workdir);
    if dir.len() < base.len() {
        return false;
    }
    dir[..base.len()] == base[..]
}

/// Owned path components when `path` exists (canonicalized) or lexically
/// otherwise: symlink targets are resolved before comparison.
fn canonical_or_lexical(path: &Path) -> Vec<String> {
    let resolved;
    let effective = match std::fs::canonicalize(path) {
        Ok(r) => {
            resolved = r;
            &resolved
        }
        Err(_) => path,
    };
    let mut out: Vec<(String, bool)> = Vec::new();
    for c in effective.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.last(), Some((_, true))) {
                    out.pop();
                }
            }
            Component::Normal(_) => {
                out.push((c.as_os_str().to_string_lossy().into_owned(), true));
            }
            _ => out.push((c.as_os_str().to_string_lossy().into_owned(), false)),
        }
    }
    out.into_iter().map(|(s, _)| s).collect()
}

/// Lexically normalise path components: drop `.`, resolve `..` by popping
/// the previous normal component. Prefixes (`/`, `C:`) and roots are kept
/// as leading components so absolute/relative shapes still compare sanely.
fn normalize(path: &Path) -> Vec<Component<'_>> {
    let mut out: Vec<Component<'_>> = Vec::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Relative slash path of `path` inside `workdir`, or `None` when outside.
/// Comparison is lexical on normalized components (same rules as
/// [`workdir_inside`]): `.` segments are dropped, `..` pops the previous
/// component, and a `..` that escapes above `workdir` (or a path that never
/// shares `workdir` as a component prefix, e.g. an absolute path elsewhere
/// or a Windows `C:\…` path on a Unix workdir) yields `None`. A path equal
/// to `workdir` itself also yields `None`: the workdir directory is not a
/// file inside it. No filesystem access; neither path needs to exist.
pub(crate) fn repo_relative(workdir: &Path, path: &str) -> Option<String> {
    let base = normalize(workdir);
    let full = normalize(Path::new(path));
    if full.len() < base.len() || full[..base.len()] != base[..] {
        return None;
    }
    let mut parts = Vec::new();
    for c in &full[base.len()..] {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            // `normalize` already dropped `.` and resolved `..`, so only
            // normal segments can remain past the shared prefix.
            _ => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workdir_prefix_is_component_wise() {
        assert!(workdir_inside(Path::new("/repo"), Path::new("/repo/sub")));
        assert!(!workdir_inside(Path::new("/repo"), Path::new("/other")));
        assert!(!workdir_inside(Path::new("/repo"), Path::new("/repo2")));
    }

    #[test]
    fn workdir_inside_normalises_dot_segments() {
        assert!(workdir_inside(
            Path::new("/repo"),
            Path::new("/repo/sub/../sub2/./leaf")
        ));
        assert!(!workdir_inside(
            Path::new("/repo"),
            Path::new("/repo/../other")
        ));
        // Trailing slashes do not affect the comparison.
        assert!(workdir_inside(Path::new("/repo/"), Path::new("/repo/sub/")));
    }

    #[test]
    fn repo_relative_inside_gives_slash_path() {
        assert_eq!(
            repo_relative(Path::new("/repo"), "/repo/src/auth.rs"),
            Some("src/auth.rs".to_string())
        );
        // Trailing slash on the workdir does not matter.
        assert_eq!(
            repo_relative(Path::new("/repo/"), "/repo/src/auth.rs"),
            Some("src/auth.rs".to_string())
        );
        // `.` segments resolve inside.
        assert_eq!(
            repo_relative(Path::new("/repo"), "/repo/sub/../src/auth.rs"),
            Some("src/auth.rs".to_string())
        );
    }

    #[test]
    fn repo_relative_outside_is_none() {
        // Absolute path elsewhere.
        assert_eq!(
            repo_relative(Path::new("/repo"), "/other/src/auth.rs"),
            None
        );
        // Sibling prefix is not a component match.
        assert_eq!(
            repo_relative(Path::new("/repo"), "/repo2/src/auth.rs"),
            None
        );
        // `..` traversal escaping the workdir.
        assert_eq!(
            repo_relative(Path::new("/repo"), "/repo/../other/auth.rs"),
            None
        );
        assert_eq!(
            repo_relative(Path::new("/repo"), "/repo/sub/../../other.rs"),
            None
        );
        // Relative paths have no anchor to compare against.
        assert_eq!(repo_relative(Path::new("/repo"), "src/auth.rs"), None);
        // Windows drive paths never match a Unix workdir.
        assert_eq!(
            repo_relative(Path::new("/repo"), "C:\\repo\\src\\auth.rs"),
            None
        );
    }

    #[test]
    fn repo_relative_equal_is_none() {
        // The workdir itself is a directory, not a file inside it.
        assert_eq!(repo_relative(Path::new("/repo"), "/repo"), None);
        assert_eq!(repo_relative(Path::new("/repo"), "/repo/."), None);
    }

    #[cfg(unix)]
    #[test]
    fn workdir_inside_symlink_outside_is_not_inside() {
        let tmp = tempfile::tempdir().unwrap();
        let worktree = tmp.path().join("repo");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let link = worktree.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(
            !workdir_inside(&worktree, &link),
            "symlink inside the tree pointing outside must not count as inside"
        );
        assert!(workdir_inside(&worktree, &worktree));
    }
}
