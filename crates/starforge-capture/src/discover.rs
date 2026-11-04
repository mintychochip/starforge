use std::path::{Component, Path};

/// True when `workdir` lies inside `worktree` (prefix match on path components).
///
/// Comparison is component-wise: `/repo` contains `/repo/sub` but not
/// `/repo2`. `.` segments are dropped and `..` segments pop the previous
/// normal component lexically; no filesystem access is performed so neither
/// path needs to exist.
pub fn workdir_inside(worktree: &Path, workdir: &Path) -> bool {
    let base = normalize(worktree);
    let dir = normalize(workdir);
    if dir.len() < base.len() {
        return false;
    }
    dir[..base.len()] == base[..]
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
}
