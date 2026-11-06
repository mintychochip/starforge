//! Creating hosted repositories and installing their hooks.

use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

/// Hooks installed in every hosted repository; each runs `<hook_exe> hook <name>`.
pub const HOOKS: &[&str] = &["pre-receive"];

/// Creates a bare repository at `path` (parents included) whose HEAD points at `default_branch`,
/// enables partial-clone filters, and installs the hooks.
pub async fn init_bare(path: &Path, default_branch: &str, hook_exe: &Path) -> Result<(), GitError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    run([
        OsStr::new("init"),
        OsStr::new("--bare"),
        OsStr::new("--quiet"),
        OsStr::new("--initial-branch"),
        OsStr::new(default_branch),
        path.as_os_str(),
    ])
    .await?;
    run([
        OsStr::new("--git-dir"),
        path.as_os_str(),
        OsStr::new("config"),
        OsStr::new("uploadpack.allowFilter"),
        OsStr::new("true"),
    ])
    .await?;
    install_hooks(path, hook_exe).await
}

pub async fn install_hooks(repo: &Path, hook_exe: &Path) -> Result<(), GitError> {
    let dir = repo.join("hooks");
    tokio::fs::create_dir_all(&dir).await?;
    for name in HOOKS {
        let path = dir.join(name);
        tokio::fs::write(&path, hook_script(hook_exe, name)).await?;
        set_executable(&path).await?;
    }
    Ok(())
}

pub fn hook_script(hook_exe: &Path, name: &str) -> String {
    format!(
        "#!/bin/sh\nexec {} hook {name}\n",
        shell_quote(&hook_exe.to_string_lossy())
    )
}

/// The expected content of the hook script for `name` when installed by
/// `hook_exe`. Exposed for `starforged doctor`, which verifies every hosted
/// repository carries exactly this content (modulo the hook executable
/// path, which may move between releases — see [`is_expected_hook`]).
pub fn expected_hook_content(hook_exe: &Path, name: &str) -> String {
    hook_script(hook_exe, name)
}

/// Whether `content` is a hook script of the shape [`hook_script`] writes
/// for `name`: a `/bin/sh` wrapper that execs the server binary with
/// `hook <name>`. The executable path itself is not compared, so a binary
/// upgrade that moved the executable does not read as drift.
pub fn is_expected_hook(content: &str, name: &str) -> bool {
    let Some(rest) = content.strip_prefix("#!/bin/sh\nexec ") else {
        return false;
    };
    rest.ends_with(&format!(" hook {name}\n"))
}

/// Single-quotes `s` for `/bin/sh`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(unix)]
async fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).await
}

#[cfg(not(unix))]
async fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::run;

    #[tokio::test]
    async fn init_bare_creates_head_config_and_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("07").join("7.git");
        init_bare(&repo, "main", Path::new("/opt/star forge/starforged"))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(repo.join("HEAD")).unwrap().trim(),
            "ref: refs/heads/main"
        );
        let hook = std::fs::read_to_string(repo.join("hooks/pre-receive")).unwrap();
        assert_eq!(
            hook,
            "#!/bin/sh\nexec '/opt/star forge/starforged' hook pre-receive\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(repo.join("hooks/pre-receive"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        let filter = run([
            std::ffi::OsStr::new("--git-dir"),
            repo.as_os_str(),
            std::ffi::OsStr::new("config"),
            std::ffi::OsStr::new("--get"),
            std::ffi::OsStr::new("uploadpack.allowFilter"),
        ])
        .await
        .unwrap();
        assert_eq!(String::from_utf8(filter).unwrap().trim(), "true");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
