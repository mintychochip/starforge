//! Shared hermetic-process helper for CLI integration tests.
//!
//! Every spawn of the `starforge` binary, a shim calling it, or the
//! installed git hook dispatchers MUST go through [`hermetic_command`] so no
//! test can read the developer's real `$HOME` / agent stores or inherit a
//! real token / agent-store override from the environment.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// A `Command` for `program` pinned to the test's temp `home`:
/// `STARFORGE_HOME` and `HOME` point at `home`, and the agent-store / token
/// overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_DATA_HOME`,
/// `XDG_CONFIG_HOME`, `STARFORGE_TOKEN`) are removed. Callers that need a
/// token set `.env("STARFORGE_TOKEN", …)` after this, which overrides the
/// removal.
pub fn hermetic_command(program: impl AsRef<OsStr>, home: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("STARFORGE_HOME", home)
        .env("HOME", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("STARFORGE_TOKEN");
    cmd
}
