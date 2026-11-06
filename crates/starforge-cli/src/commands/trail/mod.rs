//! `starforge trail` commands (M2d J3–J5): list/show/create/comment here,
//! checkout/push in `sync`, review/merge in `decide`.

pub mod decide;
pub mod read;
pub mod sync;
pub mod write;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::api::ApiClient;
use crate::config::CliPaths;

/// Injected context for trail commands: the API client, the repo the command
/// runs in, the chosen remote name (if any), and extra env for git subprocesses
/// (empty in production; hermetic sets in tests). J3 handlers use only `api`.
/// `Debug` redacts the token via [`ApiClient`].
#[derive(Debug)]
pub struct TrailCtx {
    pub api: ApiClient,
    pub repo_dir: PathBuf,
    pub remote: Option<String>,
    pub git_env: Vec<(OsString, OsString)>,
}

impl TrailCtx {
    /// Discover the server and resolve the token for `repo_dir`. `git_env` is
    /// empty: production git inherits its own environment.
    pub async fn resolve(repo_dir: &Path, paths: &CliPaths) -> Result<TrailCtx, String> {
        let (server, owner_repo, chosen) = crate::commands::status::resolve_server(repo_dir, paths)
            .await
            .map_err(|err| err.to_string())?;
        let host = crate::cli::sync_host_key(&server.api_url)
            .ok_or_else(|| format!("invalid server api_url: {}", server.api_url))?;
        let token = crate::auth::resolve_token(paths, &host, |key| std::env::var(key).ok())
            .map_err(|err| err.to_string())?;
        let api = ApiClient::new(&server.api_url, &owner_repo, token.token())
            .map_err(|err| err.to_string())?;
        // Git ops use the remote NAME, never the sanitized display URL: the
        // name preserves the user's own credentials and remote config.
        let remotes = crate::git::remotes(repo_dir).unwrap_or_default();
        let remote = crate::discovery::remote_name_for_chosen(&remotes, &chosen).unwrap_or(chosen);
        Ok(TrailCtx {
            api,
            repo_dir: repo_dir.to_path_buf(),
            remote: Some(remote),
            git_env: Vec::new(),
        })
    }

    /// Build a context with everything injected (no env, no I/O); tests use this.
    pub fn new(
        api: ApiClient,
        repo_dir: &Path,
        remote: Option<&str>,
        git_env: Vec<(OsString, OsString)>,
    ) -> TrailCtx {
        TrailCtx {
            api,
            repo_dir: repo_dir.to_path_buf(),
            remote: remote.map(str::to_string),
            git_env,
        }
    }
}

/// Output format. Only `show` accepts `agent`; the other subcommands take a
/// narrower enum so clap rejects `agent` as a usage error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Agent,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Format::Text => write!(f, "text"),
            Format::Json => write!(f, "json"),
            Format::Agent => write!(f, "agent"),
        }
    }
}

/// `--format text|json` for every subcommand but `show`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum TextJson {
    Text,
    Json,
}

impl std::fmt::Display for TextJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextJson::Text => write!(f, "text"),
            TextJson::Json => write!(f, "json"),
        }
    }
}

impl From<TextJson> for Format {
    fn from(format: TextJson) -> Format {
        match format {
            TextJson::Text => Format::Text,
            TextJson::Json => Format::Json,
        }
    }
}

/// Read a `--body`/`--body-file` pair. Exactly one source; `-` reads stdin;
/// empty text is allowed (the server decides). Errors carry no prefix; the
/// caller formats them as `error: …`.
pub fn read_body(
    body: Option<&str>,
    body_file: Option<&Path>,
    stdin: impl std::io::Read,
) -> Result<String, String> {
    match (body, body_file) {
        (Some(_), Some(_)) => Err("only one of --body and --body-file may be given".to_string()),
        (None, None) => Err("one of --body or --body-file is required".to_string()),
        (Some(text), None) => Ok(text.to_string()),
        (None, Some(path)) if path.as_os_str() == "-" => read_stdin(stdin),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read body file {}: {err}", path.display())),
    }
}

fn read_stdin(mut stdin: impl std::io::Read) -> Result<String, String> {
    let mut text = String::new();
    stdin
        .read_to_string(&mut text)
        .map_err(|err| format!("cannot read stdin: {err}"))?;
    Ok(text)
}

/// Pick the change for `--change`: `wanted` must name an existing change;
/// otherwise the single open change (with `allow_sole_closed`, the only
/// change when none is open). Anything else errors listing `k (state)`.
/// (D4; `checkout` passes `allow_sole_closed = true`, the rest pass false.)
pub fn select_change(
    changes: &[serde_json::Value],
    wanted: Option<i64>,
    allow_sole_closed: bool,
) -> Result<i64, String> {
    if let Some(k) = wanted {
        if changes
            .iter()
            .any(|change| change.get("k").and_then(|v| v.as_i64()) == Some(k))
        {
            return Ok(k);
        }
        return Err(format!(
            "no change {k} (available: {})",
            change_list(changes)
        ));
    }
    let open: Vec<i64> = changes
        .iter()
        .filter(|change| change.get("state").and_then(|v| v.as_str()) == Some("open"))
        .filter_map(|change| change.get("k").and_then(|v| v.as_i64()))
        .collect();
    if open.len() == 1 {
        return Ok(open[0]);
    }
    if open.is_empty()
        && allow_sole_closed
        && changes.len() == 1
        && let Some(k) = changes[0].get("k").and_then(|v| v.as_i64())
    {
        return Ok(k);
    }
    Err(format!(
        "specify --change K (available: {})",
        change_list(changes)
    ))
}

/// `k (state)` per change, in order; `(none)` when there are no changes.
fn change_list(changes: &[serde_json::Value]) -> String {
    if changes.is_empty() {
        return "(none)".to_string();
    }
    changes
        .iter()
        .map(|change| {
            let k = change
                .get("k")
                .and_then(|v| v.as_i64())
                .map_or("?".to_string(), |k| k.to_string());
            let state = change.get("state").and_then(|v| v.as_str()).unwrap_or("?");
            format!("{k} ({state})")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Pretty JSON for `--format json` passthrough.
pub(crate) fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

/// `--format agent` outside `trail show` is a handler-level backstop (clap
/// rejects it first); every other command errors the same way.
pub(crate) fn agent_unsupported() -> (String, u8) {
    (
        "error: --format agent is only supported by `trail show`".to_string(),
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn body_sources_are_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("body.md");
        std::fs::write(&file, "from file").unwrap();
        assert_eq!(
            read_body(Some("x"), Some(&file), Cursor::new("")),
            Err("only one of --body and --body-file may be given".to_string())
        );
        assert_eq!(
            read_body(None, None, Cursor::new("")),
            Err("one of --body or --body-file is required".to_string())
        );
        assert_eq!(
            read_body(Some("x"), None, Cursor::new("")),
            Ok("x".to_string())
        );
        assert_eq!(
            read_body(None, Some(&file), Cursor::new("")),
            Ok("from file".to_string())
        );
        assert_eq!(
            read_body(None, Some(Path::new("-")), Cursor::new("piped")),
            Ok("piped".to_string())
        );
        assert!(read_body(None, Some(Path::new("missing.md")), Cursor::new("")).is_err());
        assert!(read_body(None, Some(&dir.path().join("absent.md")), Cursor::new("")).is_err());
        // Empty text is allowed.
        assert_eq!(
            read_body(Some(""), None, Cursor::new("")),
            Ok(String::new())
        );
    }

    fn changes() -> Vec<serde_json::Value> {
        vec![
            json!({"k": 1, "state": "open"}),
            json!({"k": 2, "state": "closed"}),
        ]
    }

    #[test]
    fn select_change_wanted_must_exist() {
        assert_eq!(select_change(&changes(), Some(2), false), Ok(2));
        assert!(
            select_change(&changes(), Some(9), false)
                .unwrap_err()
                .contains("no change 9")
        );
    }

    #[test]
    fn select_change_defaults_to_single_open() {
        assert_eq!(select_change(&changes(), None, false), Ok(1));
        let two_open = vec![
            json!({"k": 1, "state": "open"}),
            json!({"k": 2, "state": "open"}),
        ];
        let err = select_change(&two_open, None, false).unwrap_err();
        assert!(
            err.contains("1 (open)") && err.contains("2 (open)"),
            "{err}"
        );
        let none_open = vec![json!({"k": 1, "state": "closed"})];
        assert_eq!(select_change(&none_open, None, true), Ok(1));
        let err = select_change(&none_open, None, false).unwrap_err();
        assert!(err.contains("1 (closed)"), "{err}");
        let two_closed = vec![
            json!({"k": 1, "state": "closed"}),
            json!({"k": 2, "state": "merged"}),
        ];
        assert!(select_change(&two_closed, None, true).is_err());
        assert!(select_change(&[], None, true).is_err());
    }

    #[test]
    fn debug_redacts_the_token() {
        let token = "sk-test-distinctive-token-ABCDEF123456";
        let api = ApiClient::new("http://host:8080/", "o/r", token).unwrap();
        let ctx = TrailCtx::new(api, Path::new("/tmp/cli-trail"), Some("origin"), Vec::new());
        let shown = format!("{ctx:?}");
        assert!(!shown.contains(token), "token leaked: {shown}");
        assert!(
            !shown.contains(&token[token.len() - 8..]),
            "token tail leaked: {shown}"
        );
        assert!(shown.contains("<redacted>"), "redaction marker: {shown}");
    }
}
