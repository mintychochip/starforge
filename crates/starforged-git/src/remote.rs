//! Outbound git remote operations for import and mirroring (M4b).
//!
//! Every operation runs the hermetic [`crate::command::git`] helper with a
//! timeout, `GIT_TERMINAL_PROMPT=0`, a protocol allow-list
//! (`protocol.allow=never` plus explicit allows), `http.followRedirects=false`,
//! and a pinned destination address so a DNS change between the policy
//! check and git's own lookup cannot redirect the connection.
//!
//! Credentials travel only through the environment
//! (`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` as an
//! `http.extraHeader` Basic-auth header, or a 0600 SSH key file) — never
//! argv, never URLs. [`scrub`] removes URL userinfo from stderr before it
//! is stored or rendered.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;

use crate::command::{GitError, git};

/// Transport of a policy-checked remote URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteScheme {
    Https,
    Http,
    Ssh,
    File,
}

/// A remote URL that passed [`crate::remotes`] policy, with the address the
/// policy check resolved pinned for git to use.
///
/// `url` is the URL git receives: userinfo passwords are stripped (the
/// password travels via the `http.extraHeader` env, never the URL).
/// `pinned_ip` is `None` for IP literals, `file://` URLs, and local paths
/// (nothing to pin); otherwise it is the first host-allowed address the
/// resolver returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRemote {
    pub url: String,
    pub scheme: RemoteScheme,
    pub host: String,
    pub port: u16,
    pub pinned_ip: Option<IpAddr>,
}

impl PinnedRemote {
    /// `-c` arguments: the protocol allow-list, no redirects, and the
    /// pinned HTTPS resolve entry when there is an IP to pin.
    pub fn config_args(&self) -> Vec<String> {
        let mut args = vec![
            "-c".to_owned(),
            "protocol.allow=never".to_owned(),
            "-c".to_owned(),
            "http.followRedirects=false".to_owned(),
        ];
        let allow = match self.scheme {
            RemoteScheme::Https => "protocol.https.allow=always",
            RemoteScheme::Http => "protocol.http.allow=always",
            RemoteScheme::Ssh => "protocol.ssh.allow=always",
            RemoteScheme::File => "protocol.file.allow=always",
        };
        args.push("-c".to_owned());
        args.push(allow.to_owned());
        if let Some(ip) = self.pinned_ip
            && matches!(self.scheme, RemoteScheme::Https | RemoteScheme::Http)
        {
            args.push("-c".to_owned());
            args.push(format!(
                "http.curloptResolve={}:{}:{}",
                self.host, self.port, ip
            ));
        }
        args
    }

    /// Extra `ssh` options pinning the connection to the checked address:
    /// `HostName=<ip>` connects to the pinned IP while `HostKeyAlias=<host>`
    /// keeps host-key verification against the original name.
    pub fn ssh_args(&self) -> Vec<String> {
        let mut args = vec![
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
        ];
        if self.scheme == RemoteScheme::Ssh
            && let Some(ip) = self.pinned_ip
        {
            args.push("-o".to_owned());
            args.push(format!("HostName={ip}"));
            args.push("-o".to_owned());
            args.push(format!("HostKeyAlias={}", self.host));
        }
        args
    }

    /// The full `GIT_SSH_COMMAND` for an SSH remote, or `None` otherwise.
    /// `key_file`, when given, is passed as `-i <key_file>`.
    pub fn ssh_command(&self, key_file: Option<&Path>) -> Option<String> {
        if self.scheme != RemoteScheme::Ssh {
            return None;
        }
        let mut parts = vec!["ssh".to_owned()];
        parts.extend(self.ssh_args());
        if let Some(key) = key_file {
            parts.push("-i".to_owned());
            parts.push(key.to_string_lossy().into_owned());
        }
        Some(parts.join(" "))
    }
}

/// Credentials for one remote operation. HTTPS credentials become an
/// `http.extraHeader` env entry; an SSH private key is written to a 0600
/// temporary file for the duration of one command and removed afterwards.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RemoteCreds {
    #[default]
    None,
    Basic {
        username: String,
        password: String,
    },
    SshKey {
        private_key: String,
    },
}
impl std::fmt::Debug for RemoteCreds {
    /// Redacted: the password and private key never render in any format.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteCreds::None => f.write_str("None"),
            RemoteCreds::Basic { username, .. } => {
                write!(
                    f,
                    "Basic {{ username: {username:?}, password: <redacted> }}"
                )
            }
            RemoteCreds::SshKey { .. } => f.write_str("SshKey { private_key: <redacted> }"),
        }
    }
}

/// Removes the password from any URL userinfo in `stderr` (and any exact
/// occurrence of `url`'s password) so secrets never reach logs or stored
/// `last_error` rows. The username, host, and path stay for debuggability.
pub fn scrub(stderr: &str, url: &str) -> String {
    let mut out = stderr.to_owned();
    // Replace every `://user:password@` with `://user@`.
    out = scrub_userinfo(&out);
    // Belt and braces: the literal password from the URL, if any, is gone.
    if let Some(password) = url_password(url)
        && !password.is_empty()
    {
        out = out.replace(&password, "<redacted>");
    }
    // The full original URL (with userinfo) must not survive either.
    let clean = scrub_userinfo(url);
    if url != clean {
        out = out.replace(url, &clean);
    }
    out
}

fn scrub_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(idx) = rest.find("://") {
        out.push_str(&rest[..idx + 3]);
        rest = &rest[idx + 3..];
        // Userinfo runs to the next `@` before any `/`, `?`, `#`, or space.
        let end = rest.find(['/', '?', '#', ' ', '\n']).unwrap_or(rest.len());
        let authority = &rest[..end];
        if let Some(at) = authority.find('@') {
            let userinfo = &authority[..at];
            if let Some(colon) = userinfo.find(':') {
                out.push_str(&userinfo[..colon + 1]);
                out.push_str("<redacted>");
            } else {
                out.push_str(userinfo);
            }
            out.push('@');
            out.push_str(&authority[at + 1..]);
        } else {
            out.push_str(authority);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn url_password(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let authority = after.split(['/', '?', '#']).next()?;
    let userinfo = authority.rsplit_once('@')?.0;
    let password = userinfo.split_once(':')?.1;
    // Percent-decoding is unnecessary: git echoes the literal bytes it was
    // given, and the policy strips passwords from URLs before handing them
    // to git in the first place.
    Some(password.to_owned())
}

/// `git fetch --prune -- <url> <refspec>...` argv (no credentials, ever).
/// The `--` keeps a dash-leading URL/refspec positional, and
/// [`validate_positionals`] refuses such values outright anyway.
pub fn fetch_args(pinned: &PinnedRemote, refspecs: &[String]) -> Vec<String> {
    let mut args = pinned.config_args();
    args.push("fetch".to_owned());
    args.push("--prune".to_owned());
    args.push("--".to_owned());
    args.push(pinned.url.clone());
    args.extend(refspecs.iter().cloned());
    args
}

/// `git push --prune -- <url> <refspec>...` argv (no credentials, ever).
pub fn push_args(pinned: &PinnedRemote, refspecs: &[String]) -> Vec<String> {
    let mut args = pinned.config_args();
    args.push("push".to_owned());
    args.push("--prune".to_owned());
    args.push("--".to_owned());
    args.push(pinned.url.clone());
    args.extend(refspecs.iter().cloned());
    args
}

/// `git ls-remote --symref <url> HEAD` argv (no credentials, ever).
pub fn ls_remote_args(pinned: &PinnedRemote) -> Vec<String> {
    let mut args = pinned.config_args();
    args.push("ls-remote".to_owned());
    args.push("--symref".to_owned());
    args.push(pinned.url.clone());
    args.push("HEAD".to_owned());
    args
}

/// Refuses a dash-leading URL or refspec before git is spawned: git would
/// otherwise read it as an option (e.g. `--upload-pack=<cmd>`).
fn validate_positionals(
    pinned: &PinnedRemote,
    refspecs: &[String],
    args: &[String],
) -> Result<(), GitError> {
    let command = args.join(" ");
    let bad = |value: &str| GitError::Failed {
        command: command.clone(),
        stderr: format!("remote url or refspec must not start with '-': {value}"),
    };
    if pinned.url.starts_with('-') {
        return Err(bad(&pinned.url));
    }
    for refspec in refspecs {
        if refspec.starts_with('-') {
            return Err(bad(refspec));
        }
    }
    Ok(())
}

/// Environment entries carrying credentials, as
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` pairs.
/// Empty for [`RemoteCreds::None`]; SSH keys are handled by a temp file,
/// not the environment.
pub fn credential_env(creds: &RemoteCreds) -> Vec<(String, String)> {
    match creds {
        RemoteCreds::None | RemoteCreds::SshKey { .. } => Vec::new(),
        RemoteCreds::Basic { username, password } => {
            let token =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            vec![
                ("GIT_CONFIG_COUNT".to_owned(), "1".to_owned()),
                ("GIT_CONFIG_KEY_0".to_owned(), "http.extraHeader".to_owned()),
                (
                    "GIT_CONFIG_VALUE_0".to_owned(),
                    format!("Authorization: Basic {token}"),
                ),
            ]
        }
    }
}

/// The result of a successful fetch or push. `stderr` is git's stderr,
/// scrubbed of URL userinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    pub stderr: String,
}

/// The `HEAD` of a remote: its object id and, when the remote advertises
/// it, the symref target (e.g. `refs/heads/main`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsRemoteHead {
    pub oid: Option<String>,
    pub symref: Option<String>,
}

/// Stdout and scrubbed stderr of a successful remote command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteOutput {
    stdout: String,
    stderr: String,
}

/// Runs one git command in `repo_dir` (when it exists) with the pinned
/// config, credential env, and a timeout. The single place key-file,
/// credential-env, and spawn/timeout handling lives: `fetch`, `push`, and
/// `ls_remote_head` all go through here.
async fn run_remote(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    args: Vec<String>,
    timeout: Duration,
) -> Result<RemoteOutput, GitError> {
    // An SSH key lives in a 0600 temp file for the duration of the command
    // and is removed afterwards, including on failure and timeout.
    let key_file = match creds {
        RemoteCreds::SshKey { private_key } if pinned.scheme == RemoteScheme::Ssh => {
            Some(write_key_file(private_key)?)
        }
        _ => None,
    };
    let result = run_remote_inner(
        repo_dir,
        pinned,
        creds,
        &args,
        timeout,
        key_file.as_ref().map(KeyFile::path),
    )
    .await;
    // Removal happens here on every path (success, failure, timeout);
    // dropping the `KeyFile` then removes the private temp dir too.
    if let Some(key) = &key_file {
        let _ = std::fs::remove_file(key.path());
    }
    result
}

async fn run_remote_inner(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    args: &[String],
    timeout: Duration,
    key_file: Option<&Path>,
) -> Result<RemoteOutput, GitError> {
    let scrubbed_url = pinned.url.clone();
    let command = args.join(" ");
    let mut cmd = git();
    if repo_dir.exists() {
        cmd.current_dir(repo_dir);
    }
    cmd.args(args);
    for (key, value) in credential_env(creds) {
        cmd.env(key, value);
    }
    if let Some(ssh_command) = pinned.ssh_command(key_file) {
        cmd.env("GIT_SSH_COMMAND", ssh_command);
    }
    let output = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| GitError::Failed {
            command: command.clone(),
            stderr: format!("git timed out after {}s", timeout.as_secs()),
        })??;
    let stderr = scrub(&String::from_utf8_lossy(&output.stderr), &scrubbed_url)
        .trim()
        .to_owned();
    if !output.status.success() {
        return Err(GitError::Failed {
            command,
            stderr: if stderr.is_empty() {
                format!("git exited with {}", output.status)
            } else {
                stderr
            },
        });
    }
    Ok(RemoteOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr,
    })
}

/// A 0600 SSH private-key file in a private temp dir. The dir (and the
/// file with it) is removed when this is dropped.
struct KeyFile {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl KeyFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn write_key_file(private_key: &str) -> Result<KeyFile, GitError> {
    use std::io::Write as _;
    // One step, no window: `create_new` refuses a pre-existing path (and
    // follows no symlink into it), and `mode(0o600)` applies at creation
    // rather than in a later chmod. The temp dir itself is owner-only
    // (0700); tempfile's default would be umask-filtered 0777.
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder.tempdir()?;
    let path = dir.path().join("key");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(private_key.as_bytes())?;
    Ok(KeyFile { _dir: dir, path })
}

/// `git fetch --prune -- <url> <refspec>...` with a timeout. Only the given
/// refspecs are fetched (callers pass the heads/tags refspecs), so
/// `refs/notes/*`, `refs/pull/*`, and friends never arrive.
pub async fn fetch(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    refspecs: &[String],
    timeout: Duration,
) -> Result<FetchOutcome, GitError> {
    let args = fetch_args(pinned, refspecs);
    validate_positionals(pinned, refspecs, &args)?;
    let output = run_remote(repo_dir, pinned, creds, args, timeout).await?;
    Ok(FetchOutcome {
        stderr: output.stderr,
    })
}

/// `git push --prune -- <url> <refspec>...` with a timeout.
pub async fn push(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    refspecs: &[String],
    timeout: Duration,
) -> Result<FetchOutcome, GitError> {
    let args = push_args(pinned, refspecs);
    validate_positionals(pinned, refspecs, &args)?;
    let output = run_remote(repo_dir, pinned, creds, args, timeout).await?;
    Ok(FetchOutcome {
        stderr: output.stderr,
    })
}

/// `git ls-remote --symref <url> HEAD` with a timeout: the remote's `HEAD`
/// object id and symref target (the default branch), for import.
pub async fn ls_remote_head(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    timeout: Duration,
) -> Result<LsRemoteHead, GitError> {
    let args = ls_remote_args(pinned);
    validate_positionals(pinned, &[], &args)?;
    let output = run_remote(repo_dir, pinned, creds, args, timeout).await?;
    Ok(parse_ls_remote_head(&output.stdout))
}
/// `git ls-remote <url> <ref>` argv (no credentials, ever). The explicit
/// ref argument names one ref (e.g. `refs/pull/2/head`), which GitHub and
/// plain git remotes both answer even when the ref is not advertised for
/// fetching. (`git ls-remote` takes no `--` separator; dash-leading values
/// are refused by [`validate_positionals`] before git is spawned.)
pub fn ls_remote_ref_args(pinned: &PinnedRemote, refname: &str) -> Vec<String> {
    let mut args = pinned.config_args();
    args.push("ls-remote".to_owned());
    args.push(pinned.url.clone());
    args.push(refname.to_owned());
    args
}

/// The object id `git ls-remote` reports for `refname` on the remote, or
/// `None` when the remote does not have that ref (e.g. a pull request whose
/// head ref is gone, D3).
pub async fn ls_remote_ref(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    refname: &str,
    timeout: Duration,
) -> Result<Option<String>, GitError> {
    let args = ls_remote_ref_args(pinned, refname);
    validate_positionals(pinned, &[refname.to_owned()], &args)?;
    let output = run_remote(repo_dir, pinned, creds, args, timeout).await?;
    for line in output.stdout.lines() {
        let mut parts = line.splitn(2, '\t');
        if let (Some(oid), Some(name)) = (parts.next(), parts.next())
            && name.trim() == refname
        {
            return Ok(Some(oid.trim().to_owned()));
        }
    }
    Ok(None)
}

/// The fetch refspecs carrying one GitHub pull-request head into the trail
/// refs (`refs/trails/<n>/changes/1/{head,rev/1}`), or `None` when
/// `number` is not a positive GitHub number. The destination refs are built
/// here, never from caller input, so a refspec cannot escape
/// `refs/trails/`.
pub fn pull_head_refspecs(number: i64) -> Option<Vec<String>> {
    if number <= 0 {
        return None;
    }
    Some(vec![
        format!("+refs/pull/{number}/head:refs/trails/{number}/changes/1/head"),
        format!("+refs/pull/{number}/head:refs/trails/{number}/changes/1/rev/1"),
    ])
}

/// Fetches one pull-request head (`refs/pull/<n>/head`) into the trail refs
/// of trait `number`, through the same validated [`fetch`] path (dash
/// refusal, `--`, refspec checks, credential handling, stderr scrubbing).
/// `Err` when the remote does not have the ref or the fetch fails; the
/// caller (the importer, D3) treats that as an unfetchable head, not a
/// failed import.
pub async fn fetch_pull_head(
    repo_dir: &Path,
    pinned: &PinnedRemote,
    creds: &RemoteCreds,
    number: i64,
    timeout: Duration,
) -> Result<FetchOutcome, GitError> {
    let refspecs = pull_head_refspecs(number).ok_or_else(|| GitError::Failed {
        command: "fetch pull head".to_owned(),
        stderr: format!("pull number must be positive: {number}"),
    })?;
    fetch(repo_dir, pinned, creds, &refspecs, timeout).await
}

fn parse_ls_remote_head(stdout: &str) -> LsRemoteHead {
    let mut head = LsRemoteHead {
        oid: None,
        symref: None,
    };
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("ref: ")
            && let Some(target) = rest.split_whitespace().next()
        {
            // `ref: refs/heads/main\tHEAD`
            head.symref = Some(target.to_owned());
        } else if (line.ends_with("\tHEAD") || line.ends_with(" HEAD"))
            && let Some(oid) = line.split_whitespace().next()
        {
            head.oid = Some(oid.to_owned());
        }
    }
    head
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn pinned() -> PinnedRemote {
        PinnedRemote {
            url: "https://git.example.com/owner/repo.git".to_owned(),
            scheme: RemoteScheme::Https,
            host: "git.example.com".to_owned(),
            port: 443,
            pinned_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        }
    }

    #[test]
    fn pinning_arguments_are_produced() {
        let args = pinned().config_args();
        assert!(args.iter().any(|a| a == "protocol.allow=never"), "{args:?}");
        assert!(
            args.iter().any(|a| a == "protocol.https.allow=always"),
            "{args:?}"
        );
        assert!(
            args.iter().any(|a| a == "http.followRedirects=false"),
            "{args:?}"
        );
        assert!(
            args.iter()
                .any(|a| a == "http.curloptResolve=git.example.com:443:93.184.216.34"),
            "{args:?}"
        );
        let ssh = PinnedRemote {
            url: "ssh://git@git.example.com/owner/repo.git".to_owned(),
            scheme: RemoteScheme::Ssh,
            host: "git.example.com".to_owned(),
            port: 22,
            pinned_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        };
        let ssh_args = ssh.ssh_args();
        assert!(
            ssh_args.iter().any(|a| a == "HostName=93.184.216.34"),
            "{ssh_args:?}"
        );
        assert!(
            ssh_args.iter().any(|a| a == "HostKeyAlias=git.example.com"),
            "{ssh_args:?}"
        );
    }

    #[test]
    fn argv_never_contains_the_secret() {
        let creds = RemoteCreds::Basic {
            username: "git".to_owned(),
            password: "super-secret-token".to_owned(),
        };
        let refspecs = vec!["+refs/heads/*:refs/heads/*".to_owned()];
        for args in [
            fetch_args(&pinned(), &refspecs),
            push_args(&pinned(), &refspecs),
            ls_remote_args(&pinned()),
        ] {
            assert!(
                !args.iter().any(|a| a.contains("super-secret-token")),
                "argv leaks the secret: {args:?}"
            );
        }
        // The secret travels in the environment, as a Basic header.
        let env = credential_env(&creds);
        assert!(env.iter().any(|(k, _)| k == "GIT_CONFIG_COUNT"));
        assert!(env.iter().any(|(k, _)| k == "GIT_CONFIG_KEY_0"));
        let value = env
            .iter()
            .find(|(k, _)| k == "GIT_CONFIG_VALUE_0")
            .map(|(_, v)| v)
            .unwrap();
        assert!(value.starts_with("Authorization: Basic "));
        assert!(!value.contains("super-secret-token"));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.strip_prefix("Authorization: Basic ").unwrap())
            .unwrap();
        assert_eq!(decoded, b"git:super-secret-token");
    }

    #[test]
    fn scrub_removes_url_passwords() {
        let url = "https://git:tok123@git.example.com/owner/repo.git";
        let stderr =
            format!("fatal: unable to access '{url}': The requested URL returned error: 401\n");
        let scrubbed = scrub(&stderr, url);
        assert!(!scrubbed.contains("tok123"), "{scrubbed}");
        assert!(scrubbed.contains("git.example.com"), "{scrubbed}");
        // A URL without userinfo passes through untouched.
        assert_eq!(
            scrub("plain error", "https://example.com/x.git"),
            "plain error"
        );
        // A bare token echoing the password is redacted too.
        let scrubbed = scrub("server said tok123", url);
        assert!(!scrubbed.contains("tok123"), "{scrubbed}");
    }

    #[test]
    fn parses_ls_remote_head() {
        let out = "ref: refs/heads/main\tHEAD\n0123456789abcdef0123456789abcdef01234567\tHEAD\n";
        let head = parse_ls_remote_head(out);
        assert_eq!(head.symref.as_deref(), Some("refs/heads/main"));
        assert_eq!(
            head.oid.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
    }

    #[test]
    fn fetch_and_push_args_separate_positionals_with_dashdash() {
        let refspecs = vec!["+refs/heads/*:refs/heads/*".to_owned()];
        for args in [
            fetch_args(&pinned(), &refspecs),
            push_args(&pinned(), &refspecs),
        ] {
            let dashdash = args.iter().position(|a| a == "--").unwrap();
            assert_eq!(args[dashdash + 1], pinned().url, "{args:?}");
            assert_eq!(args[dashdash + 2], refspecs[0], "{args:?}");
        }
    }

    #[tokio::test]
    async fn dash_prefixed_url_or_refspec_is_refused_before_spawning() {
        // A repo dir that does not exist: if git were spawned the error
        // would be git's own failure, not our refusal, so the message
        // proves nothing was spawned.
        let dir = Path::new("/nonexistent-starforged-repo");
        let timeout = Duration::from_secs(5);
        // Dash-leading refspec.
        let err = fetch(
            dir,
            &pinned(),
            &RemoteCreds::None,
            &["--upload-pack=id".to_owned()],
            timeout,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("must not start with '-'"), "{err}");
        let err = push(
            dir,
            &pinned(),
            &RemoteCreds::None,
            &["--receive-pack=id".to_owned()],
            timeout,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("must not start with '-'"), "{err}");
        // Dash-leading URL.
        let mut bad = pinned();
        bad.url = "--upload-pack=id".to_owned();
        let err = fetch(
            dir,
            &bad,
            &RemoteCreds::None,
            &["+refs/heads/*:refs/heads/*".to_owned()],
            timeout,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("must not start with '-'"), "{err}");
        let err = ls_remote_head(dir, &bad, &RemoteCreds::None, timeout)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must not start with '-'"), "{err}");
    }

    #[test]
    fn key_file_is_private_and_removed_with_its_dir() {
        let key = write_key_file("-----BEGIN TEST KEY-----").unwrap();
        let path = key.path().to_owned();
        assert!(path.exists());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "-----BEGIN TEST KEY-----"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file mode {mode:o}");
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700, "temp dir mode {dir_mode:o}");
        }
        drop(key);
        assert!(!path.exists(), "key file must be removed with its dir");
    }
}
