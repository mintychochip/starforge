//! Smart HTTP plumbing: ref advertisement and stateless RPC processes (gitprotocol-http).

use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};

use crate::command::{GitError, git};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    /// Parses the `service` query parameter of `GET info/refs`.
    pub fn from_query(name: &str) -> Option<Service> {
        match name {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }

    fn subcommand(self) -> &'static str {
        match self {
            Service::UploadPack => "upload-pack",
            Service::ReceivePack => "receive-pack",
        }
    }

    pub fn advertisement_content_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }

    pub fn result_content_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }
}

pub fn pkt_line(payload: &str) -> Vec<u8> {
    format!("{:04x}{payload}", payload.len() + 4).into_bytes()
}

fn is_v2(git_protocol: Option<&str>) -> bool {
    git_protocol.is_some_and(|p| p.split(':').any(|kv| kv == "version=2"))
}

/// Body for `GET info/refs?service=…`. Protocol v2 responses have no `# service=` preamble.
pub async fn advertisement(
    repo: &Path,
    service: Service,
    git_protocol: Option<&str>,
) -> Result<Vec<u8>, GitError> {
    let mut cmd = git();
    cmd.arg(service.subcommand())
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(repo);
    if let Some(protocol) = git_protocol {
        cmd.env("GIT_PROTOCOL", protocol);
    }
    let out = cmd.output().await?;
    if !out.status.success() {
        return Err(GitError::Failed {
            command: format!("{} --advertise-refs", service.subcommand()),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    let mut body = Vec::with_capacity(out.stdout.len() + 40);
    if !is_v2(git_protocol) {
        body.extend(pkt_line(&format!("# service={}\n", service.name())));
        body.extend_from_slice(b"0000");
    }
    body.extend(out.stdout);
    Ok(body)
}

pub struct RpcProcess {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

/// Spawns `git <service> --stateless-rpc <repo>` with piped stdio. `env` reaches the repository's hooks.
pub fn spawn_rpc(
    repo: &Path,
    service: Service,
    git_protocol: Option<&str>,
    env: &[(&str, String)],
) -> Result<RpcProcess, GitError> {
    let mut cmd = git();
    cmd.arg(service.subcommand())
        .arg("--stateless-rpc")
        .arg(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(protocol) = git_protocol {
        cmd.env("GIT_PROTOCOL", protocol);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    Ok(RpcProcess {
        child,
        stdin,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn pkt_lines_are_length_prefixed() {
        assert_eq!(
            pkt_line("# service=git-upload-pack\n"),
            b"001e# service=git-upload-pack\n"
        );
    }

    #[test]
    fn service_names_and_content_types() {
        assert_eq!(
            Service::from_query("git-receive-pack"),
            Some(Service::ReceivePack)
        );
        assert_eq!(Service::from_query("git-upload-archive"), None);
        assert_eq!(
            Service::UploadPack.advertisement_content_type(),
            "application/x-git-upload-pack-advertisement"
        );
        assert_eq!(
            Service::ReceivePack.result_content_type(),
            "application/x-git-receive-pack-result"
        );
    }

    #[test]
    fn detects_protocol_v2() {
        assert!(is_v2(Some("version=2")));
        assert!(is_v2(Some("object-format=sha1:version=2")));
        assert!(!is_v2(Some("version=1")));
        assert!(!is_v2(None));
    }

    #[tokio::test]
    async fn advertisement_preamble_depends_on_protocol_version() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        let v0 = advertisement(&repo, Service::UploadPack, None)
            .await
            .unwrap();
        assert!(v0.starts_with(b"001e# service=git-upload-pack\n0000"));
        let v2 = advertisement(&repo, Service::UploadPack, Some("version=2"))
            .await
            .unwrap();
        assert!(
            v2.starts_with(b"000eversion 2\n"),
            "{}",
            String::from_utf8_lossy(&v2)
        );
    }
}
