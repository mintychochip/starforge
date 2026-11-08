//! Client for a local `starforge-sandboxd` over its Unix socket.
//!
//! The daemon speaks HTTP/1.1 on a Unix socket with a bearer token read
//! from a `0600` file it rotates on every start. This client is the
//! developer-facing counterpart of the server's local sandbox provider:
//! `starforge sandbox` uses it to create, exec in, copy from, and kill a
//! sandbox without a server or a CI job.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use starforge_sandbox_protocol::{CreateSandboxRequest, ExecChunk, ExecRequest, SandboxInfo};

use crate::RunnerError;

/// A client for one `starforge-sandboxd` instance.
#[derive(Debug, Clone)]
pub struct LocalSandboxClient {
    socket: PathBuf,
    token_file: PathBuf,
}

impl LocalSandboxClient {
    pub fn new(socket: impl Into<PathBuf>, token_file: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            token_file: token_file.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Create a sandbox. The daemon's `POST /sandboxes` returns the
    /// [`SandboxInfo`] (id, state, runtime, expiry).
    pub async fn create(&self, req: &CreateSandboxRequest) -> Result<SandboxInfo, RunnerError> {
        let body = serde_json::to_vec(req)
            .map_err(|e| RunnerError::Malformed(format!("create request: {e}")))?;
        let (status, bytes) = self.request("POST", "/sandboxes", Some(&body)).await?;
        if !(200..300).contains(&status) {
            return Err(provider_error(status, &bytes));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| RunnerError::Malformed(format!("create response: {e}")))
    }

    /// Run one command and return its output chunks (stdout, stderr, exit).
    pub async fn exec(&self, id: &str, req: &ExecRequest) -> Result<Vec<ExecChunk>, RunnerError> {
        let body = serde_json::to_vec(req)
            .map_err(|e| RunnerError::Malformed(format!("exec request: {e}")))?;
        let (status, bytes) = self
            .request("POST", &format!("/sandboxes/{id}/exec"), Some(&body))
            .await?;
        if !(200..300).contains(&status) {
            return Err(provider_error(status, &bytes));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| RunnerError::Malformed(format!("exec response: {e}")))
    }

    /// Read one file from the sandbox workspace. `None` when it is missing.
    pub async fn read_file(&self, id: &str, path: &str) -> Result<Option<Vec<u8>>, RunnerError> {
        let query = url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>();
        let (status, bytes) = self
            .request("GET", &format!("/sandboxes/{id}/files?path={query}"), None)
            .await?;
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(provider_error(status, &bytes));
        }
        #[derive(Deserialize)]
        struct FileRead {
            content: String,
        }
        let body: FileRead = serde_json::from_slice(&bytes)
            .map_err(|e| RunnerError::Malformed(format!("file response: {e}")))?;
        base64::engine::general_purpose::STANDARD
            .decode(body.content)
            .map(Some)
            .map_err(|e| RunnerError::Malformed(format!("file content: {e}")))
    }

    /// List one directory in the sandbox workspace.
    pub async fn list_files(&self, id: &str, path: &str) -> Result<Vec<String>, RunnerError> {
        let query = url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>();
        let (status, bytes) = self
            .request(
                "GET",
                &format!("/sandboxes/{id}/files?path={query}&op=list"),
                None,
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(provider_error(status, &bytes));
        }
        #[derive(Deserialize)]
        struct FileList {
            entries: Vec<String>,
        }
        let body: FileList = serde_json::from_slice(&bytes)
            .map_err(|e| RunnerError::Malformed(format!("file list response: {e}")))?;
        Ok(body.entries)
    }

    /// Kill a sandbox. A missing sandbox is success (the daemon's delete is
    /// idempotent for unknown ids).
    pub async fn kill(&self, id: &str) -> Result<(), RunnerError> {
        let (status, bytes) = self
            .request("DELETE", &format!("/sandboxes/{id}"), None)
            .await?;
        if (200..300).contains(&status) || status == 404 {
            return Ok(());
        }
        Err(provider_error(status, &bytes))
    }

    /// One HTTP/1.1 request over the Unix socket. `Connection: close` makes
    /// the body end at EOF; `Content-Length` and chunked bodies are both
    /// handled.
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), RunnerError> {
        let token = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|e| {
                RunnerError::Transport(format!(
                    "reading sandboxd token {}: {e}",
                    self.token_file.display()
                ))
            })?;
        let mut stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|e| {
                RunnerError::Transport(format!(
                    "connecting to sandboxd socket {}: {e}",
                    self.socket.display()
                ))
            })?;
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
            token.trim()
        );
        if let Some(body) = body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| RunnerError::Transport(format!("sandboxd request: {e}")))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .await
                .map_err(|e| RunnerError::Transport(format!("sandboxd request body: {e}")))?;
        }
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| RunnerError::Transport(format!("sandboxd response: {e}")))?;
        parse_response(&raw)
    }
}

fn provider_error(status: u16, bytes: &[u8]) -> RunnerError {
    let text = String::from_utf8_lossy(bytes);
    if status == 404 {
        return RunnerError::NotFound;
    }
    RunnerError::Provider(format!("sandboxd {status}: {text}"))
}

/// Parse an HTTP/1.1 response into `(status, body)`.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), RunnerError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| RunnerError::Malformed("sandboxd response has no header end".into()))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| RunnerError::Malformed("sandboxd response has no status line".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| RunnerError::Malformed(format!("bad status line: {status_line}")))?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        decode_chunked(rest)?
    } else if let Some(len) = content_length {
        rest.get(..len)
            .ok_or_else(|| {
                RunnerError::Malformed("sandboxd body shorter than Content-Length".into())
            })?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok((status, body))
}

/// Decode an HTTP/1.1 chunked body. Tolerates a missing terminal chunk when
/// the connection closed after the last data chunk.
fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, RunnerError> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| RunnerError::Malformed("chunked body has no size line".into()))?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|e| RunnerError::Malformed(format!("chunk size: {e}")))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        let chunk = rest
            .get(..size)
            .ok_or_else(|| RunnerError::Malformed("chunked body is short".into()))?;
        out.extend_from_slice(chunk);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_creates_execs_and_kills_over_a_unix_socket() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sandboxd.sock");
        let token_file = dir.path().join("sandboxd.token");
        std::fs::write(&token_file, "test-token").unwrap();
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.contains("Authorization: Bearer test-token"), "{req}");
                let (status, body) = if req.starts_with("POST /sandboxes ") {
                    (
                        200,
                        r#"{"id":"sbx-1","state":"running","runtime":"podman","expires_at":null,"provider":"local"}"#,
                    )
                } else if req.contains("/exec ") {
                    (
                        200,
                        r#"[{"stream":"stdout","data":"hi"},{"stream":"exit","code":0}]"#,
                    )
                } else {
                    (204, "")
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        let client = LocalSandboxClient::new(&sock, &token_file);
        let info = client
            .create(&CreateSandboxRequest {
                template: "img".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(info.id, "sbx-1");
        let chunks = client
            .exec(
                "sbx-1",
                &ExecRequest {
                    command: vec!["echo".into(), "hi".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(chunks[0], ExecChunk::Stdout { .. }));
        client.kill("sbx-1").await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn parses_content_length_and_chunked_responses() {
        let (status, body) =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").unwrap();
        assert_eq!((status, body.as_slice()), (200, b"hi".as_slice()));
        let (status, body) = parse_response(
            b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!((status, body.as_slice()), (201, b"hi".as_slice()));
    }
}
