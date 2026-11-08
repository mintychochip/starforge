//! The E2B provider adapter (plan M6b B3): a `reqwest` client for the
//! E2B-shaped sandbox API. The API key comes from config and is sent as
//! `Authorization: Bearer <key>` plus `X-API-Key: <key>`; it is never
//! logged or rendered. Wire shapes are the `starforge-sandbox-protocol`
//! types, so a fake server can stand in for E2B in tests.

use std::future::Future;
use std::pin::Pin;

use serde_json::json;
use starforge_sandbox_protocol::{
    CreateSandboxRequest, ExecChunk, ExecRequest, FileOp, PortUrl, ProviderError, SandboxInfo,
};

use crate::sandboxes::{SandboxProvider, encode};

/// A sandbox provider talking to an E2B-compatible endpoint.
#[derive(Clone)]
pub struct E2bSandboxProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl std::fmt::Debug for E2bSandboxProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2bSandboxProvider")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl E2bSandboxProvider {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        Self {
            client: reqwest::Client::builder()
                .build()
                .expect("reqwest client builder"),
            base_url,
            api_key: api_key.into(),
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(u16, Vec<u8>), ProviderError> {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.base_url))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.api_key),
            )
            .header("X-API-Key", &self.api_key);
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProviderError::retryable("unavailable", format!("calling e2b: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| {
                ProviderError::retryable("unavailable", format!("reading e2b response: {e}"))
            })?
            .to_vec();
        Ok((status, bytes))
    }

    async fn json<T>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, ProviderError>
    where
        T: serde::de::DeserializeOwned,
    {
        let (status, bytes) = self.request(method, path, body).await?;
        if status >= 400 {
            return Err(parse_error(status, &bytes));
        }
        if bytes.is_empty() {
            return Err(ProviderError::new("internal", "empty e2b response"));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| ProviderError::new("internal", format!("decoding e2b response: {e}")))
    }
}

fn parse_error(status: u16, bytes: &[u8]) -> ProviderError {
    if let Ok(err) = serde_json::from_slice::<ProviderError>(bytes) {
        return err;
    }
    let code = match status {
        404 => "not_found",
        401 | 403 => "unauthorized",
        409 => "conflict",
        413 => "too_large",
        429 => "capacity",
        _ => "internal",
    };
    ProviderError::new(code, format!("e2b answered {status}"))
}

impl SandboxProvider for E2bSandboxProvider {
    fn create(
        &self,
        request: CreateSandboxRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            // Local-daemon-only field: never send secret values to the
            // remote gateway, even if a caller populated it.
            let mut request = request;
            request.secret_bindings.clear();
            let body = serde_json::to_value(&request).expect("JSON");
            self.json(reqwest::Method::POST, "/sandboxes", Some(&body))
                .await
        })
    }

    fn get(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json(
                reqwest::Method::GET,
                &format!("/sandboxes/{}", encode(&id)),
                None,
            )
            .await
        })
    }

    fn kill(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let (status, bytes) = self
                .request(
                    reqwest::Method::DELETE,
                    &format!("/sandboxes/{}", encode(&id)),
                    None,
                )
                .await?;
            if status >= 400 {
                return Err(parse_error(status, &bytes));
            }
            Ok(())
        })
    }

    fn pause(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json(
                reqwest::Method::POST,
                &format!("/sandboxes/{}/pause", encode(&id)),
                None,
            )
            .await
        })
    }

    fn resume(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json(
                reqwest::Method::POST,
                &format!("/sandboxes/{}/resume", encode(&id)),
                None,
            )
            .await
        })
    }

    fn set_timeout(
        &self,
        id: String,
        timeout_s: u64,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxInfo, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let body = json!({ "timeout_s": timeout_s });
            self.json(
                reqwest::Method::POST,
                &format!("/sandboxes/{}/timeout", encode(&id)),
                Some(&body),
            )
            .await
        })
    }

    fn exec(
        &self,
        id: String,
        request: ExecRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExecChunk>, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let body = serde_json::to_value(&request).expect("JSON");
            self.json(
                reqwest::Method::POST,
                &format!("/sandboxes/{}/exec", encode(&id)),
                Some(&body),
            )
            .await
        })
    }

    fn files(
        &self,
        id: String,
        op: FileOp,
    ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            match op {
                FileOp::Read { path } => {
                    let body: serde_json::Value = self
                        .json(
                            reqwest::Method::GET,
                            &format!("/sandboxes/{}/files?path={}", encode(&id), encode(&path)),
                            None,
                        )
                        .await?;
                    Ok(body["content"]
                        .as_str()
                        .ok_or_else(|| ProviderError::new("internal", "file read has no content"))?
                        .to_owned())
                }
                FileOp::List { path } => {
                    let body: serde_json::Value = self
                        .json(
                            reqwest::Method::GET,
                            &format!(
                                "/sandboxes/{}/files?path={}&op=list",
                                encode(&id),
                                encode(&path)
                            ),
                            None,
                        )
                        .await?;
                    let entries = body["entries"].as_array().ok_or_else(|| {
                        ProviderError::new("internal", "file list has no entries")
                    })?;
                    Ok(entries
                        .iter()
                        .filter_map(|e| e.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"))
                }
                FileOp::Write { path, content } => {
                    let body = json!({ "path": path, "content": content });
                    let _: serde_json::Value = self
                        .json(
                            reqwest::Method::PUT,
                            &format!("/sandboxes/{}/files", encode(&id)),
                            Some(&body),
                        )
                        .await?;
                    Ok(String::new())
                }
                FileOp::Delete { path } => {
                    let (status, bytes) = self
                        .request(
                            reqwest::Method::DELETE,
                            &format!("/sandboxes/{}/files?path={}", encode(&id), encode(&path)),
                            None,
                        )
                        .await?;
                    if status >= 400 {
                        return Err(parse_error(status, &bytes));
                    }
                    Ok(String::new())
                }
            }
        })
    }

    fn port_url(
        &self,
        id: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortUrl, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            self.json(
                reqwest::Method::GET,
                &format!("/sandboxes/{}/ports/{}/url", encode(&id), port),
                None,
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use starforge_sandbox_protocol::{ExecChunk, SandboxInfo, SandboxState, SecretBindingWire};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A tiny fake E2B server over TCP: routes the adapter's paths to
    /// canned JSON and records nothing.
    async fn fake_e2b(listener: tokio::net::TcpListener) {
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let line = req.lines().next().unwrap_or_default().to_owned();
                    let mut parts = line.split_whitespace();
                    let (method, path) = (
                        parts.next().unwrap_or_default(),
                        parts.next().unwrap_or_default(),
                    );
                    let (status, body): (u16, String) = match (method, path) {
                        ("POST", "/sandboxes") => (
                            200,
                            serde_json::to_string(&SandboxInfo {
                                id: "sbx-1".into(),
                                state: SandboxState::Running,
                                runtime: "e2b".into(),
                                expires_at: None,
                                provider: "e2b".into(),
                            })
                            .unwrap(),
                        ),
                        ("GET", "/sandboxes/sbx-1") => (
                            200,
                            serde_json::to_string(&SandboxInfo {
                                id: "sbx-1".into(),
                                state: SandboxState::Running,
                                runtime: "e2b".into(),
                                expires_at: None,
                                provider: "e2b".into(),
                            })
                            .unwrap(),
                        ),
                        ("DELETE", "/sandboxes/sbx-1") => (204, String::new()),
                        ("POST", "/sandboxes/sbx-1/exec") => (
                            200,
                            serde_json::to_string(&vec![
                                ExecChunk::Stdout { data: "hi".into() },
                                ExecChunk::Exit { code: 0 },
                            ])
                            .unwrap(),
                        ),
                        ("GET", "/sandboxes/sbx-1/files?path=a.txt") => {
                            (200, r#"{"path":"a.txt","content":"hello"}"#.to_owned())
                        }
                        ("PUT", "/sandboxes/sbx-1/files") => {
                            (200, r#"{"path":"a.txt"}"#.to_owned())
                        }
                        ("DELETE", "/sandboxes/sbx-1/files?path=a.txt") => (204, String::new()),
                        ("GET", "/sandboxes/sbx-1/ports/8080/url") => (
                            200,
                            r#"{"url":"https://sbx-1.example:8080","port":8080,"expires_at":null}"#
                                .to_owned(),
                        ),
                        ("POST", "/sandboxes/sbx-1/pause") => (
                            200,
                            serde_json::to_string(&SandboxInfo {
                                id: "sbx-1".into(),
                                state: SandboxState::Paused,
                                runtime: "e2b".into(),
                                expires_at: None,
                                provider: "e2b".into(),
                            })
                            .unwrap(),
                        ),
                        ("POST", "/sandboxes/sbx-1/resume") => (
                            200,
                            serde_json::to_string(&SandboxInfo {
                                id: "sbx-1".into(),
                                state: SandboxState::Running,
                                runtime: "e2b".into(),
                                expires_at: None,
                                provider: "e2b".into(),
                            })
                            .unwrap(),
                        ),
                        ("POST", "/sandboxes/sbx-1/timeout") => (
                            200,
                            serde_json::to_string(&SandboxInfo {
                                id: "sbx-1".into(),
                                state: SandboxState::Running,
                                runtime: "e2b".into(),
                                expires_at: None,
                                provider: "e2b".into(),
                            })
                            .unwrap(),
                        ),
                        ("GET", "/sandboxes/missing") => (
                            404,
                            serde_json::to_string(&ProviderError::new(
                                "not_found",
                                "no such sandbox",
                            ))
                            .unwrap(),
                        ),
                        _ => (
                            404,
                            r#"{"code":"not_found","message":"no route","retryable":false}"#
                                .to_owned(),
                        ),
                    };
                    let reason = match status {
                        200 => "OK",
                        204 => "No Content",
                        404 => "Not Found",
                        _ => "Error",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
    }

    async fn e2b() -> (E2bSandboxProvider, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        fake_e2b(listener).await;
        (E2bSandboxProvider::new(url.clone(), "sekret"), url)
    }

    #[tokio::test]
    async fn create_get_exec_kill_round_trip() {
        let (provider, _url) = e2b().await;
        let info = provider
            .create(CreateSandboxRequest {
                runtime: "e2b".into(),
                template: "starforge/rust".into(),
                timeout_s: 300,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(info.id, "sbx-1");
        assert_eq!(info.state, SandboxState::Running);
        let got = provider.get("sbx-1".into()).await.unwrap();
        assert_eq!(got.state, SandboxState::Running);
        let chunks = provider
            .exec(
                "sbx-1".into(),
                ExecRequest {
                    command: vec!["echo".into(), "hi".into()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            chunks,
            vec![
                ExecChunk::Stdout { data: "hi".into() },
                ExecChunk::Exit { code: 0 }
            ]
        );
        provider.kill("sbx-1".into()).await.unwrap();
    }

    #[tokio::test]
    async fn files_and_port_url_round_trip() {
        let (provider, _url) = e2b().await;
        assert_eq!(
            provider
                .files(
                    "sbx-1".into(),
                    FileOp::Read {
                        path: "a.txt".into()
                    }
                )
                .await
                .unwrap(),
            "hello"
        );
        provider
            .files(
                "sbx-1".into(),
                FileOp::Write {
                    path: "a.txt".into(),
                    content: "hello".into(),
                },
            )
            .await
            .unwrap();
        provider
            .files(
                "sbx-1".into(),
                FileOp::Delete {
                    path: "a.txt".into(),
                },
            )
            .await
            .unwrap();
        let port = provider.port_url("sbx-1".into(), 8080).await.unwrap();
        assert_eq!(port.port, 8080);
        assert!(port.url.contains("sbx-1"));
    }

    #[tokio::test]
    async fn pause_resume_timeout_round_trip() {
        let (provider, _url) = e2b().await;
        assert_eq!(
            provider.pause("sbx-1".into()).await.unwrap().state,
            SandboxState::Paused
        );
        assert_eq!(
            provider.resume("sbx-1".into()).await.unwrap().state,
            SandboxState::Running
        );
        assert_eq!(
            provider
                .set_timeout("sbx-1".into(), 60)
                .await
                .unwrap()
                .state,
            SandboxState::Running
        );
    }

    #[tokio::test]
    async fn provider_error_maps_from_the_wire() {
        let (provider, _url) = e2b().await;
        let err = provider.get("missing".into()).await.unwrap_err();
        assert_eq!(err.code, "not_found");
    }

    #[tokio::test]
    async fn create_never_sends_secret_bindings() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
        let rec = Arc::clone(&recorded);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            rec.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            let body = serde_json::to_string(&SandboxInfo {
                id: "sbx-1".into(),
                state: SandboxState::Running,
                runtime: "e2b".into(),
                expires_at: None,
                provider: "e2b".into(),
            })
            .unwrap();
            let _ = stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await;
        });
        let provider = E2bSandboxProvider::new(url, "key".to_owned());
        let info = provider
            .create(CreateSandboxRequest {
                runtime: "e2b".into(),
                template: "starforge/rust".into(),
                secret_bindings: vec![SecretBindingWire {
                    host: "registry.example".into(),
                    header: "Authorization".into(),
                    value: "super-secret".into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(info.id, "sbx-1");
        let req = recorded.lock().unwrap()[0].clone();
        assert!(!req.contains("secret_bindings"), "{req}");
        assert!(!req.contains("super-secret"), "{req}");
    }
}
