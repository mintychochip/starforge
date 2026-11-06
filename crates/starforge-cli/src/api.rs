//! JSON API client for `trail` commands (M2d J3).
//!
//! One [`ApiClient`] (async `reqwest`, 30 s timeout, bearer token from
//! `auth::resolve_token`) plus the single error-envelope parser. Trail
//! commands never retry: they are user-initiated and their mutations are not
//! idempotent. The token never appears in any output, log, or error.

/// JSON API client rooted at one repo: `{api_url}/api/v1/repos/{owner}/{repo}/`.
///
/// `Debug` is redacted by hand: the bearer token must never reach logs.
pub struct ApiClient {
    /// Server origin as passed to [`ApiClient::new`] (trailing `/` trimmed).
    server: String,
    /// `{server}/api/v1/repos/{owner}/{repo}/`.
    api_base: String,
    /// `{server}/{owner}/{repo}/` (web link base).
    web_base: String,
    token: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("server", &self.server)
            .field("api_base", &self.api_base)
            .field("web_base", &self.web_base)
            .field("token", &"<redacted>")
            .field("client", &self.client)
            .finish()
    }
}

impl ApiClient {
    /// Build a client for `owner_repo` (`"owner/repo"`) against `api_url`
    /// (the discovery `ServerInfo.api_url` origin, e.g. `https://host`).
    pub fn new(api_url: &str, owner_repo: &str, token: &str) -> Result<ApiClient, ApiError> {
        let server = api_url.trim_end_matches('/').to_string();
        let client = crate::discovery::forge_client(std::time::Duration::from_secs(30))
            .map_err(|err| ApiError::Transport(format!("cannot build http client: {err}")))?;
        let api_base = format!("{server}/api/v1/repos/{owner_repo}/");
        let web_base = format!("{server}/{owner_repo}/");
        for base in [&api_base, &web_base] {
            url::Url::parse(base)
                .map_err(|err| ApiError::Transport(format!("invalid api url {server:?}: {err}")))?;
        }
        Ok(ApiClient {
            server,
            api_base,
            web_base,
            token: token.to_string(),
            client,
        })
    }

    /// Web URL for a path relative to the repo root, e.g. `web_url("trails/12")`.
    pub fn web_url(&self, path: &str) -> String {
        format!("{}{}", self.web_base, path)
    }

    /// `GET {api_base}{path}?{query}`.
    pub async fn get(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<serde_json::Value, ApiError> {
        let url = join_query(&format!("{}{}", self.api_base, path), query);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        self.read(response).await
    }

    /// `POST {api_base}{path}` with a JSON body.
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        let url = format!("{}{}", self.api_base, path);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        self.read(response).await
    }

    /// `DELETE {api_base}{path}`. Any 2xx (including an empty `204`) is
    /// success; anything else is [`parse_error`].
    pub async fn delete(&self, path: &str) -> Result<(), ApiError> {
        let url = format!("{}{}", self.api_base, path);
        let response = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            let body = response
                .bytes()
                .await
                .map_err(|err| ApiError::Transport(err.to_string()))?;
            Err(parse_error(status, &body))
        }
    }

    /// `GET {api_base}{path}` as raw bytes (segment downloads); the body is
    /// never parsed as JSON. Non-2xx answers [`parse_error`] like [`get`].
    pub async fn get_bytes(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<u8>, ApiError> {
        let url = join_query(&format!("{}{}", self.api_base, path), query);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        if (200..300).contains(&status) {
            Ok(body.to_vec())
        } else {
            Err(parse_error(status, &body))
        }
    }

    /// Render an API failure as `(message, 1)` per the CLI HTTP binding.
    /// The token never appears: only the server origin, envelope fields, and
    /// transport causes (which carry URLs but never headers) are used.
    pub fn render_error(&self, err: ApiError) -> (String, u8) {
        match err {
            ApiError::Auth { message, .. } => (
                format!(
                    "error: authentication failed ({message}); run `starforge auth login {}`",
                    host_of(&self.server)
                ),
                1,
            ),
            ApiError::Status { code, message, .. } => (format!("error: {message} ({code})"), 1),
            ApiError::Transport(cause) => {
                (format!("error: cannot reach {}: {cause}", self.server), 1)
            }
            ApiError::Decode(cause) => (format!("error: unexpected response: {cause}"), 1),
        }
    }

    async fn read(&self, response: reqwest::Response) -> Result<serde_json::Value, ApiError> {
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        if (200..300).contains(&status) {
            serde_json::from_slice(&body)
                .map_err(|err| ApiError::Decode(format!("invalid JSON response: {err}")))
        } else {
            Err(parse_error(status, &body))
        }
    }
}
/// Append percent-encoded query pairs (`reqwest` is built without its `query`
/// feature, so this uses the already-present `url` crate).
fn join_query(base: &str, query: &[(&str, String)]) -> String {
    if query.is_empty() {
        return base.to_string();
    }
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in query {
        encoded.append_pair(key, value);
    }
    format!("{base}?{}", encoded.finish())
}

/// Host (plus explicit port) for the login hint, mirroring
/// `crate::cli::sync_host_key` without depending on it.
fn host_of(api_url: &str) -> String {
    let parsed = url::Url::parse(api_url).ok();
    match parsed.as_ref().and_then(|url| url.host_str()) {
        Some(host) => {
            let lower = host.to_lowercase();
            match parsed.as_ref().and_then(|url| url.port()) {
                Some(port) => format!("{lower}:{port}"),
                None => lower,
            }
        }
        None => api_url.to_string(),
    }
}

/// API failures.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 401 or 403 with a JSON envelope.
    #[error("authentication failed ({message})")]
    Auth { status: u16, message: String },
    /// Any other non-2xx status.
    #[error("{message} ({code})")]
    Status {
        status: u16,
        code: String,
        message: String,
    },
    /// The request never completed.
    #[error("cannot reach the server: {0}")]
    Transport(String),
    /// A 2xx body that is not JSON.
    #[error("unexpected response: {0}")]
    Decode(String),
}

/// Parse an error body into [`ApiError::Auth`] (401/403 with an envelope) or
/// [`ApiError::Status`]. A non-JSON body (proxy pages) becomes
/// `Status { code: "http_<status>", message: <first line, at most 200 chars> }`.
/// Never panics on any input.
pub fn parse_error(status: u16, body: &[u8]) -> ApiError {
    if let Some((code, message)) = envelope(body) {
        if status == 401 || status == 403 {
            return ApiError::Auth { status, message };
        }
        return ApiError::Status {
            status,
            code,
            message,
        };
    }
    ApiError::Status {
        status,
        code: format!("http_{status}"),
        message: first_line(body),
    }
}

/// `(code, message)` when `body` is `{"error": {"code": str, "message": str, ..}}`.
fn envelope(body: &[u8]) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error")?.as_object()?;
    let code = error.get("code")?.as_str()?;
    let message = error.get("message")?.as_str()?;
    Some((code.to_string(), message.to_string()))
}

/// First line of `body`, lossy-decoded, at most 200 chars.
fn first_line(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    text.lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_maps_401_to_auth() {
        let body = serde_json::to_vec(&json!({
            "error": {"code": "unauthenticated", "message": "a valid token is required", "details": null}
        }))
        .unwrap();
        match parse_error(401, &body) {
            ApiError::Auth { status, message } => {
                assert_eq!(status, 401);
                assert_eq!(message, "a valid token is required");
            }
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    fn envelope_maps_403_to_auth_and_404_to_status() {
        let forbidden = serde_json::to_vec(&json!({
            "error": {"code": "forbidden", "message": "permission denied", "details": null}
        }))
        .unwrap();
        match parse_error(403, &forbidden) {
            ApiError::Auth { status, .. } => assert_eq!(status, 403),
            other => panic!("expected Auth, got {other:?}"),
        }
        let missing = serde_json::to_vec(&json!({
            "error": {"code": "not_found", "message": "not found", "details": null}
        }))
        .unwrap();
        match parse_error(404, &missing) {
            ApiError::Status {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 404);
                assert_eq!(code, "not_found");
                assert_eq!(message, "not found");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn non_json_body_uses_first_line() {
        let body = b"<html>\nproxy page here</html>";
        match parse_error(502, body) {
            ApiError::Status {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 502);
                assert_eq!(code, "http_502");
                assert_eq!(message, "<html>");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn long_first_line_truncates_to_200_chars() {
        let line = "x".repeat(300);
        let body = format!("{line}\nsecond");
        match parse_error(500, body.as_bytes()) {
            ApiError::Status { code, message, .. } => {
                assert_eq!(code, "http_500");
                assert_eq!(message.chars().count(), 200);
                assert_eq!(message, "x".repeat(200));
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn empty_bytes_do_not_panic() {
        match parse_error(500, b"") {
            ApiError::Status { code, message, .. } => {
                assert_eq!(code, "http_500");
                assert_eq!(message, "");
            }
            other => panic!("expected Status, got {other:?}"),
        }
        // Garbage bytes and wrong-shaped JSON fall back the same way.
        match parse_error(401, b"\xff\xfe\x00oops") {
            ApiError::Status { code, .. } => assert_eq!(code, "http_401"),
            other => panic!("expected Status, got {other:?}"),
        }
        match parse_error(200, b"{\"ok\": true}") {
            ApiError::Status { code, message, .. } => {
                assert_eq!(code, "http_200");
                assert_eq!(message, "{\"ok\": true}");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn web_url_joins_repo_base() {
        let api = ApiClient::new("http://host:8080/", "o/r", "t").unwrap();
        assert_eq!(api.web_url("trails/12"), "http://host:8080/o/r/trails/12");
    }

    #[test]
    fn debug_redacts_the_token() {
        let token = "sk-test-distinctive-token-ABCDEF123456";
        let api = ApiClient::new("http://host:8080/", "o/r", token).unwrap();
        let shown = format!("{api:?}");
        assert!(!shown.contains(token), "token leaked: {shown}");
        assert!(
            !shown.contains(&token[token.len() - 8..]),
            "token tail leaked: {shown}"
        );
        assert!(shown.contains("<redacted>"), "redaction marker: {shown}");
    }
}
