//! The Depot usage adapter: a `reqwest` client for Depot's Connect
//! `UsageService/GetUsage` endpoint. The organization token is sent as
//! `Authorization: Bearer <token>` and is never logged or rendered.
//! Depot meters and enforces its own limits; this adapter only reports
//! what the API returns.

use std::sync::LazyLock;
use std::time::Duration;

/// The default Depot API base URL.
pub const DEFAULT_API_URL: &str = "https://api.depot.dev";

/// The HTTP client shared by every Depot call (one connection pool), or
/// why it could not be built.
static HTTP: LazyLock<Result<reqwest::Client, String>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())
});

/// A client for Depot's usage API.
#[derive(Clone)]
pub struct DepotUsageClient {
    api_url: String,
    token: String,
}

impl std::fmt::Debug for DepotUsageClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DepotUsageClient")
            .field("api_url", &self.api_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl DepotUsageClient {
    /// Creates a client for `api_url` (trailing slashes are stripped) that
    /// authenticates with the organization `token`.
    pub fn new(api_url: &str, token: &str) -> Self {
        Self {
            api_url: api_url.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
        }
    }

    /// POSTs `{api_url}/depot.core.v1.UsageService/GetUsage` with the
    /// given period and returns the decoded usage.
    pub async fn get_usage(
        &self,
        start_at: i64,
        end_at: i64,
    ) -> Result<GetUsageResponse, DepotError> {
        let body = serde_json::json!({
            "startAt": rfc3339(start_at)?,
            "endAt": rfc3339(end_at)?,
        });
        let body = serde_json::to_vec(&body).map_err(|e| DepotError {
            code: "internal".to_owned(),
            message: format!("encoding depot request: {e}"),
        })?;
        let url = format!("{}/depot.core.v1.UsageService/GetUsage", self.api_url);
        let http = HTTP.as_ref().map_err(|e| DepotError {
            code: "internal".to_owned(),
            message: format!("building the HTTP client: {e}"),
        })?;
        let resp = http
            .post(url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.token),
            )
            .header("Connect-Protocol-Version", "1")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| DepotError {
                code: "unavailable".to_owned(),
                message: format!("calling depot: {e}"),
            })?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| DepotError {
                code: "unavailable".to_owned(),
                message: format!("reading depot response: {e}"),
            })?
            .to_vec();
        if !status.is_success() {
            return Err(parse_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|e| DepotError {
            code: "internal".to_owned(),
            message: format!("decoding depot response: {e}"),
        })
    }
}

/// An error from the Depot usage API, decoded from the Connect error
/// body or synthesized from the HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepotError {
    /// The Connect error code, e.g. `unauthenticated`.
    pub code: String,
    /// The human-readable error message.
    pub message: String,
}

impl std::fmt::Display for DepotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DepotError {}

/// The decoded `GetUsageResponse`.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetUsageResponse {
    /// The start of the returned period (RFC 3339), when present.
    pub period_start: Option<String>,
    /// The end of the returned period (RFC 3339), when present.
    pub period_end: Option<String>,
    /// Container build usage (organization-level).
    pub container_build: Vec<ContainerBuildUsage>,
    /// GitHub Actions jobs usage, per repository.
    pub github_actions_jobs: Vec<GithubActionsJobsUsage>,
    /// Storage usage (organization-level).
    pub storage: Vec<StorageUsage>,
    /// Agent sandbox usage (organization-level).
    pub agent_sandbox: Vec<AgentSandboxUsage>,
    /// Depot CI usage, per repository.
    pub depot_ci: Vec<DepotCiUsage>,
}

/// Container build usage for one project.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ContainerBuildUsage {
    /// The project name.
    pub project_name: String,
    /// The number of builds.
    pub build_count: i64,
    /// Minutes saved by Depot's caching, when reported.
    pub minutes_saved: f64,
    /// Minutes billed by Depot.
    pub minutes_billed: f64,
}

/// GitHub Actions jobs usage for one repository.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GithubActionsJobsUsage {
    /// The repository as `owner/name`.
    pub repo: String,
    /// The aggregate totals for the repository.
    pub total: GithubActionsJobsUsageTotal,
    /// The per-job breakdowns.
    pub jobs: Vec<GithubActionsJobUsageDetail>,
}

/// Aggregate GitHub Actions jobs usage totals.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GithubActionsJobsUsageTotal {
    /// The number of jobs.
    pub job_count: i64,
    /// Elapsed job minutes.
    pub minutes_elapsed: f64,
    /// Billed job minutes.
    pub minutes_billed: f64,
}

/// One GitHub Actions job usage breakdown.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GithubActionsJobUsageDetail {
    /// The workflow name.
    pub workflow: String,
    /// The runner name.
    pub runner: String,
    /// The number of jobs.
    pub job_count: i64,
    /// Elapsed job minutes.
    pub minutes_elapsed: f64,
    /// Billed job minutes.
    pub minutes_billed: f64,
    /// The branch, when the API reports it.
    pub branch: Option<String>,
    /// The actor, when the API reports it.
    pub actor: Option<String>,
    /// The status, when the API reports it.
    pub status: Option<String>,
}

/// Storage usage for one storage type.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StorageUsage {
    /// The storage type.
    pub storage_type: String,
    /// The total storage in gigabytes.
    pub total_gb: f64,
}

/// Agent sandbox usage for one agent type.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AgentSandboxUsage {
    /// The agent type.
    pub agent_type: String,
    /// The number of sandboxes.
    pub sandboxes_count: i64,
    /// Elapsed sandbox minutes.
    pub minutes_elapsed: f64,
    /// Billed sandbox minutes.
    pub minutes_billed: f64,
}

/// Depot CI usage for one repository workflow.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DepotCiUsage {
    /// The repository as `owner/name`.
    pub repo: String,
    /// The workflow name.
    pub workflow: String,
    /// The workflow file path.
    pub workflow_path: String,
    /// The runner name.
    pub runner: String,
    /// The number of attempts.
    pub attempt_count: i64,
    /// Elapsed attempt minutes.
    pub minutes_elapsed: f64,
    /// Billed vCPU-minutes.
    pub vcpu_minutes_billed: f64,
    /// The number of failed attempts, when reported.
    pub failed_attempt_count: Option<i64>,
    /// The error rate, when reported.
    pub error_rate: Option<f64>,
}

/// Usage Depot attributes to one repository.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DepotRepoUsage {
    /// Summed Depot CI attempts.
    pub depot_ci_attempts: i64,
    /// Summed Depot CI elapsed minutes.
    pub depot_ci_minutes_elapsed: f64,
    /// Summed billed Depot CI vCPU-minutes.
    pub depot_ci_vcpu_minutes_billed: f64,
    /// Summed GitHub Actions jobs.
    pub github_actions_jobs: i64,
    /// Summed GitHub Actions elapsed minutes.
    pub github_actions_minutes_elapsed: f64,
    /// Summed billed GitHub Actions minutes.
    pub github_actions_minutes_billed: f64,
}

impl GetUsageResponse {
    /// Sums the `depotCi` rows and the `githubActionsJobs` totals whose
    /// `repo` equals `repo` ("owner/name", ASCII case-insensitive).
    /// Container builds, storage, and agent sandboxes are org-level and
    /// not attributed.
    pub fn for_repo(&self, repo: &str) -> DepotRepoUsage {
        let mut usage = DepotRepoUsage::default();
        for row in &self.depot_ci {
            if row.repo.eq_ignore_ascii_case(repo) {
                usage.depot_ci_attempts += row.attempt_count;
                usage.depot_ci_minutes_elapsed += row.minutes_elapsed;
                usage.depot_ci_vcpu_minutes_billed += row.vcpu_minutes_billed;
            }
        }
        for entry in &self.github_actions_jobs {
            if entry.repo.eq_ignore_ascii_case(repo) {
                usage.github_actions_jobs += entry.total.job_count;
                usage.github_actions_minutes_elapsed += entry.total.minutes_elapsed;
                usage.github_actions_minutes_billed += entry.total.minutes_billed;
            }
        }
        usage
    }
}

/// The wire shape of a Connect error body.
#[derive(serde::Deserialize)]
struct ConnectError {
    code: String,
    #[serde(default)]
    message: String,
}

/// Formats a Unix timestamp (seconds) as an RFC 3339 UTC string.
fn rfc3339(unix_seconds: i64) -> Result<String, DepotError> {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix_seconds).map_err(|e| DepotError {
        code: "invalid_argument".to_owned(),
        message: format!("timestamp {unix_seconds} out of range: {e}"),
    })?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| DepotError {
            code: "invalid_argument".to_owned(),
            message: format!("formatting timestamp {unix_seconds}: {e}"),
        })
}

/// Maps a non-2xx response to a `DepotError`, preferring a Connect error
/// JSON body and falling back to a code derived from the status.
fn parse_error(status: reqwest::StatusCode, bytes: &[u8]) -> DepotError {
    if let Ok(err) = serde_json::from_slice::<ConnectError>(bytes) {
        return DepotError {
            code: err.code,
            message: err.message,
        };
    }
    let code = match status.as_u16() {
        401 => "unauthenticated",
        403 => "permission_denied",
        404 => "not_found",
        429 => "resource_exhausted",
        500..=599 => "unavailable",
        _ => "unknown",
    };
    DepotError {
        code: code.to_owned(),
        message: format!("Depot answered {}", status.as_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A request recorded by the fake Depot server.
    struct RecordedRequest {
        request_line: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl RecordedRequest {
        /// Case-insensitive header lookup.
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    /// Builds a minimal HTTP/1.1 response with the given status and body.
    fn http_response(status: u16, body: &str) -> Vec<u8> {
        let reason = match status {
            200 => "OK",
            401 => "Unauthorized",
            503 => "Service Unavailable",
            _ => "Error",
        };
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        )
        .into_bytes()
    }

    /// Reads one request: headers up to the blank line, then exactly
    /// `Content-Length` body bytes.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<RecordedRequest> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end = loop {
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let mut lines = header_str.lines();
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut headers = Vec::new();
        let mut content_length = 0usize;
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_owned();
                let value = value.trim().to_owned();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.push((key, value));
            }
        }
        while buf.len() - header_end < content_length {
            let n = stream.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let body =
            buf[header_end..header_end + content_length.min(buf.len() - header_end)].to_vec();
        Some(RecordedRequest {
            request_line,
            headers,
            body,
        })
    }

    /// Builds the raw HTTP response for one recorded request.
    type Responder = Arc<dyn Fn(&RecordedRequest) -> Vec<u8> + Send + Sync>;

    /// A tiny fake Depot server over TCP: records each request and
    /// answers with whatever `responder` returns.
    async fn fake_depot(
        listener: tokio::net::TcpListener,
        recorded: Arc<Mutex<Vec<RecordedRequest>>>,
        responder: Responder,
    ) {
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let recorded = Arc::clone(&recorded);
                let responder = Arc::clone(&responder);
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    let response = responder(&request);
                    recorded.lock().unwrap().push(request);
                    let _ = stream.write_all(&response).await;
                });
            }
        });
    }

    /// Spins up a fake server with the given canned responder and returns
    /// a client pointed at it plus the recorded requests.
    async fn depot<F>(responder: F) -> (DepotUsageClient, Arc<Mutex<Vec<RecordedRequest>>>)
    where
        F: Fn(&RecordedRequest) -> Vec<u8> + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let recorded = Arc::new(Mutex::new(Vec::new()));
        fake_depot(listener, Arc::clone(&recorded), Arc::new(responder)).await;
        (DepotUsageClient::new(&url, "sekret-token"), recorded)
    }

    #[tokio::test]
    async fn get_usage_posts_connect_unary_request() {
        let (client, recorded) = depot(|_| http_response(200, "{}")).await;
        let resp = client
            .get_usage(1_700_000_000, 1_700_086_400)
            .await
            .unwrap();
        assert_eq!(resp, GetUsageResponse::default());
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1, "exactly one request recorded");
        let request = &recorded[0];
        assert_eq!(
            request.request_line,
            "POST /depot.core.v1.UsageService/GetUsage HTTP/1.1",
        );
        assert_eq!(request.header("authorization"), Some("Bearer sekret-token"),);
        assert_eq!(request.header("connect-protocol-version"), Some("1"));
        assert_eq!(request.header("content-type"), Some("application/json"),);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({
                "startAt": "2023-11-14T22:13:20Z",
                "endAt": "2023-11-15T22:13:20Z",
            }),
        );
    }

    #[tokio::test]
    async fn for_repo_sums_matching_rows_only() {
        let body = r#"{
            "periodStart": "2023-11-14T22:13:20Z",
            "periodEnd": "2023-11-15T22:13:20Z",
            "depotCi": [
                {"repo": "acme/app", "workflow": "ci", "workflowPath": ".github/workflows/ci.yml", "runner": "depot-32", "attemptCount": 3, "minutesElapsed": 10.5, "vcpuMinutesBilled": 12.0},
                {"repo": "acme/app", "workflow": "tests", "workflowPath": ".github/workflows/tests.yml", "runner": "depot-32", "attemptCount": 2, "minutesElapsed": 5.5, "vcpuMinutesBilled": 6.5, "failedAttemptCount": 1, "errorRate": 0.5},
                {"repo": "other/repo", "workflow": "ci", "runner": "depot-32", "attemptCount": 7, "minutesElapsed": 20.0, "vcpuMinutesBilled": 25.0}
            ],
            "githubActionsJobs": [
                {"repo": "Acme/App", "total": {"jobCount": 10, "minutesElapsed": 30.5, "minutesBilled": 33.0}},
                {"repo": "other/repo", "total": {"jobCount": 4, "minutesElapsed": 8.0, "minutesBilled": 9.0}, "jobs": [{"workflow": "ci", "runner": "hosted", "jobCount": 4, "minutesElapsed": 8.0, "minutesBilled": 9.0}]}
            ],
            "containerBuild": [{"projectName": "acme", "buildCount": 5, "minutesSaved": 1.5, "minutesBilled": 2.5}],
            "storage": [{"storageType": "artifact", "totalGb": 3.5}]
        }"#;
        let (client, _recorded) = depot(move |_| http_response(200, body)).await;
        let resp = client
            .get_usage(1_700_000_000, 1_700_086_400)
            .await
            .unwrap();
        assert_eq!(resp.period_start.as_deref(), Some("2023-11-14T22:13:20Z"));
        assert_eq!(resp.period_end.as_deref(), Some("2023-11-15T22:13:20Z"));
        assert_eq!(
            resp.container_build,
            vec![ContainerBuildUsage {
                project_name: "acme".into(),
                build_count: 5,
                minutes_saved: 1.5,
                minutes_billed: 2.5,
            }],
        );
        assert_eq!(
            resp.storage,
            vec![StorageUsage {
                storage_type: "artifact".into(),
                total_gb: 3.5,
            }],
        );
        assert_eq!(
            resp.for_repo("acme/app"),
            DepotRepoUsage {
                depot_ci_attempts: 5,
                depot_ci_minutes_elapsed: 16.0,
                depot_ci_vcpu_minutes_billed: 18.5,
                github_actions_jobs: 10,
                github_actions_minutes_elapsed: 30.5,
                github_actions_minutes_billed: 33.0,
            },
        );
        assert_eq!(
            resp.for_repo("OTHER/REPO"),
            DepotRepoUsage {
                depot_ci_attempts: 7,
                depot_ci_minutes_elapsed: 20.0,
                depot_ci_vcpu_minutes_billed: 25.0,
                github_actions_jobs: 4,
                github_actions_minutes_elapsed: 8.0,
                github_actions_minutes_billed: 9.0,
            },
        );
        assert_eq!(resp.for_repo("unrelated/repo"), DepotRepoUsage::default());
    }

    #[tokio::test]
    async fn connect_error_body_maps_code_and_message() {
        let (client, _recorded) = depot(|_| {
            http_response(
                401,
                r#"{"code":"unauthenticated","message":"invalid token"}"#,
            )
        })
        .await;
        let err = client
            .get_usage(1_700_000_000, 1_700_086_400)
            .await
            .unwrap_err();
        assert_eq!(err.code, "unauthenticated");
        assert_eq!(err.message, "invalid token");
    }

    #[tokio::test]
    async fn plain_text_error_maps_by_status() {
        let (client, _recorded) = depot(|_| http_response(503, "temporarily unavailable")).await;
        let err = client
            .get_usage(1_700_000_000, 1_700_086_400)
            .await
            .unwrap_err();
        assert_eq!(err.code, "unavailable");
    }

    #[tokio::test]
    async fn undecodable_success_body_is_internal() {
        let (client, _recorded) = depot(|_| http_response(200, "not json")).await;
        let err = client
            .get_usage(1_700_000_000, 1_700_086_400)
            .await
            .unwrap_err();
        assert_eq!(err.code, "internal");
    }

    #[tokio::test]
    async fn out_of_range_timestamp_is_invalid_argument_without_network() {
        let (client, recorded) = depot(|_| http_response(200, "{}")).await;
        let err = client.get_usage(i64::MAX, 0).await.unwrap_err();
        assert_eq!(err.code, "invalid_argument");
        assert!(recorded.lock().unwrap().is_empty());
    }

    #[test]
    fn debug_does_not_contain_token() {
        let client = DepotUsageClient::new(DEFAULT_API_URL, "super-secret-token");
        let debug = format!("{client:?}");
        assert!(
            !debug.contains("super-secret-token"),
            "token leaked: {debug}"
        );
        assert!(debug.contains(DEFAULT_API_URL));
    }
}
