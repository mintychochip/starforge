//! A fake GitHub API for the M4c import tests (G1): the repository,
//! issues, pulls, issue-comment, review-comment, and review listings from
//! the JSON fixtures under `tests/fixtures/github/`, served behind axum on
//! a loopback port.
//!
//! Listings paginate like the real API: page 1 carries a same-origin
//! `Link: rel="next"` header and holds the first half of the fixture
//! array; page 2 holds the rest with no next link. Special repository
//! names model the edge cases the client must handle:
//!
//! - repo `flaky` — answers the first two requests, rate-limits the third,
//!   then answers normally again: the G2 resumption test's injected
//!   mid-run failure.
//! - the token `bad-token` — every route answers 401: bad credentials.
//!
//! [`FakeGithub::start_with_clone_url`] overrides the repository fixture's
//! `clone_url` (the G2 tests point it at a `file://` remote holding
//! `refs/pull/<n>/head`). Issue comments are served only for issue 1 and
//! review comments/reviews only for pull 4; other numbers get empty
//! listings.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::get,
};

/// Fake-API state shared by the handlers.
#[derive(Debug, Default)]
struct FakeState {
    clone_url: Option<String>,
    requests: AtomicUsize,
}

/// The running fake API. `base` is the loopback base URL (no trailing
/// slash), suitable as `GithubClient::new`'s `api_url` (with the
/// test-only loopback flag).
pub struct FakeGithub {
    pub base: String,
}

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("tests/fixtures/github/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("reading {path}"));
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("parsing {path}"))
}

fn authority_of(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_owned()
}

fn ratelimited() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
    headers.insert("X-RateLimit-Reset", "1893456000".parse().unwrap());
    (
        StatusCode::FORBIDDEN,
        headers,
        axum::Json(serde_json::json!({"message": "API rate limit exceeded"})),
    )
}

fn big() -> impl IntoResponse {
    (StatusCode::OK, "x".repeat(11 * 1024 * 1024))
}

/// One paginated listing over fixture `name`: page 1 holds the first half
/// of the array with a `Link: rel="next"` header (same-origin, or
/// off-origin for the `crossorigin` repo), page 2 the rest with no next
/// link.
fn listing_for(
    fixture_name: &str,
    kind: &str,
    query: HashMap<String, String>,
    authority: String,
    cross_origin: bool,
) -> impl IntoResponse {
    let items = fixture(fixture_name)
        .as_array()
        .expect("fixture listing is an array")
        .clone();
    let total = items.len();
    let page: u32 = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let half = total.div_ceil(2);
    let body: Vec<serde_json::Value> = match page {
        1 => items.into_iter().take(half).collect(),
        _ => items.into_iter().skip(half).collect(),
    };
    let mut headers = HeaderMap::new();
    if page == 1 && total > 1 {
        let next = if cross_origin {
            format!("https://evil.example.com/repos/octo/proj/{kind}?page=2")
        } else {
            format!("http://{authority}/repos/octo/proj/{kind}?page=2")
        };
        headers.insert(
            header::LINK,
            format!("<{next}>; rel=\"next\"").parse().unwrap(),
        );
    }
    (StatusCode::OK, headers, axum::Json(body)).into_response()
}

async fn listing(
    fixture_name: &'static str,
    kind: &'static str,
    repo: String,
    query: HashMap<String, String>,
    headers: HeaderMap,
    state: Arc<FakeState>,
) -> axum::response::Response {
    let unauthorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some("Bearer bad-token");
    if unauthorized {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"message": "Bad credentials"})),
        )
            .into_response();
    }
    if repo == "ratelimited" {
        return ratelimited().into_response();
    }
    if repo == "flaky" && state.requests.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
        return ratelimited().into_response();
    }
    if repo == "big" {
        return big().into_response();
    }
    let cross_origin = repo == "crossorigin";
    let authority = authority_of(&headers);
    listing_for(fixture_name, kind, query, authority, cross_origin).into_response()
}

async fn issues(
    State(state): State<Arc<FakeState>>,
    Path((_owner, repo)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("issues.json", "issues", repo, query, headers, state.clone()).await
}

async fn pulls(
    State(state): State<Arc<FakeState>>,
    Path((_owner, repo)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("pulls.json", "pulls", repo, query, headers, state.clone()).await
}

async fn issue_comments(
    State(state): State<Arc<FakeState>>,
    Path((_owner, repo, n)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if n != "1" {
        return axum::Json(serde_json::json!([])).into_response();
    }
    listing(
        "issue_comments.json",
        "issues",
        repo,
        query,
        headers,
        state.clone(),
    )
    .await
}

async fn review_comments(
    State(state): State<Arc<FakeState>>,
    Path((_owner, repo, n)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if n != "4" {
        return axum::Json(serde_json::json!([])).into_response();
    }
    listing(
        "review_comments.json",
        "pulls",
        repo,
        query,
        headers,
        state.clone(),
    )
    .await
}

async fn reviews(
    State(state): State<Arc<FakeState>>,
    Path((_owner, repo, n)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if n != "4" {
        return axum::Json(serde_json::json!([])).into_response();
    }
    listing("reviews.json", "pulls", repo, query, headers, state.clone()).await
}

async fn repository(
    State(state): State<Arc<FakeState>>,
    Path((_owner, repo)): Path<(String, String)>,
) -> impl IntoResponse {
    if repo == "ratelimited" {
        return ratelimited().into_response();
    }
    if repo == "big" {
        return big().into_response();
    }
    let mut repository = fixture("repository.json");
    if let Some(clone_url) = &state.clone_url {
        repository["clone_url"] = serde_json::Value::String(clone_url.clone());
    }
    axum::Json(repository).into_response()
}

impl FakeGithub {
    /// Starts the fake API on a loopback port and returns its base URL.
    pub async fn start() -> FakeGithub {
        Self::start_with_state(FakeState::default()).await
    }

    /// Like [`FakeGithub::start`], but the repository fixture's `clone_url`
    /// is replaced with `clone_url` (a `file://` remote in the G2 tests).
    pub async fn start_with_clone_url(clone_url: String) -> FakeGithub {
        Self::start_with_state(FakeState {
            clone_url: Some(clone_url),
            requests: AtomicUsize::new(0),
        })
        .await
    }

    async fn start_with_state(state: FakeState) -> FakeGithub {
        let app = Router::new()
            .route("/repos/{owner}/{repo}", get(repository))
            .route("/repos/{owner}/{repo}/issues", get(issues))
            .route("/repos/{owner}/{repo}/pulls", get(pulls))
            .route(
                "/repos/{owner}/{repo}/issues/{n}/comments",
                get(issue_comments),
            )
            .route(
                "/repos/{owner}/{repo}/pulls/{n}/comments",
                get(review_comments),
            )
            .route("/repos/{owner}/{repo}/pulls/{n}/reviews", get(reviews))
            .with_state(Arc::new(state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeGithub {
            base: format!("http://{addr}"),
        }
    }
}
