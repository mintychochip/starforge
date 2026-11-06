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
//! - repo `ratelimited` — every route answers 403 with
//!   `X-RateLimit-Remaining: 0` and an `X-RateLimit-Reset`, which the
//!   client maps to `RateLimited { reset_at }`.
//! - repo `big` — every route answers an 11 MiB body, past the client's
//!   10 MiB cap, which the client refuses.
//! - repo `crossorigin` — listings link their next page off-origin,
//!   which the client must refuse to follow.

use std::collections::HashMap;

use axum::{
    Router,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::get,
};

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
) -> impl IntoResponse {
    if repo == "ratelimited" {
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
    Path((_owner, repo)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("issues.json", "issues", repo, query, headers).await
}

async fn pulls(
    Path((_owner, repo)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("pulls.json", "pulls", repo, query, headers).await
}

async fn issue_comments(
    Path((_owner, repo, _n)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("issue_comments.json", "issues", repo, query, headers).await
}

async fn review_comments(
    Path((_owner, repo, _n)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("review_comments.json", "pulls", repo, query, headers).await
}

async fn reviews(
    Path((_owner, repo, _n)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    listing("reviews.json", "pulls", repo, query, headers).await
}

async fn repository(Path((_owner, repo)): Path<(String, String)>) -> impl IntoResponse {
    if repo == "ratelimited" {
        return ratelimited().into_response();
    }
    if repo == "big" {
        return big().into_response();
    }
    axum::Json(fixture("repository.json")).into_response()
}

impl FakeGithub {
    /// Starts the fake API on a loopback port and returns its base URL.
    pub async fn start() -> FakeGithub {
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
            .route("/repos/{owner}/{repo}/pulls/{n}/reviews", get(reviews));
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
