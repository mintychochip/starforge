//! Search routes (spec §10.5, plan M4a D6): Trail and session search as
//! JSON. Handlers authenticate (a token must carry `repo:read`; anonymous
//! callers are fine) and delegate to [`Core`]; validation lives in
//! [`starforged_core::search`] and answers `422`. Session search sends
//! `X-Robots-Tag: noindex` (spec §11.1), like every session response.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};
use starforged_core::search::{SearchQuery, Snippet};

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

/// Sessions never reach search indexes (spec §11.1).
fn noindex_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers
}

fn snippet_json(snippet: &Snippet) -> Value {
    json!({
        "text": snippet.text,
        "highlights": snippet.highlights,
    })
}

#[derive(Debug, Default, Deserialize)]
pub struct TrailsQuery {
    pub q: Option<String>,
    pub repo: Option<String>,
    pub author: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SessionsQuery {
    pub q: Option<String>,
    pub repo: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub author: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub commit: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

/// `GET /api/v1/search/trails?q=&repo=&author=&from=&to=&page=&per_page=`.
pub async fn search_trails(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Query(query): Query<TrailsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth.reader()?;
    let page = state
        .core
        .search_trails(
            user,
            &SearchQuery {
                q: query.q.clone().unwrap_or_default(),
                repo: query.repo.clone().filter(|v| !v.is_empty()),
                author: query.author.clone().filter(|v| !v.is_empty()),
                from: query.from.clone().filter(|v| !v.is_empty()),
                to: query.to.clone().filter(|v| !v.is_empty()),
                page: query.page,
                per_page: query.per_page,
                ..Default::default()
            },
        )
        .await?;
    let results: Vec<Value> = page
        .items
        .iter()
        .map(|result| {
            json!({
                "repo": format!("{}/{}", result.owner, result.repo),
                "number": result.number,
                "title": result.title,
                "state": result.state,
                "updated_at": rfc3339(result.updated_at),
                "snippet": snippet_json(&result.snippet),
            })
        })
        .collect();
    Ok(Json(json!({
        "results": results,
        "page": page.page,
        "per_page": page.per_page,
        "has_more": page.has_more,
    })))
}

/// `GET /api/v1/search/sessions?q=&repo=&agent=&model=&author=&from=&to=&commit=&page=&per_page=`.
pub async fn search_sessions(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Query(query): Query<SessionsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth.reader()?;
    let page = state
        .core
        .search_sessions(
            user,
            &SearchQuery {
                q: query.q.clone().unwrap_or_default(),
                repo: query.repo.clone().filter(|v| !v.is_empty()),
                agent: query.agent.clone().filter(|v| !v.is_empty()),
                model: query.model.clone().filter(|v| !v.is_empty()),
                author: query.author.clone().filter(|v| !v.is_empty()),
                from: query.from.clone().filter(|v| !v.is_empty()),
                to: query.to.clone().filter(|v| !v.is_empty()),
                commit: query.commit.clone().filter(|v| !v.is_empty()),
                page: query.page,
                per_page: query.per_page,
            },
        )
        .await?;
    let results: Vec<Value> = page
        .items
        .iter()
        .map(|result| {
            let events: Vec<Value> = result
                .events
                .iter()
                .map(|event| {
                    json!({
                        "seq": event.seq,
                        "kind": event.kind,
                        "snippet": snippet_json(&event.snippet),
                    })
                })
                .collect();
            json!({
                "repo": format!("{}/{}", result.owner, result.repo),
                "session": result.session,
                "agent": result.agent,
                "title": result.title,
                "events": events,
            })
        })
        .collect();
    Ok((
        noindex_headers(),
        Json(json!({
            "results": results,
            "page": page.page,
            "per_page": page.per_page,
            "has_more": page.has_more,
        })),
    ))
}
