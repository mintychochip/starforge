//! Search page (spec §10.5, plan M4a S3): `/search` with Trails and
//! Sessions tabs sharing one filter form. Reads go through [`Core`], so
//! permissions and the per-hit re-check hold exactly as the API;
//! invalid filters answer 422. Snippets render escape-first: the text is
//! askama-escaped and `<mark>` wraps only the highlighted byte ranges,
//! never `|safe` on raw text. Every search page is noindex (spec §11.1).

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, format_age, nav};
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::search::{SearchQuery, Snippet};

fn noindex_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchParams {
    q: Option<String>,
    tab: Option<String>,
    repo: Option<String>,
    agent: Option<String>,
    model: Option<String>,
    author: Option<String>,
    from: Option<String>,
    to: Option<String>,
    commit: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// One snippet slice: escaped text, `<mark>`ed when it is a highlight.
pub struct Seg {
    pub text: String,
    pub mark: bool,
}

/// Splits `text` at the snippet's highlight ranges into renderable
/// segments. Ranges are byte offsets into `text` (ascending, disjoint).
fn segments(snippet: &Snippet) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut cursor = 0;
    for &(start, end) in &snippet.highlights {
        if start > cursor {
            out.push(Seg {
                text: snippet.text[cursor..start].to_owned(),
                mark: false,
            });
        }
        out.push(Seg {
            text: snippet.text[start..end].to_owned(),
            mark: true,
        });
        cursor = end;
    }
    if cursor < snippet.text.len() {
        out.push(Seg {
            text: snippet.text[cursor..].to_owned(),
            mark: false,
        });
    }
    if out.is_empty() && !snippet.text.is_empty() {
        out.push(Seg {
            text: snippet.text.clone(),
            mark: false,
        });
    }
    out
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn enc(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

/// A `/search` link carrying every filter (and the given page).
#[allow(clippy::too_many_arguments)]
fn search_href(
    tab: &str,
    q: &str,
    repo: &str,
    agent: &str,
    model: &str,
    author: &str,
    from: &str,
    to: &str,
    commit: &str,
    per_page: &str,
    page: i64,
) -> String {
    let mut href = format!(
        "/search?tab={}&q={}&repo={}&agent={}&model={}&author={}&from={}&to={}&commit={}&per_page={}&page={}",
        enc(tab),
        enc(q),
        enc(repo),
        enc(agent),
        enc(model),
        enc(author),
        enc(from),
        enc(to),
        enc(commit),
        enc(per_page),
        page,
    );
    if q.is_empty()
        && repo.is_empty()
        && agent.is_empty()
        && model.is_empty()
        && author.is_empty()
        && from.is_empty()
        && to.is_empty()
        && commit.is_empty()
    {
        href = format!("/search?tab={}&page={}", enc(tab), page);
    }
    href
}

pub struct TrailRow {
    owner: String,
    repo: String,
    number: i64,
    title: String,
    state: String,
    age: String,
    segs: Vec<Seg>,
}

pub struct SessionEventRow {
    href: String,
    kind: String,
    segs: Vec<Seg>,
}

pub struct SessionRow {
    owner: String,
    repo: String,
    ulid: String,
    agent: String,
    title: String,
    events: Vec<SessionEventRow>,
}

#[derive(Template, WebTemplate)]
#[template(path = "search.html")]
pub struct SearchPage {
    nav_user: Option<NavUser>,
    tab: String,
    q: String,
    repo: String,
    agent: String,
    model: String,
    author: String,
    from: String,
    to: String,
    commit: String,
    per_page: String,
    page: i64,
    trails: Vec<TrailRow>,
    sessions: Vec<SessionRow>,
    prev_href: Option<String>,
    next_href: Option<String>,
}

/// `GET /search?tab=&q=&repo=&agent=&model=&author=&from=&to=&commit=&page=&per_page=`.
/// The default tab is Trails; `tab=sessions` adds the session filters.
pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Query(params): Query<SearchParams>,
) -> Result<impl IntoResponse, WebError> {
    let tab = params.tab.as_deref().unwrap_or("trails").to_owned();
    if !matches!(tab.as_str(), "trails" | "sessions") {
        return Err(WebError::Unprocessable(format!(
            "unknown tab '{tab}': want trails or sessions"
        )));
    }
    let view = |value: &Option<String>| value.clone().filter(|v| !v.is_empty());
    let query = SearchQuery {
        q: params.q.clone().unwrap_or_default(),
        repo: view(&params.repo),
        agent: view(&params.agent),
        model: view(&params.model),
        author: view(&params.author),
        from: view(&params.from),
        to: view(&params.to),
        commit: view(&params.commit),
        page: params.page,
        per_page: params.per_page,
    };
    let user = session.as_ref().map(|s| &s.user);
    let map_err = |err: CoreError| match err {
        CoreError::Invalid(message) => WebError::Unprocessable(message),
        other => WebError::from(other),
    };
    let (trails, sessions, page_no, has_more) = if tab == "sessions" {
        let page = state
            .core
            .search_sessions(user, &query)
            .await
            .map_err(map_err)?;
        let rows = page
            .items
            .into_iter()
            .map(|result| {
                let events = result
                    .events
                    .into_iter()
                    .map(|event| SessionEventRow {
                        href: format!(
                            "/{}/{}/sessions/{}#turn-{}",
                            result.owner, result.repo, result.session, event.seq
                        ),
                        kind: event.kind,
                        segs: segments(&event.snippet),
                    })
                    .collect();
                SessionRow {
                    owner: result.owner,
                    repo: result.repo,
                    ulid: result.session,
                    agent: result.agent,
                    title: result.title,
                    events,
                }
            })
            .collect();
        (Vec::new(), rows, page.page, page.has_more)
    } else {
        let page = state
            .core
            .search_trails(user, &query)
            .await
            .map_err(map_err)?;
        let now = unix_now();
        let rows = page
            .items
            .into_iter()
            .map(|result| TrailRow {
                owner: result.owner,
                repo: result.repo,
                number: result.number,
                title: result.title,
                state: result.state,
                age: format_age(now, result.updated_at),
                segs: segments(&result.snippet),
            })
            .collect();
        (rows, Vec::new(), page.page, page.has_more)
    };
    let q = params.q.clone().unwrap_or_default();
    let repo = params.repo.clone().unwrap_or_default();
    let agent = params.agent.clone().unwrap_or_default();
    let model = params.model.clone().unwrap_or_default();
    let author = params.author.clone().unwrap_or_default();
    let from = params.from.clone().unwrap_or_default();
    let to = params.to.clone().unwrap_or_default();
    let commit = params.commit.clone().unwrap_or_default();
    let per_page = params.per_page.map(|v| v.to_string()).unwrap_or_default();
    let prev_href = (page_no > 1).then(|| {
        search_href(
            &tab,
            &q,
            &repo,
            &agent,
            &model,
            &author,
            &from,
            &to,
            &commit,
            &per_page,
            page_no - 1,
        )
    });
    let next_href = has_more.then(|| {
        search_href(
            &tab,
            &q,
            &repo,
            &agent,
            &model,
            &author,
            &from,
            &to,
            &commit,
            &per_page,
            page_no + 1,
        )
    });
    Ok((
        noindex_headers(),
        SearchPage {
            nav_user: nav(session.as_ref()),
            tab,
            q,
            repo,
            agent,
            model,
            author,
            from,
            to,
            commit,
            per_page,
            page: page_no,
            trails,
            sessions,
            prev_href,
            next_href,
        },
    ))
}
