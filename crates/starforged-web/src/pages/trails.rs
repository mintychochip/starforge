//! Trail web UI (spec §6.2, M2a): list with filters, new form, and detail
//! with discussion plus triage-gated controls. Reads 404 for non-readers
//! so trail numbers stay undiscoverable; mutations answer 403 below their
//! threshold. Intent and comment bodies render through
//! [`crate::markdown::render_prose`]; everything else relies on askama escaping.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;
use starforged_core::trails::TrailFilterInput;

use crate::AppState;
use crate::auth::{MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::markdown;
use crate::views::{NavUser, RepoHead, STRICT_CSP, format_age, format_time, nav};

/// Trails per web page; the API stays keyset-based.
const PAGE_SIZE: i64 = 30;
/// `?page` beyond this 404s without walking cursors (DoS guard).
const MAX_PAGE: i64 = 1000;

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// `X-Robots-Tag: noindex` on every trail page, matching the session pages.
fn noindex_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers
}

/// Noindex plus the strict CSP for every trail page, whose intent and
/// comments are attacker-influenced Markdown (same combination as the
/// session viewer).
fn detail_headers() -> HeaderMap {
    let mut headers = noindex_headers();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
    headers
}

#[derive(Deserialize)]
pub struct ListQuery {
    state: Option<String>,
    label: Option<String>,
    assignee: Option<String>,
    author: Option<String>,
    page: Option<i64>,
}

pub struct TrailRow {
    number: i64,
    title: String,
    state: String,
    ready: bool,
    labels: Vec<String>,
    assignees: Vec<String>,
    age: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "trails.html")]
pub struct TrailsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    rows: Vec<TrailRow>,
    state: String,
    label: String,
    assignee: String,
    author: String,
    page: i64,
    prev_href: Option<String>,
    next_href: Option<String>,
}

/// `GET /{owner}/{repo}/trails[?state=&label=&assignee=&author=&page=]`.
/// Non-readers 404, exactly like every other trail read.
pub async fn list(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, WebError> {
    let user = session.as_ref().map(|s| &s.user);
    let access = state.core.repo_for(user, &owner, &repo).await?;
    let repo_owner = access.repo.owner.clone();
    let repo_name = access.repo.name.clone();
    let filter_state = query.state.clone().filter(|s| !s.is_empty());
    let filter_label = query.label.clone().filter(|s| !s.is_empty());
    let filter_assignee = query.assignee.clone().filter(|s| !s.is_empty());
    let filter_author = query.author.clone().filter(|s| !s.is_empty());
    let page_no = query.page.unwrap_or(1).max(1);
    if page_no > MAX_PAGE {
        return Err(WebError::NotFound);
    }

    // The service is keyset-paged; walk cursors to reach `?page=N`.
    let mut listed = fetch_page(
        &state,
        user,
        &owner,
        &repo,
        &filter_state,
        &filter_label,
        &filter_assignee,
        &filter_author,
        None,
    )
    .await?;
    if listed.trails.is_empty() && page_no > 1 {
        return Err(WebError::NotFound);
    }
    for _ in 1..page_no {
        let Some(cursor) = listed.next_after else {
            return Err(WebError::NotFound);
        };
        listed = fetch_page(
            &state,
            user,
            &owner,
            &repo,
            &filter_state,
            &filter_label,
            &filter_assignee,
            &filter_author,
            Some(cursor),
        )
        .await?;
        if listed.trails.is_empty() {
            return Err(WebError::NotFound);
        }
    }

    let now = unix_now();
    let rows = listed
        .trails
        .into_iter()
        .map(|t| TrailRow {
            number: t.number,
            title: t.title,
            state: t.state,
            ready: t.ready,
            labels: t.labels,
            assignees: t.assignees,
            age: format_age(now, t.created_at),
        })
        .collect();
    let prev_href = (page_no > 1).then(|| {
        list_href(
            &repo_owner,
            &repo_name,
            filter_state.as_deref().unwrap_or_default(),
            filter_label.as_deref().unwrap_or_default(),
            filter_assignee.as_deref().unwrap_or_default(),
            filter_author.as_deref().unwrap_or_default(),
            page_no - 1,
        )
    });
    let next_href = listed.next_after.is_some().then(|| {
        list_href(
            &repo_owner,
            &repo_name,
            filter_state.as_deref().unwrap_or_default(),
            filter_label.as_deref().unwrap_or_default(),
            filter_assignee.as_deref().unwrap_or_default(),
            filter_author.as_deref().unwrap_or_default(),
            page_no + 1,
        )
    });
    Ok((
        detail_headers(),
        TrailsPage {
            nav_user: nav(session.as_ref()),
            head: RepoHead::new(&access, "trails", None),
            rows,
            state: filter_state.unwrap_or_default(),
            label: filter_label.unwrap_or_default(),
            assignee: filter_assignee.unwrap_or_default(),
            author: filter_author.unwrap_or_default(),
            page: page_no,
            prev_href,
            next_href,
        },
    ))
}

/// Filter-preserving pager links; values come from constrained charsets
/// (states, lowercased labels, handles), and askama escapes them in `href`.
fn list_href(
    owner: &str,
    repo: &str,
    state: &str,
    label: &str,
    assignee: &str,
    author: &str,
    page: i64,
) -> String {
    let mut query = String::new();
    for (key, value) in [
        ("state", state),
        ("label", label),
        ("assignee", assignee),
        ("author", author),
    ] {
        if !value.is_empty() {
            if !query.is_empty() {
                query.push('&');
            }
            query.push_str(key);
            query.push('=');
            query.push_str(value);
        }
    }
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(&format!("page={page}"));
    format!("/{owner}/{repo}/trails?{query}")
}
/// One keyset page of the trail list, mapped from web filters.
#[allow(clippy::too_many_arguments)]
async fn fetch_page(
    state: &AppState,
    user: Option<&starforged_core::accounts::User>,
    owner: &str,
    repo: &str,
    filter_state: &Option<String>,
    filter_label: &Option<String>,
    filter_assignee: &Option<String>,
    filter_author: &Option<String>,
    after: Option<i64>,
) -> Result<starforged_core::trails::ListPage, WebError> {
    Ok(state
        .core
        .list_trails(
            user,
            owner,
            repo,
            &TrailFilterInput {
                state: filter_state.clone(),
                label: filter_label.clone(),
                assignee: filter_assignee.clone(),
                author: filter_author.clone(),
                after,
                limit: Some(PAGE_SIZE),
            },
        )
        .await?)
}

#[derive(Template, WebTemplate)]
#[template(path = "trail_new.html")]
pub struct TrailNewPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    title: String,
    intent: String,
    error: Option<String>,
}

/// `GET /{owner}/{repo}/trails/new`: signed-in readers only (anonymous
/// requests redirect to sign-in via `RequireUser`; other non-readers 404).
pub async fn new_form(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<impl IntoResponse, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok((
        detail_headers(),
        TrailNewPage {
            nav_user: Some(NavUser::from_session(&session)),
            head: RepoHead::new(&access, "trails", None),
            csrf: session.csrf_token.clone(),
            title: String::new(),
            intent: String::new(),
            error: None,
        },
    ))
}

#[derive(Deserialize)]
pub struct NewForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    intent: String,
}

/// `POST /{owner}/{repo}/trails/new`: creates the trail and redirects to it.
/// `Invalid` re-renders the form with 422 instead of dropping the input.
pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<NewForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .create_trail(&session.user, &owner, &repo, &form.title, &form.intent)
        .await
    {
        Ok(view) => Ok(Redirect::to(&format!(
            "/{}/{}/trails/{}",
            access.repo.owner, access.repo.name, view.number
        ))
        .into_response()),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            detail_headers(),
            TrailNewPage {
                nav_user: Some(NavUser::from_session(&session)),
                head: RepoHead::new(&access, "trails", None),
                csrf: session.csrf_token.clone(),
                title: form.title.clone(),
                intent: form.intent.clone(),
                error: Some(message),
            },
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

pub struct CommentItem {
    id: i64,
    author_handle: String,
    body_html: String,
    body_raw: String,
    created: String,
    edited: Option<String>,
    can_edit: bool,
}

pub struct TimelineItem {
    text: String,
    time: String,
}

/// One change on a trail, as the trail page's Changes section renders it.
pub struct TrailChangeItem {
    k: i64,
    kind: String,
    head_branch: Option<String>,
    base_branch: String,
    current_revision: i64,
    state: String,
    mergeability: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "trail.html")]
pub struct TrailPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    number: i64,
    title: String,
    state: String,
    ready: bool,
    author_handle: String,
    labels: Vec<String>,
    assignees: Vec<String>,
    created: String,
    updated: String,
    closed: Option<String>,
    intent_html: String,
    intent_raw: String,
    comments: Vec<CommentItem>,
    timeline: Vec<TimelineItem>,
    changes: Vec<TrailChangeItem>,
    can_create_change: bool,
    can_edit: bool,
    can_triage: bool,
    can_comment: bool,
    is_open: bool,
    error: Option<String>,
}

/// Builds the detail view; shared by the viewer and the 422 re-renders.
pub(crate) async fn detail_view(
    state: &AppState,
    session: Option<&WebSession>,
    owner: &str,
    repo: &str,
    number: i64,
    error: Option<String>,
) -> Result<TrailPage, WebError> {
    let user = session.map(|s| &s.user);
    let access = state.core.repo_for(user, owner, repo).await?;
    let detail = state
        .core
        .trail_by_number(user, owner, repo, number)
        .await?;
    let trail = &detail.trail;
    let mut handles: HashMap<i64, String> = HashMap::new();
    for id in detail.timeline.iter().filter_map(|event| event.actor_id) {
        if let Entry::Vacant(slot) = handles.entry(id) {
            let handle = state
                .core
                .user_by_id(id)
                .await?
                .map(|u| u.handle)
                .unwrap_or_else(|| "someone".to_owned());
            slot.insert(handle);
        }
    }
    let timeline = detail
        .timeline
        .iter()
        .map(|event| {
            let actor = event
                .actor_id
                .and_then(|id| handles.get(&id).cloned())
                .unwrap_or_else(|| "starforge".to_owned());
            TimelineItem {
                text: timeline_text(&event.kind, &event.payload, &actor),
                time: format_time(event.created_at),
            }
        })
        .collect();
    let comments = detail
        .comments
        .iter()
        .map(|c| CommentItem {
            id: c.id,
            author_handle: c.author_handle.clone(),
            body_html: markdown::render_prose(&c.body),
            body_raw: c.body.clone(),
            created: format_time(c.created_at),
            edited: c.edited_at.map(format_time),
            can_edit: session.is_some_and(|s| {
                c.author_id == Some(s.user.id)
                    || access.permission >= Permission::Admin
                    || s.user.is_admin
            }),
        })
        .collect();
    Ok(TrailPage {
        nav_user: session.map(NavUser::from_session),
        head: RepoHead::new(&access, "trails", None),
        csrf: session.map(|s| s.csrf_token.clone()).unwrap_or_default(),
        number: trail.number,
        title: trail.title.clone(),
        state: trail.state.clone(),
        ready: trail.ready,
        author_handle: trail.author_handle.clone(),
        labels: trail.labels.clone(),
        assignees: trail.assignees.clone(),
        created: format_time(trail.created_at),
        updated: format_time(trail.updated_at),
        closed: trail.closed_at.map(format_time),
        intent_html: markdown::render_prose(&trail.intent),
        intent_raw: trail.intent.clone(),
        comments,
        timeline,
        changes: state
            .core
            .list_changes(user, owner, repo, number, None)
            .await?
            .into_iter()
            .map(|c| TrailChangeItem {
                k: c.k,
                kind: c.kind,
                head_branch: c.head_branch,
                base_branch: c.base_branch,
                current_revision: c.current_revision,
                state: c.state,
                mergeability: c.mergeability,
            })
            .collect(),
        can_edit: detail.can_edit,
        can_triage: detail.can_triage,
        can_comment: session.is_some(),
        can_create_change: detail.can_triage,
        is_open: trail.state == "open",
        error,
    })
}

/// Human-readable timeline lines. The payload is untrusted JSON, so unknown
/// shapes fall back to the bare kind; askama escapes the result.
fn timeline_text(kind: &str, payload: &str, actor: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
    let field = |name: &str| value.get(name).and_then(|v| v.as_str());
    match kind {
        "trail.open" => format!("{actor} opened this trail"),
        "trail.state" => match field("to") {
            Some("closed") => format!("{actor} closed this trail"),
            Some("open") => format!("{actor} reopened this trail"),
            _ => format!("{actor} changed the state"),
        },
        "trail.comment" => format!("{actor} commented"),
        "trail.label" => {
            let name = field("name").unwrap_or("a label");
            match field("action") {
                Some("remove") => format!("{actor} removed label {name}"),
                _ => format!("{actor} added label {name}"),
            }
        }
        "trail.assignee" => {
            let who = field("user").unwrap_or("someone");
            match field("action") {
                Some("remove") => format!("{actor} unassigned {who}"),
                _ => format!("{actor} assigned {who}"),
            }
        }
        "trail.edit" => {
            let fields = value
                .get("fields")
                .and_then(|v| v.as_array())
                .map(|fields| {
                    fields
                        .iter()
                        .filter_map(|f| f.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "the trail".to_owned());
            format!("{actor} edited {fields}")
        }
        _ => format!("{actor} {kind}"),
    }
}

/// `GET /{owner}/{repo}/trails/{number}`.
pub async fn detail(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
) -> Result<impl IntoResponse, WebError> {
    let page = detail_view(&state, session.as_ref(), &owner, &repo, number, None).await?;
    Ok((detail_headers(), page))
}

#[derive(Deserialize)]
pub struct CommentForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    body: String,
}

/// `POST /{owner}/{repo}/trails/{number}/comment`: any signed-in reader.
/// `Invalid` re-renders the detail with 422.
pub async fn comment(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<CommentForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .add_comment(&session.user, &owner, &repo, number, &form.body)
        .await
    {
        Ok(saved) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}#comment-{}",
                access.repo.owner, access.repo.name, saved.id
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page =
                detail_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct EditForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    title: Option<String>,
    intent: Option<String>,
    ready: Option<String>,
}

/// `POST /{owner}/{repo}/trails/{number}/edit`: the author (title/intent)
/// or triage (anything, including the ready toggle). `Invalid` re-renders.
pub async fn edit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<EditForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let ready = match form.ready.as_deref() {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return Err(WebError::BadRequest("invalid ready value".into())),
    };
    match state
        .core
        .update_trail(
            &session.user,
            &owner,
            &repo,
            number,
            form.title.as_deref(),
            form.intent.as_deref(),
            ready,
        )
        .await
    {
        Ok(_) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}",
                access.repo.owner, access.repo.name
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page =
                detail_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct CommentEditForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    body: String,
}

/// `POST /{owner}/{repo}/trails/{number}/comments/{id}/edit`: the comment
/// author or an admin. `Invalid` re-renders the detail with 422.
pub async fn edit_comment(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number, id)): Path<(String, String, i64, i64)>,
    Form(form): Form<CommentEditForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .edit_comment(&session.user, &owner, &repo, number, id, &form.body)
        .await
    {
        Ok(_) => {
            let access = state
                .core
                .repo_for(Some(&session.user), &owner, &repo)
                .await?;
            Ok(Redirect::to(&format!(
                "/{}/{}/trails/{number}#comment-{id}",
                access.repo.owner, access.repo.name
            ))
            .into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page =
                detail_view(&state, Some(&session), &owner, &repo, number, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, detail_headers(), page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct StateForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    state: String,
}

/// `POST /{owner}/{repo}/trails/{number}/state`: triage-only close/reopen.
/// `merged` is owned by the merge path and rejected with 400.
pub async fn set_state(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<StateForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .set_trail_state(&session.user, &owner, &repo, number, &form.state)
        .await?;
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct LabelForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    name: String,
}

/// `POST /{owner}/{repo}/trails/{number}/labels`: triage-only add/remove
/// via the `action` field. Bad labels are 400.
pub async fn set_label(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<LabelForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match form.action.as_str() {
        "add" => {
            state
                .core
                .add_label(&session.user, &owner, &repo, number, &form.name)
                .await?;
        }
        "remove" => {
            state
                .core
                .remove_label(&session.user, &owner, &repo, number, &form.name)
                .await?;
        }
        _ => return Err(WebError::BadRequest("unknown action".into())),
    }
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct AssigneeForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    handle: String,
}

/// `POST /{owner}/{repo}/trails/{number}/assignees`: triage-only add/remove
/// via the `action` field. Unknown users are 400.
pub async fn set_assignee(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, number)): Path<(String, String, i64)>,
    Form(form): Form<AssigneeForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match form.action.as_str() {
        "add" => {
            state
                .core
                .add_assignee(&session.user, &owner, &repo, number, &form.handle)
                .await?;
        }
        "remove" => {
            state
                .core
                .remove_assignee(&session.user, &owner, &repo, number, &form.handle)
                .await?;
        }
        _ => return Err(WebError::BadRequest("unknown action".into())),
    }
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/trails/{number}",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}
