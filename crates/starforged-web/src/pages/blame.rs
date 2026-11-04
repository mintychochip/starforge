//! Blame with session chips (M1e E4): line-numbered code with per-run
//! attribution and the linked sessions each blamed commit carries.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
use serde::Deserialize;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{
    BlameLineGroup, Crumb, NavUser, RepoHead, STRICT_CSP, SessionChip, content_href, crumbs, nav,
};

/// Lines per blame page.
pub const PER_PAGE: usize = 500;

#[derive(Deserialize)]
pub struct BlameQuery {
    at: Option<String>,
    page: Option<usize>,
}

#[derive(Template, WebTemplate)]
#[template(path = "blame.html")]
pub struct BlamePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    ref_name: String,
    path: String,
    file_name: String,
    crumbs: Vec<Crumb>,
    blob_href: String,
    page: usize,
    pages: usize,
    total: usize,
    prev: Option<usize>,
    next: Option<usize>,
    notice: Option<String>,
    groups: Vec<BlameLineGroup>,
}

/// `/{owner}/{repo}/blame/{*rest}?at=<ref>&page=N`: the blamed file with
/// per-run attribution and session chips. Unknown revs, missing files, and
/// traversal/absolute paths answer 404; out-of-range pages too.
pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
    Query(query): Query<BlameQuery>,
) -> Result<(HeaderMap, BlamePage), WebError> {
    if rest.is_empty() || rest.starts_with('/') || rest.split('/').any(|s| s == "..") {
        return Err(WebError::NotFound);
    }
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let view = state
        .core
        .blame_with_sessions(
            &access,
            session.as_ref().map(|s| &s.user),
            query.at.as_deref(),
            &rest,
        )
        .await?;
    let repo_ref = &access.repo;
    let (dir, file_name) = view
        .path
        .rsplit_once('/')
        .unwrap_or(("", view.path.as_str()));
    let blob_href = content_href(
        &repo_ref.owner,
        &repo_ref.name,
        "blob",
        &view.ref_name,
        &view.path,
    );
    let base = BlamePage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "code", Some(&view.ref_name)),
        ref_name: view.ref_name.clone(),
        path: view.path.clone(),
        file_name: file_name.to_owned(),
        crumbs: crumbs(&repo_ref.owner, &repo_ref.name, &view.ref_name, dir),
        blob_href,
        page: 1,
        pages: 1,
        total: 0,
        prev: None,
        next: None,
        notice: None,
        groups: Vec::new(),
    };
    if let Some(reason) = view.unavailable {
        return Ok((
            strict_csp_headers(),
            BlamePage {
                notice: Some(reason),
                ..base
            },
        ));
    }
    let total: usize = view.blocks.iter().map(|b| b.lines.len()).sum();
    let pages = total.div_ceil(PER_PAGE).max(1);
    let page = query.page.unwrap_or(1);
    if page < 1 || page > pages {
        return Err(WebError::NotFound);
    }
    let first = (page - 1) * PER_PAGE + 1;
    let last = (page * PER_PAGE).min(total);
    let mut groups = Vec::new();
    for block in &view.blocks {
        let block_first = block.start;
        let block_last = block.start + block.lines.len() - 1;
        if block_last < first || block_first > last {
            continue;
        }
        let mut lines = Vec::new();
        for (i, text) in block.lines.iter().enumerate() {
            let n = block_first + i;
            if n >= first && n <= last {
                lines.push(crate::views::BlameLine {
                    n,
                    text: text.clone(),
                });
            }
        }
        if lines.is_empty() {
            continue;
        }
        groups.push(BlameLineGroup {
            sha: block.sha.clone(),
            short: block.sha.chars().take(8).collect(),
            author: block.author.clone(),
            when: crate::views::format_time(block.author_time),
            summary: block.summary.lines().next().unwrap_or("").to_owned(),
            commit_href: format!("/{}/{}/commit/{}", repo_ref.owner, repo_ref.name, block.sha),
            continuation: block_first < first,
            sessions: block
                .sessions
                .iter()
                .map(|(link, session_row)| {
                    SessionChip::new(
                        &repo_ref.owner,
                        &repo_ref.name,
                        &link.session_ulid,
                        &session_row.agent_name,
                        &session_row.agent_version,
                        session_row.started_at,
                        &link.confidence,
                        &link.source,
                        link.seq_start,
                    )
                })
                .collect(),
            lines,
        });
    }
    Ok((
        strict_csp_headers(),
        BlamePage {
            page,
            pages,
            total,
            prev: (page > 1).then_some(page - 1),
            next: (page < pages).then_some(page + 1),
            groups,
            ..base
        },
    ))
}

/// The strict CSP for a page rendered from attacker-influenced content
/// (blamed lines, commit summaries, and session chips). Wins over the
/// `security_headers` middleware default, which uses `or_insert`.
fn strict_csp_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(STRICT_CSP),
    );
    headers
}
