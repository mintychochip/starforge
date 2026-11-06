//! Site-admin API (spec §10.4): the audit log. D3.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use starforged_core::audit::AuditQuery;
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::rfc3339;

#[derive(Deserialize)]
pub struct AuditParams {
    actor: Option<String>,
    action: Option<String>,
    target: Option<String>,
    from: Option<String>,
    to: Option<String>,
    after: Option<i64>,
    limit: Option<i64>,
}

/// `GET /admin/audit`: newest first, keyset-paginated audit entries. Needs a site
/// admin with the `admin` token scope; anyone else is answered as if the route
/// did not exist (a non-admin token) or refused for the missing scope.
#[utoipa::path(
    get,
    path = "/api/v1/admin/audit",
    params(
        ("actor" = Option<String>, Query, description = "Filter by actor"),
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("target" = Option<String>, Query, description = "Filter by target"),
        ("from" = Option<String>, Query, description = "Entries at or after this timestamp"),
        ("to" = Option<String>, Query, description = "Entries at or before this timestamp"),
        ("after" = Option<i64>, Query, description = "Keyset cursor"),
        ("limit" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Audit entries", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn audit(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Query(params): Query<AuditParams>,
) -> Result<Json<Value>, ApiError> {
    let auth = auth.require(Scope::Admin)?;
    if !auth.user.is_admin {
        return Err(ApiError::NotFound);
    }
    let non_empty = |value: Option<String>| value.filter(|v| !v.is_empty());
    let limit = params.limit.unwrap_or(100).clamp(1, 200);
    let mut entries = state
        .core
        .admin_audit(
            &auth.user,
            &AuditQuery {
                actor: non_empty(params.actor),
                action: non_empty(params.action),
                target: non_empty(params.target),
                from: non_empty(params.from),
                to: non_empty(params.to),
                after: params.after,
                limit: limit + 1,
            },
        )
        .await?;
    // One extra row: its presence means the page continues at its id.
    let next_after = if entries.len() > limit as usize {
        entries.truncate(limit as usize);
        entries.last().map(|entry| entry.id)
    } else {
        None
    };
    let entries: Vec<Value> = entries
        .iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "actor": entry.actor,
                "action": entry.action,
                "target": entry.target,
                "detail": entry.detail,
                "ip": entry.ip,
                "user_agent": entry.user_agent,
                "created_at": rfc3339(entry.created_at),
            })
        })
        .collect();
    Ok(Json(
        json!({ "entries": entries, "next_after": next_after }),
    ))
}
