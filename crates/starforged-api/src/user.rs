use axum::Json;
use serde::Serialize;

use crate::auth::ApiAuth;
use crate::error::ApiError;

#[derive(Serialize, utoipa::ToSchema)]
pub struct UserJson {
    id: i64,
    handle: String,
    display_name: String,
    is_admin: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/user",
    responses(
        (status = 200, description = "Current user", body = UserJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn show(auth: ApiAuth) -> Result<Json<UserJson>, ApiError> {
    let auth = auth.0.ok_or(ApiError::Unauthenticated)?;
    let user = auth.user;
    Ok(Json(UserJson {
        id: user.id,
        handle: user.handle,
        display_name: user.display_name,
        is_admin: user.is_admin,
    }))
}
