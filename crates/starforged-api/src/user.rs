use axum::Json;
use serde::Serialize;

use crate::auth::ApiAuth;
use crate::error::ApiError;

#[derive(Serialize)]
pub struct UserJson {
    id: i64,
    handle: String,
    display_name: String,
    is_admin: bool,
}

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
