//! Errors for HTML routes, rendered as an error page.

use askama::Template;
use askama_web::WebTemplate;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use starforged_core::CoreError;

use crate::views::NavUser;

#[derive(Debug)]
pub enum WebError {
    NotFound,
    Forbidden,
    BadRequest(String),
    Internal(String),
}

impl From<CoreError> for WebError {
    fn from(err: CoreError) -> WebError {
        match err {
            CoreError::NotFound => WebError::NotFound,
            CoreError::Forbidden | CoreError::Unauthenticated => WebError::Forbidden,
            CoreError::Invalid(message) | CoreError::Conflict(message) => {
                WebError::BadRequest(message)
            }
            other => WebError::Internal(other.to_string()),
        }
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
struct ErrorPage {
    nav_user: Option<NavUser>,
    title: &'static str,
    message: String,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let (status, title, message) = match self {
            WebError::NotFound => (
                StatusCode::NOT_FOUND,
                "Not found",
                "That page does not exist, or you do not have access to it.".to_owned(),
            ),
            WebError::Forbidden => (
                StatusCode::FORBIDDEN,
                "Forbidden",
                "You do not have permission to do that.".to_owned(),
            ),
            WebError::BadRequest(message) => (StatusCode::BAD_REQUEST, "Invalid request", message),
            WebError::Internal(message) => {
                tracing::error!(error = %message, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Server error",
                    "Something went wrong; the error was logged.".to_owned(),
                )
            }
        };
        (
            status,
            ErrorPage {
                nav_user: None,
                title,
                message,
            },
        )
            .into_response()
    }
}
