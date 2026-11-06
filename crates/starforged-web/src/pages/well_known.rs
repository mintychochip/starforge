//! `GET /.well-known/starforge.json` (spec §7.6): anonymous server discovery
//! for the `starforge` CLI. The body names the server version, the API root
//! (`api_url`, scheme + authority + optional path prefix, no trailing slash —
//! the CLI appends `/api/v1/...` itself), and the SSH clone base (`ssh_url`,
//! empty when SSH is disabled). It reveals nothing beyond the clone URLs,
//! which are already public, so it stays reachable without sign-in even on
//! instances that require an account to browse.

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::AppState;

/// The discovery document. Unauthenticated: the router-level middleware
/// (`moved::redirect_renamed`) only rewrites 404/401 answers under repository
/// paths, and page handlers opt into sign-in per route — this one does not.
pub async fn show(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "starforge": env!("CARGO_PKG_VERSION"),
        "api_url": state.settings.base_url.trim_end_matches('/'),
        "ssh_url": state.settings.ssh_clone_base.as_deref().unwrap_or(""),
    }))
}
