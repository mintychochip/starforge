//! Server discovery info (implemented C3).

/// Server endpoints discovered via `/.well-known/starforge.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerInfo {
    pub api_url: String,
    pub ssh_url: String,
    pub version: String,
}
