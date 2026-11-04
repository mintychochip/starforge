//! Credentials file shape (implemented C2).

/// Credentials for one server host.
///
/// Stored file shape: `{ [servers."<host>"] = Credentials }`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
}
