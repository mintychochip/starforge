//! Upload HTTP client (implemented C6).

/// Authenticated client for session uploads.
pub struct UploadClient {
    pub api_url: String,
    pub token: String,
    pub client: reqwest::Client,
}

impl UploadClient {
    /// Build a client for `api_url` with bearer `token`.
    pub fn new(api_url: String, token: String) -> Self {
        Self {
            api_url,
            token,
            client: reqwest::Client::new(),
        }
    }
}
