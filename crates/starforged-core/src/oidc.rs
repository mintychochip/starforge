//! OIDC single sign-on (spec §9, M3d D2, D4, D5): authorization-code flow
//! with PKCE against one configured provider, and complete ID-token
//! verification in one pure function ([`verify_id_token`]).
//!
//! Flow state (`state`, `nonce`, PKCE verifier) lives server-side in
//! `login_challenges` (single use, 10-minute expiry); the browser carries
//! only the random challenge token. Discovery is fetched on first use and
//! cached for one hour; JWKS keys are cached by `kid` and refreshed once on
//! an unknown `kid`. HTTPS is required everywhere except loopback `http`
//! (the in-process fake provider in tests). Any verification failure logs
//! the specific reason at debug level and fails the login generically.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use starforged_db::{auth_factors, now, users};
use subtle::ConstantTimeEq;

use crate::accounts::{CreateUser, User};
use crate::registration::RegistrationMode;
use crate::sessions::SECOND_FACTOR_TTL_SECS;
use crate::{Core, CoreError, CoreResult, crypto};

/// Clock leeway applied to `exp`/`iat` (plan Global Constraints: 60 s).
pub const LEEWAY_SECS: i64 = 60;
/// Login challenges live 10 minutes.
pub const CHALLENGE_TTL_SECS: i64 = 600;
/// Discovery documents are cached for one hour (plan D4).
pub const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
/// OIDC callback path on this server (plan D4).
pub const CALLBACK_PATH: &str = "/login/oidc/callback";

/// The `[oidc]` section as core settings (plan D4). `client_secret` never
/// renders in `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OidcConfig {
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub button_label: String,
    pub auto_create: bool,
    pub link_by_email: bool,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &if self.client_secret.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .field("scopes", &self.scopes)
            .field("button_label", &self.button_label)
            .field("auto_create", &self.auto_create)
            .field("link_by_email", &self.link_by_email)
            .finish()
    }
}

/// Why a login is happening: a fresh sign-in, or linking the provider to
/// the already-signed-in user (`user_id` rides on the challenge row, so
/// `oidc_finish`'s callers can tell the intents apart before finishing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcIntent {
    Login,
    Link { user_id: i64 },
}

/// One identity linked to the signed-in user, for `/settings/identities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedIdentity {
    pub id: i64,
    pub issuer: String,
    pub subject: String,
}

/// The outcome of resolving verified claims to a sign-in
/// ([`Core::oidc_login`], plan D5).
#[derive(Debug, Clone)]
pub enum OidcLoginOutcome {
    /// The web session was opened.
    Session(User, crate::sessions::NewSession),
    /// The identity resolved; the second factor must complete the login.
    /// The inner string is the random challenge token for the browser cookie.
    NeedsSecondFactor(String),
    /// No linked identity, no verified-email match, and auto-create is
    /// off or not allowed: the generic "no account" page.
    NoAccount,
}

/// Turns provider text into handle-shaped text (plan D5 step 3): ASCII
/// letters and digits kept (lowercased), anything else becomes `-`, runs
/// of `-` collapse, and leading/trailing `-` are dropped. The result may
/// still clash or be reserved; the caller deduplicates and `create_user`
/// validates.
pub fn sanitize_handle(raw: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true;
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.chars()
        .take(39)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned()
}

/// The OIDC discovery document, reduced to what the flow needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub token_endpoint_auth_methods: Vec<String>,
}

/// What [`verify_id_token`] checks the token against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expect {
    pub issuer: String,
    pub client_id: String,
    /// The nonce stored on the challenge row; `None` skips the check.
    pub nonce: Option<String>,
    /// Current time in unix seconds.
    pub now: i64,
}

/// The verified ID-token claims (only what identity resolution reads).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    #[serde(default, deserialize_with = "de_string_or_vec")]
    pub aud: Vec<String>,
    pub azp: Option<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub nonce: Option<String>,
    pub email: Option<String>,
    #[serde(default, deserialize_with = "de_bool_or_string")]
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

fn de_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(vec![s]),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| serde::de::Error::custom("audience must be a string"))
            })
            .collect(),
        _ => Err(serde::de::Error::custom("aud must be a string or array")),
    }
}

fn de_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Bool(b) => Ok(Some(b)),
        serde_json::Value::String(s) => match s.as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom("email_verified must be a boolean")),
        },
        _ => Err(serde::de::Error::custom("email_verified must be a boolean")),
    }
}

/// Why ID-token verification refused the token. The login fails with a
/// generic message; this reason only reaches the debug log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported signing algorithm")]
    UnsupportedAlg,
    #[error("unknown key id")]
    UnknownKid,
    #[error("bad signature")]
    BadSignature,
    #[error("unexpected issuer")]
    WrongIssuer,
    #[error("unexpected audience")]
    WrongAudience,
    #[error("unexpected authorized party")]
    WrongAzp,
    #[error("token expired")]
    Expired,
    #[error("token issued in the future")]
    NotYetValid,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Parses a JWKS document (`{"keys": [...]}`).
    pub fn parse(text: &str) -> Result<Jwks, VerifyError> {
        #[derive(Deserialize)]
        struct Doc {
            keys: Vec<Jwk>,
        }
        let doc: Doc = serde_json::from_str(text).map_err(|_| VerifyError::Malformed)?;
        Ok(Jwks { keys: doc.keys })
    }

    pub(crate) fn from_vec(keys: Vec<Jwk>) -> Jwks {
        Jwks { keys }
    }

    fn get(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

fn b64url_decode(text: &str) -> Result<Vec<u8>, VerifyError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| VerifyError::Malformed)
}

fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0_u8; bytes];
    getrandom::fill(&mut buf).expect("the OS random number generator is available");
    b64url_encode(&buf)
}

/// The PKCE S256 challenge for `verifier` (RFC 7636 §4.2): base64url of
/// `SHA-256(verifier)` without padding.
pub fn pkce_challenge(verifier: &str) -> String {
    b64url_encode(&Sha256::digest(verifier.as_bytes()))
}

/// Parses the JWS header without verifying anything (key selection only;
/// [`verify_id_token`] re-checks everything before trusting the claims).
pub(crate) fn token_header_kid(token: &str) -> Result<String, VerifyError> {
    let header_segment = token.split('.').next().ok_or(VerifyError::Malformed)?;
    let header: Header = serde_json::from_slice(&b64url_decode(header_segment)?)
        .map_err(|_| VerifyError::Malformed)?;
    header.kid.ok_or(VerifyError::UnknownKid)
}

/// Verifies an ID token completely (plan Global Constraints): `alg` ∈
/// {RS256, ES256} (never `none` or HS*), `kid` match, signature, `iss`
/// exact, `aud` contains the client id, `azp` equals the client id when
/// present, `exp`/`iat` within 60 s leeway, and the nonce.
pub fn verify_id_token(token: &str, jwks: &Jwks, expect: &Expect) -> Result<Claims, VerifyError> {
    let mut segments = token.split('.');
    let (header_segment, claims_segment, signature_segment) = (
        segments.next().ok_or(VerifyError::Malformed)?,
        segments.next().ok_or(VerifyError::Malformed)?,
        segments.next().ok_or(VerifyError::Malformed)?,
    );
    if segments.next().is_some() || header_segment.is_empty() || signature_segment.is_empty() {
        return Err(VerifyError::Malformed);
    }
    let header: Header = serde_json::from_slice(&b64url_decode(header_segment)?)
        .map_err(|_| VerifyError::Malformed)?;
    if header.alg != "RS256" && header.alg != "ES256" {
        return Err(VerifyError::UnsupportedAlg);
    }
    let kid = header.kid.ok_or(VerifyError::UnknownKid)?;
    let key = jwks.get(&kid).ok_or(VerifyError::UnknownKid)?;
    let signing_input = format!("{header_segment}.{claims_segment}");
    let signature = b64url_decode(signature_segment)?;
    match header.alg.as_str() {
        "RS256" => verify_rs256(key, signing_input.as_bytes(), &signature)?,
        _ => verify_es256(key, signing_input.as_bytes(), &signature)?,
    }
    let claims: Claims = serde_json::from_slice(&b64url_decode(claims_segment)?)
        .map_err(|_| VerifyError::Malformed)?;
    if claims.sub.is_empty() {
        return Err(VerifyError::MissingClaim("sub"));
    }
    if claims.iss != expect.issuer {
        return Err(VerifyError::WrongIssuer);
    }
    if !claims.aud.iter().any(|aud| aud == &expect.client_id) {
        return Err(VerifyError::WrongAudience);
    }
    if let Some(azp) = &claims.azp
        && azp != &expect.client_id
    {
        return Err(VerifyError::WrongAzp);
    }
    if expect.now > claims.exp + LEEWAY_SECS {
        return Err(VerifyError::Expired);
    }
    if claims.iat > expect.now + LEEWAY_SECS {
        return Err(VerifyError::NotYetValid);
    }
    if claims.nbf.is_some_and(|nbf| nbf > expect.now + LEEWAY_SECS) {
        return Err(VerifyError::NotYetValid);
    }
    if let Some(want) = &expect.nonce {
        match &claims.nonce {
            Some(got) if bool::from(got.as_bytes().ct_eq(want.as_bytes())) => {}
            _ => return Err(VerifyError::NonceMismatch),
        }
    }
    Ok(claims)
}

fn verify_rs256(key: &Jwk, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    if key.kty != "RSA" {
        return Err(VerifyError::UnsupportedAlg);
    }
    let n = b64url_decode(key.n.as_deref().ok_or(VerifyError::Malformed)?)?;
    let e = b64url_decode(key.e.as_deref().ok_or(VerifyError::Malformed)?)?;
    ring::signature::RsaPublicKeyComponents {
        n: std::borrow::Cow::Owned(n),
        e: std::borrow::Cow::Owned(e),
    }
    .verify(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        message,
        signature,
    )
    .map_err(|_| VerifyError::BadSignature)
}

impl std::fmt::Debug for OidcCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcCache").finish_non_exhaustive()
    }
}

fn verify_es256(key: &Jwk, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    if key.kty != "EC" || key.crv.as_deref() != Some("P-256") {
        return Err(VerifyError::UnsupportedAlg);
    }
    let x = b64url_decode(key.x.as_deref().ok_or(VerifyError::Malformed)?)?;
    let y = b64url_decode(key.y.as_deref().ok_or(VerifyError::Malformed)?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerifyError::Malformed);
    }
    let mut subject_public_key = Vec::with_capacity(65);
    subject_public_key.push(0x04);
    subject_public_key.extend_from_slice(&x);
    subject_public_key.extend_from_slice(&y);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        subject_public_key,
    )
    .verify(message, signature)
    .map_err(|_| VerifyError::BadSignature)
}

/// Whether `url` may be fetched: HTTPS always; plain HTTP only to
/// loopback (the fake provider in tests).
pub fn url_allowed(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "https" => true,
        "http" => match parsed.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
            Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
            _ => false,
        },
        _ => false,
    }
}

/// Per-process OIDC caches (plan D4): the discovery document (1 h) and the
/// JWKS keys by `kid` (refreshed once on an unknown `kid`).
pub(crate) struct OidcCache {
    discovery: tokio::sync::Mutex<Option<(Instant, Discovery)>>,
    jwks: tokio::sync::Mutex<HashMap<String, Jwk>>,
    http: reqwest::Client,
}

impl OidcCache {
    pub(crate) fn new() -> OidcCache {
        OidcCache {
            discovery: tokio::sync::Mutex::new(None),
            jwks: tokio::sync::Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("the OIDC HTTP client always builds"),
        }
    }
}

fn oidc_error(reason: &str) -> CoreError {
    tracing::debug!(reason, "OIDC flow failed");
    CoreError::Invalid("single sign-on failed".into())
}

fn generic(err: VerifyError) -> CoreError {
    oidc_error(&err.to_string())
}

/// Maximum provider response body read for any OIDC fetch (1 MiB): discovery
/// documents, JWKS, and token responses are all small JSON; a hostile
/// provider must not be able to OOM the server by buffering a huge body.
pub const MAX_PROVIDER_BODY_BYTES: usize = 1024 * 1024;

/// Reads a provider response body, refusing when `Content-Length` already
/// exceeds the cap or when the streamed bytes do. Every failure is the
/// generic single-sign-on error.
async fn read_capped_body(response: reqwest::Response) -> CoreResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_PROVIDER_BODY_BYTES as u64)
    {
        return Err(oidc_error("the oidc provider response is too large"));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| oidc_error(&err.to_string()))?
    {
        if body.len() + chunk.len() > MAX_PROVIDER_BODY_BYTES {
            return Err(oidc_error("the oidc provider response is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl Core {
    fn oidc_config(&self) -> CoreResult<&OidcConfig> {
        let config = &self.config().oidc;
        if !config.enabled {
            return Err(oidc_error("oidc is not enabled"));
        }
        if config.issuer.is_empty() || config.client_id.is_empty() {
            return Err(oidc_error("oidc is not fully configured"));
        }
        Ok(config)
    }

    /// The provider's discovery document, fetched on first use and cached
    /// for one hour. The document's `issuer` must equal the configured
    /// issuer exactly.
    pub async fn oidc_discovery(&self) -> CoreResult<Discovery> {
        let config = self.oidc_config()?.clone();
        let cache = &self.inner.oidc_cache;
        if let Some((fetched_at, discovery)) = cache.discovery.lock().await.as_ref()
            && fetched_at.elapsed() < DISCOVERY_TTL
        {
            return Ok(discovery.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        if !url_allowed(&url) {
            return Err(oidc_error("the oidc issuer URL is not https"));
        }
        let response = cache
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| oidc_error(&err.to_string()))?;
        if !url_allowed(response.url().as_str()) {
            return Err(oidc_error("the oidc discovery redirect left https"));
        }
        if !response.status().is_success() {
            return Err(oidc_error("the oidc discovery request failed"));
        }
        #[derive(Deserialize)]
        struct Doc {
            issuer: String,
            authorization_endpoint: String,
            token_endpoint: String,
            jwks_uri: String,
            #[serde(default)]
            token_endpoint_auth_methods_supported: Vec<String>,
        }
        let body = read_capped_body(response).await?;
        let doc: Doc = serde_json::from_slice(&body).map_err(|err| oidc_error(&err.to_string()))?;
        if doc.issuer != config.issuer {
            return Err(oidc_error("the oidc discovery issuer does not match"));
        }
        for endpoint in [
            &doc.authorization_endpoint,
            &doc.token_endpoint,
            &doc.jwks_uri,
        ] {
            if !url_allowed(endpoint) {
                return Err(oidc_error("the oidc discovery listed a non-https endpoint"));
            }
        }
        let discovery = Discovery {
            issuer: doc.issuer,
            authorization_endpoint: doc.authorization_endpoint,
            token_endpoint: doc.token_endpoint,
            jwks_uri: doc.jwks_uri,
            token_endpoint_auth_methods: doc.token_endpoint_auth_methods_supported,
        };
        *cache.discovery.lock().await = Some((Instant::now(), discovery.clone()));
        Ok(discovery)
    }

    /// The signing keys for `kid`, from the cached JWKS; on an unknown
    /// `kid` the JWKS is refreshed once and the lookup retried.
    async fn oidc_jwks_for(&self, kid: &str) -> CoreResult<Jwks> {
        let cache = &self.inner.oidc_cache;
        if cache.jwks.lock().await.contains_key(kid) {
            return Ok(Jwks::from_vec(
                cache.jwks.lock().await.values().cloned().collect(),
            ));
        }
        let discovery = self.oidc_discovery().await?;
        if !url_allowed(&discovery.jwks_uri) {
            return Err(oidc_error("the oidc jwks_uri is not https"));
        }
        let response = cache
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|err| oidc_error(&err.to_string()))?;
        if !url_allowed(response.url().as_str()) {
            return Err(oidc_error("the oidc jwks redirect left https"));
        }
        if !response.status().is_success() {
            return Err(oidc_error("the oidc jwks request failed"));
        }
        let body = read_capped_body(response).await?;
        let text = String::from_utf8(body).map_err(|err| oidc_error(&err.to_string()))?;
        let jwks = Jwks::parse(&text).map_err(generic)?;
        let mut cached = cache.jwks.lock().await;
        for key in &jwks.keys {
            cached.insert(key.kid.clone(), key.clone());
        }
        drop(cached);
        if cache.jwks.lock().await.contains_key(kid) {
            Ok(Jwks::from_vec(
                cache.jwks.lock().await.values().cloned().collect(),
            ))
        } else {
            Err(generic(VerifyError::UnknownKid))
        }
    }

    /// Starts an authorization-code flow: stores the server-side challenge
    /// (single use, 10 minutes) and returns the challenge token (the
    /// browser carries only this) plus the provider authorization URL.
    pub async fn oidc_begin(&self, intent: OidcIntent) -> CoreResult<(String, String)> {
        let config = self.oidc_config()?.clone();
        let discovery = self.oidc_discovery().await?;
        let challenge = crypto::random_hex(32);
        let state = random_b64(32);
        let nonce = random_b64(32);
        let verifier = random_b64(32);
        let user_id = match intent {
            OidcIntent::Login => None,
            OidcIntent::Link { user_id } => Some(user_id),
        };
        auth_factors::insert_oidc_challenge(
            self.db(),
            &crypto::sha256_hex(&challenge),
            user_id,
            &state,
            &nonce,
            &verifier,
            now() + CHALLENGE_TTL_SECS,
        )
        .await?;
        let redirect_uri = format!(
            "{}{}",
            self.config().base_url.trim_end_matches('/'),
            CALLBACK_PATH
        );
        let mut url = url::Url::parse(&discovery.authorization_endpoint)
            .map_err(|err| oidc_error(&err.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &config.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &pkce_challenge(&verifier))
            .append_pair("code_challenge_method", "S256");
        Ok((challenge, url.to_string()))
    }

    /// Finishes an authorization-code flow: consumes the challenge
    /// (single use), matches `state` in constant time, exchanges the code
    /// at the token endpoint, and verifies the ID token.
    pub async fn oidc_finish(
        &self,
        challenge_id: &str,
        code: &str,
        state: &str,
    ) -> CoreResult<Claims> {
        Ok(self
            .oidc_finish_with_user(challenge_id, code, state)
            .await?
            .0)
    }

    /// Like [`Core::oidc_finish`], also returning the challenge's intent:
    /// `Some(user_id)` for a link flow, `None` for a fresh sign-in. The
    /// caller needs it before dispatching to [`Core::oidc_link`] or
    /// [`Core::oidc_login`]; the challenge row itself is deleted on finish.
    pub async fn oidc_finish_with_user(
        &self,
        challenge_id: &str,
        code: &str,
        state: &str,
    ) -> CoreResult<(Claims, Option<i64>)> {
        let config = self.oidc_config()?.clone();
        // Single use, claimed atomically: exactly one concurrent callback
        // owns the challenge; a loser (or an unknown/expired challenge)
        // gets the generic failure and never reaches the token exchange.
        let row = auth_factors::claim_challenge(
            self.db(),
            "oidc",
            &crypto::sha256_hex(challenge_id),
            now(),
        )
        .await?
        .ok_or_else(|| oidc_error("unknown login challenge"))?;
        let intent_user = row.user_id;
        let stored_state = row.state.as_deref().unwrap_or_default();
        if !bool::from(stored_state.as_bytes().ct_eq(state.as_bytes())) {
            return Err(oidc_error("the oidc state does not match"));
        }
        let discovery = self.oidc_discovery().await?;
        if !url_allowed(&discovery.token_endpoint) {
            return Err(oidc_error("the oidc token endpoint is not https"));
        }
        let redirect_uri = format!(
            "{}{}",
            self.config().base_url.trim_end_matches('/'),
            CALLBACK_PATH
        );
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            (
                "code_verifier",
                row.code_verifier.as_deref().unwrap_or_default(),
            ),
        ];
        // `client_secret_basic` unless discovery lists only `client_secret_post` (plan D4).
        let post_only = !discovery.token_endpoint_auth_methods.is_empty()
            && !discovery
                .token_endpoint_auth_methods
                .iter()
                .any(|method| method == "client_secret_basic");
        if post_only {
            form.push(("client_id", config.client_id.as_str()));
            form.push(("client_secret", config.client_secret.as_str()));
        }
        let mut request = self
            .inner
            .oidc_cache
            .http
            .post(&discovery.token_endpoint)
            .form(&form);
        if !post_only {
            request = request.basic_auth(&config.client_id, Some(config.client_secret.as_str()));
        }
        let response = request
            .send()
            .await
            .map_err(|err| oidc_error(&err.to_string()))?;
        if !url_allowed(response.url().as_str()) {
            return Err(oidc_error("the oidc token response left https"));
        }
        if !response.status().is_success() {
            return Err(oidc_error("the oidc token exchange failed"));
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let body = read_capped_body(response).await?;
        let token: TokenResponse =
            serde_json::from_slice(&body).map_err(|err| oidc_error(&err.to_string()))?;
        let kid = token_header_kid(&token.id_token).map_err(generic)?;
        let jwks = self.oidc_jwks_for(&kid).await?;
        let claims = verify_id_token(
            &token.id_token,
            &jwks,
            &Expect {
                issuer: config.issuer.clone(),
                client_id: config.client_id.clone(),
                nonce: row.nonce.clone(),
                now: now(),
            },
        )
        .map_err(generic)?;
        Ok((claims, intent_user))
    }

    /// Whether the login page offers the SSO button (plan D6).
    pub fn oidc_enabled(&self) -> bool {
        let config = &self.config().oidc;
        config.enabled && !config.issuer.trim().is_empty() && !config.client_id.trim().is_empty()
    }

    /// The label for the SSO button on the login page.
    pub fn oidc_button_label(&self) -> String {
        let label = self.config().oidc.button_label.trim();
        if label.is_empty() {
            "Sign in with SSO".to_owned()
        } else {
            label.to_owned()
        }
    }

    /// Identities linked to the user, for `/settings/identities`.
    pub async fn linked_identities(&self, user_id: i64) -> CoreResult<Vec<LinkedIdentity>> {
        Ok(auth_factors::identities_for_user(self.db(), user_id)
            .await?
            .into_iter()
            .map(|row| LinkedIdentity {
                id: row.id,
                issuer: row.issuer,
                subject: row.subject,
            })
            .collect())
    }

    /// Links `(issuer, sub)` to `user_id` (a `link`-intent flow). Refused
    /// when the identity is already linked to a different account.
    /// Audited as `account.identity_linked`, once per link.
    pub async fn oidc_link(
        &self,
        claims: &Claims,
        user_id: i64,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<()> {
        let user_agent: String = user_agent.chars().take(256).collect();
        if let Some(existing) =
            auth_factors::identity_by_issuer_subject(self.db(), &claims.iss, &claims.sub).await?
        {
            if existing.user_id != user_id {
                return Err(CoreError::Invalid(
                    "This sign-in is already linked to another account.".into(),
                ));
            }
            return Ok(());
        }
        // Check-then-insert races the unique `(issuer, subject)`: a
        // concurrent loser re-reads the winner instead of failing with a 500.
        match auth_factors::insert_identity(self.db(), user_id, &claims.iss, &claims.sub).await {
            Ok(_) => {}
            Err(err) if err.is_unique_violation() => {
                return match auth_factors::identity_by_issuer_subject(
                    self.db(),
                    &claims.iss,
                    &claims.sub,
                )
                .await?
                {
                    Some(existing) if existing.user_id == user_id => Ok(()),
                    Some(_) => Err(CoreError::Invalid(
                        "This sign-in is already linked to another account.".into(),
                    )),
                    None => Err(err.into()),
                };
            }
            Err(err) => return Err(err.into()),
        }
        let target = match self.user_by_id(user_id).await? {
            Some(user) => format!("user:{}", user.handle),
            None => format!("user:{user_id}"),
        };
        self.audit_client(
            Some(user_id),
            "account.identity_linked",
            &target,
            &claims.iss,
            ip,
            &user_agent,
        )
        .await?;
        Ok(())
    }

    /// Removes one of the user's identity links. Refused when it would
    /// leave the account with no way to sign in (no password and no other
    /// identity). Audited as `account.identity_unlinked`.
    pub async fn unlink_identity(
        &self,
        user: &User,
        identity_id: i64,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<()> {
        let user_agent: String = user_agent.chars().take(256).collect();
        match auth_factors::delete_identity_unless_last(self.db(), identity_id, user.id).await? {
            Ok(()) => {}
            Err(auth_factors::UnlinkIdentityError::NotFound) => {
                return Err(CoreError::NotFound);
            }
            Err(auth_factors::UnlinkIdentityError::LastMeansOfLogin) => {
                return Err(CoreError::Invalid(
                    "This is the only way to sign in to this account; set a password or link another sign-in first."
                        .into(),
                ));
            }
        }
        self.audit_client(
            Some(user.id),
            "account.identity_unlinked",
            &format!("user:{}", user.handle),
            "",
            ip,
            &user_agent,
        )
        .await?;
        Ok(())
    }

    /// Resolves verified claims to a login (plan D5): a linked identity,
    /// else a verified-email match, else auto-create when allowed, else
    /// [`OidcLoginOutcome::NoAccount`]. Suspended users are refused. A
    /// user with TOTP enabled gets [`OidcLoginOutcome::NeedsSecondFactor`]
    /// (plan D2), exactly like password login.
    pub async fn oidc_login(
        &self,
        claims: &Claims,
        user_agent: &str,
        ip: &str,
    ) -> CoreResult<OidcLoginOutcome> {
        let user_agent: String = user_agent.chars().take(256).collect();
        let config = self.oidc_config()?.clone();
        let login_name = claims
            .email
            .as_deref()
            .map(|e| e.trim().to_ascii_lowercase())
            .unwrap_or_else(|| claims.sub.clone());
        self.check_login_limits(&login_name, ip, &user_agent)
            .await?;
        let user = match self.resolve_identity(claims, &config).await? {
            Some(user) => user,
            None => {
                self.audit_client(
                    None,
                    "login.failure",
                    &format!("login:{login_name}"),
                    "no account for this sign-in",
                    ip,
                    &user_agent,
                )
                .await?;
                return Ok(OidcLoginOutcome::NoAccount);
            }
        };
        if !user.active {
            self.audit_client(
                Some(user.id),
                "login.failure",
                &format!("user:{}", user.handle),
                "suspended",
                ip,
                &user_agent,
            )
            .await?;
            return Err(CoreError::Unauthenticated);
        }
        self.audit_client(
            Some(user.id),
            "login.oidc",
            &format!("user:{}", user.handle),
            &claims.iss,
            ip,
            &user_agent,
        )
        .await?;
        if self.totp_enabled(user.id).await? {
            let token = crypto::random_hex(32);
            auth_factors::insert_challenge(
                self.db(),
                "totp",
                Some(user.id),
                &crypto::sha256_hex(&token),
                now() + SECOND_FACTOR_TTL_SECS,
            )
            .await?;
            return Ok(OidcLoginOutcome::NeedsSecondFactor(token));
        }
        let session = self.open_session(&user, &user_agent, ip).await?;
        self.audit_client(
            Some(user.id),
            "auth.login",
            &format!("user:{}", user.handle),
            "",
            ip,
            &user_agent,
        )
        .await?;
        Ok(OidcLoginOutcome::Session(user, session))
    }

    /// Steps 1–3 of plan D5 identity resolution. `None` means no account.
    async fn resolve_identity(
        &self,
        claims: &Claims,
        config: &OidcConfig,
    ) -> CoreResult<Option<User>> {
        if let Some(row) =
            auth_factors::identity_by_issuer_subject(self.db(), &claims.iss, &claims.sub).await?
        {
            return self.user_by_id(row.user_id).await;
        }
        let email = claims
            .email
            .as_deref()
            .map(|e| e.trim().to_ascii_lowercase())
            .filter(|e| !e.is_empty());
        if config.link_by_email
            && claims.email_verified == Some(true)
            && let Some(email) = email.as_deref()
            && let Some(row) = users::by_email(self.db(), email).await?
        {
            let user = User::from(row);
            // Plan D5 step 2 requires exactly one local VERIFIED email:
            // an unverified local address never links (it falls through),
            // and a suspended account is resolved here so the login is
            // refused below — but no identity is inserted for either.
            if user.email_verified {
                if !user.active {
                    return Ok(Some(user));
                }
                // A concurrent login may have linked first; return its user.
                match auth_factors::insert_identity(self.db(), user.id, &claims.iss, &claims.sub)
                    .await
                {
                    Ok(_) => {}
                    Err(err) if err.is_unique_violation() => {
                        match auth_factors::identity_by_issuer_subject(
                            self.db(),
                            &claims.iss,
                            &claims.sub,
                        )
                        .await?
                        {
                            Some(row) if row.user_id == user.id => {
                                return self.user_by_id(row.user_id).await;
                            }
                            _ => return Err(err.into()),
                        }
                    }
                    Err(err) => return Err(err.into()),
                }
                self.audit(
                    Some(user.id),
                    "account.identity_linked",
                    &format!("user:{}", user.handle),
                    &claims.iss,
                )
                .await?;
                return Ok(Some(user));
            }
        }
        if config.auto_create && self.auto_create_allowed(email.as_deref()) {
            match self.auto_create_user(claims, email.as_deref()).await {
                Ok(user) => {
                    // Two concurrent first logins may both auto-create; the
                    // identity unique constraint picks the winner and the
                    // loser returns the winner's account.
                    match auth_factors::insert_identity(
                        self.db(),
                        user.id,
                        &claims.iss,
                        &claims.sub,
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(err) if err.is_unique_violation() => {
                            match auth_factors::identity_by_issuer_subject(
                                self.db(),
                                &claims.iss,
                                &claims.sub,
                            )
                            .await?
                            {
                                Some(row) => return self.user_by_id(row.user_id).await,
                                None => return Err(err.into()),
                            }
                        }
                        Err(err) => return Err(err.into()),
                    }
                    self.audit(
                        Some(user.id),
                        "account.identity_linked",
                        &format!("user:{}", user.handle),
                        &claims.iss,
                    )
                    .await?;
                    return Ok(Some(user));
                }
                // The handle or email is already taken (e.g. the email
                // belongs to an unverified local account that could not
                // link): the generic no-account outcome, never a 400
                // naming the collision.
                Err(CoreError::Conflict(_)) => return Ok(None),
                Err(other) => return Err(other),
            }
        }
        Ok(None)
    }

    /// Whether auto-create may create an account for `email` under the
    /// current registration mode (plan D5 step 3).
    fn auto_create_allowed(&self, email: Option<&str>) -> bool {
        let registration = self.registration();
        match registration.mode {
            RegistrationMode::Sso | RegistrationMode::Open => true,
            RegistrationMode::Domains => match email {
                Some(email) => {
                    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                    registration.allowed_domains.iter().any(|d| d == domain)
                }
                None => false,
            },
            RegistrationMode::Invite => false,
        }
    }

    /// Creates an SSO-only account: a sanitized, deduplicated handle, the
    /// provider's email marked verified when the provider verified it,
    /// and no password.
    async fn auto_create_user(&self, claims: &Claims, email: Option<&str>) -> CoreResult<User> {
        let base = claims
            .preferred_username
            .as_deref()
            .map(sanitize_handle)
            .filter(|h| !h.is_empty())
            .or_else(|| {
                email
                    .and_then(|e| e.split_once('@').map(|(local, _)| sanitize_handle(local)))
                    .filter(|h| !h.is_empty())
            })
            .unwrap_or_else(|| "user".to_owned());
        let mut handle = base.clone();
        let mut n = 2_i64;
        while self.user_by_handle(&handle).await?.is_some() {
            let suffix = format!("-{n}");
            let stem: String = base
                .chars()
                .take(39usize.saturating_sub(suffix.len()))
                .collect();
            handle = format!("{stem}{suffix}");
            n += 1;
        }
        let display_name = claims
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .unwrap_or(&handle)
            .to_owned();
        let user = self
            .create_user(CreateUser {
                handle,
                display_name,
                email: email.map(str::to_owned),
                email_verified: claims.email_verified == Some(true),
                password: None,
                is_admin: false,
            })
            .await?;
        self.audit(
            Some(user.id),
            "account.sign_up",
            &format!("user:{}", user.handle),
            "oidc:auto_create",
        )
        .await?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair,
    };

    const ISSUER: &str = "https://idp.example.com";
    const CLIENT_ID: &str = "starforge-test";
    const NONCE: &str = "test-nonce";

    struct EsKey {
        pair: EcdsaKeyPair,
        jwk: Jwk,
    }
    fn es_key() -> EsKey {
        let rng = ring::rand::SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .unwrap();
        let public = pair.public_key().as_ref();
        EsKey {
            jwk: Jwk {
                kty: "EC".into(),
                kid: "es-test".into(),
                alg: Some("ES256".into()),
                crv: Some("P-256".into()),
                n: None,
                e: None,
                x: Some(b64url_encode(&public[1..33])),
                y: Some(b64url_encode(&public[33..65])),
            },
            pair,
        }
    }

    struct RsKey {
        pair: RsaKeyPair,
        jwk: Jwk,
    }

    fn rs_key() -> RsKey {
        let der = include_bytes!("../../starforged/tests/fixtures/oidc_rsa_test_key.pk8");
        let pair = RsaKeyPair::from_pkcs8(der).unwrap();
        let (n, e) = rsa_components(&pair);
        RsKey {
            jwk: Jwk {
                kty: "RSA".into(),
                kid: "rs-test".into(),
                alg: Some("RS256".into()),
                crv: None,
                n: Some(b64url_encode(&n)),
                e: Some(b64url_encode(&e)),
                x: None,
                y: None,
            },
            pair,
        }
    }

    /// `n` and `e` (big-endian, no leading zeros) for the JWK.
    fn rsa_components(pair: &RsaKeyPair) -> (Vec<u8>, Vec<u8>) {
        let components: ring::rsa::PublicKeyComponents<Vec<u8>> = pair.public().into();
        (components.n, components.e)
    }
    fn claims_json(now: i64) -> serde_json::Value {
        serde_json::json!({
            "sub": "user-123",
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": now + 600,
            "iat": now,
            "nonce": NONCE,
            "email": "user@example.com",
            "email_verified": true,
            "preferred_username": "user",
        })
    }

    fn expect(now: i64) -> Expect {
        Expect {
            issuer: ISSUER.into(),
            client_id: CLIENT_ID.into(),
            nonce: Some(NONCE.into()),
            now,
        }
    }

    fn sign_es256(key: &EsKey, header: serde_json::Value, claims: serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            b64url_encode(serde_json::to_vec(&header).unwrap().as_slice()),
            b64url_encode(serde_json::to_vec(&claims).unwrap().as_slice())
        );
        // `ECDSA_P256_SHA256_FIXED_SIGNING` already returns raw `r‖s`.
        let signature = key
            .pair
            .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64url_encode(signature.as_ref()))
    }

    fn sign_rs256(key: &RsKey, header: serde_json::Value, claims: serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            b64url_encode(serde_json::to_vec(&header).unwrap().as_slice()),
            b64url_encode(serde_json::to_vec(&claims).unwrap().as_slice())
        );
        let mut signature = vec![0_u8; key.pair.public().modulus_len()];
        key.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .unwrap();
        format!("{input}.{}", b64url_encode(&signature))
    }

    fn es_token(
        key: &EsKey,
        mutate: impl FnOnce(&mut serde_json::Value, &mut serde_json::Value),
    ) -> String {
        let mut header = serde_json::json!({"alg": "ES256", "kid": "es-test", "typ": "JWT"});
        let mut claims = claims_json(1000);
        mutate(&mut header, &mut claims);
        sign_es256(key, header, claims)
    }

    #[test]
    fn valid_es256_token_passes() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let token = es_token(&key, |_, _| {});
        let claims = verify_id_token(&token, &jwks, &expect(1000)).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn valid_rs256_token_passes() {
        let key = rs_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let header = serde_json::json!({"alg": "RS256", "kid": "rs-test", "typ": "JWT"});
        let token = sign_rs256(&key, header, claims_json(1000));
        let claims = verify_id_token(&token, &jwks, &expect(1000)).unwrap();
        assert_eq!(claims.sub, "user-123");
    }

    #[test]
    fn alg_none_and_hs256_refused() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let none = es_token(&key, |header, _| {
            header["alg"] = serde_json::json!("none");
        });
        assert_eq!(
            verify_id_token(&none, &jwks, &expect(1000)),
            Err(VerifyError::UnsupportedAlg)
        );
        let hs = es_token(&key, |header, _| {
            header["alg"] = serde_json::json!("HS256");
        });
        assert_eq!(
            verify_id_token(&hs, &jwks, &expect(1000)),
            Err(VerifyError::UnsupportedAlg)
        );
    }

    #[test]
    fn unknown_kid_and_bad_signature_refused() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let unknown = es_token(&key, |header, _| {
            header["kid"] = serde_json::json!("other-key");
        });
        assert_eq!(
            verify_id_token(&unknown, &jwks, &expect(1000)),
            Err(VerifyError::UnknownKid)
        );
        // A token signed by a different key under the same kid.
        let other = es_key();
        let forged = sign_es256(
            &other,
            serde_json::json!({"alg": "ES256", "kid": "es-test"}),
            claims_json(1000),
        );
        assert_eq!(
            verify_id_token(&forged, &jwks, &expect(1000)),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn wrong_iss_aud_azp_refused() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let wrong_iss = es_token(&key, |_, claims| {
            claims["iss"] = serde_json::json!("https://evil.example.com");
        });
        assert_eq!(
            verify_id_token(&wrong_iss, &jwks, &expect(1000)),
            Err(VerifyError::WrongIssuer)
        );
        let wrong_aud = es_token(&key, |_, claims| {
            claims["aud"] = serde_json::json!("someone-else");
        });
        assert_eq!(
            verify_id_token(&wrong_aud, &jwks, &expect(1000)),
            Err(VerifyError::WrongAudience)
        );
        // Multiple audiences with the client id present pass azp == client id …
        let multi = es_token(&key, |_, claims| {
            claims["aud"] = serde_json::json!([CLIENT_ID, "other"]);
            claims["azp"] = serde_json::json!(CLIENT_ID);
        });
        assert!(verify_id_token(&multi, &jwks, &expect(1000)).is_ok());
        // … but a different azp fails.
        let wrong_azp = es_token(&key, |_, claims| {
            claims["aud"] = serde_json::json!([CLIENT_ID, "other"]);
            claims["azp"] = serde_json::json!("someone-else");
        });
        assert_eq!(
            verify_id_token(&wrong_azp, &jwks, &expect(1000)),
            Err(VerifyError::WrongAzp)
        );
    }

    #[test]
    fn expired_and_future_iat_refused_within_leeway() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let expired = es_token(&key, |_, claims| {
            claims["exp"] = serde_json::json!(900);
        });
        assert_eq!(
            verify_id_token(&expired, &jwks, &expect(1000)),
            Err(VerifyError::Expired)
        );
        // Inside the 60 s leeway the token still passes …
        let leeway = es_token(&key, |_, claims| {
            claims["exp"] = serde_json::json!(950);
        });
        assert!(verify_id_token(&leeway, &jwks, &expect(1000)).is_ok());
        // … but an `iat` beyond the leeway in the future fails.
        let future = es_token(&key, |_, claims| {
            claims["iat"] = serde_json::json!(1200);
        });
        assert_eq!(
            verify_id_token(&future, &jwks, &expect(1000)),
            Err(VerifyError::NotYetValid)
        );
    }

    #[test]
    fn nonce_mismatch_refused() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let token = es_token(&key, |_, claims| {
            claims["nonce"] = serde_json::json!("another-nonce");
        });
        assert_eq!(
            verify_id_token(&token, &jwks, &expect(1000)),
            Err(VerifyError::NonceMismatch)
        );
    }

    #[test]
    fn malformed_tokens_refused() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        for bad in ["", "one-part", "two.parts", "a.b.c.d", "!!!.@@@.###"] {
            assert_eq!(
                verify_id_token(bad, &jwks, &expect(1000)),
                Err(VerifyError::Malformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn pkce_matches_the_rfc7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn jwks_parse_round_trip() {
        let key = es_key();
        let text = serde_json::json!({"keys": [key.jwk]}).to_string();
        let jwks = Jwks::parse(&text).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, "es-test");
        assert!(Jwks::parse("{}").is_err());
        assert!(Jwks::parse("not json").is_err());
    }

    #[test]
    fn oidc_config_debug_hides_the_secret() {
        let config = OidcConfig {
            client_secret: "hunter2secret".into(),
            ..OidcConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("hunter2secret"), "{rendered}");
    }

    #[test]
    fn url_policy_allows_https_and_loopback_http_only() {
        assert!(url_allowed("https://idp.example.com/"));
        assert!(url_allowed("http://127.0.0.1:8080/"));
        assert!(url_allowed("http://localhost:8080/"));
        assert!(url_allowed("http://[::1]:8080/"));
        assert!(!url_allowed("http://idp.example.com/"));
        assert!(!url_allowed("ftp://idp.example.com/"));
        assert!(!url_allowed("not a url"));
    }

    #[test]
    fn future_nbf_refused_within_leeway() {
        let key = es_key();
        let jwks = Jwks::from_vec(vec![key.jwk.clone()]);
        let future = es_token(&key, |_, claims| {
            claims["nbf"] = serde_json::json!(1200);
        });
        assert_eq!(
            verify_id_token(&future, &jwks, &expect(1000)),
            Err(VerifyError::NotYetValid)
        );
        let leeway = es_token(&key, |_, claims| {
            claims["nbf"] = serde_json::json!(1050);
        });
        assert!(verify_id_token(&leeway, &jwks, &expect(1000)).is_ok());
    }

    #[test]
    fn sanitize_handle_shapes_text() {
        assert_eq!(sanitize_handle("Fake User!"), "fake-user");
        assert_eq!(sanitize_handle("--Foo__Bar--"), "foo-bar");
        assert_eq!(sanitize_handle("user@example.com"), "user-example-com");
        assert_eq!(sanitize_handle("!!!"), "");
        assert_eq!(sanitize_handle(""), "");
    }
}
