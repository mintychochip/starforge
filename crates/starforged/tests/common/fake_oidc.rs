//! A fake OIDC provider for integration tests (M3d D2): discovery, JWKS,
//! the authorize redirect, and the token endpoint behind axum, on a
//! loopback port. ES256 is signed with a `ring` P-256 key generated at
//! start; RS256 with the fixed test key at
//! `tests/fixtures/oidc_rsa_test_key.pk8` (test-only).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use base64::Engine as _;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair,
};

pub const CLIENT_ID: &str = "starforge-test-client";
pub const CLIENT_SECRET: &str = "test-client-secret";
pub const SUBJECT: &str = "fake-user-sub";

enum Signer {
    Es(EcdsaKeyPair),
    Rs(RsaKeyPair),
}

struct Pending {
    nonce: String,
    code_challenge: String,
}

struct Inner {
    signer: Signer,
    kid: String,
    /// Extra claims merged into every issued ID token (tests override the
    /// nonce-sensitive ones by finishing a fresh flow).
    extra_claims: Mutex<serde_json::Value>,
    pending: Mutex<HashMap<String, Pending>>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Inner>,
    issuer: String,
}

/// The running fake provider. `issuer` is the loopback base URL.
pub struct FakeOidc {
    pub issuer: String,
    inner: Arc<Inner>,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn random_code() -> String {
    let mut buf = [0_u8; 32];
    getrandom::fill(&mut buf).unwrap();
    b64url(&buf)
}

/// The JWK for `signer`: ES256 from the uncompressed point, RS256 from the
/// `n`/`e` inside the SubjectPublicKeyInfo.
fn jwk(signer: &Signer, kid: &str) -> serde_json::Value {
    match signer {
        Signer::Es(pair) => {
            let public = pair.public_key().as_ref();
            serde_json::json!({
                "kty": "EC", "kid": kid, "alg": "ES256", "crv": "P-256",
                "x": b64url(&public[1..33]), "y": b64url(&public[33..65]),
            })
        }
        Signer::Rs(pair) => {
            let (n, e) = rsa_components(pair);
            serde_json::json!({
                "kty": "RSA", "kid": kid, "alg": "RS256",
                "n": b64url(&n), "e": b64url(&e),
            })
        }
    }
}

/// `n` and `e` (big-endian, no leading zeros) for the JWK.
fn rsa_components(pair: &RsaKeyPair) -> (Vec<u8>, Vec<u8>) {
    let components: ring::rsa::PublicKeyComponents<Vec<u8>> = pair.public().into();
    (components.n, components.e)
}

impl FakeOidc {
    /// An ES256 provider with a fresh P-256 key.
    pub async fn start_es256() -> FakeOidc {
        let rng = ring::rand::SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .unwrap();
        Self::start(Signer::Es(pair), "fake-es256").await
    }

    /// An RS256 provider with the fixed test key.
    pub async fn start_rs256() -> FakeOidc {
        let der = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/oidc_rsa_test_key.pk8"),
        )
        .unwrap();
        let pair = RsaKeyPair::from_pkcs8(&der).unwrap();
        Self::start(Signer::Rs(pair), "fake-rs256").await
    }

    async fn start(signer: Signer, kid: &str) -> FakeOidc {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let inner = Arc::new(Inner {
            signer,
            kid: kid.into(),
            extra_claims: Mutex::new(serde_json::json!({})),
            pending: Mutex::new(HashMap::new()),
        });
        let state = AppState {
            inner: inner.clone(),
            issuer: issuer.clone(),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeOidc { issuer, inner }
    }

    /// Extra claims (e.g. `email`) merged into every issued ID token.
    pub fn set_claims(&self, extra: serde_json::Value) {
        *self.inner.extra_claims.lock().unwrap() = extra;
    }

    /// Signs `claims` as a JWS under the provider key (for unit-style
    /// tokens the flow tests do not need, e.g. a forged signature).
    pub fn sign(&self, claims: serde_json::Value) -> String {
        sign(&self.inner, claims)
    }

    /// The default claims for a token issued by the token endpoint.
    fn issue(&self, nonce: &str) -> String {
        issue_token(&self.inner, &self.issuer, nonce)
    }
}

fn sign(inner: &Inner, claims: serde_json::Value) -> String {
    let alg = match &inner.signer {
        Signer::Es(_) => "ES256",
        Signer::Rs(_) => "RS256",
    };
    let header = serde_json::json!({"alg": alg, "kid": inner.kid, "typ": "JWT"});
    let input = format!(
        "{}.{}",
        b64url(serde_json::to_vec(&header).unwrap().as_slice()),
        b64url(serde_json::to_vec(&claims).unwrap().as_slice())
    );
    let signature = match &inner.signer {
        Signer::Es(pair) => pair
            .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec(),
        Signer::Rs(pair) => {
            let mut signature = vec![0_u8; pair.public().modulus_len()];
            pair.sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .unwrap();
            signature
        }
    };
    format!("{input}.{}", b64url(&signature))
}

fn issue_token(inner: &Inner, issuer: &str, nonce: &str) -> String {
    let now = now_secs();
    let mut claims = serde_json::json!({
        "sub": SUBJECT,
        "iss": issuer,
        "aud": CLIENT_ID,
        "exp": now + 600,
        "iat": now,
        "nonce": nonce,
        "email": "fake-user@example.com",
        "email_verified": true,
        "preferred_username": "fake-user",
    });
    let extra = inner.extra_claims.lock().unwrap().clone();
    if let Some(map) = claims.as_object_mut() {
        for (key, value) in extra.as_object().cloned().unwrap_or_default() {
            map.insert(key, value);
        }
    }
    sign(inner, claims)
}

async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }))
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(serde_json::json!({"keys": [jwk(&state.inner.signer, &state.inner.kid)]}))
}

#[derive(serde::Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
}

async fn authorize(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AuthorizeQuery>,
) -> impl IntoResponse {
    if query.client_id != CLIENT_ID || query.code_challenge_method != "S256" {
        return (StatusCode::BAD_REQUEST, "bad authorize request").into_response();
    }
    let code = random_code();
    state.inner.pending.lock().unwrap().insert(
        code.clone(),
        Pending {
            nonce: query.nonce.clone(),
            code_challenge: query.code_challenge.clone(),
        },
    );
    let mut url = url::Url::parse(&query.redirect_uri).unwrap();
    url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &query.state);
    Redirect::to(url.as_str()).into_response()
}

#[derive(serde::Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

fn pkce_challenge(verifier: &str) -> String {
    use sha2::Digest as _;
    b64url(&sha2::Sha256::digest(verifier.as_bytes()))
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<TokenForm>,
) -> impl IntoResponse {
    let bad = || (StatusCode::BAD_REQUEST, "bad token request").into_response();
    if form.grant_type != "authorization_code" {
        return bad();
    }
    // `client_secret_basic` (preferred) or `client_secret_post`.
    let basic_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .is_some_and(|credentials| credentials == format!("{CLIENT_ID}:{CLIENT_SECRET}"));
    let post_ok = form.client_id.as_deref() == Some(CLIENT_ID)
        && form.client_secret.as_deref() == Some(CLIENT_SECRET);
    if !basic_ok && !post_ok {
        return bad();
    }
    let Some(pending) = state.inner.pending.lock().unwrap().remove(&form.code) else {
        return bad();
    };
    if pkce_challenge(&form.code_verifier) != pending.code_challenge {
        return bad();
    }
    let id_token = issue_token(&state.inner, &state.issuer, &pending.nonce);
    axum::Json(serde_json::json!({
        "access_token": "fake-access-token",
        "token_type": "Bearer",
        "expires_in": 600,
        "id_token": id_token,
    }))
    .into_response()
}
