# Starforge M3d (TOTP two-factor and OIDC single sign-on) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The remaining §9 authentication.
- Optional TOTP two-factor authentication with recovery codes.
- OIDC single sign-on with any compliant provider: authorization code flow with PKCE, optional automatic account creation, and account linking by verified email.
- The fourth registration mode, `sso` (SSO-only).
- The §10.1 user settings page for two-factor authentication and linked identities.

**Architecture:** No new crates and no new third-party dependencies.
- **TOTP:** RFC 6238 (HMAC-SHA1, 6 digits, 30 s step) built on `ring::hmac` (`HMAC_SHA1_FOR_LEGACY_USE_ONLY`), with base32 encoding hand-written.
- **OIDC client:**
  - discovery and the token exchange use `reqwest`;
  - ID tokens are verified with `ring::signature` (RS256 via `RsaPublicKeyComponents`, ES256 via `ECDSA_P256_SHA256_FIXED`);
  - JWKS is parsed with `serde`.
- **`starforged-db`** gains `0025_auth_factors.sql`: TOTP columns on `users`, `recovery_codes`, `user_identities`, and `login_challenges`.
- **`starforged-core`** gains `totp.rs`, `oidc.rs` (pure verification module plus flow state), and login-flow changes in `sessions.rs`.
- **`starforged-web`** gains the second login step, the OIDC login and callback routes, `/settings/two-factor`, `/settings/identities`, and a site-admin 2FA reset.

**Tech Stack:** as M3a. Tests run a fake OIDC provider (axum) in-process that signs ES256 ID tokens with a `ring` P-256 key, plus an RS256 variant using a fixed RSA test key in PKCS#8 committed under `tests/fixtures/`. The RSA key is generated once with `openssl` during implementation; it is a test-only key.

**Spec:** §9 (local accounts, TOTP with recovery codes, OIDC, registration modes, web sessions), §6.1 (users: TOTP secret optional; password hash absent for SSO-only accounts), §6.5 (audit: logins, 2FA changes), §10.1 (settings: two-factor).

**Deferred (not built here):**
- WebAuthn and passkeys (non-goal);
- multiple OIDC providers (one configured provider);
- SCIM;
- OIDC logout propagation;
- login rate limits (M5 §11.6). This milestone has only the per-challenge attempt cap in D2.

## Global Constraints

- **No new third-party dependencies.** Crypto comes only from `ring`: HMAC-SHA1 for TOTP, SHA-256 for PKCE, recovery-code hashing, and RS256/ES256 verification. `getrandom` supplies randomness.
- **Secrets at rest:** TOTP secrets are AEAD-sealed with the existing server-key seal helper, never stored in clear and never logged. Recovery codes are stored as SHA-256 hashes. The OIDC client secret lives only in config.
- **Constant-time comparisons** (`subtle` or `ring::constant_time`) for codes and hashes.
- **ID token verification is complete** and in one pure, unit-tested function:
  - `alg` ∈ {RS256, ES256} (never `none` or HS*);
  - `kid` match;
  - signature;
  - `iss` equals the configured issuer exactly;
  - `aud` contains `client_id`, and `azp` equals `client_id` when present with multiple audiences;
  - `exp` and `iat` within 60 s leeway;
  - `nonce` equals the stored nonce.
  Any failure means login fails with a generic message; the specific reason goes to the debug log.
- **Flow state:** OIDC `state`, `nonce`, and the PKCE verifier live server-side in `login_challenges` (single use, 10-minute expiry). The browser carries only a random challenge id in an `HttpOnly`, `SameSite=Lax` cookie. Callback state is matched in constant time.
- **Audit (§6.5):**
  - `login.success`, `login.failure`, `login.2fa_failure`, and `login.oidc`, where the existing login audit kinds stay as they are and new ones are added only where missing;
  - `account.2fa_enabled`, `account.2fa_disabled`, `account.recovery_codes_regenerated`;
  - `account.identity_linked`, `account.identity_unlinked`;
  - `user.2fa_reset` (site admin).
  Each is written once per event.
- **Tokens:** PATs and OAuth device tokens are unaffected by 2FA (they are created from an already-2FA-authenticated web session).
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. TOTP parameters.**
  - 20-byte secrets; base32 without padding; `otpauth://totp/<issuer>:<handle>?secret=…&issuer=<issuer>&algorithm=SHA1&digits=6&period=30`, with issuer = the configured site name, or `Starforge`.
  - Accepted window ±1 step. A used step is recorded (`totp_last_step`), and replay of the same or an older step is refused.
  - Enrollment: the user scans the URI or enters the secret, then confirms with a valid code. Only then is 2FA enabled and 10 recovery codes issued (format `xxxxx-xxxxx` over base32, shown once).
  - Disabling requires the password (or, for SSO-only accounts, a current TOTP code) plus a code.
  - Regenerating recovery codes requires a code and invalidates the old ones.
- **D2. Login with 2FA.**
  - Password login (or OIDC login, D5) for a user with TOTP enabled creates a `login_challenges` row (kind `totp`, user id, expiry 5 min, attempts 0) and redirects to `/login/two-factor`. No web session exists yet.
  - A correct TOTP or unused recovery code completes the login: the web session is created, a used recovery code is consumed, and `login.success` is written.
  - Five failed attempts delete the challenge and the user must start again; each failure writes `login.2fa_failure`.
- **D3. Admin reset.** Site admins disable a user's 2FA from the admin user page (CSRF): the secret and recovery codes are deleted and `user.2fa_reset` is audited. Users cannot reset another user.
- **D4. OIDC config.**
  - `[oidc]` section:
    - `enabled`;
    - `issuer` (https, or http only for loopback);
    - `client_id` and `client_secret`;
    - `scopes` (default `["openid", "email", "profile"]`);
    - `button_label` (default "Sign in with SSO");
    - `auto_create` (default false);
    - `link_by_email` (default true).
  - All are overridable by `STARFORGE__OIDC__*`.
  - Discovery is fetched on first use and cached for 1 hour. JWKS is cached by `kid` and refreshed once on an unknown `kid`.
  - The token endpoint uses `client_secret_basic`, falling back to `client_secret_post` when discovery lists only that.
  - The redirect URI is `<base_url>/login/oidc/callback`.
- **D5. OIDC login.**
  - `GET /login/oidc` creates a challenge (state, nonce, PKCE S256 verifier) and redirects to the authorization endpoint.
  - `GET /login/oidc/callback?code&state` verifies state, exchanges the code, verifies the ID token (Global Constraints), and resolves the identity `(issuer, sub)`:
    1. linked → that user (refused when suspended);
    2. else, when `link_by_email` and `email_verified == true` and the email matches exactly one local VERIFIED email → link and log in (`account.identity_linked`);
    3. else, when `auto_create` (and registration allows SSO creation: mode `sso` or `open`, or the email domain is allowed in `domains` mode) → create the user (handle from `preferred_username`, else the email local part, sanitized to handle rules, with `-2`, `-3`… on clash), mark the email verified when `email_verified`, give no password, link, and log in;
    4. else → a generic "no account for this sign-in" page.
  - After resolution, a user with TOTP enabled goes through D2.
- **D6. Linked identities and SSO-only mode.**
  - `/settings/identities` lists linked identities, links the current account to the provider (a flow with `link` intent), and unlinks.
  - Unlinking is refused when it would leave the account with no way to sign in (no password and no other identity).
  - Registration mode `sso`: the sign-up and invite-acceptance forms are disabled; new accounts come only from D5 auto-create. Password login stays available to accounts that have a password, including the bootstrap admin.
  - The login page shows the SSO button whenever OIDC is enabled.

## File Structure

```
crates/starforged-db/migrations/{sqlite,postgres}/0025_auth_factors.sql
crates/starforged-db/src/{users.rs,auth_factors.rs (new)}
crates/starforged-core/src/{totp.rs (new),oidc.rs (new),sessions.rs,registration.rs,admin.rs}
crates/starforged/src/config.rs                 [oidc], registration mode sso
crates/starforged-web/src/{auth.rs,pages/login.rs,pages/settings_2fa.rs (new),pages/identities.rs (new),pages/admin.rs}, templates
crates/starforged/tests/{two_factor.rs,oidc_login.rs,auth_security.rs}, tests/common/fake_oidc.rs, tests/fixtures/oidc_rsa_test_key.pk8
README.md
```

---

### Task D1: TOTP two-factor authentication

**Files:**
- Create:
  - the 0025 migrations (all four tables/columns; D3 and D5 use them later);
  - `crates/starforged-core/src/totp.rs`;
  - `crates/starforged-db/src/auth_factors.rs`;
  - `crates/starforged-web/src/pages/settings_2fa.rs` and its templates;
  - `crates/starforged/tests/two_factor.rs`.
- Modify:
  - `crates/starforged-core/src/{sessions.rs,admin.rs,lib.rs}`;
  - `crates/starforged-web/src/{lib.rs,auth.rs,pages/login.rs,pages/admin.rs}` and the login templates.

**Interfaces:**
- `totp::code_at(secret, unix_step) -> u32`, `totp::verify(...)`, `base32::encode/decode` (pure, with RFC 6238 test vectors);
- `Core::begin_totp_enrollment`, `confirm_totp_enrollment`, `disable_totp`, `regenerate_recovery_codes`;
- `Core::login` returning `LoginOutcome::{Session(..), NeedsSecondFactor(challenge_id)}`;
- `Core::complete_second_factor(challenge_id, code)`;
- `Core::admin_reset_2fa`.

- [ ] **Step 1: Write the failing tests.**
  - **RFC 6238 vectors:** the SHA-1 rows at T=59, 1111111109, …, truncated to 6 digits.
  - **Base32** round-trips.
  - **Enrollment:** enroll, then confirm with the code at the current step; recovery codes are shown once.
  - **Login:**
    - password login now requires the second step;
    - the right code logs in;
    - replay of the same step is refused;
    - a recovery code works exactly once;
    - five failures void the challenge;
    - an expired challenge is refused.
  - **Disable and regenerate:** disabling needs password + code; regeneration invalidates the old codes.
  - **Admin reset:** works for site admins; others get 404 or 403 (match admin pages).
  - **Audit and storage:** audit rows; the secret is never stored in clear (the db row is sealed).
  - **CSRF and XSS:** CSRF on every form; nothing user-controlled renders unescaped.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core totp` and `cargo test -p starforged --test two_factor`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus `--test web_login` (or the existing login test file) and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add TOTP two-factor authentication`.

---

### Task D2: OIDC verification core

**Files:**
- Create:
  - `crates/starforged-core/src/oidc.rs`;
  - `crates/starforged/tests/common/fake_oidc.rs`;
  - `crates/starforged/tests/fixtures/oidc_rsa_test_key.pk8`.
- Modify:
  - `crates/starforged/src/config.rs` (`[oidc]`);
  - `crates/starforged-core/src/lib.rs`.

**Interfaces:**
- `oidc::verify_id_token(token: &str, jwks: &Jwks, expect: &Expect { issuer, client_id, nonce, now }) -> Result<Claims, VerifyError>` (pure);
- `Jwks::parse`;
- `pkce_challenge(verifier)`;
- `Core::oidc_discovery()` (cached);
- `Core::oidc_begin(intent) -> (challenge_id, redirect_url)`;
- `Core::oidc_finish(challenge_id, code, state) -> CoreResult<Claims>`.

- [ ] **Step 1: Write the failing tests.**
  - **Pure verification:** RS256 and ES256 valid tokens pass. Each of these is refused:
    - `alg=none`, `alg=HS256`;
    - unknown `kid`, bad signature;
    - wrong `iss`, wrong `aud`, wrong `azp`;
    - expired, `iat` in the future beyond leeway;
    - nonce mismatch;
    - a malformed JWT.
  - **PKCE:** the S256 challenge matches the RFC 7636 example.
  - **Flow against the fake provider:**
    - begin produces a URL with state, nonce, and `code_challenge`;
    - finish exchanges the code and returns the claims;
    - a reused challenge is refused;
    - a state mismatch is refused.
  - **Config validation:** `enabled` without issuer or client fails startup.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core oidc` and `cargo test -p starforged --test oidc_login`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add OIDC token verification and the code flow core`.

---

### Task D3: OIDC login, linking, auto-create, and SSO-only registration

**Files:**
- Create: `crates/starforged-web/src/pages/identities.rs` and its templates.
- Modify:
  - `crates/starforged-core/src/{oidc.rs,sessions.rs,registration.rs}`;
  - `crates/starforged-web/src/{lib.rs,pages/login.rs}` and the login template;
  - `crates/starforged/src/config.rs` (mode `sso`);
  - `crates/starforged/tests/oidc_login.rs`.

**Interfaces:** D5 and D6.

- [ ] **Step 1: Write the failing tests** against the fake provider through the browser helper:
  - **Resolution:**
    - first login links by verified email to an existing user;
    - an unverified email does not link ("no account");
    - `auto_create` creates a user with a sanitized, deduplicated handle, verified email, and no password;
    - an already-linked identity logs straight in;
    - a suspended linked user is refused;
    - TOTP-enabled users must pass the second step after OIDC.
  - **Settings:** link from settings, then unlink; the last-means-of-login unlink is refused.
  - **SSO-only mode:**
    - sign-up and invite acceptance are refused;
    - password login for the bootstrap admin works;
    - auto-create works.
  - **Audit and CSRF:** audit rows for links, unlinks, and OIDC logins; CSRF on settings forms.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test oidc_login`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test two_factor` and the registration tests, plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add OIDC sign-in, account linking, and SSO-only registration`.

---

### Task D4: Authentication sweep and docs

**Files:**
- Create: `crates/starforged/tests/auth_security.rs`.
- Modify: `README.md`.

- [ ] **Step 1: Write the sweep.**
  - **Challenge isolation:**
    - a challenge cannot be completed by another browser (cookie-bound);
    - a challenge id from user A cannot finish user B's login;
    - no session cookie is set before the second factor.
  - **Open redirect:** OIDC callback errors never reflect provider strings unescaped; the open-redirect check covers the `next` parameters that login accepts.
  - **Tokens:** PAT and device-flow API access still work for 2FA users; the device-flow approval page requires a fully authenticated session.
  - **Revocation:** session list and revoke still work.
  - **Session cookies:** cookie flags on the new cookies (Secure when https, HttpOnly, SameSite=Lax).
- [ ] **Step 2: Run the sweep** 3 times; all green. Fix defects found and report them.
- [ ] **Step 3: README:** "Two-factor authentication" and "Single sign-on (OIDC)" sections (config keys with an example for a generic provider, linking rules, auto-create, SSO-only mode, admin reset). Check examples against the code.
- [ ] **Step 4: Commit** (PG gate first): `Add authentication sweep and docs`.
