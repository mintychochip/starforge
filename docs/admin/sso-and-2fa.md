# SSO and 2FA

With an `[oidc]` section enabled, the sign-in page offers a single sign-on button that runs the authorization-code flow with PKCE against any compliant provider:

```toml
[oidc]
enabled = true
issuer = "https://idp.example.com"
client_id = "<client id from the provider>"
client_secret = "<client secret>"
auto_create = false
link_by_email = true
```

Every key also works as `STARFORGE__OIDC__*`. The redirect URI is `<server.base_url>/login/oidc/callback`. Only RS256 or ES256 ID tokens are accepted; signature, issuer, audience, expiry, and nonce are all checked, and any failure shows one generic message. Provider discovery and keys are cached (discovery for an hour; keys by `kid`).

**Linking rules.** On sign-in Starforge resolves: (1) an already linked (issuer, subject) signs straight in (a suspended user is refused); (2) otherwise, when `link_by_email` is on and the provider reports `email_verified`, an exact match against exactly one locally **verified** email links the identity (`account.identity_linked`) — an unverified email on either side never links; (3) otherwise, when `auto_create` is on and the registration mode allows it, a password-less account is created with a sanitized, deduplicated handle; (4) otherwise the page says "No account for this sign-in".

**Settings.** **Settings → Linked sign-ins** (`/settings/identities`) links and unlinks provider identities. Unlinking is refused when it is the account's last way to sign in (no password and no other identity).

**SSO-only mode.** `registration.mode = "sso"` disables sign-up; new accounts come only from `auto_create`. Password login stays available for accounts that have a password, including the bootstrap admin.

Any account can turn on TOTP two-factor authentication under **Settings → Two-factor** (`/settings/two-factor`):

1. **Enroll.** The page shows an `otpauth://` URI (issuer `Starforge`, one 20-byte secret, 6 digits, 30 s step) and the base32 secret. The secret is stored sealed with the server key, never in clear, and is never logged.
2. **Confirm** with a current code. Only then is 2FA enabled, and 10 recovery codes (`xxxxx-xxxxx`) are shown **once** — save them. Signing in then asks for the password and a current code (or one recovery code) at `/login/two-factor`; no web session exists before the second factor.
3. A code is accepted within one step either way, and a step is never reused. Each recovery code is shown once, five failed codes void the challenge and sign-in starts again, and challenges expire after five minutes. All of these write audit rows (`account.2fa_enabled`, `account.2fa_disabled`, `account.recovery_codes_regenerated`, `login.2fa_failure`).
4. Disable needs the password plus a code — for a password-less SSO-only account the password is waived but a current code is still required; regenerate needs a code and invalidates the old ones.

Personal access tokens and OAuth device tokens are not affected by 2FA. A site admin can disable a user's 2FA from the admin user page (`/admin/users/{handle}`, audited as `user.2fa_reset`).
