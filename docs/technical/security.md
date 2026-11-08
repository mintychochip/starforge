# Security

## Purpose

> **Note:** This page describes trust boundaries and security controls.
> For setup procedures, read the administration guide in `docs/admin`.

This page describes the trust boundaries Starforge enforces.
It describes authentication, authorization, web defenses, and outbound request rules.
It addresses operators and developers who maintain the server.
The page links runtime limits to the operations page at [operations.md](operations.md).

## Scope

This page covers browser, API, git, agent output, mirror, and webhook boundaries.
It covers passwords, one time codes, single sign on, tokens, and SSH keys.
It covers permission levels, web defenses, SSRF rules, and push defenses.
It covers secrets at rest, audit reads, and known limits.

## Design

### Trust boundaries

| Boundary | Default stance |
|---|---|
| Browser and web session | Untrusted until templates escape output |
| API client and token | Untrusted until scope and rate checks pass |
| Git client through SSH or smart HTTP | Untrusted until `git_access` grants access |
| Agent output and session traces | Untrusted text until redaction and quarantine run |
| Mirror upstream | Untrusted until URL and SSRF checks pass |
| Webhook receiver | Untrusted until the SSRF gate allows delivery |

- The server treats browser input as untrusted until templates escape output.
- The server treats agent output as untrusted until redaction and quarantine run.
- The server treats mirror upstreams as untrusted until URL and SSRF checks pass.
- Webhook delivery is fail closed when the SSRF gate denies a host.

### Authentication

- The server hashes passwords with Argon2 through `hash_password` in `accounts.rs`.
- Only the password hash reaches the database.
- A one time secret holds 20 bytes and rests in sealed form.
- Current code never logs the sealed TOTP secret.
- The server verifies time based codes with HMAC SHA1 across one step either way.
- The server refuses a code step twice through `totp_last_step`.
- Recovery codes rest as normalized SHA256 hashes.
- A challenge expires after five minutes. Five failed codes void it earlier.
- Single sign on uses the authorization code flow with PKCE.
- The PKCE method is S256.
- The server accepts only RS256 and ES256 identity tokens.
- The server checks issuer, audience, expiry, and nonce on each token.
- The server requires HTTPS for the issuer except on loopback hosts. Production builds accept loopback HTTP.
- Discovery rests in cache for one hour.
- The server caches JSON Web Key Set entries by `kid` and refreshes once on unknown `kid`.
- The `client_secret` field redacts in `Debug` output.
- Device flow accepts only client `starforge-cli`.
- The server stores only a hash of each device code.
- Device codes expire after 900 seconds.
- The server answers `slow_down` for a faster poll.
- Access tokens live 3600 seconds and refresh tokens live 90 days.
- A transaction compare and swap mints a token pair once.
- The server rejects an unknown client identifier outright.

| Item | Format |
|---|---|
| Personal access token | `sfp_` plus 64 hex characters |
| Device user code | `XXXX-XXXX` in Crockford form |
| Sign on callback | `<base_url>/login/oidc/callback` |
| Device verification site | `/oauth/device?user_code=` |

- The server shows a personal access token once at creation.
- Only the SHA256 hash of the token reaches the database.
- Invite links expire after 7 days.
- Invite links are single use and release on a failed sign up.
- Registration modes are `invite`, `open`, `domains`, and `sso`.

| Scope | Grant |
|---|---|
| `repo:read` | Read repository content |
| `repo:write` | Write repository content |
| `trail:write` | Change Trail content |
| `session:upload` | Upload session segments |
| `admin` | Full site administration |

- `repo:write` implies `repo:read`.
- `admin` implies every scope.
- The SSH server accepts public key authentication only.
- The SSH username must be `git`.
- The SSH server allows at most 3 authentication attempts.
- Accepted algorithms are `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, and `ssh-rsa`.
- RSA moduli must hold at least 2048 bits.
- The server rejects certificate keys.
- The server rejects options prefixes and multiple keys on one line.
- A fingerprint is unique across user keys and deploy keys.
- The server holds at most 100 user keys and 50 deploy keys per repository.

### Authorization model

- Permission levels in order are `Read`, `Triage`, `Write`, `Maintain`, and `Admin`.
- Visibility levels in order are `Public`, `Internal`, and `Private`.
- The `effective` function resolves one permission per caller.
- An owner resolves to `Admin`.
- A site admin resolves to `Admin`.
- Other callers take the maximum of organization base, team grants, and collaborator grants.
- Public repositories grant implicit read to anonymous callers.
- Internal repositories grant implicit read to signed in callers only.
- A member holds an explicit grant.
- A site admin alone is not a member.
- Implicit read is not membership.
- Deploy keys grant `Read` or `Write` and never `refs/for` access.
- The admin pages answer 404 to non admin callers.
- The server refuses to suspend or delete the caller. The server allows self-demotion unless the caller is the last active admin.
- The server refuses to suspend, delete, or demote the last active admin.
- Session publication follows the publish and quarantine rules in [trace-and-redaction.md](trace-and-redaction.md).

### Web defenses

- State changing forms check a CSRF token against the web session.
- Signed out forms check a token against the `sf_login_csrf` cookie.
- Pages carry a strict content security policy without nonces.
- User text reaches templates only through escaping.
- Markdown rendering disables raw HTML and then cleans output through `ammonia`.
- Relative links in repository documents resolve to local blob, tree, or raw pages. Absolute links stay unchanged. Ammonia strips `javascript:` targets.
- Responses carry `nosniff` for content type handling.
- Change and search pages carry `X-Robots-Tag: noindex`.
- Cookies are `HttpOnly` with `SameSite=Lax`.
- Cookies gain `Secure` when `server.base_url` starts with `https://`.
- Redirect targets must start with one slash.
- Redirect targets reject backslash and control characters.
- An unsafe redirect target falls back to `/`.

### Outbound request defenses

- The webhook gate resolves the host at delivery time.
- The gate denies loopback when the loopback flag stays off.
- The gate denies private, link local, unique local, multicast, and reserved addresses.
- The gate unwraps IPv4 mapped IPv6 forms before classification.
- The client pins the checked address and never resolves again.
- The client follows no redirect.
- Delivery times out after 10 seconds.
- The client caps success bodies at 64 KiB.
- Mirror URL checks share the same host rules.
- The server refuses `file://` URLs unless the file URL flag allows them.
- GitHub import checks `github.api_url` against the same host rules.
- The GitHub API host must be HTTPS except on loopback hosts.
- The GitHub API host must resolve to an allowed address.

### Git push defenses

- The pre receive hook reads only the `STARFORGE_*` snapshot environment.
- The hook talks to no database.
- A missing or malformed `STARFORGE_PROTECTION` value fails closed for branches, tags, and namespaces.
- A malformed snapshot still allows `refs/for` pushes.
- An import in progress blocks every ref update.
- A pull mirror blocks branch, tag, and namespace updates.
- A pull mirror keeps `refs/for` open for discussion.
- Deploy keys and anonymous pushers cannot push `refs/for`.
- `refs/for` updates need read permission and a known base branch.
- The server refuses deletion of `refs/for` tips.
- Protected branches apply the gate rules in [git-hosting.md](git-hosting.md).
- Deploy keys push as `Write` without a user identity.
- Archived repositories refuse pushes.

### Secrets handling

- The configuration value `security.secret_key` holds 64 hex characters.
- Loss of the value makes sealed webhook secrets and sealed mirror credentials unreadable.
- Loss of the value does not by itself end a web session. Web sessions store only a hash of a random token.
- Unreadable sealed values produce a clear error rather than a panic.
- The credential box seals git remote credentials through XChaCha20 Poly1305.
- The credential box derives its key from `security.secret_key`.
- The server seals webhook secrets and remote credentials at rest.
- Secrets never reach log output, rendered pages, command lines, or URLs.
- `Debug` output redacts the OIDC secret, metrics token, and mail credentials.
- The SSH host key file has mode 0600.
- The configuration file has mode 0600.
- Backup and restore directories have mode 0700. The initial data directory follows the process umask.
- The server deletes temporary SSH files after a failure.
- Git error text redacts user info before logging.

## Interfaces

| Route | Purpose |
|---|---|
| `/login` | Starts a web session |
| `/login/oidc/callback` | Completes single sign on |
| `/oauth/device?user_code=` | Verifies a device code |
| `/settings/two-factor` | Manages two factor authentication |
| `/settings/keys` | Manages SSH keys |
| `/settings/identities` | Manages linked sign on identities |
| `/admin/audit` | Reads the audit log |

- Rate limits and quotas rest in the operations page at [operations.md](operations.md).
- Web session details rest in the web page at [web-and-auth.md](web-and-auth.md).
- Session upload detail rests in the sessions page at [sessions.md](sessions.md).

## Failure behavior

- Single sign on failures show one generic message.
- The server logs the failure reason at debug level.
- A refused device client answers an error without data.
- Unknown fingerprints answer a generic refusal.
- The SSH server refuses shell, subsystem, PTY, and forwarding requests with exit code 1.
- Unreadable repositories answer `repository not found`.
- An archived repository refuses pushes.
- A denied webhook host receives no request and no retry.
- A corrupt hook snapshot fails closed for branches and tags.
- A failed sign on writes an audit row.
- A refused action otherwise writes no audit row.

## Verification

- `crates/starforged-core/src/oidc.rs` covers token verification tables.
- `crates/starforged-core/src/totp.rs` covers code vectors and recovery codes.
- `crates/starforged-core/src/oauth.rs` covers device flow tokens.
- `crates/starforged-core/src/permission.rs` covers the effective permission matrix.
- `crates/starforged-core/src/sshkeys.rs` covers key parsing and caps.
- `crates/starforged-web/src/markdown.rs` covers sanitized output and link stripping.
- `crates/starforged-web/src/auth.rs` covers CSRF checks and safe redirects.
- `crates/starforged/src/hook.rs` covers push snapshot behavior.
- Run the checker in [maintenance.md](maintenance.md) after changes.

## Related

- Read the operations page at [operations.md](operations.md).
- Read the web and auth page at [web-and-auth.md](web-and-auth.md).
- Read the accounts and permissions page at [accounts-and-permissions.md](accounts-and-permissions.md).
- Read the git hosting page at [git-hosting.md](git-hosting.md).
- Read the trace and redaction page at [trace-and-redaction.md](trace-and-redaction.md).

<!-- ste-sources
crates/starforged-core/src/permission.rs
crates/starforged-core/src/tokens.rs
crates/starforged-core/src/oidc.rs
crates/starforged-core/src/totp.rs
crates/starforged-core/src/oauth.rs
crates/starforged-core/src/sshkeys.rs
crates/starforged-web/src/auth.rs
crates/starforged-web/src/markdown.rs
-->
