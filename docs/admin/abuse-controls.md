# Abuse controls

Abuse controls (spec §11.6) are all configurable under `[limits]`; every key is
also overridable as `STARFORGE__LIMITS__*`. Setting any limit to `0` disables it.
The session-upload volume and storage quotas keep their own `[sessions]` keys
(500 MiB/hour upload volume, 5 GiB per user, 20 GiB per repository, 16 MiB per
segment) and their existing errors.

| Limit | Config key | Default | What it counts |
|---|---|---|---|
| Sign-in attempts | `limits.login_per_ip_per_minute` | `10` | Attempts from one client IP per fixed 1-minute window (in-memory) |
| Failed sign-ins | `limits.login_per_account_per_hour` | `20` | `auth.login_failed` rows for the normalized login name in the last hour (database) |
| API requests | `limits.api_per_token_per_hour` | `5000` | Requests per token per fixed 1-hour window (in-memory) |
| New `refs/for` changes | `limits.refs_for_new_changes_per_hour` | `30` | `agit` changes created by the user in all repositories in the last hour (database) |

**Client IP.** The login limiter, the login page, and the audit writer all use
the same address: the TCP peer (`ConnectInfo`) of the HTTP connection. An
`X-Forwarded-For` header is never trusted, so a client cannot spoof its
address; only a reverse proxy in front of a single server can see the proxied
address, and behind one the limiter and the audit log see the proxy, not the
client. The per-account limit counts failures for existing and non-existing
login names identically (by the normalized name), so probing unknown names is
limited the same way.

**Response shapes.** Over the API limit: `429` with the error envelope
`{"error": {"code": "rate_limited", "message": "rate limit exceeded"}}`,
`Retry-After`, and on every token-authenticated API response (when the limit is
enabled) `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`
(unix seconds). When the limit is disabled no `X-RateLimit-*` headers are sent.
Over a sign-in limit: the sign-in page re-renders with `429` and a generic
message; failed attempts while limited are still audited
(`auth.login_rate_limited`). Over the `refs/for` budget: the push of that ref
is refused with a `remote: starforge: …` message naming the limit; updating
an existing topic is still accepted. API `429`s are never audited (too noisy)
and are logged at `info` with the token id, never the token. The in-memory
windows reset on restart, which a single-process deployment accepts.
