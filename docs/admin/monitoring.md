# Monitoring



`GET /healthz` answers `ok` unconditionally (liveness). `GET /readyz` answers
`200` only while the database answers `SELECT 1` within 2 s, migrations are
up to date, job workers have heartbeated within 30 s, the search index is
open, the SSH listener is bound (when enabled), and the data directory is
present; otherwise it answers `503` with a
JSON list of the failing items (for example `{"status": "unavailable",
"failing": ["jobs"]}`).

`GET /metrics` serves Prometheus text exposition when `metrics.token` is
set (`Authorization: Bearer <token>`): it answers `404` when no token is
configured and `401` on a wrong token. The counters, gauges, and the request
duration histogram carry no user, repository, or token labels.




`log.format` selects `text` (default) or `json` (one JSON object per line,
for log aggregation), and `log.level` is an `EnvFilter` string (default
`info`). Both are overridable as `STARFORGE__LOG__FORMAT` /
`STARFORGE__LOG__LEVEL`. Secrets are never logged.


Logs: `log.format` selects `text` or `json`; override with `STARFORGE__LOG__FORMAT` / `STARFORGE__LOG__LEVEL`.
