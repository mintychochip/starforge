# Reverse proxy and TLS

Starforge serves plain HTTP on `server.http_addr` and does not terminate TLS. Put a reverse proxy (e.g. nginx) in front and set `server.base_url` to the public `https://` URL (no trailing slash); an `https://` `base_url` turns on secure cookies automatically.

Forward to the `server.http_addr` listener. The application never trusts `X-Forwarded-For`: client-IP sensitive code (the login rate limiter, the login page, audit rows) uses the TCP peer address, so behind a proxy those surfaces see the proxy address, not the original client. The git rate limiter (`limits.git_per_ip_per_minute`) uses the same address: every client shares the proxy's address there too, so prefer rate limiting at the proxy there. There is no supported way to pass the real client IP through.

Health checks: `GET /healthz` always answers `ok`; `GET /readyz` answers `200` only while the database, migrations, job workers, search index, SSH listener (when enabled), and data directory are healthy. `GET /metrics` needs `metrics.token` (see monitoring).
