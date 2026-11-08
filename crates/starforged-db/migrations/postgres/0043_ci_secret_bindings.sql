-- Starforge Phase 4: per-secret egress host/header bindings.
-- Keep in lockstep with ../sqlite/0043_ci_secret_bindings.sql.
--
-- `ci_secrets.bind_host` is the only host the secret value may be injected
-- for (empty = unbound); `bind_header` is the HTTP header token the egress
-- proxy sets. Both empty means the secret is unbound and cannot be resolved
-- for a sandbox; exactly one set is rejected by core validation.

ALTER TABLE ci_secrets ADD COLUMN bind_host TEXT NOT NULL DEFAULT '';
ALTER TABLE ci_secrets ADD COLUMN bind_header TEXT NOT NULL DEFAULT '';
