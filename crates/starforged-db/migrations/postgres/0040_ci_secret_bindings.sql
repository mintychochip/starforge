-- Starforge M6c C3 follow-up: per-repo CI secret policy and the
-- egress-proxy destination binding.
-- Keep in lockstep with ../sqlite/0040_ci_secret_bindings.sql.
--
-- `repos.ci_allow_secrets_on_refs_for` opts a repo into resolving secrets
-- for `refs/for` (Trail change) jobs without maintainer approval;
-- `repos.ci_env_secrets` opts a repo into delivering secrets as sandbox
-- environment variables on providers without an egress proxy.
-- `ci_secrets.host`/`header` name the one destination an egress proxy
-- injects the secret under (`host` empty means no proxy injection).

ALTER TABLE repos ADD COLUMN ci_allow_secrets_on_refs_for BIGINT NOT NULL DEFAULT 0;
ALTER TABLE repos ADD COLUMN ci_env_secrets BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ci_secrets ADD COLUMN host TEXT NOT NULL DEFAULT '';
ALTER TABLE ci_secrets ADD COLUMN header TEXT NOT NULL DEFAULT 'Authorization';
