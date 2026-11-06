-- Starforge M3c: SSH keys and deploy keys (spec §6.1, D3).
-- Keep in lockstep with ../sqlite/0024_ssh_keys.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- `ssh_keys` holds per-user OpenSSH public keys; `deploy_keys` holds
-- per-repository keys. `fingerprint` is UNIQUE per table; the cross-table
-- uniqueness is enforced in Core. Forward-only.

CREATE TABLE ssh_keys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE INDEX ssh_keys_user ON ssh_keys (user_id);

CREATE TABLE deploy_keys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    read_write BIGINT NOT NULL DEFAULT 0,
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT
);
CREATE INDEX deploy_keys_repo ON deploy_keys (repo_id);
