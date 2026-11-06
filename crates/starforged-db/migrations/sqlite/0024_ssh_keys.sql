-- Starforge M3c: SSH keys and deploy keys (spec §6.1, D3).
-- Keep in lockstep with ../postgres/0024_ssh_keys.sql.
--
-- `ssh_keys` holds per-user OpenSSH public keys; `deploy_keys` holds
-- per-repository keys. `fingerprint` is UNIQUE per table; the cross-table
-- uniqueness is enforced in Core. Forward-only.

CREATE TABLE ssh_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX ssh_keys_user ON ssh_keys (user_id);

CREATE TABLE deploy_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    read_write INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX deploy_keys_repo ON deploy_keys (repo_id);
