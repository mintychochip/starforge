-- Starforge M4b: git import and mirrors (spec §8.6, D2).
-- Keep in lockstep with ../postgres/0026_mirrors.sql.
--
-- `repo_remotes` is the one row per configured remote: the one-time import
-- source (`role = 'import'`), the pull mirror (`role = 'pull'`), or a push
-- mirror (`role = 'push'`). Credentials are stored only sealed
-- (`sealed_secret`, XChaCha20-Poly1305 under the M4b credential box); the
-- API and pages never return them. For `auth = 'ssh'` the row also carries
-- the generated public key (`ssh_public_key`) the user installs upstream.
-- `last_error` is git stderr scrubbed of URL userinfo.
--
-- `repos.mirror` is true while a pull remote exists and is enabled (I3 owns
-- writing it; I2 only declares the columns). `repos.import_state` carries
-- the one-time import's `none|pending|running|done|failed` state.

CREATE TABLE repo_remotes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('import', 'pull', 'push')),
    url TEXT NOT NULL,
    auth TEXT NOT NULL DEFAULT 'none' CHECK (auth IN ('none', 'https', 'ssh')),
    username TEXT NOT NULL DEFAULT '',
    sealed_secret TEXT,
    ssh_public_key TEXT,
    interval_secs INTEGER NOT NULL DEFAULT 3600,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_attempt_at INTEGER,
    last_success_at INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX repo_remotes_repo ON repo_remotes (repo_id);
CREATE UNIQUE INDEX repo_remotes_one_import ON repo_remotes (repo_id) WHERE role = 'import';
CREATE UNIQUE INDEX repo_remotes_one_pull ON repo_remotes (repo_id) WHERE role = 'pull';

ALTER TABLE repos ADD COLUMN mirror INTEGER NOT NULL DEFAULT 0 CHECK (mirror IN (0, 1));
ALTER TABLE repos ADD COLUMN import_state TEXT NOT NULL DEFAULT 'none'
    CHECK (import_state IN ('none', 'pending', 'running', 'done', 'failed'));
