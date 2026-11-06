-- Starforge M4b: git import and mirrors (spec §8.6, D2).
-- Keep in lockstep with ../sqlite/0026_mirrors.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
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
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('import', 'pull', 'push')),
    url TEXT NOT NULL,
    auth TEXT NOT NULL DEFAULT 'none' CHECK (auth IN ('none', 'https', 'ssh')),
    username TEXT NOT NULL DEFAULT '',
    sealed_secret TEXT,
    ssh_public_key TEXT,
    interval_secs BIGINT NOT NULL DEFAULT 3600,
    enabled BIGINT NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_attempt_at BIGINT,
    last_success_at BIGINT,
    last_error TEXT NOT NULL DEFAULT '',
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX repo_remotes_repo ON repo_remotes (repo_id);
CREATE UNIQUE INDEX repo_remotes_one_import ON repo_remotes (repo_id) WHERE role = 'import';
CREATE UNIQUE INDEX repo_remotes_one_pull ON repo_remotes (repo_id) WHERE role = 'pull';

ALTER TABLE repos ADD COLUMN mirror BIGINT NOT NULL DEFAULT 0 CHECK (mirror IN (0, 1));
ALTER TABLE repos ADD COLUMN import_state TEXT NOT NULL DEFAULT 'none'
    CHECK (import_state IN ('none', 'pending', 'running', 'done', 'failed'));
