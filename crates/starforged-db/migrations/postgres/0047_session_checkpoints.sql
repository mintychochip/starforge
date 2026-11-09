-- Starforge: session checkpoints (git snapshots of the working tree).
-- Keep in lockstep with ../sqlite/0047_session_checkpoints.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE session_checkpoints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    session_id BIGINT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    n BIGINT NOT NULL CHECK (n > 0),
    commit_sha TEXT NOT NULL,
    tree_sha TEXT NOT NULL,
    parent_sha TEXT,
    label TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    created_at BIGINT NOT NULL,
    UNIQUE (session_id, n)
);
CREATE INDEX session_checkpoints_repo ON session_checkpoints (repo_id, session_id);
