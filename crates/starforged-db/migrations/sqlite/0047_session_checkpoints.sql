-- Starforge: session checkpoints (git snapshots of the working tree).
-- Keep in lockstep with ../postgres/0047_session_checkpoints.sql.
--
-- A checkpoint is a git commit under refs/starforge/checkpoints/<ulid>/<n>;
-- this table carries its label and ordering. The ref supplies the objects, so
-- the viewer can link to the existing commit and compare pages.

CREATE TABLE session_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    n INTEGER NOT NULL CHECK (n > 0),
    commit_sha TEXT NOT NULL,
    tree_sha TEXT NOT NULL,
    parent_sha TEXT,
    label TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    created_at INTEGER NOT NULL,
    UNIQUE (session_id, n)
);
CREATE INDEX session_checkpoints_repo ON session_checkpoints (repo_id, session_id);
