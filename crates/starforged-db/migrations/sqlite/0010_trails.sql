-- Starforge M2a: Trails (issue-like objects scoped to a repository).
-- Keep in lockstep with ../postgres/0010_trails.sql.
--
-- Numbering is per repository (UNIQUE (repo_id, number)); the number is allocated
-- by a single INSERT ... SELECT COALESCE(MAX(number), 0) + 1 statement.
-- `merged` is admitted by the state CHECK now so the M2c merge path can write it
-- with no migration rewrite; it is never written in M2a.

CREATE TABLE trails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    number INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    intent TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'merged', 'closed')),
    ready INTEGER NOT NULL DEFAULT 0,
    author_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    closed_at INTEGER,
    merged_at INTEGER,
    UNIQUE (repo_id, number)
);
CREATE INDEX trails_repo ON trails (repo_id);
CREATE INDEX trails_repo_number ON trails (repo_id, number);
CREATE INDEX trails_author ON trails (author_id);

CREATE TABLE trail_labels (
    trail_id INTEGER NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE (trail_id, name)
);
CREATE INDEX trail_labels_trail ON trail_labels (trail_id);

CREATE TABLE trail_assignees (
    trail_id INTEGER NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (trail_id, user_id)
);
CREATE INDEX trail_assignees_trail ON trail_assignees (trail_id);

CREATE TABLE trail_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trail_id INTEGER NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    author_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    body TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    edited_at INTEGER
);
CREATE INDEX trail_comments_trail ON trail_comments (trail_id);

CREATE TABLE timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    trail_id INTEGER REFERENCES trails (id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT '',
    actor_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    payload TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX timeline_events_trail ON timeline_events (trail_id);
CREATE INDEX timeline_events_repo ON timeline_events (repo_id);
