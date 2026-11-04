-- Starforge M2a: Trails (issue-like objects scoped to a repository).
-- Keep in lockstep with ../sqlite/0010_trails.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- Numbering is per repository (UNIQUE (repo_id, number)); the number is allocated
-- by a single INSERT ... SELECT COALESCE(MAX(number), 0) + 1 statement.
-- `merged` is admitted by the state CHECK now so the M2c merge path can write it
-- with no migration rewrite; it is never written in M2a.

CREATE TABLE trails (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    number BIGINT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    intent TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'merged', 'closed')),
    ready BIGINT NOT NULL DEFAULT 0,
    author_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    closed_at BIGINT,
    merged_at BIGINT,
    UNIQUE (repo_id, number)
);
CREATE INDEX trails_repo ON trails (repo_id);
CREATE INDEX trails_repo_number ON trails (repo_id, number);
CREATE INDEX trails_author ON trails (author_id);

CREATE TABLE trail_labels (
    trail_id BIGINT NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE (trail_id, name)
);
CREATE INDEX trail_labels_trail ON trail_labels (trail_id);

CREATE TABLE trail_assignees (
    trail_id BIGINT NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (trail_id, user_id)
);
CREATE INDEX trail_assignees_trail ON trail_assignees (trail_id);

CREATE TABLE trail_comments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trail_id BIGINT NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    author_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    body TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    edited_at BIGINT
);
CREATE INDEX trail_comments_trail ON trail_comments (trail_id);

CREATE TABLE timeline_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    trail_id BIGINT REFERENCES trails (id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT '',
    actor_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    payload TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
CREATE INDEX timeline_events_trail ON timeline_events (trail_id);
CREATE INDEX timeline_events_repo ON timeline_events (repo_id);
