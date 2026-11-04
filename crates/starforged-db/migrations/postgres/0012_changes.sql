-- Starforge M2b: Changes, revisions, reviews, and review threads.
-- Keep in lockstep with ../sqlite/0012_changes.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- `changes.number` is per trail and `revisions.number` per change, allocated from
-- `change_sequences` / `revision_sequences` with the same upsert-then-insert
-- pattern as `trail_sequences` (0011); the UNIQUE constraints are the defensive
-- fallback. Both sequence tables seed empty: no prior rows can exist on upgrade.
-- `merged` is admitted by the state CHECK now so the M2c merge path can write it
-- with no migration rewrite; it is never written in M2b. `imported` is admitted
-- by the kind CHECK for M4 mirrors; never written in M2b.
--
-- `topic` carries the refs/for push topic for `agit` changes (whose `head_branch`
-- stays NULL); it is `''` for other kinds. `current_revision_id` is a plain
-- nullable column with no FOREIGN KEY: `revisions` is created after `changes`,
-- so the reference cannot be declared inline, and the aggregate dies together
-- through `revisions.change_id ON DELETE CASCADE` anyway.

ALTER TABLE repos ADD COLUMN refs_for_access TEXT NOT NULL DEFAULT 'anyone_with_read'
    CHECK (refs_for_access IN ('anyone_with_read', 'members'));

CREATE TABLE changes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trail_id BIGINT NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    number BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('branch', 'agit', 'imported')),
    head_branch TEXT,
    base_branch TEXT NOT NULL DEFAULT '',
    topic TEXT NOT NULL DEFAULT '',
    current_revision_id BIGINT,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'merged', 'closed')),
    merge_method TEXT,
    merge_commit TEXT,
    creator_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    mergeability TEXT NOT NULL DEFAULT 'unknown',
    conflict_paths TEXT NOT NULL DEFAULT '',
    UNIQUE (trail_id, number)
);
CREATE INDEX changes_trail ON changes (trail_id);
CREATE INDEX changes_trail_number ON changes (trail_id, number);

CREATE TABLE revisions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    change_id BIGINT NOT NULL REFERENCES changes (id) ON DELETE CASCADE,
    number BIGINT NOT NULL,
    head_sha TEXT NOT NULL,
    base_sha TEXT NOT NULL DEFAULT '',
    merge_base_sha TEXT,
    pusher_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    mergeability TEXT NOT NULL DEFAULT 'unknown',
    conflict_paths TEXT NOT NULL DEFAULT '',
    UNIQUE (change_id, number)
);
CREATE INDEX revisions_change ON revisions (change_id);
CREATE INDEX revisions_change_number ON revisions (change_id, number);

CREATE TABLE reviews (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    change_id BIGINT NOT NULL REFERENCES changes (id) ON DELETE CASCADE,
    revision_id BIGINT NOT NULL REFERENCES revisions (id) ON DELETE CASCADE,
    author_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('approve', 'request_changes', 'comment')),
    body TEXT NOT NULL DEFAULT '',
    session_ulid TEXT,
    state TEXT NOT NULL DEFAULT 'submitted' CHECK (state IN ('pending', 'submitted', 'dismissed')),
    created_at BIGINT NOT NULL
);
CREATE INDEX reviews_change ON reviews (change_id);
CREATE INDEX reviews_revision ON reviews (revision_id);

CREATE TABLE review_threads (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    change_id BIGINT NOT NULL REFERENCES changes (id) ON DELETE CASCADE,
    anchor_revision_id BIGINT NOT NULL REFERENCES revisions (id) ON DELETE CASCADE,
    path TEXT NOT NULL DEFAULT '',
    side TEXT NOT NULL DEFAULT 'head' CHECK (side IN ('base', 'head')),
    start_line BIGINT NOT NULL DEFAULT 0,
    end_line BIGINT NOT NULL DEFAULT 0,
    resolved BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
);
CREATE INDEX review_threads_change ON review_threads (change_id);

CREATE TABLE review_comments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    thread_id BIGINT NOT NULL REFERENCES review_threads (id) ON DELETE CASCADE,
    review_id BIGINT REFERENCES reviews (id) ON DELETE SET NULL,
    author_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    body TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
CREATE INDEX review_comments_thread ON review_comments (thread_id);

CREATE TABLE change_sequences (
    trail_id BIGINT PRIMARY KEY REFERENCES trails (id) ON DELETE CASCADE,
    next_number BIGINT NOT NULL
);
CREATE TABLE revision_sequences (
    change_id BIGINT PRIMARY KEY REFERENCES changes (id) ON DELETE CASCADE,
    next_number BIGINT NOT NULL
);
