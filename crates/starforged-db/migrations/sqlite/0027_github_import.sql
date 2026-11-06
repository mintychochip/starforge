-- Starforge M4c: GitHub metadata import (spec §8.6).
-- Keep in lockstep with ../postgres/0027_github_import.sql.
--
-- `imported_author` holds the original GitHub login when the author could
-- not be matched to a local user by verified email (D1); the local
-- `author_id` column is then NULL and the row renders "login (imported)".
-- `github_id` is the GitHub API object id; the UNIQUE index on it makes
-- each object import idempotent so a resumed run never duplicates a row.
-- GitHub ids are globally unique, so the index needs no repository scope.
-- `trails.number` for an imported row is the GitHub issue/PR number (D2);
-- `trail_sequences` is advanced past it by the importer.
--
-- `github_imports` is the one resumable record per repository: the source
-- slug, the state, the cursor (`cursor_kind`/`cursor_page`/`cursor_number`),
-- the counts, the dropped-assignee summary, and the GitHub token sealed
-- with the M4b credential box (`token_sealed`, deleted on finish/failure).

ALTER TABLE trails ADD COLUMN imported_author TEXT;
ALTER TABLE trails ADD COLUMN github_id INTEGER;
CREATE UNIQUE INDEX trails_github_id ON trails (github_id);

ALTER TABLE trail_comments ADD COLUMN imported_author TEXT;
ALTER TABLE trail_comments ADD COLUMN github_id INTEGER;
CREATE UNIQUE INDEX trail_comments_github_id ON trail_comments (github_id);

ALTER TABLE reviews ADD COLUMN imported_author TEXT;
ALTER TABLE reviews ADD COLUMN github_id INTEGER;
CREATE UNIQUE INDEX reviews_github_id ON reviews (github_id);

ALTER TABLE review_comments ADD COLUMN imported_author TEXT;
ALTER TABLE review_comments ADD COLUMN github_id INTEGER;
CREATE UNIQUE INDEX review_comments_github_id ON review_comments (github_id);

CREATE TABLE github_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL UNIQUE REFERENCES repos (id) ON DELETE CASCADE,
    source TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'running', 'rate_limited', 'completed', 'failed')),
    cursor_kind TEXT NOT NULL DEFAULT '',
    cursor_page INTEGER NOT NULL DEFAULT 1,
    cursor_number INTEGER,
    issues_count INTEGER NOT NULL DEFAULT 0,
    pulls_count INTEGER NOT NULL DEFAULT 0,
    comments_count INTEGER NOT NULL DEFAULT 0,
    reviews_count INTEGER NOT NULL DEFAULT 0,
    review_comments_count INTEGER NOT NULL DEFAULT 0,
    dropped_assignees TEXT NOT NULL DEFAULT '',
    token_sealed TEXT,
    error TEXT,
    failures INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER
);
CREATE INDEX github_imports_repo ON github_imports (repo_id);
