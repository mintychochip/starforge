-- Starforge Phase 3: releases and release assets.
-- Keep in lockstep with ../postgres/0042_releases.sql.
--
-- `releases` holds one row per tagged release. `author_id` is NULL for a
-- deleted author. `published_at` is NULL while the release is a draft.
-- `release_assets` holds the files attached to a release; the bytes live in
-- the content-addressed blob store and `blob_hash` names the stored blob.

CREATE TABLE releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    draft INTEGER NOT NULL DEFAULT 0,
    prerelease INTEGER NOT NULL DEFAULT 0,
    author_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    published_at INTEGER,
    UNIQUE (repo_id, tag)
);

CREATE TABLE release_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id INTEGER NOT NULL REFERENCES releases (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    blob_hash TEXT NOT NULL,
    content_type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (release_id, name)
);
CREATE INDEX release_assets_release ON release_assets (release_id);
