-- Starforge M2f F5: per-reader viewed state for change files.
-- Keep in lockstep with ../sqlite/0019_change_file_views.sql.
--
-- `change_file_views` records that a reader has viewed a file at a given
-- blob: a file counts as viewed while the stored `blob_sha` equals the
-- file's blob at the displayed head, so a later revision that changes the
-- file resets it. One row per (reader, change, path); un-marking deletes
-- the row. Viewed state writes no timeline rows.

CREATE TABLE change_file_views (
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    change_id BIGINT NOT NULL REFERENCES changes (id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    blob_sha TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    UNIQUE (user_id, change_id, path)
);
CREATE INDEX change_file_views_change ON change_file_views (change_id);
