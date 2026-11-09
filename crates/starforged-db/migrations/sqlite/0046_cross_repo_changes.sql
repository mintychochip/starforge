-- Starforge: cross-repository Trail changes.
-- Keep in lockstep with ../postgres/0046_cross_repo_changes.sql.
--
-- A change whose head branch lives in another repository keeps its existing
-- `changes` row; this side table records the source. The head objects are
-- fetched into the target repository, so every read, diff, gate, and merge
-- path stays unchanged. A change without a row here is same-repository.

CREATE TABLE change_sources (
    change_id INTEGER PRIMARY KEY REFERENCES changes (id) ON DELETE CASCADE,
    source_repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    source_branch TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX change_sources_source ON change_sources (source_repo_id, source_branch);
