-- Starforge: cross-repository Trail changes.
-- Keep in lockstep with ../sqlite/0046_cross_repo_changes.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE change_sources (
    change_id BIGINT PRIMARY KEY REFERENCES changes (id) ON DELETE CASCADE,
    source_repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    source_branch TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX change_sources_source ON change_sources (source_repo_id, source_branch);
