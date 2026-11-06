-- Starforge M3b: tag protection (spec §8.2, D3).
-- Keep in lockstep with ../sqlite/0023_tag_protection.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- `tag_protections` holds one optional glob per row: any tag matching any
-- pattern needs `maintain` or above to create, move, or delete. Forward-only.

CREATE TABLE tag_protections (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (repo_id, pattern)
);
CREATE INDEX tag_protections_repo ON tag_protections (repo_id);
