-- Starforge M0.5: old repository names redirect to the renamed repository (forge-basics design §5.3).
-- Keep in lockstep with ../sqlite/0005_repo_redirects.sql.

CREATE TABLE repo_redirects (
    owner_id BIGINT NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
    lower_name TEXT NOT NULL,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (owner_id, lower_name)
);
CREATE INDEX repo_redirects_repo ON repo_redirects (repo_id);
