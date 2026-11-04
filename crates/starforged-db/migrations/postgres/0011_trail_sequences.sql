-- Starforge M2a: per-repo trail number sequences.
-- Keep in lockstep with ../sqlite/0011_trail_sequences.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- The sequence serializes number allocation (`ON CONFLICT (repo_id) DO UPDATE`
-- takes the row lock), so concurrent creates never collide; a rolled-back trail
-- insert returns its number. Backfill seeds every repo that already has trails.

CREATE TABLE trail_sequences (
    repo_id BIGINT PRIMARY KEY REFERENCES repos (id) ON DELETE CASCADE,
    next_number BIGINT NOT NULL
);
INSERT INTO trail_sequences (repo_id, next_number)
    SELECT repo_id, MAX(number) + 1 FROM trails GROUP BY repo_id;
