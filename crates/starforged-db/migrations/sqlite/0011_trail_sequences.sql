-- Starforge M2a: per-repo trail number sequences.
-- Keep in lockstep with ../postgres/0011_trail_sequences.sql.
--
-- The sequence serializes number allocation (`ON CONFLICT (repo_id) DO UPDATE`
-- takes the row lock), so concurrent creates never collide; a rolled-back trail
-- insert returns its number. Backfill seeds every repo that already has trails.

CREATE TABLE trail_sequences (
    repo_id INTEGER PRIMARY KEY REFERENCES repos (id) ON DELETE CASCADE,
    next_number INTEGER NOT NULL
);
INSERT INTO trail_sequences (repo_id, next_number)
    SELECT repo_id, MAX(number) + 1 FROM trails GROUP BY repo_id;
