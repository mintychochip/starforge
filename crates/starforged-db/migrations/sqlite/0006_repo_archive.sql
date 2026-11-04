-- Starforge M0.5: archived repositories stay readable and refuse pushes (forge-basics design §5.4).
-- Keep in lockstep with ../postgres/0006_repo_archive.sql.

ALTER TABLE repos ADD COLUMN archived_at INTEGER;
