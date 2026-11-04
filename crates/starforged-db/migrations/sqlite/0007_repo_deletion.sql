-- Starforge M0.5: deleted repositories keep their name and can be restored for 7 days (forge-basics design §5.5).
-- Keep in lockstep with ../postgres/0007_repo_deletion.sql.

ALTER TABLE repos ADD COLUMN deleted_at INTEGER;
CREATE INDEX repos_deleted ON repos (deleted_at);
