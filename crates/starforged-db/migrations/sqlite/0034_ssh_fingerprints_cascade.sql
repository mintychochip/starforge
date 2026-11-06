-- Starforge M3c fix: registry rows must not outlive their key rows (spec §6.1).
-- Keep in lockstep with ../postgres/0034_ssh_fingerprints_cascade.sql.
-- Rebuild `ssh_fingerprints` with one nullable FK per key table (cascade
-- delete), so account deletion, repo purge, and org deletion free the
-- fingerprint for re-use instead of orphaning the claim row. Orphans left
-- by 0029 (key row already gone) are dropped during the copy. Forward-only.
CREATE TABLE ssh_fingerprints_new (
    fingerprint TEXT PRIMARY KEY,
    ssh_key_id INTEGER REFERENCES ssh_keys (id) ON DELETE CASCADE,
    deploy_key_id INTEGER REFERENCES deploy_keys (id) ON DELETE CASCADE,
    CHECK ((ssh_key_id IS NULL) <> (deploy_key_id IS NULL))
);
INSERT INTO ssh_fingerprints_new (fingerprint, ssh_key_id, deploy_key_id)
    SELECT fingerprint,
        CASE WHEN kind = 'ssh_key' THEN ref_id END,
        CASE WHEN kind = 'deploy_key' THEN ref_id END
    FROM ssh_fingerprints
    WHERE (kind = 'ssh_key' AND EXISTS (
        SELECT 1 FROM ssh_keys WHERE id = ref_id))
       OR (kind = 'deploy_key' AND EXISTS (
        SELECT 1 FROM deploy_keys WHERE id = ref_id));
DROP TABLE ssh_fingerprints;
ALTER TABLE ssh_fingerprints_new RENAME TO ssh_fingerprints;
CREATE INDEX ssh_fingerprints_ssh_key ON ssh_fingerprints (ssh_key_id);
CREATE INDEX ssh_fingerprints_deploy_key ON ssh_fingerprints (deploy_key_id);
