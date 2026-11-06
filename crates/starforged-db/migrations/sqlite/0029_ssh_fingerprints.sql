-- Starforge M3c fix: atomic cross-table SSH fingerprint registry (spec §6.1).
-- Keep in lockstep with ../postgres/0029_ssh_fingerprints.sql.
-- `ssh_fingerprints` is the single claim table for every SSH key fingerprint:
-- user-key and deploy-key inserts register here in the same transaction as
-- the key row, so concurrent adds (same table or across tables) serialize
-- on the primary key and the loser observes a unique violation (422).
-- `kind` is 'ssh_key' (ref_id = ssh_keys.id) or 'deploy_key'
-- (ref_id = deploy_keys.id). Backfilled from both key tables. Forward-only.
CREATE TABLE ssh_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    ref_id INTEGER NOT NULL
);
INSERT INTO ssh_fingerprints (fingerprint, kind, ref_id)
    SELECT fingerprint, 'ssh_key', id FROM ssh_keys;
INSERT INTO ssh_fingerprints (fingerprint, kind, ref_id)
    SELECT fingerprint, 'deploy_key', id FROM deploy_keys;
