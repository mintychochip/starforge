-- Starforge M2f F2: the Trail commits cache and explicit Trail↔session links.
-- Keep in lockstep with ../sqlite/0018_trail_sessions.sql.
--
-- `revision_commits` caches the commits reachable from a revision's head and
-- not from its base, so `has_sessions` can filter in SQL with keyset paging.
-- `position` is 0 for the head; at most 250 rows per revision (the recorder
-- keeps the newest 250). `revisions.commits_recorded` marks recorded
-- revisions; the hourly maintenance pass backfills the rest.
-- `trail_session_links` are explicit hand links (triage+ or the author for
-- their own sessions); at most 50 per Trail.

ALTER TABLE revisions ADD COLUMN commits_recorded BIGINT NOT NULL DEFAULT 0;

CREATE TABLE revision_commits (
    revision_id BIGINT NOT NULL REFERENCES revisions (id) ON DELETE CASCADE,
    sha TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    position BIGINT NOT NULL,
    PRIMARY KEY (revision_id, position)
);
CREATE INDEX revision_commits_sha ON revision_commits (sha);

CREATE TABLE trail_session_links (
    trail_id BIGINT NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    session_id BIGINT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    linked_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (trail_id, session_id)
);
CREATE INDEX trail_session_links_trail ON trail_session_links (trail_id);
