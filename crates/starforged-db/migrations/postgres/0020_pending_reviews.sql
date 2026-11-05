-- Starforge M2f F6: one pending review per author per change.
-- Keep in lockstep with ../sqlite/0020_pending_reviews.sql.
--
-- A signed-in reader holds at most one `pending` review per change; draft
-- comments attach to it. Partial unique indexes are valid on both engines.

CREATE UNIQUE INDEX reviews_one_pending_per_author
    ON reviews (change_id, author_id)
    WHERE state = 'pending';
