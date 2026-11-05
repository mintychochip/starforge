-- Starforge M2e K4: per-trail review requests.
-- Keep in lockstep with ../postgres/0016_review_requests.sql.

CREATE TABLE trail_review_requests (
    trail_id INTEGER NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    requested_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (trail_id, user_id)
);
CREATE INDEX trail_review_requests_trail ON trail_review_requests (trail_id);
CREATE INDEX trail_review_requests_user ON trail_review_requests (user_id);
