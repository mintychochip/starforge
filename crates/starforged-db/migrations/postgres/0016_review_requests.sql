-- Starforge M2e K4: per-trail review requests.
-- Keep in lockstep with ../sqlite/0016_review_requests.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE trail_review_requests (
    trail_id BIGINT NOT NULL REFERENCES trails (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    requested_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (trail_id, user_id)
);
CREATE INDEX trail_review_requests_trail ON trail_review_requests (trail_id);
CREATE INDEX trail_review_requests_user ON trail_review_requests (user_id);
