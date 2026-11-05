-- Starforge M2e K5: index the assignee lookup side of the dashboard query.
-- Keep in lockstep with ../postgres/0017_dashboard_indexes.sql.
-- (`sessions(uploader_id)` and `trail_review_requests(user_id)` are already
-- indexed by 0008 and 0016; `changes(trail_id)` by 0012.)

CREATE INDEX trail_assignees_user ON trail_assignees (user_id);
