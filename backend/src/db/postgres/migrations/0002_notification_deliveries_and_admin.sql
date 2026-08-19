-- Closes the gap between 0001's snapshot and the live SQLite schema as of
-- the SQLite -> PostgreSQL migration: two things were added to
-- src/db/index.ts's runtime ALTER-if-missing blocks after 0001 was written
-- (users.is_admin, notification_deliveries) and were never backported here.

ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;

CREATE TABLE notification_deliveries (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  channel TEXT NOT NULL,
  destination TEXT NOT NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_notification_deliveries_status ON notification_deliveries(status, created_at DESC);
CREATE INDEX idx_notification_deliveries_project ON notification_deliveries(project_id, created_at DESC);
