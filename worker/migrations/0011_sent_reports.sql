-- 0011_sent_reports.sql
--
-- Append-only: do not edit after this file has been deployed.
-- Tracks monthly billing health reports sent via cron to avoid double-sends.

CREATE TABLE IF NOT EXISTS sent_reports (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  month INTEGER NOT NULL,
  year INTEGER NOT NULL,
  sent_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(user_id, month, year)
);

CREATE INDEX IF NOT EXISTS idx_sent_reports_user_id ON sent_reports(user_id);
