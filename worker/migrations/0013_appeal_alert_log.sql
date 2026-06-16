-- 0013_appeal_alert_log.sql
--
-- Append-only: do not edit after this file has been deployed.
-- Tracks appeal overdue alerts sent (30-day and 60-day) to prevent duplicate sends.

CREATE TABLE IF NOT EXISTS appeal_alert_log (
  id TEXT PRIMARY KEY,
  appeal_id TEXT NOT NULL REFERENCES appeals_tracker(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alert_type TEXT NOT NULL, -- '30day' or '60day'
  sent_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(appeal_id, alert_type)
);

CREATE INDEX IF NOT EXISTS idx_appeal_alert_log_appeal_id ON appeal_alert_log(appeal_id);
CREATE INDEX IF NOT EXISTS idx_appeal_alert_log_user_id ON appeal_alert_log(user_id);
