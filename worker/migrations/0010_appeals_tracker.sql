-- 0010_appeals_tracker.sql
--
-- Append-only: do not edit after this file has been deployed.
-- See worker/migrations/0001_initial.sql for the full rules.

CREATE TABLE IF NOT EXISTS appeals_tracker (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  denial_code TEXT NOT NULL,
  cpt_code TEXT NOT NULL,
  payer TEXT NOT NULL,
  billed_amount REAL NOT NULL DEFAULT 0,
  date_sent TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Sent',
  letter_text TEXT,
  resolved_at TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_appeals_tracker_user_id ON appeals_tracker(user_id);
CREATE INDEX IF NOT EXISTS idx_appeals_tracker_status ON appeals_tracker(status);
CREATE INDEX IF NOT EXISTS idx_appeals_tracker_date_sent ON appeals_tracker(date_sent);
