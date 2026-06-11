-- Custom denial rules per account (Professional plan)
CREATE TABLE IF NOT EXISTS custom_rules (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  name TEXT NOT NULL,
  payer TEXT NOT NULL DEFAULT 'all',
  condition_type TEXT NOT NULL,
  condition_value TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'Medium',
  custom_message TEXT NOT NULL DEFAULT '',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_account ON custom_rules(account_id, is_active);
