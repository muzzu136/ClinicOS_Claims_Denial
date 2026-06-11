-- 0006_pm_connections.sql
--
-- Append-only: do not edit after this file has been deployed.
-- See worker/migrations/0001_initial.sql for the full rules.

CREATE TABLE pm_connections (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  system TEXT NOT NULL CHECK(system IN ('kareo','advancedmd','drchrono')),
  credentials_encrypted TEXT NOT NULL,
  connected_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER,
  UNIQUE(user_id, system)
);
CREATE INDEX idx_pm_connections_user_id ON pm_connections(user_id);

