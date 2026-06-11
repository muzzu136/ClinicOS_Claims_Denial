-- 0008_team_seats.sql
--
-- Append-only: do not edit after this file has been deployed.
-- See worker/migrations/0001_initial.sql for the full rules.

-- Add team/multi-user support: account_id, role, name on users table
ALTER TABLE users ADD COLUMN account_id TEXT;
ALTER TABLE users ADD COLUMN role TEXT;
ALTER TABLE users ADD COLUMN name TEXT;

CREATE INDEX idx_users_account_id ON users(account_id);

-- Team invitations
CREATE TABLE team_invites (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  invited_email TEXT NOT NULL,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  accepted INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX idx_team_invites_token_hash ON team_invites(token_hash);
CREATE INDEX idx_team_invites_account_id ON team_invites(account_id);
