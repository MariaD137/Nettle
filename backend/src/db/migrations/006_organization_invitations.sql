-- Organization invitations (deferred item, now implemented). Mirrors
-- password_resets exactly: only a hash of the token is ever stored, so a
-- database read (backup, log export, injection) never yields a replayable
-- credential. token_hash is UNIQUE so a hash collision (practically
-- impossible with SHA-256 over a 32-byte random token, but cheap to assert
-- at the schema level anyway) can never let two invitations resolve to the
-- same lookup.
CREATE TABLE IF NOT EXISTS organization_invitations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  token_hash TEXT NOT NULL UNIQUE,
  invited_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  -- NULL until accepted. A non-NULL value is what makes the invitation
  -- single-use: acceptance checks this is still NULL before creating the
  -- membership, then stamps it in the same transaction.
  accepted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON organization_invitations(email);
