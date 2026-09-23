-- Organizations (Phase D scoped MVP): owner/member roles, projects can
-- optionally belong to an organization instead of a single user.
--
-- Deliberately minimal, per this round's explicit scope: no invitations (a
-- member is added directly by email, must already have a Nettle account),
-- no per-organization billing (plan/subscription stay on the user row —
-- project-count limits are still checked against the creating user's own
-- plan). Both are real gaps for a full multi-tenant product, left for a
-- later, larger round rather than folded into this one.
--
-- owner_id on organizations is a convenience denormalization (who founded
-- it, checked without a join) — the owner also always has a row in
-- organization_members with role 'owner', which is the table every
-- membership/role check actually queries.

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_organizations_owner ON organizations(owner_id);

CREATE TABLE IF NOT EXISTS organization_members (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL DEFAULT 'member',
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_members_unique ON organization_members(organization_id, user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- Nullable: an existing project keeps organization_id NULL and stays a
-- personal project owned solely by projects.user_id, unchanged. Only a
-- project deliberately created under an organization sets this.
ALTER TABLE projects ADD COLUMN organization_id TEXT;
CREATE INDEX IF NOT EXISTS idx_projects_organization ON projects(organization_id);
