-- Additive per-organization billing: an organization can optionally carry
-- its own Stripe subscription, independent of its owner's personal one.
--
-- Deliberately additive, not a migration: every column here defaults to the
-- unsubscribed state ('none'/NULL), so every existing organization is
-- unaffected and keeps resolving entitlement from its owner's personal plan
-- exactly as before (see billing/orgSubscription.ts's fallback). Nothing
-- here touches users.plan/stripe_customer_id/subscription_status, and no
-- existing account's billing is migrated onto its organization automatically
-- — an owner has to actively subscribe the organization for this to do
-- anything.
--
-- Mirrors users' own billing columns (001_baseline.sql,
-- 003_webhook_ledger.sql) rather than inventing a different shape, so the
-- webhook handler and subscription-state logic can reuse the same pattern
-- for both.
ALTER TABLE organizations ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';
ALTER TABLE organizations ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE organizations ADD COLUMN subscription_status TEXT NOT NULL DEFAULT 'none';
ALTER TABLE organizations ADD COLUMN last_subscription_event_at TEXT;
CREATE INDEX IF NOT EXISTS idx_organizations_stripe_customer ON organizations(stripe_customer_id);
