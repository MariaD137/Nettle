-- Pricing rework: FREE / BUILD / PROTECT replaces free / tier1 / tier2.
-- Renames existing accounts' recorded plan in place — no accounts are
-- affected in their entitlements, only the string naming: an active tier1
-- account becomes an active build account with the exact same billing
-- anchor, subscription status, and Stripe customer id it had before.
UPDATE users SET plan = 'build' WHERE plan = 'tier1';
UPDATE users SET plan = 'protect' WHERE plan = 'tier2';
