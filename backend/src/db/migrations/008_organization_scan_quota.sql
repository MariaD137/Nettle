-- Organization-aware scan quotas: a project owned by an actively-subscribed
-- organization draws from that organization's own shared monthly
-- allowance (its members' scans pool together against ONE limit, not one
-- limit each) instead of the triggering member's personal quota.
--
-- billing_anchor mirrors users.billing_anchor (001_baseline.sql) exactly —
-- stamped once, the first time the organization becomes actively
-- subscribed, never overwritten, so its monthly period is derived the same
-- way a personal account's is (billing/scanQuota.ts's currentPeriod()).
ALTER TABLE organizations ADD COLUMN billing_anchor TEXT;

-- Nullable: a personal-project scan (or an org-project scan whose
-- organization isn't actively subscribed, which still falls back to the
-- triggering user's own quota) leaves this NULL, exactly like today.
-- Only a scan actually billed to an organization's shared pool sets it —
-- see billing/scanQuota.ts's resolveQuotaSubject(). user_id is still
-- always recorded either way (who triggered it, for audit), so an
-- organization-billed row is identified by organization_id being set, not
-- by user_id being absent.
ALTER TABLE scan_usage ADD COLUMN organization_id TEXT;
CREATE INDEX IF NOT EXISTS idx_scan_usage_organization_time ON scan_usage(organization_id, occurred_at);
