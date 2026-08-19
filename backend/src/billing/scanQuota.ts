import { db, newId } from "../db";
import { getUserById } from "../auth/users";
import { hasPaidEntitlement } from "./entitlement";

/**
 * Monthly scan allowance per plan — the metered dimension the subscription
 * actually buys. Change a number here and the API, the dashboard and the
 * paywall copy all follow.
 *
 * Keep in sync with the "N scans per month" lines in frontend/src/plans.ts:
 * that copy is what a customer is quoted, this table is what they get.
 */
export const SCAN_QUOTAS: Record<string, number> = {
  tier1: 30,
  tier2: 60,
};

export interface QuotaState {
  limit: number;
  used: number;
  remaining: number;
  periodStart: string;
  periodEnd: string;
  exhausted: boolean;
}

/**
 * Adds whole months without rolling over the end of a short month: an
 * anchor on the 31st lands on the 28th/30th rather than skipping into the
 * following month, which is the behaviour Stripe's billing cycle has too.
 */
function addMonths(date: Date, months: number): Date {
  const d = new Date(date);
  const targetDay = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() + months);
  const daysInTargetMonth = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(targetDay, daysInTargetMonth));
  return d;
}

/**
 * The billing period containing `now`, derived by rolling the anchor forward
 * a month at a time. Deriving it rather than storing a moving pointer means
 * a missed cron run or a container restart can't leave someone stuck in a
 * stale period.
 */
export function currentPeriod(anchorIso: string, now = new Date()): { start: Date; end: Date } {
  let start = new Date(anchorIso);
  if (Number.isNaN(start.getTime())) start = new Date(now);

  // Anchor in the future (clock skew, or an anchor set on signup): treat the
  // anchor itself as the period start.
  if (start > now) return { start, end: addMonths(start, 1) };

  let end = addMonths(start, 1);
  while (end <= now) {
    start = end;
    end = addMonths(start, 1);
  }
  return { start, end };
}

export function recordScanUsage(userId: string, projectId: string | null, source: "upload" | "repo" | "url"): void {
  db.prepare(
    "INSERT INTO scan_usage (id, user_id, project_id, source, occurred_at) VALUES (?, ?, ?, ?, ?)"
  ).run(newId(), userId, projectId, source, new Date().toISOString());
}

export function countScanUsage(userId: string, since: Date): number {
  const row = db
    .prepare("SELECT COUNT(*) AS n FROM scan_usage WHERE user_id = ? AND occurred_at >= ?")
    .get(userId, since.toISOString()) as { n: number } | undefined;
  return row?.n ?? 0;
}

/** Shared by getQuotaState and reserveScanUsage — the plan/period/limit an
 * account is metered against right now, or null if it isn't metered at all. */
function meteredContext(userId: string): { limit: number; anchor: string } | null {
  const user = getUserById(userId);
  if (!user) return null;
  if (!hasPaidEntitlement(user)) return null;

  const limit = SCAN_QUOTAS[user.plan];
  if (limit === undefined) return null;

  // An account subscribed before this column existed has no anchor; fall
  // back to its signup date so it gets a sensible period rather than none.
  return { limit, anchor: user.billingAnchor ?? user.createdAt };
}

/**
 * Current allowance state for a user. Returns null for accounts with no
 * currently-active paid entitlement — a free account, or one whose
 * subscription lapsed (canceled, past_due, etc) even if `plan` still says
 * "tier1"/"tier2" because nothing has reset it yet. Those callers fall back
 * to preview-tier scanning like any other free caller; there is no metered
 * quota to report because there is no paid allowance to meter.
 */
export function getQuotaState(userId: string): QuotaState | null {
  const ctx = meteredContext(userId);
  if (!ctx) return null;

  const { start, end } = currentPeriod(ctx.anchor);
  const used = countScanUsage(userId, start);

  return {
    limit: ctx.limit,
    used,
    remaining: Math.max(0, ctx.limit - used),
    periodStart: start.toISOString(),
    periodEnd: end.toISOString(),
    exhausted: used >= ctx.limit,
  };
}

export interface QuotaReservation {
  // false unless the account is genuinely metered AND already at its
  // limit — an unmetered (free/lapsed) account is never blocked here.
  blocked: boolean;
  // Set only when a usage slot was actually reserved (a metered account
  // under its limit). Pass to releaseScanUsage() if the scan this was
  // reserved for subsequently fails, so a failed attempt still doesn't
  // count against the allowance.
  usageId: string | null;
  quota: QuotaState | null;
}

/**
 * Atomically checks quota and reserves one unit of usage in a single pass,
 * with no `await` between the check and the insert.
 *
 * This replaces the previous pattern of checking quota, then — only after
 * the scan itself had already run — calling recordScanUsage(). That left a
 * real TOCTOU window: several scan submissions from the same account,
 * arriving close together, could each observe the same not-yet-exhausted
 * count before any of them recorded usage, together exceeding the
 * account's allowance. node:sqlite executes each statement synchronously,
 * so as long as nothing yields the event loop between the COUNT and the
 * INSERT below, two concurrent callers can't both observe "not yet at the
 * limit" for what should have been the last available slot.
 */
export function reserveScanUsage(
  userId: string | undefined,
  projectId: string | null,
  source: "upload" | "repo" | "url"
): QuotaReservation {
  if (!userId) return { blocked: false, usageId: null, quota: null };

  const ctx = meteredContext(userId);
  if (!ctx) return { blocked: false, usageId: null, quota: null };

  const { start, end } = currentPeriod(ctx.anchor);
  const used = countScanUsage(userId, start);

  if (used >= ctx.limit) {
    return {
      blocked: true,
      usageId: null,
      quota: {
        limit: ctx.limit,
        used,
        remaining: 0,
        periodStart: start.toISOString(),
        periodEnd: end.toISOString(),
        exhausted: true,
      },
    };
  }

  const usageId = newId();
  db.prepare(
    "INSERT INTO scan_usage (id, user_id, project_id, source, occurred_at) VALUES (?, ?, ?, ?, ?)"
  ).run(usageId, userId, projectId, source, new Date().toISOString());

  const newUsed = used + 1;
  return {
    blocked: false,
    usageId,
    quota: {
      limit: ctx.limit,
      used: newUsed,
      remaining: Math.max(0, ctx.limit - newUsed),
      periodStart: start.toISOString(),
      periodEnd: end.toISOString(),
      exhausted: newUsed >= ctx.limit,
    },
  };
}

/** Refunds a reservation for a scan that didn't actually succeed. No-op for
 * a null id (an unmetered account's reservation, which never reserved
 * anything to begin with). */
export function releaseScanUsage(usageId: string | null): void {
  if (!usageId) return;
  db.prepare("DELETE FROM scan_usage WHERE id = ?").run(usageId);
}
