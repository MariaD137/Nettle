import { db, newId } from "../db";
import { getUserById } from "../auth/users";

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

export async function recordScanUsage(userId: string, projectId: string | null, source: "upload" | "repo"): Promise<void> {
  await db.run("INSERT INTO scan_usage (id, user_id, project_id, source, occurred_at) VALUES (?, ?, ?, ?, ?)", [newId(), userId, projectId, source, new Date().toISOString()]);
}

export async function countScanUsage(userId: string, since: Date): Promise<number> {
  // CAST plus Number(): PostgreSQL returns COUNT(*) as bigint, which pg hands
  // back as a string to avoid precision loss. Without this the quota
  // comparison below would compare a string to a number.
  const row = await db.get<{ n: number | string }>(
    "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scan_usage WHERE user_id = ? AND occurred_at >= ?",
    [userId, since.toISOString()]
  );
  return Number(row?.n ?? 0);
}

/**
 * Current allowance state for a user. Returns null for accounts with no
 * metered plan — the paywall has already turned those away, so there is no
 * meaningful quota to report.
 */
export async function getQuotaState(userId: string): Promise<QuotaState | null> {
  const user = await getUserById(userId);
  if (!user) return null;

  const limit = SCAN_QUOTAS[user.plan];
  if (limit === undefined) return null;

  // An account subscribed before this column existed has no anchor; fall
  // back to its signup date so it gets a sensible period rather than none.
  const anchor = user.billingAnchor ?? user.createdAt;
  const { start, end } = currentPeriod(anchor);
  const used = await countScanUsage(userId, start);

  return {
    limit,
    used,
    remaining: Math.max(0, limit - used),
    periodStart: start.toISOString(),
    periodEnd: end.toISOString(),
    exhausted: used >= limit,
  };
}
