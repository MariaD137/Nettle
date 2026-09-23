import { db, newId } from "../db";
import { getUserById } from "../auth/users";
import { entitledPlan } from "./subscription";
import { getMonthlyScanLimit } from "./entitlements";

/**
 * Monthly scan allowance per plan — the metered dimension the subscription
 * actually buys. The actual source of truth is entitlements.ts's
 * getMonthlyScanLimit(); this constant exists only so callers that need the
 * finite (non-null) BUILD number specifically — the paywall copy
 * cross-check test, the usage-UI "X remaining" copy — don't have to guard
 * against null themselves. FREE's 0 means "no scan access at all", not "a
 * quota of zero to exhaust"; PROTECT's unlimited/fair-use entitlement is
 * represented as null (getMonthlyScanLimit), never as a large number
 * standing in for "unlimited" — see getQuotaState below for how a null
 * limit is reported.
 */
export const SCAN_QUOTAS: Record<"build", number> = {
  build: 10,
};

export interface QuotaState {
  /** null = unlimited/fair-use (PROTECT). */
  limit: number | null;
  used: number;
  /** null when the limit is unlimited — there is no "remaining count" to report. */
  remaining: number | null;
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
 * Current allowance state for a user, covering all three plans — including
 * FREE, which is a real reachable dashboard state now (not turned away
 * before reaching here), so the usage UI has something to render
 * ("Scanning is available on BUILD and PROTECT") rather than null. null is
 * reserved for "no such user", not "no metered plan".
 */
export async function getQuotaState(userId: string): Promise<QuotaState | null> {
  const user = await getUserById(userId);
  if (!user) return null;

  const plan = entitledPlan(user);
  const limit = getMonthlyScanLimit(plan);

  // An account subscribed before this column existed has no anchor; fall
  // back to its signup date so it gets a sensible period rather than none.
  const anchor = user.billingAnchor ?? user.createdAt;
  const { start, end } = currentPeriod(anchor);
  const used = await countScanUsage(userId, start);

  return {
    limit,
    used,
    remaining: limit === null ? null : Math.max(0, limit - used),
    periodStart: start.toISOString(),
    periodEnd: end.toISOString(),
    exhausted: limit !== null && used >= limit,
  };
}

/**
 * Atomically reserves one scan slot for `userId`'s current billing period,
 * returning whether the reservation succeeded. This is the actual quota
 * *enforcement* — getQuotaState above is for display, and reading it and
 * then separately deciding "used < limit, so allow it" would be exactly the
 * check-then-act race two concurrent requests could both win, each seeing
 * the pre-increment count and both proceeding past a limit of one remaining
 * slot.
 *
 * Reuses rate_limit_buckets (see middleware/rateLimit.ts) rather than a new
 * table: the same `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` shape is
 * already the proven atomic primitive this codebase uses for "increment a
 * counter and read the post-increment value in one indivisible step",
 * verified identical on both SQLite and PostgreSQL. The bucket key
 * incorporates the period's own start timestamp, so a new billing period
 * gets a fresh bucket automatically — no explicit reset step, and the old
 * bucket is swept by the existing purgeExpiredRateLimitBuckets cleanup once
 * its reset_at (set to the period end) has passed.
 *
 * A rejected reservation still increments the bucket. That's fine — the
 * bucket only ever needs to answer "have we reached the limit", not "how
 * many scans actually ran" (that's scan_usage/countScanUsage, used for
 * display), so a burst of rejected retries beyond the limit just keeps the
 * bucket comfortably over it rather than needing to be rolled back.
 *
 * FREE (limit 0) and PROTECT (unlimited) never call this — see
 * routes/scans.routes.ts, which checks canRunScan()/getMonthlyScanLimit()
 * before ever reaching a reservation attempt.
 */
export async function reserveScanSlot(userId: string, limit: number): Promise<boolean> {
  const user = await getUserById(userId);
  if (!user) return false;

  const anchor = user.billingAnchor ?? user.createdAt;
  const { start, end } = currentPeriod(anchor);
  // The period's own start is part of the key, so a new billing period is
  // automatically a fresh bucket — no reset-on-expiry branch needed the way
  // the rate limiter's reused-key buckets require (see incrementBucket in
  // middleware/rateLimit.ts): this key is never reused across periods.
  const bucketKey = `scan-quota:${userId}:${start.toISOString()}`;

  const row = await db.get<{ count: number }>(
    `INSERT INTO rate_limit_buckets (bucket_key, count, reset_at)
     VALUES (?, 1, ?)
     ON CONFLICT (bucket_key) DO UPDATE SET count = rate_limit_buckets.count + 1
     RETURNING count`,
    [bucketKey, end.toISOString()]
  );

  return (row?.count ?? Infinity) <= limit;
}
