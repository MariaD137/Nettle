import { db, newId } from "../db";
import { getUserById } from "../auth/users";
import { getOrganization } from "../organizations/organizations";
import { entitledPlan } from "./subscription";
import { getMonthlyScanLimit } from "./entitlements";

/**
 * Who a scan's monthly allowance is actually drawn from. A project owned by
 * an organization that's actively subscribed itself draws from that
 * organization's own shared pool (every member's scans count against ONE
 * limit, not one limit each); anything else — a personal project, or an
 * org-owned project whose organization isn't actively subscribed — draws
 * from the triggering account's own personal quota, exactly as before this
 * type existed. See billing/orgSubscription.ts's resolveQuotaSubject(),
 * which is what actually decides which of the two applies for a given
 * scan — this file only knows how to reserve/count/record against
 * whichever subject it's handed.
 */
export type QuotaSubject = { type: "user"; userId: string } | { type: "organization"; organizationId: string };

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

/**
 * `organizationId` defaults to null (a personal-project scan, or an
 * org-project scan whose organization isn't actively subscribed — the
 * pre-existing behavior, unchanged for every call site that doesn't pass
 * it). Set only when the scan is actually billed to an organization's
 * shared pool (see recordQuotaUsage below) — `userId` still always records
 * who actually triggered it, for audit, regardless of which quota it drew
 * from.
 */
export async function recordScanUsage(userId: string, projectId: string | null, source: "upload" | "repo", organizationId: string | null = null): Promise<void> {
  await db.run("INSERT INTO scan_usage (id, user_id, project_id, organization_id, source, occurred_at) VALUES (?, ?, ?, ?, ?, ?)", [
    newId(),
    userId,
    projectId,
    organizationId,
    source,
    new Date().toISOString(),
  ]);
}

/** Records usage against whichever subject the scan was actually billed to — see recordScanUsage's own comment for what organization_id being set vs null means. */
export async function recordQuotaUsage(subject: QuotaSubject, triggeredByUserId: string, projectId: string | null, source: "upload" | "repo"): Promise<void> {
  await recordScanUsage(triggeredByUserId, projectId, source, subject.type === "organization" ? subject.organizationId : null);
}

export async function countScanUsage(userId: string, since: Date): Promise<number> {
  // CAST plus Number(): PostgreSQL returns COUNT(*) as bigint, which pg hands
  // back as a string to avoid precision loss. Without this the quota
  // comparison below would compare a string to a number.
  //
  // organization_id IS NULL: a scan billed to an organization's shared pool
  // must not ALSO count against the triggering member's own personal
  // quota — this is a no-op for every pre-existing row (organization_id
  // didn't exist before migration 008, so every row has it NULL already)
  // and only actually excludes newly-recorded org-billed scans.
  const row = await db.get<{ n: number | string }>(
    "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scan_usage WHERE user_id = ? AND organization_id IS NULL AND occurred_at >= ?",
    [userId, since.toISOString()]
  );
  return Number(row?.n ?? 0);
}

export async function countOrgScanUsage(organizationId: string, since: Date): Promise<number> {
  const row = await db.get<{ n: number | string }>(
    "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scan_usage WHERE organization_id = ? AND occurred_at >= ?",
    [organizationId, since.toISOString()]
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

/**
 * The organization equivalent of getQuotaState — the shared allowance every
 * member's scans of the organization's projects draw from, not any one
 * member's own number. `plan` is passed in rather than re-derived here: the
 * caller (routes/scans.routes.ts, via orgSubscription.ts's
 * resolveQuotaSubject) has already established the organization is
 * actively subscribed and to which plan by the time this is called — this
 * function only reports usage against that already-resolved plan/limit,
 * the same division of responsibility getQuotaState has with entitledPlan().
 */
export async function getOrgQuotaState(organizationId: string, plan: string): Promise<QuotaState | null> {
  const org = await getOrganization(organizationId);
  if (!org) return null;

  const limit = getMonthlyScanLimit(plan);
  const anchor = org.billingAnchor ?? org.createdAt;
  const { start, end } = currentPeriod(anchor);
  const used = await countOrgScanUsage(organizationId, start);

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
 * Same atomicity guarantee as reserveScanSlot (see that function's own
 * comment — check-then-act would let concurrent requests both win the last
 * slot), scoped to the organization's own shared bucket instead of one
 * member's. Five members submitting simultaneously against one remaining
 * slot: exactly one of these calls returns true, the rest false — verified
 * directly in test/organizationScanQuota.test.ts.
 */
export async function reserveOrgScanSlot(organizationId: string, limit: number): Promise<boolean> {
  const org = await getOrganization(organizationId);
  if (!org) return false;

  const anchor = org.billingAnchor ?? org.createdAt;
  const { start, end } = currentPeriod(anchor);
  // "org" in the key, not just the id, so an organization id can never
  // collide with a user id sharing the same string in the personal bucket
  // namespace (newId() draws from the same id space for both).
  const bucketKey = `scan-quota:org:${organizationId}:${start.toISOString()}`;

  const row = await db.get<{ count: number }>(
    `INSERT INTO rate_limit_buckets (bucket_key, count, reset_at)
     VALUES (?, 1, ?)
     ON CONFLICT (bucket_key) DO UPDATE SET count = rate_limit_buckets.count + 1
     RETURNING count`,
    [bucketKey, end.toISOString()]
  );

  return (row?.count ?? Infinity) <= limit;
}

/** Dispatches to reserveScanSlot/reserveOrgScanSlot for whichever QuotaSubject the scan was resolved to — see that type's own comment. */
export async function reserveQuotaSlot(subject: QuotaSubject, limit: number): Promise<boolean> {
  return subject.type === "organization" ? reserveOrgScanSlot(subject.organizationId, limit) : reserveScanSlot(subject.userId, limit);
}

/** Dispatches to getQuotaState/getOrgQuotaState for whichever QuotaSubject a scan was resolved to. */
export async function getQuotaStateForSubject(subject: QuotaSubject, plan: string): Promise<QuotaState | null> {
  return subject.type === "organization" ? getOrgQuotaState(subject.organizationId, plan) : getQuotaState(subject.userId);
}
