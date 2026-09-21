import type { NextFunction, Request, Response } from "express";
import { db } from "../db";

/**
 * Shared, database-backed rate limiting.
 *
 * The previous implementation kept counts in an in-memory Map. That is
 * unsafe once App Runner runs more than one instance (each process only sees
 * its own share of traffic, so the real per-caller rate could be N times the
 * configured limit with N instances) and a fresh instance also forgets every
 * counter on redeploy.
 *
 * This version stores counters in `rate_limit_buckets` (see
 * src/db/migrations/002_rate_limits.sql) — the same database every App
 * Runner instance already uses for everything else. That gives a shared,
 * fleet-wide counter without adding a new AWS resource (Redis, DynamoDB): the
 * horizontal-scaling story this needs already exists for the rest of the
 * application's state.
 *
 * The tradeoff is one extra DB round trip per rate-limited request. That is
 * only paid on the specific routes this is applied to (auth, scans, events,
 * badge) — not on every request — and those routes already do meaningfully
 * more work (password hashing, file extraction, Semgrep) than one UPSERT.
 *
 * The increment itself is a single UPSERT with RETURNING, so the
 * read-window/increment/reset-if-expired decision is one atomic statement,
 * not a separate SELECT-then-UPDATE that could race between two instances
 * hitting the same key at once. Verified identical on both engines (SQLite
 * 3.24+ and PostgreSQL both support `ON CONFLICT ... DO UPDATE ... RETURNING`
 * with this exact shape).
 */

export interface RateLimitOptions {
  /** Rolling window length. */
  windowMs: number;
  /** Requests allowed per identity per window. */
  maxRequests: number;
  message?: string;
  /**
   * Names this limiter's bucket namespace, e.g. "auth:login", "scans:upload".
   * Combined with the resolved identity to form the storage key, so the same
   * IP hitting two different limited routes gets two independent counters.
   */
  scope: string;
  /**
   * Resolves the identity a request is metered against. Defaults to the
   * client IP (see requireCorrectClientIp / trust-proxy setup in index.ts).
   *
   * Async because some routes need a DB lookup to find the right identity
   * (e.g. resolving an API key to the project/owner it belongs to) — and
   * because preferring an authenticated identity over the raw IP, where one
   * is available, is what keeps many unrelated customers behind the same
   * corporate NAT or shared CI runner from throttling each other.
   *
   * Returning null skips rate limiting for that request entirely (used for
   * "there is no meaningful identity to meter yet", not as a bypass).
   */
  keyFn?: (req: Request) => string | null | Promise<string | null>;
}

const defaultKeyFn = (req: Request): string => req.ip ?? "unknown";

interface BucketRow {
  count: number;
  reset_at: string;
}

/**
 * Atomically increments the counter for `bucketKey`, resetting it first if
 * the previous window has expired. Returns the resulting count and the
 * window's reset time.
 *
 * A single statement so two instances incrementing the same key at the same
 * moment cannot both read a stale pre-increment value and undercount — each
 * UPSERT is applied to the row in full before the next one starts.
 */
async function incrementBucket(bucketKey: string, windowMs: number): Promise<BucketRow> {
  const now = new Date();
  const nowIso = now.toISOString();
  const newResetAt = new Date(now.getTime() + windowMs).toISOString();

  const row = await db.get<BucketRow>(
    `INSERT INTO rate_limit_buckets (bucket_key, count, reset_at)
     VALUES (?, 1, ?)
     ON CONFLICT (bucket_key) DO UPDATE SET
       count = CASE WHEN rate_limit_buckets.reset_at <= ? THEN 1 ELSE rate_limit_buckets.count + 1 END,
       reset_at = CASE WHEN rate_limit_buckets.reset_at <= ? THEN ? ELSE rate_limit_buckets.reset_at END
     RETURNING count, reset_at`,
    [bucketKey, newResetAt, nowIso, nowIso, newResetAt]
  );

  // RETURNING always yields a row for an UPSERT that touched exactly one key.
  return row!;
}

export function rateLimit(options: RateLimitOptions) {
  const { windowMs, maxRequests, message = "Too many requests — try again later", scope, keyFn = defaultKeyFn } = options;

  return async function rateLimitMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    let identity: string | null;
    try {
      identity = await keyFn(req);
    } catch (err) {
      // Resolving identity (e.g. an API-key lookup) failed. Treat it the same
      // as a backing-store failure below: do not let a rate limiter's own
      // error block a request that has nothing to do with rate limiting.
      console.warn(`[rate-limit] key resolution failed for scope "${scope}": ${(err as Error).message}`);
      return next();
    }
    if (identity === null) return next();

    const bucketKey = `${scope}:${identity}`;

    let bucket: BucketRow;
    try {
      bucket = await incrementBucket(bucketKey, windowMs);
    } catch (err) {
      // Fail OPEN, not closed: a database hiccup must not take down login,
      // signup or scanning. The alternative (fail closed) turns a transient
      // DB blip into a full outage of every rate-limited route at once,
      // which is a worse failure than briefly running without this
      // particular protection layer. Logged so a sustained failure is
      // visible in CloudWatch rather than silent.
      console.warn(`[rate-limit] backing store error for scope "${scope}": ${(err as Error).message}`);
      return next();
    }

    const resetAtMs = new Date(bucket.reset_at).getTime();
    const remaining = Math.max(0, maxRequests - bucket.count);

    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", remaining);
    res.setHeader("X-RateLimit-Reset", Math.ceil(resetAtMs / 1000));

    if (bucket.count > maxRequests) {
      const retryAfter = Math.max(0, Math.ceil((resetAtMs - Date.now()) / 1000));
      res.setHeader("Retry-After", retryAfter);
      res.status(429).json({ error: message });
      return;
    }

    next();
  };
}

/**
 * Deletes expired buckets in bounded batches rather than one unbounded
 * DELETE, so a large backlog cannot hold a table lock for long or run as one
 * huge transaction. Safe to call redundantly from multiple App Runner
 * instances — each just deletes whatever is still expired when it runs.
 *
 * Called from a periodic sweep (see startRateLimitCleanup) rather than
 * needing a separate scheduled AWS resource: this table's growth is bounded
 * by (distinct scopes) × (distinct recent identities), which is modest, so an
 * in-process sweep is enough. Contrast with events/audit-log retention
 * (Phase 12, not yet implemented), which needs a real scheduled job because
 * that table's volume scales with customer traffic, not with rate-limit
 * scope count.
 */
export async function purgeExpiredRateLimitBuckets(batchSize = 500): Promise<number> {
  const nowIso = new Date().toISOString();
  const result = await db.run(
    `DELETE FROM rate_limit_buckets WHERE bucket_key IN (
       SELECT bucket_key FROM rate_limit_buckets WHERE reset_at < ? LIMIT ?
     )`,
    [nowIso, batchSize]
  );
  return result.changes;
}

let cleanupTimer: NodeJS.Timeout | null = null;

/** Starts the periodic sweep. Idempotent — calling it twice is a no-op. */
export function startRateLimitCleanup(intervalMs = 5 * 60_000): void {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    purgeExpiredRateLimitBuckets().catch((err) => {
      console.warn(`[rate-limit] cleanup sweep failed: ${(err as Error).message}`);
    });
  }, intervalMs);
  cleanupTimer.unref();
}

export function stopRateLimitCleanup(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}
