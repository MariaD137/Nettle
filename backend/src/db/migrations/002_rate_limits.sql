-- Shared rate-limit counters.
--
-- Backs the rate limiter in src/middleware/rateLimit.ts. It lives in this
-- database rather than an in-memory Map so the limit is enforced correctly
-- when App Runner runs more than one instance — each instance updates the
-- same row for a given (scope, identity), so the count is real across the
-- fleet, not per-process. It is also why this needed no new AWS resource
-- (Redis/DynamoDB): the database horizontal-scaling already requires is
-- enough for this.
--
-- bucket_key encodes both the logical scope ("auth:login", "scans:upload", …)
-- and the caller's identity within it (IP, user id, project id, or API key),
-- so unrelated scopes and unrelated callers never share a counter.
--
-- Dialect-neutral like the baseline: TEXT primary key, INTEGER count,
-- ISO-8601 TEXT timestamp compared lexicographically, exactly as sessions and
-- password_resets already do it.

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  reset_at TEXT NOT NULL
);

-- Sweeps read reset_at directly (see purgeExpiredRateLimitBuckets), no
-- separate index needed beyond the primary key.
