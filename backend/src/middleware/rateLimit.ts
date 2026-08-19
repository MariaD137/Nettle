interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  message?: string;
  // Defaults to path+IP. Override to key by something else — e.g. the
  // authenticated user ID once auth middleware has run, or a project API
  // key for a public ingest endpoint where IP alone is the wrong unit (a
  // customer's app server has one stable IP shared by all its traffic).
  keyGenerator?: (req: import("express").Request) => string;
}

const buckets = new Map<string, RateLimitEntry>();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of buckets) {
    if (entry.resetAt <= now) buckets.delete(key);
  }
}, 60_000).unref();

export function rateLimit(options: RateLimitOptions) {
  const { windowMs, maxRequests, message = "Too many requests — try again later", keyGenerator } = options;

  return function rateLimitMiddleware(
    req: import("express").Request,
    res: import("express").Response,
    next: import("express").NextFunction
  ) {
    const key = keyGenerator ? keyGenerator(req) : `${req.path}:${req.ip}`;
    const now = Date.now();
    let entry = buckets.get(key);

    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      buckets.set(key, entry);
    }

    entry.count++;

    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, maxRequests - entry.count));
    res.setHeader("X-RateLimit-Reset", Math.ceil(entry.resetAt / 1000));

    if (entry.count > maxRequests) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader("Retry-After", retryAfter);
      return res.status(429).json({ error: message });
    }

    next();
  };
}
