import { Request, Response, NextFunction } from 'express';

interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  message?: string;
}

interface LegacyRateLimitEntry {
  count: number;
  resetAt: number;
}

const legacyBuckets = new Map<string, LegacyRateLimitEntry>();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of legacyBuckets) {
    if (entry.resetAt <= now) legacyBuckets.delete(key);
  }
}, 60_000).unref();

// Configurable per-route rate limiter factory (used by auth routes for
// stricter limits on signup/login).
export function rateLimit(options: RateLimitOptions) {
  const { windowMs, maxRequests, message = "Too many requests — try again later" } = options;

  return function rateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
    const key = `${req.path}:${req.ip}`;
    const now = Date.now();
    let entry = legacyBuckets.get(key);

    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      legacyBuckets.set(key, entry);
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

interface RateLimitStore {
  [key: string]: { count: number; resetTime: number };
}

class RateLimiter {
  private store: RateLimitStore = {};
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Clean up expired entries every 60 seconds
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const key in this.store) {
        if (this.store[key].resetTime < now) {
          delete this.store[key];
        }
      }
    }, 60000).unref();
  }

  private getKey(req: Request, prefix: string): string {
    // Use IP for unauthenticated endpoints, user ID for authenticated
    const identifier = (req as any).user?.id || req.ip || req.socket.remoteAddress || 'unknown';
    return `${prefix}:${identifier}`;
  }

  isLimited(
    req: Request,
    maxRequests: number,
    windowSeconds: number,
    prefix: string = 'default'
  ): boolean {
    const key = this.getKey(req, prefix);
    const now = Date.now();

    if (!this.store[key]) {
      this.store[key] = { count: 1, resetTime: now + windowSeconds * 1000 };
      return false;
    }

    if (this.store[key].resetTime < now) {
      this.store[key] = { count: 1, resetTime: now + windowSeconds * 1000 };
      return false;
    }

    this.store[key].count++;
    return this.store[key].count > maxRequests;
  }

  getRetryAfter(req: Request, prefix: string = 'default'): number {
    const key = this.getKey(req, prefix);
    if (!this.store[key]) return 0;

    const secondsUntilReset = Math.ceil((this.store[key].resetTime - Date.now()) / 1000);
    return Math.max(0, secondsUntilReset);
  }

  destroy() {
    clearInterval(this.cleanupInterval);
  }
}

const limiter = new RateLimiter();

// Scan endpoint rate limiter: 30 concurrent requests per minute per user
export function scanRateLimit(req: Request, res: Response, next: NextFunction) {
  if (limiter.isLimited(req, 30, 60, 'scan')) {
    const retryAfter = limiter.getRetryAfter(req, 'scan');
    return res.status(429).json({
      error: 'Too many scan requests. Please try again later.',
      retryAfter,
    });
  }
  next();
}

// Public endpoint rate limiter: 100 requests per 5 minutes per IP
export function publicRateLimit(req: Request, res: Response, next: NextFunction) {
  if (limiter.isLimited(req, 100, 300, 'public')) {
    const retryAfter = limiter.getRetryAfter(req, 'public');
    return res.status(429).json({
      error: 'Too many requests. Please try again later.',
      retryAfter,
    });
  }
  next();
}

// Webhook delivery rate limiter: 1000 per minute per project
export function webhookRateLimit(req: Request, res: Response, next: NextFunction) {
  const projectId = (req as any).params?.projectId || 'unknown';
  const key = `webhook:${projectId}`;

  if (limiter.isLimited(req, 1000, 60, key)) {
    const retryAfter = limiter.getRetryAfter(req, key);
    return res.status(429).json({
      error: 'Webhook delivery rate limit exceeded.',
      retryAfter,
    });
  }
  next();
}

// General API rate limiter: 500 requests per minute per authenticated user
export function apiRateLimit(req: Request, res: Response, next: NextFunction) {
  if (limiter.isLimited(req, 500, 60, 'api')) {
    const retryAfter = limiter.getRetryAfter(req, 'api');
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({
      error: 'Rate limit exceeded. Please try again later.',
      retryAfter,
    });
  }
  next();
}

export { limiter };
