// In-process metrics registry — counters and simple duration stats, held in
// memory and reset on restart. This is intentionally not a Prometheus/
// StatsD exporter: there's nothing on the other end to scrape it yet, and
// building a full metrics pipeline before there's an AWS deployment to
// send it to would be exactly the kind of premature infrastructure this
// pass is supposed to avoid. What this gives real value today is the
// admin overview endpoint (see routes/admin.routes.ts) reading a live
// snapshot of what this process has actually done since it started.

interface DurationStats {
  count: number;
  totalMs: number;
  minMs: number;
  maxMs: number;
}

const counters = new Map<string, number>();
const durations = new Map<string, DurationStats>();
const processStartedAt = Date.now();

export function incrementCounter(name: string, by: number = 1): void {
  counters.set(name, (counters.get(name) ?? 0) + by);
}

export function observeDuration(name: string, ms: number): void {
  const existing = durations.get(name);
  if (!existing) {
    durations.set(name, { count: 1, totalMs: ms, minMs: ms, maxMs: ms });
    return;
  }
  existing.count += 1;
  existing.totalMs += ms;
  existing.minMs = Math.min(existing.minMs, ms);
  existing.maxMs = Math.max(existing.maxMs, ms);
}

export interface MetricsSnapshot {
  uptimeSeconds: number;
  counters: Record<string, number>;
  durations: Record<string, { count: number; avgMs: number; minMs: number; maxMs: number }>;
}

export function getMetricsSnapshot(): MetricsSnapshot {
  const durationsOut: MetricsSnapshot["durations"] = {};
  for (const [name, stats] of durations) {
    durationsOut[name] = {
      count: stats.count,
      avgMs: Math.round(stats.totalMs / stats.count),
      minMs: stats.minMs,
      maxMs: stats.maxMs,
    };
  }
  return {
    uptimeSeconds: Math.round((Date.now() - processStartedAt) / 1000),
    counters: Object.fromEntries(counters),
    durations: durationsOut,
  };
}

/** Test-only: resets all in-memory metrics state between test runs. */
export function _resetMetricsForTests(): void {
  counters.clear();
  durations.clear();
}

// Metric name constants — not an enum/union type, deliberately: routes and
// services across the codebase increment these by string name, and a
// shared constant list here is enough to keep names consistent without
// forcing every caller to import a type.
export const Metric = {
  HttpRequests: "http_requests_total",
  HttpErrors: "http_errors_total",
  ScanFailures: "scan_failures_total",
  ScanDuration: "scan_duration_ms",
  AuthFailures: "auth_failures_total",
  RateLimitExceeded: "rate_limit_exceeded_total",
  StripeWebhookFailures: "stripe_webhook_failures_total",
  WebhookDeliveryFailures: "webhook_delivery_failures_total",
  NotificationDeliveryFailures: "notification_delivery_failures_total",
  AlertsGenerated: "alerts_generated_total",
} as const;
