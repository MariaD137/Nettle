import { db } from "../db/index";

// Configurable data retention. Each window is in days, read from env at
// call time (not cached) so a scheduled trigger always sees the current
// config, not whatever was set when the process started. A window of 0
// (or unset, for categories with no sane always-on default) disables
// deletion for that category — an explicit off-switch, not silent no-op.
//
// Deliberately NEVER touches: users, sessions, projects, scan_usage,
// payment_failures, or anything else that is account/subscription/billing
// history. Only the categories the retention policy actually names: Tier 2
// events, alerts, scan reports, and outbound webhook delivery records.
// Temporary uploads (zip files, extracted archives) are not a retention
// concern here — they're already cleaned up synchronously at the end of
// every scan job, including on timeout/cancellation (see jobs/scanJobs.ts).

function retentionDays(envVar: string, defaultDays: number): number {
  const raw = process.env[envVar];
  if (raw === undefined) return defaultDays;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : defaultDays;
}

export interface RetentionConfig {
  eventsDays: number;
  alertsDays: number;
  scansDays: number;
  webhookEventsDays: number;
}

export function getRetentionConfig(): RetentionConfig {
  return {
    eventsDays: retentionDays("RETENTION_EVENTS_DAYS", 90),
    alertsDays: retentionDays("RETENTION_ALERTS_DAYS", 180),
    scansDays: retentionDays("RETENTION_SCANS_DAYS", 365),
    webhookEventsDays: retentionDays("RETENTION_WEBHOOK_EVENTS_DAYS", 30),
  };
}

export interface RetentionCleanupResult {
  eventsDeleted: number;
  alertsDeleted: number;
  scansDeleted: number;
  webhookEventsDeleted: number;
  config: RetentionConfig;
}

function deleteOlderThan(table: string, timestampColumn: string, days: number): number {
  if (days <= 0) return 0; // 0 = retention disabled for this category
  const result = db
    .prepare(`DELETE FROM ${table} WHERE ${timestampColumn} < datetime('now', ?)`)
    .run(`-${days} days`);
  return Number(result.changes ?? 0);
}

/**
 * Deletes rows older than their configured retention window. Safe to call
 * repeatedly (a scheduled AWS trigger — EventBridge, App Runner cron, etc.
 * — is expected to call this on a recurring schedule; nothing in-process
 * schedules it, matching how the digest trigger in internal.routes.ts
 * already works). Returns real counts of what was actually deleted, never
 * an estimate.
 */
export function runRetentionCleanup(): RetentionCleanupResult {
  const config = getRetentionConfig();
  return {
    eventsDeleted: deleteOlderThan("events", "occurred_at", config.eventsDays),
    alertsDeleted: deleteOlderThan("alerts", "occurred_at", config.alertsDays),
    scansDeleted: deleteOlderThan("scans", "scanned_at", config.scansDays),
    webhookEventsDeleted: deleteOlderThan("webhook_events", "created_at", config.webhookEventsDays),
    config,
  };
}
