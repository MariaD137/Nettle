import { db } from "../db";
import geoip from "geoip-lite";
import type { AlertSeverity } from "./types";

interface AlertRow {
  occurred_at: string;
  severity: string;
  rule: string;
  message: string;
}

export interface TimelineBucket {
  hour: string; // ISO hour, e.g. "2026-02-01T14:00:00Z"
  count: number;
  bySeverity: Record<AlertSeverity, number>;
}

export interface RankedCount {
  label: string;
  count: number;
}

export interface AlertAnalytics {
  timeline: TimelineBucket[];
  topAttackTypes: RankedCount[];
  topEndpoints: RankedCount[];
  topCountries: RankedCount[];
}

// Rule identifiers that runDetection() (patrol/detection.ts) suffixes with a
// per-IP or per-path identifier, e.g. "suspicious-path-203.0.113.5". Ranking
// raw `rule` values would fragment one attack type across every distinct
// attacker, so these get stripped back to their base name first.
const SUFFIXED_RULE_PREFIXES = [
  "suspicious-path-",
  "sqli-shaped-",
  "xss-shaped-",
  "cmdi-shaped-",
  "suspicious-user-agent-",
  "credential-stuffing-",
];

/**
 * Collapses a stored alert's `rule` field back to its attack-type name.
 * "brute-force" and "high-request-rate" already are the base name.
 * "custom-rule-<ruleId>" collapses to "custom-rule" — the id varies per
 * project and isn't a distinct attack type on its own.
 */
export function normalizeAttackType(rule: string): string {
  for (const prefix of SUFFIXED_RULE_PREFIXES) {
    if (rule.startsWith(prefix)) return prefix.slice(0, -1);
  }
  if (rule.startsWith("custom-rule-")) return "custom-rule";
  return rule;
}

// Every detection.ts alert message that names a specific request wraps the
// path in double quotes (`Request to "${event.path}" from ...`), so this is
// a real extraction of what the rule actually flagged, not a guess — alerts
// with no single associated path (brute-force, high-request-rate,
// custom-rule) simply yield no match and are excluded from the ranking.
export function extractEndpoint(message: string): string | null {
  const match = /"([^"]+)"/.exec(message);
  return match ? match[1] : null;
}

const IP_PATTERN = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

// Most detection.ts alert messages name the single IP responsible
// ("... from ${event.ip}"), and per-IP rules also carry it as a rule-name
// suffix. credential-stuffing (many IPs, by design) and custom-rule alerts
// carry no single attributable IP and correctly yield no match here.
export function extractIp(rule: string, message: string): string | null {
  const match = IP_PATTERN.exec(rule) || IP_PATTERN.exec(message);
  return match ? match[1] : null;
}

function topN(counts: Map<string, number>, limit: number): RankedCount[] {
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function increment(counts: Map<string, number>, key: string | null): void {
  if (key === null) return;
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

function emptySeverityCounts(): Record<AlertSeverity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

export function getAlertAnalytics(projectId: string, hours = 24, limit = 10): AlertAnalytics {
  const since = new Date(Date.now() - hours * 3_600_000).toISOString();
  const rows = db
    .prepare("SELECT occurred_at, severity, rule, message FROM alerts WHERE project_id = ? AND occurred_at >= ? ORDER BY occurred_at ASC")
    .all(projectId, since) as unknown as AlertRow[];

  // Zero-filled hourly buckets so the chart shows a continuous timeline
  // rather than only the hours an alert happened to fire in.
  const buckets = new Map<string, TimelineBucket>();
  const startHour = new Date(Date.now() - hours * 3_600_000);
  startHour.setUTCMinutes(0, 0, 0);
  for (let i = 0; i <= hours; i++) {
    const hourDate = new Date(startHour.getTime() + i * 3_600_000);
    const key = hourDate.toISOString().slice(0, 13) + ":00:00Z";
    buckets.set(key, { hour: key, count: 0, bySeverity: emptySeverityCounts() });
  }

  const attackTypeCounts = new Map<string, number>();
  const endpointCounts = new Map<string, number>();
  const countryCounts = new Map<string, number>();

  for (const row of rows) {
    const hourKey = row.occurred_at.slice(0, 13) + ":00:00Z";
    const bucket = buckets.get(hourKey);
    if (bucket) {
      bucket.count++;
      const severity = row.severity as AlertSeverity;
      if (severity in bucket.bySeverity) bucket.bySeverity[severity]++;
    }

    increment(attackTypeCounts, normalizeAttackType(row.rule));
    increment(endpointCounts, extractEndpoint(row.message));

    const ip = extractIp(row.rule, row.message);
    const country = ip ? geoip.lookup(ip)?.country ?? null : null;
    increment(countryCounts, country);
  }

  return {
    timeline: [...buckets.values()],
    topAttackTypes: topN(attackTypeCounts, limit),
    topEndpoints: topN(endpointCounts, limit),
    topCountries: topN(countryCounts, limit),
  };
}
