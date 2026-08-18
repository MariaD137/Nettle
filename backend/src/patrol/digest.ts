import { db } from "../db";
import { getProject } from "./projects";
import { notifyChannels, getProjectIdsSubscribedTo } from "./notificationChannels";

export type DigestPeriod = "daily" | "weekly";

export interface DigestSummary {
  projectId: string;
  projectName: string;
  periodStart: string;
  periodEnd: string;
  scanCount: number;
  latestScore: number | null;
  alertCount: number;
  alertsBySeverity: Record<"critical" | "high" | "medium" | "low", number>;
  subject: string;
  text: string;
  html: string;
}

const PERIOD_HOURS: Record<DigestPeriod, number> = { daily: 24, weekly: 24 * 7 };

export function composeDigest(projectId: string, period: DigestPeriod, now: Date = new Date()): DigestSummary | null {
  const project = getProject(projectId);
  if (!project) return null;

  const periodEnd = now.toISOString();
  const periodStart = new Date(now.getTime() - PERIOD_HOURS[period] * 3_600_000).toISOString();

  const scanRow = db
    .prepare("SELECT COUNT(*) as count FROM scans WHERE project_id = ? AND scanned_at >= ? AND scanned_at <= ?")
    .get(projectId, periodStart, periodEnd) as { count: number };

  const latestScanRow = db
    .prepare("SELECT score FROM scans WHERE project_id = ? AND scanned_at >= ? AND scanned_at <= ? ORDER BY scanned_at DESC LIMIT 1")
    .get(projectId, periodStart, periodEnd) as { score: number } | undefined;

  const alertRows = db
    .prepare("SELECT severity FROM alerts WHERE project_id = ? AND occurred_at >= ? AND occurred_at <= ?")
    .all(projectId, periodStart, periodEnd) as { severity: string }[];

  const alertsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of alertRows) {
    if (row.severity in alertsBySeverity) alertsBySeverity[row.severity as keyof typeof alertsBySeverity]++;
  }

  const periodLabel = period === "daily" ? "last 24 hours" : "last 7 days";
  const subject = `Nettle ${period} summary for ${project.name}: ${scanRow.count} scan(s), ${alertRows.length} alert(s)`;
  const text = [
    `${period === "daily" ? "Daily" : "Weekly"} summary for ${project.name} (${periodLabel}):`,
    `- ${scanRow.count} scan(s) run${latestScanRow ? `, latest score ${latestScanRow.score}` : ""}`,
    `- ${alertRows.length} alert(s): ${alertsBySeverity.critical} critical, ${alertsBySeverity.high} high, ${alertsBySeverity.medium} medium, ${alertsBySeverity.low} low`,
  ].join("\n");
  const html = `<p><strong>${period === "daily" ? "Daily" : "Weekly"} summary for ${project.name}</strong> (${periodLabel})</p>
<ul>
  <li>${scanRow.count} scan(s) run${latestScanRow ? `, latest score ${latestScanRow.score}` : ""}</li>
  <li>${alertRows.length} alert(s): ${alertsBySeverity.critical} critical, ${alertsBySeverity.high} high, ${alertsBySeverity.medium} medium, ${alertsBySeverity.low} low</li>
</ul>`;

  return {
    projectId,
    projectName: project.name,
    periodStart,
    periodEnd,
    scanCount: scanRow.count,
    latestScore: latestScanRow?.score ?? null,
    alertCount: alertRows.length,
    alertsBySeverity,
    subject,
    text,
    html,
  };
}

/**
 * Composes and sends the digest for every project with at least one active
 * channel subscribed to "digest.daily"/"digest.weekly". Meant to be invoked
 * on a schedule by something outside this process (see the
 * /api/internal/digest/:period route) — this app has no in-process job
 * scheduler, and one wouldn't be safe here anyway once App Runner scales to
 * multiple instances, since each would independently fire the same digest.
 */
export function sendDigests(period: DigestPeriod): { projectId: string; sent: boolean }[] {
  const projectIds = getProjectIdsSubscribedTo(`digest.${period}`);
  const results: { projectId: string; sent: boolean }[] = [];

  for (const projectId of projectIds) {
    const digest = composeDigest(projectId, period);
    if (!digest) continue;
    notifyChannels(projectId, `digest.${period}`, digest.subject, digest.text, { html: digest.html });
    results.push({ projectId, sent: true });
  }

  return results;
}
