import { recentEvents } from "./events";
import { createAlert, hasRecentAlert } from "./alerts";
import type { StoredEvent, Alert } from "./types";

const ALERT_COOLDOWN_SECONDS = 300; // don't re-alert on an ongoing pattern every single request

const SUSPICIOUS_PATH_PATTERNS = [
  /\.\.\//, // path traversal
  /\/\.env/i,
  /\/\.git\//,
  /\/wp-admin/i,
  /\/wp-login/i,
  /\/phpmyadmin/i,
  /\/etc\/passwd/,
];

const SQLI_SHAPED_PATTERNS = [
  /'\s*or\s*'?1'?\s*=\s*'?1/i,
  /union\s+select/i,
  /;\s*drop\s+table/i,
  /--\s*$/,
];

function suspiciousPath(path: string): boolean {
  return SUSPICIOUS_PATH_PATTERNS.some((p) => p.test(path));
}

function sqliShaped(path: string): boolean {
  return SQLI_SHAPED_PATTERNS.some((p) => p.test(path));
}

/**
 * Runs after every recorded event. Intentionally simple, rule-based checks —
 * real anomaly detection (baselining normal traffic, ML-based scoring) is a
 * later investment once there's enough real traffic to learn from.
 */
export function runDetection(projectId: string, event: StoredEvent): Alert[] {
  const alerts: Alert[] = [];
  const window = recentEvents(projectId, 60);
  const fromSameIp = window.filter((e) => e.ip === event.ip);

  const recentFailedAuth = fromSameIp.filter((e) => e.statusCode === 401 || e.statusCode === 403);
  if (recentFailedAuth.length >= 5 && !hasRecentAlert(projectId, "brute-force", ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "brute-force",
        `${recentFailedAuth.length} failed-auth responses (401/403) from ${event.ip} in the last 60s — looks like a brute-force attempt.`
      )
    );
  }

  const lastTenSeconds = fromSameIp.filter(
    (e) => Date.now() - new Date(e.occurredAt).getTime() <= 10_000
  );
  if (lastTenSeconds.length >= 50 && !hasRecentAlert(projectId, "high-request-rate", ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "medium",
        "high-request-rate",
        `${lastTenSeconds.length} requests from ${event.ip} in 10s — possible scraping or denial-of-service probing.`
      )
    );
  }

  if (suspiciousPath(event.path) && !hasRecentAlert(projectId, "suspicious-path-" + event.ip, ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "suspicious-path-" + event.ip,
        `Request to "${event.path}" from ${event.ip} matches a common attack-probe pattern (path traversal, exposed config, or known CMS admin path).`
      )
    );
  }

  if (sqliShaped(event.path) && !hasRecentAlert(projectId, "sqli-shaped-" + event.ip, ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "sqli-shaped-" + event.ip,
        `Request to "${event.path}" from ${event.ip} contains a SQL-injection-shaped pattern.`
      )
    );
  }

  return alerts;
}
