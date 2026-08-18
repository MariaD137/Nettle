import { recentEvents } from "./events";
import { createAlert, hasRecentAlert } from "./alerts";
import type { StoredEvent, Alert } from "./types";
import { listCustomRules, evaluateCustomRule } from "./customRules";

const ALERT_COOLDOWN_SECONDS = 300; // don't re-alert on an ongoing pattern every single request
const CREDENTIAL_STUFFING_MIN_IPS = 5; // distinct IPs failing auth on one endpoint within the window

const SUSPICIOUS_PATH_PATTERNS = [
  /\.\.\//, // path traversal
  /\/\.env/i,
  /\/\.git\//,
  /\/wp-admin/i,
  /\/wp-login/i,
  /\/phpmyadmin/i,
  /\/etc\/passwd/,
  // Broader scanner-probe/config-exposure signatures beyond the original
  // starter set above.
  /\/\.aws\/credentials/i,
  /\/xmlrpc\.php/i,
  /\/\.ssh\//i,
  /\/actuator(\/|$)/i, // Spring Boot management endpoints — a common scan target
  /\/\.htpasswd/i,
  /\/\.DS_Store/i,
  /\/server-status/i, // Apache mod_status
];

const SQLI_SHAPED_PATTERNS = [
  /'\s*or\s*'?1'?\s*=\s*'?1/i,
  /union\s+select/i,
  /;\s*drop\s+table/i,
  /--\s*$/,
];

// XSS payload shapes — script tags, inline event handlers, and the
// javascript: pseudo-protocol turning up in a path or query string.
const XSS_SHAPED_PATTERNS = [/<script\b/i, /javascript:/i, /on(error|load)\s*=/i];

// Shell metacharacters chained with a common command name — the shape of
// an attempted OS command injection, not a legitimate path segment.
const CMDI_SHAPED_PATTERNS = [
  /[;|&]\s*(cat|ls|whoami|wget|curl|nc|bash|sh|id|uname)\b/i,
  /\$\([^)]+\)/, // $(...) command substitution
  /`[^`]+`/, // backtick command substitution
];

// Known offensive-security/scanning tools identifying themselves by their
// default User-Agent string. Deliberately narrow to unambiguous tool
// signatures — generic HTTP clients (curl, python-requests, etc.) are used
// by plenty of legitimate integrations and would be noisy false positives.
const SUSPICIOUS_USER_AGENT_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /\bnmap\b/i,
  /masscan/i,
  /nessus/i,
  /acunetix/i,
  /nuclei/i,
  /dirbuster/i,
  /gobuster/i,
  /wpscan/i,
  /metasploit/i,
  /havij/i,
  /burpsuite/i,
  /zgrab/i,
];

function suspiciousPath(path: string): boolean {
  return SUSPICIOUS_PATH_PATTERNS.some((p) => p.test(path));
}

function sqliShaped(path: string): boolean {
  return SQLI_SHAPED_PATTERNS.some((p) => p.test(path));
}

function xssShaped(path: string): boolean {
  return XSS_SHAPED_PATTERNS.some((p) => p.test(path));
}

function cmdiShaped(path: string): boolean {
  return CMDI_SHAPED_PATTERNS.some((p) => p.test(path));
}

function suspiciousUserAgent(userAgent: string | null | undefined): boolean {
  return !!userAgent && SUSPICIOUS_USER_AGENT_PATTERNS.some((p) => p.test(userAgent));
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

  if (xssShaped(event.path) && !hasRecentAlert(projectId, "xss-shaped-" + event.ip, ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "xss-shaped-" + event.ip,
        `Request to "${event.path}" from ${event.ip} contains a cross-site-scripting-shaped pattern.`
      )
    );
  }

  if (cmdiShaped(event.path) && !hasRecentAlert(projectId, "cmdi-shaped-" + event.ip, ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "cmdi-shaped-" + event.ip,
        `Request to "${event.path}" from ${event.ip} contains an OS-command-injection-shaped pattern.`
      )
    );
  }

  if (suspiciousUserAgent(event.userAgent) && !hasRecentAlert(projectId, "suspicious-user-agent-" + event.ip, ALERT_COOLDOWN_SECONDS)) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "suspicious-user-agent-" + event.ip,
        `Request from ${event.ip} used a User-Agent ("${event.userAgent}") matching a known security-scanning tool.`
      )
    );
  }

  // Credential stuffing, heuristically: brute-force (above) is repeated
  // failures from ONE ip against presumably one account. Credential
  // stuffing looks different in traffic terms — many DIFFERENT ips
  // failing auth against the SAME endpoint in a short window, i.e. a
  // distributed/coordinated attempt rather than a single attacker
  // hammering one account. We don't know which account each request
  // targeted (the event schema has no identity field), so this can't
  // distinguish "5 attempts on 5 accounts" from "5 attempts on 1 account
  // from 5 IPs" — but either shape is still credential-stuffing-relevant
  // and isn't caught by the same-IP brute-force rule at all.
  const sameFailedAuthPath = window.filter(
    (e) => e.path === event.path && (e.statusCode === 401 || e.statusCode === 403)
  );
  const distinctIps = new Set(sameFailedAuthPath.map((e) => e.ip));
  if (
    distinctIps.size >= CREDENTIAL_STUFFING_MIN_IPS &&
    !hasRecentAlert(projectId, "credential-stuffing-" + event.path, ALERT_COOLDOWN_SECONDS)
  ) {
    alerts.push(
      createAlert(
        projectId,
        "critical",
        "credential-stuffing-" + event.path,
        `${sameFailedAuthPath.length} failed-auth responses (401/403) against "${event.path}" from ${distinctIps.size} different IPs in the last 60s — looks like distributed credential stuffing rather than a single attacker.`
      )
    );
  }

  // Evaluate custom rules
  const customRules = listCustomRules(projectId, true); // enabledOnly
  for (const rule of customRules) {
    if (evaluateCustomRule(rule, event)) {
      const alertId = `custom-rule-${rule.id}`;
      if (!hasRecentAlert(projectId, alertId, ALERT_COOLDOWN_SECONDS)) {
        alerts.push(
          createAlert(
            projectId,
            rule.severity,
            alertId,
            `Custom rule "${rule.name}" matched: ${rule.description || rule.pattern_value}`
          )
        );
      }
    }
  }

  return alerts;
}
