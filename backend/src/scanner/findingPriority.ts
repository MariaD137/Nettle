/**
 * Finding prioritization: rank findings by severity + exploitability.
 * Priority 1 (fix immediately) > Priority 2 (fix soon) > Priority 3 (best practice)
 */

import type { CheckResult, Severity } from "./types";

export type Priority = 1 | 2 | 3;

interface PriorityConfig {
  severity: Severity;
  category: string;
  isExploitable: boolean;
}

/**
 * Determine if a finding is likely to be actively exploited (not just theoretical).
 * Heuristics based on common attack vectors.
 */
function isLikelyExploitable(finding: CheckResult): boolean {
  const category = finding.category?.toLowerCase() || "";
  const detail = (finding.detail || "").toLowerCase();
  const title = (finding.title || "").toLowerCase();
  const text = `${title} ${detail} ${category}`;

  // High-value attack vectors
  const exploitablePatterns = [
    /\b(secret|api.?key|password|token|credential)\b/i,
    /\b(sql|command|rce|remote.code|eval|injection)\b/i,
    /\b(xss|cross.?site|script)\b/i,
    /\b(authentication|authorization|access.?control)\b/i,
    /\b(tls|ssl|https|encryption|cryptograph)\b/i,
    /\b(cors|cross.?origin|csrf)\b/i,
    /\b(vulnerable|vulner)\b/i,
  ];

  return exploitablePatterns.some((pattern) => pattern.test(text));
}

/**
 * Map severity to priority baseline.
 * Critical/High → Priority 1, Medium → Priority 2, Low/Info → Priority 3
 */
function priorityFromSeverity(severity?: Severity): Priority {
  if (!severity) return 3;
  if (severity === "critical" || severity === "high") return 1;
  if (severity === "medium") return 2;
  return 3; // low, info, unknown
}

/**
 * Calculate finding priority (1-3, where 1 is highest priority).
 * Factors: severity, exploitability, category.
 */
export function calculatePriority(finding: CheckResult): Priority {
  const basePriority = priorityFromSeverity(finding.severity);

  // Boost exploitable findings up one level
  if (isLikelyExploitable(finding)) {
    if (basePriority === 2) return 1; // Medium exploitable → Priority 1
    if (basePriority === 3) return 2; // Low exploitable → Priority 2
    return 1; // Critical/High stays Priority 1
  }

  return basePriority;
}

/**
 * Sort findings by priority (1 first) then by severity within same priority.
 */
export function sortByPriority(findings: CheckResult[]): CheckResult[] {
  return [...findings].sort((a, b) => {
    const priorityA = calculatePriority(a);
    const priorityB = calculatePriority(b);

    if (priorityA !== priorityB) return priorityA - priorityB;

    // Same priority: sort by severity
    const severityOrder: Record<Severity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    const severityA = severityOrder[a.severity || "info"] ?? 5;
    const severityB = severityOrder[b.severity || "info"] ?? 5;

    return severityA - severityB;
  });
}

/**
 * Group findings by priority level.
 */
export function groupByPriority(findings: CheckResult[]): Map<Priority, CheckResult[]> {
  const groups = new Map<Priority, CheckResult[]>();
  groups.set(1, []);
  groups.set(2, []);
  groups.set(3, []);

  for (const finding of findings) {
    const priority = calculatePriority(finding);
    groups.get(priority)!.push(finding);
  }

  return groups;
}

/**
 * Get human-readable label for priority level.
 */
export function getPriorityLabel(priority: Priority): string {
  const labels: Record<Priority, string> = {
    1: "🔴 Fix Immediately",
    2: "🟡 Fix Soon",
    3: "🟢 Best Practices",
  };
  return labels[priority];
}

/**
 * Attach priority to all findings in array (modifies in place, but returns array).
 */
export function enrichWithPriority(findings: CheckResult[]): CheckResult[] {
  for (const finding of findings) {
    // Store priority as a computed property (not part of interface yet)
    (finding as any).priority = calculatePriority(finding);
  }
  return findings;
}
