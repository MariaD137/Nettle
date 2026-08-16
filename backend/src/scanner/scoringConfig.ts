/**
 * Versioned scoring configuration.
 *
 * When scoring configuration changes, increment the version.
 * This allows historical scores to be understood in context:
 * a score calculated under v1.0 is comparable to another v1.0 score,
 * but not necessarily to a v2.0 score.
 */

export interface ScoringConfig {
  version: string; // semantic version
  createdAt: string; // ISO timestamp
  penalties: Record<string, number>; // severity → penalty
}

export const SCORING_CONFIG: ScoringConfig = {
  version: "1.0",
  createdAt: "2026-08-16T00:00:00Z",
  penalties: {
    critical: 20, // high impact, immediate fix needed
    high: 10, // serious issue
    medium: 5, // moderate issue
    low: 2, // minor issue, best practice
    info: 0, // informational, no score impact
  },
};

/**
 * Calculate a score from findings, excluding NOT_VERIFIED results.
 *
 * NOT_VERIFIED results do not reduce score because they represent
 * incomplete analysis, not missing security. A partial scan should not
 * penalize the parts that DID complete.
 */
export function calculateScore(
  findings: Array<{ severity?: string; status?: string }>,
  config: ScoringConfig = SCORING_CONFIG
): number {
  let score = 100;

  for (const f of findings) {
    // Skip NOT_VERIFIED findings — they don't indicate actual issues
    if (f.status === "NOT_VERIFIED") continue;

    const penalty = config.penalties[f.severity ?? "unknown"] ?? 7;
    score -= penalty;
  }

  // Clamp to 0-100
  return Math.max(0, Math.min(100, score));
}

/**
 * Calculate score confidence: how complete is the analysis?
 * confidence = (findings with status / total findings) * 100
 */
export function calculateConfidence(findings: Array<{ status?: string }>): number {
  if (findings.length === 0) return 100; // No findings = complete

  const verified = findings.filter((f) => f.status !== "NOT_VERIFIED").length;
  return Math.round((verified / findings.length) * 100);
}
