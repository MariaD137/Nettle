import type { CheckResult, Finding, Pass, CheckStatus } from "./types";
import crypto from "crypto";

/**
 * Utilities for working with the three-state check model (PASS/FAIL/NOT_VERIFIED).
 */

/**
 * Generate a unique ID for a check result (for deduplication and tracking).
 */
export function generateCheckId(category: string, title: string, file?: string | null): string {
  const input = `${category}:${title}:${file || ""}`;
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 12);
}

/**
 * Convert a legacy Finding to a CheckResult with FAIL status.
 */
export function findingToCheckResult(finding: Finding): CheckResult {
  return {
    checkId: generateCheckId(finding.category, finding.title, finding.file),
    status: "FAIL",
    category: finding.category,
    title: finding.title,
    detail: finding.detail,
    severity: finding.severity,
    file: finding.file,
    line: finding.line,
    remediation: finding.remediation || undefined,
    confidence: 80, // default confidence for legacy findings
    detectionMethod: "unknown",
  };
}

/**
 * Convert a legacy Pass to a CheckResult with PASS status.
 */
export function passToCheckResult(pass: Pass): CheckResult {
  return {
    checkId: generateCheckId(pass.category, pass.title),
    status: "PASS",
    category: pass.category,
    title: pass.title,
    confidence: 100,
    detectionMethod: "unknown",
  };
}

/**
 * Create a NOT_VERIFIED CheckResult for a check that couldn't be completed.
 */
export function createNotVerified(
  category: string,
  title: string,
  reason: string,
  detail?: string
): CheckResult {
  return {
    checkId: generateCheckId(category, title),
    status: "NOT_VERIFIED",
    category: category as any, // cast since reason is dynamic
    title,
    detail: detail || reason,
    confidence: 0,
    detectionMethod: "unknown",
  };
}

/**
 * Calculate score confidence based on completed checks.
 * confidence = (completed checks / total checks) * 100
 */
export function calculateScoreConfidence(results: CheckResult[]): number {
  if (results.length === 0) return 100;
  const notVerified = results.filter((r) => r.status === "NOT_VERIFIED").length;
  const confidence = Math.round(((results.length - notVerified) / results.length) * 100);
  return Math.max(0, Math.min(100, confidence));
}

/**
 * Merge multiple check result arrays, deduplicating by checkId.
 * If the same checkId appears multiple times, keeps the last one.
 */
export function mergeCheckResults(...resultArrays: CheckResult[][]): CheckResult[] {
  const map = new Map<string, CheckResult>();
  for (const array of resultArrays) {
    for (const result of array) {
      map.set(result.checkId, result);
    }
  }
  return Array.from(map.values());
}

/**
 * Filter check results: returns only those with the given status(es).
 */
export function filterByStatus(results: CheckResult[], ...statuses: CheckStatus[]): CheckResult[] {
  const statusSet = new Set(statuses);
  return results.filter((r) => statusSet.has(r.status));
}

/**
 * Count results by status for summary reporting.
 */
export function countByStatus(results: CheckResult[]): Record<CheckStatus, number> {
  return {
    PASS: filterByStatus(results, "PASS").length,
    FAIL: filterByStatus(results, "FAIL").length,
    NOT_VERIFIED: filterByStatus(results, "NOT_VERIFIED").length,
  };
}
