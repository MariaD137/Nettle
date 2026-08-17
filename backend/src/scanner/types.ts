export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "Security"
  | "Dependencies"
  | "Authentication"
  | "Legal & Policy"
  | "AI Disclosure"
  | "Configuration"
  | "Cryptography"
  | "Database"
  | "API Security"
  | "Frontend Security"
  | "Code Quality"
  | "Supply Chain"
  | "Session Management"
  | "Infrastructure"
  | "CI/CD";

export type CheckStatus = "PASS" | "FAIL" | "NOT_VERIFIED";

/**
 * Three-state check result: PASS (no issue), FAIL (issue found), NOT_VERIFIED (couldn't determine).
 * This is the unified representation replacing the binary Finding/Pass model.
 */
export interface CheckResult {
  checkId: string;
  status: CheckStatus;
  category: FindingCategory;
  title: string;
  detail?: string;
  severity?: Severity;
  file?: string | null;
  line?: number | null;
  remediation?: string | null;
  evidence?: string;
  ruleId?: string;
  confidence?: number; // 0-100
  detectionMethod?: "regex" | "ast" | "heuristic" | "manual" | "unknown";
  whyItMatters?: string;
}

/**
 * Legacy Finding type (kept for backward compatibility during migration).
 * New code should use CheckResult.
 */
export interface Finding {
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  file: string | null;
  line: number | null;
  remediation: string | null;
}

/**
 * Legacy Pass type (kept for backward compatibility during migration).
 * New code should use CheckResult with status PASS.
 */
export interface Pass {
  category: FindingCategory;
  title: string;
}

/**
 * A correlated group of findings that together suggest a plausible path
 * from an entry point to impact — not a confirmed exploit. Language used in
 * chain descriptions should always be hedged ("may be able to", "potential")
 * unless the underlying findings themselves establish something stronger.
 */
export interface AttackChain {
  severity: Severity;
  title: string;
  entryPoint: string;
  component: string;
  impact: string;
  recommendation: string;
  findings: Finding[];
}

export const SCANNER_VERSION = "1.4.0";

export type ScanStatus = "CREATED" | "SCANNING" | "COMPLETED" | "PARTIALLY_COMPLETED" | "FAILED" | "CANCELLED";

/**
 * Describes how much of a report the caller was entitled to receive. Attached
 * at the API boundary, never at scan time — the scanner always produces a
 * complete report and storage always keeps one.
 */
export interface ScanAccess {
  tier: "preview" | "full";
  fullReport: boolean;
  totalFindings: number;
  visibleFindings: number;
  lockedFindings: number;
  message: string | null;
}

export interface ScanReport {
  scannedAt: string;
  target: string;
  scannerVersion: string;
  semgrepVersion?: string; // Version of Semgrep used (if available)
  score: number;
  scoreConfidence?: number; // 0-100: how complete is the scan
  status?: ScanStatus; // default COMPLETED for backward compatibility
  access?: ScanAccess;
  // Legacy fields for backward compatibility
  findings: Finding[];
  passed: Pass[];
  // New unified result format
  checkResults?: CheckResult[];
  // Correlated multi-finding attack paths (see AttackChain doc comment).
  attackChains?: AttackChain[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    clear: number;
  };
}
