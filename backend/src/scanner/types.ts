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
  | "Payment Security"
  | "CI/CD Security"
  | "Multi-Tenant Security"
  | "Cloud Security";

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
  /** References a Control in the control library (scanner/controls) by its
   *  controlKey, e.g. "AUTH-001". Optional: most existing scanner modules
   *  predate the control library and don't set it yet — see hydrate.ts for
   *  what that means for a result without one. */
  controlKey?: string;
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

export const SCANNER_VERSION = "1.3.0";

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
  /** Deterministic hash of every registered control's controlKey@version at
   *  scan time (see controls/registry.ts's getControlLibraryVersion). Two
   *  scans with the same value were evaluated against identical control
   *  definitions; scanComparison.ts uses a mismatch here as one signal that
   *  a fixed/regressed conclusion for a specific control may be unsafe. */
  controlLibraryVersion?: string;
  /** controlKey -> version snapshot at scan time, for the finer-grained,
   *  per-control check scanComparison.ts actually performs (the aggregate
   *  controlLibraryVersion above changing doesn't mean every control did). */
  controlVersions?: Record<string, string>;
  /** SCORING_CONFIG.version at scan time — see scanner/scoringConfig.ts. */
  scoringVersion?: string;
  score: number;
  scoreConfidence?: number; // 0-100: how complete is the scan
  status?: ScanStatus; // default COMPLETED for backward compatibility
  /** Set only on a FAILED report (see patrol/scans.ts's failQueuedScan) — the
   *  actual error message from the worker (a clone failure, a Fargate task
   *  failure, an unhandled exception in a control). Every "check the History
   *  tab for details" message the API/frontend show a customer is a promise
   *  that this field is what they'll find there. */
  error?: string;
  access?: ScanAccess;
  // Legacy fields for backward compatibility
  findings: Finding[];
  passed: Pass[];
  // New unified result format
  checkResults?: CheckResult[];
  /** Primary detected web framework, in the control library's technology-key
   *  vocabulary (see controls/technologyMap.ts) — e.g. "express", "django".
   *  null when no supported framework was identified; hydration falls back
   *  to each control's generic fix in that case. Only web/backend framework
   *  detection feeds this today, not database drivers or a browser-vs-server
   *  distinction per file, so some controls (DB-001, SECRET-001's "browser"
   *  fix) will rarely match a specific technology through this field alone —
   *  see the gap report for what fuller technology detection would need. */
  detectedTechnology?: string | null;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    clear: number;
  };
}
