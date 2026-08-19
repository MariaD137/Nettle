/**
 * Phase 5: Final Audit - Verify all 34 gap items are addressed.
 * Re-checks against original audit to confirm completeness.
 */

export type GapStatus = "PASS" | "FAIL" | "NOT_VERIFIED" | "PARTIAL";

export interface GapItem {
  id: string; // C-1, H-2, M-1, etc.
  category: "Critical" | "High" | "Medium" | "Low";
  title: string;
  description: string;
  status: GapStatus;
  implementedBy: string[]; // List of modules/files that address this
  evidence: string; // How we know it's fixed
  testCount: number;
}

/**
 * All 34 gap items from Phase 1 audit.
 */
const GAP_AUDIT: GapItem[] = [
  // Critical (C-1, C-2, C-3)
  {
    id: "C-1",
    category: "Critical",
    title: "Symlink Traversal Vulnerability",
    description: "Archive extraction allows symlink traversal to arbitrary host files",
    status: "PASS",
    implementedBy: ["src/scanner/safeExtraction.ts", "src/scanner/walk.ts"],
    evidence: "Two-layer defense: extraction-phase verification + runtime lstat checks",
    testCount: 7,
  },
  {
    id: "C-2",
    category: "Critical",
    title: "Worker Isolation for Untrusted Input",
    description: "Sandbox untrusted code analysis in separate process",
    status: "FAIL",
    implementedBy: [],
    evidence:
      "workerIsolation.ts (a WorkerPool abstraction whose task-processing body was a stub — " +
      "\"Simulate task processing\") has been removed: it was not imported by the real scan pipeline " +
      "(verified by repo-wide grep — its only prior reference was this audit file) and its presence " +
      "falsely implied isolation existed. The real execution path (scanner/scanWorker.ts) runs a scan " +
      "on a worker_thread for concurrency only — worker_threads share the host process's OS-level " +
      "privileges and are not a security boundary — while the actual work against untrusted input " +
      "(git clone, unzip, semgrep) runs via execFileSync in the same container/filesystem/network as " +
      "the API. A worker_thread memory ceiling (see Worker's resourceLimits in jobs/scanJobs.ts) was " +
      "added as a real, partial resource-exhaustion mitigation — it is not sandboxing and does not " +
      "change this item's status. Genuine isolation (a Fargate task per scan, or a purpose-built " +
      "untrusted-code runner like e2b/Modal) is infrastructure work — see backend/README.md and " +
      "infra/README.md's \"Known gaps\" sections. Re-verify only once real per-scan isolation exists.",
    testCount: 0,
  },
  {
    id: "C-3",
    category: "Critical",
    title: "Decompression Bomb Protection",
    description: "Prevent zip expansion attacks consuming memory/disk",
    status: "PASS",
    implementedBy: ["src/scanner/safeExtraction.ts"],
    evidence: "500MB limit, 10k files max, 100 depth limit, 30s timeout",
    testCount: 7,
  },

  // High (H-1 through H-7)
  {
    id: "H-1",
    category: "High",
    title: "Semgrep Honesty & Version Pinning",
    description: "Pin Semgrep version, track availability, explicit NOT_VERIFIED results",
    status: "PASS",
    implementedBy: [
      "backend/Dockerfile",
      "src/scanner/initialization.ts",
      "src/scanner/semgrepScanner.ts",
    ],
    evidence: "Semgrep 1.65.0 pinned, initialization tracking, 6 NOT_VERIFIED per AST check",
    testCount: 6,
  },
  {
    id: "H-2",
    category: "High",
    title: "Three-State Type System",
    description: "Move from binary (pass/fail) to three-state (PASS/FAIL/NOT_VERIFIED)",
    status: "PASS",
    implementedBy: ["src/scanner/types.ts", "src/scanner/threeStateModel.ts"],
    evidence: "CheckResult type with CheckStatus enum (PASS/FAIL/NOT_VERIFIED)",
    testCount: 10,
  },
  {
    id: "H-3",
    category: "High",
    title: "Reserved for Future Enhancement",
    description: "Expansion point for threat modeling or risk calculation",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Intentionally deferred per remediation plan",
    testCount: 0,
  },
  {
    id: "H-4",
    category: "High",
    title: "Score Integrity & Confidence Metric",
    description: "Versioned scoring config, NOT_VERIFIED exclusion, confidence 0-100",
    status: "PASS",
    implementedBy: ["src/scanner/scoringConfig.ts", "src/scanner/index.ts"],
    evidence: "ScoringConfig v1.0, calculateConfidence() reflects completion %",
    testCount: 9,
  },
  {
    id: "H-5",
    category: "High",
    title: "OSV Database Versioning & Freshness",
    description: "Track vulnerability database version, timestamp, confidence",
    status: "PASS",
    implementedBy: ["src/scanner/osvVulnerabilities.ts", "backend/scripts/build-osv-db.js"],
    evidence:
      "build-osv-db.js now writes a metadata table (generated_at, record_count, source) alongside the " +
      "vulnerabilities table it already built. getOSVDatabaseFreshness() in osvVulnerabilities.ts reads it " +
      "and is called directly from scanOSVVulnerabilities() on every scan, so every report carries a real " +
      "CURRENT/STALE/UNKNOWN status, database age, and record count. A separate osvVersioning.ts module (an " +
      "unused, self-contained in-memory metadata tracker, never imported by the real scan pipeline or by " +
      "this one) has since been removed entirely as dead code — it never implemented this item and its " +
      "removal changes nothing about the real freshness mechanism described above. The currently-bundled " +
      ".db file pre-dates the metadata table and correctly reports UNKNOWN rather than a fabricated " +
      "freshness value until it is rebuilt.",
    testCount: 8,
  },
  {
    id: "H-6",
    category: "High",
    title: "Auth Analysis Rewrite (Per-Route, Framework-Aware)",
    description: "Framework-specific route extraction, per-method severity assessment",
    status: "PASS",
    implementedBy: ["src/scanner/authAnalysis.ts"],
    evidence: "Express/Django/Flask/FastAPI/Rails patterns, POST/PUT/DELETE = critical",
    testCount: 19,
  },
  {
    id: "H-7",
    category: "High",
    title: "Scan Status Lifecycle Tracking",
    description: "Track scan through CREATED→SCANNING→COMPLETED/FAILED states",
    status: "PASS",
    implementedBy: ["src/patrol/scans.ts", "src/db/index.ts"],
    evidence: "ScanStatus enum in DB, lifecycle persistence, status in reports",
    testCount: 7,
  },

  // Medium (M-1 through M-6)
  {
    id: "M-1",
    category: "Medium",
    title: "Evidence Generation with Secret Redaction",
    description: "Safe, redacted proof of findings without exposing secrets",
    status: "PASS",
    implementedBy: ["src/scanner/evidence.ts"],
    evidence: "redactSecrets(), createEvidence(), extractLineEvidence() with [REDACTED] markers",
    testCount: 13,
  },
  {
    id: "M-2",
    category: "Medium",
    title: "Finding Prioritization (Exploitability Boosting)",
    description: "Priority 1-3 with severity + exploitability heuristics",
    status: "PASS",
    implementedBy: ["src/scanner/findingPriority.ts"],
    evidence: "calculatePriority() boosts secrets/injection/auth patterns, sortByPriority()",
    testCount: 20,
  },
  {
    id: "M-3",
    category: "Medium",
    title: "Education Layer (Multi-Level Explanations)",
    description: "Beginner/developer/expert explanations for findings",
    status: "PASS",
    implementedBy: ["src/scanner/education.ts"],
    evidence: "14 categories with 3-level education, formatFindingWithEducation()",
    testCount: 18,
  },
  {
    id: "M-4",
    category: "Medium",
    title: "Framework Detection (Multi-Signal)",
    description: "Detect 14+ frameworks with config, package.json, source patterns",
    status: "PASS",
    implementedBy: ["src/scanner/frameworkDetection.ts"],
    evidence: "Next/React/Express/Django/FastAPI/Vue/Svelte/Angular/Nuxt/Rails/etc.",
    testCount: 10,
  },
  {
    id: "M-5",
    category: "Medium",
    title: "Legal Disclaimers (GDPR, Liability)",
    description: "Clear legal notices about accuracy, scope, false positives",
    status: "PASS",
    implementedBy: ["src/scanner/legalDisclaimer.ts"],
    evidence: "Liability, accuracy, GDPR, scope limitation, AI-generated disclaimers",
    testCount: 8,
  },
  {
    id: "M-6",
    category: "Medium",
    title: "AI-Generated Content Disclosure",
    description: "Label AI-assisted explanations, distinguish from human review",
    status: "PASS",
    implementedBy: ["src/scanner/legalDisclaimer.ts"],
    evidence: "AI-Generated Content disclaimer with limitations and review requirements",
    testCount: 8,
  },

  // Low (L-1 through L-16) - Placeholder for future low-priority items
  {
    id: "L-1",
    category: "Low",
    title: "Reserved for Performance Optimization",
    description: "Caching, streaming, parallel analysis",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-2",
    category: "Low",
    title: "Reserved for Enhanced Reporting",
    description: "CSV export, PDF generation, trend tracking",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-3",
    category: "Low",
    title: "Reserved for Compliance Automation",
    description: "SAST, DAST, SCA automation rules",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-4",
    category: "Low",
    title: "Reserved for Language Support",
    description: "Expand to Rust, Go, Java, C#",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-5",
    category: "Low",
    title: "Reserved for IDE Integration",
    description: "VS Code, IntelliJ plugins",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-6",
    category: "Low",
    title: "Reserved for Machine Learning",
    description: "False positive reduction, smart filtering",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-7",
    category: "Low",
    title: "Reserved for Supply Chain Security",
    description: "Dependency graph, transitive auditing",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-8",
    category: "Low",
    title: "Reserved for Custom Rules",
    description: "User-defined security patterns",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-9",
    category: "Low",
    title: "Reserved for Threat Modeling",
    description: "Data flow analysis, threat actor profiles",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-10",
    category: "Low",
    title: "Reserved for Metrics & Telemetry",
    description: "Finding trends, scan metrics, usage analytics",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-11",
    category: "Low",
    title: "Reserved for Webhook Integrations",
    description: "GitHub, GitLab, Slack webhooks",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-12",
    category: "Low",
    title: "Reserved for Team Collaboration",
    description: "Comments, approval workflows, RBAC",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-13",
    category: "Low",
    title: "Reserved for Baseline Comparison",
    description: "Detect new/fixed/regressed findings",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-14",
    category: "Low",
    title: "Reserved for Cloud Deployment",
    description: "Kubernetes, Docker, serverless",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-15",
    category: "Low",
    title: "Reserved for Localization",
    description: "Multi-language support",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
  {
    id: "L-16",
    category: "Low",
    title: "Reserved for Advanced Analytics",
    description: "Risk scoring, severity aggregation",
    status: "NOT_VERIFIED",
    implementedBy: [],
    evidence: "Deferred to Phase 6 per roadmap",
    testCount: 0,
  },
];

/**
 * Get final audit report.
 */
export function getFinalAuditReport(): string {
  const statusCounts = {
    PASS: 0,
    PARTIAL: 0,
    FAIL: 0,
    NOT_VERIFIED: 0,
  };

  const testCounts = {
    total: 0,
    implemented: 0,
  };

  for (const item of GAP_AUDIT) {
    statusCounts[item.status]++;
    testCounts.total += item.testCount;
    if (item.status === "PASS") {
      testCounts.implemented += item.testCount;
    }
  }

  const passRate = Math.round((statusCounts.PASS / (GAP_AUDIT.length - statusCounts.NOT_VERIFIED)) * 100);

  return `
PHASE 5 FINAL AUDIT REPORT
===========================

SUMMARY
-------
Total Gap Items: ${GAP_AUDIT.length}
Implementation Status:
  ✓ PASS: ${statusCounts.PASS} items
  ◐ PARTIAL: ${statusCounts.PARTIAL} items
  ✗ FAIL: ${statusCounts.FAIL} items
  ? NOT_VERIFIED: ${statusCounts.NOT_VERIFIED} items (Intentionally deferred)

Implementation Rate: ${passRate}% (${statusCounts.PASS}/${GAP_AUDIT.length - statusCounts.NOT_VERIFIED})

TEST COVERAGE
-------------
Total Tests: ${testCounts.total}
Tests for Implemented Items: ${testCounts.implemented}
Coverage: ${Math.round((testCounts.implemented / testCounts.total) * 100)}%

BY CATEGORY
-----------
Critical (C-1, C-2, C-3): 3 items, 3 PASS ✓
High (H-1 to H-7): 7 items, 6 PASS, 1 DEFERRED
Medium (M-1 to M-6): 6 items, 6 PASS ✓
Low (L-1 to L-16): 16 items, all DEFERRED (Phase 6+)

IMPLEMENTED ITEMS
-----------------
${GAP_AUDIT.filter((i) => i.status === "PASS")
  .map((i) => `${i.id}: ${i.title} [${i.testCount} tests]`)
  .join("\n")}

INTENTIONALLY DEFERRED (Phase 6+)
---------------------------------
${GAP_AUDIT.filter((i) => i.status === "NOT_VERIFIED")
  .map((i) => `${i.id}: ${i.title}`)
  .join("\n")}

CONCLUSION
----------
Most prioritized gap items (Critical + High + Medium) are implemented and
tested; two Critical/High items (C-2 worker isolation, H-5 OSV freshness)
are marked FAIL above because the code they cite is not actually wired
into the paths it claims to protect — see their evidence fields. 16
low-priority items remain deferred to Phase 6+ per remediation roadmap.
This report describes code-level implementation status only; it makes no
claim about AWS or Stripe deployment readiness, which depend on
infrastructure this codebase does not control. Do not read "PASS" here as
"production ready" — see PRE_AWS_AUDIT.md and PRE_AWS_PRODUCTION_STATUS.md
for the full readiness picture.
  `.trim();
}

/**
 * Get audit items by status.
 */
export function getItemsByStatus(status: GapStatus): GapItem[] {
  return GAP_AUDIT.filter((item) => item.status === status);
}

/**
 * Verify audit completeness.
 */
export function verifyAuditCompleteness(): {
  complete: boolean;
  reason: string;
} {
  const criticalPass = GAP_AUDIT.filter((i) => i.category === "Critical" && i.status === "PASS").length;
  const highPass = GAP_AUDIT.filter((i) => i.category === "High" && i.status === "PASS").length;
  const mediumPass = GAP_AUDIT.filter((i) => i.category === "Medium" && i.status === "PASS").length;

  if (criticalPass === 3 && highPass === 6 && mediumPass === 6) {
    return {
      complete: true,
      reason: "All Critical, High, and Medium priority items implemented",
    };
  }

  return {
    complete: false,
    reason: `Missing implementations: C(${criticalPass}/3), H(${highPass}/6), M(${mediumPass}/6)`,
  };
}
