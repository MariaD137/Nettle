import type { CheckResult, Finding, ScanReport, ScanAccess, Severity } from "../scanner/types";

// Plans that unlock the complete report. Everything else — FREE accounts
// (never reach here: scans.routes.ts's scanBlocked() refuses them before a
// scan ever runs) and logged-out one-off scans — gets the preview.
const FULL_ACCESS_PLANS = new Set(["build", "protect"]);

// How many findings a preview reveals in full. Deliberately small but not
// zero: the point is to prove the scan found real, specific problems, not to
// hand over the whole remediation list.
export const PREVIEW_FINDING_LIMIT = 3;

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function hasFullScanAccess(plan: string | null | undefined): boolean {
  return FULL_ACCESS_PLANS.has(plan ?? "free");
}

function fullAccess(total: number): ScanAccess {
  return {
    tier: "full",
    fullReport: true,
    totalFindings: total,
    visibleFindings: total,
    lockedFindings: 0,
    message: null,
  };
}

function previewAccess(total: number, visible: number): ScanAccess {
  const locked = total - visible;
  return {
    tier: "preview",
    fullReport: false,
    totalFindings: total,
    visibleFindings: visible,
    lockedFindings: locked,
    message: locked > 0
      ? `${locked} more ${locked === 1 ? "finding is" : "findings are"} in the full report. Upgrade to BUILD or PROTECT to see every finding, its location, and how to fix it.`
      : null,
  };
}

/**
 * Preview-safe version of checkResults, mirroring limitFindings below.
 *
 * checkResults (the newer, three-state representation — see
 * scanner/controls/) carries the same paid detail a FAIL Finding does,
 * remediation included, once a check has been migrated onto the control
 * library. Trimming only `findings` and leaving `checkResults` untouched
 * would ship every FAIL's full remediation to a free-tier response for any
 * check that HAS been migrated — a real paywall bypass, not a hypothetical
 * one, for every control this session's control-library work adds. PASS and
 * NOT_VERIFIED entries carry no paid detail (no remediation field is ever
 * set on either) and describe the report's shape, so they stay in full,
 * same as passed[] does for findings.
 */
function limitCheckResults(checkResults: CheckResult[] | undefined): CheckResult[] | undefined {
  if (!checkResults) return checkResults;

  const fails = checkResults
    .filter((r) => r.status === "FAIL")
    .sort((a, b) => SEVERITY_RANK[a.severity ?? "info"] - SEVERITY_RANK[b.severity ?? "info"])
    .slice(0, PREVIEW_FINDING_LIMIT);
  const nonFails = checkResults.filter((r) => r.status !== "FAIL");

  return [...nonFails, ...fails];
}

/**
 * Trims a report down to what the given plan is entitled to see.
 *
 * The stored report is always the complete one — redaction happens here, at
 * the response boundary, so that upgrading retroactively unlocks scans that
 * were run while the account was still on the free plan.
 *
 * A preview keeps everything that describes the *shape* of the problem —
 * score, per-severity counts, passed checks — and reveals the few most
 * severe findings in full. The rest are withheld entirely rather than
 * returned with blanked-out fields, so a preview response never ships
 * details the caller hasn't paid for.
 */
export function applyScanAccess(report: ScanReport, plan: string | null | undefined): ScanReport {
  const total = report.findings.length;

  if (hasFullScanAccess(plan)) {
    return { ...report, access: fullAccess(total) };
  }

  const visible = [...report.findings]
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, PREVIEW_FINDING_LIMIT);

  return {
    ...report,
    findings: visible,
    checkResults: limitCheckResults(report.checkResults),
    access: previewAccess(total, visible.length),
  };
}

/**
 * Preview-safe version of a standalone finding list (scan comparisons), which
 * has no surrounding report to carry the access block.
 */
export function limitFindings(findings: Finding[], plan: string | null | undefined): Finding[] {
  if (hasFullScanAccess(plan)) return findings;
  return [...findings]
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, PREVIEW_FINDING_LIMIT);
}
