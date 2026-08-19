import type { Finding, ScanReport, ScanAccess, Severity } from "../scanner/types";
import { hasFullScanAccess, type EntitlementInput } from "./entitlement";

export { hasFullScanAccess };

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
      ? `${locked} more ${locked === 1 ? "finding is" : "findings are"} in the full report. Upgrade to Tier 1 or Tier 2 to see every finding, its location, and how to fix it.`
      : null,
  };
}

/**
 * Trims a report down to what the given entitlement is allowed to see.
 *
 * The stored report is always the complete one — redaction happens here, at
 * the response boundary, so that upgrading retroactively unlocks scans that
 * were run while the account was still on the free plan (and, symmetrically,
 * so that a lapsed subscription immediately stops seeing full reports on the
 * next request, with no separate revocation step needed).
 *
 * A preview keeps everything that describes the *shape* of the problem —
 * score, per-severity counts, passed checks — and reveals the few most
 * severe findings in full. The rest are withheld entirely rather than
 * returned with blanked-out fields, so a preview response never ships
 * details the caller hasn't paid for.
 */
export function applyScanAccess(report: ScanReport, entitlement: EntitlementInput): ScanReport {
  const total = report.findings.length;

  if (hasFullScanAccess(entitlement)) {
    return { ...report, access: fullAccess(total) };
  }

  const visible = [...report.findings]
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, PREVIEW_FINDING_LIMIT);

  return {
    ...report,
    findings: visible,
    access: previewAccess(total, visible.length),
  };
}

/**
 * Preview-safe version of a standalone finding list (scan comparisons), which
 * has no surrounding report to carry the access block.
 */
export function limitFindings(findings: Finding[], entitlement: EntitlementInput): Finding[] {
  if (hasFullScanAccess(entitlement)) return findings;
  return [...findings]
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, PREVIEW_FINDING_LIMIT);
}
