import crypto from "crypto";
import type { CheckResult, ScanReport, ScanStatus } from "./types";

/**
 * The rescan-diff engine — Phase 6's "Verified Remediation Loop".
 *
 * Deliberately separate from the scanner (index.ts) and from the control
 * library (controls/): the scanner determines what exists in one scan: this
 * module determines what changed between two. It consumes ScanReport.checkResults
 * (the unified three-state model), never the legacy findings/passed arrays,
 * and never re-runs any detection logic of its own.
 *
 * Core rule throughout: a finding is only ever called FIXED, NEW or
 * REGRESSED when the evidence actually supports it. Where a scan's
 * completeness, a control's version, or a file's readability makes that
 * unsafe, the result is NOT_VERIFIED with an explicit reason — never a
 * guessed FIXED (see §9, §10, §31 of the Phase 6 brief).
 */

export type DiffStatus = "FIXED" | "STILL_OPEN" | "NEW" | "REGRESSED" | "CHANGED" | "NOT_VERIFIED";

export interface ComparisonFinding {
  fingerprint: string;
  status: DiffStatus;
  /** The most relevant CheckResult to show the customer: current when it
   *  exists, otherwise baseline (e.g. for FIXED, where current has none). */
  finding: CheckResult;
  baseline?: CheckResult;
  current?: CheckResult;
  /** Populated for NOT_VERIFIED (why comparison was unsafe) and CHANGED (what changed). */
  reason?: string;
}

export interface ScanForComparison {
  id: string;
  scannedAt: string;
  status?: ScanStatus;
  report: ScanReport;
}

export interface ScanComparisonResult {
  baselineScanId: string;
  currentScanId: string;
  baselineScannedAt: string;
  currentScannedAt: string;
  baselineScore: number;
  currentScore: number;
  scoreDelta: number;
  /** Non-null when the two scans' scanner or control-library metadata
   *  differ enough to be worth surfacing — informational, not a block: the
   *  per-finding NOT_VERIFIED entries are what actually withhold a claim. */
  versionNote: string | null;
  summary: {
    fixed: number;
    stillOpen: number;
    new: number;
    regressed: number;
    changed: number;
    notVerified: number;
  };
  fixed: ComparisonFinding[];
  stillOpen: ComparisonFinding[];
  new: ComparisonFinding[];
  regressed: ComparisonFinding[];
  changed: ComparisonFinding[];
  notVerified: ComparisonFinding[];
}

export class ScanComparisonError extends Error {
  constructor(
    message: string,
    public readonly code: "SCAN_NOT_FOUND" | "INVALID_ORDER"
  ) {
    super(message);
  }
}

/**
 * A stable finding identity that survives a scan-to-scan diff even though
 * CheckResult.checkId (a hash of category+title+file, sometimes including a
 * route or file path) is not guaranteed stable by contract and a raw
 * database row ID would change every scan regardless (§7).
 *
 * controlKey (falling back to category, for the legacy findings that predate
 * the control library) plus a digit-normalized title plus the file identify
 * *what* was found and *where*, independent of incidental details like a
 * PASS summary's route count ("3 route(s)..." vs "5 route(s)...") that
 * shouldn't be mistaken for a different finding. Evidence and line are
 * intentionally excluded from identity — they can legitimately change while
 * remaining the same finding (see isMeaningfulChange, which is exactly the
 * "changed" case §8 asks for instead).
 */
export function computeFingerprint(result: CheckResult): string {
  const identity = [
    result.controlKey ?? result.category,
    result.category,
    normalizeTitle(result.title),
    result.file ?? "",
  ].join("::");
  return crypto.createHash("sha256").update(identity).digest("hex").slice(0, 16);
}

function normalizeTitle(title: string): string {
  return title.replace(/\d+/g, "#");
}

function isComplete(scan: ScanForComparison): boolean {
  // Matches patrol/scans.ts's own backward-compatible default: a scan
  // recorded before the status column existed reads as COMPLETED.
  return (scan.status ?? "COMPLETED") === "COMPLETED";
}

function failMap(scan: ScanForComparison): Map<string, CheckResult> {
  const map = new Map<string, CheckResult>();
  for (const cr of scan.report.checkResults ?? []) {
    if (cr.status === "FAIL") map.set(computeFingerprint(cr), cr);
  }
  return map;
}

/**
 * True when the current scan reported NOT_VERIFIED for the same file (and
 * control, when known) a baseline FAIL concerns — e.g. the file became
 * unreadable, or its framework stopped being recognized. In that case the
 * FAIL's disappearance from the current scan's FAIL set is not evidence the
 * issue was fixed; it's evidence the check didn't run. See §10.
 */
function hasNotVerifiedCoverage(scan: ScanForComparison, file: string | null | undefined, controlKey: string | undefined): boolean {
  if (!file) return false;
  return (scan.report.checkResults ?? []).some(
    (cr) => cr.status === "NOT_VERIFIED" && cr.file === file && (!controlKey || !cr.controlKey || cr.controlKey === controlKey)
  );
}

/** True when both scans recorded a version for this finding's control and the versions differ — see §11. */
function controlVersionChanged(controlKey: string | undefined, baseline: ScanForComparison, current: ScanForComparison): boolean {
  if (!controlKey) return false;
  const bv = baseline.report.controlVersions?.[controlKey];
  const cv = current.report.controlVersions?.[controlKey];
  if (!bv || !cv) return false; // scans recorded before this metadata existed — nothing to compare, don't block
  return bv !== cv;
}

const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];

function isMeaningfulChange(baseline: CheckResult, current: CheckResult): string | null {
  if (baseline.severity !== current.severity) {
    return `Severity changed from ${baseline.severity ?? "unknown"} to ${current.severity ?? "unknown"}.`;
  }
  const bConf = baseline.confidence ?? 0;
  const cConf = current.confidence ?? 0;
  if (Math.abs(bConf - cConf) >= 20) {
    return `Confidence changed from ${bConf}% to ${cConf}%.`;
  }
  if (baseline.line != null && current.line != null && baseline.line !== current.line) {
    return `Location moved from line ${baseline.line} to line ${current.line}.`;
  }
  if (baseline.evidence && current.evidence && baseline.evidence !== current.evidence) {
    return "The evidence for this finding changed.";
  }
  return null;
}

function buildVersionNote(baseline: ScanForComparison, current: ScanForComparison): string | null {
  const parts: string[] = [];
  if (baseline.report.scannerVersion !== current.report.scannerVersion) {
    parts.push(`scanner version ${baseline.report.scannerVersion ?? "unknown"} → ${current.report.scannerVersion ?? "unknown"}`);
  }
  if (baseline.report.controlLibraryVersion && current.report.controlLibraryVersion && baseline.report.controlLibraryVersion !== current.report.controlLibraryVersion) {
    parts.push("the control library changed between these scans");
  }
  if (parts.length === 0) return null;
  return `These scans were not run under identical conditions (${parts.join("; ")}). Individual findings affected by a control-version change are marked NOT_VERIFIED rather than compared directly.`;
}

/**
 * Compares two scans belonging to the same project. `history` must contain
 * every scan for that project (any order) so REGRESSED can be told apart
 * from NEW: a finding absent from the baseline but present before that is a
 * regression of a previously-fixed issue, not a brand-new one (§8's
 * mandatory 3-scan test: open → fixed → regressed).
 */
export function compareScans(history: ScanForComparison[], baselineScanId: string, currentScanId: string): ScanComparisonResult {
  const chronological = [...history].sort((a, b) => a.scannedAt.localeCompare(b.scannedAt));

  const baselineIdx = chronological.findIndex((s) => s.id === baselineScanId);
  const currentIdx = chronological.findIndex((s) => s.id === currentScanId);
  if (baselineIdx === -1 || currentIdx === -1) {
    throw new ScanComparisonError("One or both scans were not found in this project's history", "SCAN_NOT_FOUND");
  }
  if (baselineIdx > currentIdx) {
    throw new ScanComparisonError("The baseline scan must be the same age or older than the current scan", "INVALID_ORDER");
  }

  const baseline = chronological[baselineIdx];
  const current = chronological[currentIdx];
  const priorScans = chronological.slice(0, baselineIdx);

  const priorFailFingerprints = new Set<string>();
  for (const scan of priorScans) {
    for (const cr of scan.report.checkResults ?? []) {
      if (cr.status === "FAIL") priorFailFingerprints.add(computeFingerprint(cr));
    }
  }

  const baselineFails = failMap(baseline);
  const currentFails = failMap(current);
  const baselineComplete = isComplete(baseline);
  const currentComplete = isComplete(current);

  const fixed: ComparisonFinding[] = [];
  const stillOpen: ComparisonFinding[] = [];
  const regressed: ComparisonFinding[] = [];
  const changed: ComparisonFinding[] = [];
  const notVerified: ComparisonFinding[] = [];
  const newFindings: ComparisonFinding[] = [];

  for (const [fingerprint, bResult] of baselineFails) {
    const cResult = currentFails.get(fingerprint);

    if (cResult) {
      // Present on both sides.
      if (controlVersionChanged(bResult.controlKey, baseline, current)) {
        notVerified.push({
          fingerprint,
          status: "NOT_VERIFIED",
          finding: cResult,
          baseline: bResult,
          current: cResult,
          reason: `The ${bResult.controlKey} control's definition changed between these two scans, so a direct comparison would be unsafe.`,
        });
        continue;
      }
      const changeReason = isMeaningfulChange(bResult, cResult);
      if (changeReason) {
        changed.push({ fingerprint, status: "CHANGED", finding: cResult, baseline: bResult, current: cResult, reason: changeReason });
      } else {
        stillOpen.push({ fingerprint, status: "STILL_OPEN", finding: cResult, baseline: bResult, current: cResult });
      }
      continue;
    }

    // Absent from the current scan's FAILs — looks fixed. Rule that out first.
    if (!currentComplete) {
      notVerified.push({
        fingerprint,
        status: "NOT_VERIFIED",
        finding: bResult,
        baseline: bResult,
        reason: "The current scan did not complete every check, so Nettle cannot confirm this issue is actually resolved.",
      });
      continue;
    }
    if (hasNotVerifiedCoverage(current, bResult.file, bResult.controlKey)) {
      notVerified.push({
        fingerprint,
        status: "NOT_VERIFIED",
        finding: bResult,
        baseline: bResult,
        reason: "The current scan could not reliably analyze this file, so its absence is not evidence the issue was fixed.",
      });
      continue;
    }
    if (controlVersionChanged(bResult.controlKey, baseline, current)) {
      notVerified.push({
        fingerprint,
        status: "NOT_VERIFIED",
        finding: bResult,
        baseline: bResult,
        reason: `The ${bResult.controlKey} control's definition changed between these two scans, so its disappearance cannot be confirmed as a fix.`,
      });
      continue;
    }
    fixed.push({ fingerprint, status: "FIXED", finding: bResult, baseline: bResult });
  }

  for (const [fingerprint, cResult] of currentFails) {
    if (baselineFails.has(fingerprint)) continue; // already classified above

    if (!baselineComplete) {
      notVerified.push({
        fingerprint,
        status: "NOT_VERIFIED",
        finding: cResult,
        current: cResult,
        reason: "The baseline scan did not complete every check, so Nettle cannot confirm whether this issue is new or was already present.",
      });
      continue;
    }
    if (hasNotVerifiedCoverage(baseline, cResult.file, cResult.controlKey)) {
      notVerified.push({
        fingerprint,
        status: "NOT_VERIFIED",
        finding: cResult,
        current: cResult,
        reason: "The baseline scan could not reliably analyze this file, so Nettle cannot confirm whether this issue is new.",
      });
      continue;
    }

    if (priorFailFingerprints.has(fingerprint)) {
      // REGRESSED asserts something stronger than NEW — that this exact
      // issue was previously fixed and has now come back — so it deserves
      // the same version-safety check as a FIXED claim.
      if (controlVersionChanged(cResult.controlKey, baseline, current)) {
        notVerified.push({
          fingerprint,
          status: "NOT_VERIFIED",
          finding: cResult,
          current: cResult,
          reason: `The ${cResult.controlKey} control's definition changed between these two scans, so Nettle cannot confirm this is a genuine regression rather than a new detection under the updated control.`,
        });
        continue;
      }
      regressed.push({ fingerprint, status: "REGRESSED", finding: cResult, current: cResult });
    } else {
      newFindings.push({ fingerprint, status: "NEW", finding: cResult, current: cResult });
    }
  }

  return {
    baselineScanId: baseline.id,
    currentScanId: current.id,
    baselineScannedAt: baseline.scannedAt,
    currentScannedAt: current.scannedAt,
    baselineScore: baseline.report.score,
    currentScore: current.report.score,
    scoreDelta: current.report.score - baseline.report.score,
    versionNote: buildVersionNote(baseline, current),
    summary: {
      fixed: fixed.length,
      stillOpen: stillOpen.length,
      new: newFindings.length,
      regressed: regressed.length,
      changed: changed.length,
      notVerified: notVerified.length,
    },
    fixed,
    stillOpen,
    new: newFindings,
    regressed,
    changed,
    notVerified,
  };
}
