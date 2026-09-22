import type { Severity } from "../types";
import type { Control, ReleaseImpact } from "./types";

/**
 * Computes release impact from the control's own severity->impact policy,
 * downgraded when confidence is low. A FAIL Nettle isn't confident about
 * should never block a release the way a well-evidenced one does — that
 * would be inventing certainty the scan doesn't have.
 *
 * Never called for PASS or NOT_VERIFIED: only an actual FAIL has a release
 * impact. NOT_VERIFIED findings are surfaced separately, as scan
 * limitations, not release blockers (see spec §5, §18).
 */
export function computeReleaseImpact(
  control: Control,
  severity: Severity,
  confidence: number
): ReleaseImpact {
  const baseline = control.releaseImpactBySeverity[severity] ?? "FIX_RECOMMENDED";

  // Low-confidence findings (heuristic match, unfamiliar framework, partial
  // scan) are downgraded one step so a release is never blocked on a guess.
  if (confidence < 50) {
    return downgrade(downgrade(baseline));
  }
  if (confidence < 75) {
    return downgrade(baseline);
  }
  return baseline;
}

const ORDER: ReleaseImpact[] = [
  "BLOCK_RELEASE",
  "REVIEW_BEFORE_RELEASE",
  "FIX_RECOMMENDED",
  "IMPROVEMENT",
  "INFORMATIONAL",
];

function downgrade(impact: ReleaseImpact): ReleaseImpact {
  const idx = ORDER.indexOf(impact);
  return ORDER[Math.min(idx + 1, ORDER.length - 1)];
}
