import type { CheckResult } from "../types";
import type { Control, Recommendation, RecommendationConfidence, ReleaseImpact } from "./types";
import { getControl } from "./registry";
import { computeReleaseImpact } from "./releaseGate";

export interface HydratedFinding extends CheckResult {
  recommendation: Recommendation | null;
  releaseImpact: ReleaseImpact | null;
  humanReviewRequired: boolean;
}

/**
 * Picks the fix for a detected technology, falling back to the control's
 * "generic" entry. Never invents a fix for a technology the control doesn't
 * cover — that would be exactly the "invent an API" failure mode spec §25
 * forbids.
 */
function selectTechnologyFix(control: Control, detectedTechnology: string | undefined) {
  const byTech = detectedTechnology
    ? control.technologyFixes.find((f) => f.technology === detectedTechnology)
    : undefined;
  if (byTech) return byTech;
  return control.technologyFixes.find((f) => f.technology === "generic") ?? control.technologyFixes[0];
}

/**
 * Distinct from finding confidence entirely — see RecommendationConfidence's
 * own doc comment. Computed purely from whether the shown fix is
 * technology-specific, and if not, whether a technology-specific one exists
 * that just wasn't matched.
 */
function computeRecommendationConfidence(matchedTechnology: string, hasNonGenericFixes: boolean): RecommendationConfidence {
  if (matchedTechnology !== "generic") return "HIGH";
  return hasNonGenericFixes ? "LOW" : "MEDIUM";
}

/**
 * Turns a raw CheckResult into a full finding with the recommendation block
 * spec §20/§22 want (recommendedSolution/quickFix/developerFix/
 * architectureFix/longTermHardening/verification/references) and a release
 * impact — by looking up the CheckResult's controlKey in the control
 * library. A CheckResult with no controlKey, or one referencing a control
 * that isn't registered yet, is returned with recommendation: null rather
 * than a fabricated one: most of the ~30 existing scanner modules haven't
 * been migrated onto the control library yet (see controls/README in the
 * gap report), and pretending they have one would be exactly the "fabricate
 * a recommendation" failure mode this system exists to avoid.
 */
export function hydrateCheckResult(
  result: CheckResult,
  options?: { detectedTechnology?: string }
): HydratedFinding {
  const control = result.controlKey ? getControl(result.controlKey) : undefined;

  if (!control || result.status !== "FAIL") {
    return {
      ...result,
      recommendation: null,
      releaseImpact: null,
      humanReviewRequired: result.status === "NOT_VERIFIED",
    };
  }

  const fix = selectTechnologyFix(control, options?.detectedTechnology);
  const nonGenericFixes = control.technologyFixes.filter((f) => f.technology !== "generic");

  const recommendation: Recommendation = {
    whyItMatters: result.whyItMatters ?? control.whyItMatters,
    recommendedSolution: fix.developerFix,
    quickFix: fix.quickFix,
    developerFix: fix.developerFix,
    architectureFix: fix.architectureFix ?? null,
    longTermHardening: control.longTermHardening ?? null,
    verificationMethod: control.verificationMethod,
    references: control.references ?? [],
    technologyMatched: fix.technology,
    multipleValidSolutions: nonGenericFixes.length > 1,
    recommendationConfidence: computeRecommendationConfidence(fix.technology, nonGenericFixes.length > 0),
  };

  const severity = result.severity ?? control.defaultSeverity;
  const confidence = result.confidence ?? 50;
  const releaseImpact = computeReleaseImpact(control, severity, confidence);

  return {
    ...result,
    recommendation,
    releaseImpact,
    humanReviewRequired: false,
  };
}

export function hydrateCheckResults(
  results: CheckResult[],
  options?: { detectedTechnology?: string }
): HydratedFinding[] {
  return results.map((r) => hydrateCheckResult(r, options));
}
