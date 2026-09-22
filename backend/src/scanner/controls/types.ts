import type { FindingCategory, Severity } from "../types";

/**
 * Release-gate impact, tied to severity + confidence + the control's own
 * policy — never assigned ad hoc per finding. See releaseGate.ts.
 */
export type ReleaseImpact =
  | "BLOCK_RELEASE"
  | "REVIEW_BEFORE_RELEASE"
  | "FIX_RECOMMENDED"
  | "IMPROVEMENT"
  | "INFORMATIONAL";

/**
 * A single remediation option. Controls with more than one valid
 * implementation (technologyFixes) list several; a control with one
 * universal fix uses a single generic fix instead.
 */
export interface TechnologyFix {
  /** e.g. "express", "django", "fastapi", "browser", "aws" — matched against
   *  detected technologies. "generic" applies when nothing more specific matched. */
  technology: string;
  quickFix: string;
  developerFix: string;
  architectureFix?: string;
  codeExample?: string;
}

/**
 * A structured control definition — the machine-enforceable shape spec'd in
 * NETTLE's control-library requirement. One Control is checked many times
 * (once per file/route/dependency); each check produces a CheckResult that
 * references this control's controlKey and gets hydrated with the content
 * below at report time (see hydrate.ts).
 *
 * Static, reusable content lives here. Dynamic, per-instance content
 * (which file, which line, what evidence) lives on the CheckResult.
 */
export interface Control {
  controlKey: string; // e.g. "AUTH-001" — stable, referenced by CheckResult.controlKey
  category: FindingCategory;
  subcategory?: string;
  name: string;
  description: string;
  question: string;
  defaultSeverity: Severity;

  /** What determines PASS vs FAIL vs NOT_VERIFIED for this control, in plain language. */
  passCriteria: string;
  failCriteria: string;
  notVerifiedCriteria: string;

  whyItMatters: string;

  /** One or more technology-specific fixes. Always include a "generic" entry
   *  as a fallback for when no more specific technology was detected. */
  technologyFixes: TechnologyFix[];
  longTermHardening?: string;
  verificationMethod: string;
  references?: string[];
  complianceMappings?: string[];

  /** Baseline release impact by severity; releaseGate.ts adjusts by confidence. */
  releaseImpactBySeverity: Partial<Record<Severity, ReleaseImpact>>;

  enabled: boolean;
  version: string;
}

/** The recommendation block attached to a hydrated finding — spec §20/§22. */
export interface Recommendation {
  whyItMatters: string;
  recommendedSolution: string;
  quickFix: string;
  developerFix: string;
  architectureFix: string | null;
  longTermHardening: string | null;
  verificationMethod: string;
  references: string[];
  technologyMatched: string; // which TechnologyFix.technology was used ("generic" if none matched)
  multipleValidSolutions: boolean; // true when the control has >1 non-generic TechnologyFix
}
