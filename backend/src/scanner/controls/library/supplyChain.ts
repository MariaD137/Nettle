import type { Control } from "../types";
import { registerControl } from "../registry";

export const SUPPLY_001: Control = {
  controlKey: "SUPPLY-001",
  category: "Supply Chain",
  subcategory: "Typosquatting",
  name: "No dependency name resembles a well-known package (possible typosquat)",
  description:
    "A declared dependency whose name is one or two characters off from a well-known, extremely popular package " +
    "(lodahs vs. lodash, expresss vs. express) may be an accidental typo that installed an entirely different, " +
    "unvetted package — or a deliberately-published malicious package relying on exactly that typo.",
  question: "Do all declared dependency names avoid close resemblance to a well-known package's name?",
  defaultSeverity: "high",
  passCriteria: "No declared dependency name is within edit-distance 2 of a well-known package name without being an exact match to it.",
  failCriteria: "A declared dependency name is within edit-distance 2 of a well-known package name, but isn't that package.",
  notVerifiedCriteria: "No package.json was found in the scanned project, so dependency names could not be checked. This check is also necessarily approximate: it compares against a small, fixed reference list of well-known packages, not the full npm registry, so it can miss a typosquat of a less common package and, rarely, flag a legitimate package that happens to be a near-name variant of one on the list.",
  whyItMatters:
    "Typosquatting is a real, actively-exploited npm attack vector — a malicious package published under a name " +
    "one keystroke away from a popular one, waiting for a developer's typo (or an AI code generator's slightly " +
    "wrong guess at a package name) to get it installed with no other action required from the attacker.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Double-check the flagged package name against the well-known package it resembles, and correct it if it's a typo.",
      developerFix: "If the dependency is intentional and genuinely not the well-known package, no action is needed — this is a heuristic, not a certainty. If it was meant to be the well-known package, fix the name and re-run npm install; check whether the wrong package was already imported anywhere before removing it.",
    },
  ],
  longTermHardening: "Enable npm's own package provenance/signature verification where available, and consider a private registry proxy that blocks first-time installs of very recently published packages.",
  verificationMethod: "Rescan and confirm the dependency name no longer resembles a well-known package it isn't.",
  references: ["OWASP: Software Supply Chain Security — Typosquatting"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const SUPPLY_002: Control = {
  controlKey: "SUPPLY-002",
  category: "Supply Chain",
  subcategory: "Dependency provenance",
  name: "Dependencies installed from the registry, not a git/URL reference",
  description:
    "A dependency specified as a git URL, a GitHub shorthand (user/repo), or a direct tarball URL bypasses the " +
    "npm registry entirely — no published version, no registry-level integrity hash, and (for a branch reference) " +
    "no guarantee the code installed today is the same code that will be installed tomorrow from the same " +
    "package.json.",
  question: "Are all dependencies installed from the npm registry rather than a git URL or direct download?",
  defaultSeverity: "medium",
  passCriteria: "No declared dependency's version specifier is a git URL, GitHub shorthand, or tarball URL.",
  failCriteria: "A declared dependency's version specifier is a git URL, GitHub shorthand, or tarball URL.",
  notVerifiedCriteria: "No package.json was found in the scanned project, so dependency sources could not be checked.",
  whyItMatters:
    "A git-URL dependency pinned to a branch (not a tag or commit SHA) can change what code gets installed on the " +
    "next install with no change to package.json at all — the same class of risk an unpinned GitHub Action has. A " +
    "tarball URL has the same problem plus no built-in integrity check the registry's own tarball hash provides.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Publish the dependency to the npm registry (even a private/scoped one) instead of referencing it by URL, or pin the git reference to an immutable commit SHA.",
      developerFix: "If the package is internal and can't be published publicly, use a private npm registry or a scoped package on npm/GitHub Packages — both give the same install-time integrity guarantees a public registry dependency has. If a git URL is unavoidable, pin it to a full commit SHA, not a branch or tag.",
      codeExample: "// Instead of: \"pkg\": \"git+https://github.com/org/pkg.git#main\"\n\"pkg\": \"git+https://github.com/org/pkg.git#a1b2c3d4e5f6...\"",
    },
  ],
  longTermHardening: "Set up a private registry (Verdaccio, GitHub Packages, npm Enterprise) for internal packages so every dependency, internal or external, goes through the same registry-level integrity and audit path.",
  verificationMethod: "Rescan and confirm the dependency is now installed from the registry, or pinned to an immutable commit SHA if a git reference is unavoidable.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(SUPPLY_001);
registerControl(SUPPLY_002);
