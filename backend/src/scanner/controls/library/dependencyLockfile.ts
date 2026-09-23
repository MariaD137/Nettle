import type { Control } from "../types";
import { registerControl } from "../registry";

export const DEPS_001: Control = {
  controlKey: "DEPS-001",
  category: "Dependencies",
  subcategory: "Supply chain",
  name: "Dependency lockfile committed",
  description:
    "A lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml) pins the exact resolved version — and, for npm " +
    "and pnpm, the integrity hash — of every dependency and transitive dependency. Without one, an install can " +
    "silently resolve to a newer, and possibly compromised or incompatible, version of any package in the tree.",
  question: "Is a dependency lockfile committed to the repository?",
  defaultSeverity: "medium",

  passCriteria: "A package-lock.json, yarn.lock, or pnpm-lock.yaml file is present alongside package.json.",
  failCriteria: "package.json is present but none of package-lock.json, yarn.lock, or pnpm-lock.yaml exist.",
  notVerifiedCriteria: "No package.json was found at the scan target's root, so dependency management could not be assessed — this may not be a Node.js project, or the manifest wasn't included in the scan.",

  whyItMatters:
    "Without a lockfile, `npm install` (or the equivalent) re-resolves the dependency tree against whatever the " +
    "registry currently serves for each version range. A dependency publishing a new version between deploys — " +
    "whether an ordinary update or a supply-chain compromise pushing a malicious release under the same range — " +
    "changes what gets installed with no corresponding change to the application's own source.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Run npm install (or yarn / pnpm install) and commit the generated lockfile to the repository.",
      developerFix: "Commit the lockfile your package manager already generates, and use `npm ci` (or the yarn/pnpm equivalent) in CI/deploy pipelines so installs fail rather than silently drift when the lockfile is out of sync with package.json.",
      architectureFix: "Enable Dependabot or Renovate to open pull requests for dependency updates, so the lockfile changes deliberately and under review rather than implicitly on every install.",
    },
  ],

  longTermHardening: "Enable npm/GitHub's dependency review or an equivalent supply-chain scanner on pull requests that modify the lockfile.",
  verificationMethod: "Rescan and confirm the lockfile is now present in the repository.",
  references: ["npm docs: package-lock.json"],
  complianceMappings: ["SOC 2 CC7.1"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(DEPS_001);
