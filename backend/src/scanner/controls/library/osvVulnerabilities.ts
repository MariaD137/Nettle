import type { Control } from "../types";
import { registerControl } from "../registry";

export const OSV_001: Control = {
  controlKey: "OSV-001",
  category: "Dependencies",
  subcategory: "Known vulnerabilities",
  name: "No known-vulnerable dependencies",
  description:
    "Every declared dependency (and dev dependency) is checked against a bundled snapshot of the OSV " +
    "(Open Source Vulnerabilities) database for npm. A declared version range that falls inside a known " +
    "vulnerable range for that package is reported, with the worst known severity and a path to the fixed " +
    "version where one exists.",
  question: "Do the application's declared dependencies avoid known-vulnerable version ranges?",
  defaultSeverity: "high",

  passCriteria: "package.json was read, the OSV database was available, and no declared dependency's version range fell inside a known-vulnerable range.",
  failCriteria: "A declared dependency's version range falls inside a version range OSV records as vulnerable for that package.",
  notVerifiedCriteria: "Either no package.json was found in the scanned project, or the bundled OSV database was unavailable — in both cases dependency vulnerabilities could not be checked, which is not the same as confirming there are none.",

  whyItMatters:
    "A known-vulnerable dependency is a documented, often publicly exploitable weakness with no code of the " +
    "application's own involved — an attacker doesn't need to find anything, the vulnerability and often a " +
    "working exploit are already public. This is usually the highest-value, lowest-effort fix available: bump a " +
    "version number.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Upgrade the flagged package to the fixed version named in the finding: npm install <package>@<fixed-version>.",
      developerFix: "Run npm audit (or the equivalent for the package manager in use) to see the full vulnerability tree, upgrade directly where a fix is available, and check whether a transitive dependency needs a manual override where it isn't.",
      architectureFix: "Add automated dependency-update tooling (Dependabot, Renovate) so a newly-disclosed vulnerability produces a pull request automatically instead of waiting for the next manual audit.",
      codeExample: "npm install lodash@4.17.21",
    },
  ],

  longTermHardening: "Re-run dependency vulnerability checks on a schedule (not just at scan time), since a package can become vulnerable after a new CVE is disclosed even if its own source never changes.",
  verificationMethod: "Rescan and confirm the flagged package's declared version now falls outside the vulnerable range.",
  references: ["OSV.dev — Open Source Vulnerabilities database"],
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

registerControl(OSV_001);
