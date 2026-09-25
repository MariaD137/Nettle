import type { Control } from "../types";
import { registerControl } from "../registry";

export const OSV_002: Control = {
  controlKey: "OSV-002",
  category: "Dependencies",
  subcategory: "Known vulnerabilities",
  name: "No known-vulnerable Python dependencies",
  description:
    "Every package pinned in requirements.txt is checked against a bundled snapshot of the OSV (Open Source " +
    "Vulnerabilities) database for PyPI. A pinned version that falls inside a known vulnerable range for that " +
    "package is reported, with the worst known severity and a path to the fixed version where one exists. " +
    "requirements.txt only — poetry.lock/Pipfile.lock are not parsed by this build (see this control's own " +
    "notVerifiedCriteria).",
  question: "Do the application's pinned Python dependencies avoid known-vulnerable version ranges?",
  defaultSeverity: "high",

  passCriteria: "requirements.txt was read, the bundled PyPI OSV database was available, and no pinned dependency's version fell inside a known-vulnerable range.",
  failCriteria: "A dependency pinned in requirements.txt falls inside a version range OSV records as vulnerable for that package.",
  notVerifiedCriteria:
    "No requirements.txt was found (a Python project using only poetry.lock/Pipfile.lock is NOT_VERIFIED here, not " +
    "assumed clean — this build does not parse those formats), a requirement wasn't pinned to an exact version " +
    "(range/unpinned requirements can't be checked against a single known-vulnerable range the same way), or the " +
    "bundled PyPI OSV database was unavailable.",

  whyItMatters:
    "A known-vulnerable dependency is a documented, often publicly exploitable weakness with no code of the " +
    "application's own involved — an attacker doesn't need to find anything, the vulnerability and often a " +
    "working exploit are already public. This is usually the highest-value, lowest-effort fix available: bump a " +
    "version number.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Upgrade the flagged package to the fixed version named in the finding: pip install <package>==<fixed-version>, then update requirements.txt.",
      developerFix: "Run pip-audit (or the equivalent for the tool in use — poetry, pipenv) to see the full vulnerability tree, upgrade directly where a fix is available, and re-pin requirements.txt to the new version.",
      architectureFix: "Add automated dependency-update tooling (Dependabot, Renovate) so a newly-disclosed vulnerability produces a pull request automatically instead of waiting for the next manual audit.",
      codeExample: "pip install requests==2.32.0",
    },
  ],

  longTermHardening: "Re-run dependency vulnerability checks on a schedule (not just at scan time), since a package can become vulnerable after a new CVE is disclosed even if its own source never changes. Consider migrating to a lockfile format (poetry.lock, a pip-compile'd requirements.txt with hashes) for reproducible installs.",
  verificationMethod: "Rescan and confirm the flagged package's pinned version now falls outside the vulnerable range.",
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

registerControl(OSV_002);
