import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const LOCKFILE_NAMES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

/**
 * DEPS-001, wired to the control library. Extracted from dependencies.ts's
 * former inline checks -- same detection logic and title/detail/remediation
 * text, restructured to emit CheckResult with a controlKey.
 *
 * Redesigned in one respect: the legacy module treated "no package.json
 * found" as its own medium-severity FAIL. That's not evidence of an
 * insecure app -- it just means dependency management for this project
 * couldn't be assessed at all (it may not be a Node.js project, or the
 * manifest wasn't in the scanned file set), which is exactly what
 * NOT_VERIFIED exists to express instead of a fabricated FAIL.
 *
 * A root-existence check, not per-file or content-aggregate: it looks only
 * at whether specific well-known files exist at the scan target's root.
 */
export function scanDependencyLockfileControl(targetRoot: string): CheckResult[] {
  const pkgPath = path.join(targetRoot, "package.json");

  if (!fs.existsSync(pkgPath)) {
    return [
      {
        checkId: generateCheckId("Dependencies", "DEPS-001:no-manifest"),
        status: "NOT_VERIFIED",
        category: "Dependencies",
        title: "No package.json found — dependency management could not be assessed",
        detail: "Couldn't run dependency checks without a manifest to check against.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "DEPS-001",
      },
    ];
  }

  const hasLockfile = LOCKFILE_NAMES.some((f) => fs.existsSync(path.join(targetRoot, f)));
  if (hasLockfile) {
    return [
      {
        checkId: generateCheckId("Dependencies", "DEPS-001:pass"),
        status: "PASS",
        category: "Dependencies",
        title: "Dependency lockfile present",
        confidence: 95,
        detectionMethod: "heuristic",
        controlKey: "DEPS-001",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("Dependencies", "DEPS-001:fail"),
      status: "FAIL",
      category: "Dependencies",
      title: "No dependency lockfile committed",
      detail: "Without a lockfile, installs can silently pull newer (or compromised) transitive versions. Commit package-lock.json / yarn.lock / pnpm-lock.yaml.",
      severity: "medium",
      file: "package.json",
      confidence: 95,
      detectionMethod: "heuristic",
      remediation: "Run npm install (or yarn / pnpm install) and commit the generated lockfile to your repository.",
      controlKey: "DEPS-001",
    },
  ];
}
