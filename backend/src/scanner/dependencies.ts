import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

// Vulnerable-version checking lives in osvVulnerabilities.ts now, against a
// real bundled snapshot of OSV's database — this module just covers what
// OSV doesn't: whether a lockfile exists at all.
export function scanDependencies(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  const pkgPath = path.join(targetRoot, "package.json");

  if (!fs.existsSync(pkgPath)) {
    findings.push({
      severity: "caution",
      category: "Security",
      title: "No package.json found",
      detail: "Couldn't run dependency checks.",
      file: null,
    });
    return { findings, passed };
  }

  const hasLockfile = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"].some((f) =>
    fs.existsSync(path.join(targetRoot, f))
  );
  if (!hasLockfile) {
    findings.push({
      severity: "caution",
      category: "Security",
      title: "No dependency lockfile committed",
      detail: "Without a lockfile, installs can silently pull newer (or compromised) transitive versions. Commit package-lock.json / yarn.lock / pnpm-lock.yaml.",
      file: "package.json",
    });
  } else {
    passed.push({ category: "Security", title: "Dependency lockfile present" });
  }

  return { findings, passed };
}
