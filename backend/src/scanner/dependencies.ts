import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

export function scanDependencies(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  const pkgPath = path.join(targetRoot, "package.json");

  if (!fs.existsSync(pkgPath)) {
    findings.push({
      severity: "medium",
      category: "Dependencies",
      title: "No package.json found",
      detail: "Couldn't run dependency checks.",
      file: null,
      remediation: "If this is a Node.js project, run npm init to create a package.json.",
    });
    return { findings, passed };
  }

  const hasLockfile = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"].some((f) =>
    fs.existsSync(path.join(targetRoot, f))
  );
  if (!hasLockfile) {
    findings.push({
      severity: "medium",
      category: "Dependencies",
      title: "No dependency lockfile committed",
      detail: "Without a lockfile, installs can silently pull newer (or compromised) transitive versions. Commit package-lock.json / yarn.lock / pnpm-lock.yaml.",
      file: "package.json",
      remediation: "Run npm install (or yarn / pnpm install) and commit the generated lockfile to your repository.",
    });
  } else {
    passed.push({ category: "Dependencies", title: "Dependency lockfile present" });
  }

  return { findings, passed };
}
