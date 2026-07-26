import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

interface VulnerableDependency {
  atOrBelow: string;
  issue: string;
}

// Small, hand-curated seed list. Production version should call an OSV/CVE
// feed instead of hardcoding — this is enough to prove the check works end to end.
const VULNERABLE_DEPS: Record<string, VulnerableDependency> = {
  lodash: { atOrBelow: "4.17.20", issue: "Prototype pollution (CVE-2020-8203 / CVE-2021-23337) — fixed in 4.17.21" },
  jsonwebtoken: { atOrBelow: "8.5.1", issue: "Improper signature/algorithm handling — fixed in 9.x" },
  "node-fetch": { atOrBelow: "2.6.6", issue: "Exposure of sensitive info via bad redirect handling — fixed in 2.6.7" },
  axios: { atOrBelow: "0.21.1", issue: "SSRF via unvalidated redirect (CVE-2021-3749) — fixed in 0.21.2" },
};

function versionAtOrBelow(version: string, ceiling: string): boolean {
  const a = version.replace(/^[^\d]*/, "").split(".").map(Number);
  const b = ceiling.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) < (b[i] || 0)) return true;
    if ((a[i] || 0) > (b[i] || 0)) return false;
  }
  return true;
}

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

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const deps: Record<string, string> = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  let vulnFound = false;

  for (const [name, range] of Object.entries(deps)) {
    const known = VULNERABLE_DEPS[name];
    if (known && versionAtOrBelow(range, known.atOrBelow)) {
      vulnFound = true;
      findings.push({
        severity: "critical",
        category: "Security",
        title: `Vulnerable dependency: ${name}@${range}`,
        detail: known.issue,
        file: "package.json",
      });
    }
  }
  if (!vulnFound) passed.push({ category: "Security", title: "No known-vulnerable dependency versions detected" });

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
