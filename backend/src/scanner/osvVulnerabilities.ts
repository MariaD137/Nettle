import { DatabaseSync } from "node:sqlite";
import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

const DB_PATH = path.join(__dirname, "osv-data", "npm-vulnerabilities.db");

interface VulnRow {
  package: string;
  vuln_id: string;
  introduced: string;
  fixed: string | null;
  severity: string;
  summary: string;
}

// Deliberately simple: compares major.minor.patch numerically and ignores
// pre-release suffixes (e.g. "4.0.0-rc1" is treated as "4.0.0"). That's a
// real simplification — it means a range boundary that falls exactly on a
// pre-release version can be slightly off — but it's the same tradeoff
// already made in dependencies.ts's version comparator, and correct in the
// overwhelming majority of real-world version strings.
function compareVersions(a: string, b: string): number {
  const parse = (v: string) =>
    v
      .replace(/^[^\d]*/, "")
      .split("-")[0]
      .split(".")
      .map((n) => parseInt(n, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

function inRange(version: string, introduced: string, fixed: string | null): boolean {
  if (compareVersions(version, introduced) < 0) return false;
  if (fixed !== null && compareVersions(version, fixed) >= 0) return false;
  return true;
}

const SEVERITY_ORDER = ["LOW", "MODERATE", "HIGH", "CRITICAL"];
function worseSeverity(a: string, b: string): string {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

/**
 * Checks package.json dependencies against a real, bundled snapshot of
 * OSV's npm vulnerability database (215k+ known vulnerability ranges as of
 * the last `scripts/build-osv-db.js` run) — not a hand-picked list of a
 * couple of examples. Runs entirely offline against the local .db file,
 * same reasoning as the Semgrep integration: the production API has no
 * internet egress, so a live query API was never an option.
 */
export function scanOSVVulnerabilities(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const pkgPath = path.join(targetRoot, "package.json");
  if (!fs.existsSync(pkgPath)) {
    return { findings: [], passed: [] };
  }

  if (!fs.existsSync(DB_PATH)) {
    return {
      findings: [
        {
          severity: "caution",
          category: "Security",
          title: "OSV vulnerability database not found",
          detail: "The bundled OSV npm vulnerability database is missing from this build. Dependency vulnerability checks did not run.",
          file: null,
        },
      ],
      passed: [],
    };
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const deps: Record<string, string> = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

  const db = new DatabaseSync(DB_PATH, { readOnly: true });
  const query = db.prepare("SELECT * FROM vulnerabilities WHERE package = ?");

  const findings: Finding[] = [];
  let anyFound = false;

  for (const [name, range] of Object.entries(deps)) {
    const version = range.replace(/^[^\d]*/, "");
    const rows = query.all(name) as unknown as VulnRow[];
    const matches = rows.filter((r) => inRange(version, r.introduced, r.fixed));
    if (matches.length === 0) continue;

    anyFound = true;
    const worst = matches.reduce((acc, m) => worseSeverity(acc, m.severity), "LOW");
    const severity: Finding["severity"] = worst === "CRITICAL" || worst === "HIGH" ? "critical" : "caution";
    const representative = matches.find((m) => m.severity === worst) ?? matches[0];

    findings.push({
      severity,
      category: "Security",
      title: `Vulnerable dependency: ${name}@${range}`,
      detail: `${matches.length} known vulnerabilit${matches.length === 1 ? "y" : "ies"} in this version range, worst severity ${worst}. Example: ${representative.vuln_id} — ${representative.summary}`,
      file: "package.json",
    });
  }

  db.close();

  const passed: Pass[] = anyFound
    ? []
    : [{ category: "Security", title: "No known OSV vulnerabilities detected in declared dependencies" }];

  return { findings, passed };
}
