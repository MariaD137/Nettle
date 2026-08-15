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

function mapSeverity(osvSeverity: string): Finding["severity"] {
  switch (osvSeverity) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MODERATE": return "medium";
    case "LOW": return "low";
    default: return "medium";
  }
}

export function scanOSVVulnerabilities(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const pkgPath = path.join(targetRoot, "package.json");
  if (!fs.existsSync(pkgPath)) {
    return { findings: [], passed: [] };
  }

  if (!fs.existsSync(DB_PATH)) {
    return {
      findings: [
        {
          severity: "low",
          category: "Dependencies",
          title: "OSV vulnerability database not found",
          detail: "The bundled OSV npm vulnerability database is missing from this build. Dependency vulnerability checks did not run.",
          file: null,
        line: null,
          remediation: "Rebuild the OSV database by running: node scripts/build-osv-db.js",
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
    const severity = mapSeverity(worst);
    const representative = matches.find((m) => m.severity === worst) ?? matches[0];
    const fixedVersion = representative.fixed;

    findings.push({
      severity,
      category: "Dependencies",
      title: `Vulnerable dependency: ${name}@${range}`,
      detail: `${matches.length} known vulnerabilit${matches.length === 1 ? "y" : "ies"} in this version range, worst severity ${worst}. Example: ${representative.vuln_id} — ${representative.summary}`,
      file: "package.json",
        line: null,
      remediation: fixedVersion
        ? `Upgrade ${name} to version ${fixedVersion} or later: npm install ${name}@${fixedVersion}`
        : `Check for a patched version of ${name} or evaluate an alternative package.`,
    });
  }

  db.close();

  const passed: Pass[] = anyFound
    ? []
    : [{ category: "Dependencies", title: "No known OSV vulnerabilities detected in declared dependencies" }];

  return { findings, passed };
}
