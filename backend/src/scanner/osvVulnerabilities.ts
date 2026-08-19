import { DatabaseSync } from "node:sqlite";
import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";
import { loadLockfileGraph, findDependencyPaths } from "./lockfileGraph";

const DB_PATH = path.join(__dirname, "osv-data", "npm-vulnerabilities.db");

// A bulk OSV export is a point-in-time snapshot, not a live feed (see
// scripts/build-osv-db.js) — this is how long a snapshot is considered
// current before findings should be caveated as possibly missing newer
// disclosures.
const STALE_AFTER_DAYS = 30;

export interface OSVDatabaseFreshness {
  status: "CURRENT" | "STALE" | "UNKNOWN";
  generatedAt: string | null;
  ageDays: number | null;
  recordCount: number | null;
  source: string;
}

/**
 * Reports the real freshness of the bundled OSV database — when it was
 * actually built and how many records it has — by reading the metadata
 * table build-osv-db.js writes. Databases built before that table existed
 * (or a missing database file) report UNKNOWN rather than a fabricated
 * freshness value.
 */
export function getOSVDatabaseFreshness(dbPath: string = DB_PATH): OSVDatabaseFreshness {
  if (!fs.existsSync(dbPath)) {
    return { status: "UNKNOWN", generatedAt: null, ageDays: null, recordCount: null, source: "none (database missing)" };
  }

  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const row = db.prepare("SELECT generated_at, record_count, source FROM metadata LIMIT 1").get() as
      | { generated_at: string; record_count: number; source: string }
      | undefined;
    if (!row) {
      return { status: "UNKNOWN", generatedAt: null, ageDays: null, recordCount: null, source: "unknown (pre-dates freshness tracking)" };
    }
    const ageDays = Math.floor((Date.now() - new Date(row.generated_at).getTime()) / (1000 * 60 * 60 * 24));
    return {
      status: ageDays <= STALE_AFTER_DAYS ? "CURRENT" : "STALE",
      generatedAt: row.generated_at,
      ageDays,
      recordCount: row.record_count,
      source: row.source,
    };
  } catch {
    // metadata table doesn't exist on this build of the .db file.
    return { status: "UNKNOWN", generatedAt: null, ageDays: null, recordCount: null, source: "unknown (pre-dates freshness tracking)" };
  } finally {
    db.close();
  }
}

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

  // Additive only: enriches findings with how a vulnerable package was
  // actually pulled in, root to leaf. Detection above is unaffected either
  // way — a missing or unsupported-format lockfile just means no paths get
  // attached, not that findings are dropped or re-evaluated.
  const lockfileGraph = loadLockfileGraph(path.join(targetRoot, "package-lock.json"));

  const findings: Finding[] = [];
  let anyFound = false;

  const freshness = getOSVDatabaseFreshness();
  if (freshness.status === "STALE") {
    findings.push({
      severity: "low",
      category: "Dependencies",
      title: `OSV vulnerability database is stale (${freshness.ageDays} days old)`,
      detail: `The bundled dependency vulnerability database was generated ${freshness.ageDays} days ago (${freshness.generatedAt}, ${freshness.recordCount} records, source: ${freshness.source}). Vulnerabilities disclosed after that date will not be detected by this scan.`,
      file: null,
      line: null,
      remediation: "Rebuild the OSV database with a fresh export: node scripts/build-osv-db.js",
    });
  } else if (freshness.status === "UNKNOWN") {
    findings.push({
      severity: "low",
      category: "Dependencies",
      title: "OSV vulnerability database freshness could not be determined",
      detail: "This build of the bundled dependency vulnerability database pre-dates freshness tracking, so its age is unknown. Results below may be based on stale or current data — there's no way to tell from this build.",
      file: null,
      line: null,
      remediation: "Rebuild the OSV database with a fresh export: node scripts/build-osv-db.js",
    });
  }

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

    const dependencyPaths = lockfileGraph ? findDependencyPaths(lockfileGraph, name) : [];

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
      ...(dependencyPaths.length > 0 ? { dependencyPaths } : {}),
    });
  }

  db.close();

  const passed: Pass[] = anyFound
    ? []
    : [{ category: "Dependencies", title: "No known OSV vulnerabilities detected in declared dependencies" }];

  if (freshness.status === "CURRENT") {
    passed.push({
      category: "Dependencies",
      title: `OSV vulnerability database is current (${freshness.ageDays} day${freshness.ageDays === 1 ? "" : "s"} old, ${freshness.recordCount} records, generated ${freshness.generatedAt})`,
    });
  }

  return { findings, passed };
}
