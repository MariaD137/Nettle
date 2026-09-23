import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const RAW_DRIVER_PATTERNS = [
  /require\(\s*['"]pg['"]\s*\)/,
  /from\s+['"]pg['"]/,
  /require\(\s*['"]mysql2?['"]\s*\)/,
  /from\s+['"]mysql2?['"]/,
  /require\(\s*['"]sqlite3['"]\s*\)/,
  /from\s+['"]sqlite3['"]/,
  /require\(\s*['"]better-sqlite3['"]\s*\)/,
  /from\s+['"]better-sqlite3['"]/,
];

const PARAMETERIZED_PATTERNS = [
  /\.prepare\s*\(/,
  /\.query\s*\(\s*['"`][^'"]*\?\s*['"`]/,
  /\$\d+/,
  /\.bind\s*\(/,
  /\.parameterize/,
  /\.escape\s*\(/,
];

const ORM_PATTERNS = [
  /require\(\s*['"]sequelize['"]\s*\)/,
  /from\s+['"]sequelize['"]/,
  /require\(\s*['"]prisma['"]\s*\)/,
  /from\s+['"]@prisma\/client['"]/,
  /require\(\s*['"]typeorm['"]\s*\)/,
  /from\s+['"]typeorm['"]/,
  /require\(\s*['"]drizzle-orm['"]\s*\)/,
  /from\s+['"]drizzle-orm['"]/,
  /require\(\s*['"]knex['"]\s*\)/,
  /from\s+['"]knex['"]/,
  /require\(\s*['"]mongoose['"]\s*\)/,
  /from\s+['"]mongoose['"]/,
];

const DB_USAGE_PATTERN = /\b(sqlite|postgres|mysql|mongo|database|sequelize|prisma|knex|typeorm|drizzle)\b/i;

/**
 * DB-003, wired to the control library. Extracted from databaseSecurity.ts's
 * former inline "hasParameterized || hasOrm" PASS-only block -- but the
 * legacy code never emitted the negative case at all (a codebase that uses
 * a database but matched neither pattern got no finding and no pass,
 * silently). This gives it a real three-state answer: FAIL only where the
 * evidence is actually strong enough to support it (a raw SQL driver is
 * imported directly and truly nothing in the source suggests
 * parameterization), NOT_VERIFIED where the only signal is a weaker generic
 * "database" word-match (too little evidence to conclude anything).
 * Aggregate, like API-001: parameterization patterns are normally spread
 * throughout query call sites, not concentrated in one file.
 */
export function scanParameterizedQueryControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let allSource = "";
  let anyUnreadable = false;
  for (const file of jsFiles) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
    } catch {
      anyUnreadable = true;
    }
  }

  const hasOrm = ORM_PATTERNS.some((p) => p.test(allSource));
  const hasParameterized = PARAMETERIZED_PATTERNS.some((p) => p.test(allSource));

  if (hasOrm || hasParameterized) {
    return [
      {
        checkId: generateCheckId("Database", "DB-003:pass"),
        status: "PASS",
        category: "Database",
        title: hasOrm ? "ORM or query builder detected (provides parameterization by default)" : "Parameterized queries detected",
        confidence: 80,
        detectionMethod: "heuristic",
        controlKey: "DB-003",
      },
    ];
  }

  const usesRawDriver = RAW_DRIVER_PATTERNS.some((p) => p.test(allSource));
  if (usesRawDriver && !anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Database", "DB-003:fail"),
        status: "FAIL",
        category: "Database",
        title: "No evidence of parameterized queries alongside direct database driver usage",
        detail: "A raw SQL driver is imported directly, but no parameterized-query pattern or ORM was found anywhere in the scanned source — there is no positive evidence queries are built safely.",
        severity: "medium",
        confidence: 60,
        detectionMethod: "heuristic",
        remediation: "Use the driver's parameterized-query syntax (?, $1, or named parameters) for every query, or adopt an ORM/query builder.",
        controlKey: "DB-003",
      },
    ];
  }

  const usesDbWeakly = DB_USAGE_PATTERN.test(allSource);
  if (usesDbWeakly || anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Database", "DB-003:unreadable"),
        status: "NOT_VERIFIED",
        category: "Database",
        title: "Not enough evidence to confirm how database queries are constructed",
        detail: anyUnreadable
          ? "At least one file could not be read, so query-construction patterns may have been missed."
          : "Database usage was detected only through a weak signal (a word like \"database\" in a comment or config file), not an actual driver import — too little evidence to conclude how queries are built.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "DB-003",
      },
    ];
  }

  return []; // no database usage signal at all — nothing to check
}
