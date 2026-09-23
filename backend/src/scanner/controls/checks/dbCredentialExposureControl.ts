import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const DB_USAGE_PATTERN = /\b(sqlite|postgres|mysql|mongo|database|sequelize|prisma|knex|typeorm|drizzle)\b/i;
const DB_URL_EXPOSED_PATTERN = /(DATABASE_URL|DB_URL|MONGO_URI|POSTGRES_URL|MYSQL_URL)\s*=\s*['"][^'"]+['"]/;

/**
 * DB-002, wired to the control library. Extracted from databaseSecurity.ts's
 * former inline DB-URL-exposure block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Per-file, like DB-001,
 * since a hardcoded connection string is tied to a specific file/line.
 */
export function scanDbCredentialExposureControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let usesDb = false;
  let anyFailure = false;
  let anyFileRead = false;

  for (const file of jsFiles) {
    const relFile = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (err) {
      results.push({
        checkId: generateCheckId("Database", "DB-002:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Database",
        title: "File could not be read for database credential analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "DB-002",
      });
      continue;
    }

    anyFileRead = true;
    if (DB_USAGE_PATTERN.test(text)) usesDb = true;

    if (DB_URL_EXPOSED_PATTERN.test(text)) {
      anyFailure = true;
      results.push({
        checkId: generateCheckId("Database", "DB-002:fail", relFile),
        status: "FAIL",
        category: "Database",
        title: "Database connection string hardcoded in source",
        detail: "Hardcoded database URLs typically include credentials (username:password@host). Anyone with repo access can connect to the database directly.",
        severity: "critical",
        file: relFile,
        confidence: 90,
        detectionMethod: "regex",
        remediation: "Move the connection string to an environment variable (e.g. process.env.DATABASE_URL) and never commit it to source control.",
        controlKey: "DB-002",
      });
    }
  }

  if (!anyFailure && anyFileRead && usesDb) {
    results.push({
      checkId: generateCheckId("Database", "DB-002:pass"),
      status: "PASS",
      category: "Database",
      title: "No hardcoded database credentials in source",
      confidence: 90,
      detectionMethod: "regex",
      controlKey: "DB-002",
    });
  }

  return results;
}
