import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const SQL_CONCAT_PATTERNS = [
  /`\s*SELECT\b[^`]*\$\{/gi,
  /`\s*INSERT\b[^`]*\$\{/gi,
  /`\s*UPDATE\b[^`]*\$\{/gi,
  /`\s*DELETE\b[^`]*\$\{/gi,
  /['"]SELECT\b.*['"]\s*\+\s*/gi,
  /['"]INSERT\b.*['"]\s*\+\s*/gi,
  /['"]UPDATE\b.*['"]\s*\+\s*/gi,
  /['"]DELETE\b.*['"]\s*\+\s*/gi,
];

const DB_USAGE_PATTERN = /\b(sqlite|postgres|mysql|mongo|database|sequelize|prisma|knex|typeorm|drizzle)\b/i;

/**
 * DB-001, wired to the control library. Extracted from databaseSecurity.ts's
 * former inline SQL-concatenation block — same detection, moved so its
 * output carries a controlKey, and made resilient to an unreadable file
 * (the original had no try/catch, like secrets.ts before its own fix).
 */
export function scanSqlInjectionControl(files: string[], targetRoot: string): CheckResult[] {
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
        checkId: generateCheckId("Database", "DB-001:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Database",
        title: "File could not be read for SQL injection analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "DB-001",
      });
      continue;
    }

    anyFileRead = true;
    if (DB_USAGE_PATTERN.test(text)) usesDb = true;

    for (const pattern of SQL_CONCAT_PATTERNS) {
      const matches = text.match(pattern);
      if (!matches) continue;

      anyFailure = true;
      results.push({
        checkId: generateCheckId("Database", "DB-001:fail", relFile),
        status: "FAIL",
        category: "Database",
        title: "SQL query built with string concatenation or interpolation",
        detail: `Found ${matches.length} SQL statement(s) that embed variables directly into the query string. This is the #1 cause of SQL injection vulnerabilities.`,
        severity: "critical",
        file: relFile,
        confidence: 90,
        detectionMethod: "regex",
        remediation: "Use parameterized queries with placeholders: db.prepare('SELECT * FROM users WHERE id = ?').get(userId).",
        controlKey: "DB-001",
      });
      break; // one finding per file is enough signal; matches prior behavior
    }
  }

  // A PASS asserts "this app uses a database and its queries are safe" —
  // only meaningful if database usage was actually detected and at least
  // one file was successfully read.
  if (!anyFailure && anyFileRead && usesDb) {
    results.push({
      checkId: generateCheckId("Database", "DB-001:pass"),
      status: "PASS",
      category: "Database",
      title: "No SQL injection patterns (string concatenation in queries) detected",
      confidence: 90,
      detectionMethod: "regex",
      controlKey: "DB-001",
    });
  }

  return results;
}
