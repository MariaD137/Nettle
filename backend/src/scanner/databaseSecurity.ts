import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

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

const DB_URL_EXPOSED = /(DATABASE_URL|DB_URL|MONGO_URI|POSTGRES_URL|MYSQL_URL)\s*=\s*['"][^'"]+['"]/g;

export function scanDatabaseSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));
  let hasSqlConcat = false;
  let hasParameterized = false;
  let hasOrm = false;
  let usesDb = false;
  let hasDbUrlExposed = false;

  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    if (/\b(sqlite|postgres|mysql|mongo|database|sequelize|prisma|knex|typeorm|drizzle)\b/i.test(text)) {
      usesDb = true;
    }

    if (PARAMETERIZED_PATTERNS.some((p) => p.test(text))) hasParameterized = true;
    if (ORM_PATTERNS.some((p) => p.test(text))) hasOrm = true;

    for (const pattern of SQL_CONCAT_PATTERNS) {
      const matches = text.match(pattern);
      if (matches) {
        hasSqlConcat = true;
        findings.push({
          severity: "critical",
          category: "Database",
          title: "SQL query built with string concatenation or interpolation",
          detail: `Found ${matches.length} SQL statement(s) that embed variables directly into the query string. This is the #1 cause of SQL injection vulnerabilities.`,
          file: rel,
          remediation: "Use parameterized queries with placeholders: db.prepare('SELECT * FROM users WHERE id = ?').get(userId).",
        });
        break;
      }
    }

    const dbUrlMatches = text.match(DB_URL_EXPOSED);
    if (dbUrlMatches) {
      hasDbUrlExposed = true;
      findings.push({
        severity: "critical",
        category: "Database",
        title: "Database connection string hardcoded in source",
        detail: "Hardcoded database URLs typically include credentials (username:password@host). Anyone with repo access can connect to the database directly.",
        file: rel,
        remediation: "Move the connection string to an environment variable (e.g. process.env.DATABASE_URL) and never commit it to source control.",
      });
    }
  }

  if (usesDb && !hasSqlConcat) {
    passed.push({ category: "Database", title: "No SQL injection patterns (string concatenation in queries) detected" });
  }
  if (hasParameterized || hasOrm) {
    passed.push({ category: "Database", title: hasOrm ? "ORM or query builder detected (provides SQL injection protection)" : "Parameterized queries detected" });
  }
  if (usesDb && !hasDbUrlExposed) {
    passed.push({ category: "Database", title: "No hardcoded database credentials in source" });
  }

  return { findings, passed };
}
