import type { Control } from "../types";
import { registerControl } from "../registry";

export const DB_001: Control = {
  controlKey: "DB-001",
  category: "Database",
  subcategory: "SQL injection",
  name: "Parameterized database queries",
  description:
    "SQL queries must never be built by concatenating or interpolating variables directly into the query string — " +
    "every value must be passed as a bound parameter, letting the database driver handle escaping.",
  question: "Are SQL queries built with parameterized/prepared statements rather than string concatenation?",
  defaultSeverity: "critical",

  passCriteria: "No SQL statement in the scanned source embeds a variable directly into the query string (via template literal or + concatenation); parameterized calls or an ORM are used instead.",
  failCriteria: "A SQL statement (SELECT/INSERT/UPDATE/DELETE) was found built via template-literal interpolation or string concatenation with a variable.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its queries were not checked.",

  whyItMatters:
    "A SQL query built by pasting a variable into the string lets an attacker who controls that variable's value " +
    "change the query's actual meaning — reading other users' data, bypassing a WHERE clause, or in some drivers, " +
    "chaining additional statements. This is the single most common cause of SQL injection.",

  technologyFixes: [
    {
      technology: "node-sqlite",
      quickFix: "Replace the interpolated string with a prepared statement using ? placeholders and bound parameters.",
      developerFix: "Use db.prepare('SELECT * FROM users WHERE id = ?').get(userId) (better-sqlite3) or db.query('...', [userId]) (node:sqlite) — never build the string with the value inline.",
      architectureFix: "If the same query shape appears in many places, wrap it in a small query-builder function so every call site is forced through the parameterized form.",
      codeExample: "db.prepare('SELECT * FROM pets WHERE user_id = ?').all(userId);",
    },
    {
      technology: "postgres",
      quickFix: "Replace the interpolated string with a parameterized query using $1, $2, ... placeholders.",
      developerFix: "Use the driver's parameterized form: pool.query('SELECT * FROM pets WHERE user_id = $1', [userId]) — never template the value into the SQL string.",
      architectureFix: "Adopt a query builder or ORM (Knex, Prisma, Drizzle) for the codebase so parameterization is the path of least resistance, not an opt-in discipline.",
      codeExample: "await pool.query('SELECT * FROM pets WHERE user_id = $1', [userId]);",
    },
    {
      technology: "generic",
      quickFix: "Replace the string-concatenated query with a parameterized/prepared statement using your driver's placeholder syntax.",
      developerFix: "Pass every variable as a bound parameter to the query call, never interpolated into the SQL string itself. If available, use the project's ORM or query builder instead of raw SQL.",
      architectureFix: "Adopt an ORM or query builder project-wide so raw string-built SQL is the exception, not the default, and is easy to spot in review.",
    },
  ],

  longTermHardening: "Add a lint rule or pre-commit check that flags template-literal SQL strings containing ${...}, so a new instance can't be merged without review.",
  verificationMethod: "Rescan the repository and confirm no SQL statement is built via string concatenation or interpolation with a variable.",
  references: ["OWASP Top 10: A03:2021 – Injection", "CWE-89: SQL Injection"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS Req. 6"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "BLOCK_RELEASE",
    medium: "REVIEW_BEFORE_RELEASE",
    low: "FIX_RECOMMENDED",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(DB_001);
