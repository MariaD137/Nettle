import type { Control } from "../types";
import { registerControl } from "../registry";

export const DB_003: Control = {
  controlKey: "DB-003",
  category: "Database",
  subcategory: "Query construction",
  name: "Positive evidence of parameterized queries or ORM usage",
  description:
    "Distinct from DB-001 (which catches the specific bad pattern of string-concatenated SQL): this looks for " +
    "positive evidence that queries are actually being built safely — a parameterized-query call, a prepared " +
    "statement, or an ORM/query-builder — wherever a raw SQL driver is used directly.",
  question: "Where a raw SQL driver is used directly, is there positive evidence its queries are parameterized?",
  defaultSeverity: "medium",

  passCriteria: "An ORM/query-builder is used, or a parameterized-query/prepared-statement pattern is found alongside raw driver usage.",
  failCriteria: "A raw SQL driver (pg, mysql, mysql2, sqlite3) is imported directly, and no parameterized-query pattern or ORM was found anywhere in the scanned source.",
  notVerifiedCriteria:
    "Database usage was detected only through a weaker signal (a word like \"database\" in a comment or config file, " +
    "not an actual driver import) — too little evidence to conclude how queries are actually built one way or the other.",

  whyItMatters:
    "A codebase can avoid the exact string-concatenation pattern DB-001 looks for while still never having adopted " +
    "parameterization at all — e.g. queries built with a templating helper DB-001 doesn't recognize. Confirming " +
    "positive evidence of a safe pattern, not just the absence of one specific bad one, is a meaningfully different " +
    "and complementary signal.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Confirm every raw query call in the codebase uses the driver's parameter-binding syntax (?, $1, or a named-parameter form), not manual string building.",
      developerFix: "Adopt a consistent pattern: either a query builder/ORM (Prisma, Knex, Drizzle) project-wide, or disciplined use of the raw driver's own parameterized-query API for every call.",
      architectureFix: "Wrap raw driver access behind a small internal query layer so every call site is forced through parameterization by construction, rather than relying on each call site remembering to do it correctly.",
    },
  ],

  longTermHardening: "Add a lint rule that flags any raw driver .query()/.execute() call whose argument isn't a parameterized call through the approved query layer.",
  verificationMethod: "Rescan and confirm a parameterized-query pattern or ORM is now present alongside the raw driver usage.",
  references: ["OWASP Top 10: A03:2021 – Injection"],
  complianceMappings: ["SOC 2 CC6.1"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(DB_003);
