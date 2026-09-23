import type { Control } from "../types";
import { registerControl } from "../registry";

export const DB_002: Control = {
  controlKey: "DB-002",
  category: "Database",
  subcategory: "Credential exposure",
  name: "Database connection string not hardcoded in source",
  description:
    "A database connection string (DATABASE_URL, MONGO_URI, etc.) almost always embeds credentials directly in its " +
    "own syntax — postgres://user:password@host/db — so finding one hardcoded in source is finding a plaintext " +
    "credential committed to the repository, visible to anyone with repo access and permanently in its history.",
  question: "Is the database connection string kept out of source code?",
  defaultSeverity: "critical",

  passCriteria: "Database usage was detected, and no hardcoded connection-string assignment (DATABASE_URL/DB_URL/MONGO_URI/POSTGRES_URL/MYSQL_URL = a literal string) was found in the scanned source.",
  failCriteria: "A connection-string environment variable name is assigned a literal string value in the scanned source, rather than read from the environment.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so it was not checked for a hardcoded connection string.",

  whyItMatters:
    "Unlike a lone API key, a database connection string is a complete, ready-to-use credential — host, port, " +
    "database name, username, and password all in one value. Anyone who can read the source (a repo compromise, " +
    "an ex-employee's cached clone, a public fork) can connect directly to production data.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Remove the hardcoded connection string immediately, rotate the database password, and read the value from an environment variable instead.",
      developerFix: "Read the connection string from process.env.DATABASE_URL (or equivalent), set via your deployment platform's environment configuration — never assigned as a literal in source.",
      architectureFix: "Use a secret manager (AWS Secrets Manager, etc.) to inject the connection string at runtime, and rotate database credentials on a schedule so a historical leak in git history has a limited window of validity.",
      codeExample: "const databaseUrl = process.env.DATABASE_URL;\nif (!databaseUrl) throw new Error('DATABASE_URL is not set');",
    },
  ],

  longTermHardening: "Add a pre-commit secret-scanning hook so a connection string can't be committed in the first place, and check whether the exposed credential also appears in git history (a rotation doesn't retroactively protect historical clones).",
  verificationMethod: "Rescan and confirm no hardcoded connection-string assignment is present in the source.",
  references: ["OWASP Top 10: A02:2021 – Cryptographic Failures", "CWE-798: Use of Hard-coded Credentials"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS Req. 3"],

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

registerControl(DB_002);
