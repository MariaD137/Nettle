import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

interface PatternCheck {
  name: string;
  regex: RegExp;
  severity: Finding["severity"];
  detail: string;
  remediation: string;
  matchAll?: boolean;
}

const CHECKS: PatternCheck[] = [
  {
    name: "Debug console output in production code",
    regex: /console\.(log|debug|trace)\s*\(/g,
    severity: "low",
    detail: "console.log statements left in production code can leak sensitive data (tokens, passwords, user info) into browser consoles or server logs.",
    remediation: "Remove debug logging or replace with a structured logger that respects log levels and redacts sensitive fields.",
    matchAll: true,
  },
  {
    name: "TODO/FIXME security items",
    regex: /(TODO|FIXME|HACK|XXX)\b.*?(security|auth|secret|password|token|key|cred|encrypt|vuln|inject|sanitiz)/gi,
    severity: "medium",
    detail: "Unresolved security-related TODO/FIXME comments indicate known security gaps that haven't been addressed.",
    remediation: "Address the security concern described in the comment before shipping to production.",
  },
  {
    name: "Debug mode enabled",
    regex: /(debug\s*[:=]\s*true|DEBUG\s*=\s*['"]?true|NODE_ENV\s*[:=!]=\s*['"]development['"].*\?\s*true)/gi,
    severity: "medium",
    detail: "Debug mode in production can expose stack traces, internal state, and verbose error messages to attackers.",
    remediation: "Ensure debug mode is controlled by environment variables and defaults to false in production.",
  },
  {
    name: "Stack traces returned to client",
    regex: /res\.(json|send)\s*\([^)]*\b(stack|stackTrace|err\.stack|error\.stack)\b/g,
    severity: "high",
    detail: "Sending stack traces in HTTP responses reveals internal file paths, library versions, and code structure to attackers.",
    remediation: "Return generic error messages to clients. Log the full error server-side with a correlation ID and return only the ID to the client.",
  },
  {
    name: "Verbose error responses",
    regex: /catch\s*\([^)]*\)\s*\{[^}]*res\.(json|send)\s*\(\s*(err|error|e)\s*\)/gs,
    severity: "medium",
    detail: "Passing raw error objects to response methods can leak internal details (SQL errors, file paths, service names).",
    remediation: "Catch errors and return a generic message: res.status(500).json({ error: 'Internal server error' }). Log the real error server-side.",
  },
  {
    name: "Test/debug endpoint in production code",
    regex: /app\.(get|post|put|delete)\s*\(\s*['"`]\/(test|debug|dev|internal|admin-bypass|backdoor)/gi,
    severity: "high",
    detail: "Test or debug endpoints left in production code can provide unauthenticated access to internal functionality.",
    remediation: "Remove test/debug endpoints or gate them behind authentication and a NODE_ENV !== 'production' check.",
  },
  {
    name: "Disabled security checks",
    regex: /(eslint-disable|@ts-ignore|@ts-nocheck|no-verify|--force|--insecure|verify\s*[:=]\s*false)/g,
    severity: "low",
    detail: "Disabled security checks (linting rules, type checking, TLS verification) can mask real vulnerabilities.",
    remediation: "Re-enable the security check and fix the underlying issue rather than suppressing the warning.",
  },
];

const EXPOSED_ENV_PATTERN = /\.(env|env\.local|env\.production|env\.development)$/;

export function scanCodeQuality(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passedSet = new Set<string>();

  const checkedNames = new Set(CHECKS.map((c) => c.name));

  for (const file of files) {
    const rel = path.relative(targetRoot, file);
    if (/node_modules|\.git|dist|build/.test(rel)) continue;

    if (EXPOSED_ENV_PATTERN.test(file)) {
      findings.push({
        severity: "critical",
        category: "Security",
        title: "Environment file committed to source",
        detail: "Environment files often contain secrets (API keys, database URLs, signing keys) that should never be in version control.",
        file: rel,
        remediation: "Add .env* to .gitignore, remove the file from git history (git filter-branch or BFG), and rotate any secrets it contained.",
      });
      continue;
    }

    const text = fs.readFileSync(file, "utf8");

    for (const check of CHECKS) {
      const matches = text.match(check.regex);
      if (matches && matches.length > 0) {
        if (check.matchAll && matches.length < 3) continue;
        findings.push({
          severity: check.severity,
          category: "Code Quality",
          title: check.name,
          detail: `${check.detail} Found ${matches.length} occurrence(s).`,
          file: rel,
          remediation: check.remediation,
        });
      }
    }
  }

  for (const check of CHECKS) {
    if (!findings.some((f) => f.title === check.name)) {
      passedSet.add(check.name);
    }
  }

  if (!findings.some((f) => f.title === "Environment file committed to source")) {
    passedSet.add("No .env files committed to source");
  }

  const passed: Pass[] = [];
  if (passedSet.has("Stack traces returned to client") && passedSet.has("Verbose error responses")) {
    passed.push({ category: "Code Quality", title: "No stack traces or verbose errors returned to clients" });
  }
  if (passedSet.has("Test/debug endpoint in production code")) {
    passed.push({ category: "Code Quality", title: "No test/debug endpoints found in production code" });
  }
  if (passedSet.has("No .env files committed to source")) {
    passed.push({ category: "Security", title: "No .env files committed to source" });
  }

  return { findings, passed };
}
