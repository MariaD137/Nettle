import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

interface PatternCheck {
  controlKey: string;
  regex: RegExp;
  title: string;
  passTitle: string;
  severity: "critical" | "high" | "medium" | "low";
  detail: string;
  remediation: string;
  /** Only counts as a match when the file has 3+ occurrences — avoids
   *  flagging a single, ordinary debug log statement. */
  matchAll?: boolean;
}

const CHECKS: PatternCheck[] = [
  {
    controlKey: "CQ-001",
    regex: /console\.(log|debug|trace)\s*\(/g,
    title: "Debug console output in production code",
    passTitle: "No excessive debug console output detected",
    severity: "low",
    detail: "console.log statements left in production code can leak sensitive data (tokens, passwords, user info) into browser consoles or server logs.",
    remediation: "Remove debug logging or replace with a structured logger that respects log levels and redacts sensitive fields.",
    matchAll: true,
  },
  {
    controlKey: "CQ-002",
    regex: /(TODO|FIXME|HACK|XXX)\b.*?(security|auth|secret|password|token|key|cred|encrypt|vuln|inject|sanitiz)/gi,
    title: "TODO/FIXME security items",
    passTitle: "No unresolved security TODO/FIXME items detected",
    severity: "medium",
    detail: "Unresolved security-related TODO/FIXME comments indicate known security gaps that haven't been addressed.",
    remediation: "Address the security concern described in the comment before shipping to production.",
  },
  {
    controlKey: "CQ-003",
    regex: /(debug\s*[:=]\s*true|DEBUG\s*=\s*['"]?true|NODE_ENV\s*[:=!]=\s*['"]development['"].*\?\s*true)/gi,
    title: "Debug mode enabled",
    passTitle: "Debug mode is not hardcoded on",
    severity: "medium",
    detail: "Debug mode in production can expose stack traces, internal state, and verbose error messages to attackers.",
    remediation: "Ensure debug mode is controlled by environment variables and defaults to false in production.",
  },
  {
    controlKey: "CQ-004",
    regex: /res\.(json|send)\s*\([^)]*\b(stack|stackTrace|err\.stack|error\.stack)\b/g,
    title: "Stack traces returned to client",
    passTitle: "No stack traces returned to clients",
    severity: "high",
    detail: "Sending stack traces in HTTP responses reveals internal file paths, library versions, and code structure to attackers.",
    remediation: "Return generic error messages to clients. Log the full error server-side with a correlation ID and return only the ID to the client.",
  },
  {
    controlKey: "CQ-005",
    regex: /catch\s*\([^)]*\)\s*\{[^}]*res\.(json|send)\s*\(\s*(err|error|e)\s*\)/gs,
    title: "Verbose error responses",
    passTitle: "No raw error objects returned to clients",
    severity: "medium",
    detail: "Passing raw error objects to response methods can leak internal details (SQL errors, file paths, service names).",
    remediation: "Catch errors and return a generic message: res.status(500).json({ error: 'Internal server error' }). Log the real error server-side.",
  },
  {
    controlKey: "CQ-006",
    regex: /app\.(get|post|put|delete)\s*\(\s*['"`]\/(test|debug|dev|internal|admin-bypass|backdoor)/gi,
    title: "Test/debug endpoint in production code",
    passTitle: "No test/debug endpoints found in production code",
    severity: "high",
    detail: "Test or debug endpoints left in production code can provide unauthenticated access to internal functionality.",
    remediation: "Remove test/debug endpoints or gate them behind authentication and a NODE_ENV !== 'production' check.",
  },
  {
    controlKey: "CQ-007",
    regex: /(eslint-disable|@ts-ignore|@ts-nocheck|no-verify|--force|--insecure|verify\s*[:=]\s*false)/g,
    title: "Disabled security checks",
    passTitle: "No disabled security or quality checks detected",
    severity: "low",
    detail: "Disabled security checks (linting rules, type checking, TLS verification) can mask real vulnerabilities.",
    remediation: "Re-enable the security check and fix the underlying issue rather than suppressing the warning.",
  },
];

const EXPOSED_ENV_PATTERN = /\.(env|env\.local|env\.production|env\.development)$/;

/**
 * CQ-001..007 and SECRET-002, wired to the control library. Extracted from
 * codeQuality.ts's former CHECKS array and standalone .env-file block --
 * same detection patterns, restructured to emit CheckResult per control,
 * with three fixes:
 *
 * 1. Only 3 of the 7 CHECKS-array items (stack traces, verbose errors, and
 *    test/debug endpoints) ever produced a PASS, and stack traces/verbose
 *    errors were joined by an AND, so either one firing suppressed the
 *    other's PASS even though it was independently clean. The other 4
 *    checks (debug console output, TODO/FIXME, debug mode, disabled
 *    checks) never emitted PASS at all -- a control genuinely checked and
 *    found clean was invisible in the report, the same asymmetric-PASS
 *    defect already fixed for AUTH-007 and AI-003. Every check here now
 *    independently reports PASS when clean.
 * 2. fs.readFileSync had no try/catch, so one unreadable file would throw
 *    and abort the entire scan -- the same defect class already fixed for
 *    SECRET-001, aiDisclosure.ts, and OSV-001.
 * 3. Dropped the legacy module's `/node_modules|\.git|dist|build/` path
 *    filter: walk() (the only source of the `files` this function is ever
 *    called with) already excludes those directories during the directory
 *    walk itself, so the filter could never match anything -- dead code,
 *    not a behavior change.
 */
export function scanCodeQualityControl(files: string[], targetRoot: string): CheckResult[] {
  const failedControlKeys = new Set<string>();
  let anyUnreadable = false;
  let anyFileRead = false;
  const results: CheckResult[] = [];

  for (const file of files) {
    const rel = path.relative(targetRoot, file);

    if (EXPOSED_ENV_PATTERN.test(file)) {
      failedControlKeys.add("SECRET-002");
      results.push({
        checkId: generateCheckId("Security", "SECRET-002:fail", rel),
        status: "FAIL",
        category: "Security",
        title: "Environment file committed to source",
        detail: "Environment files often contain secrets (API keys, database URLs, signing keys) that should never be in version control.",
        severity: "critical",
        file: rel,
        confidence: 95,
        detectionMethod: "heuristic",
        remediation: "Add .env* to .gitignore, remove the file from git history (git filter-branch or BFG), and rotate any secrets it contained.",
        controlKey: "SECRET-002",
      });
      continue; // matches legacy behavior: an .env file isn't also run through the content checks below
    }

    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }
    anyFileRead = true;

    for (const check of CHECKS) {
      const matches = text.match(check.regex);
      if (!matches || matches.length === 0) continue;
      if (check.matchAll && matches.length < 3) continue;

      failedControlKeys.add(check.controlKey);
      results.push({
        checkId: generateCheckId("Code Quality", `${check.controlKey}:fail`, rel),
        status: "FAIL",
        category: "Code Quality",
        title: check.title,
        detail: `${check.detail} Found ${matches.length} occurrence(s).`,
        severity: check.severity,
        file: rel,
        confidence: 90,
        detectionMethod: "regex",
        remediation: check.remediation,
        controlKey: check.controlKey,
      });
    }
  }

  for (const check of CHECKS) {
    if (failedControlKeys.has(check.controlKey)) continue;
    if (anyUnreadable) {
      results.push({
        checkId: generateCheckId("Code Quality", `${check.controlKey}:unreadable`),
        status: "NOT_VERIFIED",
        category: "Code Quality",
        title: `Some files could not be read for "${check.title}" analysis`,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: check.controlKey,
      });
      continue;
    }
    if (!anyFileRead) continue; // nothing was actually checked — no PASS to assert
    results.push({
      checkId: generateCheckId("Code Quality", `${check.controlKey}:pass`),
      status: "PASS",
      category: "Code Quality",
      title: check.passTitle,
      confidence: 90,
      detectionMethod: "regex",
      controlKey: check.controlKey,
    });
  }

  if (!failedControlKeys.has("SECRET-002") && files.length > 0) {
    // SECRET-002 is a filename check, independent of file readability, so
    // it still asserts PASS even when every other file was unreadable —
    // but only when there was a file set to check at all.
    results.push({
      checkId: generateCheckId("Security", "SECRET-002:pass"),
      status: "PASS",
      category: "Security",
      title: "No .env files committed to source",
      confidence: 95,
      detectionMethod: "heuristic",
      controlKey: "SECRET-002",
    });
  }

  return results;
}
