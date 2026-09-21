import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { Finding, Pass, CheckResult } from "./types";
import { createNotVerified, generateCheckId } from "./threeStateModel";

const RULES_PATH = path.join(__dirname, "semgrep-rules", "nettle-js-rules.yaml");

const SEMGREP_ARGS = [
  "--config",
  RULES_PATH,
  "--no-git-ignore",
  "--disable-version-check",
  "--metrics=off",
  "--json",
  "--quiet",
];

/**
 * Runs Semgrep over `targetRoot` and returns its raw JSON.
 *
 * Semgrep resolves `.semgrepignore` relative to the *working directory*, not
 * the scan target (verified against the pinned 1.65.0). Uploaded archives are
 * untrusted, so running with our own cwd is what stops an attacker shipping a
 * `.semgrepignore` that hides their code from analysis. An earlier version
 * passed `--x-ignore-semgrepignore-files` for this, but that flag does not
 * exist in 1.65.0 — Semgrep exited 2 on every invocation and every AST check
 * silently degraded to NOT_VERIFIED.
 *
 * The cwd is a fresh empty directory rather than os.tmpdir() itself, so a
 * stray `.semgrepignore` left in the temp dir cannot influence a scan. It is
 * never the target directory, so the caller's own files are never read as
 * configuration and never modified.
 */
function runSemgrep(targetRoot: string): string {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-semgrep-cwd-"));
  try {
    return execFileSync("semgrep", [...SEMGREP_ARGS, targetRoot], {
      cwd,
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 20 * 1024 * 1024,
    });
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  extra: { severity: "ERROR" | "WARNING" | "INFO"; message: string };
}

interface SemgrepOutput {
  results: SemgrepResult[];
  errors: unknown[];
}

function severityFor(semgrepSeverity: SemgrepResult["extra"]["severity"]): Finding["severity"] {
  switch (semgrepSeverity) {
    case "ERROR": return "critical";
    case "WARNING": return "medium";
    case "INFO": return "info";
    default: return "medium";
  }
}

function titleFor(checkId: string): string {
  const ruleId = checkId.split(".").pop() ?? checkId;
  return ruleId
    .replace(/^nettle-/, "")
    .split("-")
    .join(" ")
    .replace(/^\w/, (c) => c.toUpperCase());
}

const REMEDIATION_BY_RULE: Record<string, string> = {
  "eval-usage": "Replace eval() with a safer alternative like JSON.parse() for data or a proper template engine for dynamic code.",
  "child-process-exec-template": "Use execFile() with an arguments array instead of exec() with string interpolation to prevent command injection.",
  "sql-string-concat": "Use parameterized queries (e.g. db.query('SELECT * FROM users WHERE id = ?', [id])) instead of string concatenation.",
  "hardcoded-jwt-secret": "Move the JWT secret to an environment variable (e.g. process.env.JWT_SECRET) and load it at runtime.",
  "disabled-tls-verification": "Remove rejectUnauthorized: false. If you need to trust a custom CA, configure the CA certificate explicitly instead.",
  "wildcard-cors": "Restrict the CORS origin to your actual frontend domain instead of allowing all origins with '*'.",
};

// The 6 AST checks that Semgrep performs
const SEMGREP_AST_CHECKS = [
  "SQL injection detection",
  "Command injection detection",
  "Eval usage detection",
  "Hardcoded JWT detection",
  "Disabled TLS verification detection",
  "Wildcard CORS detection",
];

export function scanWithSemgrep(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  let output: SemgrepOutput;
  try {
    const raw = runSemgrep(targetRoot);
    output = JSON.parse(raw);
  } catch (err) {
    // Return NOT_VERIFIED for each of the 6 AST checks that couldn't run
    return {
      findings: [
        {
          severity: "low",
          category: "Configuration",
          title: "Semgrep static analysis did not run",
          detail: `Couldn't run the Semgrep-based checks (secrets/injection/TLS/CORS patterns) for this scan: ${(err as Error).message}. The rest of the readiness report is unaffected.`,
          file: null,
          line: null,
          remediation: "Install Semgrep (pip install semgrep) to enable deeper static analysis checks.",
        },
      ],
      passed: [],
    };
  }

  if (output.results.length === 0) {
    return { findings: [], passed: [{ category: "Security", title: "No Semgrep findings (secrets, injection, TLS, CORS patterns)" }] };
  }

  const findings: Finding[] = output.results.map((r) => {
    const ruleId = (r.check_id.split(".").pop() ?? "").replace(/^nettle-/, "");
    return {
      severity: severityFor(r.extra.severity),
      category: "Security" as const,
      title: titleFor(r.check_id),
      detail: r.extra.message.trim(),
      file: `${path.relative(targetRoot, r.path)}:${r.start.line}`,
      line: null,
      remediation: REMEDIATION_BY_RULE[ruleId] ?? null,
    };
  });

  return { findings, passed: [] };
}

/**
 * Return new CheckResult format: includes NOT_VERIFIED for checks that couldn't run.
 */
export function scanWithSemgrepCheckResults(targetRoot: string): CheckResult[] {
  let output: SemgrepOutput;
  let semgrepAvailable = true;

  try {
    const raw = runSemgrep(targetRoot);
    output = JSON.parse(raw);
  } catch (err) {
    semgrepAvailable = false;
    // Return NOT_VERIFIED for each of the 6 AST checks that couldn't run
    return SEMGREP_AST_CHECKS.map((title) =>
      createNotVerified("Security", title, `Semgrep not available: ${(err as Error).message}`)
    );
  }

  const results: CheckResult[] = output.results.map((r) => {
    const ruleId = (r.check_id.split(".").pop() ?? "").replace(/^nettle-/, "");
    return {
      checkId: generateCheckId("Security", titleFor(r.check_id), r.path),
      status: "FAIL" as const,
      category: "Security" as const,
      title: titleFor(r.check_id),
      detail: r.extra.message.trim(),
      severity: severityFor(r.extra.severity),
      file: `${path.relative(targetRoot, r.path)}`,
      line: r.start.line,
      remediation: REMEDIATION_BY_RULE[ruleId] ?? undefined,
      ruleId: r.check_id,
      confidence: 95,
      detectionMethod: "ast" as const,
    };
  });

  // If no failures, add PASS results for all AST checks
  if (results.length === 0) {
    return SEMGREP_AST_CHECKS.map((title) => ({
      checkId: generateCheckId("Security", title),
      status: "PASS" as const,
      category: "Security" as const,
      title,
      confidence: 100,
      detectionMethod: "ast" as const,
    }));
  }

  return results;
}

