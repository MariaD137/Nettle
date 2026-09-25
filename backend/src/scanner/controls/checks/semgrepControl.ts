import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { CheckResult, FindingCategory } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const JS_RULES_PATH = path.join(__dirname, "..", "..", "semgrep-rules", "nettle-js-rules.yaml");
const PY_RULES_PATH = path.join(__dirname, "..", "..", "semgrep-rules", "nettle-py-rules.yaml");

const SEMGREP_ARGS = [
  "--config",
  JS_RULES_PATH,
  "--config",
  PY_RULES_PATH,
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

function severityFor(semgrepSeverity: SemgrepResult["extra"]["severity"]): "critical" | "medium" | "info" {
  switch (semgrepSeverity) {
    case "ERROR": return "critical";
    case "WARNING": return "medium";
    case "INFO": return "info";
    default: return "medium";
  }
}

const REMEDIATION_BY_RULE: Record<string, string> = {
  "eval-usage": "Replace eval() with a safer alternative like JSON.parse() for data or a proper template engine for dynamic code.",
  "child-process-exec-template": "Use execFile() with an arguments array instead of exec() with string interpolation to prevent command injection.",
  "sql-string-concat": "Use parameterized queries (e.g. db.query('SELECT * FROM users WHERE id = ?', [id])) instead of string concatenation.",
  "hardcoded-jwt-secret": "Move the JWT secret to an environment variable (e.g. process.env.JWT_SECRET) and load it at runtime.",
  "disabled-tls-verification": "Remove rejectUnauthorized: false. If you need to trust a custom CA, configure the CA certificate explicitly instead.",
  "wildcard-cors": "Restrict the CORS origin to your actual frontend domain instead of allowing all origins with '*'.",
  "eval-usage-py": "Replace eval()/exec() with a safer alternative like json.loads() for data, or ast.literal_eval() for trusted literal expressions.",
  "shell-injection-py": "Use subprocess.run() with an argument list and shell=False (the default) instead of shell=True or os.system().",
  "sql-string-format-py": "Use parameterized queries (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (id,))) instead of building the query string yourself.",
  "hardcoded-jwt-secret-py": "Move the JWT secret to an environment variable (e.g. os.environ['JWT_SECRET']) and load it at runtime.",
  "disabled-tls-verification-py": "Remove verify=False. If you need to trust a custom CA, pass its certificate path to verify= explicitly instead.",
  "unsafe-deserialization-py": "Use json for untrusted data, or yaml.safe_load() instead of yaml.load(). Never unpickle data from an untrusted source.",
};

/** Which language a rule applies to — used to gate that rule's PASS/NOT_VERIFIED entries on whether this codebase actually contains any file of that language (see scanSemgrepControl's own comment on why: claiming "PASS, no eval() usage" for Python when the scan found zero .py files would be exactly the fabricated-PASS-for-an-unsupported/inapplicable-case this library's three-state model exists to prevent). */
const RULE_LANGUAGE: Record<string, "js" | "py"> = {
  "eval-usage": "js",
  "child-process-exec-template": "js",
  "sql-string-concat": "js",
  "hardcoded-jwt-secret": "js",
  "disabled-tls-verification": "js",
  "wildcard-cors": "js",
  "eval-usage-py": "py",
  "shell-injection-py": "py",
  "sql-string-format-py": "py",
  "hardcoded-jwt-secret-py": "py",
  "disabled-tls-verification-py": "py",
  "unsafe-deserialization-py": "py",
};

interface RuleMapping {
  controlKey: string;
  category: FindingCategory;
  failTitle: string;
  passTitle: string;
  notVerifiedTitle: string;
}

/**
 * Maps each Semgrep rule to a control. Two of the six rules (eval usage,
 * command injection) have no existing regex-based control anywhere in the
 * library, so they get new ones (INPUT-003/004). The other four detect a
 * risk an existing regex-based control already owns — SQL injection
 * (DB-001), hardcoded JWT secrets (SECRET-001), disabled TLS verification
 * (NET-001), and wildcard CORS (API-002) — from a genuinely different code
 * shape than that control's own regex catches (e.g. NET-001's regex doesn't
 * catch process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; API-002's doesn't
 * catch res.setHeader("Access-Control-Allow-Origin", "*")). Rather than
 * inventing a second, near-duplicate control for the same underlying
 * requirement, the AST-detected result is attached to the SAME controlKey
 * as complementary, higher-precision (AST, not text-match) evidence —
 * exactly the multiple-CheckResults-per-control pattern already used by
 * BROWSER-001's per-header subchecks.
 */
const RULE_MAP: Record<string, RuleMapping> = {
  "eval-usage": {
    controlKey: "INPUT-003",
    category: "Security",
    failTitle: "eval() usage detected",
    passTitle: "No eval() usage detected",
    notVerifiedTitle: "Eval usage could not be checked",
  },
  "child-process-exec-template": {
    controlKey: "INPUT-004",
    category: "Security",
    failTitle: "Shell command built via string interpolation passed to exec()",
    passTitle: "No shell commands built via string interpolation",
    notVerifiedTitle: "Command injection risk could not be checked",
  },
  "sql-string-concat": {
    controlKey: "DB-001",
    category: "Database",
    failTitle: "SQL injection pattern detected via AST analysis",
    passTitle: "No SQL injection patterns detected via AST analysis",
    notVerifiedTitle: "SQL injection (AST analysis) could not be checked",
  },
  "hardcoded-jwt-secret": {
    controlKey: "SECRET-001",
    category: "Security",
    failTitle: "JWT signed or verified with a hardcoded secret (detected via AST analysis)",
    passTitle: "No hardcoded JWT secrets detected via AST analysis",
    notVerifiedTitle: "Hardcoded JWT secrets (AST analysis) could not be checked",
  },
  "disabled-tls-verification": {
    controlKey: "NET-001",
    category: "Security",
    failTitle: "TLS certificate verification disabled (detected via AST analysis)",
    passTitle: "No disabled TLS verification detected via AST analysis",
    notVerifiedTitle: "Disabled TLS verification (AST analysis) could not be checked",
  },
  "wildcard-cors": {
    controlKey: "API-002",
    category: "API Security",
    failTitle: "CORS configured to allow any origin (detected via AST analysis)",
    passTitle: "No wildcard CORS configuration detected via AST analysis",
    notVerifiedTitle: "Wildcard CORS (AST analysis) could not be checked",
  },
  // Python rules map onto the SAME controlKeys as their JS/TS equivalents
  // above — same reasoning as those: this is complementary, language-
  // specific AST evidence for the same underlying control, not a second,
  // near-duplicate control. unsafe-deserialization-py has no direct JS rule
  // in this file, so it maps onto INPUT-002 ("Deserialization" —
  // controls/library/deserialization.ts), the existing control for exactly
  // this risk class.
  "eval-usage-py": {
    controlKey: "INPUT-003",
    category: "Security",
    failTitle: "eval()/exec() usage detected (Python)",
    passTitle: "No eval()/exec() usage detected (Python)",
    notVerifiedTitle: "Eval/exec usage could not be checked (Python)",
  },
  "shell-injection-py": {
    controlKey: "INPUT-004",
    category: "Security",
    failTitle: "Shell command run with shell=True/os.system() and dynamic input (Python)",
    passTitle: "No shell=True/os.system() command-injection pattern detected (Python)",
    notVerifiedTitle: "Command injection risk could not be checked (Python)",
  },
  "sql-string-format-py": {
    controlKey: "DB-001",
    category: "Database",
    failTitle: "SQL injection pattern detected via AST analysis (Python)",
    passTitle: "No SQL injection patterns detected via AST analysis (Python)",
    notVerifiedTitle: "SQL injection (AST analysis) could not be checked (Python)",
  },
  "hardcoded-jwt-secret-py": {
    controlKey: "SECRET-001",
    category: "Security",
    failTitle: "JWT signed or decoded with a hardcoded secret (detected via AST analysis, Python)",
    passTitle: "No hardcoded JWT secrets detected via AST analysis (Python)",
    notVerifiedTitle: "Hardcoded JWT secrets (AST analysis) could not be checked (Python)",
  },
  "disabled-tls-verification-py": {
    controlKey: "NET-001",
    category: "Security",
    failTitle: "TLS certificate verification disabled (detected via AST analysis, Python)",
    passTitle: "No disabled TLS verification detected via AST analysis (Python)",
    notVerifiedTitle: "Disabled TLS verification (AST analysis) could not be checked (Python)",
  },
  "unsafe-deserialization-py": {
    controlKey: "INPUT-002",
    category: "Security",
    failTitle: "Unsafe deserialization detected (pickle or yaml.load, Python)",
    passTitle: "No unsafe deserialization detected via AST analysis (Python)",
    notVerifiedTitle: "Unsafe deserialization could not be checked (Python)",
  },
};

/**
 * The Semgrep-backed AST checks, wired to the control library. Moved here
 * wholesale from semgrepScanner.ts (deleted), with two fixes:
 *
 * 1. Per-rule PASS, not all-or-nothing: the legacy scanWithSemgrepCheckResults
 *    only emitted PASS results when EVERY rule was clean (results.length ===
 *    0) — if even one rule fired, the other five clean rules got no PASS
 *    entry at all, so a control that Semgrep genuinely checked and found
 *    clean was invisible for that scan (neither PASS nor FAIL). Each rule
 *    now independently reports PASS or FAIL based on its own findings.
 * 2. checkId collision fix: the legacy generateCheckId call used only the
 *    file path, not the line, as the disambiguating third argument — two
 *    findings for the same rule in the same file (different lines) would
 *    collide onto the same checkId. Now includes the line.
 */
export function scanSemgrepControl(files: string[], targetRoot: string): CheckResult[] {
  const hasJs = files.some((f) => /\.(js|jsx|ts|tsx)$/i.test(f));
  const hasPy = files.some((f) => f.toLowerCase().endsWith(".py"));
  function ruleApplicable(ruleId: string): boolean {
    const lang = RULE_LANGUAGE[ruleId];
    if (lang === "js") return hasJs;
    if (lang === "py") return hasPy;
    return true;
  }

  let output: SemgrepOutput;
  try {
    const raw = runSemgrep(targetRoot);
    output = JSON.parse(raw);
  } catch (err) {
    return Object.entries(RULE_MAP)
      .filter(([ruleId]) => ruleApplicable(ruleId))
      .map(([ruleId, mapping]) => ({
        checkId: generateCheckId(mapping.category, `${mapping.controlKey}:ast-unavailable`, ruleId),
        status: "NOT_VERIFIED",
        category: mapping.category,
        title: mapping.notVerifiedTitle,
        detail: `Semgrep not available: ${(err as Error).message}`,
        confidence: 0,
        detectionMethod: "unknown",
        controlKey: mapping.controlKey,
      }));
  }

  const failedRuleIds = new Set<string>();
  const results: CheckResult[] = [];

  for (const r of output.results) {
    const ruleId = (r.check_id.split(".").pop() ?? "").replace(/^nettle-/, "");
    const mapping = RULE_MAP[ruleId];
    if (!mapping) continue; // defensive: only our own rules file is configured, so this shouldn't occur

    failedRuleIds.add(ruleId);
    const relFile = path.relative(targetRoot, r.path);
    results.push({
      checkId: generateCheckId(mapping.category, `${mapping.controlKey}:ast-fail`, `${relFile}:${r.start.line}`),
      status: "FAIL",
      category: mapping.category,
      title: mapping.failTitle,
      detail: r.extra.message.trim(),
      severity: severityFor(r.extra.severity),
      file: relFile,
      line: r.start.line,
      remediation: REMEDIATION_BY_RULE[ruleId] ?? undefined,
      ruleId: r.check_id,
      confidence: 95,
      detectionMethod: "ast",
      controlKey: mapping.controlKey,
    });
  }

  for (const [ruleId, mapping] of Object.entries(RULE_MAP)) {
    if (failedRuleIds.has(ruleId)) continue;
    // A rule for a language this codebase doesn't contain never ran
    // meaningfully — claiming PASS ("no eval() usage") for Python against a
    // pure-JS codebase would be exactly the fabricated-PASS-for-an-
    // inapplicable-language this library's three-state model exists to
    // prevent. A FAIL above is self-gating (Semgrep can only match a Python
    // rule inside an actual .py file), so only PASS needs this check.
    if (!ruleApplicable(ruleId)) continue;
    results.push({
      checkId: generateCheckId(mapping.category, `${mapping.controlKey}:ast-pass`, ruleId),
      status: "PASS",
      category: mapping.category,
      title: mapping.passTitle,
      confidence: 100,
      detectionMethod: "ast",
      controlKey: mapping.controlKey,
    });
  }

  return results;
}
