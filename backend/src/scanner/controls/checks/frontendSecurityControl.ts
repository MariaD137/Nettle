import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const LOCAL_STORAGE_SECRET_PATTERNS = [
  /localStorage\.(set|get)Item\s*\(\s*['"][^'"]*(?:token|jwt|secret|key|password|session|auth|credential|api_?key)[^'"]*['"]/gi,
  /sessionStorage\.(set|get)Item\s*\(\s*['"][^'"]*(?:token|jwt|secret|password|session|auth|credential|api_?key)[^'"]*['"]/gi,
];

const DANGEROUS_INNER_HTML = [
  /dangerouslySetInnerHTML/g,
  /\.innerHTML\s*=/g,
  /document\.write\s*\(/g,
];

const INLINE_EVENT_PATTERNS = [
  /on(click|load|error|submit|change|input|keydown|keyup|mouseover|focus|blur)\s*=\s*["']\s*[^"']*\(/gi,
];

const EVAL_PATTERNS = [
  /\beval\s*\(/g,
  /new\s+Function\s*\(/g,
  /setTimeout\s*\(\s*['"`]/g,
  /setInterval\s*\(\s*['"`]/g,
];

const SOURCE_MAP_PATTERNS = [
  /sourceMappingURL\s*=/,
  /sourceMap\s*:\s*true/,
  /devtool\s*:\s*['"]source-map['"]/,
];

interface PatternGroup {
  controlKey: string;
  patterns: RegExp[];
  category: "Frontend Security" | "Security";
  title: string;
  passTitle: string;
  severity: "critical" | "high" | "medium" | "low";
  detail: string;
  remediation: string;
}

const GROUPS: PatternGroup[] = [
  {
    controlKey: "FE-001",
    patterns: LOCAL_STORAGE_SECRET_PATTERNS,
    category: "Frontend Security",
    title: "Sensitive data stored in localStorage/sessionStorage",
    passTitle: "No sensitive data stored in localStorage/sessionStorage",
    severity: "high",
    detail: "Found reference(s) to storing tokens, secrets, or credentials in browser storage. This data is accessible to any JavaScript on the page, including XSS payloads.",
    remediation: "Use HttpOnly cookies for session tokens instead of localStorage. If you must use browser storage, store only non-sensitive identifiers.",
  },
  {
    controlKey: "FE-002",
    patterns: DANGEROUS_INNER_HTML,
    category: "Frontend Security",
    title: "Unescaped HTML injection (dangerouslySetInnerHTML or innerHTML)",
    passTitle: "No unescaped HTML injection patterns detected",
    severity: "high",
    detail: "Found use(s) of raw HTML insertion. If the content includes user input, this creates a direct XSS vulnerability.",
    remediation: "Use text content or React's JSX escaping instead. If you must render HTML, sanitize it first with DOMPurify: DOMPurify.sanitize(html).",
  },
  {
    controlKey: "FE-003",
    patterns: INLINE_EVENT_PATTERNS,
    category: "Frontend Security",
    title: "Inline event handler with embedded logic",
    passTitle: "No inline event handlers with embedded logic detected",
    severity: "medium",
    detail: "Found inline on*=\"...\" event handler attribute(s) calling a function. This blocks adopting a strict Content-Security-Policy and puts executable logic directly in markup.",
    remediation: "Replace the inline handler with addEventListener in JavaScript, or the framework's event-binding syntax (onClick={handler} in React).",
  },
  {
    controlKey: "INPUT-003",
    patterns: EVAL_PATTERNS,
    category: "Security",
    title: "Dynamic code execution (eval, Function, or string-based timer) detected in frontend code",
    passTitle: "No dynamic code execution (eval/Function/string-timer) detected in frontend code",
    severity: "critical",
    detail: "Found use(s) of eval(), new Function(), or string-based setTimeout/setInterval. These execute arbitrary code and are a primary XSS vector.",
    remediation: "Replace eval with JSON.parse (for data), a proper template engine, or direct function references for setTimeout/setInterval.",
  },
  {
    controlKey: "FE-004",
    patterns: SOURCE_MAP_PATTERNS,
    category: "Frontend Security",
    title: "Source maps may be exposed in production",
    passTitle: "No source map exposure detected",
    severity: "low",
    detail: "Source maps reveal the original un-minified source code, making it easier for attackers to find vulnerabilities.",
    remediation: "Disable source maps in production builds or restrict access to them. In webpack: devtool: false for production.",
  },
];

const IS_FRONTEND_SIGNAL = /react|jsx|tsx|document\.|window\.|localStorage|sessionStorage|addEventListener|querySelector|getElementById/i;

/**
 * FE-001..004, wired to the control library. The eval/Function/string-timer
 * group attaches to the existing INPUT-003 ("no eval() usage") rather than
 * a new control -- it's the same underlying risk INPUT-003 already covers
 * for eval() specifically (via Semgrep AST elsewhere in the pipeline), just
 * regex-detected here and broadened to new Function() and string-based
 * setTimeout/setInterval, which the AST rule doesn't cover. Same
 * multiple-CheckResults-per-control pattern the Semgrep migration already
 * established for DB-001/SECRET-001/NET-001/API-002.
 *
 * Extracted from frontendSecurity.ts's former inline checks, with three
 * fixes:
 *
 * 1. INLINE_EVENT_PATTERNS was declared but never actually used anywhere in
 *    the legacy module -- inline event handler detection was dead code
 *    that never ran. Now wired in as FE-003.
 * 2. The source-map check (FE-004) could FAIL but never PASS -- it wasn't
 *    included in the legacy module's PASS-emission block at all, the same
 *    asymmetric-PASS defect already fixed repeatedly across this
 *    migration. Every group here now independently reports PASS when
 *    clean.
 * 3. fs.readFileSync had no try/catch, so one unreadable file would throw
 *    and abort the entire scan.
 */
export function scanFrontendSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const frontendFiles = files.filter((f) => /\.(jsx|tsx|js|ts)$/.test(f));

  const failedControlKeys = new Set<string>();
  let hasFrontendCode = false;
  let anyUnreadable = false;
  const results: CheckResult[] = [];

  for (const file of frontendFiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    if (IS_FRONTEND_SIGNAL.test(text)) hasFrontendCode = true;

    for (const group of GROUPS) {
      for (const pattern of group.patterns) {
        const matches = text.match(pattern);
        if (!matches) continue;

        failedControlKeys.add(group.controlKey);
        results.push({
          checkId: generateCheckId(group.category, `${group.controlKey}:fail`, rel),
          status: "FAIL",
          category: group.category,
          title: group.title,
          detail: `${group.detail} Found ${matches.length} occurrence(s).`,
          severity: group.severity,
          file: rel,
          confidence: 85,
          detectionMethod: "regex",
          remediation: group.remediation,
          controlKey: group.controlKey,
        });
        break; // one finding per group per file, matching prior behavior
      }
    }
  }

  if (!hasFrontendCode) {
    // Nothing recognizable as frontend code was found — matches the legacy
    // module's own gate: don't assert PASS on checks that had nothing
    // meaningful to look at, but any FAIL already recorded above (e.g. a
    // backend file that happens to contain eval()) still stands.
    return results;
  }

  for (const group of GROUPS) {
    if (failedControlKeys.has(group.controlKey)) continue;
    if (anyUnreadable) {
      results.push({
        checkId: generateCheckId(group.category, `${group.controlKey}:unreadable`),
        status: "NOT_VERIFIED",
        category: group.category,
        title: `Some frontend files could not be read for "${group.title}" analysis`,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: group.controlKey,
      });
      continue;
    }
    results.push({
      checkId: generateCheckId(group.category, `${group.controlKey}:pass`),
      status: "PASS",
      category: group.category,
      title: group.passTitle,
      confidence: 85,
      detectionMethod: "regex",
      controlKey: group.controlKey,
    });
  }

  return results;
}
