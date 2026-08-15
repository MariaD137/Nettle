import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

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

export function scanFrontendSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const frontendFiles = files.filter((f) => /\.(jsx|tsx|js|ts)$/.test(f));
  let hasLocalStorageSecrets = false;
  let hasDangerousHtml = false;
  let hasEval = false;
  let hasSourceMaps = false;
  let hasFrontendCode = false;

  for (const file of frontendFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    const isFrontend = /react|jsx|tsx|document\.|window\.|localStorage|sessionStorage|addEventListener|querySelector|getElementById/i.test(text);
    if (isFrontend) hasFrontendCode = true;

    for (const pattern of LOCAL_STORAGE_SECRET_PATTERNS) {
      const matches = text.match(pattern);
      if (matches) {
        hasLocalStorageSecrets = true;
        findings.push({
          severity: "high",
          category: "Frontend Security",
          title: "Sensitive data stored in localStorage/sessionStorage",
          detail: `Found ${matches.length} reference(s) to storing tokens, secrets, or credentials in browser storage. This data is accessible to any JavaScript on the page, including XSS payloads.`,
          file: rel,
        line: null,
          remediation: "Use HttpOnly cookies for session tokens instead of localStorage. If you must use browser storage, store only non-sensitive identifiers.",
        });
        break;
      }
    }

    for (const pattern of DANGEROUS_INNER_HTML) {
      const matches = text.match(pattern);
      if (matches) {
        hasDangerousHtml = true;
        findings.push({
          severity: "high",
          category: "Frontend Security",
          title: "Unescaped HTML injection (dangerouslySetInnerHTML or innerHTML)",
          detail: `Found ${matches.length} use(s) of raw HTML insertion. If the content includes user input, this creates a direct XSS vulnerability.`,
          file: rel,
        line: null,
          remediation: "Use text content or React's JSX escaping instead. If you must render HTML, sanitize it first with DOMPurify: DOMPurify.sanitize(html).",
        });
        break;
      }
    }

    for (const pattern of EVAL_PATTERNS) {
      const matches = text.match(pattern);
      if (matches) {
        hasEval = true;
        findings.push({
          severity: "critical",
          category: "Frontend Security",
          title: "Dynamic code execution (eval or Function constructor)",
          detail: `Found ${matches.length} use(s) of eval(), new Function(), or string-based setTimeout/setInterval. These execute arbitrary code and are a primary XSS vector.`,
          file: rel,
        line: null,
          remediation: "Replace eval with JSON.parse (for data), a proper template engine, or direct function references for setTimeout/setInterval.",
        });
        break;
      }
    }

    for (const pattern of SOURCE_MAP_PATTERNS) {
      if (pattern.test(text)) {
        hasSourceMaps = true;
        findings.push({
          severity: "low",
          category: "Frontend Security",
          title: "Source maps may be exposed in production",
          detail: "Source maps reveal the original un-minified source code, making it easier for attackers to find vulnerabilities.",
          file: rel,
        line: null,
          remediation: "Disable source maps in production builds or restrict access to them. In webpack: devtool: false for production.",
        });
        break;
      }
    }
  }

  if (hasFrontendCode && !hasLocalStorageSecrets) {
    passed.push({ category: "Frontend Security", title: "No sensitive data stored in localStorage/sessionStorage" });
  }
  if (hasFrontendCode && !hasDangerousHtml) {
    passed.push({ category: "Frontend Security", title: "No unescaped HTML injection patterns detected" });
  }
  if (hasFrontendCode && !hasEval) {
    passed.push({ category: "Frontend Security", title: "No dynamic code execution (eval/Function) detected" });
  }

  return { findings, passed };
}
