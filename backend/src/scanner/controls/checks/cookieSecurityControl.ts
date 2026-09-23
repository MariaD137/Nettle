import fs from "fs";
import type { CheckResult, Severity } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const SET_COOKIE_PATTERN = /res\.cookie\s*\(|set-cookie|setCookie/i;

interface CookieFlagCheck {
  name: string;
  pattern: RegExp;
  severity: Severity;
  detail: string;
  remediation: string;
}

const FLAG_CHECKS: CookieFlagCheck[] = [
  {
    name: "HttpOnly",
    pattern: /httpOnly\s*:\s*true/,
    severity: "high",
    detail: "Without HttpOnly, cookies are accessible to JavaScript — an XSS vulnerability can steal session tokens.",
    remediation: "Set httpOnly: true on all authentication cookies: res.cookie('session', token, { httpOnly: true }).",
  },
  {
    name: "Secure",
    pattern: /secure\s*:\s*true/,
    severity: "medium",
    detail: "Without the Secure flag, cookies are sent over plain HTTP, allowing interception on untrusted networks.",
    remediation: "Set secure: true on cookies in production: res.cookie('session', token, { secure: true }).",
  },
  {
    name: "SameSite",
    pattern: /sameSite\s*:\s*['"](strict|lax)['"]/i,
    severity: "medium",
    detail: "Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
    remediation: "Set sameSite: 'strict' (or 'lax') on cookies: res.cookie('session', token, { sameSite: 'strict' }).",
  },
];

/**
 * AUTH-004, wired to the control library. Extracted from apiSecurity.ts's
 * former inline cookie-flags block -- same detection logic and
 * title/detail/remediation text per flag, restructured as one CheckResult
 * per flag (matching securityHeadersControl.ts's multi-subcheck pattern)
 * rather than a single combined finding, so each missing flag gets its own
 * fingerprint, recommendation, and fix-center entry.
 */
export function scanCookieSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let allSource = "";
  let anyUnreadable = false;
  for (const file of jsFiles) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
    } catch {
      anyUnreadable = true;
    }
  }

  const usesCookies = SET_COOKIE_PATTERN.test(allSource);
  if (!usesCookies) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("Session Management", "AUTH-004:unreadable"),
          status: "NOT_VERIFIED",
          category: "Session Management",
          title: "Some files could not be read for cookie security analysis",
          detail: "No cookie-setting calls were found in the files that could be read, but at least one file was unreadable and may have set cookies.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AUTH-004",
        },
      ];
    }
    return []; // no cookies set at all — nothing to check
  }

  const results: CheckResult[] = [];
  for (const check of FLAG_CHECKS) {
    if (check.pattern.test(allSource)) {
      results.push({
        checkId: generateCheckId("Session Management", `AUTH-004:pass:${check.name}`),
        status: "PASS",
        category: "Session Management",
        title: `Cookies set with ${check.name}`,
        confidence: 75,
        detectionMethod: "heuristic",
        controlKey: "AUTH-004",
      });
    } else {
      results.push({
        checkId: generateCheckId("Session Management", `AUTH-004:fail:${check.name}`),
        status: "FAIL",
        category: "Session Management",
        title: `Cookies set without ${check.name} flag`,
        detail: check.detail,
        severity: check.severity,
        confidence: 75,
        detectionMethod: "heuristic",
        remediation: check.remediation,
        controlKey: "AUTH-004",
      });
    }
  }

  return results;
}
