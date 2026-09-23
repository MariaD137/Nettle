import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const SET_COOKIE_PATTERN = /res\.cookie\s*\(|set-cookie|setCookie/i;
const CSRF_PATTERNS = [/csrf/i, /csurf/, /csrfToken/, /xsrf/i, /_csrf/];

/**
 * API-003, wired to the control library. Extracted from apiSecurity.ts's
 * former inline CSRF block -- same detection logic (only applicable when
 * cookie-based auth is in use, matching AUTH-004's own trigger condition)
 * and title/detail/remediation text, restructured to emit CheckResult with
 * a controlKey and to survive an unreadable file.
 */
export function scanCsrfControl(files: string[], targetRoot: string): CheckResult[] {
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
          checkId: generateCheckId("API Security", "API-003:unreadable"),
          status: "NOT_VERIFIED",
          category: "API Security",
          title: "Some files could not be read for CSRF analysis",
          detail: "No cookie-based authentication was found in the files that could be read, but at least one file was unreadable and may have used cookies.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "API-003",
        },
      ];
    }
    return []; // no cookie-based auth detected — CSRF via cookies doesn't apply
  }

  const hasCsrf = CSRF_PATTERNS.some((p) => p.test(allSource));
  if (hasCsrf) {
    return [
      {
        checkId: generateCheckId("API Security", "API-003:pass"),
        status: "PASS",
        category: "API Security",
        title: "CSRF protection is configured",
        confidence: 70,
        detectionMethod: "heuristic",
        controlKey: "API-003",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("API Security", "API-003:unreadable"),
        status: "NOT_VERIFIED",
        category: "API Security",
        title: "Cookies are used but not every file could be read for CSRF analysis",
        detail: "No CSRF protection was found in the files that could be read, but at least one file was unreadable and may have configured it.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "API-003",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("API Security", "API-003:fail"),
      status: "FAIL",
      category: "API Security",
      title: "No CSRF protection detected for cookie-based auth",
      detail: "The app uses cookies but no CSRF token or double-submit pattern was detected. This allows cross-site request forgery attacks.",
      severity: "medium",
      confidence: 70,
      detectionMethod: "heuristic",
      remediation: "Add CSRF protection: use the SameSite cookie attribute (strict or lax), or implement CSRF tokens with a library like csrf or csurf.",
      controlKey: "API-003",
    },
  ];
}
