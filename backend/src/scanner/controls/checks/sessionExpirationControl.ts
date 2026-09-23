import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const EXPRESS_SESSION_PATTERN = /express-session|require\(\s*['"]express-session['"]\s*\)/;
const MAXAGE_PATTERN = /maxAge\s*:/;

/**
 * AUTH-007, wired to the control library. Extracted from sessionJwt.ts's
 * former inline session-maxAge block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file.
 *
 * The legacy version had no PASS branch at all for this check (see its
 * `if (!hasSessionMaxAge) { findings.push(...) }` with no else) — a
 * correctly-configured maxAge produced neither a finding nor a pass,
 * silently. Fixed here: a real PASS is now emitted when maxAge is present.
 */
export function scanSessionExpirationControl(files: string[], targetRoot: string): CheckResult[] {
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

  const usesSession = EXPRESS_SESSION_PATTERN.test(allSource);
  if (!usesSession) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("Session Management", "AUTH-007:unreadable"),
          status: "NOT_VERIFIED",
          category: "Session Management",
          title: "Some files could not be read for session-expiration analysis",
          detail: "No express-session usage was found in the files that could be read, but at least one file was unreadable and may have used it.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AUTH-007",
        },
      ];
    }
    return []; // app doesn't use express-session at all — nothing to check
  }

  const hasMaxAge = MAXAGE_PATTERN.test(allSource);
  if (hasMaxAge) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-007:pass"),
        status: "PASS",
        category: "Session Management",
        title: "Session expiration (maxAge) is configured",
        confidence: 70,
        detectionMethod: "heuristic",
        controlKey: "AUTH-007",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-007:unreadable"),
        status: "NOT_VERIFIED",
        category: "Session Management",
        title: "express-session is used but not every file could be read for session-expiration analysis",
        detail: "No maxAge was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-007",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("Session Management", "AUTH-007:fail"),
      status: "FAIL",
      category: "Session Management",
      title: "No session expiration (maxAge) configured",
      detail: "Sessions without maxAge persist indefinitely, increasing the window for session hijacking.",
      severity: "medium",
      confidence: 70,
      detectionMethod: "heuristic",
      remediation: "Set a session maxAge: cookie: { maxAge: 24 * 60 * 60 * 1000 } for a 24-hour session.",
      controlKey: "AUTH-007",
    },
  ];
}
