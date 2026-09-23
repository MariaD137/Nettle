import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const JWT_USAGE_PATTERNS = [/jsonwebtoken/, /jwt\.sign/, /jwt\.verify/, /jose/];
const EXPRESS_SESSION_PATTERN = /express-session|require\(\s*['"]express-session['"]\s*\)/;
const LOGOUT_INVALIDATION_PATTERNS = [
  /blacklist|blocklist|revoke|invalidate.*token|token.*invalid/i,
  /destroy.*session|session.*destroy|req\.session\.destroy/i,
  /delete.*token|remove.*token|clear.*session/i,
];

/**
 * AUTH-008, wired to the control library. Extracted from sessionJwt.ts's
 * former inline logout-invalidation block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Applicable whenever the app
 * uses JWTs or sessions, matching the legacy `(usesJwt || usesSession)` gate.
 */
export function scanLogoutInvalidationControl(files: string[], targetRoot: string): CheckResult[] {
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

  const usesJwt = JWT_USAGE_PATTERNS.some((p) => p.test(allSource));
  const usesSession = EXPRESS_SESSION_PATTERN.test(allSource);

  if (!usesJwt && !usesSession) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("Session Management", "AUTH-008:unreadable"),
          status: "NOT_VERIFIED",
          category: "Session Management",
          title: "Some files could not be read for logout-invalidation analysis",
          detail: "No JWT or session usage was found in the files that could be read, but at least one file was unreadable and may have used either.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AUTH-008",
        },
      ];
    }
    return []; // app doesn't use JWTs or sessions at all — nothing to check
  }

  const hasLogoutInvalidation = LOGOUT_INVALIDATION_PATTERNS.some((p) => p.test(allSource));
  if (hasLogoutInvalidation) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-008:pass"),
        status: "PASS",
        category: "Session Management",
        title: "Token/session invalidation on logout detected",
        confidence: 65,
        detectionMethod: "heuristic",
        controlKey: "AUTH-008",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-008:unreadable"),
        status: "NOT_VERIFIED",
        category: "Session Management",
        title: "JWTs or sessions are used but not every file could be read for logout-invalidation analysis",
        detail: "No invalidation pattern was found in the files that could be read, but at least one file was unreadable and may have configured it.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-008",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("Session Management", "AUTH-008:fail"),
      status: "FAIL",
      category: "Session Management",
      title: "No token/session invalidation on logout",
      detail: "Without explicit token blacklisting or session destruction on logout, tokens remain valid until they expire naturally.",
      severity: "medium",
      confidence: 65,
      detectionMethod: "heuristic",
      remediation: "Destroy sessions on logout (req.session.destroy()) or maintain a token blacklist/revocation list for JWTs.",
      controlKey: "AUTH-008",
    },
  ];
}
