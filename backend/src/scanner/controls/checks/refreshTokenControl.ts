import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const JWT_USAGE_PATTERNS = [/jsonwebtoken/, /jwt\.sign/, /jwt\.verify/, /jose/];
const REFRESH_TOKEN_PATTERNS = [/refresh[_-]?token/i, /refreshToken/, /token.*rotation/i, /rotate.*token/i];

/**
 * AUTH-005, wired to the control library. Extracted from sessionJwt.ts's
 * former inline refresh-token block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Aggregate, like AUTH-003
 * (JWT expiry): refresh-token issuance is normally defined once, separate
 * from wherever access tokens are signed.
 */
export function scanRefreshTokenControl(files: string[], targetRoot: string): CheckResult[] {
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
  if (!usesJwt) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("Session Management", "AUTH-005:unreadable"),
          status: "NOT_VERIFIED",
          category: "Session Management",
          title: "Some files could not be read for refresh-token analysis",
          detail: "No JWT usage was found in the files that could be read, but at least one file was unreadable and may have used JWTs.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AUTH-005",
        },
      ];
    }
    return []; // app doesn't use JWTs at all — nothing to check
  }

  const hasRefreshToken = REFRESH_TOKEN_PATTERNS.some((p) => p.test(allSource));
  if (hasRefreshToken) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-005:pass"),
        status: "PASS",
        category: "Session Management",
        title: "Refresh token pattern detected",
        confidence: 75,
        detectionMethod: "heuristic",
        controlKey: "AUTH-005",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-005:unreadable"),
        status: "NOT_VERIFIED",
        category: "Session Management",
        title: "JWTs are used but not every file could be read for refresh-token analysis",
        detail: "No refresh-token pattern was found in the files that could be read, but at least one file was unreadable and may have configured it.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-005",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("Session Management", "AUTH-005:fail"),
      status: "FAIL",
      category: "Session Management",
      title: "No refresh token rotation detected",
      detail: "Without refresh tokens, either access tokens are long-lived (risky) or users must re-authenticate frequently (poor UX).",
      severity: "medium",
      confidence: 75,
      detectionMethod: "heuristic",
      remediation: "Implement refresh token rotation: short-lived access tokens (15m) with one-time-use refresh tokens that rotate on each use.",
      controlKey: "AUTH-005",
    },
  ];
}
