import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const JWT_USAGE_PATTERNS = [/jsonwebtoken/, /jwt\.sign/, /jwt\.verify/, /jose/];
const JWT_EXPIRY_PATTERNS = [/expiresIn\s*:/, /expiresIn\s*,/, /exp\s*:/, /maxAge\s*:/];

/**
 * AUTH-003, wired to the control library. Extracted from sessionJwt.ts's
 * former inline expiry check (see that file's history) — aggregate across
 * all files, like API-001, since sign options are normally set once rather
 * than per-route.
 */
export function scanJwtExpiryControl(files: string[], targetRoot: string): CheckResult[] {
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
          checkId: generateCheckId("Session Management", "AUTH-003:unreadable"),
          status: "NOT_VERIFIED",
          category: "Session Management",
          title: "Some files could not be read for JWT expiration analysis",
          detail: "No JWT usage was found in the files that could be read, but at least one file was unreadable and may have used JWTs.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AUTH-003",
        },
      ];
    }
    return []; // app doesn't use JWTs at all — nothing to check
  }

  const hasExpiry = JWT_EXPIRY_PATTERNS.some((p) => p.test(allSource));
  if (hasExpiry) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-003:pass"),
        status: "PASS",
        category: "Session Management",
        title: "JWT tokens have expiration configured",
        confidence: 80,
        detectionMethod: "heuristic",
        controlKey: "AUTH-003",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-003:unreadable"),
        status: "NOT_VERIFIED",
        category: "Session Management",
        title: "JWTs are used but not every file could be read for expiration analysis",
        detail: "No expiration pattern was found in the files that could be read, but at least one file was unreadable and may have configured it.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-003",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("Session Management", "AUTH-003:fail"),
      status: "FAIL",
      category: "Session Management",
      title: "JWT tokens issued without expiration",
      detail: "Tokens without an expiry never become invalid. A leaked token grants permanent access until the signing key is rotated.",
      severity: "high",
      confidence: 80,
      detectionMethod: "heuristic",
      remediation: "Set a short expiration on JWTs: jwt.sign(payload, secret, { expiresIn: '15m' }). Use refresh tokens for longer sessions.",
      controlKey: "AUTH-003",
    },
  ];
}
