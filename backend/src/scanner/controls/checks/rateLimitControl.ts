import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const RATE_LIMIT_PATTERNS = [
  /rate[_-]?limit/i,
  /express-rate-limit/,
  /rateLimit/,
  /throttle/i,
  /req.*per.*second/i,
  /too many requests/i,
];

const HAS_ROUTES_PATTERN = /app\.(get|post|put|delete|patch)\s*\(/;

/**
 * API-001, wired to the control library. Extracted from apiSecurity.ts's
 * former inline rate-limit block (see that file's history) so its output
 * carries a controlKey and can be hydrated with a real recommendation —
 * logic unchanged, just moved and made resilient to an unreadable file.
 *
 * Aggregate, not per-file (unlike auth/secrets): the pattern this looks for
 * (rate-limit middleware registration) is normally defined once, separately
 * from the routes it protects, so per-file analysis would produce a FAIL for
 * every route file even when the limiter is correctly applied in the app's
 * entry point.
 */
export function scanApiRateLimitControl(files: string[], targetRoot: string): CheckResult[] {
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

  const hasRoutes = HAS_ROUTES_PATTERN.test(allSource);
  if (!hasRoutes) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("API Security", "API-001:unreadable"),
          status: "NOT_VERIFIED",
          category: "API Security",
          title: "Some files could not be read for rate-limit analysis",
          detail: "No routes were found in the files that could be read, but at least one file was unreadable and may have contained routes.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "API-001",
        },
      ];
    }
    return []; // no routes at all — nothing to check
  }

  const hasRateLimit = RATE_LIMIT_PATTERNS.some((p) => p.test(allSource));
  if (hasRateLimit) {
    return [
      {
        checkId: generateCheckId("API Security", "API-001:pass"),
        status: "PASS",
        category: "API Security",
        title: "Rate limiting is configured",
        confidence: 80,
        detectionMethod: "heuristic",
        controlKey: "API-001",
      },
    ];
  }

  // No rate-limit pattern found. If a file couldn't be read, that file might
  // have held the limiter — a confident FAIL would be a guess, not evidence.
  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("API Security", "API-001:unreadable"),
        status: "NOT_VERIFIED",
        category: "API Security",
        title: "Routes were found but not every file could be read for rate-limit analysis",
        detail: "No rate-limiting pattern was found in the files that could be read, but at least one file was unreadable and may have configured it.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "API-001",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("API Security", "API-001:fail"),
      status: "FAIL",
      category: "API Security",
      title: "No rate limiting detected",
      detail: "Without rate limiting, the API is vulnerable to brute-force attacks, credential stuffing, denial of service, and resource exhaustion.",
      severity: "high",
      confidence: 80,
      detectionMethod: "heuristic",
      remediation: "Add rate limiting middleware: npm install express-rate-limit, then app.use(rateLimit({ windowMs: 15*60*1000, max: 100 })).",
      controlKey: "API-001",
    },
  ];
}
