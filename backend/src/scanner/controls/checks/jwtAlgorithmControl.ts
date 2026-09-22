import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const JWT_USAGE_PATTERNS = [/jsonwebtoken/, /jwt\.sign/, /jwt\.verify/, /jose/];
const JWT_ALGO_NONE_PATTERN = /algorithm\s*:\s*['"]none['"]/i;

/**
 * AUTH-002, wired to the control library. Extracted from sessionJwt.ts's
 * former inline "algorithm: 'none'" check -- the single highest-severity
 * finding in that module, promoted on its own; the rest of sessionJwt.ts
 * (expiry, refresh tokens, session store, logout invalidation) is
 * unchanged, still legacy Finding/Pass.
 */
export function scanJwtAlgorithmControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let usesJwt = false;
  let anyFailure = false;
  let anyFileRead = false;

  for (const file of jsFiles) {
    const relFile = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (err) {
      results.push({
        checkId: generateCheckId("Session Management", "AUTH-002:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Session Management",
        title: "File could not be read for JWT algorithm analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "AUTH-002",
      });
      continue;
    }

    anyFileRead = true;
    if (JWT_USAGE_PATTERNS.some((p) => p.test(text))) usesJwt = true;

    if (JWT_ALGO_NONE_PATTERN.test(text)) {
      anyFailure = true;
      results.push({
        checkId: generateCheckId("Session Management", "AUTH-002:fail", relFile),
        status: "FAIL",
        category: "Session Management",
        title: "JWT algorithm set to 'none'",
        detail: "Using algorithm: 'none' disables signature verification entirely. Anyone can forge valid tokens.",
        severity: "critical",
        file: relFile,
        confidence: 95,
        detectionMethod: "regex",
        remediation: "Use a strong signing algorithm like RS256 or ES256. Never allow 'none' as an algorithm.",
        controlKey: "AUTH-002",
      });
    }
  }

  if (!anyFailure && anyFileRead && usesJwt) {
    results.push({
      checkId: generateCheckId("Session Management", "AUTH-002:pass"),
      status: "PASS",
      category: "Session Management",
      title: "No JWT 'none' algorithm configuration detected",
      confidence: 90,
      detectionMethod: "regex",
      controlKey: "AUTH-002",
    });
  }

  return results;
}
