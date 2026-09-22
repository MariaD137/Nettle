import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const HTTPS_PATTERNS = [
  /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
  /https?\s*[:=]\s*false/gi,
  /rejectUnauthorized\s*:\s*false/g,
];

/**
 * NET-001, wired to the control library. Extracted from apiSecurity.ts's
 * former inline HTTPS/TLS block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file.
 */
export function scanTransportSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let anyFailure = false;
  let anyFileRead = false;

  for (const file of jsFiles) {
    const relFile = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (err) {
      results.push({
        checkId: generateCheckId("Security", "NET-001:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Security",
        title: "File could not be read for transport-security analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "NET-001",
      });
      continue;
    }

    anyFileRead = true;
    for (const pattern of HTTPS_PATTERNS) {
      const matches = text.match(pattern);
      if (!matches || matches.length === 0) continue;

      anyFailure = true;
      const isRejectUnauthorized = /rejectUnauthorized/.test(matches[0]);
      results.push({
        checkId: generateCheckId("Security", `NET-001:fail:${isRejectUnauthorized ? "tls" : "http"}`, relFile),
        status: "FAIL",
        category: "Security",
        title: isRejectUnauthorized ? "TLS certificate verification disabled" : "Non-HTTPS URL in server code",
        detail: isRejectUnauthorized
          ? "Disabling certificate verification makes the connection vulnerable to man-in-the-middle attacks."
          : `Found ${matches.length} non-localhost HTTP URL(s). Data sent over HTTP is visible to anyone on the network path.`,
        severity: isRejectUnauthorized ? "critical" : "medium",
        file: relFile,
        confidence: 85,
        detectionMethod: "regex",
        remediation: isRejectUnauthorized
          ? "Remove rejectUnauthorized: false. If you need to trust a custom CA, configure the CA certificate explicitly."
          : "Change HTTP URLs to HTTPS. If connecting to a local service, use localhost or 127.0.0.1.",
        controlKey: "NET-001",
      });
      break; // one finding per file, matching prior behavior
    }
  }

  if (!anyFailure && anyFileRead) {
    results.push({
      checkId: generateCheckId("Security", "NET-001:pass"),
      status: "PASS",
      category: "Security",
      title: "No non-HTTPS URLs or disabled TLS verification detected",
      confidence: 85,
      detectionMethod: "regex",
      controlKey: "NET-001",
    });
  }

  return results;
}
