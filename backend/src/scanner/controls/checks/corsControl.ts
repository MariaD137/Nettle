import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const CORS_ANY_PATTERN = /cors/i;
const CORS_WILDCARD_PATTERN = /origin\s*:\s*['"]?\*['"]?|credentials\s*:\s*true.*origin\s*:\s*true/i;

/**
 * API-002, wired to the control library. Extracted from apiSecurity.ts's
 * former inline CORS block (see that file's history) — aggregate across all
 * files, like API-001, since CORS is normally configured once at the app's
 * entry point rather than per-route.
 */
export function scanCorsControl(files: string[], targetRoot: string): CheckResult[] {
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

  const usesCors = CORS_ANY_PATTERN.test(allSource);
  if (!usesCors) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("API Security", "API-002:unreadable"),
          status: "NOT_VERIFIED",
          category: "API Security",
          title: "Some files could not be read for CORS analysis",
          detail: "No CORS configuration was found in the files that could be read, but at least one file was unreadable and may have configured it.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "API-002",
        },
      ];
    }
    // No CORS configuration found at all — may be a server-rendered app with
    // no cross-origin API surface, or CORS enforced at the infra layer.
    // Neither is evidence of a misconfiguration, so nothing to report.
    return [];
  }

  const isWildcard = CORS_WILDCARD_PATTERN.test(allSource);
  if (isWildcard) {
    return [
      {
        checkId: generateCheckId("API Security", "API-002:fail"),
        status: "FAIL",
        category: "API Security",
        title: "CORS allows all origins (wildcard)",
        detail: "A wildcard CORS policy allows any website to make cross-origin requests to this API. Combined with credentials, this enables cross-site request attacks.",
        severity: "high",
        confidence: 85,
        detectionMethod: "heuristic",
        remediation: "Restrict CORS to your actual frontend domain: cors({ origin: 'https://yourapp.com', credentials: true }).",
        controlKey: "API-002",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("API Security", "API-002:unreadable"),
        status: "NOT_VERIFIED",
        category: "API Security",
        title: "CORS is configured but not every file could be read for wildcard analysis",
        detail: "No wildcard origin was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "API-002",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("API Security", "API-002:pass"),
      status: "PASS",
      category: "API Security",
      title: "CORS is configured with specific origins",
      confidence: 85,
      detectionMethod: "heuristic",
      controlKey: "API-002",
    },
  ];
}
