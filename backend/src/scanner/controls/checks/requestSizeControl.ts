import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const REQUEST_SIZE_PATTERNS = [
  /express\.json\s*\(\s*\{[^}]*limit/,
  /bodyParser.*limit/,
  /express\.urlencoded\s*\(\s*\{[^}]*limit/,
  /payload.*limit/i,
];

const USES_BODY_PARSER_PATTERN = /express\.json\s*\(|bodyParser/;

/**
 * API-005, wired to the control library. Extracted from apiSecurity.ts's
 * former inline request-size block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file.
 */
export function scanRequestSizeControl(files: string[], targetRoot: string): CheckResult[] {
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

  const hasLimit = REQUEST_SIZE_PATTERNS.some((p) => p.test(allSource));
  if (hasLimit) {
    return [
      {
        checkId: generateCheckId("API Security", "API-005:pass"),
        status: "PASS",
        category: "API Security",
        title: "Request body size limit is configured",
        confidence: 75,
        detectionMethod: "heuristic",
        controlKey: "API-005",
      },
    ];
  }

  const usesBodyParser = USES_BODY_PARSER_PATTERN.test(allSource);
  if (!usesBodyParser) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("API Security", "API-005:unreadable"),
          status: "NOT_VERIFIED",
          category: "API Security",
          title: "Some files could not be read for request-size analysis",
          detail: "No body parser was found in the files that could be read, but at least one file was unreadable and may have used one.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "API-005",
        },
      ];
    }
    return []; // no body parser at all — nothing to check
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("API Security", "API-005:unreadable"),
        status: "NOT_VERIFIED",
        category: "API Security",
        title: "A body parser is used but not every file could be read for request-size analysis",
        detail: "No size limit was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "API-005",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("API Security", "API-005:fail"),
      status: "FAIL",
      category: "API Security",
      title: "No request body size limit configured",
      detail: "Without a body size limit, attackers can send extremely large payloads to exhaust memory and crash the server.",
      severity: "medium",
      confidence: 75,
      detectionMethod: "heuristic",
      remediation: "Set a body size limit: app.use(express.json({ limit: '1mb' })). Adjust the limit to match your largest expected payload.",
      controlKey: "API-005",
    },
  ];
}
