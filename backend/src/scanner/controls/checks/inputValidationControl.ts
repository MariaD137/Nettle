import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const INPUT_VALIDATION_PATTERNS = [
  /require\(\s*['"]joi['"]\s*\)/,
  /from\s+['"]joi['"]/,
  /require\(\s*['"]zod['"]\s*\)/,
  /from\s+['"]zod['"]/,
  /require\(\s*['"]yup['"]\s*\)/,
  /from\s+['"]yup['"]/,
  /require\(\s*['"]express-validator['"]\s*\)/,
  /from\s+['"]express-validator['"]/,
  /require\(\s*['"]ajv['"]\s*\)/,
  /from\s+['"]ajv['"]/,
  /require\(\s*['"]superstruct['"]\s*\)/,
  /from\s+['"]superstruct['"]/,
  /\.safeParse\s*\(/,
  /\.validate\s*\(/,
  /\.parse\s*\(/,
];

const HAS_BODY_ROUTES_PATTERN = /app\.(post|put|patch)\s*\(/;

/**
 * API-004, wired to the control library. Extracted from apiSecurity.ts's
 * former inline input-validation block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Aggregate, like API-001:
 * a validation library is normally imported once, separate from the routes
 * that use it.
 */
export function scanInputValidationControl(files: string[], targetRoot: string): CheckResult[] {
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

  const hasInputValidation = INPUT_VALIDATION_PATTERNS.some((p) => p.test(allSource));
  if (hasInputValidation) {
    return [
      {
        checkId: generateCheckId("API Security", "API-004:pass"),
        status: "PASS",
        category: "API Security",
        title: "Input validation library detected (Zod, Joi, express-validator, or similar)",
        confidence: 75,
        detectionMethod: "heuristic",
        controlKey: "API-004",
      },
    ];
  }

  const hasBodyRoutes = HAS_BODY_ROUTES_PATTERN.test(allSource);
  if (!hasBodyRoutes) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("API Security", "API-004:unreadable"),
          status: "NOT_VERIFIED",
          category: "API Security",
          title: "Some files could not be read for input-validation analysis",
          detail: "No routes accepting a request body were found in the files that could be read, but at least one file was unreadable and may have contained one.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "API-004",
        },
      ];
    }
    return []; // no body-accepting routes at all — nothing to check
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("API Security", "API-004:unreadable"),
        status: "NOT_VERIFIED",
        category: "API Security",
        title: "Routes accepting a body were found but not every file could be read for input-validation analysis",
        detail: "No validation library was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "API-004",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("API Security", "API-004:fail"),
      status: "FAIL",
      category: "API Security",
      title: "No schema validation library detected",
      detail: "Without a validation library, request bodies are accepted as-is. Missing validation leads to type confusion, injection, and unexpected behavior.",
      severity: "medium",
      confidence: 75,
      detectionMethod: "heuristic",
      remediation: "Add schema validation with Zod (npm install zod) or Joi. Validate every request body: const schema = z.object({ email: z.string().email() }); schema.parse(req.body).",
      controlKey: "API-004",
    },
  ];
}
