import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const TOOL_EXECUTION_PATTERNS = [
  /function_call/i, /tool_use/i, /tools\s*:/, /functions\s*:/,
  /tool_choice/i, /exec\s*\(/, /spawn\s*\(/, /execSync\s*\(/,
];

const TOOL_SAFEGUARD_PATTERNS = [
  /allow[_-]?list/i,
  /allowed[_-]?tools/i,
  /tool.*allowlist/i,
  /require.*approval/i,
  /requireApproval/i,
  /human.*(?:review|approval|in.*the.*loop)/i,
  /confirm.*before.*(?:execut|run|call)/i,
  /approval.*(?:flow|required|gate)/i,
];

/**
 * AI-003, wired to the control library. Redesigned, not just extracted:
 * aiSecurity.ts's legacy tool-execution check could only ever emit FAIL
 * whenever tool/function-calling capability was present -- it had no PASS
 * path at all, so an app that already implemented an allowlist and a
 * human-approval gate (exactly what the finding's own remediation text
 * recommended) still got flagged as if it had done nothing. Same real bug
 * shape as AUTH-007's maxAge check in the previous round: a check that
 * structurally cannot recognize the fix it asks for isn't measuring
 * anything. This version adds TOOL_SAFEGUARD_PATTERNS so a genuine
 * allowlist/approval-gate pattern is recognized as satisfying the control.
 *
 * Aggregate, like the legacy check: tool/function-calling capability and
 * its safeguards are normally not defined at the same call site.
 */
export function scanAiToolExecutionControl(files: string[], targetRoot: string): CheckResult[] {
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

  const hasToolExecution = TOOL_EXECUTION_PATTERNS.some((p) => p.test(allSource));
  if (!hasToolExecution) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("AI Disclosure", "AI-003:unreadable"),
          status: "NOT_VERIFIED",
          category: "AI Disclosure",
          title: "Some files could not be read for AI tool-execution analysis",
          detail: "No tool/function-calling capability was found in the files that could be read, but at least one file was unreadable and may have used it.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AI-003",
        },
      ];
    }
    return []; // no tool/function-calling capability at all — nothing to check
  }

  const hasSafeguard = TOOL_SAFEGUARD_PATTERNS.some((p) => p.test(allSource));
  if (hasSafeguard) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-003:pass"),
        status: "PASS",
        category: "AI Disclosure",
        title: "AI tool-execution capability has an allowlist or approval safeguard",
        confidence: 60,
        detectionMethod: "heuristic",
        controlKey: "AI-003",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-003:unreadable"),
        status: "NOT_VERIFIED",
        category: "AI Disclosure",
        title: "AI tool-execution capability is present but not every file could be read for safeguard analysis",
        detail: "No allowlist or approval-gate pattern was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AI-003",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("AI Disclosure", "AI-003:fail"),
      status: "FAIL",
      category: "AI Disclosure",
      title: "AI model has tool/function execution capability with no allowlist or approval safeguard",
      detail: "The app gives the AI model access to tools or functions. Without an allowlist and approval flow, a prompt injection could cause the model to execute unintended actions.",
      severity: "high",
      confidence: 60,
      detectionMethod: "heuristic",
      remediation: "Implement a tool allowlist, sandbox tool execution, and require human approval for destructive actions (delete, send, pay).",
      controlKey: "AI-003",
    },
  ];
}
