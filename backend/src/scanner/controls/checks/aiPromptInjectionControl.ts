import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const PROMPT_INJECTION_GUARDS = [
  /prompt.*inject/i,
  /sanitize.*prompt/i,
  /input.*filter/i,
  /system.*prompt.*\+/i,
  /guardrail/i,
  /content.*filter/i,
  /moderat/i,
  /validate.*input.*before.*(?:ai|llm|model|prompt)/i,
];

const USER_INPUT_TO_PROMPT = /(?:req\.body|req\.query|req\.params|user_?input|user_?message)\b[^;]*(?:prompt|message|content)\s*[:=+]/gi;

/**
 * AI-001, wired to the control library. Extracted from aiSecurity.ts's
 * former inline prompt-injection check -- the single item the product spec
 * lists first under its dedicated AI Security category, promoted on its
 * own; the rest of aiSecurity.ts (AI key exposure, token limits, tool
 * execution risk, output validation) is unchanged, still legacy
 * Finding/Pass.
 *
 * Per-file, like SECRET-001/DB-001: the guard-pattern check is scoped to
 * the same file as the user-input-to-prompt match, matching the original
 * module's behavior (a guard anywhere in the SAME file suppresses the
 * finding for that file, not just the same line).
 */
export function scanAiPromptInjectionControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  for (const file of jsFiles) {
    const relFile = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (err) {
      results.push({
        checkId: generateCheckId("AI Disclosure", "AI-001:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "AI Disclosure",
        title: "File could not be read for prompt-injection analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "AI-001",
      });
      continue;
    }

    const hasGuard = PROMPT_INJECTION_GUARDS.some((p) => p.test(text));
    USER_INPUT_TO_PROMPT.lastIndex = 0;
    const reachesPrompt = USER_INPUT_TO_PROMPT.test(text);

    if (reachesPrompt && !hasGuard) {
      results.push({
        checkId: generateCheckId("AI Disclosure", "AI-001:fail", relFile),
        status: "FAIL",
        category: "AI Disclosure",
        title: "User input passed directly to AI prompt without sanitization",
        detail: "User-supplied content is concatenated into AI prompts without visible input filtering. This enables prompt injection attacks that can override system instructions.",
        severity: "high",
        file: relFile,
        confidence: 60, // regex-level heuristic, not data-flow — see the control's notVerifiedCriteria
        detectionMethod: "heuristic",
        remediation: "Validate and sanitize user input before including it in prompts. Use structured message formats (separate system/user roles) and consider input/output guardrails.",
        controlKey: "AI-001",
      });
    } else if (reachesPrompt && hasGuard) {
      results.push({
        checkId: generateCheckId("AI Disclosure", "AI-001:pass", relFile),
        status: "PASS",
        category: "AI Disclosure",
        title: "User input reaching an AI prompt has a visible guard in the same file",
        confidence: 60,
        detectionMethod: "heuristic",
        controlKey: "AI-001",
      });
    }
    // Neither pattern present: nothing to report for this file — it isn't
    // putting user input in front of a model at all, on this heuristic.
  }

  return results;
}
