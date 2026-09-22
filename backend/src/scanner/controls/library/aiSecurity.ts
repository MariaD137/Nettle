import type { Control } from "../types";
import { registerControl } from "../registry";

export const AI_001: Control = {
  controlKey: "AI-001",
  category: "AI Disclosure",
  subcategory: "Prompt injection",
  name: "User input reaches an AI prompt without visible sanitization",
  description:
    "Request-derived content (body, query, params, or an obviously user-supplied variable) that is concatenated " +
    "into an AI prompt, with no visible input filtering, moderation, or guardrail nearby, lets a user's own input " +
    "influence or override the system's instructions to the model.",
  question: "Is user-supplied input filtered, validated, or otherwise guarded before it reaches an AI prompt?",
  defaultSeverity: "high",

  passCriteria: "User-derived content reaching a prompt is accompanied by a recognized guard (input filtering, moderation, a guardrail library, or structured system/user role separation) in the same file.",
  failCriteria: "Request-derived content (req.body/query/params, or a user_input/user_message-shaped variable) is concatenated toward a prompt/message/content field with no recognized guard present in the file.",
  notVerifiedCriteria: "This is a regex-level heuristic over source text, not a data-flow analysis — it cannot confirm the guard it did or didn't find is actually applied to the same input on the path that reaches the prompt, only that a pattern for one is or isn't present nearby.",

  whyItMatters:
    "Prompt injection is the AI-specific analog of the injection vulnerabilities this scanner already checks for " +
    "in SQL and shell commands: an attacker who controls text that reaches the model's prompt can attempt to " +
    "override the system's instructions, exfiltrate the system prompt, or push the model toward output or tool " +
    "calls the application never intended it to produce. Unlike SQL, there is no fully reliable technical fix — " +
    "defense is layered filtering, structured roles, and treating model output as untrusted, not a single escape function.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Add input filtering or a moderation check on user-supplied content before it reaches the prompt, and keep it in a separate user-role message rather than concatenated into the system prompt.",
      developerFix: "Use the provider's structured message format (separate system/user roles) instead of string-concatenating user input into one prompt block — this alone limits how much a user's text can look like an instruction. Add an input filter or moderation call ahead of it for the content that matters most (anything that could reach a tool call or a privileged action).",
      architectureFix: "Never let AI output directly trigger a privileged/destructive action without a human-approved or allowlisted intermediate step — treat model output as untrusted input to the rest of the system, the same as any other user-controlled data.",
      codeExample: "const messages = [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: sanitizedUserInput }];",
    },
  ],

  longTermHardening: "Add adversarial test cases (\"ignore previous instructions and...\") to the test suite for any endpoint that puts user input in front of a model, and log/monitor prompts and outputs for review.",
  verificationMethod: "Rescan and confirm a recognized guard is now present in the same file as the user-input-to-prompt pattern.",
  references: ["OWASP Top 10 for LLM Applications: LLM01 – Prompt Injection"],
  complianceMappings: [],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(AI_001);
