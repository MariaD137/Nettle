import type { Control } from "../types";
import { registerControl } from "../registry";

export const AI_003: Control = {
  controlKey: "AI-003",
  category: "AI Disclosure",
  subcategory: "Unsafe tool execution",
  name: "AI tool/function-calling capability has an allowlist or approval safeguard",
  description:
    "When an AI model is given tool or function-calling capability, the model itself decides which tool to call " +
    "and with what arguments, based on the conversation so far. Without an allowlist restricting which tools can " +
    "run and/or a human approval step before a destructive one executes, a successful prompt injection can cause " +
    "the model to invoke tools the application never intended a user's input to trigger.",
  question: "Is tool/function-calling capability restricted by an allowlist or gated by human approval?",
  defaultSeverity: "high",

  passCriteria: "Tool/function-calling capability is present alongside a recognized allowlist or approval-gate pattern in the scanned source.",
  failCriteria: "Tool/function-calling capability is present with no recognized allowlist or approval-gate pattern found anywhere in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so tool-execution safeguards were not checked.",

  whyItMatters:
    "Tool-calling turns a prompt injection from an output-integrity problem into an action-integrity one: instead " +
    "of just manipulating what the model says, an attacker can manipulate what it does — call an internal API, " +
    "run a shell command, or send an email — using whatever tools the application exposed to it. An allowlist " +
    "limits the blast radius to tools that were deliberately exposed; a human-approval gate stops any single " +
    "prompt from directly causing a destructive action.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Restrict the tools passed to the model to an explicit allowlist, and require human approval before executing any destructive one (delete, send, pay, modify).",
      developerFix: "Maintain an explicit allowlist of callable tools rather than exposing every available function to the model. For tools with side effects, insert a confirmation/approval step between the model's tool-call request and actually executing it.",
      architectureFix: "Sandbox tool execution (least-privilege credentials scoped to only what each tool needs) so that even an unintended tool call from the model can't escalate beyond its own narrow capability.",
      codeExample: "const allowedTools = ['searchDocs', 'getWeather']; if (!allowedTools.includes(toolCall.name)) throw new Error('tool not allowed'); if (isDestructive(toolCall.name)) await requireApproval(toolCall);",
    },
  ],

  longTermHardening: "Log every tool call the model makes (tool name, arguments, and the triggering conversation) for audit and anomaly detection.",
  verificationMethod: "Rescan and confirm an allowlist or approval-gate pattern is now present alongside the tool/function-calling capability.",
  references: ["OWASP Top 10 for LLM Applications: LLM06 – Excessive Agency"],
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

registerControl(AI_003);
