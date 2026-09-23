import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanAiCostLimitsControl } from "../src/scanner/controls/checks/aiCostLimitsControl";
import { scanAiToolExecutionControl } from "../src/scanner/controls/checks/aiToolExecutionControl";
import { scanAiOutputValidationControl } from "../src/scanner/controls/checks/aiOutputValidationControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the aiSecurity.ts migration onto the control library
 * (AI-002..004) -- prompt injection was already promoted to AI-001 in an
 * earlier round. aiSecurity.ts itself has been deleted; every meaningful
 * check it made now lives here or was deliberately dropped:
 *
 * - "AI API key hardcoded in source" was NOT migrated. secrets.ts's
 *   already-live SECRET-001 matches the real OpenAI (sk-...T3BlbkFJ...) and
 *   Anthropic (sk-ant-...) key formats precisely; aiSecurity.ts's own
 *   AI_KEY_PATTERNS was a strictly weaker, broader pattern for the same
 *   risk. Migrating it as its own control would duplicate a control that
 *   already exists and already does the job better.
 * - "Prompt injection guards or content filtering detected" (the legacy
 *   aggregate, PASS-only signal) was NOT migrated as a separate control.
 *   AI-001 (aiPromptInjectionControl.ts) uses the same guard pattern list,
 *   per-file, with both a PASS and a FAIL branch -- it already fully
 *   supersedes this signal.
 * - Token limits (denial-of-wallet) is now AI-002.
 * - Tool/function execution is now AI-003, redesigned: the legacy check
 *   could only ever FAIL whenever tool-calling capability was present, with
 *   no way to recognize an allowlist or human-approval safeguard even
 *   though its own remediation text recommended exactly that. AI-003 adds
 *   TOOL_SAFEGUARD_PATTERNS so implementing the recommended fix produces a
 *   PASS.
 * - Output validation is now AI-004.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("AI-002, AI-003, and AI-004 are registered", () => {
  for (const key of ["AI-002", "AI-003", "AI-004"]) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

// --- AI-002: token limits / denial-of-wallet ---

test("scanAiCostLimitsControl: FAIL when an AI SDK is used with no token limit", () => {
  const dir = tmpDir("nettle-aicost-");
  const file = writeTempFile(dir, "chat.js", `const openai = require('openai');\nawait openai.chat.completions.create({ model: 'gpt-4', messages });\n`);

  const results = scanAiCostLimitsControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AI-002");
  assert.equal(results[0].severity, "medium");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCostLimitsControl: PASS when a token limit is configured", () => {
  const dir = tmpDir("nettle-aicost-");
  const file = writeTempFile(dir, "chat.js", `const openai = require('openai');\nawait openai.chat.completions.create({ model: 'gpt-4', max_tokens: 1024, messages });\n`);

  const results = scanAiCostLimitsControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCostLimitsControl: no unearned finding when no AI SDK is used", () => {
  const dir = tmpDir("nettle-aicost-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanAiCostLimitsControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AI-003: tool execution safety ---

test("scanAiToolExecutionControl: FAIL when tool-calling is present with no safeguard", () => {
  const dir = tmpDir("nettle-aitool-");
  const file = writeTempFile(
    dir,
    "agent.js",
    `const res = await openai.chat.completions.create({ tools: [{ type: 'function', function: { name: 'deleteUser' } }] });\nexecuteTool(res.tool_calls[0]);\n`
  );

  const results = scanAiToolExecutionControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AI-003");
  assert.equal(results[0].severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiToolExecutionControl: PASS when an allowlist/approval safeguard is present (the legacy check never emitted this)", () => {
  const dir = tmpDir("nettle-aitool-");
  const file = writeTempFile(
    dir,
    "agent.js",
    `const res = await openai.chat.completions.create({ tools: allowedTools });\nif (res.tool_calls) { await requireApproval(res.tool_calls); }\n`
  );

  const results = scanAiToolExecutionControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiToolExecutionControl: no unearned finding when there's no tool-calling capability", () => {
  const dir = tmpDir("nettle-aitool-");
  const file = writeTempFile(dir, "chat.js", `await openai.chat.completions.create({ model: 'gpt-4', messages });\n`);

  assert.equal(scanAiToolExecutionControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AI-004: output validation ---

test("scanAiOutputValidationControl: FAIL when AI output is used with no validation", () => {
  const dir = tmpDir("nettle-aiout-");
  const file = writeTempFile(dir, "chat.js", `const res = await openai.chat.completions.create({ model: 'gpt-4', messages });\nconst text = res.choices[0].message.content;\n`);

  const results = scanAiOutputValidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AI-004");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiOutputValidationControl: PASS when output is schema-validated", () => {
  const dir = tmpDir("nettle-aiout-");
  const file = writeTempFile(dir, "chat.js", `const openai = require('openai');\nconst parsed = responseSchema.parse(aiOutput);\n`);

  const results = scanAiOutputValidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiOutputValidationControl: no unearned finding when no AI SDK is used", () => {
  const dir = tmpDir("nettle-aiout-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanAiOutputValidationControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- unreadable file paths ---

test("scanAiCostLimitsControl: NOT_VERIFIED when a file is unreadable and no AI SDK usage was found elsewhere", () => {
  const dir = tmpDir("nettle-aicost-unread-");
  const missing = path.join(dir, "does-not-exist.js");

  const results = scanAiCostLimitsControl([missing], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "AI-002");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives AI-002 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "AI Disclosure", title: "No token limits configured for AI API calls", severity: "medium", confidence: 70, controlKey: "AI-002" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /max_tokens/);
});

test("hydration gives AI-003 a real fix", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "AI Disclosure",
    title: "AI model has tool/function execution capability with no allowlist or approval safeguard",
    severity: "high",
    confidence: 60,
    controlKey: "AI-003",
  });
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /allowlist|approval/i);
});

test("AI-003 FAIL at its real confidence (60) downgrades one release-impact step below its critical/high default", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "AI Disclosure",
    title: "AI model has tool/function execution capability with no allowlist or approval safeguard",
    severity: "high",
    confidence: 60,
    controlKey: "AI-003",
  });
  assert.equal(hydrated.releaseImpact, "FIX_RECOMMENDED");
});

// --- scan comparison: a newly-migrated finding participates in the diff engine ---

function report(checkResults: CheckResult[]): ScanReport {
  return {
    scannedAt: "2026-01-01T00:00:00.000Z",
    target: "app",
    scannerVersion: "1.3.0",
    score: 80,
    findings: [],
    passed: [],
    checkResults,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
  };
}

function scanAt(id: string, scannedAt: string, checkResults: CheckResult[]): ScanForComparison {
  return { id, scannedAt, status: "COMPLETED", report: report(checkResults) };
}

test("AI-003 (a newly-migrated, redesigned control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirNoSafeguard = tmpDir("nettle-aitool-cmp-none-");
  writeTempFile(
    dirNoSafeguard,
    "agent.js",
    `const res = await openai.chat.completions.create({ tools: [{ type: 'function', function: { name: 'deleteUser' } }] });\nexecuteTool(res.tool_calls[0]);\n`
  );
  const dirWithSafeguard = tmpDir("nettle-aitool-cmp-safe-");
  writeTempFile(
    dirWithSafeguard,
    "agent.js",
    `const res = await openai.chat.completions.create({ tools: allowedTools });\nif (res.tool_calls) { await requireApproval(res.tool_calls); }\n`
  );

  const noSafeguardResults = scanAiToolExecutionControl([path.join(dirNoSafeguard, "agent.js")], dirNoSafeguard);
  const withSafeguardResults = scanAiToolExecutionControl([path.join(dirWithSafeguard, "agent.js")], dirWithSafeguard);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", noSafeguardResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", withSafeguardResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", noSafeguardResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "AI-003"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "AI-003"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirNoSafeguard, { recursive: true, force: true });
  fs.rmSync(dirWithSafeguard, { recursive: true, force: true });
});
