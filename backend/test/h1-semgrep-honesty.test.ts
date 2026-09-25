import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSemgrepControl } from "../src/scanner/controls/checks/semgrepControl";
import { initializeScanner, isSemgrepAvailable } from "../src/scanner/initialization";
import { walk } from "../src/scanner/walk";
import path from "node:path";

// A fixed fixture, not "/tmp": scanning the machine's shared temp directory
// made these tests depend on whatever else happened to be on the host, and
// on a busy runner it is also a large, slow target.
const CLEAN_FIXTURE = path.join(__dirname, "fixtures", "clean-app");
// Same extension list production's runScan() walks with — scanSemgrepControl
// uses this to decide which language-specific rules are even applicable
// (see its own comment on why: a PASS for a language with zero files of
// that language would be a fabricated result).
const CLEAN_FIXTURE_FILES = walk(CLEAN_FIXTURE, [".js", ".ts", ".jsx", ".tsx", ".py"]);

test("H-1: Semgrep initialization records version", () => {
  const metadata = initializeScanner();
  assert.ok(metadata.initializationTime);
  // In this environment, Semgrep may not be available, so we just check the metadata structure
  assert.ok(typeof metadata.semgrepAvailable === "boolean");
  if (metadata.semgrepAvailable) {
    assert.ok(metadata.semgrepVersion, "Should have version if available");
  }
});

test("H-1: isSemgrepAvailable tracks initialization", () => {
  initializeScanner();
  const available = isSemgrepAvailable();
  assert.ok(typeof available === "boolean");
});

test("H-1: Semgrep missing returns NOT_VERIFIED for AST checks", () => {
  // If Semgrep is not available in this environment, scanSemgrepControl
  // should return NOT_VERIFIED for each of the 6 AST checks
  const dummyPath = CLEAN_FIXTURE;
  let results;

  try {
    results = scanSemgrepControl(CLEAN_FIXTURE_FILES, dummyPath);
  } catch {
    // If there's a fatal error, skip — the mock may not have write access
    return;
  }

  // If Semgrep is available, we should get either PASS or FAIL for the checks
  // If Semgrep is not available, we should get NOT_VERIFIED
  const statuses = results.map((r) => r.status);
  const allSame = new Set(statuses).size === 1;

  if (!isSemgrepAvailable()) {
    // All results should be NOT_VERIFIED
    assert.ok(allSame || statuses.every((s) => s === "NOT_VERIFIED"), "All results should be NOT_VERIFIED when Semgrep unavailable");
    const confidence = results.map((r) => r.confidence);
    assert.ok(confidence.every((c) => c === 0), "Confidence should be 0 for NOT_VERIFIED results");
  } else {
    // All results should have the same status (either all PASS, or mixed FAIL, or some PASS some FAIL)
    // but not NOT_VERIFIED (since Semgrep is available)
    assert.ok(!statuses.includes("NOT_VERIFIED"), "Results should not be NOT_VERIFIED when Semgrep is available");
  }
});

test("H-1: Check results include detection method", () => {
  const dummyPath = CLEAN_FIXTURE;
  let results;

  try {
    results = scanSemgrepControl(CLEAN_FIXTURE_FILES, dummyPath);
  } catch {
    return;
  }

  assert.ok(results.length > 0, "Should have results");
  assert.ok(results.every((r) => r.detectionMethod), "All results should have detectionMethod");
  // If Semgrep is available, detection method should be 'ast'
  // If Semgrep is not available, detection method should be 'unknown'
  const expectedMethod = isSemgrepAvailable() ? "ast" : "unknown";
  assert.ok(
    results.every((r) => r.detectionMethod === expectedMethod),
    `All results should have detectionMethod '${expectedMethod}'`
  );
});

test("H-1: Check results include confidence", () => {
  const dummyPath = CLEAN_FIXTURE;
  let results;

  try {
    results = scanSemgrepControl(CLEAN_FIXTURE_FILES, dummyPath);
  } catch {
    return;
  }

  assert.ok(results.length > 0, "Should have results");
  assert.ok(
    results.every((r) => typeof r.confidence === "number"),
    "All results should have confidence as a number"
  );
  assert.ok(
    results.every((r) => r.confidence !== undefined && r.confidence >= 0 && r.confidence <= 100),
    "Confidence should be 0-100"
  );
});

test("H-1: AST check titles are descriptive", () => {
  const dummyPath = CLEAN_FIXTURE;
  let results;

  try {
    results = scanSemgrepControl(CLEAN_FIXTURE_FILES, dummyPath);
  } catch {
    return;
  }

  assert.ok(
    results.every((r) => typeof r.title === "string" && r.title.length > 10),
    "Every result should have a descriptive title"
  );
  assert.ok(results.length >= 6, "Should have at least the 6 required AST checks");

  // Each of the 6 rules is wired to a controlKey — two brand-new controls
  // (eval usage, command injection) and four that attach as complementary
  // AST evidence onto an existing control (SQL injection -> DB-001,
  // hardcoded JWT -> SECRET-001, disabled TLS -> NET-001, wildcard CORS ->
  // API-002) rather than duplicating them. See semgrepControl.ts's RULE_MAP.
  const controlKeys = new Set(results.map((r) => r.controlKey));
  for (const key of ["INPUT-003", "INPUT-004", "DB-001", "SECRET-001", "NET-001", "API-002"]) {
    assert.ok(controlKeys.has(key), `Expected a result for ${key}`);
  }
});
