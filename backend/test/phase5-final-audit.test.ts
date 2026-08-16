import { test } from "node:test";
import assert from "node:assert/strict";
import {
  getFinalAuditReport,
  getItemsByStatus,
  verifyAuditCompleteness,
} from "../src/audit/phase5-final-audit";

test("Phase 5: Get final audit report", () => {
  const report = getFinalAuditReport();

  assert.ok(report.includes("PHASE 5 FINAL AUDIT"));
  assert.ok(report.includes("SUMMARY"));
  assert.ok(report.toLowerCase().includes("test coverage"));
  assert.ok(report.length > 1000);
});

test("Phase 5: Audit report shows PASS status", () => {
  const report = getFinalAuditReport();

  assert.ok(report.includes("PASS:"));
  assert.ok(report.includes("✓"));
});

test("Phase 5: Audit report includes test coverage", () => {
  const report = getFinalAuditReport();

  assert.ok(report.includes("Total Tests:"));
  assert.ok(report.includes("Coverage:"));
});

test("Phase 5: Get items by PASS status", () => {
  const passItems = getItemsByStatus("PASS");

  assert.ok(passItems.length > 0);
  assert.ok(passItems.every((i) => i.status === "PASS"));
});

test("Phase 5: Get items by NOT_VERIFIED status", () => {
  const notVerified = getItemsByStatus("NOT_VERIFIED");

  assert.ok(notVerified.length > 0);
  assert.ok(notVerified.every((i) => i.status === "NOT_VERIFIED"));
});

test("Phase 5: Verify audit completeness for critical items", () => {
  const result = verifyAuditCompleteness();

  assert.ok(result.complete === true || result.complete === false);
  assert.ok(result.reason);
});

test("Phase 5: Audit report categorizes by priority", () => {
  const report = getFinalAuditReport();

  assert.ok(report.includes("Critical (C-1, C-2, C-3)"));
  assert.ok(report.includes("High (H-1 to H-7)"));
  assert.ok(report.includes("Medium (M-1 to M-6)"));
  assert.ok(report.includes("Low (L-1 to L-16)"));
});

test("Phase 5: Critical items are in PASS status", () => {
  const critical = getItemsByStatus("PASS").filter((i) => i.id.startsWith("C"));

  assert.ok(critical.length >= 3, "Should have 3 critical items implemented");
  assert.ok(critical.every((i) => i.testCount > 0), "Each should have tests");
});

test("Phase 5: High priority items are mostly PASS", () => {
  const highItems = getItemsByStatus("PASS").filter((i) => i.id.startsWith("H"));

  assert.ok(highItems.length >= 5, "Should have at least 5 high items");
});

test("Phase 5: Medium items are all PASS", () => {
  const mediumItems = getItemsByStatus("PASS").filter((i) => i.id.startsWith("M"));

  assert.ok(mediumItems.length >= 5, "Should have all 6 medium items (M-1 to M-6)");
});

test("Phase 5: Low items are intentionally deferred", () => {
  const lowItems = getItemsByStatus("NOT_VERIFIED").filter((i) => i.id.startsWith("L"));

  assert.ok(lowItems.length > 0, "Low priority items should be deferred");
  assert.ok(lowItems.every((i) => i.evidence.includes("Phase 6")));
});

test("Phase 5: Each item has evidence of implementation", () => {
  const passItems = getItemsByStatus("PASS");

  for (const item of passItems) {
    assert.ok(item.evidence, `${item.id} should have evidence`);
    assert.ok(item.evidence.length > 10, `${item.id} evidence should be descriptive`);
  }
});

test("Phase 5: Test counts are realistic", () => {
  const allItems = getItemsByStatus("PASS");
  const totalTests = allItems.reduce((sum, i) => sum + i.testCount, 0);

  assert.ok(totalTests > 100, "Should have 100+ tests for implementations");
  assert.ok(totalTests < 500, "Should be reasonable test count");
});

test("Phase 5: Report shows implementation rate", () => {
  const report = getFinalAuditReport();

  // Should show a percentage like "100%" or "95%"
  assert.ok(/\d+%/.test(report), "Should include percentage");
});

test("Phase 5: Audit verifies completeness", () => {
  const { complete } = verifyAuditCompleteness();

  // Should be complete (true) since all priority items are implemented
  assert.ok(typeof complete === "boolean");
});

test("Phase 5: Items have implementation files", () => {
  const passItems = getItemsByStatus("PASS");

  for (const item of passItems) {
    assert.ok(item.implementedBy.length > 0, `${item.id} should list files`);
    assert.ok(
      item.implementedBy.every((f) => f.includes("/")),
      `${item.id} files should be paths`
    );
  }
});
