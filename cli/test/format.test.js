import { test } from "node:test";
import assert from "node:assert/strict";
import {
  colorSeverity,
  formatScore,
  formatSummary,
  formatFindings,
  formatAccessNotice,
  formatProjectsTable,
  formatScanHistory,
  meetsThreshold,
} from "../src/format.js";

test("colorSeverity uppercases the severity", () => {
  assert.match(colorSeverity("critical"), /CRITICAL/);
  assert.match(colorSeverity("low"), /LOW/);
});

test("formatScore includes the numeric score out of 100", () => {
  assert.match(formatScore(87), /87 \/ 100/);
  assert.match(formatScore(12), /12 \/ 100/);
});

test("formatSummary includes every severity count and the passed-checks count", () => {
  const out = formatSummary({ critical: 2, high: 1, medium: 3, low: 4, info: 0, clear: 10 });
  assert.match(out, /Critical/);
  assert.match(out, /\b2\b/);
  assert.match(out, /\b10\b/);
  assert.match(out, /Passed checks/);
});

test("formatFindings reports no findings cleanly", () => {
  const out = formatFindings([]);
  assert.match(out, /No security findings detected/);
});

test("formatFindings sorts by severity, most severe first", () => {
  const findings = [
    { severity: "low", category: "Security", title: "Low issue", file: null, detail: null },
    { severity: "critical", category: "Security", title: "Critical issue", file: null, detail: null },
    { severity: "medium", category: "Security", title: "Medium issue", file: null, detail: null },
  ];
  const out = formatFindings(findings);
  const criticalIdx = out.indexOf("Critical issue");
  const mediumIdx = out.indexOf("Medium issue");
  const lowIdx = out.indexOf("Low issue");
  assert.ok(criticalIdx < mediumIdx);
  assert.ok(mediumIdx < lowIdx);
});

test("formatFindings truncates beyond the limit and says how many more", () => {
  const findings = Array.from({ length: 25 }, (_, i) => ({
    severity: "low",
    category: "Security",
    title: `Issue ${i}`,
    file: null,
    detail: null,
  }));
  const out = formatFindings(findings, 20);
  assert.match(out, /and 5 more findings/);
  assert.ok(!out.includes("Issue 24"));
  assert.ok(out.includes("Issue 0"));
});

test("formatFindings includes file and detail lines when present", () => {
  const out = formatFindings([
    { severity: "high", category: "Security", title: "Hardcoded key", file: "src/config.js:12", detail: "Found a key" },
  ]);
  assert.match(out, /src\/config\.js:12/);
  assert.match(out, /Found a key/);
});

test("formatAccessNotice is empty for a full report", () => {
  assert.equal(formatAccessNotice({ fullReport: true }), "");
  assert.equal(formatAccessNotice(undefined), "");
});

test("formatAccessNotice explains a preview-only report", () => {
  const out = formatAccessNotice({ fullReport: false, message: "Upgrade for more." });
  assert.match(out, /Preview report/);
  assert.match(out, /Upgrade for more\./);
});

test("formatProjectsTable handles an empty project list", () => {
  const out = formatProjectsTable([]);
  assert.match(out, /No projects found/);
});

test("formatProjectsTable lists project id, name, and a truncated api key", () => {
  const out = formatProjectsTable([{ id: "proj-123", name: "My App", apiKey: "nettle_abcdefghijklmnopqrstuvwxyz" }]);
  assert.match(out, /proj-123/);
  assert.match(out, /My App/);
  assert.match(out, /nettle_abcdefghi/);
});

test("formatScanHistory handles no scans", () => {
  assert.match(formatScanHistory([], "My App"), /No scan history/);
});

test("formatScanHistory includes the project name and each scan's score", () => {
  const out = formatScanHistory(
    [{ scannedAt: "2026-01-01T00:00:00.000Z", score: 78, criticalCount: 1, cautionCount: 2, summary: { medium: 3 } }],
    "My App"
  );
  assert.match(out, /My App/);
  assert.match(out, /78/);
});

test("meetsThreshold: a critical finding meets every threshold", () => {
  const summary = { critical: 1, high: 0, medium: 0, low: 0 };
  assert.equal(meetsThreshold(summary, "critical"), true);
  assert.equal(meetsThreshold(summary, "high"), true);
  assert.equal(meetsThreshold(summary, "low"), true);
});

test("meetsThreshold: a low-only finding does not meet a stricter threshold", () => {
  const summary = { critical: 0, high: 0, medium: 0, low: 3 };
  assert.equal(meetsThreshold(summary, "critical"), false);
  assert.equal(meetsThreshold(summary, "high"), false);
  assert.equal(meetsThreshold(summary, "low"), true);
});

test("meetsThreshold: a clean summary meets nothing", () => {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  assert.equal(meetsThreshold(summary, "low"), false);
});

test("meetsThreshold: an unrecognized threshold is treated as not met", () => {
  assert.equal(meetsThreshold({ critical: 5 }, "not-a-real-severity"), false);
});
