import { test } from "node:test";
import assert from "node:assert/strict";
import { meetsThreshold } from "../src/format.js";

// meetsThreshold(summary, threshold) is the actual gate behind `nettle scan
// --fail-on <severity>` / `nettle scan-repo --fail-on <severity>` (see
// src/index.js) — it decides whether the CLI exits 1 and fails a CI build.
// Never had test coverage before this file existed, despite being the one
// function CI pipelines actually depend on.

const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 10 };

test("--fail-on critical: triggers only on critical findings", () => {
  assert.equal(meetsThreshold({ ...zero, critical: 1 }, "critical"), true);
  assert.equal(meetsThreshold({ ...zero, high: 1 }, "critical"), false);
  assert.equal(meetsThreshold({ ...zero, medium: 1 }, "critical"), false);
  assert.equal(meetsThreshold({ ...zero, low: 1 }, "critical"), false);
  assert.equal(meetsThreshold(zero, "critical"), false);
});

test("--fail-on high: triggers on high or critical, not medium/low", () => {
  assert.equal(meetsThreshold({ ...zero, critical: 1 }, "high"), true);
  assert.equal(meetsThreshold({ ...zero, high: 1 }, "high"), true);
  assert.equal(meetsThreshold({ ...zero, medium: 1 }, "high"), false);
  assert.equal(meetsThreshold({ ...zero, low: 1 }, "high"), false);
  assert.equal(meetsThreshold(zero, "high"), false);
});

test("--fail-on medium: triggers on medium, high or critical, not low", () => {
  assert.equal(meetsThreshold({ ...zero, critical: 1 }, "medium"), true);
  assert.equal(meetsThreshold({ ...zero, high: 1 }, "medium"), true);
  assert.equal(meetsThreshold({ ...zero, medium: 1 }, "medium"), true);
  assert.equal(meetsThreshold({ ...zero, low: 1 }, "medium"), false);
  assert.equal(meetsThreshold(zero, "medium"), false);
});

test("--fail-on low: triggers on any of critical/high/medium/low", () => {
  assert.equal(meetsThreshold({ ...zero, critical: 1 }, "low"), true);
  assert.equal(meetsThreshold({ ...zero, high: 1 }, "low"), true);
  assert.equal(meetsThreshold({ ...zero, medium: 1 }, "low"), true);
  assert.equal(meetsThreshold({ ...zero, low: 1 }, "low"), true);
  assert.equal(meetsThreshold(zero, "low"), false);
});

test("info-only findings never trigger any threshold — info is not a --fail-on level", () => {
  const infoOnly = { ...zero, info: 5 };
  assert.equal(meetsThreshold(infoOnly, "critical"), false);
  assert.equal(meetsThreshold(infoOnly, "low"), false);
});

test("an unrecognized threshold value never triggers a failure", () => {
  assert.equal(meetsThreshold({ ...zero, critical: 99 }, "nonsense"), false);
  assert.equal(meetsThreshold({ ...zero, critical: 99 }, ""), false);
  assert.equal(meetsThreshold({ ...zero, critical: 99 }, undefined), false);
});

test("a clean report (all zero counts) never triggers any threshold", () => {
  for (const threshold of ["critical", "high", "medium", "low"]) {
    assert.equal(meetsThreshold(zero, threshold), false);
  }
});
