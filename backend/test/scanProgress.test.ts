import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { runScan, sourceScanSteps, type ScanStepEvent } from "../src/scanner";

function tempProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scanprogress-"));
  fs.writeFileSync(path.join(dir, "index.js"), "console.log('hi');\n");
  return dir;
}

test("runScan with no onProgress behaves exactly as before (no callback, no crash)", () => {
  const dir = tempProject();
  try {
    const report = runScan(dir);
    assert.ok(typeof report.score === "number");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("onProgress fires a start and complete event for every step, in order, with a stable total", () => {
  const dir = tempProject();
  try {
    const events: ScanStepEvent[] = [];
    runScan(dir, undefined, (e) => events.push(e));

    const expectedSteps = sourceScanSteps([], dir).length;
    assert.equal(events.length, expectedSteps * 2, "expected a start and complete event per step");

    // Each step's start must come before its complete, and steps fire in
    // ascending index order with no gaps or repeats.
    for (let i = 0; i < expectedSteps; i++) {
      assert.equal(events[i * 2].type, "step-start");
      assert.equal(events[i * 2].index, i);
      assert.equal(events[i * 2 + 1].type, "step-complete");
      assert.equal(events[i * 2 + 1].index, i);
      assert.equal(events[i * 2].stepId, events[i * 2 + 1].stepId);
      assert.equal(events[i * 2].total, expectedSteps);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the report produced with onProgress is identical to the one produced without it", () => {
  const dir = tempProject();
  try {
    const withoutCallback = runScan(dir);
    const withCallback = runScan(dir, undefined, () => {});

    // scannedAt is a fresh timestamp each call, so compare everything else.
    const strip = (r: typeof withoutCallback) => ({ ...r, scannedAt: undefined });
    assert.deepEqual(strip(withCallback), strip(withoutCallback));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("sourceScanSteps returns a stable, non-empty, uniquely-identified step list", () => {
  const steps = sourceScanSteps([], "/tmp");
  assert.ok(steps.length > 15, `expected a substantial step list, got ${steps.length}`);
  const ids = steps.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "step ids must be unique");
  for (const s of steps) {
    assert.ok(s.label.length > 0);
  }
});
