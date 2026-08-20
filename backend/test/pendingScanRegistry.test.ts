import { test } from "node:test";
import assert from "node:assert/strict";
import {
  newCallbackToken,
  registerPendingScan,
  resolvePendingScan,
  rejectPendingScan,
  _resetPendingScansForTests,
} from "../src/jobs/pendingScanRegistry";
import type { ScanReport } from "../src/scanner/types";

const fakeReport = { findings: [], passed: [], summary: {} } as unknown as ScanReport;

test.beforeEach(() => {
  _resetPendingScansForTests();
});

test("registerPendingScan resolves its promise on a matching resolvePendingScan call", async () => {
  const token = newCallbackToken();
  const promise = registerPendingScan("job-1", token, 5000);

  const claimed = resolvePendingScan("job-1", token, fakeReport);
  assert.equal(claimed, true);

  const report = await promise;
  assert.equal(report, fakeReport);
});

test("registerPendingScan rejects its promise on a matching rejectPendingScan call", async () => {
  const token = newCallbackToken();
  const promise = registerPendingScan("job-2", token, 5000);

  const claimed = rejectPendingScan("job-2", token, "scanner crashed");
  assert.equal(claimed, true);

  await assert.rejects(promise, /scanner crashed/);
});

test("a wrong token does not resolve or consume the pending entry", async () => {
  const token = newCallbackToken();
  const promise = registerPendingScan("job-3", token, 5000);

  const claimedWrong = resolvePendingScan("job-3", "not-the-right-token", fakeReport);
  assert.equal(claimedWrong, false);

  // The entry is still there — a correct token presented afterward still works.
  const claimedRight = resolvePendingScan("job-3", token, fakeReport);
  assert.equal(claimedRight, true);
  assert.equal(await promise, fakeReport);
});

test("a token of the wrong length does not throw and does not resolve (timingSafeEqual length guard)", () => {
  const token = newCallbackToken();
  registerPendingScan("job-4", token, 5000);

  assert.doesNotThrow(() => {
    const claimed = resolvePendingScan("job-4", "short", fakeReport);
    assert.equal(claimed, false);
  });
});

test("resolving or rejecting an unknown jobId is a no-op, not a throw", () => {
  assert.equal(resolvePendingScan("no-such-job", "whatever", fakeReport), false);
  assert.equal(rejectPendingScan("no-such-job", "whatever", "nope"), false);
});

test("registering the same jobId twice while the first is still pending throws (duplicate scan request)", () => {
  const token = newCallbackToken();
  registerPendingScan("job-5", token, 5000);

  assert.throws(() => registerPendingScan("job-5", newCallbackToken(), 5000), /already pending/);
});

test("a claimed jobId can be re-registered — the slot is freed once resolved", async () => {
  const token1 = newCallbackToken();
  const promise1 = registerPendingScan("job-6", token1, 5000);
  resolvePendingScan("job-6", token1, fakeReport);
  await promise1;

  // No longer pending — registering the same id again should succeed.
  const token2 = newCallbackToken();
  const promise2 = registerPendingScan("job-6", token2, 5000);
  resolvePendingScan("job-6", token2, fakeReport);
  await assert.doesNotReject(promise2);
});

test("registerPendingScan rejects on its own timeout when nothing ever calls back", async () => {
  // registerPendingScan's own timeout is deliberately .unref()'d (correct
  // in production, where the HTTP server's listening handle already keeps
  // the event loop alive) — but in this standalone unit test nothing else
  // refs the loop, so without a keep-alive the process can decide it's
  // done and exit before the unref'd timer ever fires. A tiny refed
  // interval for the duration of this test only is the fix.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    const token = newCallbackToken();
    const promise = registerPendingScan("job-7", token, 20);

    await assert.rejects(promise, /did not report back within/);

    // Timed-out entries are cleaned up — a late callback after timeout is a no-op.
    assert.equal(resolvePendingScan("job-7", token, fakeReport), false);
  } finally {
    clearInterval(keepAlive);
  }
});

test("newCallbackToken produces distinct, sufficiently long random tokens", () => {
  const a = newCallbackToken();
  const b = newCallbackToken();
  assert.notEqual(a, b);
  assert.equal(a.length, 64); // 32 bytes, hex-encoded
});
