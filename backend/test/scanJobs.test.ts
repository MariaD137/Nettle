import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execSync } from "child_process";
import { createScanJob, getScanJob, cancelScanJob, _resetScanJobsForTests } from "../src/jobs/scanJobs";

function makeZip(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jobtest-src-"));
  fs.writeFileSync(path.join(dir, "index.js"), "console.log('hello');\n");
  const zipPath = path.join(os.tmpdir(), `nettle-jobtest-${crypto.randomUUID()}.zip`);
  execSync(`cd ${dir} && zip -r -q ${zipPath} .`);
  fs.rmSync(dir, { recursive: true, force: true });
  return zipPath;
}

async function waitFor(check: () => boolean, timeoutMs = 20_000, intervalMs = 100): Promise<void> {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

test.beforeEach(() => {
  _resetScanJobsForTests();
  delete process.env.NETTLE_MAX_CONCURRENT_SCANS;
});

test("an upload job runs in the background and completes with a real report", async () => {
  const zipPath = makeZip();
  const job = createScanJob({ mode: "upload", zipPath }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });

  // With nothing else running, createScanJob's own synchronous dequeue can
  // already flip this to "running" by the time it returns — a job only
  // stays "queued" when a concurrency slot isn't free yet (covered below).
  assert.ok(["queued", "running"].includes(job.status));
  assert.ok(job.steps.length > 15, "expected the full source-scan step list to be pre-populated");
  assert.ok(job.steps.every((s) => s.status === "pending"), "the worker hasn't had a chance to report progress yet at this synchronous point");

  await waitFor(() => getScanJob(job.id)!.status === "completed");

  const finished = getScanJob(job.id)!;
  assert.equal(finished.error, null);
  assert.ok(finished.report, "expected a report on completion");
  assert.ok(typeof finished.report!.score === "number");
  assert.ok(finished.steps.every((s) => s.status === "done"), "every step should be marked done on completion");
  assert.ok(finished.startedAt);
  assert.ok(finished.finishedAt);
});

test("step statuses actually progress from pending -> running -> done while the job runs", async () => {
  const zipPath = makeZip();
  const job = createScanJob({ mode: "upload", zipPath }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });

  // Catch it mid-flight: at least one step should be running or done before
  // the whole job completes, proving progress is reported incrementally
  // and not just flipped to "done" all at once at the end.
  let sawIntermediateProgress = false;
  await waitFor(() => {
    const current = getScanJob(job.id)!;
    if (current.status === "completed") return true;
    if (current.steps.some((s) => s.status !== "pending")) sawIntermediateProgress = true;
    return false;
  });

  assert.ok(sawIntermediateProgress, "expected to observe at least one step leave the pending state before completion");
});

test("an unreachable-URL job fails with a real error and no report", async () => {
  const job = createScanJob({ mode: "url", targetUrl: "http://127.0.0.1:1/" }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });

  await waitFor(() => getScanJob(job.id)!.status === "failed");

  const finished = getScanJob(job.id)!;
  assert.equal(finished.report, null);
  assert.ok(finished.error && finished.error.length > 0);
});

test("a queued job waits behind a running one when concurrency is limited to 1", async () => {
  process.env.NETTLE_MAX_CONCURRENT_SCANS = "1";
  const zipA = makeZip();
  const zipB = makeZip();

  const jobA = createScanJob({ mode: "upload", zipPath: zipA }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });
  const jobB = createScanJob({ mode: "upload", zipPath: zipB }, { ownerUserId: "user-2", projectId: null, billedUserId: "user-2" });

  await waitFor(() => getScanJob(jobA.id)!.status === "running");
  // B must still be queued while A occupies the only concurrency slot.
  assert.equal(getScanJob(jobB.id)!.status, "queued");
  assert.equal(getScanJob(jobB.id)!.queuePosition, 0);

  await waitFor(() => getScanJob(jobA.id)!.status === "completed");
  await waitFor(() => getScanJob(jobB.id)!.status === "completed");
});

test("cancelling a queued job removes it from the queue without running it", async () => {
  process.env.NETTLE_MAX_CONCURRENT_SCANS = "1";
  const zipA = makeZip();
  const zipB = makeZip();

  const jobA = createScanJob({ mode: "upload", zipPath: zipA }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });
  const jobB = createScanJob({ mode: "upload", zipPath: zipB }, { ownerUserId: "user-2", projectId: null, billedUserId: "user-2" });

  await waitFor(() => getScanJob(jobA.id)!.status === "running");
  assert.equal(getScanJob(jobB.id)!.status, "queued");

  const cancelled = cancelScanJob(jobB.id);
  assert.equal(cancelled, true);
  assert.equal(getScanJob(jobB.id)!.status, "cancelled");
  assert.equal(getScanJob(jobB.id)!.report, null);

  await waitFor(() => getScanJob(jobA.id)!.status === "completed");
});

test("cancelling a running job actually terminates it", async () => {
  const zipPath = makeZip();
  const job = createScanJob({ mode: "upload", zipPath }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });

  await waitFor(() => getScanJob(job.id)!.status === "running");
  const cancelled = cancelScanJob(job.id);
  assert.equal(cancelled, true);
  assert.equal(getScanJob(job.id)!.status, "cancelled");

  // Give it a moment, then confirm it never quietly completes after being
  // cancelled — a genuinely terminated worker can't post a "done" message.
  await new Promise((r) => setTimeout(r, 1000));
  assert.equal(getScanJob(job.id)!.status, "cancelled");
  assert.equal(getScanJob(job.id)!.report, null);
});

test("cancelling an already-finished job is a no-op that returns false", async () => {
  const zipPath = makeZip();
  const job = createScanJob({ mode: "upload", zipPath }, { ownerUserId: "user-1", projectId: null, billedUserId: "user-1" });
  await waitFor(() => getScanJob(job.id)!.status === "completed");

  assert.equal(cancelScanJob(job.id), false);
  assert.equal(getScanJob(job.id)!.status, "completed");
});

test("onComplete fires exactly once with the finished report, for bookkeeping like recordScan", async () => {
  const zipPath = makeZip();
  let completeCallCount = 0;
  let receivedScore: number | null = null;
  const job = createScanJob(
    { mode: "upload", zipPath },
    {
      ownerUserId: "user-1",
      projectId: "proj-1",
      billedUserId: "user-1",
      onComplete: (report) => {
        completeCallCount++;
        receivedScore = report.score;
      },
    }
  );

  await waitFor(() => getScanJob(job.id)!.status === "completed");
  assert.equal(completeCallCount, 1);
  assert.equal(receivedScore, getScanJob(job.id)!.report!.score);
});

test("getScanJob returns null for an unknown id", () => {
  assert.equal(getScanJob("00000000-0000-0000-0000-000000000000"), null);
});
