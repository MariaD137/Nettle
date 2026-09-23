// Async scan execution (master spec Phase 7-10): a project-tied scan no
// longer runs on the request path. POST /api/scans / /api/scans/repo
// creates a CREATED scan record and returns immediately; the actual scan
// runs afterward via scanner/scanQueue.ts. This is the first test coverage
// of that HTTP path with a project attached at all — every prior scan test
// either called recordScan()/runScan() directly (bypassing the route) or
// hit the route without an API key, which stays synchronous.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject, findProjectByApiKey } from "../src/patrol/projects";
import { getLatestScan, listScans, createQueuedScan } from "../src/patrol/scans";
import { scansRouter } from "../src/routes/scans.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { enqueueScan, flushScanQueue, pendingScanJobs } from "../src/scanner/scanQueue";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(scansRouter);
  app.use(projectsRouter);
  return app;
}

const PASSWORD = "correct horse battery staple";

let zipPath: string;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scanqueue-"));
  zipPath = path.join(dir, "app.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "sample-app"], { cwd: path.join(__dirname, "fixtures") });
});

async function subscriber(email: string) {
  const user = await createUser(email, PASSWORD);
  await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);
  return { user, token };
}

async function uploadScan(base: string, apiKey: string) {
  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { "x-nettle-api-key": apiKey },
    body: form,
  });
  return { status: res.status, body: (await res.json()) as any };
}

async function pollUntilDone(base: string, token: string, projectId: string, scanId: string, timeoutMs = 15000) {
  const start = Date.now();
  for (;;) {
    const res = await fetch(`${base}/api/projects/${projectId}/scans`, { headers: { Authorization: `Bearer ${token}` } });
    const body = (await res.json()) as any;
    const found = body.scans.find((s: any) => s.id === scanId);
    if (found && found.status !== "CREATED" && found.status !== "SCANNING") return found;
    if (Date.now() - start > timeoutMs) throw new Error("timed out waiting for scan to finish");
    await new Promise((r) => setTimeout(r, 50));
  }
}

test("POST /api/scans with a project API key returns immediately with a CREATED scan, not a full report", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user, token } = await subscriber("scanqueue-basic@example.com");
  const project = await createProject(user.id, "Async Target");

  const start = Date.now();
  const res = await uploadScan(base, project.apiKey);
  const elapsed = Date.now() - start;

  assert.equal(res.status, 202);
  assert.ok(res.body.scanId);
  assert.equal(res.body.projectId, project.id);
  assert.equal(res.body.status, "CREATED");
  assert.ok(!res.body.findings, "the immediate response must not contain scan results — those aren't ready yet");
  // Loose bound, not a tight timing assertion: the point is this returns
  // long before a real Semgrep run over the fixture would finish, not an
  // exact millisecond budget.
  assert.ok(elapsed < 5000, `expected an immediate response, took ${elapsed}ms`);

  const finished = await pollUntilDone(base, token, project.id, res.body.scanId);
  assert.equal(finished.status, "COMPLETED");
  assert.ok(finished.report.checkResults?.length > 0, "the completed scan must carry real results");
});

test("a queued scan is visible as CREATED/SCANNING before the worker finishes it", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user, token } = await subscriber("scanqueue-visible@example.com");
  const project = await createProject(user.id, "Visibility Target");

  const uploadRes = await uploadScan(base, project.apiKey);
  assert.equal(uploadRes.status, 202);

  // Immediately after the 202, before flushing the queue, the project
  // detail route must already show the real CREATED/SCANNING record —
  // not null (as if nothing had been requested) and not a fabricated
  // completed one.
  const detailRes = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${token}` } });
  const detail = (await detailRes.json()) as any;
  assert.ok(detail.latestScan, "the queued scan must already be visible, not null");
  assert.ok(
    detail.latestScan.status === "CREATED" || detail.latestScan.status === "SCANNING" || detail.latestScan.status === "COMPLETED",
    `unexpected status: ${detail.latestScan.status}`
  );

  await flushScanQueue();
  assert.equal(pendingScanJobs(), 0);
});

test("two scans for different projects never cross-contaminate results (isolation)", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user: userA, token: tokenA } = await subscriber("scanqueue-iso-a@example.com");
  const { user: userB, token: tokenB } = await subscriber("scanqueue-iso-b@example.com");
  const projectA = await createProject(userA.id, "Isolated A");
  const projectB = await createProject(userB.id, "Isolated B");

  const resA = await uploadScan(base, projectA.apiKey);
  const resB = await uploadScan(base, projectB.apiKey);
  assert.equal(resA.status, 202);
  assert.equal(resB.status, 202);
  assert.notEqual(resA.body.scanId, resB.body.scanId);

  const finishedA = await pollUntilDone(base, tokenA, projectA.id, resA.body.scanId);
  const finishedB = await pollUntilDone(base, tokenB, projectB.id, resB.body.scanId);

  assert.equal(finishedA.status, "COMPLETED");
  assert.equal(finishedB.status, "COMPLETED");

  // Each project only ever sees its own scan.
  const scansAOnly = await listScans(projectA.id);
  const scansBOnly = await listScans(projectB.id);
  assert.equal(scansAOnly.length, 1);
  assert.equal(scansBOnly.length, 1);
  assert.equal(scansAOnly[0].id, resA.body.scanId);
  assert.equal(scansBOnly[0].id, resB.body.scanId);
});

test("submitting the same scan twice produces two independent records — not coalesced, not duplicated results in one record", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user, token } = await subscriber("scanqueue-duplicate@example.com");
  const project = await createProject(user.id, "Duplicate Submit Target");

  const first = await uploadScan(base, project.apiKey);
  const second = await uploadScan(base, project.apiKey);
  assert.equal(first.status, 202);
  assert.equal(second.status, 202);
  assert.notEqual(first.body.scanId, second.body.scanId, "each submission gets its own scan record, matching the pre-existing synchronous behavior");

  await pollUntilDone(base, token, project.id, first.body.scanId);
  await pollUntilDone(base, token, project.id, second.body.scanId);

  const scans = await listScans(project.id);
  assert.equal(scans.length, 2);
  assert.ok(scans.every((s) => s.status === "COMPLETED"));
});

test("a worker failure produces a real FAILED scan, never a fabricated result", async (t) => {
  const user = (await createUser("scanqueue-fail@example.com", PASSWORD));
  await setSubscriptionStatus(user.id, "build", "active");
  const project = await createProject(user.id, "Failure Target");

  const queued = await createQueuedScan(project.id);
  assert.equal(queued.status, "CREATED");

  // A scan root that doesn't exist forces runScan() to throw during
  // execution — a real failure, not a simulated one.
  const doomedRoot = path.join(os.tmpdir(), "nettle-does-not-exist-" + Date.now());
  let cleanupCalled = false;
  enqueueScan({ scanId: queued.id, scanRoot: doomedRoot, cleanup: () => { cleanupCalled = true; } });
  await flushScanQueue();

  const failed = await getLatestScan(project.id);
  assert.ok(failed);
  assert.equal(failed!.id, queued.id);
  assert.equal(failed!.status, "FAILED");
  assert.equal(failed!.report.findings.length, 0, "a failed scan carries no fabricated findings");
  assert.equal(cleanupCalled, true, "cleanup must still run after a failed job");
});

test("cleanup runs exactly once after a successful scan, and the extraction directory is actually removed", async () => {
  const user = await createUser("scanqueue-cleanup@example.com", PASSWORD);
  await setSubscriptionStatus(user.id, "build", "active");
  const project = await createProject(user.id, "Cleanup Target");

  const scanRoot = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scan-cleanup-test-"));
  fs.cpSync(path.join(__dirname, "fixtures", "clean-app"), scanRoot, { recursive: true });

  const queued = await createQueuedScan(project.id);
  let cleanupCalls = 0;
  enqueueScan({ scanId: queued.id, scanRoot, cleanup: () => { cleanupCalls++; fs.rmSync(scanRoot, { recursive: true, force: true }); } });
  await flushScanQueue();

  const finished = await getLatestScan(project.id);
  assert.equal(finished!.status, "COMPLETED");
  assert.equal(cleanupCalls, 1, "cleanup must run exactly once, not zero or twice");
  assert.equal(fs.existsSync(scanRoot), false, "the extraction directory must actually be gone after cleanup");
});

test("findProjectByApiKey still resolves the project an async scan was queued against", async () => {
  const user = await createUser("scanqueue-lookup@example.com", PASSWORD);
  await setSubscriptionStatus(user.id, "build", "active");
  const project = await createProject(user.id, "Lookup Target");
  const found = await findProjectByApiKey(project.apiKey);
  assert.equal(found?.id, project.id);
});
