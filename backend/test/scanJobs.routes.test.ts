import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { authRouter } from "../src/routes/auth.routes";
import { scansRouter } from "../src/routes/scans.routes";
import { scanJobsRouter } from "../src/routes/scanJobs.routes";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { _resetScanJobsForTests } from "../src/jobs/scanJobs";
import { recordScanUsage, SCAN_QUOTAS } from "../src/billing/scanQuota";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, base: `http://localhost:${port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  app.use(scansRouter);
  app.use(scanJobsRouter);
  return app;
}

function makeZip(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jobroutes-src-"));
  fs.writeFileSync(path.join(dir, "index.js"), "console.log('hello');\n");
  const zipPath = path.join(os.tmpdir(), `nettle-jobroutes-${Math.random().toString(36).slice(2)}.zip`);
  execSync(`cd ${dir} && zip -r -q ${zipPath} .`);
  fs.rmSync(dir, { recursive: true, force: true });
  return zipPath;
}

async function waitFor(check: () => Promise<boolean>, timeoutMs = 20_000, intervalMs = 150): Promise<void> {
  const start = Date.now();
  while (!(await check())) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

const PASSWORD = "correct horse battery staple";
let counter = 0;
async function subscriber(): Promise<{ token: string; userId: string }> {
  const user = await createUser(`scanjobroutes-${counter++}@example.com`, PASSWORD);
  setSubscriptionStatus(user.id, "tier1", "active");
  const token = createSession(user.id);
  return { token, userId: user.id };
}

test.beforeEach(() => {
  _resetScanJobsForTests();
});

test("upload job route: create, poll to completion, get a real report shaped by applyScanAccess", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const { token } = await subscriber();
  const zipPath = makeZip();

  try {
    const zipBuffer = fs.readFileSync(zipPath);
    const form = new FormData();
    form.append("codebase", new Blob([zipBuffer]), "codebase.zip");

    const createRes = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    assert.equal(createRes.status, 202);
    const { jobId } = await createRes.json();
    assert.ok(jobId);

    let finalBody: any;
    await waitFor(async () => {
      const pollRes = await fetch(`${base}/api/scans/jobs/${jobId}`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(pollRes.status, 200);
      const body = await pollRes.json();
      if (body.status === "completed" || body.status === "failed") {
        finalBody = body;
        return true;
      }
      // While in flight, steps should already be a populated list.
      assert.ok(Array.isArray(body.steps) && body.steps.length > 15);
      return false;
    });

    assert.equal(finalBody.status, "completed");
    assert.ok(finalBody.report);
    assert.ok(typeof finalBody.report.score === "number");
    assert.ok(finalBody.report.access, "expected applyScanAccess to have attached an access block");
    assert.equal(finalBody.report.access.tier, "full"); // tier1 subscriber
  } finally {
    server.close();
  }
});

// Regression coverage for the entitlement-drift bug: this route previously
// gated only on the raw `plan` column, so a canceled tier1 subscriber (plan
// still "tier1", subscriptionStatus "canceled") kept getting full,
// non-preview reports here indefinitely. It must now fall back to preview
// access exactly like a free account, via the same entitlement mechanism
// used everywhere else.
test("a canceled subscriber gets a preview report on the job route, not full access", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`scanjobroutes-canceled-${counter++}@example.com`, PASSWORD);
  setSubscriptionStatus(user.id, "tier1", "active");
  setSubscriptionStatus(user.id, "tier1", "canceled");
  const token = createSession(user.id);
  const zipPath = makeZip();

  try {
    const zipBuffer = fs.readFileSync(zipPath);
    const form = new FormData();
    form.append("codebase", new Blob([zipBuffer]), "codebase.zip");

    const createRes = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    assert.equal(createRes.status, 202, "a canceled account is not blocked from scanning at all — only full access is withheld");
    const { jobId } = await createRes.json();

    let finalBody: any;
    await waitFor(async () => {
      const pollRes = await fetch(`${base}/api/scans/jobs/${jobId}`, { headers: { Authorization: `Bearer ${token}` } });
      const body = await pollRes.json();
      if (body.status === "completed" || body.status === "failed") {
        finalBody = body;
        return true;
      }
      return false;
    });

    assert.equal(finalBody.status, "completed");
    assert.equal(finalBody.report.access.tier, "preview");
    assert.equal(finalBody.report.access.fullReport, false);
  } finally {
    server.close();
  }
});

// Regression coverage for M-3: quota used to be recorded only inside
// onComplete, which fires asynchronously once the worker_thread finishes —
// well after the job-creation request has already returned. A second
// job-creation request submitted in that gap saw the exact same
// not-yet-exhausted count and was let through too, together exceeding the
// account's allowance. Usage is now reserved synchronously inside the
// request handler itself, before the response is even sent, so a second
// request submitted immediately after — regardless of whether the first
// job's actual scan has finished — must see the reservation already made.
test("submitting a second job the instant after the account's last quota slot was just used is blocked, not let through", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`scanjobroutes-quotarace-${counter++}@example.com`, PASSWORD);
  setSubscriptionStatus(user.id, "tier1", "active");
  const token = createSession(user.id);

  // Use up all but one slot ahead of time so the very next submission is
  // the one that matters.
  for (let i = 0; i < SCAN_QUOTAS.tier1 - 1; i++) {
    recordScanUsage(user.id, null, "upload");
  }

  const zipPath = makeZip();
  try {
    const zipBuffer = fs.readFileSync(zipPath);

    const form1 = new FormData();
    form1.append("codebase", new Blob([zipBuffer]), "codebase.zip");
    const first = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form1,
    });
    assert.equal(first.status, 202, "the last available slot should be accepted");

    // Submitted immediately after — the first job's worker_thread has
    // almost certainly not finished yet, but the quota check must not
    // care: the slot was already reserved synchronously above.
    const form2 = new FormData();
    form2.append("codebase", new Blob([zipBuffer]), "codebase.zip");
    const second = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form2,
    });
    assert.equal(second.status, 402, "the account has no slots left — this must be blocked, not accepted");
    assert.equal((await second.json()).quotaExceeded, true);
  } finally {
    server.close();
  }
});

// If the first (accepted) job then fails, its reserved slot must be
// refunded — otherwise a failed scan would permanently cost real quota,
// which is not how the pre-existing (successful-scans-only) behavior
// worked before this fix, and is not something this fix should change.
test("a failed job releases its reserved quota slot back to the account", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`scanjobroutes-quotarelease-${counter++}@example.com`, PASSWORD);
  setSubscriptionStatus(user.id, "tier1", "active");
  const token = createSession(user.id);

  for (let i = 0; i < SCAN_QUOTAS.tier1 - 1; i++) {
    recordScanUsage(user.id, null, "upload");
  }

  try {
    // A deliberately corrupt "zip" — no real network dependency, and fails
    // deterministically inside the worker (safeExtractZip's own integrity
    // check) rather than depending on an external host being unreachable.
    // The job is still accepted (a slot was available) but its worker will
    // report "failed", which must trigger the release via onFailure.
    const corruptZipPath = path.join(os.tmpdir(), `nettle-corrupt-${Math.random().toString(36).slice(2)}.zip`);
    fs.writeFileSync(corruptZipPath, "this is not a real zip file");
    const form = new FormData();
    form.append("codebase", new Blob([fs.readFileSync(corruptZipPath)]), "codebase.zip");
    fs.unlinkSync(corruptZipPath);

    const createRes = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    assert.equal(createRes.status, 202);
    const { jobId } = await createRes.json();

    let finalBody: any;
    await waitFor(async () => {
      const pollRes = await fetch(`${base}/api/scans/jobs/${jobId}`, { headers: { Authorization: `Bearer ${token}` } });
      const body = await pollRes.json();
      if (body.status === "completed" || body.status === "failed") {
        finalBody = body;
        return true;
      }
      return false;
    }, 30_000);

    assert.equal(finalBody.status, "failed");

    // The slot should be back — a fresh submission must be accepted again.
    const retryZipPath = makeZip();
    const retryZipBuffer = fs.readFileSync(retryZipPath);
    const retryForm = new FormData();
    retryForm.append("codebase", new Blob([retryZipBuffer]), "codebase.zip");
    const retryRes = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: retryForm,
    });
    assert.equal(retryRes.status, 202, "the failed job's slot should have been released back to the account");
  } finally {
    server.close();
  }
});

test("job routes require authentication", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/scans/jobs/repo`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: "https://github.com/owner/repo" }),
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("a job belonging to a different user is not visible (404, not leaked)", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const { token: tokenA } = await subscriber();
  const { token: tokenB } = await subscriber();
  const zipPath = makeZip();

  try {
    const zipBuffer = fs.readFileSync(zipPath);
    const form = new FormData();
    form.append("codebase", new Blob([zipBuffer]), "codebase.zip");
    const createRes = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenA}` },
      body: form,
    });
    const { jobId } = await createRes.json();

    const pollAsB = await fetch(`${base}/api/scans/jobs/${jobId}`, { headers: { Authorization: `Bearer ${tokenB}` } });
    assert.equal(pollAsB.status, 404);

    const cancelAsB = await fetch(`${base}/api/scans/jobs/${jobId}/cancel`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(cancelAsB.status, 404);
  } finally {
    server.close();
  }
});

test("cancel route actually stops a running job", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const { token } = await subscriber();
  const zipPath = makeZip();

  try {
    const zipBuffer = fs.readFileSync(zipPath);
    const form = new FormData();
    form.append("codebase", new Blob([zipBuffer]), "codebase.zip");
    const createRes = await fetch(`${base}/api/scans/jobs/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    const { jobId } = await createRes.json();

    const cancelRes = await fetch(`${base}/api/scans/jobs/${jobId}/cancel`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(cancelRes.status, 204);

    const pollRes = await fetch(`${base}/api/scans/jobs/${jobId}`, { headers: { Authorization: `Bearer ${token}` } });
    const body = await pollRes.json();
    assert.equal(body.status, "cancelled");

    // Cancelling again should fail — it's already resolved.
    const secondCancel = await fetch(`${base}/api/scans/jobs/${jobId}/cancel`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(secondCancel.status, 409);
  } finally {
    server.close();
  }
});

test("a bad repo URL is rejected before a job is ever created", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const { token } = await subscriber();
  try {
    const res = await fetch(`${base}/api/scans/jobs/repo`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ repoUrl: "not-a-url" }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("polling an unknown job id returns 404", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const { token } = await subscriber();
  try {
    const res = await fetch(`${base}/api/scans/jobs/00000000-0000-0000-0000-000000000000`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 404);
  } finally {
    server.close();
  }
});
