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
