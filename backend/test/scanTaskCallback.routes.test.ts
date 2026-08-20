import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { scanTaskCallbackRouter } from "../src/routes/scanTaskCallback.routes";
import {
  newCallbackToken,
  registerPendingScan,
  _resetPendingScansForTests,
} from "../src/jobs/pendingScanRegistry";
import type { ScanReport } from "../src/scanner/types";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  // Deliberately no app-wide express.json() here — scanTaskCallbackRouter
  // brings its own parser, matching how it's actually mounted in index.ts
  // (before the app-wide one, for a bigger size limit).
  app.use(scanTaskCallbackRouter);
  return app;
}

const validReport = { findings: [], passed: [], summary: { total: 0 } } as unknown as ScanReport;

test.beforeEach(() => {
  _resetPendingScansForTests();
});

test("POST .../result with no callback token header is a 404, not a 401 (no info leak about job existence)", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/internal/scan-tasks/some-job/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(res.status, 404);
  } finally {
    server.close();
  }
});

test("POST .../result for a job that was never registered is a 404", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/internal/scan-tasks/never-registered/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": "anything" },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(res.status, 404);
  } finally {
    server.close();
  }
});

test("POST .../result with the wrong token for a real pending job is a 404, and the job is still pending afterward", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const token = newCallbackToken();
  const pending = registerPendingScan("job-wrong-token", token, 5000);
  // Prevent an unhandled-rejection warning if the timeout somehow fires
  // before this test's assertions run.
  pending.catch(() => {});
  try {
    const res = await fetch(`${base}/api/internal/scan-tasks/job-wrong-token/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": "wrong-token" },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(res.status, 404);

    // The correct token still works afterward — a wrong attempt didn't consume the entry.
    const correctRes = await fetch(`${base}/api/internal/scan-tasks/job-wrong-token/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": token },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(correctRes.status, 204);
    assert.deepEqual(await pending, validReport);
  } finally {
    server.close();
  }
});

test("POST .../result with a malformed report shape is a 400 and does not consume the pending entry", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const token = newCallbackToken();
  const pending = registerPendingScan("job-bad-shape", token, 5000);
  pending.catch(() => {});
  try {
    const badRes = await fetch(`${base}/api/internal/scan-tasks/job-bad-shape/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": token },
      body: JSON.stringify({ report: { not: "a real report" } }),
    });
    assert.equal(badRes.status, 400);

    // Still pending — a well-formed report with the same token now succeeds.
    const goodRes = await fetch(`${base}/api/internal/scan-tasks/job-bad-shape/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": token },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(goodRes.status, 204);
    assert.deepEqual(await pending, validReport);
  } finally {
    server.close();
  }
});

test("POST .../result with a valid token and report resolves the pending scan with 204", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const token = newCallbackToken();
  const pending = registerPendingScan("job-ok", token, 5000);
  try {
    const res = await fetch(`${base}/api/internal/scan-tasks/job-ok/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": token },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(res.status, 204);
    assert.deepEqual(await pending, validReport);
  } finally {
    server.close();
  }
});

test("POST .../error with a valid token rejects the pending scan with the reported message, 204", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const token = newCallbackToken();
  const pending = registerPendingScan("job-err", token, 5000);
  // Attach the rejection expectation before firing the request that
  // triggers it — the route handles rejectPendingScan synchronously within
  // the request/response cycle, so waiting until after `await fetch(...)`
  // to start listening would leave `pending` briefly unhandled and trip
  // Node's unhandledRejection detection.
  const expectRejection = assert.rejects(pending, /container crashed mid-scan/);
  try {
    const res = await fetch(`${base}/api/internal/scan-tasks/job-err/error`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": token },
      body: JSON.stringify({ message: "container crashed mid-scan" }),
    });
    assert.equal(res.status, 204);
    await expectRejection;
  } finally {
    server.close();
  }
});

test("POST .../error without a token is a 404 and does not touch the pending job", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const token = newCallbackToken();
  const pending = registerPendingScan("job-err-notoken", token, 5000);
  pending.catch(() => {});
  try {
    const res = await fetch(`${base}/api/internal/scan-tasks/job-err-notoken/error`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "should not apply" }),
    });
    assert.equal(res.status, 404);

    const okRes = await fetch(`${base}/api/internal/scan-tasks/job-err-notoken/result`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Nettle-Scan-Callback-Token": token },
      body: JSON.stringify({ report: validReport }),
    });
    assert.equal(okRes.status, 204);
    assert.deepEqual(await pending, validReport);
  } finally {
    server.close();
  }
});
