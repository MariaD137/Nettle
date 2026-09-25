// Regression coverage for a real bug introduced by API-key masking
// (patrol/projects.ts's maskApiKey / routes/projects.routes.ts's
// withMaskedKey): the dashboard's Scan tab used to send the project's own
// apiKey (read back from a fetched Project) to identify which project a
// scan belongs to. Once GET routes started masking that field, the
// dashboard was sending a masked, non-functional value — findProjectByApiKey
// never matches it, so the scan silently stopped being tied to any project
// at all. Fixed by having authenticated dashboard requests identify the
// project by id instead (resolveScanProject in scans.routes.ts); the
// external/API-key path is unchanged for CI-style callers with no session.
import { test } from "node:test";
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
import { createProject, maskApiKey, findProjectByApiKey } from "../src/patrol/projects";
import { listScans } from "../src/patrol/scans";
import { scansRouter } from "../src/routes/scans.routes";
import { flushScanQueue } from "../src/scanner/scanQueue";

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
  return app;
}

const PASSWORD = "correct horse battery staple";

let zipPath: string;
test.before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scanidentity-"));
  zipPath = path.join(dir, "app.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "sample-app"], { cwd: path.join(__dirname, "fixtures") });
});

async function subscriber(email: string) {
  const user = await createUser(email, PASSWORD);
  await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);
  return { user, token };
}

async function uploadScan(base: string, token: string, projectId?: string) {
  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  if (projectId) form.append("projectId", projectId);
  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  return { status: res.status, body: (await res.json()) as any };
}

test("an authenticated dashboard scan with projectId (no apiKey at all) is tied to that project", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user, token } = await subscriber("scanidentity-basic@example.com");
  const project = await createProject(user.id, "Dashboard Target");

  const res = await uploadScan(base, token, project.id);
  assert.equal(res.status, 202);
  assert.equal(res.body.projectId, project.id, "the scan must be tied to the project by id, exactly as the dashboard intends");

  await flushScanQueue();
  const scans = await listScans(project.id);
  assert.equal(scans.length, 1, "the scan must actually land on the project's own history");
});

test("a non-owner cannot tie a scan to someone else's project via projectId", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user: owner } = await subscriber("scanidentity-owner@example.com");
  const { token: strangerToken } = await subscriber("scanidentity-stranger@example.com");
  const project = await createProject(owner.id, "Not Yours");

  const res = await uploadScan(base, strangerToken, project.id);
  // Not the owner's project, so projectId is rejected — falls back to the
  // apiKey path, which found nothing (no apiKey sent either) — so this
  // subscribed stranger's request has no project to queue against and runs
  // the pre-existing synchronous, unassociated path (a full report, no
  // scanId/projectId), never silently attached to the stranger's target.
  assert.equal(res.status, 200);
  assert.ok(!res.body.scanId, "no queued scan should have been created for someone else's project");

  await flushScanQueue();
  const scans = await listScans(project.id);
  assert.equal(scans.length, 0, "the real owner's project must not gain a scan it never requested");
});

test("the masked key form of a real API key never resolves back to its project — the exact pre-fix regression", async () => {
  // Exercised at the function level, not over HTTP: the "•" characters
  // maskApiKey produces aren't valid Latin1/ByteString content, so a raw
  // fetch() Headers object can't even carry one as an X-Nettle-Api-Key
  // value (undici throws before the request is sent) — which on its own
  // proves the old dashboard code (sending project.apiKey as that header)
  // could never have silently "worked" with a masked value; it would have
  // hard-failed client-side. The actual bug this guards was in the JSON-body
  // apiKey path (scanRepo), where no such encoding restriction protects you
  // — a masked key there fails silently (no match) rather than throwing,
  // exactly what findProjectByApiKey must never do.
  const user = await createUser("scanidentity-maskedkey@example.com", PASSWORD);
  const project = await createProject(user.id, "Masked Key Target");

  const resolved = await findProjectByApiKey(maskApiKey(project.apiKey));
  assert.equal(resolved, null, "a masked key must never resolve to the real project — that was the bug");
});
