import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { createApiKey } from "../src/patrol/apiKeys";
import { listScans } from "../src/patrol/scans";
import { eventsRouter } from "../src/routes/events.routes";
import { scansRouter } from "../src/routes/scans.routes";

// Real HTTP-level proof that key scoping is actually enforced at the two
// places that consume it — not just recorded in the database and never
// checked.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function makeZip(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scope-src-"));
  fs.writeFileSync(path.join(dir, "index.js"), "console.log('hello');\n");
  const zipPath = path.join(os.tmpdir(), `nettle-scope-${Math.random().toString(36).slice(2)}.zip`);
  execSync(`cd ${dir} && zip -r -q ${zipPath} .`);
  fs.rmSync(dir, { recursive: true, force: true });
  return zipPath;
}

let counter = 0;
async function testProject() {
  const user = await createUser(`api-key-scope-${counter++}@example.com`, "correct horse battery staple");
  return createProject(user.id, "Scope Test Project");
}

test("POST /api/events accepts a key scoped to events, and rejects one scoped only to scan", async () => {
  const app = express();
  app.use(express.json());
  app.use(eventsRouter);
  const { server, base } = await listen(app);
  try {
    const project = await testProject();
    const eventsKey = createApiKey(project.id, "Events key", ["events"]);
    const scanOnlyKey = createApiKey(project.id, "Scan-only key", ["scan"]);

    const body = { ip: "1.2.3.4", method: "GET", path: "/", statusCode: 200 };

    const okRes = await fetch(`${base}/api/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-nettle-api-key": eventsKey.key },
      body: JSON.stringify(body),
    });
    assert.equal(okRes.status, 202);

    const rejectedRes = await fetch(`${base}/api/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-nettle-api-key": scanOnlyKey.key },
      body: JSON.stringify(body),
    });
    assert.equal(rejectedRes.status, 401);
  } finally {
    server.close();
  }
});

test("POST /api/scans with a scan-scoped key attributes the scan to the project; an events-only key does not (falls back to anonymous, doesn't 401)", async () => {
  const app = express();
  app.use(express.json());
  app.use(scansRouter);
  const { server, base } = await listen(app);
  const zipPath = makeZip();
  try {
    const project = await testProject();
    const scanKey = createApiKey(project.id, "Scan key", ["scan"]);
    const eventsOnlyKey = createApiKey(project.id, "Events-only key", ["events"]);

    const withScanScope = await fetch(`${base}/api/scans`, {
      method: "POST",
      headers: { "x-nettle-api-key": scanKey.key },
      body: (() => {
        const fd = new FormData();
        fd.append("codebase", new Blob([fs.readFileSync(zipPath)]), "codebase.zip");
        return fd;
      })(),
    });
    assert.equal(withScanScope.status, 200);
    assert.equal(listScans(project.id).length, 1, "a scan-scoped key should attribute the scan to the project");

    const withEventsScope = await fetch(`${base}/api/scans`, {
      method: "POST",
      headers: { "x-nettle-api-key": eventsOnlyKey.key },
      body: (() => {
        const fd = new FormData();
        fd.append("codebase", new Blob([fs.readFileSync(zipPath)]), "codebase.zip");
        return fd;
      })(),
    });
    // The request itself still succeeds (a key without "scan" scope is
    // treated like no key at all, not a hard failure) — it just isn't
    // attributed to the project, so the project's scan count must not
    // have grown even though a real scan just ran.
    assert.equal(withEventsScope.status, 200);
    const report = await withEventsScope.json();
    assert.ok(typeof report.score === "number");
    assert.equal(listScans(project.id).length, 1, "an events-only key must not attribute the scan to the project");
  } finally {
    server.close();
    fs.rmSync(zipPath, { force: true });
  }
});
