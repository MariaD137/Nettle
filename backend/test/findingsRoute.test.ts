import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";
import { hashFinding } from "../src/patrol/findingStatuses";
import { projectsRouter } from "../src/routes/projects.routes";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");

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
  app.use(projectsRouter);
  return app;
}

test("GET /api/projects/:id/findings returns findingHistory alongside findingStatuses", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("findings-route-history@example.com", "correct horse battery staple");
    await setSubscriptionStatus(user.id, "tier1", "active");
    const token = await createSession(user.id);
    const project = await createProject(user.id, "Findings Route Target");

    const report = runScan(FLAWED_APP);
    report.scannedAt = "2026-01-01T00:00:00.000Z";
    await recordScan(project.id, report);
    const hash = hashFinding(report.findings[0].category, report.findings[0].title, report.findings[0].file);

    const res = await fetch(`${base}/api/projects/${project.id}/findings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.ok(Array.isArray(body.findingStatuses));
    assert.ok(Array.isArray(body.findingHistory));
    const entry = body.findingHistory.find((e: any) => e.findingHash === hash);
    assert.ok(entry, "the scanned finding's hash should have a history entry");
    assert.equal(entry.firstSeenAt, "2026-01-01T00:00:00.000Z");
    assert.equal(entry.lastSeenAt, "2026-01-01T00:00:00.000Z");
  } finally {
    server.close();
  }
});
