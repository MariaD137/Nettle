import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import path from "path";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";
import { projectsRouter } from "../src/routes/projects.routes";

// Proves the gap this round's work closed: a scan recorded via recordScan()
// (what POST /api/scans does internally) stores raw, unhydrated
// checkResults -- hydration only ever happened at the scans.routes.ts
// response boundary, never for a scan fetched back out through the project
// detail or scan history routes. The Fix Center reads a project's stored
// scans through exactly those routes, so without this they'd show
// recommendation: null for every finding, control-migrated or not.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

test("GET /api/projects/:id returns a hydrated latestScan", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const user = await createUser("fixcenter-detail@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "tier1", "active");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Fix Center Test");

  const report = runScan(path.join(__dirname, "fixtures", "sample-app"));
  await recordScan(project.id, report);

  const res = await fetch(`${base}/api/projects/${project.id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;

  assert.ok(body.latestScan);
  const authFail = body.latestScan.report.checkResults.find(
    (r: any) => r.controlKey === "AUTH-001" && r.status === "FAIL"
  );
  assert.ok(authFail, "the recorded scan should still have its AUTH-001 FAIL");
  assert.ok(authFail.recommendation, "GET /api/projects/:id must hydrate stored checkResults, not just fresh scans");
  assert.equal(authFail.recommendation.technologyMatched, "express");
});

test("GET /api/projects/:id/scans returns hydrated history entries", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const user = await createUser("fixcenter-history@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "tier1", "active");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Fix Center History Test");

  const report = runScan(path.join(__dirname, "fixtures", "sample-app"));
  await recordScan(project.id, report);

  const res = await fetch(`${base}/api/projects/${project.id}/scans`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;

  assert.equal(body.scans.length, 1);
  const secretFail = body.scans[0].report.checkResults.find(
    (r: any) => r.controlKey === "SECRET-001" && r.status === "FAIL"
  );
  assert.ok(secretFail);
  assert.ok(secretFail.recommendation);
});
