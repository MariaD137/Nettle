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

// Regression test for a real bug: GET /api/overview built its per-project
// summaries with `projects.map(async (p) => {...})` without awaiting the
// result. That returns an array of pending Promises, not resolved objects --
// JSON.stringify on a Promise produces "{}", so every project in the
// response serialized to an empty object (no badge, no score), and the
// aggregate totals (critical/high/alerts/latestScore) were read before any
// of the async work had run, so they were always stuck at their initial
// 0/null values regardless of what was actually in the database. Existing
// tests only asserted totalProjects (which comes from projects.length, not
// the broken map) against fresh accounts with no scans, where 0/null happen
// to be the correct answer anyway -- so this was invisible to the existing
// suite. Caught via an actual browser render crashing on `state.status` of
// an empty badge object.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

test("GET /api/overview returns real per-project badges and real aggregate totals, not empty stubs", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const user = await createUser("overview-agg@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Overview Aggregation Test");

  const report = runScan(path.join(__dirname, "fixtures", "sample-app"));
  await recordScan(project.id, report);

  const res = await fetch(`${base}/api/overview`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;

  // The bug's exact symptom: every project serialized as {}.
  assert.equal(body.projects.length, 1);
  const summary = body.projects[0];
  assert.equal(summary.id, project.id);
  assert.equal(summary.name, "Overview Aggregation Test");
  assert.ok(summary.badge, "project summary must include a real badge object, not an empty stub");
  assert.ok(typeof summary.badge.status === "string" && summary.badge.status.length > 0);
  assert.equal(typeof summary.latestScore, "number");

  // The bug's other exact symptom: these always read 0/null regardless of
  // real data, because they were read before Promise.all resolved anything.
  assert.ok(body.totalCriticalFindings > 0, "the flawed fixture has real critical findings the aggregate must count");
  assert.equal(body.latestScore, summary.latestScore);
  assert.ok(body.latestScanAt);
});
