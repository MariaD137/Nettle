import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { createAlert } from "../src/patrol/alerts";
import { projectsRouter } from "../src/routes/projects.routes";

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

let counter = 0;
async function subscriberWithProject(): Promise<{ token: string; projectId: string; base: string; server: Server }> {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`alert-analytics-route-${counter++}@example.com`, "correct horse battery staple");
  await setSubscriptionStatus(user.id, "tier1", "active");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Alert Analytics Route Target");
  return { token, projectId: project.id, base, server };
}

test("GET /api/projects/:id/alerts/analytics returns a timeline and rankings for the project's own alerts", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    await createAlert(projectId, "critical", "suspicious-path-8.8.8.8", 'Request to "/wp-admin" from 8.8.8.8 matches a common attack-probe pattern.');

    const res = await fetch(`${base}/api/projects/${projectId}/alerts/analytics`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.analytics.timeline));
    assert.equal(body.analytics.timeline.reduce((sum: number, b: any) => sum + b.count, 0), 1);
    assert.deepEqual(body.analytics.topAttackTypes[0], { label: "suspicious-path", count: 1 });
    assert.deepEqual(body.analytics.topEndpoints[0], { label: "/wp-admin", count: 1 });
    assert.deepEqual(body.analytics.topCountries[0], { label: "US", count: 1 });
  } finally {
    server.close();
  }
});

test("GET /api/projects/:id/alerts/analytics clamps an out-of-range hours query", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/alerts/analytics?hours=99999`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.analytics.timeline.length, 721); // clamped to 720 hours, inclusive of the current hour
  } finally {
    server.close();
  }
});

test("GET /api/projects/:id/alerts/analytics 404s for a project the caller doesn't own", async () => {
  const a = await subscriberWithProject();
  const b = await subscriberWithProject();
  try {
    const res = await fetch(`${a.base}/api/projects/${a.projectId}/alerts/analytics`, {
      headers: { Authorization: `Bearer ${b.token}` },
    });
    assert.equal(res.status, 404);
  } finally {
    a.server.close();
    b.server.close();
  }
});
