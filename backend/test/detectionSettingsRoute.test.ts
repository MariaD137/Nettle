import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
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
async function subscriberWithProject() {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`detection-settings-route-${counter++}@example.com`, "correct horse battery staple");
  setSubscriptionStatus(user.id, "tier1", "active");
  const token = createSession(user.id);
  const project = createProject(user.id, "Detection Settings Route Target");
  return { token, projectId: project.id, base, server };
}

test("GET /api/projects/:id/detection-settings returns the defaults for an unconfigured project", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/detection-settings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.settings.bruteForceThreshold, 5);
    assert.equal(body.settings.highRequestRateThreshold, 50);
    assert.equal(body.settings.credentialStuffingMinIps, 5);
  } finally {
    server.close();
  }
});

test("PATCH /api/projects/:id/detection-settings persists real changes", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/detection-settings`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ bruteForceThreshold: 3 }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.settings.bruteForceThreshold, 3);

    const reread = await (await fetch(`${base}/api/projects/${projectId}/detection-settings`, { headers: { Authorization: `Bearer ${token}` } })).json();
    assert.equal(reread.settings.bruteForceThreshold, 3);
  } finally {
    server.close();
  }
});

test("POST /api/projects/:id/detection-settings/reset restores defaults", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    await fetch(`${base}/api/projects/${projectId}/detection-settings`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ bruteForceThreshold: 1 }),
    });

    const res = await fetch(`${base}/api/projects/${projectId}/detection-settings/reset`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.settings.bruteForceThreshold, 5);
  } finally {
    server.close();
  }
});

test("detection-settings routes 404 for a project the caller doesn't own", async () => {
  const owner = await subscriberWithProject();
  const other = await subscriberWithProject();
  try {
    const res = await fetch(`${owner.base}/api/projects/${owner.projectId}/detection-settings`, {
      headers: { Authorization: `Bearer ${other.token}` },
    });
    assert.equal(res.status, 404);
  } finally {
    owner.server.close();
    other.server.close();
  }
});
