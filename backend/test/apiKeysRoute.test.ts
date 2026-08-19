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
async function subscriberWithProject(): Promise<{ token: string; projectId: string; base: string; server: Server }> {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`api-keys-route-${counter++}@example.com`, "correct horse battery staple");
  await setSubscriptionStatus(user.id, "tier1", "active");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Route Test Project");
  return { token, projectId: project.id, base, server };
}

test("POST /api/projects/:id/api-keys creates a key and returns the full value once", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "CI key", scopes: ["scan"] }),
    });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.match(body.apiKey.key, /^nettle_[0-9a-f]{48}$/);
    assert.equal(body.apiKey.name, "CI key");
    assert.deepEqual(body.apiKey.scopes, ["scan"]);
  } finally {
    server.close();
  }
});

test("POST /api/projects/:id/api-keys requires a name", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ scopes: ["scan"] }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("GET /api/projects/:id/api-keys lists keys with masked values, including the seeded default", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    await fetch(`${base}/api/projects/${projectId}/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Second key", scopes: ["events"] }),
    });

    const res = await fetch(`${base}/api/projects/${projectId}/api-keys`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.apiKeys.length, 2);
    assert.ok(body.apiKeys.some((k: any) => k.isDefault));
    assert.ok(body.apiKeys.every((k: any) => k.key.includes("…")), "every listed key must be masked");
  } finally {
    server.close();
  }
});

test("PATCH /api/projects/:id/api-keys/:keyId renames and rescopes", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const created = await (
      await fetch(`${base}/api/projects/${projectId}/api-keys`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "Original", scopes: ["scan", "events"] }),
      })
    ).json();

    const res = await fetch(`${base}/api/projects/${projectId}/api-keys/${created.apiKey.id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Renamed", scopes: ["events"] }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.apiKey.name, "Renamed");
    assert.deepEqual(body.apiKey.scopes, ["events"]);
  } finally {
    server.close();
  }
});

test("POST .../api-keys/:keyId/revoke marks it revoked and it stops working for scanning", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const created = await (
      await fetch(`${base}/api/projects/${projectId}/api-keys`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "To revoke", scopes: ["scan"] }),
      })
    ).json();

    const res = await fetch(`${base}/api/projects/${projectId}/api-keys/${created.apiKey.id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.apiKey.revokedAt);
  } finally {
    server.close();
  }
});

test("POST .../api-keys/:keyId/rotate on the default key updates the legacy project.apiKey field too", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const list = await (await fetch(`${base}/api/projects/${projectId}/api-keys`, { headers: { Authorization: `Bearer ${token}` } })).json();
    const defaultKey = list.apiKeys.find((k: any) => k.isDefault);
    assert.ok(defaultKey);

    const oldProjectRes = await fetch(`${base}/api/projects/${projectId}`, { headers: { Authorization: `Bearer ${token}` } });
    const oldProject = (await oldProjectRes.json()).project;

    const rotateRes = await fetch(`${base}/api/projects/${projectId}/api-keys/${defaultKey.id}/rotate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(rotateRes.status, 200);
    const rotated = (await rotateRes.json()).apiKey;
    assert.match(rotated.key, /^nettle_[0-9a-f]{48}$/);

    const newProjectRes = await fetch(`${base}/api/projects/${projectId}`, { headers: { Authorization: `Bearer ${token}` } });
    const newProject = (await newProjectRes.json()).project;
    assert.equal(newProject.apiKey, rotated.key, "rotating the default key via the new endpoint must update the legacy field");
    assert.notEqual(newProject.apiKey, oldProject.apiKey);
  } finally {
    server.close();
  }
});

test("API key routes 404 for a project the caller doesn't own", async () => {
  const a = await subscriberWithProject();
  const b = await subscriberWithProject();
  try {
    const res = await fetch(`${a.base}/api/projects/${a.projectId}/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${b.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Should not work" }),
    });
    assert.equal(res.status, 404);
  } finally {
    a.server.close();
    b.server.close();
  }
});

test("a keyId that belongs to a different project 404s even for the project's own owner", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  const other = await subscriberWithProject();
  try {
    const otherKeyRes = await fetch(`${other.base}/api/projects/${other.projectId}/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${other.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Belongs elsewhere" }),
    });
    const otherKey = (await otherKeyRes.json()).apiKey;

    const res = await fetch(`${base}/api/projects/${projectId}/api-keys/${otherKey.id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 404);
  } finally {
    server.close();
    other.server.close();
  }
});
