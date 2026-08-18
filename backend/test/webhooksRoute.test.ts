import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import integrationsRouter from "../src/routes/integrations.routes";

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
  app.use("/api/projects", integrationsRouter);
  return app;
}

let counter = 0;
async function subscriberWithProject(): Promise<{ token: string; projectId: string; base: string; server: Server }> {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`webhooks-route-${counter++}@example.com`, "correct horse battery staple");
  const token = createSession(user.id);
  const project = createProject(user.id, "Webhook Route Test Project");
  return { token, projectId: project.id, base, server };
}

test("POST /api/projects/:id/webhooks creates a webhook config", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/webhooks`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ service: "generic", webhook_url: "https://example.com/hook", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.service, "generic");
    assert.equal(body.webhook_url, "https://example.com/hook");
    assert.deepEqual(body.event_types, ["scan.completed"]);
    assert.equal(body.is_active, true);
  } finally {
    server.close();
  }
});

test("POST /api/projects/:id/webhooks rejects an invalid service", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/webhooks`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ service: "not-a-real-service", webhook_url: "https://example.com/hook", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("POST /api/projects/:id/webhooks requires webhook_url and event_types", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/webhooks`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ service: "generic" }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("GET /api/projects/:id/webhooks lists configured webhooks for the project", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    await fetch(`${base}/api/projects/${projectId}/webhooks`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ service: "slack", webhook_url: "https://hooks.slack.com/x", event_types: ["scan.completed", "incident_alert"] }),
    });

    const res = await fetch(`${base}/api/projects/${projectId}/webhooks`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.length, 1);
    assert.equal(body[0].service, "slack");
  } finally {
    server.close();
  }
});

test("PATCH /api/projects/:id/webhooks/:webhookId updates url, event types, and active state", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const created = await (
      await fetch(`${base}/api/projects/${projectId}/webhooks`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ service: "generic", webhook_url: "https://example.com/a", event_types: ["scan.completed"] }),
      })
    ).json();

    const res = await fetch(`${base}/api/projects/${projectId}/webhooks/${created.id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ webhook_url: "https://example.com/b", event_types: ["incident_alert"], is_active: false }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.webhook_url, "https://example.com/b");
    assert.deepEqual(body.event_types, ["incident_alert"]);
    assert.equal(body.is_active, false);
  } finally {
    server.close();
  }
});

test("DELETE /api/projects/:id/webhooks/:webhookId removes it", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const created = await (
      await fetch(`${base}/api/projects/${projectId}/webhooks`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ service: "generic", webhook_url: "https://example.com/a", event_types: ["scan.completed"] }),
      })
    ).json();

    const del = await fetch(`${base}/api/projects/${projectId}/webhooks/${created.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(del.status, 204);

    const list = await (await fetch(`${base}/api/projects/${projectId}/webhooks`, { headers: { Authorization: `Bearer ${token}` } })).json();
    assert.equal(list.length, 0);
  } finally {
    server.close();
  }
});

test("webhook routes 404 for a project the caller doesn't own", async () => {
  const a = await subscriberWithProject();
  const b = await subscriberWithProject();
  try {
    const res = await fetch(`${a.base}/api/projects/${a.projectId}/webhooks`, {
      method: "POST",
      headers: { Authorization: `Bearer ${b.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ service: "generic", webhook_url: "https://example.com/a", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 404);
  } finally {
    a.server.close();
    b.server.close();
  }
});
