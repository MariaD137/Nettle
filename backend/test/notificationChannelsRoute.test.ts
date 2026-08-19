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
  const user = await createUser(`notification-channels-route-${counter++}@example.com`, "correct horse battery staple");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Notification Channels Route Target");
  return { token, projectId: project.id, base, server };
}

test("POST /api/projects/:id/notification-channels creates an email channel", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "email", destination: "ops@example.com", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.channel, "email");
    assert.equal(body.destination, "ops@example.com");
    assert.equal(body.is_active, true);
  } finally {
    server.close();
  }
});

test("POST rejects an invalid email destination", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "email", destination: "not-an-email", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("POST rejects an SMS destination that isn't E.164", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "sms", destination: "555-1234", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("POST accepts a valid E.164 SMS destination", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const res = await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "sms", destination: "+15551234567", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 201);
  } finally {
    server.close();
  }
});

test("GET lists channels for the project", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "email", destination: "a@example.com", event_types: ["scan.completed"] }),
    });
    const res = await fetch(`${base}/api/projects/${projectId}/notification-channels`, { headers: { Authorization: `Bearer ${token}` } });
    const body = await res.json();
    assert.equal(body.length, 1);
  } finally {
    server.close();
  }
});

test("PATCH updates event types and active state, and re-validates a changed destination", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const created = await (
      await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "email", destination: "a@example.com", event_types: ["scan.completed"] }),
      })
    ).json();

    const ok = await fetch(`${base}/api/projects/${projectId}/notification-channels/${created.id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ is_active: false, event_types: ["incident_alert"] }),
    });
    assert.equal(ok.status, 200);
    const okBody = await ok.json();
    assert.equal(okBody.is_active, false);
    assert.deepEqual(okBody.event_types, ["incident_alert"]);

    const bad = await fetch(`${base}/api/projects/${projectId}/notification-channels/${created.id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ destination: "not-an-email" }),
    });
    assert.equal(bad.status, 400);
  } finally {
    server.close();
  }
});

test("DELETE removes a channel", async () => {
  const { token, projectId, base, server } = await subscriberWithProject();
  try {
    const created = await (
      await fetch(`${base}/api/projects/${projectId}/notification-channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "email", destination: "a@example.com", event_types: ["scan.completed"] }),
      })
    ).json();

    const del = await fetch(`${base}/api/projects/${projectId}/notification-channels/${created.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(del.status, 204);

    const list = await (await fetch(`${base}/api/projects/${projectId}/notification-channels`, { headers: { Authorization: `Bearer ${token}` } })).json();
    assert.equal(list.length, 0);
  } finally {
    server.close();
  }
});

test("notification-channel routes 404 for a project the caller doesn't own", async () => {
  const a = await subscriberWithProject();
  const b = await subscriberWithProject();
  try {
    const res = await fetch(`${a.base}/api/projects/${a.projectId}/notification-channels`, {
      method: "POST",
      headers: { Authorization: `Bearer ${b.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "email", destination: "a@example.com", event_types: ["scan.completed"] }),
    });
    assert.equal(res.status, 404);
  } finally {
    a.server.close();
    b.server.close();
  }
});
