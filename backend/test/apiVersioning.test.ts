import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { apiVersioning } from "../src/middleware/apiVersion";
import { healthRouter } from "../src/routes/health.routes";
import { authRouter } from "../src/routes/auth.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { badgeRouter } from "../src/routes/badge.routes";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";

// API versioning (master spec §30): /api/v1/<rest> is rewritten to
// /api/<rest> before any router runs, so both surfaces serve identical
// responses from the same handler with no duplicated route definitions.
// /health has no versioned equivalent by design — health checks stay
// stable regardless of API version.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

async function setUp() {
  const app = express();
  app.use(apiVersioning);
  app.use(express.json());
  app.use(healthRouter);
  app.use(authRouter);
  app.use(projectsRouter);
  app.use(badgeRouter);
  const { server, base } = await listen(app);
  return { server, base };
}

test("GET /api/v1/... and GET /api/... return identical responses from the same handler", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const user = await createUser("apiver-get@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);
  await createProject(user.id, "V1 Test");

  const v1Res = await fetch(`${base}/api/v1/projects`, { headers: { Authorization: `Bearer ${token}` } });
  const legacyRes = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${token}` } });

  assert.equal(v1Res.status, 200);
  assert.equal(legacyRes.status, 200);
  const v1Body = await v1Res.json();
  const legacyBody = await legacyRes.json();
  assert.deepEqual(v1Body, legacyBody);
});

test("POST /api/v1/... carries the request body through correctly (rewrite happens before express.json())", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const res = await fetch(`${base}/api/v1/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "apiver-post@example.com", password: "correct horse battery staple" }),
  });
  assert.equal(res.status, 201);
  const body = (await res.json()) as any;
  assert.equal(body.user.email, "apiver-post@example.com");
});

test("every response carries an X-API-Version header, versioned or not", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const res = await fetch(`${base}/health`);
  assert.equal(res.headers.get("x-api-version"), "v1");

  const v1Res = await fetch(`${base}/api/v1/does-not-exist`);
  assert.equal(v1Res.headers.get("x-api-version"), "v1");
});

test("/health has no versioned equivalent — /api/v1/health does not alias it", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);

  // /api/v1/health rewrites to /api/health, which is not a registered route
  // in this test app (health.routes.ts only registers the bare /health
  // path) — falls through with no handler, not a 200.
  const v1Res = await fetch(`${base}/api/v1/health`);
  assert.notEqual(v1Res.status, 200);
});

test("query strings survive the rewrite", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const user = await createUser("apiver-query@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Archived Test");

  const res = await fetch(`${base}/api/v1/projects?includeArchived=true`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;
  assert.ok(body.projects.some((p: any) => p.id === project.id));
});

test("the unversioned path keeps working unchanged — badge URLs meant for long-lived third-party embeds must never break", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const user = await createUser("apiver-badge@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Badge Test");

  const res = await fetch(`${base}/api/projects/${project.id}/badge.svg`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /svg/);
});
