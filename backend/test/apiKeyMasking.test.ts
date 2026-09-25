import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { findProjectByApiKey, maskApiKey } from "../src/patrol/projects";
import { projectsRouter } from "../src/routes/projects.routes";

// A scanning product whose own controls flag secrets exposed to the browser
// (SECRET-001) must not itself keep re-serving a live project API key on
// every ordinary page load. Only the moment a key is actually created or
// deliberately regenerated should ever return the real value — every other
// route that returns a Project must return the masked form. See
// routes/projects.routes.ts's withMaskedKey/patrol/projects.ts's
// maskApiKey.

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

test("POST /api/projects returns the real, usable key", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const user = await createUser("apikey-create@example.com", "correct horse battery staple");
  const token = await createSession(user.id);

  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Real Key Test" }),
  });
  assert.equal(res.status, 201);
  const body = (await res.json()) as { apiKey: string };

  assert.ok(body.apiKey.startsWith("nettle_"));
  assert.ok(!body.apiKey.includes("•"), "creation must hand back the real key, not a masked one");
  // The real key must actually work as a credential elsewhere in the API.
  const found = await findProjectByApiKey(body.apiKey);
  assert.ok(found, "the key returned at creation must be the real, live key");
});

test("GET/PATCH/archive/restore never return the real key again", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const user = await createUser("apikey-mask@example.com", "correct horse battery staple");
  const token = await createSession(user.id);
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

  const created = (await (
    await fetch(`${base}/api/projects`, { method: "POST", headers, body: JSON.stringify({ name: "Mask Test" }) })
  ).json()) as { id: string; apiKey: string };
  const realKey = created.apiKey;
  const expectedMasked = maskApiKey(realKey);

  const list = (await (await fetch(`${base}/api/projects`, { headers })).json()) as { projects: { apiKey: string }[] };
  assert.equal(list.projects[0].apiKey, expectedMasked);
  assert.notEqual(list.projects[0].apiKey, realKey);

  const detail = (await (await fetch(`${base}/api/projects/${created.id}`, { headers })).json()) as { project: { apiKey: string } };
  assert.equal(detail.project.apiKey, expectedMasked);

  const patched = (await (
    await fetch(`${base}/api/projects/${created.id}`, { method: "PATCH", headers, body: JSON.stringify({ name: "Renamed" }) })
  ).json()) as { apiKey: string };
  assert.equal(patched.apiKey, expectedMasked);

  const archived = (await (
    await fetch(`${base}/api/projects/${created.id}/archive`, { method: "POST", headers })
  ).json()) as { apiKey: string };
  assert.equal(archived.apiKey, expectedMasked);

  const restored = (await (
    await fetch(`${base}/api/projects/${created.id}/restore`, { method: "POST", headers })
  ).json()) as { apiKey: string };
  assert.equal(restored.apiKey, expectedMasked);

  // The masked value is display-only — it must not work as a credential.
  assert.equal(await findProjectByApiKey(expectedMasked), null);
});

test("POST /rotate-key returns the new real key, and it works", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const user = await createUser("apikey-rotate@example.com", "correct horse battery staple");
  const token = await createSession(user.id);
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

  const created = (await (
    await fetch(`${base}/api/projects`, { method: "POST", headers, body: JSON.stringify({ name: "Rotate Test" }) })
  ).json()) as { id: string; apiKey: string };

  const rotated = (await (
    await fetch(`${base}/api/projects/${created.id}/rotate-key`, { method: "POST", headers })
  ).json()) as { apiKey: string };

  assert.ok(!rotated.apiKey.includes("•"), "rotation must hand back the real new key, not a masked one");
  assert.notEqual(rotated.apiKey, created.apiKey);
  assert.ok(await findProjectByApiKey(rotated.apiKey), "the rotated key must actually work as a credential");
  assert.equal(await findProjectByApiKey(created.apiKey), null, "the old key must stop working immediately");
});

test("maskApiKey keeps the prefix and last 4 characters, hides the rest", () => {
  const masked = maskApiKey("nettle_abcdef0123456789abcdef0123456789abcdef01234567");
  assert.ok(masked.startsWith("nettle_"));
  assert.ok(masked.endsWith("4567"));
  assert.ok(masked.includes("•"));
  assert.ok(!masked.includes("abcdef0123456789"));
});
