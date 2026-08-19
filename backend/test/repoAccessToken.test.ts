import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";

process.env.NETTLE_TOKEN_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");

import { createProject, setRepoAccessToken, getDecryptedRepoAccessToken, getProject } from "../src/patrol/projects";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { projectsRouter } from "../src/routes/projects.routes";

const PASSWORD = "correct horse battery staple";
let counter = 0;
async function testUser() {
  const user = await createUser(`repo-token-test-${counter++}@example.com`, PASSWORD);
  await setSubscriptionStatus(user.id, "tier1", "active");
  return user;
}

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, base: `http://localhost:${port}` });
    });
  });
}

// --- patrol layer ---

test("setRepoAccessToken stores an encrypted token and flips hasRepoAccessToken", async () => {
  const user = await testUser();
  const project = await createProject(user.id, "Token Project");
  assert.equal(project.hasRepoAccessToken, false);

  const updated = await setRepoAccessToken(project.id, "ghp_secretvalue");
  assert.equal(updated?.hasRepoAccessToken, true);

  const fetched = await getProject(project.id);
  assert.equal(fetched?.hasRepoAccessToken, true);
});

test("setRepoAccessToken(null) clears a stored token", async () => {
  const user = await testUser();
  const project = await createProject(user.id, "Clearable Project");
  await setRepoAccessToken(project.id, "ghp_secretvalue");
  assert.equal((await getProject(project.id))?.hasRepoAccessToken, true);

  await setRepoAccessToken(project.id, null);
  assert.equal((await getProject(project.id))?.hasRepoAccessToken, false);
  assert.equal(await getDecryptedRepoAccessToken(project.id), null);
});

test("getDecryptedRepoAccessToken returns the original plaintext", async () => {
  const user = await testUser();
  const project = await createProject(user.id, "Round Trip Project");
  await setRepoAccessToken(project.id, "ghp_originalvalue123");
  assert.equal(await getDecryptedRepoAccessToken(project.id), "ghp_originalvalue123");
});

test("getDecryptedRepoAccessToken returns null when nothing is stored", async () => {
  const user = await testUser();
  const project = await createProject(user.id, "No Token Project");
  assert.equal(await getDecryptedRepoAccessToken(project.id), null);
});

// --- route contract: the token value is never returned by the API ---

test("PATCH /api/projects/:id accepts a repoAccessToken but never echoes it back", async () => {
  const user = await testUser();
  const token = await createSession(user.id);
  const project = await createProject(user.id, "API Contract Project");

  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);

  try {
    const res = await fetch(`${base}/api/projects/${project.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ repoAccessToken: "ghp_shouldneverberoundtripped" }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.hasRepoAccessToken, true);
    const serialized = JSON.stringify(body);
    assert.equal(serialized.includes("ghp_shouldneverberoundtripped"), false);
    assert.equal(serialized.includes("repoAccessToken"), false);
    assert.equal(serialized.includes("repo_access_token_encrypted"), false);

    // And clearing it round-trips correctly too.
    const clearRes = await fetch(`${base}/api/projects/${project.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ repoAccessToken: "" }),
    });
    const clearBody = await clearRes.json();
    assert.equal(clearBody.hasRepoAccessToken, false);
  } finally {
    server.close();
  }
});

test("PATCH without repoAccessToken in the body leaves an existing token untouched", async () => {
  const user = await testUser();
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Untouched Token Project");
  await setRepoAccessToken(project.id, "ghp_originalvalue");

  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);

  try {
    const res = await fetch(`${base}/api/projects/${project.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ name: "Renamed, token untouched" }),
    });
    const body = await res.json();
    assert.equal(body.name, "Renamed, token untouched");
    assert.equal(body.hasRepoAccessToken, true);
    assert.equal(await getDecryptedRepoAccessToken(project.id), "ghp_originalvalue");
  } finally {
    server.close();
  }
});
