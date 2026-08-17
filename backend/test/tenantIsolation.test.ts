import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { createAlert } from "../src/patrol/alerts";
import { runScan } from "../src/scanner";
import { projectsRouter } from "../src/routes/projects.routes";
import { authRouter } from "../src/routes/auth.routes";
import { badgeRouter } from "../src/routes/badge.routes";

/**
 * Every account gets its own dashboard, and nothing about another account's
 * projects may leak into it. The ownership check lives in a helper each
 * handler has to remember to call, so this exercises every project route as
 * a signed-in stranger rather than trusting that the helper was wired up
 * consistently.
 */

const PASSWORD = "correct horse battery staple";
const FIXTURE = path.join(__dirname, "fixtures", "sample-app");

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
  app.use(authRouter);
  app.use(badgeRouter);
  return app;
}

async function subscribedUser(base: string, email: string) {
  const user = await createUser(email, PASSWORD);
  setSubscriptionStatus(user.id, "tier2", "active");
  const res = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  return { user, token: (await res.json()).token };
}

test("each account's dashboard lists only its own projects", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const alice = await subscribedUser(base, "iso-alice@example.com");
    const bob = await subscribedUser(base, "iso-bob@example.com");

    const alicesProject = createProject(alice.user.id, "Alice Secret Project");
    createProject(bob.user.id, "Bob Project");

    const res = await fetch(`${base}/api/projects`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const { projects } = await res.json();

    assert.equal(projects.length, 1);
    assert.equal(projects[0].name, "Bob Project");
    assert.ok(
      !projects.some((p: { id: string }) => p.id === alicesProject.id),
      "Bob's project list must not contain Alice's project"
    );
  } finally {
    server.close();
  }
});

test("the overview totals never count another account's data", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const alice = await subscribedUser(base, "iso-overview-a@example.com");
    const bob = await subscribedUser(base, "iso-overview-b@example.com");

    // Alice has a project with a bad scan; Bob has nothing at all.
    const alicesProject = createProject(alice.user.id, "Alice Scanned");
    recordScan(alicesProject.id, runScan(FIXTURE));

    const res = await fetch(`${base}/api/overview`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    const body = await res.json();

    assert.equal(body.totalProjects, 0);
    assert.equal(body.totalCriticalFindings, 0);
    assert.equal(body.latestScore, null);
    assert.equal(body.projects.length, 0);
  } finally {
    server.close();
  }
});

test("every project route refuses a signed-in stranger", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const alice = await subscribedUser(base, "iso-routes-a@example.com");
    const bob = await subscribedUser(base, "iso-routes-b@example.com");

    const project = createProject(alice.user.id, "Alice Private");
    const scan = recordScan(project.id, runScan(FIXTURE));
    const alert = createAlert(project.id, "critical", "test-rule", "private alert text");

    const routes: [string, string][] = [
      ["GET", `/api/projects/${project.id}`],
      ["PATCH", `/api/projects/${project.id}`],
      ["DELETE", `/api/projects/${project.id}`],
      ["POST", `/api/projects/${project.id}/archive`],
      ["POST", `/api/projects/${project.id}/restore`],
      ["POST", `/api/projects/${project.id}/rotate-key`],
      ["GET", `/api/projects/${project.id}/alerts`],
      ["PATCH", `/api/projects/${project.id}/alerts/${alert.id}`],
      ["GET", `/api/projects/${project.id}/scans`],
      ["GET", `/api/projects/${project.id}/scans/compare`],
      ["GET", `/api/projects/${project.id}/findings`],
      ["PATCH", `/api/projects/${project.id}/findings/abc12345`],
      ["GET", `/api/projects/${project.id}/scans/${scan.id}/export`],
    ];

    for (const [method, url] of routes) {
      const res = await fetch(`${base}${url}`, {
        method,
        headers: { Authorization: `Bearer ${bob.token}`, "Content-Type": "application/json" },
        body: method === "GET" || method === "DELETE" ? undefined : JSON.stringify({ status: "resolved", name: "hijacked" }),
      });
      assert.equal(res.status, 404, `${method} ${url} should be 404 for a non-owner, got ${res.status}`);

      // 404 rather than 403 on purpose: a stranger shouldn't be able to
      // confirm that a project id exists at all.
      const body = await res.json().catch(() => ({}));
      assert.equal(body.error, "Project not found");
    }
  } finally {
    server.close();
  }
});

test("a refused write leaves the owner's project untouched", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const alice = await subscribedUser(base, "iso-write-a@example.com");
    const bob = await subscribedUser(base, "iso-write-b@example.com");
    const project = createProject(alice.user.id, "Original Name");
    const originalKey = project.apiKey;

    await fetch(`${base}/api/projects/${project.id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${bob.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Hijacked" }),
    });
    await fetch(`${base}/api/projects/${project.id}/rotate-key`, {
      method: "POST",
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    await fetch(`${base}/api/projects/${project.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${bob.token}` },
    });

    // Alice still sees exactly what she had.
    const res = await fetch(`${base}/api/projects/${project.id}`, {
      headers: { Authorization: `Bearer ${alice.token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.project.name, "Original Name");
    assert.equal(body.project.apiKey, originalKey);
  } finally {
    server.close();
  }
});

test("the public trust badge stays public — it is the one intentional leak", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const alice = await subscribedUser(base, "iso-badge@example.com");
    const project = createProject(alice.user.id, "Alice Badged");

    // No token at all: this is an <img> on someone else's marketing site.
    const res = await fetch(`${base}/api/projects/${project.id}/badge.svg`);
    assert.equal(res.status, 200);

    // It may reveal status, but never the project name or any finding detail.
    const svg = await res.text();
    assert.ok(!svg.includes("Alice Badged"), "badge must not expose the project name");
  } finally {
    server.close();
  }
});
