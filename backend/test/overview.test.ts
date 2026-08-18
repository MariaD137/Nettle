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

test("GET /api/overview includes each project's environment tag", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("overview-env@example.com", "correct horse battery staple");
    setSubscriptionStatus(user.id, "tier1", "active");
    const token = createSession(user.id);
    createProject(user.id, "Staging App", { environment: "staging" });
    createProject(user.id, "No Env Set");

    const res = await fetch(`${base}/api/overview`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
    const body = await res.json();

    const staging = body.projects.find((p: any) => p.name === "Staging App");
    assert.equal(staging.environment, "staging");

    const defaulted = body.projects.find((p: any) => p.name === "No Env Set");
    assert.equal(defaulted.environment, "production"); // createProject's own default
  } finally {
    server.close();
  }
});
