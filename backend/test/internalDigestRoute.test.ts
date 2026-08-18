import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { createNotificationChannel } from "../src/patrol/notificationChannels";
import { internalRouter } from "../src/routes/internal.routes";

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
  app.use(internalRouter);
  return app;
}

test("POST /api/internal/digest/:period is unauthorized without the correct secret header", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const original = process.env.CRON_SECRET;
  process.env.CRON_SECRET = "s3cr3t";
  try {
    const noHeader = await fetch(`${base}/api/internal/digest/daily`, { method: "POST" });
    assert.equal(noHeader.status, 401);

    const wrongHeader = await fetch(`${base}/api/internal/digest/daily`, {
      method: "POST",
      headers: { "X-Nettle-Cron-Secret": "wrong" },
    });
    assert.equal(wrongHeader.status, 401);
  } finally {
    process.env.CRON_SECRET = original;
    server.close();
  }
});

test("POST /api/internal/digest/:period is disabled (503) when CRON_SECRET isn't configured", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const original = process.env.CRON_SECRET;
  delete process.env.CRON_SECRET;
  try {
    const res = await fetch(`${base}/api/internal/digest/daily`, {
      method: "POST",
      headers: { "X-Nettle-Cron-Secret": "anything" },
    });
    assert.equal(res.status, 503);
  } finally {
    process.env.CRON_SECRET = original;
    server.close();
  }
});

test("POST /api/internal/digest/:period rejects an unknown period", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const original = process.env.CRON_SECRET;
  process.env.CRON_SECRET = "s3cr3t";
  try {
    const res = await fetch(`${base}/api/internal/digest/monthly`, {
      method: "POST",
      headers: { "X-Nettle-Cron-Secret": "s3cr3t" },
    });
    assert.equal(res.status, 400);
  } finally {
    process.env.CRON_SECRET = original;
    server.close();
  }
});

test("POST /api/internal/digest/:period with the correct secret sends digests and reports how many projects were notified", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const original = process.env.CRON_SECRET;
  process.env.CRON_SECRET = "s3cr3t";
  try {
    const user = await createUser("internal-digest-route@example.com", "correct horse battery staple");
    const project = createProject(user.id, "Internal Digest Route Target");
    createNotificationChannel(project.id, "email", "ops@example.com", ["digest.weekly"]);

    const res = await fetch(`${base}/api/internal/digest/weekly`, {
      method: "POST",
      headers: { "X-Nettle-Cron-Secret": "s3cr3t" },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.period, "weekly");
    assert.equal(body.projectsNotified, 1);
  } finally {
    process.env.CRON_SECRET = original;
    server.close();
  }
});
