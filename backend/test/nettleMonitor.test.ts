// NETTLE_DB_PATH=:memory: is set by the `test` npm script, not here — see
// the comment in patrol.test.ts for why an in-file assignment doesn't work.
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { nettleMonitor } from "../src/middleware/nettleMonitor";
import { eventsRouter } from "../src/routes/events.routes";
import { createProject } from "../src/patrol/projects";
import { listAlerts } from "../src/patrol/alerts";
import { createUser } from "../src/auth/users";

function listen(app: express.Express): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, port: (server.address() as AddressInfo).port });
    });
  });
}

async function poll<T>(fn: () => Promise<T>, predicate: (v: T) => boolean, timeoutMs = 2000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const value = await fn();
    if (predicate(value)) return value;
    if (Date.now() - start > timeoutMs) return value;
    await new Promise((r) => setTimeout(r, 25));
  }
}

test("a customer app using the middleware actually reports events that trigger a real alert", async () => {
  const user = await createUser("nettle-monitor-tests@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Middleware Test App");

  const ingestionApp = express();
  ingestionApp.use(express.json());
  ingestionApp.use(eventsRouter);
  const { server: ingestionServer, port } = await listen(ingestionApp);

  const customerApp = express();
  customerApp.use(nettleMonitor({ apiKey: project.apiKey, endpoint: `http://localhost:${port}/api/events` }));
  customerApp.post("/login", (_req, res) => res.status(401).json({ error: "Unauthorized" }));
  const { server: customerServer, port: customerPort } = await listen(customerApp);

  try {
    for (let i = 0; i < 5; i++) {
      await fetch(`http://localhost:${customerPort}/login`, { method: "POST" });
    }

    const alerts = await poll(async () => listAlerts(project.id), (a) => a.length > 0);
    assert.ok(alerts.some((a) => a.rule === "brute-force"), "expected the real ingestion+detection pipeline to fire a brute-force alert");
  } finally {
    customerServer.close();
    ingestionServer.close();
  }
});

test("the middleware never blocks or breaks the customer's response when the ingestion endpoint is unreachable", async () => {
  const customerApp = express();
  customerApp.use(
    nettleMonitor({
      apiKey: "irrelevant-key",
      endpoint: "http://127.0.0.1:1/unreachable", // port 1: nothing will ever be listening here
      timeoutMs: 300,
    })
  );
  customerApp.get("/ping", (_req, res) => res.status(200).json({ ok: true }));
  const { server, port } = await listen(customerApp);

  try {
    const start = Date.now();
    const response = await fetch(`http://localhost:${port}/ping`);
    const elapsed = Date.now() - start;

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true });
    assert.ok(elapsed < 300, `expected the response to return immediately, not wait on the failed report (took ${elapsed}ms)`);
  } finally {
    server.close();
  }
});
