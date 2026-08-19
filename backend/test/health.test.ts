import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { healthRouter } from "../src/routes/health.routes";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

test("GET /health reports real status, a real DB check, and real scan queue state — no secrets", async () => {
  const app = express();
  app.use(healthRouter);
  const { server, base } = await listen(app);

  try {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.status, "ok");
    assert.equal(body.database, "ok");
    assert.ok(typeof body.uptimeSeconds === "number");
    assert.ok(body.scanQueue);
    assert.ok(typeof body.scanQueue.queued === "number");
    assert.ok(typeof body.scanQueue.running === "number");

    const raw = JSON.stringify(body).toLowerCase();
    for (const forbidden of ["secret", "password", "token", "key", "database_url"]) {
      assert.ok(!raw.includes(forbidden), `health response leaked something matching "${forbidden}"`);
    }
  } finally {
    server.close();
  }
});
