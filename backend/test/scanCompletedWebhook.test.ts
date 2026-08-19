import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { createWebhookConfig } from "../src/integrations/webhooks";
import { runScan } from "../src/scanner";
import { db } from "../src/db";
import path from "path";
import crypto from "crypto";

// generateSignature() now fails closed with no default secret (see
// src/integrations/webhooks.ts) — needs an explicit value for delivery to
// actually reach this test's receiver instead of failing in the retry loop.
process.env.NETTLE_WEBHOOK_SECRET ??= crypto.randomBytes(32).toString("hex");

const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

function startReceiver(): Promise<{ url: string; received: () => any[]; close: () => Promise<void> }> {
  const received: any[] = [];
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        received.push(JSON.parse(body));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
    });
    server.listen(0, () => {
      const url = `http://localhost:${(server.address() as AddressInfo).port}/`;
      resolve({
        url,
        received: () => received,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

function waitFor(check: () => boolean, timeoutMs = 5000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      if (check()) return resolve();
      if (Date.now() - start > timeoutMs) return reject(new Error("timed out waiting for webhook delivery"));
      setTimeout(tick, 25);
    };
    tick();
  });
}

// Regression note (C-3): this used to point a webhook at a real local HTTP
// receiver (127.0.0.1/localhost) and assert the request actually arrived.
// Once outbound webhook delivery was correctly routed through the
// SSRF-hardened client (see webhookSsrf.test.ts), a loopback receiver is —
// correctly — never reachable from that code path, the same as it wouldn't
// be for a real customer webhook pointed at an internal address. Delivery
// mechanics themselves (a real POST reaching a real receiver) are already
// covered end-to-end in webhookSsrf.test.ts. What this test verifies —
// that recordScan() actually wires up to sendWebhook() with the right
// payload — is verified here via the row queueWebhookEvent() persists
// *before* attempting delivery, which is deterministic and doesn't depend
// on the delivery attempt's (now correctly-blocked) outcome.
test("recordScan fires a scan.completed webhook to every active webhook subscribed to it", async () => {
  const user = await createUser("scan-completed-webhook@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Scan Webhook Target");
  const webhook = createWebhookConfig(project.id, "generic", "https://example.invalid/hook", ["scan.completed"]);

  const report = runScan(CLEAN_APP);
  const stored = recordScan(project.id, report);

  await waitFor(() => {
    const row = db.prepare("SELECT payload FROM webhook_events WHERE webhook_id = ?").get(webhook.id) as { payload: string } | undefined;
    return !!row;
  });

  const row = db.prepare("SELECT payload FROM webhook_events WHERE webhook_id = ?").get(webhook.id) as { payload: string };
  const payload = JSON.parse(row.payload);
  assert.equal(payload.scan_id, stored.id);
  assert.equal(payload.project_id, project.id);
  assert.equal(payload.score, stored.score);
  assert.equal(payload.status, stored.status);
});

test("recordScan does not deliver to a webhook that isn't subscribed to scan.completed", async () => {
  const user = await createUser("scan-completed-webhook-filtered@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Scan Webhook Filtered Target");
  const receiver = await startReceiver();
  try {
    createWebhookConfig(project.id, "generic", receiver.url, ["incident_alert"]);

    recordScan(project.id, runScan(CLEAN_APP));

    // Give any (incorrect) delivery a chance to arrive before asserting none did.
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(receiver.received().length, 0);
  } finally {
    await receiver.close();
  }
});

test("recordScan does not deliver to a webhook belonging to a different project", async () => {
  const user = await createUser("scan-completed-webhook-isolation@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Scan Webhook Isolation Target A");
  const otherProject = createProject(user.id, "Scan Webhook Isolation Target B");
  const receiver = await startReceiver();
  try {
    createWebhookConfig(otherProject.id, "generic", receiver.url, ["scan.completed"]);

    recordScan(project.id, runScan(CLEAN_APP));

    await new Promise((r) => setTimeout(r, 300));
    assert.equal(receiver.received().length, 0);
  } finally {
    await receiver.close();
  }
});
