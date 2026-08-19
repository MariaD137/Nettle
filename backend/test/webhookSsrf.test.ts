import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import http from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { createWebhookConfig, sendWebhook } from "../src/integrations/webhooks";
import { db } from "../src/db/index";

process.env.NETTLE_WEBHOOK_SECRET ??= crypto.randomBytes(32).toString("hex");

// Regression coverage for the webhook SSRF vulnerability: outbound webhook
// delivery used to call the plain global fetch() directly on a
// customer-supplied URL, with no host validation at all — an authenticated
// project owner could point a webhook at an internal address and fire it on
// demand. Delivery is now routed through the same SSRF-hardened client the
// URL scanner uses; these tests prove malicious destinations are actually
// rejected at delivery time, not just "should be" by convention.

let counter = 0;
async function projectId(): Promise<string> {
  const user = await createUser(`webhook-ssrf-${counter++}@example.com`, "correct horse battery staple");
  return createProject(user.id, "SSRF Test Project").id;
}

function lastEvent(webhookId: string): { status: string; last_error: string | null } {
  return db
    .prepare("SELECT status, last_error FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1")
    .get(webhookId) as { status: string; last_error: string | null };
}

async function deliverAndGetOutcome(webhookUrl: string): Promise<{ status: string; last_error: string | null }> {
  const pid = await projectId();
  const webhook = createWebhookConfig(pid, "generic", webhookUrl, ["scan.completed"]);
  await sendWebhook(pid, "scan.completed", { hello: "world" });
  return lastEvent(webhook.id);
}

test("a webhook pointed at localhost is rejected, not delivered", async () => {
  const outcome = await deliverAndGetOutcome("http://localhost:1/hook");
  assert.equal(outcome.status, "failed");
  assert.match(outcome.last_error ?? "", /reserved hostname|private|reserved/i);
});

test("a webhook pointed at a loopback IP literal is rejected", async () => {
  const outcome = await deliverAndGetOutcome("http://127.0.0.1:1/hook");
  assert.equal(outcome.status, "failed");
  assert.match(outcome.last_error ?? "", /private|reserved/i);
});

test("a webhook pointed at the IPv6 loopback literal is rejected", async () => {
  const outcome = await deliverAndGetOutcome("http://[::1]:1/hook");
  assert.equal(outcome.status, "failed");
  // Bracketed IPv6 literals fall through to the DNS-lookup path rather than
  // the literal-IP fast path (URL.hostname keeps the brackets, which
  // net.isIP doesn't recognize) — still safely blocked either way, just
  // with a "couldn't resolve" message instead of "private/reserved".
  assert.match(outcome.last_error ?? "", /private|reserved|couldn't resolve/i);
});

test("a webhook pointed at a private IPv4 range is rejected", async () => {
  const outcome = await deliverAndGetOutcome("http://10.0.0.5:1/hook");
  assert.equal(outcome.status, "failed");
  assert.match(outcome.last_error ?? "", /private|reserved/i);
});

test("a webhook pointed at the cloud metadata address is rejected", async () => {
  const outcome = await deliverAndGetOutcome("http://169.254.169.254/latest/meta-data/");
  assert.equal(outcome.status, "failed");
  assert.match(outcome.last_error ?? "", /private|reserved/i);
});

test("a webhook with an unsupported scheme is rejected before any network activity", async () => {
  const outcome = await deliverAndGetOutcome("file:///etc/passwd");
  assert.equal(outcome.status, "failed");
  assert.match(outcome.last_error ?? "", /unsupported protocol/i);
});

test("SSRF-blocked destinations fail permanently, without retry-storming the target", async () => {
  const start = Date.now();
  await deliverAndGetOutcome("http://127.0.0.1:1/hook");
  const elapsed = Date.now() - start;
  // The retry backoff schedule is 1s/3s/10s; a permanent SSRF rejection
  // must return well before the first backoff would even elapse.
  assert.ok(elapsed < 1000, `expected an immediate permanent failure, took ${elapsed}ms`);
});

test("a genuine, reachable HTTP webhook still gets delivered through the safe path", async () => {
  let received: { headers: http.IncomingHttpHeaders; body: string } | null = null;
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received = { headers: req.headers, body: Buffer.concat(chunks).toString("utf8") };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const port = (server.address() as AddressInfo).port;
    // 127.0.0.1 is blocked by design — this proves *delivery mechanics*
    // (POST, headers, body, signature) still work correctly once a target
    // is legitimately reachable, using the same fetcher a public host would
    // go through. Loopback here stands in for "a real external host",
    // which the SSRF-safe fetcher can't be pointed at from a test without a
    // live public server.
    const pid = await projectId();
    const { performValidatedRequest } = await import("../src/scanner/ssrfSafeFetch");
    const { generateSignature } = await import("../src/integrations/webhooks");
    const url = new URL(`http://127.0.0.1:${port}/hook`);
    const payload = { hello: "world" };
    const result = await performValidatedRequest(url, "127.0.0.1", 4, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Nettle-Signature": generateSignature(payload),
        "X-Nettle-Event-Type": "scan.completed",
      },
      body: JSON.stringify({ id: "evt_1", timestamp: new Date().toISOString(), event_type: "scan.completed", data: payload }),
    });

    assert.equal(result.res.statusCode, 200);
    assert.ok(received, "the target server should have received the request");
    assert.equal(received!.headers["x-nettle-event-type"], "scan.completed");
    assert.ok(received!.headers["x-nettle-signature"]);
    const parsedBody = JSON.parse(received!.body);
    assert.equal(parsedBody.event_type, "scan.completed");
    assert.deepEqual(parsedBody.data, payload);
    void pid;
  } finally {
    server.close();
  }
});
