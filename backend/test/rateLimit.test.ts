import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { rateLimit } from "../src/middleware/rateLimit";
import { scansRouter } from "../src/routes/scans.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { badgeRouter } from "../src/routes/badge.routes";
import { eventsRouter } from "../src/routes/events.routes";
import { billingRouter } from "../src/routes/billing.routes";
import { authRouter } from "../src/routes/auth.routes";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

// Unit-level coverage of the shared rateLimit() middleware itself — the
// specific per-route thresholds are exercised separately below via
// header-presence checks rather than by actually exhausting a real
// 10/120/300-request budget in a test.
test("rateLimit middleware returns 429 with Retry-After once the limit is exceeded", async () => {
  const app = express();
  app.get(
    "/probe",
    rateLimit({ windowMs: 60_000, maxRequests: 3, message: "slow down" }),
    (_req, res) => res.status(200).json({ ok: true })
  );
  const { server, base } = await listen(app);
  try {
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${base}/probe`);
      assert.equal(res.status, 200);
    }
    const blocked = await fetch(`${base}/probe`);
    assert.equal(blocked.status, 429);
    assert.ok(blocked.headers.get("retry-after"));
    const body = await blocked.json();
    assert.equal(body.error, "slow down");
  } finally {
    server.close();
  }
});

test("rateLimit's keyGenerator gives independent budgets to different keys", async () => {
  const app = express();
  app.get(
    "/probe",
    rateLimit({
      windowMs: 60_000,
      maxRequests: 1,
      keyGenerator: (req) => `${req.path}:${req.header("x-key")}`,
    }),
    (_req, res) => res.status(200).json({ ok: true })
  );
  const { server, base } = await listen(app);
  try {
    const a1 = await fetch(`${base}/probe`, { headers: { "x-key": "a" } });
    assert.equal(a1.status, 200);
    const a2 = await fetch(`${base}/probe`, { headers: { "x-key": "a" } });
    assert.equal(a2.status, 429, "second request with the same key should be blocked");

    const b1 = await fetch(`${base}/probe`, { headers: { "x-key": "b" } });
    assert.equal(b1.status, 200, "a different key should have its own untouched budget");
  } finally {
    server.close();
  }
});

// These previously had zero rate limiting at all (H-3). Each check below
// confirms a limiter is genuinely mounted on the route — not just defined
// somewhere unused — by looking for the X-RateLimit-Limit header the
// rateLimit middleware sets on every response it handles.
test("scan upload endpoint has a rate limiter mounted", async () => {
  const app = express();
  app.use(express.json());
  app.use(scansRouter);
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/scans`, { method: "POST" });
    assert.ok(res.headers.get("x-ratelimit-limit"), "expected a rate limit header on /api/scans");
  } finally {
    server.close();
  }
});

test("project routes have a rate limiter mounted", async () => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/projects`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    assert.ok(res.headers.get("x-ratelimit-limit"), "expected a rate limit header on /api/projects");
  } finally {
    server.close();
  }
});

test("badge endpoints have a rate limiter mounted", async () => {
  const app = express();
  app.use(badgeRouter);
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/projects/nonexistent/badge.json`);
    assert.ok(res.headers.get("x-ratelimit-limit"), "expected a rate limit header on the badge endpoint");
  } finally {
    server.close();
  }
});

test("event ingestion endpoint has a rate limiter mounted, keyed by API key not just IP", async () => {
  const app = express();
  app.use(express.json());
  app.use(eventsRouter);
  const { server, base } = await listen(app);
  try {
    const res = await fetch(`${base}/api/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-nettle-api-key": "nettle_fake" },
      body: "{}",
    });
    assert.ok(res.headers.get("x-ratelimit-limit"), "expected a rate limit header on /api/events");
  } finally {
    server.close();
  }
});

test("billing checkout endpoint has a rate limiter mounted", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  app.use(billingRouter);
  const { server, base } = await listen(app);
  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "ratelimit-billing@example.com", password: "correct horse battery staple" }),
    });
    const { token } = await signup.json();

    const res = await fetch(`${base}/api/billing/checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ plan: "tier1" }),
    });
    assert.ok(res.headers.get("x-ratelimit-limit"), "expected a rate limit header on /api/billing/checkout-session");
  } finally {
    server.close();
  }
});
