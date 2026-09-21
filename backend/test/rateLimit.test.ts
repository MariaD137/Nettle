import { test } from "node:test";
import assert from "node:assert/strict";
import express, { type Request } from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { db } from "../src/db";
import {
  rateLimit,
  purgeExpiredRateLimitBuckets,
  startRateLimitCleanup,
  stopRateLimitCleanup,
} from "../src/middleware/rateLimit";
import { authRouter } from "../src/routes/auth.routes";
import { scansRouter } from "../src/routes/scans.routes";
import { eventsRouter } from "../src/routes/events.routes";
import { badgeRouter } from "../src/routes/badge.routes";
import { createUser } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

// A fresh, unique scope per unit test, so these never collide with each
// other or with the route-coverage tests below even though they all run
// against the same shared (:memory:) database in one process.
let scopeCounter = 0;
function uniqueScope(): string {
  return `test-scope-${Date.now()}-${scopeCounter++}`;
}

// =====================================================================
// A. Middleware mechanics (unit-level, via rateLimit() directly)
// =====================================================================

function buildLimiterApp(opts: Parameters<typeof rateLimit>[0]) {
  const app = express();
  app.use(express.json());
  app.get("/x", rateLimit(opts), (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

test("rateLimit: allows up to maxRequests, blocks the next one with 429", async (t) => {
  const { server, base } = await listen(buildLimiterApp({ windowMs: 60_000, maxRequests: 3, scope: uniqueScope() }));
  t.after(() => server.close());

  for (let i = 0; i < 3; i++) {
    const res = await fetch(`${base}/x`);
    assert.equal(res.status, 200, `request ${i + 1} of 3 should be allowed`);
  }
  const blocked = await fetch(`${base}/x`);
  assert.equal(blocked.status, 429);
  assert.equal((await blocked.json()).error, "Too many requests — try again later");
  assert.ok(blocked.headers.get("retry-after"), "Retry-After header must be set once blocked");
});

test("rateLimit: sets X-RateLimit-* headers reflecting the running count", async (t) => {
  const { server, base } = await listen(buildLimiterApp({ windowMs: 60_000, maxRequests: 5, scope: uniqueScope() }));
  t.after(() => server.close());

  const first = await fetch(`${base}/x`);
  assert.equal(first.headers.get("x-ratelimit-limit"), "5");
  assert.equal(first.headers.get("x-ratelimit-remaining"), "4");

  const second = await fetch(`${base}/x`);
  assert.equal(second.headers.get("x-ratelimit-remaining"), "3");
});

test("rateLimit: a custom message is used on the 429 response", async (t) => {
  const { server, base } = await listen(
    buildLimiterApp({ windowMs: 60_000, maxRequests: 1, scope: uniqueScope(), message: "slow down" })
  );
  t.after(() => server.close());

  await fetch(`${base}/x`);
  const blocked = await fetch(`${base}/x`);
  assert.equal((await blocked.json()).error, "slow down");
});

test("rateLimit: the window resets after it elapses", async (t) => {
  const { server, base } = await listen(buildLimiterApp({ windowMs: 80, maxRequests: 1, scope: uniqueScope() }));
  t.after(() => server.close());

  assert.equal((await fetch(`${base}/x`)).status, 200);
  assert.equal((await fetch(`${base}/x`)).status, 429, "second request within the window must be blocked");

  await new Promise((r) => setTimeout(r, 150));
  assert.equal((await fetch(`${base}/x`)).status, 200, "a request after the window elapses must be allowed again");
});

test("rateLimit: two different identities in the same scope get independent counters", async () => {
  const scope = uniqueScope();
  const limiter = rateLimit({ windowMs: 60_000, maxRequests: 1, scope, keyFn: (req) => req.headers["x-id"] as string });

  const app = express();
  app.get("/x", limiter, (_req, res) => res.status(200).end());
  const { server, base } = await listen(app);
  try {
    const a1 = await fetch(`${base}/x`, { headers: { "x-id": "alice" } });
    const b1 = await fetch(`${base}/x`, { headers: { "x-id": "bob" } });
    assert.equal(a1.status, 200);
    assert.equal(b1.status, 200, "a distinct identity must not be affected by another identity's usage");

    const a2 = await fetch(`${base}/x`, { headers: { "x-id": "alice" } });
    const b2 = await fetch(`${base}/x`, { headers: { "x-id": "bob" } });
    assert.equal(a2.status, 429, "alice is now over her own limit");
    assert.equal(b2.status, 429, "bob is now over his own limit");
  } finally {
    server.close();
  }
});

test("rateLimit: the same identity in two different scopes gets independent counters", async () => {
  const app = express();
  app.get("/a", rateLimit({ windowMs: 60_000, maxRequests: 1, scope: uniqueScope() }), (_req, res) => res.status(200).end());
  app.get("/b", rateLimit({ windowMs: 60_000, maxRequests: 1, scope: uniqueScope() }), (_req, res) => res.status(200).end());
  const { server, base } = await listen(app);
  try {
    assert.equal((await fetch(`${base}/a`)).status, 200);
    assert.equal((await fetch(`${base}/a`)).status, 429, "route /a is now limited");
    assert.equal((await fetch(`${base}/b`)).status, 200, "a different scope must not be affected by /a's usage");
  } finally {
    server.close();
  }
});

test("rateLimit: a keyFn returning null skips limiting entirely", async (t) => {
  const { server, base } = await listen(
    buildLimiterApp({ windowMs: 60_000, maxRequests: 1, scope: uniqueScope(), keyFn: () => null })
  );
  t.after(() => server.close());

  for (let i = 0; i < 5; i++) {
    assert.equal((await fetch(`${base}/x`)).status, 200, `request ${i + 1} with no identity must never be limited`);
  }
});

test("rateLimit: a keyFn that throws fails open rather than 500ing or crashing", async (t) => {
  const { server, base } = await listen(
    buildLimiterApp({
      windowMs: 60_000,
      maxRequests: 1,
      scope: uniqueScope(),
      keyFn: () => {
        throw new Error("boom");
      },
    })
  );
  t.after(() => server.close());

  const res = await fetch(`${base}/x`);
  assert.equal(res.status, 200, "a broken key resolver must not block the request behind it");
});

test("rateLimit: a backing-store failure fails open, not closed", async (t) => {
  const scope = uniqueScope();
  const { server, base } = await listen(buildLimiterApp({ windowMs: 60_000, maxRequests: 1, scope }));
  t.after(() => server.close());

  // Simulate the database being unreachable. This must not turn into a
  // total outage of every rate-limited route (login, signup, scanning) —
  // that would be a worse failure than briefly running unprotected.
  const originalGet = db.get.bind(db);
  db.get = async () => {
    throw new Error("connection refused (simulated)");
  };
  try {
    const res = await fetch(`${base}/x`);
    assert.equal(res.status, 200, "a DB error must not block requests that have nothing to do with rate limiting");
  } finally {
    db.get = originalGet;
  }
});

// =====================================================================
// B. Cleanup / retention
// =====================================================================

test("purgeExpiredRateLimitBuckets removes only expired rows, in bounded batches", async () => {
  const past = new Date(Date.now() - 60_000).toISOString();
  const future = new Date(Date.now() + 60_000).toISOString();

  for (let i = 0; i < 7; i++) {
    await db.run("INSERT INTO rate_limit_buckets (bucket_key, count, reset_at) VALUES (?, 1, ?)", [
      `purge-test-expired-${i}`,
      past,
    ]);
  }
  await db.run("INSERT INTO rate_limit_buckets (bucket_key, count, reset_at) VALUES (?, 1, ?)", [
    "purge-test-live",
    future,
  ]);

  const firstBatch = await purgeExpiredRateLimitBuckets(3);
  assert.equal(firstBatch, 3, "must not delete more than the requested batch size in one call");

  const remainingExpired = await db.all(
    "SELECT bucket_key FROM rate_limit_buckets WHERE bucket_key LIKE 'purge-test-expired-%'"
  );
  assert.equal(remainingExpired.length, 4, "the rest of the expired rows must still be there after a partial sweep");

  const secondBatch = await purgeExpiredRateLimitBuckets(100);
  assert.equal(secondBatch, 4, "a later sweep clears what the first one left");

  const live = await db.get("SELECT bucket_key FROM rate_limit_buckets WHERE bucket_key = 'purge-test-live'");
  assert.ok(live, "a row whose window has not expired must never be purged");
});

test("rate limit cleanup start/stop is idempotent and safe to call repeatedly", () => {
  assert.doesNotThrow(() => {
    startRateLimitCleanup(3600_000);
    startRateLimitCleanup(3600_000); // second call must be a no-op, not a second timer
    stopRateLimitCleanup();
    stopRateLimitCleanup(); // stopping twice must not throw
  });
});

// =====================================================================
// C. Trust proxy — the brief's central concern
// =====================================================================
//
// src/index.ts sets `app.set("trust proxy", 1)`, reasoned through in detail
// there. index.ts itself cannot be imported in a test (it calls start() at
// import time, which listens on a port and touches the database/scanner) —
// consistent with how every other test file in this suite rebuilds an
// equivalent app rather than importing the production entrypoint (see the
// mount-order comment in paywall.test.ts). These tests prove the MECHANISM
// is safe when configured exactly as index.ts configures it; keep the
// `app.set("trust proxy", 1)` line below in sync with index.ts.

function buildTrustProxyApp(trustSetting: number | boolean) {
  const app = express();
  app.set("trust proxy", trustSetting);
  app.get("/whoami", (req, res) => res.json({ ip: req.ip }));
  return app;
}

test("trust proxy=1: a single X-Forwarded-For entry (what App Runner sets) is used as req.ip", async (t) => {
  const { server, base } = await listen(buildTrustProxyApp(1));
  t.after(() => server.close());

  const res = await fetch(`${base}/whoami`, { headers: { "X-Forwarded-For": "5.5.5.5" } });
  assert.equal((await res.json()).ip, "5.5.5.5");
});

test("trust proxy=1: a spoofed extra entry ahead of the real one is ignored", async (t) => {
  const { server, base } = await listen(buildTrustProxyApp(1));
  t.after(() => server.close());

  // Simulates a client that sent its own X-Forwarded-For header claiming to
  // be 9.9.9.9, with our one trusted hop (App Runner, standing in for
  // "whatever this test server's direct TCP peer is") appending the address
  // it actually observed, 5.5.5.5, per standard reverse-proxy convention.
  const res = await fetch(`${base}/whoami`, { headers: { "X-Forwarded-For": "9.9.9.9, 5.5.5.5" } });
  assert.equal(
    (await res.json()).ip,
    "5.5.5.5",
    "trusting exactly one hop must read the address our own trusted proxy reported, not a value the client injected ahead of it"
  );
});

test("trust proxy=true (NOT what this app uses) would let a client spoof its IP — the reason it is avoided", async (t) => {
  const { server, base } = await listen(buildTrustProxyApp(true));
  t.after(() => server.close());

  const res = await fetch(`${base}/whoami`, { headers: { "X-Forwarded-For": "9.9.9.9, 5.5.5.5" } });
  assert.equal(
    (await res.json()).ip,
    "9.9.9.9",
    "trust proxy=true reads the leftmost/oldest entry, which is exactly the value an attacker controls — " +
      "this is the concrete vulnerability app.set('trust proxy', 1) in index.ts avoids"
  );
});

test("trust proxy unset (default): X-Forwarded-For is ignored entirely", async (t) => {
  const { server, base } = await listen(buildTrustProxyApp(false));
  t.after(() => server.close());

  const res = await fetch(`${base}/whoami`, { headers: { "X-Forwarded-For": "5.5.5.5" } });
  const ip = (await res.json()).ip as string;
  assert.ok(
    ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1",
    `expected the raw loopback socket address, got ${ip}`
  );
});

// =====================================================================
// D. Route coverage — every endpoint the brief lists is actually wired
// =====================================================================

function buildFullApp() {
  // Mirrors the mount order in src/index.ts.
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(scansRouter);
  app.use(eventsRouter);
  app.use(authRouter);
  app.use(badgeRouter);
  return app;
}

const PASSWORD = "correct horse battery staple";

test("POST /api/auth/signup is rate limited per IP", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  let last: Response | undefined;
  for (let i = 0; i < 16; i++) {
    last = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: `rl-signup-${i}@example.com`, password: PASSWORD }),
    });
  }
  assert.equal(last!.status, 429, "the 16th signup within the window must be blocked (limit is 15)");
});

test("POST /api/auth/login is rate limited per IP, independently of signup", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  let last: Response | undefined;
  for (let i = 0; i < 16; i++) {
    last = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "nobody@example.com", password: "wrong" }),
    });
  }
  assert.equal(last!.status, 429, "the 16th login attempt within the window must be blocked (limit is 15)");
});

test("POST /api/auth/forgot-password: the per-email limiter trips before the per-IP one for repeated use of one address", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  let last: { status: number; body: any } | undefined;
  for (let i = 0; i < 6; i++) {
    const res = await fetch(`${base}/api/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "single-target@example.com" }),
    });
    last = { status: res.status, body: await res.json() };
  }
  assert.equal(last!.status, 429, "the 6th request for the same address must be blocked (per-email limit is 5)");
  assert.match(last!.body.error, /this address/i);
});

test("POST /api/auth/forgot-password: the per-IP limiter trips independently across many distinct addresses", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  let last: { status: number; body: any } | undefined;
  for (let i = 0; i < 16; i++) {
    // A distinct address each time, so the per-email limiter (cap 5) never
    // fires — only the per-IP limiter (cap 15) is exercised here.
    const res = await fetch(`${base}/api/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: `distinct-${i}@example.com` }),
    });
    last = { status: res.status, body: await res.json() };
  }
  assert.equal(last!.status, 429, "the 16th distinct address from one IP must be blocked (per-IP limit is 15)");
  assert.match(last!.body.error, /try again in a few minutes/i);
});

test("POST /api/auth/reset-password is rate limited per IP", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  let last: Response | undefined;
  for (let i = 0; i < 16; i++) {
    last = await fetch(`${base}/api/auth/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "not-a-real-token", password: PASSWORD }),
    });
  }
  assert.equal(last!.status, 429, "the 16th reset attempt within the window must be blocked (limit is 15)");
});

test("POST /api/scans: anonymous callers are limited by IP, and it does not affect a different, authenticated identity", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  // No file is attached, so a request that gets past the limiter fails fast
  // with a 400 from the handler rather than running a real scan — this test
  // is about the limiter's wiring and identity resolution, not scan
  // correctness (covered exhaustively elsewhere).
  async function anonymousAttempt() {
    return fetch(`${base}/api/scans`, { method: "POST", body: new FormData() });
  }

  let last: Response | undefined;
  for (let i = 0; i < 21; i++) last = await anonymousAttempt();
  assert.equal(last!.status, 429, "the 21st anonymous scan within the window must be blocked (limit is 20)");

  const alice = await createUser("rl-scan-alice@example.com", PASSWORD);
  const aliceToken = await createSession(alice.id);
  const aliceAttempt = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${aliceToken}` },
    body: new FormData(),
  });
  assert.notEqual(
    aliceAttempt.status,
    429,
    "an authenticated user must get her own bucket, not share the anonymous IP bucket that is now exhausted"
  );

  const bob = await createUser("rl-scan-bob@example.com", PASSWORD);
  const bobToken = await createSession(bob.id);
  const bobAttempt = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${bobToken}` },
    body: new FormData(),
  });
  assert.notEqual(
    bobAttempt.status,
    429,
    "two different authenticated users behind the same IP must not share a bucket " +
      "(the corporate-NAT / shared-CI-runner scenario)"
  );
});

test("POST /api/scans/repo is rate limited per account, ahead of the subscription check", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  const user = await createUser("rl-repo@example.com", PASSWORD);
  const token = await createSession(user.id);
  // No subscription on this account — every request will eventually 402 from
  // requireSubscription, UNLESS the limiter (mounted ahead of it) trips
  // first. Reaching 429 here proves the limiter really does run before the
  // paywall check, not after it.
  let last: Response | undefined;
  for (let i = 0; i < 11; i++) {
    last = await fetch(`${base}/api/scans/repo`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: "https://github.com/example/example" }),
    });
  }
  assert.equal(last!.status, 429, "the 11th repo-scan request within the window must be blocked (limit is 10)");
});

test("POST /api/events carries the configured, generous rate-limit headers", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  const user = await createUser("rl-events@example.com", PASSWORD);
  const project = await createProject(user.id, "Rate Limit Events Project");

  // 600/min is deliberately generous — this endpoint receives one call per
  // HTTP request a customer's own monitored app serves, so exhausting it in
  // a test would mean 601 real round trips for no additional coverage beyond
  // what the generic mechanics tests above already prove. Verifying the
  // configured limit is present on this specific route is what proves it is
  // actually wired here.
  const res = await fetch(`${base}/api/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-nettle-api-key": project.apiKey },
    body: JSON.stringify({ ip: "203.0.113.1", method: "GET", path: "/", statusCode: 200 }),
  });
  assert.equal(res.status, 202);
  assert.equal(res.headers.get("x-ratelimit-limit"), "600");
});

test("GET /api/projects/:id/badge.svg and badge.json are rate limited per IP, sharing one bucket", async (t) => {
  const { server, base } = await listen(buildFullApp());
  t.after(() => server.close());

  // A nonexistent project is fine here: the limiter runs before the project
  // lookup, so it still counts and still trips regardless of whether the
  // badge itself resolves.
  let last: Response | undefined;
  for (let i = 0; i < 61; i++) {
    // Alternate endpoints to prove they share one counter (a scripted client
    // hitting both must not effectively double its allowance).
    const path = i % 2 === 0 ? "badge.svg" : "badge.json";
    last = await fetch(`${base}/api/projects/nonexistent-project/${path}`);
  }
  assert.equal(last!.status, 429, "the 61st badge request within the window must be blocked (limit is 60)");
});
