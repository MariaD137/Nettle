import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { scansRouter } from "../src/routes/scans.routes";
import { authRouter } from "../src/routes/auth.routes";
import { limiter, apiRateLimit } from "../src/middleware/rateLimit";
import { optionalAuth } from "../src/auth/middleware";

// Regression coverage for a real bug: index.ts used to mount scanRateLimit
// and publicRateLimit the same way `app.use(limiter, router)` mounts any
// middleware — at the default "/" path. Express runs middleware mounted
// that way for EVERY request that reaches it, regardless of whether the
// router that follows would actually handle the path — so scanRateLimit's
// 30-requests/60s budget (meant only for scan submissions) was being
// consumed by literally every API call in the app, including something as
// unrelated as GET /api/auth/me. A user just browsing the dashboard could
// exhaust it and start seeing "Too many scan requests" on pages that never
// touch scanning at all. Fixed by attaching scanRateLimit/publicRateLimit
// only to the specific routes that need them (scans.routes.ts,
// scanJobs.routes.ts, events.routes.ts, badge.routes.ts), the same way
// auth.routes.ts already scopes its own authLimiter.

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
  // Mirrors index.ts's real mounting: no rate limiter wrapped around
  // either router at the app level.
  app.use(scansRouter);
  app.use(authRouter);
  return app;
}

test("scanRateLimit's budget is not consumed by unrelated requests", async () => {
  (limiter as unknown as { store: Record<string, unknown> }).store = {};

  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("ratelimit-scoping@example.com", "correct horse battery staple");
    const token = createSession(user.id);

    // Comfortably more than scanRateLimit's 30/60s budget, all against a
    // route scanRateLimit must never touch.
    for (let i = 0; i < 40; i++) {
      const res = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(res.status, 200, `request ${i + 1} to /api/auth/me must not be rate-limited by the scan budget`);
    }
  } finally {
    server.close();
  }
});

test("scanRateLimit still applies to the scan routes it's meant for", async () => {
  (limiter as unknown as { store: Record<string, unknown> }).store = {};

  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("ratelimit-scan-real@example.com", "correct horse battery staple");
    setSubscriptionStatus(user.id, "tier1", "active");
    const token = createSession(user.id);

    // An invalid repoUrl fails validation fast (400) without doing any
    // real cloning/scanning work, but scanRateLimit runs before that
    // validation, so the count still climbs — a cheap way to reach 31
    // real requests against a genuine scan-submission route.
    let sawRateLimited = false;
    for (let i = 0; i < 31; i++) {
      const res = await fetch(`${base}/api/scans/repo`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: "not-a-valid-url" }),
      });
      if (res.status === 429) {
        sawRateLimited = true;
        break;
      }
      assert.equal(res.status, 400);
    }
    assert.ok(sawRateLimited, "scanRateLimit should still kick in on the 31st real scan-submission request");
  } finally {
    server.close();
  }
});

// Regression coverage for M-1: RateLimiter.getKey() used to read
// `(req as any).user?.id`, a property nothing in this codebase ever sets
// (only req.userId exists) — so it silently fell back to req.ip for every
// request, meaning two different authenticated accounts sharing an IP
// (a NAT'd office, a shared proxy — or, as here, two callers hitting the
// same test server, which is indistinguishable from that case at the IP
// level) shared ONE rate-limit budget instead of getting one each.
test("two different authenticated users sharing the same client IP get independent scanRateLimit budgets", async () => {
  (limiter as unknown as { store: Record<string, unknown> }).store = {};

  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const userA = await createUser("ratelimit-peruser-a@example.com", "correct horse battery staple");
    setSubscriptionStatus(userA.id, "tier1", "active");
    const tokenA = createSession(userA.id);

    const userB = await createUser("ratelimit-peruser-b@example.com", "correct horse battery staple");
    setSubscriptionStatus(userB.id, "tier1", "active");
    const tokenB = createSession(userB.id);

    // Every request in this test goes to the same loopback test server, so
    // both users share the same req.ip — the only thing that can still
    // separate their budgets is being keyed by req.userId.
    for (let i = 0; i < 30; i++) {
      const res = await fetch(`${base}/api/scans/repo`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenA}`, "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: "not-a-valid-url" }),
      });
      assert.equal(res.status, 400, `user A's request ${i + 1}/30 should not be rate-limited yet`);
    }

    // User A is now at their 30/30 budget. If keying were still per-IP,
    // this next request — a completely different account — would already
    // be rate-limited too.
    const userBFirstRequest = await fetch(`${base}/api/scans/repo`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenB}`, "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: "not-a-valid-url" }),
    });
    assert.equal(userBFirstRequest.status, 400, "user B must have their own, untouched rate-limit budget");

    // And user A's own next request should now be the one that's limited.
    const userANextRequest = await fetch(`${base}/api/scans/repo`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenA}`, "Content-Type": "application/json" },
      body: JSON.stringify({ repoUrl: "not-a-valid-url" }),
    });
    assert.equal(userANextRequest.status, 429, "user A should be rate-limited on their own 31st request");
  } finally {
    server.close();
  }
});

test("an unauthenticated caller still gets a real per-IP rate limit (falls back correctly, isn't left unlimited)", async () => {
  (limiter as unknown as { store: Record<string, unknown> }).store = {};

  const app = express();
  app.use(express.json());
  app.use(optionalAuth);
  app.use(apiRateLimit);
  app.use(authRouter);
  const { server, base } = await listen(app);
  try {
    let sawRateLimited = false;
    for (let i = 0; i < 501; i++) {
      // /api/auth/me with no Authorization header is a cheap, unauthenticated
      // request that still passes through the real apiRateLimit middleware.
      const res = await fetch(`${base}/api/auth/me`);
      if (res.status === 429) {
        sawRateLimited = true;
        break;
      }
      assert.equal(res.status, 401);
    }
    assert.ok(sawRateLimited, "an unauthenticated caller must still be rate-limited by IP, not left unbounded");
  } finally {
    server.close();
  }
});
