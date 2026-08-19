import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { scansRouter } from "../src/routes/scans.routes";
import { authRouter } from "../src/routes/auth.routes";
import { limiter } from "../src/middleware/rateLimit";

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
