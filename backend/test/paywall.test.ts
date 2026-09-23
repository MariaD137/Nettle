import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { projectsRouter } from "../src/routes/projects.routes";
import { authRouter } from "../src/routes/auth.routes";
import { badgeRouter } from "../src/routes/badge.routes";
import { hasActiveSubscription } from "../src/billing/subscription";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

// Mount order mirrors src/index.ts exactly, projectsRouter ahead of
// authRouter and badgeRouter. That ordering matters: projectsRouter is
// mounted at the app root, so anything it registers as bare middleware would
// intercept requests meant for the routers behind it. Building the test app
// in a friendlier order than production would hide precisely that bug.
function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  app.use(authRouter);
  app.use(badgeRouter);
  return app;
}

async function signUp(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return (await res.json()).token;
}

async function login(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return (await res.json()).token;
}

const PASSWORD = "correct horse battery staple";

test("hasActiveSubscription requires both a paid plan and an active status", () => {
  assert.equal(hasActiveSubscription({ plan: "build", subscriptionStatus: "active" }), true);
  assert.equal(hasActiveSubscription({ plan: "protect", subscriptionStatus: "active" }), true);
  assert.equal(hasActiveSubscription({ plan: "build", subscriptionStatus: "trialing" }), true);

  // A brand new account.
  assert.equal(hasActiveSubscription({ plan: "free", subscriptionStatus: "none" }), false);
  // Plan set but payment never completed, or the subscription ended.
  assert.equal(hasActiveSubscription({ plan: "build", subscriptionStatus: "none" }), false);
  assert.equal(hasActiveSubscription({ plan: "build", subscriptionStatus: "canceled" }), false);
  // A failed payment stops access rather than coasting.
  assert.equal(hasActiveSubscription({ plan: "build", subscriptionStatus: "past_due" }), false);
  // A status alone is not enough.
  assert.equal(hasActiveSubscription({ plan: "free", subscriptionStatus: "active" }), false);
  assert.equal(hasActiveSubscription(null), false);
});

// FREE is a real, usable dashboard tier now (pricing rework — see
// billing/entitlements.ts): a signed-up account with no subscription can
// reach the dashboard itself. What actually requires BUILD/PROTECT is real
// scan execution and the BUILD+/PROTECT-only routes covered below.
test("a newly signed up FREE account can reach the dashboard, with FREE-shaped limits", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-new@example.com", PASSWORD);
    assert.ok(token, "signup should still succeed and return a session");

    const res = await fetch(`${base}/api/overview`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.totalProjects, 0);
    assert.equal(body.quota.limit, 0, "FREE has no scan allowance at all");
  } finally {
    server.close();
  }
});

test("basic project management is open to every signed-in account, FREE included", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-free-crud@example.com", PASSWORD);

    const createRes = await fetch(`${base}/api/projects`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "My First Project" }),
    });
    assert.equal(createRes.status, 201, "FREE gets its one project");
    const project = await createRes.json();

    const listRes = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(listRes.status, 200);

    const detailRes = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(detailRes.status, 200);
    const detail = await detailRes.json();
    assert.equal(detail.latestScan, null, "FREE never has Fix Center content — no scan ever ran");

    // A second project is over FREE's limit of 1.
    const secondRes = await fetch(`${base}/api/projects`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Second Project" }),
    });
    assert.equal(secondRes.status, 403);
    assert.equal((await secondRes.json()).projectLimitReached, true);
  } finally {
    server.close();
  }
});

test("BUILD+ routes stay paywalled behind a real subscription", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const user = await createUser("paywall-routes@example.com", PASSWORD);
    const project = await createProject(user.id, "Unreachable");
    const ownerToken = await login(base, "paywall-routes@example.com", PASSWORD);

    const routes: [string, string][] = [
      ["GET", `/api/projects/${project.id}/scans`],
      ["GET", `/api/projects/${project.id}/scans/compare`],
      ["GET", `/api/projects/${project.id}/findings`],
      ["GET", `/api/projects/${project.id}/scans/anything/export`],
    ];

    // The project's own owner, still on FREE (never subscribed) — the
    // actual paywall case: reachable, but not entitled.
    for (const [method, path] of routes) {
      const res = await fetch(`${base}${path}`, {
        method,
        headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
      });
      assert.equal(res.status, 402, `${method} ${path} should stay paywalled behind BUILD/PROTECT`);
    }

    // A total stranger — not the owner, not an organization member — gets
    // 404, not 402: requireProjectPlan (billing/orgSubscription.ts) checks
    // accessibility before entitlement, same "don't confirm the project
    // exists to someone with no relationship to it" rule accessibleProjectOr404
    // already applies to every other project route.
    const strangerToken = await signUp(base, "paywall-other@example.com", PASSWORD);
    const strangerRes = await fetch(`${base}${routes[0][1]}`, {
      headers: { Authorization: `Bearer ${strangerToken}` },
    });
    assert.equal(strangerRes.status, 404);
  } finally {
    server.close();
  }
});

test("PROTECT-only routes (continuous monitoring's alerts) reject a FREE or BUILD caller", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const user = await createUser("paywall-alerts-owner@example.com", PASSWORD);
    const project = await createProject(user.id, "Alert Target");
    const ownerToken = await login(base, "paywall-alerts-owner@example.com", PASSWORD);

    // The project's own owner, still FREE — the real paywall case.
    const freeRes = await fetch(`${base}/api/projects/${project.id}/alerts`, {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    assert.equal(freeRes.status, 402);
    assert.equal((await freeRes.json()).requiredPlan, "protect");

    // Same owner, upgraded to BUILD — still not enough, alerts need PROTECT specifically.
    await setSubscriptionStatus(user.id, "build", "active");
    const buildToken = await login(base, "paywall-alerts-owner@example.com", PASSWORD);
    const buildRes = await fetch(`${base}/api/projects/${project.id}/alerts`, {
      headers: { Authorization: `Bearer ${buildToken}` },
    });
    assert.equal(buildRes.status, 402, "BUILD alone is not enough — alerts need PROTECT specifically");

    // A total stranger gets 404, not 402 — see the equivalent case in
    // "BUILD+ routes stay paywalled behind a real subscription" above.
    const strangerToken = await signUp(base, "paywall-alerts-stranger@example.com", PASSWORD);
    const strangerRes = await fetch(`${base}/api/projects/${project.id}/alerts`, {
      headers: { Authorization: `Bearer ${strangerToken}` },
    });
    assert.equal(strangerRes.status, 404);
  } finally {
    server.close();
  }
});

test("the paywall does not mask a missing session — unauthenticated still 401s", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/overview`);
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("an active subscription opens the BUILD+ routes", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-paid@example.com", PASSWORD);
    const userId = await findUserId(base, token);
    const project = await createProject(userId, "Paid Project");

    let res = await fetch(`${base}/api/projects/${project.id}/scans`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 402);

    // What the Stripe checkout.session.completed webhook does.
    await setSubscriptionStatus(userId, "build", "active");

    res = await fetch(`${base}/api/projects/${project.id}/scans`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
  } finally {
    server.close();
  }
});

test("cancelling a subscription closes the BUILD+ routes again, but not the dashboard itself", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-lapse@example.com", PASSWORD);
    const id = await findUserId(base, token);
    const project = await createProject(id, "Lapsing Project");

    await setSubscriptionStatus(id, "build", "active");
    let res = await fetch(`${base}/api/projects/${project.id}/scans`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);

    // Mirrors the customer.subscription.deleted webhook path.
    await setSubscriptionStatus(id, "build", "canceled");
    res = await fetch(`${base}/api/projects/${project.id}/scans`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 402);
    assert.equal((await res.json()).subscriptionRequired, true);

    // The dashboard itself (basic project access) stays open — data is
    // preserved on downgrade, never walled off entirely.
    res = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
  } finally {
    server.close();
  }
});

// The two routes that must stay reachable with the paywall in place. Both sit
// behind projectsRouter in the mount order, and one shares its URL prefix, so
// a carelessly scoped gate takes them out — which is exactly what happened
// the first time this was written.
test("the paywall does not swallow signup or login", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "paywall-reachable@example.com", password: PASSWORD }),
    });
    assert.equal(res.status, 201, "signup must not be intercepted by the paywall");
    assert.ok((await res.json()).token);
  } finally {
    server.close();
  }
});

test("public trust badges stay readable without auth or a subscription", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const user = await createUser("paywall-badge@example.com", PASSWORD);
    const project = await createProject(user.id, "Badged");

    // No Authorization header at all — this is an <img> tag on someone's site.
    const res = await fetch(`${base}/api/projects/${project.id}/badge.svg`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /svg/);
  } finally {
    server.close();
  }
});

async function findUserId(base: string, token: string): Promise<string> {
  const res = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  return (await res.json()).user.id;
}
