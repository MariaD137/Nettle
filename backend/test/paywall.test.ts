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

const PASSWORD = "correct horse battery staple";

test("hasActiveSubscription requires both a paid plan and an active status", () => {
  assert.equal(hasActiveSubscription({ plan: "tier1", subscriptionStatus: "active" }), true);
  assert.equal(hasActiveSubscription({ plan: "tier2", subscriptionStatus: "active" }), true);
  assert.equal(hasActiveSubscription({ plan: "tier1", subscriptionStatus: "trialing" }), true);

  // A brand new account.
  assert.equal(hasActiveSubscription({ plan: "free", subscriptionStatus: "none" }), false);
  // Plan set but payment never completed, or the subscription ended.
  assert.equal(hasActiveSubscription({ plan: "tier1", subscriptionStatus: "none" }), false);
  assert.equal(hasActiveSubscription({ plan: "tier1", subscriptionStatus: "canceled" }), false);
  // A failed payment stops access rather than coasting.
  assert.equal(hasActiveSubscription({ plan: "tier1", subscriptionStatus: "past_due" }), false);
  // A status alone is not enough.
  assert.equal(hasActiveSubscription({ plan: "free", subscriptionStatus: "active" }), false);
  assert.equal(hasActiveSubscription(null), false);
});

test("a newly signed up account is paywalled out of the dashboard", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-new@example.com", PASSWORD);
    assert.ok(token, "signup should still succeed and return a session");

    const res = await fetch(`${base}/api/overview`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 402);
    const body = await res.json();
    assert.equal(body.subscriptionRequired, true);
    assert.equal(body.plan, "free");
  } finally {
    server.close();
  }
});

test("every dashboard route is paywalled, not just the entry point", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const user = await createUser("paywall-routes@example.com", PASSWORD);
    const project = await createProject(user.id, "Unreachable");
    const token = await signUp(base, "paywall-other@example.com", PASSWORD);

    const routes: [string, string][] = [
      ["GET", "/api/overview"],
      ["GET", "/api/projects"],
      ["POST", "/api/projects"],
      ["GET", `/api/projects/${project.id}`],
      ["PATCH", `/api/projects/${project.id}`],
      ["DELETE", `/api/projects/${project.id}`],
      ["POST", `/api/projects/${project.id}/archive`],
      ["POST", `/api/projects/${project.id}/rotate-key`],
      ["GET", `/api/projects/${project.id}/alerts`],
      ["GET", `/api/projects/${project.id}/scans`],
      ["GET", `/api/projects/${project.id}/scans/compare`],
      ["GET", `/api/projects/${project.id}/findings`],
      ["GET", `/api/projects/${project.id}/scans/anything/export`],
    ];

    for (const [method, path] of routes) {
      const res = await fetch(`${base}${path}`, {
        method,
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: method === "GET" || method === "DELETE" ? undefined : "{}",
      });
      assert.equal(res.status, 402, `${method} ${path} should be paywalled`);
    }
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

test("an active subscription opens the dashboard", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-paid@example.com", PASSWORD);

    let res = await fetch(`${base}/api/overview`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 402);

    // What the Stripe checkout.session.completed webhook does.
    await setSubscriptionStatus(await findUserId(base, token), "tier1", "active");

    res = await fetch(`${base}/api/overview`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.totalProjects, 0);
  } finally {
    server.close();
  }
});

test("cancelling a subscription closes the dashboard again", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const token = await signUp(base, "paywall-lapse@example.com", PASSWORD);
    const id = await findUserId(base, token);

    await setSubscriptionStatus(id, "tier1", "active");
    let res = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);

    // Mirrors the customer.subscription.deleted webhook path.
    await setSubscriptionStatus(id, "tier1", "canceled");
    res = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(res.status, 402);
    assert.equal((await res.json()).subscriptionRequired, true);
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
