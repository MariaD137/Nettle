import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { authRouter } from "../src/routes/auth.routes";
import { createUser, completeOnboarding } from "../src/auth/users";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, base: `http://localhost:${port}` });
    });
  });
}

const PASSWORD = "correct horse battery staple";

test("a newly created account has not completed onboarding", async () => {
  const user = await createUser("onboarding-new@example.com", PASSWORD);
  assert.equal(user.onboardingCompletedAt, null);
});

test("completeOnboarding stamps a timestamp and is idempotent", async () => {
  const user = await createUser("onboarding-complete@example.com", PASSWORD);
  assert.equal(user.onboardingCompletedAt, null);

  const first = completeOnboarding(user.id);
  assert.ok(first?.onboardingCompletedAt);

  // Calling it again must not move the timestamp forward — completion is
  // stamped once, the same way the billing anchor is.
  const second = completeOnboarding(user.id);
  assert.equal(second?.onboardingCompletedAt, first?.onboardingCompletedAt);
});

test("full HTTP flow: signup returns onboardingCompletedAt: null, completing it persists across /me", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const signupRes = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "onboarding-http@example.com", password: PASSWORD }),
    });
    const { token, user } = await signupRes.json();
    assert.equal(user.onboardingCompletedAt, null);

    const completeRes = await fetch(`${base}/api/auth/onboarding/complete`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(completeRes.status, 200);
    const { user: completed } = await completeRes.json();
    assert.ok(completed.onboardingCompletedAt);

    const meRes = await fetch(`${base}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const { user: fetched } = await meRes.json();
    assert.equal(fetched.onboardingCompletedAt, completed.onboardingCompletedAt);
  } finally {
    server.close();
  }
});

test("completing onboarding without a session is rejected", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const res = await fetch(`${base}/api/auth/onboarding/complete`, { method: "POST" });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});
