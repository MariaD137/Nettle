import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { billingRouter, billingWebhookRouter } from "../src/routes/billing.routes";
import { authRouter } from "../src/routes/auth.routes";
import { createUser, getUserById, setStripeCustomerId, setSubscriptionStatus } from "../src/auth/users";
import { getPaymentFailures } from "../src/billing/stripeEvents";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(billingWebhookRouter); // must precede express.json(), same reasoning as index.ts
  app.use(express.json());
  app.use(authRouter);
  app.use(billingRouter);
  return app;
}

// Mirrors Stripe's actual webhook signing scheme (HMAC-SHA256 over
// "<timestamp>.<payload>"), so this is real signature verification against
// our own handler — not a mocked check — with no network call involved.
function signStripePayload(payload: string, secret: string, timestamp = Math.floor(Date.now() / 1000)) {
  const signedPayload = `${timestamp}.${payload}`;
  const signature = crypto.createHmac("sha256", secret).update(signedPayload).digest("hex");
  return `t=${timestamp},v1=${signature}`;
}

test("checkout-session requires auth", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/billing/checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plan: "tier1" }),
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("checkout-session returns 503 (not a crash) when billing isn't configured", async () => {
  delete process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_PRICE_TIER1;

  const { server, base } = await listen(buildApp());
  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "billing-unconfigured@example.com", password: "correct horse battery staple" }),
    });
    const { token } = await signup.json();

    const res = await fetch(`${base}/api/billing/checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ plan: "tier1" }),
    });
    assert.equal(res.status, 503);
  } finally {
    server.close();
  }
});

test("checkout-session rejects an unknown plan", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  const { server, base } = await listen(buildApp());
  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "billing-badplan@example.com", password: "correct horse battery staple" }),
    });
    const { token } = await signup.json();

    const res = await fetch(`${base}/api/billing/checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ plan: "enterprise-super-plan" }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("webhook rejects a request with no signature header", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "checkout.session.completed" }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("webhook rejects a signature that doesn't match the payload", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_for_local_tests_only";

  const { server, base } = await listen(buildApp());
  try {
    const payload = JSON.stringify({ id: "evt_fake", type: "checkout.session.completed", data: { object: {} } });
    const res = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": "t=1,v1=deadbeef" },
      body: payload,
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("a genuinely, correctly-signed checkout.session.completed webhook activates the user's plan", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("webhook-activates@example.com", "correct horse battery staple");
  assert.equal(getUserById(user.id)!.subscriptionStatus, "none");

  const payload = JSON.stringify({
    id: "evt_test_123",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: {
      object: {
        id: "cs_test_123",
        object: "checkout.session",
        customer: "cus_test_123",
        metadata: { userId: user.id, plan: "tier1" },
      },
    },
  });

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
      body: payload,
    });
    assert.equal(res.status, 200, JSON.stringify(await res.json()));

    const updated = getUserById(user.id)!;
    assert.equal(updated.subscriptionStatus, "active");
    assert.equal(updated.plan, "tier1");
    assert.equal(updated.stripeCustomerId, "cus_test_123");
  } finally {
    server.close();
  }
});

test("redelivering the same event id is a no-op the second time", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("webhook-redelivery@example.com", "correct horse battery staple");

  const payload = JSON.stringify({
    id: "evt_redelivery_test",
    object: "event",
    type: "checkout.session.completed",
    data: {
      object: {
        id: "cs_redelivery_test",
        object: "checkout.session",
        customer: "cus_redelivery_test",
        metadata: { userId: user.id, plan: "tier1" },
      },
    },
  });
  const signature = signStripePayload(payload, webhookSecret);

  const { server, base } = await listen(buildApp());
  try {
    const first = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signature },
      body: payload,
    });
    assert.equal(first.status, 200);
    assert.equal((await first.json()).duplicate, undefined);

    // Stripe would recompute a fresh, valid signature for a genuine
    // redelivery of the same event id — reuse the same one here since it's
    // still valid for this exact payload.
    const second = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signature },
      body: payload,
    });
    assert.equal(second.status, 200);
    assert.equal((await second.json()).duplicate, true);
  } finally {
    server.close();
  }
});

test("a genuinely, correctly-signed invoice.payment_failed webhook marks the user past_due and records the failure", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("payment-failed@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_payment_failed_test");
  setSubscriptionStatus(user.id, "tier1", "active");

  const payload = JSON.stringify({
    id: "evt_payment_failed_test",
    object: "event",
    type: "invoice.payment_failed",
    data: {
      object: {
        id: "in_test_123",
        object: "invoice",
        customer: "cus_payment_failed_test",
        amount_due: 4900,
        currency: "usd",
      },
    },
  });

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
      body: payload,
    });
    assert.equal(res.status, 200, JSON.stringify(await res.json()));

    const updated = getUserById(user.id)!;
    assert.equal(updated.subscriptionStatus, "past_due");
    assert.equal(updated.plan, "tier1");

    const failures = getPaymentFailures(user.id);
    assert.equal(failures.length, 1);
    assert.equal(failures[0].stripeInvoiceId, "in_test_123");
    assert.equal(failures[0].amountDue, 4900);
  } finally {
    server.close();
  }
});

test("portal-session requires auth", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/billing/portal-session`, { method: "POST" });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("portal-session returns 400 for a user with no Stripe customer yet", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "portal-no-customer@example.com", password: "correct horse battery staple" }),
    });
    const { token } = await signup.json();

    const res = await fetch(`${base}/api/billing/portal-session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});
