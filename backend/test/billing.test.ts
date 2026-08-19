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

// Regression coverage for M-2: the old check-then-mark idempotency had a
// real TOCTOU window between isStripeEventProcessed() (a SELECT) and
// markStripeEventProcessed() (an INSERT, only called after every side
// effect finished) — including an `await sendEmail(...)` in between for
// invoice.payment_failed specifically. Two genuinely concurrent requests
// for the same event id (fired together via Promise.all against a real
// listening server, not sequentially) exercise that exact window. With the
// old code this reliably produced two payment_failures rows and two
// emails; with claimStripeEvent()'s atomic INSERT-first claim, only one
// request's side effects should ever run.
test("two genuinely concurrent deliveries of the same event id produce side effects exactly once, not twice", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("webhook-concurrent-race@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_concurrent_race_test");
  setSubscriptionStatus(user.id, "tier1", "active");

  const payload = JSON.stringify({
    id: "evt_concurrent_race_test",
    object: "event",
    type: "invoice.payment_failed",
    data: {
      object: {
        id: "in_concurrent_race_test",
        object: "invoice",
        customer: "cus_concurrent_race_test",
        amount_due: 4900,
        currency: "usd",
      },
    },
  });
  const signature = signStripePayload(payload, webhookSecret);

  const { server, base } = await listen(buildApp());
  try {
    // Fired together, not awaited one at a time — both requests' handlers
    // are in flight simultaneously and will both reach their internal
    // `await sendEmail(...)` before either one's claim/side-effects have
    // necessarily resolved from the other's perspective.
    const [first, second] = await Promise.all([
      fetch(`${base}/api/billing/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Stripe-Signature": signature },
        body: payload,
      }),
      fetch(`${base}/api/billing/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Stripe-Signature": signature },
        body: payload,
      }),
    ]);

    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    const [firstBody, secondBody] = await Promise.all([first.json(), second.json()]);
    // Exactly one of the two must have lost the race and been told it's a
    // duplicate; the other genuinely processed it.
    const duplicateCount = [firstBody, secondBody].filter((b) => b.duplicate === true).length;
    assert.equal(duplicateCount, 1, "exactly one of the two concurrent requests should see duplicate:true");

    const failures = getPaymentFailures(user.id);
    assert.equal(failures.length, 1, "the side effect (a payment_failures row) must be recorded exactly once, not twice");
  } finally {
    server.close();
  }
});

test("customer.subscription.updated re-derives the plan from Stripe's own price on an upgrade", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_TIER1 = "price_test_tier1";
  process.env.STRIPE_PRICE_TIER2 = "price_test_tier2";

  const user = await createUser("webhook-upgrade@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_upgrade_test");
  setSubscriptionStatus(user.id, "tier1", "active");

  const payload = JSON.stringify({
    id: "evt_upgrade_test",
    object: "event",
    type: "customer.subscription.updated",
    data: {
      object: {
        id: "sub_upgrade_test",
        object: "subscription",
        customer: "cus_upgrade_test",
        status: "active",
        items: { object: "list", data: [{ id: "si_1", price: { id: "price_test_tier2" } }] },
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
    // The stored plan must reflect the subscription's actual current price
    // (tier2), not the plan it was on before the portal upgrade.
    assert.equal(updated.plan, "tier2");
    assert.equal(updated.subscriptionStatus, "active");
  } finally {
    server.close();
  }
});

test("customer.subscription.updated re-derives the plan from Stripe's own price on a downgrade", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_TIER1 = "price_test_tier1";
  process.env.STRIPE_PRICE_TIER2 = "price_test_tier2";

  const user = await createUser("webhook-downgrade@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_downgrade_test");
  setSubscriptionStatus(user.id, "tier2", "active");

  const payload = JSON.stringify({
    id: "evt_downgrade_test",
    object: "event",
    type: "customer.subscription.updated",
    data: {
      object: {
        id: "sub_downgrade_test",
        object: "subscription",
        customer: "cus_downgrade_test",
        status: "active",
        items: { object: "list", data: [{ id: "si_1", price: { id: "price_test_tier1" } }] },
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
    // This is the exact bug the fix closes: without re-deriving plan from
    // Stripe's price, this would still read "tier2" here, keeping Tier 2
    // scan quota and full-report access after the customer downgraded.
    assert.equal(updated.plan, "tier1");
    assert.equal(updated.subscriptionStatus, "active");
  } finally {
    server.close();
  }
});

test("customer.subscription.deleted resets the plan to free, not just the status to canceled", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("webhook-cancel@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_cancel_test");
  setSubscriptionStatus(user.id, "tier2", "active");

  const payload = JSON.stringify({
    id: "evt_cancel_test",
    object: "event",
    type: "customer.subscription.deleted",
    data: {
      object: {
        id: "sub_cancel_test",
        object: "subscription",
        customer: "cus_cancel_test",
        status: "canceled",
        items: { object: "list", data: [{ id: "si_1", price: { id: "price_test_tier2" } }] },
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
    // A canceled subscription must not leave a stale "tier2" sitting on the
    // account forever — the product's cancellation policy is that paid
    // access ends, and the stored plan should say so.
    assert.equal(updated.plan, "free");
    assert.equal(updated.subscriptionStatus, "canceled");
  } finally {
    server.close();
  }
});

test("customer.subscription.updated with a terminal status (incomplete_expired) also resets the plan to free", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("webhook-incomplete-expired@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_incomplete_expired_test");
  setSubscriptionStatus(user.id, "tier1", "active");

  const payload = JSON.stringify({
    id: "evt_incomplete_expired_test",
    object: "event",
    type: "customer.subscription.updated",
    data: {
      object: {
        id: "sub_incomplete_expired_test",
        object: "subscription",
        customer: "cus_incomplete_expired_test",
        status: "incomplete_expired",
        items: { object: "list", data: [{ id: "si_1", price: { id: "price_test_tier1" } }] },
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
    assert.equal(updated.plan, "free");
    assert.equal(updated.subscriptionStatus, "incomplete_expired");
  } finally {
    server.close();
  }
});

test("customer.subscription.updated with a non-terminal status (past_due) preserves the derived plan but is not access-granting", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_TIER1 = "price_test_tier1";
  process.env.STRIPE_PRICE_TIER2 = "price_test_tier2";

  const user = await createUser("webhook-subscription-pastdue@example.com", "correct horse battery staple");
  setStripeCustomerId(user.id, "cus_subscription_pastdue_test");
  setSubscriptionStatus(user.id, "tier1", "active");

  const payload = JSON.stringify({
    id: "evt_subscription_pastdue_test",
    object: "event",
    type: "customer.subscription.updated",
    data: {
      object: {
        id: "sub_subscription_pastdue_test",
        object: "subscription",
        customer: "cus_subscription_pastdue_test",
        status: "past_due",
        items: { object: "list", data: [{ id: "si_1", price: { id: "price_test_tier1" } }] },
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
    assert.equal(updated.plan, "tier1");
    assert.equal(updated.subscriptionStatus, "past_due");
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
