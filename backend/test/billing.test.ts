import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { billingRouter, billingWebhookRouter } from "../src/routes/billing.routes";
import { authRouter } from "../src/routes/auth.routes";
import { createUser, getUserById, setSubscriptionStatus } from "../src/auth/users";
import { __setStripeClientForTesting } from "../src/billing/stripeClient";
import type Stripe from "stripe";

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

test("checkout-session refuses to create a second subscription for an already-active account", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_PRICE_TIER1 = "price_tier1_fake";
  process.env.STRIPE_PRICE_TIER2 = "price_tier2_fake";

  const user = await createUser("already-subscribed@example.com", "correct horse battery staple");
  setSubscriptionStatus(user.id, "tier1", "active");

  const { server, base } = await listen(buildApp());
  try {
    const login = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "already-subscribed@example.com", password: "correct horse battery staple" }),
    });
    const { token } = await login.json();

    const res = await fetch(`${base}/api/billing/checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ plan: "tier2" }),
    });
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.alreadySubscribed, true);
  } finally {
    server.close();
  }
});

function buildSubscriptionEvent(overrides: {
  id: string;
  type: "customer.subscription.updated" | "customer.subscription.deleted";
  customer: string;
  status: string;
  priceId: string;
  created: number;
}) {
  return JSON.stringify({
    id: overrides.id,
    object: "event",
    api_version: "2025-01-01",
    created: overrides.created,
    type: overrides.type,
    data: {
      object: {
        id: "sub_test_123",
        object: "subscription",
        customer: overrides.customer,
        status: overrides.status,
        items: { data: [{ price: { id: overrides.priceId } }] },
      },
    },
  });
}

test("customer.subscription.updated derives the plan from the event's price, not the stale DB plan", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_TIER1 = "price_tier1_fake";
  process.env.STRIPE_PRICE_TIER2 = "price_tier2_fake";

  const user = await createUser("plan-drift@example.com", "correct horse battery staple");
  setSubscriptionStatus(user.id, "tier1", "active");
  // Simulate the checkout webhook having already attached a Stripe customer.
  const { setStripeCustomerId } = await import("../src/auth/users");
  setStripeCustomerId(user.id, "cus_plan_drift");

  // The subscription was changed to tier2 outside this app's own checkout
  // flow (e.g. the Stripe dashboard) — the event carries the tier2 price,
  // even though our DB still says "tier1".
  const payload = buildSubscriptionEvent({
    id: "evt_plan_drift",
    type: "customer.subscription.updated",
    customer: "cus_plan_drift",
    status: "active",
    priceId: "price_tier2_fake",
    created: Math.floor(Date.now() / 1000),
  });

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
      body: payload,
    });
    assert.equal(res.status, 200);

    const updated = getUserById(user.id)!;
    assert.equal(updated.plan, "tier2", "plan should follow the event's price, not the stale DB value");
  } finally {
    server.close();
  }
});

test("a duplicate webhook delivery (same event.id) is only applied once", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("dup-webhook@example.com", "correct horse battery staple");

  const payload = JSON.stringify({
    id: "evt_dup_test",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: {
      object: {
        id: "cs_dup_test",
        object: "checkout.session",
        customer: "cus_dup_test",
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
    assert.equal(getUserById(user.id)!.subscriptionStatus, "active");

    // Simulate Stripe retrying the exact same delivery.
    const second = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signature },
      body: payload,
    });
    assert.equal(second.status, 200);
    const secondBody = await second.json();
    assert.equal(secondBody.duplicate, true);
  } finally {
    server.close();
  }
});

test("an out-of-order webhook event cannot resurrect an already-cancelled subscription", async () => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_TIER1 = "price_tier1_fake";
  process.env.STRIPE_PRICE_TIER2 = "price_tier2_fake";

  const user = await createUser("out-of-order@example.com", "correct horse battery staple");
  const { setStripeCustomerId } = await import("../src/auth/users");
  setStripeCustomerId(user.id, "cus_out_of_order");

  const now = Math.floor(Date.now() / 1000);
  const cancelledEvent = buildSubscriptionEvent({
    id: "evt_cancelled",
    type: "customer.subscription.deleted",
    customer: "cus_out_of_order",
    status: "canceled",
    priceId: "price_tier1_fake",
    created: now, // the newer event
  });
  const staleActiveEvent = buildSubscriptionEvent({
    id: "evt_stale_active",
    type: "customer.subscription.updated",
    customer: "cus_out_of_order",
    status: "active",
    priceId: "price_tier1_fake",
    created: now - 60, // delivered late, but timestamped earlier
  });

  const { server, base } = await listen(buildApp());
  try {
    // The cancellation lands first...
    const cancelRes = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(cancelledEvent, webhookSecret) },
      body: cancelledEvent,
    });
    assert.equal(cancelRes.status, 200);
    assert.equal(getUserById(user.id)!.subscriptionStatus, "canceled");

    // ...then the older "active" event arrives late, out of order.
    const staleRes = await fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Stripe-Signature": signStripePayload(staleActiveEvent, webhookSecret),
      },
      body: staleActiveEvent,
    });
    assert.equal(staleRes.status, 200);

    // Must still be cancelled — the stale event must not have reapplied.
    assert.equal(getUserById(user.id)!.subscriptionStatus, "canceled");
  } finally {
    server.close();
  }
});

test("deleting an account cancels its live Stripe subscription first", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";

  const user = await createUser("delete-cancels-sub@example.com", "correct horse battery staple");
  const { setStripeCustomerId, deleteUser, getUserById: lookupUser } = await import("../src/auth/users");
  setStripeCustomerId(user.id, "cus_delete_test");

  const cancelledIds: string[] = [];
  const fakeStripe = {
    subscriptions: {
      list: async () => ({
        data: [
          { id: "sub_active_1", status: "active" },
          { id: "sub_already_canceled", status: "canceled" },
        ],
      }),
      cancel: async (id: string) => {
        cancelledIds.push(id);
        return {};
      },
    },
  } as unknown as Stripe;

  __setStripeClientForTesting(fakeStripe);
  try {
    await deleteUser(user.id);
  } finally {
    __setStripeClientForTesting(null);
  }

  assert.deepEqual(cancelledIds, ["sub_active_1"], "only the still-active subscription should be cancelled");
  assert.equal(lookupUser(user.id), null, "the account should be deleted");
});

test("account deletion is not lost if the Stripe cancellation call fails", async () => {
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";

  const user = await createUser("delete-fails-sub@example.com", "correct horse battery staple");
  const { setStripeCustomerId, deleteUser, getUserById: lookupUser } = await import("../src/auth/users");
  setStripeCustomerId(user.id, "cus_delete_fail_test");

  const fakeStripe = {
    subscriptions: {
      list: async () => {
        throw new Error("Stripe API unreachable");
      },
      cancel: async () => ({}),
    },
  } as unknown as Stripe;

  __setStripeClientForTesting(fakeStripe);
  try {
    await assert.rejects(() => deleteUser(user.id), /unreachable/);
  } finally {
    __setStripeClientForTesting(null);
  }

  // The account must still exist — deleting it locally while Stripe billing
  // stays live would be worse than leaving it in place for a retry.
  assert.notEqual(lookupUser(user.id), null, "the account should not be deleted when cancellation fails");
});
