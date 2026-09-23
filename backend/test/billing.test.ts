import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { billingRouter, billingWebhookRouter } from "../src/routes/billing.routes";
import { authRouter } from "../src/routes/auth.routes";
import { createUser, getUserById, setSubscriptionStatus } from "../src/auth/users";

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
      body: JSON.stringify({ plan: "build" }),
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("checkout-session returns 503 (not a crash) when billing isn't configured", async () => {
  delete process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_PRICE_BUILD;

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
      body: JSON.stringify({ plan: "build" }),
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
  assert.equal((await getUserById(user.id))!.subscriptionStatus, "none");

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
        metadata: { userId: user.id, plan: "build" },
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

    const updated = (await getUserById(user.id))!;
    assert.equal(updated.subscriptionStatus, "active");
    assert.equal(updated.plan, "build");
    assert.equal(updated.stripeCustomerId, "cus_test_123");
  } finally {
    server.close();
  }
});

test("checkout-session rejects an account that already has an active subscription", async (t) => {
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const signup = await fetch(`${base}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "billing-already-subscribed@example.com", password: "correct horse battery staple" }),
  });
  const { token, user } = (await signup.json()) as any;
  await setSubscriptionStatus(user.id, "build", "active");

  const res = await fetch(`${base}/api/billing/checkout-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ plan: "protect" }),
  });
  // 409, not a call to Stripe: an account already paid up must not be able
  // to create a second subscription by retrying/double-clicking checkout.
  assert.equal(res.status, 409);
});

test("a redelivered webhook (same event id) is a no-op the second time", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const user = await createUser("webhook-redelivered@example.com", "correct horse battery staple");

  const payload = JSON.stringify({
    id: "evt_redelivered_1",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: {
      object: {
        id: "cs_redelivered",
        object: "checkout.session",
        customer: "cus_redelivered",
        metadata: { userId: user.id, plan: "build" },
      },
    },
  });

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const send = () =>
    fetch(`${base}/api/billing/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
      body: payload,
    });

  const first = await send();
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.equal(firstBody.duplicate, undefined);

  // Simulate Stripe retrying the exact same event id (e.g. the first
  // delivery's 200 was lost in transit) after the account was separately
  // downgraded some other way — if this were re-applied, it would
  // incorrectly resurrect the "active" state the first delivery set.
  await setSubscriptionStatus(user.id, "build", "canceled");

  const second = await send();
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.equal(secondBody.duplicate, true);

  const afterReplay = (await getUserById(user.id))!;
  assert.equal(afterReplay.subscriptionStatus, "canceled", "a replayed event must not re-apply and overwrite the separately-made change");
});

test("an out-of-order webhook does not overwrite a more recent applied state", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_BUILD = "price_build_test";
  process.env.STRIPE_PRICE_PROTECT = "price_protect_test";

  const user = await createUser("webhook-out-of-order@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");

  function subscriptionUpdatedPayload(eventId: string, createdAt: number, priceId: string, status: string) {
    return JSON.stringify({
      id: eventId,
      object: "event",
      api_version: "2025-01-01",
      created: createdAt,
      type: "customer.subscription.updated",
      data: {
        object: {
          id: "sub_ooo_test",
          object: "subscription",
          customer: "cus_ooo_test",
          status,
          items: { data: [{ price: { id: priceId } }] },
        },
      },
    });
  }

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  // checkout.session.completed first, to attach the Stripe customer id.
  const checkoutPayload = JSON.stringify({
    id: "evt_ooo_checkout",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000) - 100,
    type: "checkout.session.completed",
    data: { object: { id: "cs_ooo", object: "checkout.session", customer: "cus_ooo_test", metadata: { userId: user.id, plan: "build" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(checkoutPayload, webhookSecret) },
    body: checkoutPayload,
  });

  const now = Math.floor(Date.now() / 1000);

  // The newer event (an upgrade to protect) arrives first...
  const newer = subscriptionUpdatedPayload("evt_ooo_newer", now, "price_protect_test", "active");
  const newerRes = await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(newer, webhookSecret) },
    body: newer,
  });
  assert.equal(newerRes.status, 200);
  assert.equal((await getUserById(user.id))!.plan, "protect");

  // ...and the OLDER event (still build) is delivered late, after it.
  const older = subscriptionUpdatedPayload("evt_ooo_older", now - 3600, "price_build_test", "active");
  const olderRes = await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(older, webhookSecret) },
    body: older,
  });
  assert.equal(olderRes.status, 200);

  const afterLateDelivery = (await getUserById(user.id))!;
  assert.equal(afterLateDelivery.plan, "protect", "an older, late-arriving event must not downgrade a subscription that was already updated by a newer one");
});

test("subscription.updated derives the plan from Stripe's own price, not the account's stale DB plan", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;
  process.env.STRIPE_PRICE_BUILD = "price_build_test";
  process.env.STRIPE_PRICE_PROTECT = "price_protect_test";

  const user = await createUser("webhook-derived-plan@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const checkoutPayload = JSON.stringify({
    id: "evt_derived_checkout",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000) - 100,
    type: "checkout.session.completed",
    data: { object: { id: "cs_derived", object: "checkout.session", customer: "cus_derived_test", metadata: { userId: user.id, plan: "build" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(checkoutPayload, webhookSecret) },
    body: checkoutPayload,
  });

  // The DB still says "build" (set above), but Stripe's own subscription
  // object says the price is protect — e.g. a plan change made directly in
  // the Stripe dashboard, or an earlier webhook that never arrived.
  const payload = JSON.stringify({
    id: "evt_derived_updated",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "customer.subscription.updated",
    data: {
      object: {
        id: "sub_derived",
        object: "subscription",
        customer: "cus_derived_test",
        status: "active",
        items: { data: [{ price: { id: "price_protect_test" } }] },
      },
    },
  });
  const res = await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
    body: payload,
  });
  assert.equal(res.status, 200);

  assert.equal((await getUserById(user.id))!.plan, "protect", "the plan must come from Stripe's actual price, not the previously-stored DB value");
});
