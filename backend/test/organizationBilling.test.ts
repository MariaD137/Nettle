// Additive per-organization billing: an organization can optionally carry
// its own Stripe subscription, entirely separate from any member's personal
// one. Covers the three seams this adds — the webhook routing a Stripe
// event to an organization instead of a user, the owner-only checkout
// route, and the entitlement resolution itself (a project's Fix Center
// access and an organization's team-member limit both prefer the
// organization's own subscription when it has one, falling back to the
// pre-existing per-user model otherwise) — plus the edge cases the spec
// calls out: downgrade/cancellation and a user who belongs to more than one
// organization.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { organizationsRouter } from "../src/routes/organizations.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { billingRouter, billingWebhookRouter } from "../src/routes/billing.routes";
import { getOrganization, addMember } from "../src/organizations/organizations";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  // billingWebhookRouter must precede express.json() — it needs the raw
  // request bytes to verify Stripe's signature (see billing.routes.ts).
  app.use(billingWebhookRouter);
  app.use(express.json());
  app.use(organizationsRouter);
  app.use(projectsRouter);
  app.use(billingRouter);
  return app;
}

function signStripePayload(payload: string, secret: string, timestamp = Math.floor(Date.now() / 1000)) {
  const signedPayload = `${timestamp}.${payload}`;
  const signature = crypto.createHmac("sha256", secret).update(signedPayload).digest("hex");
  return `t=${timestamp},v1=${signature}`;
}

const PASSWORD = "correct horse battery staple";

async function userAndToken(email: string) {
  const user = await createUser(email, PASSWORD);
  const token = await createSession(user.id);
  return { user, token };
}

async function createOrg(base: string, token: string, name: string) {
  const res = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  return ((await res.json()) as any).organization;
}

async function createOrgProject(base: string, token: string, organizationId: string, name: string) {
  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name, organizationId }),
  });
  assert.equal(res.status, 201, JSON.stringify(await res.clone().json()));
  return res.json();
}

// --- Webhook routing: organizationId metadata, not userId ------------------

test("checkout.session.completed with organizationId metadata activates the organization, not any user", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("orgbilling-webhook-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");

  const payload = JSON.stringify({
    id: "evt_org_checkout",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: {
      object: {
        id: "cs_org_test",
        object: "checkout.session",
        customer: "cus_org_test",
        metadata: { organizationId: org.id, plan: "protect" },
      },
    },
  });

  const res = await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
    body: payload,
  });
  assert.equal(res.status, 200, JSON.stringify(await res.clone().json()));

  const updated = await getOrganization(org.id);
  assert.equal(updated!.subscriptionStatus, "active");
  assert.equal(updated!.plan, "protect");
  assert.equal(updated!.stripeCustomerId, "cus_org_test");
});

test("customer.subscription.deleted for an organization's Stripe customer cancels only that organization", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("orgbilling-webhook-cancel-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp 2");

  const checkoutPayload = JSON.stringify({
    id: "evt_org_cancel_checkout",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000) - 100,
    type: "checkout.session.completed",
    data: { object: { id: "cs_x", object: "checkout.session", customer: "cus_org_cancel", metadata: { organizationId: org.id, plan: "build" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(checkoutPayload, webhookSecret) },
    body: checkoutPayload,
  });
  assert.equal((await getOrganization(org.id))!.subscriptionStatus, "active");

  const deletePayload = JSON.stringify({
    id: "evt_org_cancel_deleted",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "customer.subscription.deleted",
    data: { object: { id: "sub_org_cancel", object: "subscription", customer: "cus_org_cancel", status: "canceled", items: { data: [{ price: { id: "unused" } }] } } },
  });
  const res = await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(deletePayload, webhookSecret) },
    body: deletePayload,
  });
  assert.equal(res.status, 200);

  const afterCancel = await getOrganization(org.id);
  assert.equal(afterCancel!.subscriptionStatus, "canceled");
});

// --- Owner-only checkout route ----------------------------------------------

test("POST /api/organizations/:id/billing/checkout-session requires auth", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const res = await fetch(`${base}/api/organizations/whatever/billing/checkout-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plan: "build" }),
  });
  assert.equal(res.status, 401);
});

test("a non-owner member cannot start checkout for the organization", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user: owner, token: ownerToken } = await userAndToken("orgbilling-nonowner-owner@example.com");
  const { user: member, token: memberToken } = await userAndToken("orgbilling-nonowner-member@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp 3");
  await addMember(org.id, member.id);
  void owner;

  const res = await fetch(`${base}/api/organizations/${org.id}/billing/checkout-session`, {
    method: "POST",
    headers: { Authorization: `Bearer ${memberToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ plan: "build" }),
  });
  assert.equal(res.status, 403);
});

test("checkout-session rejects an organization that already has an active subscription", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("orgbilling-already-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp 4");

  const payload = JSON.stringify({
    id: "evt_already_sub",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: { object: { id: "cs_already", object: "checkout.session", customer: "cus_already", metadata: { organizationId: org.id, plan: "build" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
    body: payload,
  });

  const res = await fetch(`${base}/api/organizations/${org.id}/billing/checkout-session`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ plan: "protect" }),
  });
  // 409, not a call to Stripe — same double-subscription guard as the
  // personal checkout flow (routes/billing.routes.ts).
  assert.equal(res.status, 409);
});

test("checkout-session rejects an unknown plan", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("orgbilling-badplan-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp 5");

  const res = await fetch(`${base}/api/organizations/${org.id}/billing/checkout-session`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ plan: "enterprise-super-plan" }),
  });
  assert.equal(res.status, 400);
});

// --- Entitlement resolution: project access -------------------------------

test("a FREE member sees Fix Center content for a project owned by their organization's PROTECT subscription", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user: owner, token: ownerToken } = await userAndToken("orgbilling-fixcenter-owner@example.com");
  const { user: member, token: memberToken } = await userAndToken("orgbilling-fixcenter-member@example.com");
  const org = await createOrg(base, ownerToken, "Fix Center Corp");
  await addMember(org.id, member.id);
  void owner;

  const project = (await createOrgProject(base, ownerToken, org.id, "Org Project")) as any;

  // Before the organization is subscribed: the FREE member falls back to
  // their own (FREE) plan — the PROTECT-only alerts route stays a 402, the
  // pre-existing per-user model, unchanged.
  const beforeRes = await fetch(`${base}/api/projects/${project.id}/alerts`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(beforeRes.status, 402, "unsubscribed organization falls back to the member's own FREE plan");

  // Subscribe the organization to PROTECT.
  const payload = JSON.stringify({
    id: "evt_fixcenter_checkout",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: { object: { id: "cs_fc", object: "checkout.session", customer: "cus_fc", metadata: { organizationId: org.id, plan: "protect" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(payload, webhookSecret) },
    body: payload,
  });

  // The same FREE member's own account never changed — but the project's
  // route now resolves entitlement through the organization's subscription.
  const alertsRes = await fetch(`${base}/api/projects/${project.id}/alerts`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(alertsRes.status, 200, "PROTECT-only alerts route is reachable once the organization itself is subscribed to PROTECT");

  const detailRes = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(detailRes.status, 200);
});

test("downgrading/cancelling the organization's subscription reverts a member's project access to their own personal plan", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user: owner, token: ownerToken } = await userAndToken("orgbilling-downgrade-owner@example.com");
  const { user: member, token: memberToken } = await userAndToken("orgbilling-downgrade-member@example.com");
  const org = await createOrg(base, ownerToken, "Downgrade Corp");
  await addMember(org.id, member.id);
  void owner;

  const project = (await createOrgProject(base, ownerToken, org.id, "Downgrade Project")) as any;

  const activate = JSON.stringify({
    id: "evt_downgrade_activate",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000) - 200,
    type: "checkout.session.completed",
    data: { object: { id: "cs_dg", object: "checkout.session", customer: "cus_dg", metadata: { organizationId: org.id, plan: "protect" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(activate, webhookSecret) },
    body: activate,
  });

  const alertsWhileActive = await fetch(`${base}/api/projects/${project.id}/alerts`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(alertsWhileActive.status, 200);

  const cancel = JSON.stringify({
    id: "evt_downgrade_cancel",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "customer.subscription.deleted",
    data: { object: { id: "sub_dg", object: "subscription", customer: "cus_dg", status: "canceled", items: { data: [{ price: { id: "unused" } }] } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(cancel, webhookSecret) },
    body: cancel,
  });

  const alertsAfterCancel = await fetch(`${base}/api/projects/${project.id}/alerts`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(alertsAfterCancel.status, 402, "a cancelled organization subscription must revert to the member's own (FREE) plan, not stay entitled");
});

test("a project's entitlement comes from ITS OWN organization, not any other organization the caller belongs to", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  // One owner running two organizations — one subscribed, one not. Personal
  // project-creation limits stay deliberately per-user, not per-organization
  // (see billing/orgSubscription.ts's module comment) — a personal BUILD
  // subscription here is just what lets this one account create the two
  // projects the test needs, unrelated to the organization entitlement this
  // test actually checks.
  const { user: owner, token: ownerToken } = await userAndToken("orgbilling-multiorg-owner@example.com");
  await setSubscriptionStatus(owner.id, "build", "active");
  const subscribedOrg = await createOrg(base, ownerToken, "Subscribed Org");
  const plainOrg = await createOrg(base, ownerToken, "Plain Org");

  const activate = JSON.stringify({
    id: "evt_multiorg_activate",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: { object: { id: "cs_mo", object: "checkout.session", customer: "cus_mo", metadata: { organizationId: subscribedOrg.id, plan: "protect" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(activate, webhookSecret) },
    body: activate,
  });

  const projectInSubscribedOrg = (await createOrgProject(base, ownerToken, subscribedOrg.id, "In Subscribed Org")) as any;
  const projectInPlainOrg = (await createOrgProject(base, ownerToken, plainOrg.id, "In Plain Org")) as any;

  const subscribedRes = await fetch(`${base}/api/projects/${projectInSubscribedOrg.id}/alerts`, { headers: { Authorization: `Bearer ${ownerToken}` } });
  assert.equal(subscribedRes.status, 200, "the subscribed organization's own project is entitled");

  const plainRes = await fetch(`${base}/api/projects/${projectInPlainOrg.id}/alerts`, { headers: { Authorization: `Bearer ${ownerToken}` } });
  assert.equal(plainRes.status, 402, "an unrelated organization's subscription must never leak entitlement onto a different organization's project");
});

// --- Entitlement resolution: team-member limit ------------------------------

test("subscribing the organization itself raises its team-member limit, independent of the owner's personal plan", async (t) => {
  const webhookSecret = "whsec_test_secret_for_local_tests_only";
  process.env.STRIPE_SECRET_KEY = "sk_test_fake_key_for_local_tests_only";
  process.env.STRIPE_WEBHOOK_SECRET = webhookSecret;

  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  // Owner stays on FREE personally (team limit 1) for this whole test.
  const { token: ownerToken } = await userAndToken("orgbilling-team-owner@example.com");
  const org = await createOrg(base, ownerToken, "Team Corp");

  const { user: member1 } = await userAndToken("orgbilling-team-member1@example.com");

  // FREE's team limit is 1 (the owner alone) — a second member is refused
  // while the organization itself is unsubscribed, exactly the pre-existing
  // per-user model.
  const addRes = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "orgbilling-team-member1@example.com" }),
  });
  assert.equal(addRes.status, 403);
  assert.equal((await addRes.json()).teamLimitReached, true);
  void member1;

  // Subscribe the organization itself to PROTECT (team limit 10) — the
  // owner's own personal account is still FREE the whole time.
  const activate = JSON.stringify({
    id: "evt_team_activate",
    object: "event",
    api_version: "2025-01-01",
    created: Math.floor(Date.now() / 1000),
    type: "checkout.session.completed",
    data: { object: { id: "cs_team", object: "checkout.session", customer: "cus_team", metadata: { organizationId: org.id, plan: "protect" } } },
  });
  await fetch(`${base}/api/billing/webhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Stripe-Signature": signStripePayload(activate, webhookSecret) },
    body: activate,
  });

  const addAfterRes = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "orgbilling-team-member1@example.com" }),
  });
  assert.equal(addAfterRes.status, 201, "the organization's own PROTECT subscription must raise the team limit even though the owner's personal plan is still FREE");
});
