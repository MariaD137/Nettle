import { Router, raw } from "express";
import { getStripeClient, priceIdForPlan, planForPriceId } from "../billing/stripeClient";
import { requireAuth } from "../auth/middleware";
import { getUserById, setStripeCustomerId, setSubscriptionStatus, getUserByStripeCustomerId } from "../auth/users";
import { hasActiveSubscription } from "../billing/subscription";
import { recordWebhookEventOnce } from "../billing/webhookLedger";
import { rateLimit } from "../middleware/rateLimit";
import type Stripe from "stripe";

// Split in two deliberately: the webhook needs the exact raw request bytes
// to verify Stripe's signature (HMAC over the untouched body) — if this ran
// through the app's normal express.json() first, the bytes Stripe signed
// and the bytes we'd verify against would no longer match, and every
// webhook would fail signature verification. See index.ts for the mount
// order this depends on.
export const billingRouter = Router();
export const billingWebhookRouter = Router();

const checkoutLimiter = rateLimit({
  windowMs: 60 * 1000,
  maxRequests: 10,
  message: "Too many checkout attempts — try again shortly",
  scope: "billing:checkout",
  keyFn: (req) => (req.userId ? `user:${req.userId}` : null),
});

billingRouter.post("/api/billing/checkout-session", requireAuth, checkoutLimiter, async (req, res) => {
  const plan = req.body?.plan;
  if (plan !== "tier1" && plan !== "tier2") {
    return res.status(400).json({ error: 'plan must be "tier1" or "tier2"' });
  }

  const user = await getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  // Refuses a second checkout session for an account that's already paid up.
  // Without this, a double-clicked or retried checkout button can create two
  // Stripe subscriptions for the same customer — the account is only ever
  // entitled to one plan at a time regardless, so the second charge is pure
  // double-billing with no corresponding product benefit.
  if (hasActiveSubscription(user)) {
    return res.status(409).json({ error: "This account already has an active subscription", plan: user.plan });
  }

  try {
    const stripe = getStripeClient();
    const priceId = priceIdForPlan(plan);

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      customer: user.stripeCustomerId ?? undefined,
      customer_email: user.stripeCustomerId ? undefined : user.email,
      client_reference_id: user.id,
      metadata: { userId: user.id, plan },
      success_url: process.env.BILLING_SUCCESS_URL ?? "http://localhost:5173/billing/success",
      cancel_url: process.env.BILLING_CANCEL_URL ?? "http://localhost:5173/billing/cancelled",
    });

    res.json({ url: session.url });
  } catch (err) {
    res.status(503).json({ error: "Billing is not available", detail: (err as Error).message });
  }
});

billingWebhookRouter.post("/api/billing/webhook", raw({ type: "application/json" }), async (req, res) => {
  const signature = req.header("stripe-signature");
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!signature || !webhookSecret) {
    return res.status(400).json({ error: "Missing signature or webhook secret not configured" });
  }

  let event: Stripe.Event;
  try {
    const stripe = getStripeClient();
    event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
  } catch (err) {
    return res.status(400).json({ error: `Webhook signature verification failed: ${(err as Error).message}` });
  }

  // Idempotency: Stripe redelivers an event under the same id whenever the
  // original delivery didn't get a 2xx in time. A signature-valid replay of
  // an already-processed event must be a no-op, not a re-application of a
  // plan/status change — see webhookLedger.ts.
  const isNewEvent = await recordWebhookEventOnce(event.id, event.type);
  if (!isNewEvent) {
    return res.json({ received: true, duplicate: true });
  }

  // Stripe's own event timestamp (its clock, not arrival time), passed to
  // setSubscriptionStatus so an out-of-order delivery can't overwrite a
  // newer applied state with an older one.
  const eventCreatedAt = new Date(event.created * 1000).toISOString();

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.metadata?.userId;
      const plan = session.metadata?.plan;
      if (userId && plan && typeof session.customer === "string") {
        await setStripeCustomerId(userId, session.customer);
        await setSubscriptionStatus(userId, plan, "active", eventCreatedAt);
      }
      break;
    }
    case "customer.subscription.updated":
    case "customer.subscription.deleted": {
      const subscription = event.data.object as Stripe.Subscription;
      if (typeof subscription.customer === "string") {
        const user = await getUserByStripeCustomerId(subscription.customer);
        if (user) {
          const status = event.type === "customer.subscription.deleted" ? "canceled" : subscription.status;
          // Derived from what Stripe says is actually being billed, not from
          // this app's own possibly-stale DB plan — a plan change made
          // outside this app's own checkout flow (the Stripe dashboard, a
          // missed earlier webhook) must not desync quota/access from what
          // the customer is actually paying for. Falls back to the existing
          // DB plan only if the subscription's price doesn't map to a known
          // plan (e.g. a price not yet wired into PLAN_PRICE_ENV_VARS) —
          // never invents a plan the app doesn't recognize.
          const priceId = subscription.items.data[0]?.price?.id;
          const derivedPlan = priceId ? planForPriceId(priceId) : null;
          await setSubscriptionStatus(user.id, derivedPlan ?? user.plan, status, eventCreatedAt);
        }
      }
      break;
    }
  }

  res.json({ received: true });
});
