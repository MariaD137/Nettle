import { Router, raw } from "express";
import { getStripeClient, priceIdForPlan } from "../billing/stripeClient";
import { requireAuth } from "../auth/middleware";
import { getUserById, setStripeCustomerId, setSubscriptionStatus, getUserByStripeCustomerId } from "../auth/users";
import { isStripeEventProcessed, markStripeEventProcessed, recordPaymentFailure, getPaymentFailures } from "../billing/stripeEvents";
import { sendEmail } from "../integrations/email";
import { incrementCounter, Metric } from "../observability/metrics";
import type Stripe from "stripe";

// Split in two deliberately: the webhook needs the exact raw request bytes
// to verify Stripe's signature (HMAC over the untouched body) — if this ran
// through the app's normal express.json() first, the bytes Stripe signed
// and the bytes we'd verify against would no longer match, and every
// webhook would fail signature verification. See index.ts for the mount
// order this depends on.
export const billingRouter = Router();
export const billingWebhookRouter = Router();

billingRouter.post("/api/billing/checkout-session", requireAuth, async (req, res) => {
  const plan = req.body?.plan;
  if (plan !== "tier1" && plan !== "tier2") {
    return res.status(400).json({ error: 'plan must be "tier1" or "tier2"' });
  }

  const user = getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

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

// Lets a subscriber manage their own subscription (cancel, change plan,
// update payment method) directly through Stripe's own hosted UI, without
// Nettle needing to reimplement any of that. Only reachable once a
// customer id exists, which happens on first successful checkout.
billingRouter.post("/api/billing/portal-session", requireAuth, async (req, res) => {
  const user = getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });
  if (!user.stripeCustomerId) {
    return res.status(400).json({ error: "No billing account yet — subscribe first" });
  }

  try {
    const stripe = getStripeClient();
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: process.env.BILLING_PORTAL_RETURN_URL ?? "http://localhost:5173/settings",
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(503).json({ error: "Billing is not available", detail: (err as Error).message });
  }
});

billingRouter.get("/api/billing/payment-failures", requireAuth, (req, res) => {
  res.json({ failures: getPaymentFailures(req.userId!) });
});

billingWebhookRouter.post("/api/billing/webhook", raw({ type: "application/json" }), async (req, res) => {
  const signature = req.header("stripe-signature");
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!signature || !webhookSecret) {
    incrementCounter(Metric.StripeWebhookFailures);
    return res.status(400).json({ error: "Missing signature or webhook secret not configured" });
  }

  let event: Stripe.Event;
  try {
    const stripe = getStripeClient();
    event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
  } catch (err) {
    incrementCounter(Metric.StripeWebhookFailures);
    return res.status(400).json({ error: `Webhook signature verification failed: ${(err as Error).message}` });
  }

  // Stripe redelivers webhooks (at-least-once delivery is documented
  // behavior, not an edge case) — without this, a redelivered
  // invoice.payment_failed would send the customer a second "payment
  // failed" email for the exact same invoice.
  if (isStripeEventProcessed(event.id)) {
    return res.json({ received: true, duplicate: true });
  }

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.metadata?.userId;
      const plan = session.metadata?.plan;
      if (userId && plan && typeof session.customer === "string") {
        setStripeCustomerId(userId, session.customer);
        setSubscriptionStatus(userId, plan, "active");
      }
      break;
    }
    case "customer.subscription.updated":
    case "customer.subscription.deleted": {
      const subscription = event.data.object as Stripe.Subscription;
      if (typeof subscription.customer === "string") {
        const user = getUserByStripeCustomerId(subscription.customer);
        if (user) {
          const status = event.type === "customer.subscription.deleted" ? "canceled" : subscription.status;
          setSubscriptionStatus(user.id, user.plan, status);
        }
      }
      break;
    }
    case "invoice.payment_failed": {
      const invoice = event.data.object as Stripe.Invoice;
      if (typeof invoice.customer === "string") {
        const user = getUserByStripeCustomerId(invoice.customer);
        if (user) {
          // Reflects the failure immediately rather than waiting on a
          // separate customer.subscription.updated event, which Stripe
          // typically also sends but isn't guaranteed to arrive first (or
          // at all, e.g. if the subscription hasn't actually transitioned
          // yet on this retry). "past_due" is an existing recognized
          // status — hasActiveSubscription() already excludes it.
          setSubscriptionStatus(user.id, user.plan, "past_due");
          recordPaymentFailure({
            userId: user.id,
            stripeInvoiceId: invoice.id ?? "unknown",
            amountDue: invoice.amount_due,
            currency: invoice.currency,
            failureReason: invoice.last_finalization_error?.message ?? null,
          });
          await sendEmail(
            user.email,
            "Your Nettle payment didn't go through",
            `We weren't able to process your latest payment. Please update your payment method to avoid an interruption to your subscription.\n\nManage billing: ${process.env.BILLING_PORTAL_RETURN_URL ?? "http://localhost:5173/settings"}`,
          );
        }
      }
      break;
    }
  }

  markStripeEventProcessed(event.id, event.type);
  res.json({ received: true });
});
