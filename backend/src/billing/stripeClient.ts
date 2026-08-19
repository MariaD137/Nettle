import Stripe from "stripe";

let client: Stripe | null = null;

// Test-only seam: lets tests exercise billing logic that calls the Stripe
// API (e.g. cancelling a subscription) against a fake client, since this
// sandbox has no live Stripe credentials or network egress. Never set
// outside test/.
let testClientOverride: Stripe | null = null;

// Lazy init, not at import time — this module gets imported even in dev/test
// environments with no Stripe keys configured at all, and importing it
// shouldn't crash the whole server on boot just because billing isn't set
// up yet.
export function getStripeClient(): Stripe {
  if (testClientOverride) return testClientOverride;
  if (!client) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) {
      throw new Error("STRIPE_SECRET_KEY is not set — billing is not configured in this environment");
    }
    client = new Stripe(key);
  }
  return client;
}

export function __setStripeClientForTesting(fake: Stripe | null): void {
  testClientOverride = fake;
}

export const PLAN_PRICE_ENV_VARS: Record<string, string> = {
  tier1: "STRIPE_PRICE_TIER1",
  tier2: "STRIPE_PRICE_TIER2",
};

export function priceIdForPlan(plan: string): string {
  const envVar = PLAN_PRICE_ENV_VARS[plan];
  if (!envVar) throw new Error(`Unknown plan "${plan}"`);
  const priceId = process.env[envVar];
  if (!priceId) throw new Error(`${envVar} is not set — billing is not configured for the "${plan}" plan`);
  return priceId;
}

// The inverse of priceIdForPlan: given a Stripe price ID off a subscription
// object, which of our plans does it correspond to? Used so a subscription
// webhook event can report the plan the subscription is actually on, rather
// than trusting whatever plan happens to already be stored for the user.
export function planForPriceId(priceId: string): string | null {
  for (const [plan, envVar] of Object.entries(PLAN_PRICE_ENV_VARS)) {
    if (process.env[envVar] === priceId) return plan;
  }
  return null;
}

// Cancels every non-cancelled subscription a Stripe customer has. Used when
// an account is deleted locally — without this, deleting the local user row
// leaves Stripe still billing the card on file, and once the row is gone
// getUserByStripeCustomerId can't find the account for any future webhook
// to fix it.
//
// If billing isn't configured in this environment at all, there is no real
// subscription to cancel, so this is a no-op rather than an error. If
// billing IS configured but the Stripe call itself fails, the error
// propagates — callers should treat that as "deletion did not complete"
// rather than deleting the local account while Stripe keeps billing it.
export async function cancelAllSubscriptions(stripeCustomerId: string): Promise<void> {
  let stripe: Stripe;
  try {
    stripe = getStripeClient();
  } catch {
    return;
  }

  const subscriptions = await stripe.subscriptions.list({ customer: stripeCustomerId, status: "all" });
  for (const subscription of subscriptions.data) {
    if (subscription.status !== "canceled" && subscription.status !== "incomplete_expired") {
      await stripe.subscriptions.cancel(subscription.id);
    }
  }
}
